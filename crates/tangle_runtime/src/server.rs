#![forbid(unsafe_code)]

use crate::{
    errors::BaseRelayError,
    nip11::{BaseRelayInfoConfig, BaseRelayInfoDocument, base_relay_info_response},
    ops::{BaseRelayReadinessState, base_relay_ops_router},
    runtime::{TangleRuntime, TangleShutdownSignal},
    session::TangleWebSocketSession,
};
use axum::{
    Router,
    extract::{
        State,
        ws::{WebSocketUpgrade, rejection::WebSocketUpgradeRejection},
    },
    response::{IntoResponse, Response},
    routing::get,
};
use http::HeaderMap;
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TangleServeReport {
    listen_addr: SocketAddr,
    closed_subscriptions: usize,
}

impl TangleServeReport {
    pub fn new(listen_addr: SocketAddr, closed_subscriptions: usize) -> Self {
        Self {
            listen_addr,
            closed_subscriptions,
        }
    }

    pub fn listen_addr(self) -> SocketAddr {
        self.listen_addr
    }

    pub fn closed_subscriptions(self) -> usize {
        self.closed_subscriptions
    }
}

pub async fn serve_until_shutdown(
    runtime: TangleRuntime,
) -> Result<TangleServeReport, BaseRelayError> {
    let listener = TcpListener::bind(runtime.config().listen_addr())
        .await
        .map_err(|error| BaseRelayError::error(error.to_string()))?;
    serve_listener_until_shutdown(runtime, listener).await
}

pub async fn serve_listener_until_shutdown(
    mut runtime: TangleRuntime,
    listener: TcpListener,
) -> Result<TangleServeReport, BaseRelayError> {
    let listen_addr = listener
        .local_addr()
        .map_err(|error| BaseRelayError::error(error.to_string()))?;
    let info =
        BaseRelayInfoConfig::new("tangle", runtime.config().groups().clone())?.build_document()?;
    let router = tangle_http_router(
        runtime.readiness_state().clone(),
        info,
        runtime.limits().outbound_queue_capacity(),
        runtime.shutdown_signal().clone(),
    );
    let mut shutdown = runtime.shutdown_signal().subscribe();
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            loop {
                if *shutdown.borrow() {
                    break;
                }
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
        .map_err(|error| BaseRelayError::error(error.to_string()))?;
    let shutdown = runtime.shutdown()?;
    Ok(TangleServeReport::new(
        listen_addr,
        shutdown.closed_subscriptions(),
    ))
}

pub fn tangle_http_router(
    readiness: BaseRelayReadinessState,
    info: BaseRelayInfoDocument,
    outbound_queue_capacity: usize,
    shutdown: TangleShutdownSignal,
) -> Router {
    Router::new()
        .route("/", get(tangle_root))
        .with_state(TangleHttpState {
            info,
            outbound_queue_capacity,
            shutdown,
        })
        .merge(base_relay_ops_router(readiness))
}

#[derive(Debug, Clone)]
struct TangleHttpState {
    info: BaseRelayInfoDocument,
    outbound_queue_capacity: usize,
    shutdown: TangleShutdownSignal,
}

async fn tangle_root(
    State(state): State<TangleHttpState>,
    websocket: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    headers: HeaderMap,
) -> Response {
    match websocket {
        Ok(websocket) => match TangleWebSocketSession::new(
            state.outbound_queue_capacity,
            state.shutdown.subscribe(),
        ) {
            Ok(session) => websocket
                .protocols(["nostr"])
                .on_upgrade(move |socket| session.run(socket))
                .into_response(),
            Err(error) => (
                http::StatusCode::INTERNAL_SERVER_ERROR,
                error.prefixed_message(),
            )
                .into_response(),
        },
        Err(_) => base_relay_info_response(state.info, headers),
    }
}

#[cfg(test)]
mod tests {
    use super::{serve_until_shutdown, tangle_http_router};
    use crate::{
        config::{BaseRelayRuntimeConfig, parse_base_relay_runtime_config_json},
        nip11::BaseRelayInfoConfig,
        ops::BaseRelayReadinessState,
        runtime::{TangleRuntime, TangleShutdownSignal},
    };
    use axum::body::to_bytes;
    use http::{Request, header};
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tower::ServiceExt;

    #[tokio::test]
    async fn serve_until_shutdown_binds_listener_and_exits_on_signal() {
        let root = temp_root("serve-until-shutdown");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = TangleRuntime::open(runtime_config(&root)).expect("runtime");
        let shutdown = runtime.shutdown_signal().clone();
        let task = tokio::spawn(serve_until_shutdown(runtime));

        tokio::task::yield_now().await;
        shutdown.request_shutdown();

        let report = task.await.expect("task").expect("serve");
        assert_eq!(report.listen_addr().ip().to_string(), "127.0.0.1");
        assert_ne!(report.listen_addr().port(), 0);
        assert_eq!(report.closed_subscriptions(), 0);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn serve_until_shutdown_accepts_websocket_upgrade() {
        let root = temp_root("websocket-upgrade");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = TangleRuntime::open(runtime_config(&root)).expect("runtime");
        let shutdown = runtime.shutdown_signal().clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let task = tokio::spawn(super::serve_listener_until_shutdown(runtime, listener));
        let mut request = format!("ws://{address}/")
            .into_client_request()
            .expect("request");
        request.headers_mut().insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            http::HeaderValue::from_static("nostr"),
        );

        let (_socket, response) = tokio_tungstenite::connect_async(request)
            .await
            .expect("websocket");

        assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(
            response
                .headers()
                .get(header::SEC_WEBSOCKET_PROTOCOL)
                .expect("protocol"),
            "nostr"
        );

        shutdown.request_shutdown();
        let report = task.await.expect("task").expect("serve");
        assert_eq!(report.listen_addr(), address);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn tangle_http_router_serves_nip11_health_and_ready_routes() {
        let root = temp_root("http-router");
        let config = runtime_config(&root);
        let info = BaseRelayInfoConfig::new("tangle", config.groups().clone())
            .expect("info config")
            .build_document()
            .expect("info");
        let router = tangle_http_router(
            BaseRelayReadinessState::ready(),
            info,
            8,
            TangleShutdownSignal::new(),
        );
        let nip11 = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::ACCEPT, "application/nostr+json")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("nip11");
        let root_without_accept = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("root");
        let health = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("health");
        let ready = router
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("ready");

        assert_eq!(nip11.status(), http::StatusCode::OK);
        assert_eq!(
            nip11.headers().get(header::CONTENT_TYPE).expect("type"),
            "application/nostr+json"
        );
        let nip11_body = to_bytes(nip11.into_body(), usize::MAX).await.expect("body");
        let nip11_value = serde_json::from_slice::<serde_json::Value>(&nip11_body).expect("json");
        assert_eq!(nip11_value["name"], "tangle");
        assert!(
            nip11_value["supported_nips"]
                .as_array()
                .expect("nips")
                .contains(&serde_json::json!(29))
        );
        assert_eq!(root_without_accept.status(), http::StatusCode::NOT_FOUND);
        assert_eq!(health.status(), http::StatusCode::OK);
        assert_eq!(ready.status(), http::StatusCode::OK);
        let root_body = to_bytes(root_without_accept.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(
            String::from_utf8(root_body.to_vec()).expect("utf8"),
            "relay information requires application/nostr+json"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    fn runtime_config(root: &Path) -> BaseRelayRuntimeConfig {
        let raw = json!({
            "server": {
                "listen_addr": "127.0.0.1:0",
                "relay_url": "wss://relay.radroots.test"
            },
            "pocket": {
                "data_directory": root.join("pocket"),
                "map_size_bytes": 1073741824_u64,
                "reader_slots": 128,
                "sync_policy": "flush_on_shutdown"
            },
            "groups": {
                "enabled": true,
                "canonical_relay_url": "wss://relay.radroots.test",
                "relay_secret": "7777777777777777777777777777777777777777777777777777777777777777",
                "owner_pubkeys": ["0202020202020202020202020202020202020202020202020202020202020202"]
            },
            "auth": {
                "challenge_ttl_seconds": 300
            },
            "limits": {
                "max_pending_events": 8
            }
        })
        .to_string();
        parse_base_relay_runtime_config_json(&raw).expect("config")
    }

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("tangle-server-{name}-{}", std::process::id()))
    }
}
