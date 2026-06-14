#![forbid(unsafe_code)]

use crate::{
    errors::BaseRelayError,
    logging,
    nip11::{BaseRelayInfoConfig, BaseRelayInfoDocument, base_relay_info_response},
    ops::{BaseRelayReadinessState, base_relay_ops_router},
    runtime::{
        TangleRuntime, TangleRuntimeHandle, TangleRuntimeLimits, TangleRuntimeMetrics,
        TangleShutdownSignal,
    },
    session::TangleWebSocketSession,
};
use axum::{
    Router,
    extract::{
        ConnectInfo, State,
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
    runtime: TangleRuntime,
    listener: TcpListener,
) -> Result<TangleServeReport, BaseRelayError> {
    let listen_addr = listener
        .local_addr()
        .map_err(|error| BaseRelayError::error(error.to_string()))?;
    let relay_url = runtime.config().relay_url().to_owned();
    let info =
        BaseRelayInfoConfig::new("tangle", runtime.config().groups().clone())?.build_document()?;
    let readiness = runtime.readiness_state().clone();
    let limits = runtime.limits();
    let metrics = runtime.metrics().clone();
    let shutdown_signal = runtime.shutdown_signal().clone();
    let runtime = TangleRuntimeHandle::new(runtime);
    let router = tangle_http_router(
        readiness,
        info,
        limits,
        metrics,
        shutdown_signal.clone(),
        runtime.clone(),
    );
    let mut shutdown = shutdown_signal.subscribe();
    logging::log_server_listening(listen_addr, &relay_url);
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
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
    let shutdown = runtime.shutdown().await?;
    logging::log_server_shutdown(listen_addr, shutdown.closed_subscriptions());
    Ok(TangleServeReport::new(
        listen_addr,
        shutdown.closed_subscriptions(),
    ))
}

pub fn tangle_http_router(
    readiness: BaseRelayReadinessState,
    info: BaseRelayInfoDocument,
    limits: TangleRuntimeLimits,
    metrics: TangleRuntimeMetrics,
    shutdown: TangleShutdownSignal,
    runtime: TangleRuntimeHandle,
) -> Router {
    Router::new()
        .route("/", get(tangle_root))
        .with_state(TangleHttpState {
            info,
            limits,
            shutdown,
            runtime,
        })
        .merge(base_relay_ops_router(readiness, metrics))
}

#[derive(Debug, Clone)]
struct TangleHttpState {
    info: BaseRelayInfoDocument,
    limits: TangleRuntimeLimits,
    shutdown: TangleShutdownSignal,
    runtime: TangleRuntimeHandle,
}

async fn tangle_root(
    State(state): State<TangleHttpState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    websocket: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    headers: HeaderMap,
) -> Response {
    match websocket {
        Ok(websocket) => {
            let session = match state.runtime.auth_state().await {
                Ok(auth) => TangleWebSocketSession::new_with_peer(
                    state.limits,
                    state.shutdown.subscribe(),
                    state.runtime.clone(),
                    auth,
                    state.runtime.subscribe_events().await,
                    Some(peer_addr.ip()),
                ),
                Err(error) => Err(error),
            };
            match session {
                Ok(session) => websocket
                    .protocols(["nostr"])
                    .on_upgrade(move |socket| session.run(socket))
                    .into_response(),
                Err(error) => (
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    error.prefixed_message(),
                )
                    .into_response(),
            }
        }
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
        runtime::{TangleRuntime, TangleRuntimeHandle, TangleShutdownSignal},
    };
    use axum::{body::to_bytes, extract::ConnectInfo};
    use futures_util::{SinkExt, StreamExt};
    use http::{Request, header};
    use serde_json::json;
    use std::{
        net::SocketAddr,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };
    use tangle_protocol::event_to_value;
    use tangle_test_support::{FixtureKey, tangle_v2_auth_event, tangle_v2_event};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, timeout};
    use tokio_tungstenite::tungstenite::{
        Message as TungsteniteMessage, client::IntoClientRequest,
    };
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
    async fn serve_until_shutdown_closes_websocket_sessions() {
        let root = temp_root("websocket-shutdown");
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
        let (mut socket, response) = tokio_tungstenite::connect_async(request)
            .await
            .expect("websocket");

        assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);
        let _ = read_auth_challenge(&mut socket).await;

        shutdown.request_shutdown();

        let next = timeout(Duration::from_secs(1), socket.next())
            .await
            .expect("websocket close");
        match next {
            Some(Ok(TungsteniteMessage::Close(_))) | None => {}
            other => panic!("expected websocket close, got {other:?}"),
        }
        let report = timeout(Duration::from_secs(1), task)
            .await
            .expect("server shutdown")
            .expect("task")
            .expect("serve");
        assert_eq!(report.listen_addr(), address);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn websocket_session_dispatches_base_client_messages() {
        let root = temp_root("websocket-dispatch");
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
        let (mut socket, response) = tokio_tungstenite::connect_async(request)
            .await
            .expect("websocket");
        let event = tangle_v2_event(FixtureKey::Member, 1_714_124_433, 1, Vec::new(), "hello")
            .expect("event");

        assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);
        let challenge = read_auth_challenge(&mut socket).await;
        assert_eq!(challenge.len(), 64);
        assert_eq!(challenge, challenge.to_ascii_lowercase());

        let auth_created_at = current_unix_timestamp();
        let owner_auth = tangle_v2_auth_event(FixtureKey::Owner, &challenge, auth_created_at)
            .expect("owner auth");
        let admin_auth = tangle_v2_auth_event(
            FixtureKey::Admin,
            &challenge,
            auth_created_at.saturating_add(1),
        )
        .expect("admin auth");

        send_client_text(&mut socket, "{").await;
        let notice = read_relay_value(&mut socket).await;
        assert_eq!(notice[0], "NOTICE");
        assert!(
            notice[1]
                .as_str()
                .expect("notice")
                .starts_with("invalid: client message JSON is invalid:")
        );

        send_client_value(&mut socket, json!(["EVENT", event_to_value(&event)])).await;
        assert_eq!(
            read_relay_value(&mut socket).await,
            json!(["OK", event.id().as_str(), true, ""])
        );

        send_client_value(&mut socket, json!(["COUNT", "count-a", {}])).await;
        assert_eq!(
            read_relay_value(&mut socket).await,
            json!(["COUNT", "count-a", {"count": 1}])
        );

        send_client_value(&mut socket, json!(["REQ", "sub-a", {}])).await;
        let req_event = read_relay_value(&mut socket).await;
        assert_eq!(req_event[0], "EVENT");
        assert_eq!(req_event[1], "sub-a");
        assert_eq!(req_event[2]["id"], event.id().as_str());
        assert_eq!(
            read_relay_value(&mut socket).await,
            json!(["EOSE", "sub-a"])
        );

        send_client_value(&mut socket, json!(["AUTH", event_to_value(&owner_auth)])).await;
        assert_eq!(
            read_relay_value(&mut socket).await,
            json!(["OK", owner_auth.id().as_str(), true, ""])
        );

        send_client_value(&mut socket, json!(["AUTH", event_to_value(&admin_auth)])).await;
        assert_eq!(
            read_relay_value(&mut socket).await,
            json!(["OK", admin_auth.id().as_str(), true, ""])
        );

        send_client_value(&mut socket, json!(["CLOSE", "sub-a"])).await;
        assert!(
            timeout(Duration::from_millis(50), socket.next())
                .await
                .is_err()
        );

        shutdown.request_shutdown();
        let report = timeout(Duration::from_secs(1), task)
            .await
            .expect("server shutdown")
            .expect("task")
            .expect("serve");
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
        let runtime = TangleRuntime::open(config).expect("runtime");
        let limits = runtime.limits();
        let metrics = runtime.metrics().clone();
        let router = tangle_http_router(
            BaseRelayReadinessState::ready(),
            info,
            limits,
            metrics,
            TangleShutdownSignal::new(),
            TangleRuntimeHandle::new(runtime),
        );
        let nip11 = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::ACCEPT, "application/nostr+json")
                    .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 39_000))))
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
                    .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 39_001))))
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
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("ready");
        let metrics = router
            .oneshot(
                Request::builder()
                    .uri("/metricsz")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("metrics");

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
        assert_eq!(metrics.status(), http::StatusCode::OK);
        let metrics_body = to_bytes(metrics.into_body(), usize::MAX)
            .await
            .expect("body");
        let metrics_value =
            serde_json::from_slice::<serde_json::Value>(&metrics_body).expect("json");
        assert_eq!(metrics_value["active_sessions"], 0);
        assert_eq!(metrics_value["stored_event_offsets"], 0);
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
                "challenge_ttl_seconds": 300,
                "created_at_skew_seconds": 600
            },
            "limits": {
                "max_message_length": 1048576,
                "max_subid_length": 64,
                "max_subscriptions_per_connection": 64,
                "max_filters_per_request": 10,
                "max_tag_values_per_filter": 100,
                "max_limit": 500,
                "default_limit": 100,
                "max_event_tags": 200,
                "max_content_length": 65536,
                "broadcast_channel_capacity": 8,
                "per_connection_outbound_queue": 8
            },
            "rate_limits": {
                "auth": {
                    "per_pubkey": {"window_seconds": 60, "max_hits": 30},
                    "failures": {"window_seconds": 300, "max_hits": 5}
                },
                "event": {
                    "per_pubkey": {"window_seconds": 60, "max_hits": 120},
                    "per_kind": {"window_seconds": 60, "max_hits": 1000}
                },
                "group": {
                    "write_per_pubkey": {"window_seconds": 60, "max_hits": 60},
                    "write_per_group": {"window_seconds": 60, "max_hits": 90},
                    "write_per_kind": {"window_seconds": 60, "max_hits": 300},
                    "join_flow": {"window_seconds": 300, "max_hits": 10}
                },
                "req": {
                    "per_ip": {"window_seconds": 60, "max_hits": 600},
                    "per_connection": {"window_seconds": 60, "max_hits": 120},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 240},
                    "per_group": {"window_seconds": 60, "max_hits": 240},
                    "per_kind": {"window_seconds": 60, "max_hits": 500},
                    "broad": {"window_seconds": 60, "max_hits": 30}
                },
                "count": {
                    "per_ip": {"window_seconds": 60, "max_hits": 300},
                    "per_connection": {"window_seconds": 60, "max_hits": 60},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 120},
                    "per_group": {"window_seconds": 60, "max_hits": 120},
                    "per_kind": {"window_seconds": 60, "max_hits": 240},
                    "broad": {"window_seconds": 60, "max_hits": 20}
                }
            }
        })
        .to_string();
        parse_base_relay_runtime_config_json(&raw).expect("config")
    }

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("tangle-server-{name}-{}", std::process::id()))
    }

    type TestWebSocket = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    async fn send_client_value(socket: &mut TestWebSocket, value: serde_json::Value) {
        send_client_text(socket, &value.to_string()).await;
    }

    async fn send_client_text(socket: &mut TestWebSocket, value: &str) {
        socket
            .send(TungsteniteMessage::Text(value.to_owned().into()))
            .await
            .expect("send client message");
    }

    async fn read_relay_value(socket: &mut TestWebSocket) -> serde_json::Value {
        let message = timeout(Duration::from_secs(1), socket.next())
            .await
            .expect("relay message timeout")
            .expect("relay message")
            .expect("relay message result");
        let TungsteniteMessage::Text(text) = message else {
            panic!("expected relay text message, got {message:?}");
        };
        serde_json::from_str(text.as_str()).expect("relay json")
    }

    async fn read_auth_challenge(socket: &mut TestWebSocket) -> String {
        let auth = read_relay_value(socket).await;
        assert_eq!(auth[0], "AUTH");
        auth[1].as_str().expect("auth challenge").to_owned()
    }

    fn current_unix_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_secs()
    }
}
