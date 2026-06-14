#![forbid(unsafe_code)]

use crate::{
    errors::BaseRelayError,
    ops::{BaseRelayReadinessState, base_relay_ops_router},
    runtime::TangleRuntime,
};
use axum::{Router, routing::get};
use http::StatusCode;
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
    let router = tangle_http_router(runtime.readiness_state().clone());
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

pub fn tangle_http_router(readiness: BaseRelayReadinessState) -> Router {
    Router::new()
        .route("/", get(tangle_root_reserved))
        .merge(base_relay_ops_router(readiness))
}

async fn tangle_root_reserved() -> (StatusCode, &'static str) {
    (
        StatusCode::NOT_FOUND,
        "relay information requires application/nostr+json",
    )
}

#[cfg(test)]
mod tests {
    use super::{serve_until_shutdown, tangle_http_router};
    use crate::{
        config::{BaseRelayRuntimeConfig, parse_base_relay_runtime_config_json},
        ops::BaseRelayReadinessState,
        runtime::TangleRuntime,
    };
    use axum::body::to_bytes;
    use http::Request;
    use serde_json::json;
    use std::path::{Path, PathBuf};
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
    async fn tangle_http_router_binds_root_health_and_ready_routes() {
        let router = tangle_http_router(BaseRelayReadinessState::ready());
        let root = router
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

        assert_eq!(root.status(), http::StatusCode::NOT_FOUND);
        assert_eq!(health.status(), http::StatusCode::OK);
        assert_eq!(ready.status(), http::StatusCode::OK);
        let root_body = to_bytes(root.into_body(), usize::MAX).await.expect("body");
        assert_eq!(
            String::from_utf8(root_body.to_vec()).expect("utf8"),
            "relay information requires application/nostr+json"
        );
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
