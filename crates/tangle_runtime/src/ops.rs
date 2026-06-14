#![forbid(unsafe_code)]

use crate::runtime::{TangleRuntimeMetrics, TangleRuntimeMetricsSnapshot};
use axum::{Json, Router, extract::State, routing::get};
use http::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseRelayReadinessCheckStatus {
    Ready,
    NotReady,
}

impl BaseRelayReadinessCheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NotReady => "not_ready",
        }
    }

    pub fn is_ready(self) -> bool {
        self == Self::Ready
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseRelayReadinessState {
    config: BaseRelayReadinessCheckStatus,
    server_bind: BaseRelayReadinessCheckStatus,
    relay_identity: BaseRelayReadinessCheckStatus,
    pocket_storage: BaseRelayReadinessCheckStatus,
    group_projection: BaseRelayReadinessCheckStatus,
    group_outbox_replay: BaseRelayReadinessCheckStatus,
}

impl BaseRelayReadinessState {
    pub fn new(
        config: BaseRelayReadinessCheckStatus,
        server_bind: BaseRelayReadinessCheckStatus,
        relay_identity: BaseRelayReadinessCheckStatus,
        pocket_storage: BaseRelayReadinessCheckStatus,
        group_projection: BaseRelayReadinessCheckStatus,
        group_outbox_replay: BaseRelayReadinessCheckStatus,
    ) -> Self {
        Self {
            config,
            server_bind,
            relay_identity,
            pocket_storage,
            group_projection,
            group_outbox_replay,
        }
    }

    pub fn ready() -> Self {
        Self::new(
            BaseRelayReadinessCheckStatus::Ready,
            BaseRelayReadinessCheckStatus::Ready,
            BaseRelayReadinessCheckStatus::Ready,
            BaseRelayReadinessCheckStatus::Ready,
            BaseRelayReadinessCheckStatus::Ready,
            BaseRelayReadinessCheckStatus::Ready,
        )
    }

    pub fn runtime_ready_before_bind() -> Self {
        Self::new(
            BaseRelayReadinessCheckStatus::Ready,
            BaseRelayReadinessCheckStatus::NotReady,
            BaseRelayReadinessCheckStatus::Ready,
            BaseRelayReadinessCheckStatus::Ready,
            BaseRelayReadinessCheckStatus::Ready,
            BaseRelayReadinessCheckStatus::Ready,
        )
    }

    pub fn with_server_bind(mut self, server_bind: BaseRelayReadinessCheckStatus) -> Self {
        self.server_bind = server_bind;
        self
    }

    pub fn is_ready(&self) -> bool {
        [
            self.config,
            self.server_bind,
            self.relay_identity,
            self.pocket_storage,
            self.group_projection,
            self.group_outbox_replay,
        ]
        .into_iter()
        .all(BaseRelayReadinessCheckStatus::is_ready)
    }

    pub fn response(&self) -> BaseRelayReadinessDocument {
        BaseRelayReadinessDocument {
            status: if self.is_ready() {
                "ready".to_owned()
            } else {
                "not_ready".to_owned()
            },
            checks: BaseRelayReadinessChecksDocument {
                config: self.config.as_str().to_owned(),
                server_bind: self.server_bind.as_str().to_owned(),
                relay_identity: self.relay_identity.as_str().to_owned(),
                pocket_storage: self.pocket_storage.as_str().to_owned(),
                group_projection: self.group_projection.as_str().to_owned(),
                group_outbox_replay: self.group_outbox_replay.as_str().to_owned(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseRelayHealthDocument {
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseRelayReadinessDocument {
    pub status: String,
    pub checks: BaseRelayReadinessChecksDocument,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseRelayReadinessChecksDocument {
    pub config: String,
    pub server_bind: String,
    pub relay_identity: String,
    pub pocket_storage: String,
    pub group_projection: String,
    pub group_outbox_replay: String,
}

#[derive(Debug, Clone)]
struct BaseRelayOpsState {
    readiness: BaseRelayReadinessState,
    metrics: TangleRuntimeMetrics,
}

pub fn base_relay_ops_router(
    readiness: BaseRelayReadinessState,
    metrics: TangleRuntimeMetrics,
) -> Router {
    Router::new()
        .route("/healthz", get(base_relay_healthz))
        .route("/readyz", get(base_relay_readyz))
        .route("/metricsz", get(base_relay_metricsz))
        .with_state(BaseRelayOpsState { readiness, metrics })
}

async fn base_relay_healthz() -> Json<BaseRelayHealthDocument> {
    Json(BaseRelayHealthDocument {
        status: "ok".to_owned(),
    })
}

async fn base_relay_readyz(
    State(state): State<BaseRelayOpsState>,
) -> (StatusCode, Json<BaseRelayReadinessDocument>) {
    let status = if state.readiness.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(state.readiness.response()))
}

async fn base_relay_metricsz(
    State(state): State<BaseRelayOpsState>,
) -> Json<TangleRuntimeMetricsSnapshot> {
    Json(state.metrics.snapshot())
}

#[cfg(test)]
mod tests {
    use super::{BaseRelayReadinessCheckStatus, BaseRelayReadinessState, base_relay_ops_router};
    use crate::runtime::TangleRuntimeMetrics;
    use axum::body::to_bytes;
    use http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn base_relay_ops_router_reports_health_and_readiness() {
        let metrics = TangleRuntimeMetrics::new();
        let health = base_relay_ops_router(BaseRelayReadinessState::ready(), metrics.clone())
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("health");

        assert_eq!(health.status(), StatusCode::OK);
        let health_body = to_bytes(health.into_body(), usize::MAX)
            .await
            .expect("body");
        let health_value = serde_json::from_slice::<serde_json::Value>(&health_body).expect("json");
        assert_eq!(health_value["status"], "ok");

        metrics.record_session_opened();
        metrics.record_client_message(crate::runtime::TangleClientMessageMetricKind::Req);
        metrics.record_subscription_opened();
        let ready = base_relay_ops_router(BaseRelayReadinessState::ready(), metrics.clone())
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("ready");

        assert_eq!(ready.status(), StatusCode::OK);
        let ready_body = to_bytes(ready.into_body(), usize::MAX).await.expect("body");
        let ready_value = serde_json::from_slice::<serde_json::Value>(&ready_body).expect("json");
        assert_eq!(ready_value["status"], "ready");
        assert_eq!(ready_value["checks"]["server_bind"], "ready");
        assert_eq!(ready_value["checks"]["group_outbox_replay"], "ready");
        let metrics_response = base_relay_ops_router(BaseRelayReadinessState::ready(), metrics)
            .oneshot(
                Request::builder()
                    .uri("/metricsz")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("metrics");

        assert_eq!(metrics_response.status(), StatusCode::OK);
        let metrics_body = to_bytes(metrics_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let metrics_value =
            serde_json::from_slice::<serde_json::Value>(&metrics_body).expect("json");
        assert_eq!(metrics_value["active_sessions"], 1);
        assert_eq!(metrics_value["total_sessions"], 1);
        assert_eq!(metrics_value["client_messages"], 1);
        assert_eq!(metrics_value["req_messages"], 1);
        assert_eq!(metrics_value["opened_subscriptions"], 1);

        let not_ready = BaseRelayReadinessState::new(
            BaseRelayReadinessCheckStatus::Ready,
            BaseRelayReadinessCheckStatus::Ready,
            BaseRelayReadinessCheckStatus::Ready,
            BaseRelayReadinessCheckStatus::Ready,
            BaseRelayReadinessCheckStatus::NotReady,
            BaseRelayReadinessCheckStatus::Ready,
        );
        let rejected = base_relay_ops_router(not_ready, TangleRuntimeMetrics::new())
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("not ready");

        assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
        let rejected_body = to_bytes(rejected.into_body(), usize::MAX)
            .await
            .expect("body");
        let rejected_value =
            serde_json::from_slice::<serde_json::Value>(&rejected_body).expect("json");
        assert_eq!(rejected_value["status"], "not_ready");
        assert_eq!(rejected_value["checks"]["server_bind"], "ready");
        assert_eq!(rejected_value["checks"]["group_projection"], "not_ready");
    }
}
