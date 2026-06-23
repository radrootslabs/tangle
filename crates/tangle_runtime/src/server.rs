#![forbid(unsafe_code)]

use crate::{
    errors::BaseRelayError,
    host::{HostResolutionError, TangleHostRuntime, TenantRuntimeEntry},
    logging,
    nip11::{BaseRelayInfoConfig, BaseRelayInfoDocument, base_relay_info_response},
    ops::BaseRelayReadinessCheckStatus,
    session::TangleWebSocketSession,
};
use axum::{
    Json, Router,
    extract::{
        ConnectInfo, State,
        ws::{WebSocketUpgrade, rejection::WebSocketUpgradeRejection},
    },
    response::{IntoResponse, Response},
    routing::get,
};
use http::{HeaderMap, StatusCode};
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
    runtime: TangleHostRuntime,
) -> Result<TangleServeReport, BaseRelayError> {
    let listener = TcpListener::bind(runtime.config().host().listen_addr())
        .await
        .map_err(|error| BaseRelayError::error(error.to_string()))?;
    serve_listener_until_shutdown(runtime, listener).await
}

pub async fn serve_listener_until_shutdown(
    runtime: TangleHostRuntime,
    listener: TcpListener,
) -> Result<TangleServeReport, BaseRelayError> {
    let listen_addr = listener
        .local_addr()
        .map_err(|error| BaseRelayError::error(error.to_string()))?;
    for tenant in runtime.registry().active_tenants() {
        tenant
            .runtime()
            .readiness_handle()
            .set_server_bind(BaseRelayReadinessCheckStatus::Ready);
    }
    let shutdown_signal = runtime.shutdown_signal().clone();
    let router = tangle_http_router(runtime.clone());
    let mut shutdown = shutdown_signal.subscribe();
    logging::log_server_listening(listen_addr, "tangle-host");
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

pub fn tangle_http_router(runtime: TangleHostRuntime) -> Router {
    Router::new()
        .route("/", get(tangle_root))
        .route("/.well-known/tangle/ready", get(tangle_host_ready))
        .route("/.well-known/tangle/metrics", get(tangle_host_metrics))
        .route("/.well-known/tangle/tenants", get(tangle_host_tenants))
        .with_state(TangleHttpState { runtime })
}

#[derive(Debug, Clone)]
struct TangleHttpState {
    runtime: TangleHostRuntime,
}

async fn tangle_root(
    State(state): State<TangleHttpState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    websocket: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    headers: HeaderMap,
) -> Response {
    let tenant = match state.runtime.tenant_for_request(&headers, peer_addr) {
        Ok(tenant) => tenant.clone(),
        Err(error) => return error.into_response(),
    };
    match websocket {
        Ok(websocket) => {
            let connection = match state.runtime.resources().try_open_connection() {
                Ok(connection) => connection,
                Err(error) => {
                    return (StatusCode::TOO_MANY_REQUESTS, error.prefixed_message())
                        .into_response();
                }
            };
            let tenant_runtime = tenant.runtime().clone();
            let session = match tenant_runtime.auth_state().await {
                Ok(auth) => TangleWebSocketSession::new_with_peer_and_resources(
                    tenant_runtime.limits(),
                    state.runtime.shutdown_signal().subscribe(),
                    tenant_runtime.clone(),
                    auth,
                    tenant_runtime.subscribe_events().await,
                    Some(peer_addr.ip()),
                    Some(state.runtime.resources()),
                ),
                Err(error) => Err(error),
            };
            match session {
                Ok(session) => websocket
                    .protocols(["nostr"])
                    .on_upgrade(move |socket| async move {
                        let _connection = connection;
                        session.run(socket).await;
                    })
                    .into_response(),
                Err(error) => (
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    error.prefixed_message(),
                )
                    .into_response(),
            }
        }
        Err(_) => match tenant_info_document(&tenant) {
            Ok(info) => base_relay_info_response(info, headers),
            Err(error) => {
                (StatusCode::INTERNAL_SERVER_ERROR, error.prefixed_message()).into_response()
            }
        },
    }
}

async fn tangle_host_ready(State(state): State<TangleHttpState>) -> Response {
    if !state.runtime.config().host().ops().enabled() {
        return host_ops_disabled_response();
    }
    let readiness = state.runtime.readiness_state();
    let status = if readiness.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(serde_json::json!({
            "status": if readiness.is_ready() { "ready" } else { "not_ready" },
            "checks": {
                "config": readiness.config().as_str(),
                "tenant_registry": readiness.tenant_registry().as_str(),
                "active_tenants": readiness.active_tenants().as_str(),
                "shutdown_requested": readiness.shutdown_requested()
            }
        })),
    )
        .into_response()
}

async fn tangle_host_metrics(State(state): State<TangleHttpState>) -> Response {
    if !state.runtime.config().host().ops().enabled() {
        return host_ops_disabled_response();
    }
    let metrics = state.runtime.metrics_snapshot();
    let mut values = serde_json::Map::new();
    values.insert(
        "tangle_host_configured_tenants".to_owned(),
        serde_json::json!(metrics.configured_tenants()),
    );
    values.insert(
        "tangle_host_active_tenants".to_owned(),
        serde_json::json!(metrics.active_tenants()),
    );
    values.insert(
        "tangle_host_inactive_tenants".to_owned(),
        serde_json::json!(metrics.inactive_tenants()),
    );
    values.insert(
        "tangle_host_ws_connections_current".to_owned(),
        serde_json::json!(metrics.active_connections()),
    );
    values.insert(
        "tangle_host_subscriptions_current".to_owned(),
        serde_json::json!(metrics.active_subscriptions()),
    );
    values.insert(
        "tangle_host_ws_connections_limit".to_owned(),
        serde_json::json!(metrics.max_total_connections()),
    );
    values.insert(
        "tangle_host_subscriptions_limit".to_owned(),
        serde_json::json!(metrics.max_total_subscriptions()),
    );
    values.insert(
        "tangle_readiness_ready".to_owned(),
        serde_json::json!(state.runtime.readiness_state().is_ready()),
    );
    for tenant in state.runtime.registry().active_tenants() {
        let snapshot = tenant
            .runtime()
            .metrics()
            .snapshot_with_readiness(tenant.runtime().readiness_handle().snapshot().is_ready());
        let serde_json::Value::Object(snapshot) =
            serde_json::to_value(snapshot).expect("tenant metrics serialize")
        else {
            continue;
        };
        for (key, value) in snapshot {
            if key == "tangle_readiness_ready" {
                continue;
            }
            if let Some(value) = value.as_u64() {
                let current = values
                    .get(&key)
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                values.insert(key, serde_json::json!(current.saturating_add(value)));
            }
        }
    }
    Json(serde_json::Value::Object(values)).into_response()
}

async fn tangle_host_tenants(State(state): State<TangleHttpState>) -> Response {
    let ops = state.runtime.config().host().ops();
    if !ops.enabled() {
        return host_ops_disabled_response();
    }
    if !ops.expose_tenant_inventory() {
        return (
            StatusCode::NOT_FOUND,
            "tangle host tenant inventory is disabled",
        )
            .into_response();
    }
    let tenants = state
        .runtime
        .tenant_inventory()
        .into_iter()
        .map(|tenant| {
            serde_json::json!({
                "tenant_id": tenant.tenant_id().as_str(),
                "tenant_schema": tenant.tenant_schema().as_str(),
                "host": tenant.host().as_str(),
                "relay_url": tenant.relay_url().as_str(),
                "status": if tenant.active() { "active" } else { "inactive" },
                "ready": tenant.ready()
            })
        })
        .collect::<Vec<_>>();
    Json(serde_json::json!({ "tenants": tenants })).into_response()
}

fn host_ops_disabled_response() -> Response {
    (StatusCode::NOT_FOUND, "tangle host ops are disabled").into_response()
}

fn tenant_info_document(
    tenant: &TenantRuntimeEntry,
) -> Result<BaseRelayInfoDocument, BaseRelayError> {
    BaseRelayInfoConfig::from_tenant_config(tenant.config())?.build_document()
}

impl IntoResponse for HostResolutionError {
    fn into_response(self) -> Response {
        match self {
            Self::Missing => (StatusCode::BAD_REQUEST, "missing host").into_response(),
            Self::Invalid => (StatusCode::BAD_REQUEST, "invalid host").into_response(),
            Self::Unknown => (StatusCode::NOT_FOUND, "unknown host").into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{serve_until_shutdown, tangle_http_router};
    use crate::{
        config::{
            TangleHostRuntimeConfigSet, parse_tangle_host_runtime_config_json,
            parse_tenant_runtime_config_json,
        },
        host::TangleHostRuntime,
    };
    use axum::{
        body::{Body, to_bytes},
        extract::ConnectInfo,
    };
    use futures_util::{SinkExt, StreamExt};
    use http::{Request, header};
    use serde_json::json;
    use std::{
        net::SocketAddr,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };
    use tangle_crypto::RelaySigner;
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
        event_to_value,
    };
    use tangle_store_pocket::{
        PocketEvent, PocketKind, PocketOwnedEvent, PocketOwnedTags, PocketTime,
    };
    use tangle_test_support::FixtureKey;
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
        let runtime = host_runtime(&root);
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
        let runtime = host_runtime(&root);
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
        request.headers_mut().insert(
            header::HOST,
            http::HeaderValue::from_static("relay.radroots.test"),
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
        let runtime = host_runtime(&root);
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
        request.headers_mut().insert(
            header::HOST,
            http::HeaderValue::from_static("relay.radroots.test"),
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
        let runtime = host_runtime(&root);
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
        request.headers_mut().insert(
            header::HOST,
            http::HeaderValue::from_static("relay.radroots.test"),
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

        send_client_value(
            &mut socket,
            json!(["COUNT", "count-a", {"kinds":[1], "since": 1_714_124_433, "until": 1_714_124_433}]),
        )
        .await;
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

        send_client_value(
            &mut socket,
            json!(["REQ", "sub-search", {"search": "fresh carrots", "limit": 1}]),
        )
        .await;
        assert_eq!(
            read_relay_value(&mut socket).await,
            json!([
                "CLOSED",
                "sub-search",
                "unsupported: search filters are not supported"
            ])
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
    async fn tangle_http_router_serves_nip11_and_host_ops_routes() {
        let root = temp_root("http-router");
        let runtime = host_runtime(&root);
        for tenant in runtime.registry().active_tenants() {
            tenant
                .runtime()
                .readiness_handle()
                .set_server_bind(crate::ops::BaseRelayReadinessCheckStatus::Ready);
        }
        let router = tangle_http_router(runtime);
        let nip11 = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "relay.radroots.test")
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
                    .header(header::HOST, "relay.radroots.test")
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
                    .uri("/.well-known/tangle/ready")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("ready");
        let metrics = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/tangle/metrics")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("metrics");
        let tenants = router
            .oneshot(
                Request::builder()
                    .uri("/.well-known/tangle/tenants")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("tenants");

        assert_eq!(nip11.status(), http::StatusCode::OK);
        assert_eq!(
            nip11.headers().get(header::CONTENT_TYPE).expect("type"),
            "application/nostr+json"
        );
        let nip11_body = to_bytes(nip11.into_body(), usize::MAX).await.expect("body");
        let nip11_value = serde_json::from_slice::<serde_json::Value>(&nip11_body).expect("json");
        assert_eq!(nip11_value["name"], "Radroots Test Relay");
        assert_eq!(nip11_value["limitation"]["max_message_length"], 1_048_576);
        assert_eq!(nip11_value["limitation"]["max_subscriptions"], 64);
        assert_eq!(nip11_value["limitation"]["max_filters"], 10);
        assert_eq!(nip11_value["limitation"]["max_limit"], 500);
        assert_eq!(nip11_value["limitation"]["max_query_complexity"], 2_048);
        assert_eq!(nip11_value["limitation"]["max_subid_length"], 64);
        assert_eq!(nip11_value["limitation"]["max_event_tags"], 200);
        assert_eq!(nip11_value["limitation"]["max_content_length"], 65_536);
        assert_eq!(nip11_value["limitation"]["auth_required"], false);
        assert_eq!(nip11_value["limitation"]["payment_required"], false);
        assert_eq!(nip11_value["limitation"]["restricted_writes"], true);
        assert_eq!(nip11_value["limitation"]["default_limit"], 100);
        assert_eq!(nip11_value["retention"]["physical_erasure"], false);
        assert_eq!(nip11_value["retention"]["compaction_guarantee"], false);
        assert!(
            nip11_value["supported_nips"]
                .as_array()
                .expect("nips")
                .contains(&serde_json::json!(29))
        );
        assert_eq!(root_without_accept.status(), http::StatusCode::NOT_FOUND);
        assert_eq!(health.status(), http::StatusCode::NOT_FOUND);
        assert_eq!(ready.status(), http::StatusCode::OK);
        let ready_body = to_bytes(ready.into_body(), usize::MAX).await.expect("body");
        let ready_value = serde_json::from_slice::<serde_json::Value>(&ready_body).expect("json");
        assert_eq!(ready_value["checks"]["active_tenants"], "ready");
        assert_eq!(metrics.status(), http::StatusCode::OK);
        let metrics_body = to_bytes(metrics.into_body(), usize::MAX)
            .await
            .expect("body");
        let metrics_value =
            serde_json::from_slice::<serde_json::Value>(&metrics_body).expect("json");
        assert_eq!(metrics_value["tangle_readiness_ready"], true);
        assert_eq!(metrics_value["tangle_host_active_tenants"], 1);
        assert_eq!(metrics_value["tangle_ws_connections_current"], 0);
        assert_eq!(metrics_value["tangle_stored_event_offsets_total"], 0);
        assert_eq!(tenants.status(), http::StatusCode::OK);
        let tenants_body = to_bytes(tenants.into_body(), usize::MAX)
            .await
            .expect("body");
        let tenants_value =
            serde_json::from_slice::<serde_json::Value>(&tenants_body).expect("json");
        assert_eq!(tenants_value["tenants"][0]["tenant_id"], "test-relay");
        assert_eq!(tenants_value["tenants"][0]["ready"], true);
        let root_body = to_bytes(root_without_accept.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(
            String::from_utf8(root_body.to_vec()).expect("utf8"),
            "relay information requires application/nostr+json"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn tangle_http_router_enforces_host_ops_config() {
        let root = temp_root("http-router-ops-config");
        let _ = std::fs::remove_dir_all(&root);
        let inventory_enabled = ready_runtime(host_runtime_with_ops(&root, true, true));
        let inventory_disabled = ready_runtime(host_runtime_with_ops(&root, true, false));
        let ops_disabled = ready_runtime(host_runtime_with_ops(&root, false, true));

        let tenants = host_ops_response(
            &tangle_http_router(inventory_enabled),
            "/.well-known/tangle/tenants",
        )
        .await;
        assert_eq!(tenants.status(), http::StatusCode::OK);
        let tenants_json = response_json(tenants).await;
        assert_eq!(tenants_json["tenants"][0]["tenant_id"], "test-relay");

        let tenants = host_ops_response(
            &tangle_http_router(inventory_disabled),
            "/.well-known/tangle/tenants",
        )
        .await;
        assert_eq!(tenants.status(), http::StatusCode::NOT_FOUND);
        assert_eq!(
            response_text(tenants).await,
            "tangle host tenant inventory is disabled"
        );

        let router = tangle_http_router(ops_disabled);
        for path in [
            "/.well-known/tangle/ready",
            "/.well-known/tangle/metrics",
            "/.well-known/tangle/tenants",
        ] {
            let response = host_ops_response(&router, path).await;
            assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
            assert_eq!(
                response_text(response).await,
                "tangle host ops are disabled"
            );
        }

        let nip11 = nip11_response(&router, Some("relay.radroots.test"), None, 39_002).await;
        assert_eq!(nip11.status(), http::StatusCode::OK);
        let nip11_json = response_json(nip11).await;
        assert_eq!(nip11_json["name"], "Radroots Test Relay");

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn tangle_http_router_routes_by_host_and_fails_closed() {
        let root = temp_root("host-routing");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = multi_host_runtime(&root);
        for tenant in runtime.registry().active_tenants() {
            tenant
                .runtime()
                .readiness_handle()
                .set_server_bind(crate::ops::BaseRelayReadinessCheckStatus::Ready);
        }
        let router = tangle_http_router(runtime);

        let alpha = nip11_response(
            &router,
            Some("alpha.relay.test"),
            Some("beta.relay.test"),
            39_010,
        )
        .await;
        assert_eq!(alpha.status(), http::StatusCode::OK);
        let alpha = response_json(alpha).await;
        assert_eq!(alpha["name"], "Alpha Relay");

        let beta = nip11_response(&router, Some("beta.relay.test"), None, 39_011).await;
        assert_eq!(beta.status(), http::StatusCode::OK);
        let beta = response_json(beta).await;
        assert_eq!(beta["name"], "Beta Relay");

        let unknown = nip11_response(&router, Some("unknown.relay.test"), None, 39_012).await;
        assert_eq!(unknown.status(), http::StatusCode::NOT_FOUND);
        assert_eq!(response_text(unknown).await, "unknown host");

        let inactive = nip11_response(&router, Some("inactive.relay.test"), None, 39_013).await;
        assert_eq!(inactive.status(), http::StatusCode::NOT_FOUND);
        assert_eq!(response_text(inactive).await, "unknown host");

        let missing = nip11_response(&router, None, None, 39_014).await;
        assert_eq!(missing.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(response_text(missing).await, "missing host");

        for path in ["/healthz", "/readyz", "/metricsz"] {
            let legacy = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("legacy route");
            assert_eq!(legacy.status(), http::StatusCode::NOT_FOUND);
        }

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn websocket_auth_rejects_cross_tenant_relay_url() {
        let root = temp_root("cross-tenant-auth");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = multi_host_runtime(&root);
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
        request.headers_mut().insert(
            header::HOST,
            http::HeaderValue::from_static("beta.relay.test"),
        );
        let (mut socket, response) = tokio_tungstenite::connect_async(request)
            .await
            .expect("websocket");

        assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);
        let challenge = read_auth_challenge(&mut socket).await;
        let created_at = current_unix_timestamp();
        let alpha_auth = tangle_v2_auth_event_for_relay(
            FixtureKey::Owner,
            &challenge,
            created_at,
            "wss://alpha.relay.test",
        )
        .expect("alpha auth");
        let beta_auth = tangle_v2_auth_event_for_relay(
            FixtureKey::Owner,
            &challenge,
            created_at.saturating_add(1),
            "wss://beta.relay.test",
        )
        .expect("beta auth");

        send_client_value(&mut socket, json!(["AUTH", event_to_value(&alpha_auth)])).await;
        assert_eq!(
            read_relay_value(&mut socket).await,
            json!([
                "OK",
                alpha_auth.id().as_str(),
                false,
                "auth-required: auth relay does not match canonical relay URL"
            ])
        );

        send_client_value(&mut socket, json!(["AUTH", event_to_value(&beta_auth)])).await;
        assert_eq!(
            read_relay_value(&mut socket).await,
            json!(["OK", beta_auth.id().as_str(), true, ""])
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

    fn tangle_v2_event(
        key: FixtureKey,
        created_at: u64,
        kind: u64,
        tags: Vec<Tag>,
        content: &str,
    ) -> Result<Event, String> {
        let event = server_pocket_event(key, created_at, kind, tags, content);
        server_pocket_event_to_protocol(&event)
    }

    fn tangle_v2_auth_event(
        key: FixtureKey,
        challenge: &str,
        created_at: u64,
    ) -> Result<Event, String> {
        tangle_v2_auth_event_for_relay(key, challenge, created_at, "wss://relay.radroots.test")
    }

    fn tangle_v2_auth_event_for_relay(
        key: FixtureKey,
        challenge: &str,
        created_at: u64,
        relay_url: &str,
    ) -> Result<Event, String> {
        tangle_v2_event(
            key,
            created_at,
            22_242,
            vec![
                Tag::from_parts("relay", &[relay_url])?,
                Tag::from_parts("challenge", &[challenge])?,
            ],
            "",
        )
    }

    fn server_pocket_event(
        key: FixtureKey,
        created_at: u64,
        kind: u64,
        tags: Vec<Tag>,
        content: &str,
    ) -> PocketOwnedEvent {
        let tags = server_pocket_tags_from_protocol(&tags);
        let secret = format!("{:02x}", fixture_secret_byte(key)).repeat(32);
        RelaySigner::from_secret_hex(&secret)
            .expect("signer")
            .sign_pocket_event(
                PocketKind::from_u16(u16::try_from(kind).expect("pocket kind")),
                &tags,
                PocketTime::from_u64(created_at),
                content.as_bytes(),
            )
            .expect("pocket event")
    }

    fn server_pocket_tags_from_protocol(tags: &[Tag]) -> PocketOwnedTags {
        let parts = tags
            .iter()
            .map(|tag| tag.values().iter().map(String::as_str).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        PocketOwnedTags::new(&parts).expect("pocket tags")
    }

    fn server_pocket_event_to_protocol(event: &PocketEvent) -> Result<Event, String> {
        let tags = event
            .tags()
            .map_err(|error| error.to_string())?
            .iter()
            .map(|tag| {
                Tag::new(
                    tag.map(|value| {
                        std::str::from_utf8(value)
                            .map(str::to_owned)
                            .map_err(|error| error.to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                )
                .map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Event::new(
            EventId::new(&event.id().as_hex_string()).map_err(|error| error.to_string())?,
            UnsignedEvent::new(
                PublicKeyHex::new(&event.pubkey().as_hex_string())
                    .map_err(|error| error.to_string())?,
                UnixTimestamp::new(event.created_at().as_u64()),
                Kind::new(u64::from(event.kind().as_u16())).map_err(|error| error.to_string())?,
                tags,
                std::str::from_utf8(event.content()).map_err(|error| error.to_string())?,
            ),
            SignatureHex::new(&event.sig().to_string()).map_err(|error| error.to_string())?,
        ))
    }

    fn fixture_secret_byte(key: FixtureKey) -> u8 {
        match key {
            FixtureKey::Relay => 9,
            FixtureKey::Owner => 10,
            FixtureKey::Admin => 11,
            FixtureKey::Member => 12,
            FixtureKey::Outsider => 13,
        }
    }

    fn host_runtime(root: &Path) -> TangleHostRuntime {
        host_runtime_with_ops(root, true, true)
    }

    fn host_runtime_with_ops(
        root: &Path,
        ops_enabled: bool,
        expose_tenant_inventory: bool,
    ) -> TangleHostRuntime {
        host_runtime_from_tenants_with_host(
            host_config_value_with_ops(ops_enabled, expose_tenant_inventory),
            vec![tenant_config_value(
                root,
                TenantConfigFixture {
                    tenant_id: "test-relay",
                    tenant_schema: "test_relay",
                    host: "relay.radroots.test",
                    relay_url: "wss://relay.radroots.test",
                    name: "Radroots Test Relay",
                    inactive: false,
                    relay_secret_byte: 0x77,
                },
            )],
        )
    }

    fn multi_host_runtime(root: &Path) -> TangleHostRuntime {
        host_runtime_from_tenants(vec![
            tenant_config_value(
                root,
                TenantConfigFixture {
                    tenant_id: "alpha",
                    tenant_schema: "alpha_schema",
                    host: "alpha.relay.test",
                    relay_url: "wss://alpha.relay.test",
                    name: "Alpha Relay",
                    inactive: false,
                    relay_secret_byte: 0x77,
                },
            ),
            tenant_config_value(
                root,
                TenantConfigFixture {
                    tenant_id: "beta",
                    tenant_schema: "beta_schema",
                    host: "beta.relay.test",
                    relay_url: "wss://beta.relay.test",
                    name: "Beta Relay",
                    inactive: false,
                    relay_secret_byte: 0x88,
                },
            ),
            tenant_config_value(
                root,
                TenantConfigFixture {
                    tenant_id: "inactive",
                    tenant_schema: "inactive_schema",
                    host: "inactive.relay.test",
                    relay_url: "wss://inactive.relay.test",
                    name: "Inactive Relay",
                    inactive: true,
                    relay_secret_byte: 0x99,
                },
            ),
        ])
    }

    fn host_runtime_from_tenants(tenant_values: Vec<serde_json::Value>) -> TangleHostRuntime {
        host_runtime_from_tenants_with_host(host_config_value(), tenant_values)
    }

    fn host_runtime_from_tenants_with_host(
        host_value: serde_json::Value,
        tenant_values: Vec<serde_json::Value>,
    ) -> TangleHostRuntime {
        let host =
            parse_tangle_host_runtime_config_json(&host_value.to_string()).expect("host config");
        let tenants = tenant_values
            .into_iter()
            .map(|tenant| parse_tenant_runtime_config_json(&tenant.to_string()).expect("tenant"))
            .collect::<Vec<_>>();
        let config = TangleHostRuntimeConfigSet::new(host, tenants).expect("config set");
        TangleHostRuntime::open(config).expect("host runtime")
    }

    fn host_config_value() -> serde_json::Value {
        host_config_value_with_ops(true, true)
    }

    fn host_config_value_with_ops(
        ops_enabled: bool,
        expose_tenant_inventory: bool,
    ) -> serde_json::Value {
        json!({
            "listen_addr": "127.0.0.1:0",
            "tenant_config_dir": "tenants",
            "limits": {
                "max_total_connections": 64,
                "max_total_subscriptions": 256,
                "tenant_startup_concurrency": 4
            },
            "ops": {
                "enabled": ops_enabled,
                "expose_tenant_inventory": expose_tenant_inventory
            }
        })
    }

    struct TenantConfigFixture<'a> {
        tenant_id: &'a str,
        tenant_schema: &'a str,
        host: &'a str,
        relay_url: &'a str,
        name: &'a str,
        inactive: bool,
        relay_secret_byte: u8,
    }

    fn tenant_config_value(root: &Path, fixture: TenantConfigFixture<'_>) -> serde_json::Value {
        let relay_secret = format!("{:02x}", fixture.relay_secret_byte).repeat(32);
        json!({
            "tenant_id": fixture.tenant_id,
            "tenant_schema": fixture.tenant_schema,
            "host": fixture.host,
            "relay_url": fixture.relay_url,
            "inactive": fixture.inactive,
            "info": {
                "name": fixture.name
            },
            "pocket": {
                "data_directory": root.join(format!("{}-pocket", fixture.tenant_id)),
                "sync_policy": "flush_on_shutdown",
            },
            "pocket_query": {
              "allow_scraping": false,
              "allow_scrape_if_limited_to": 100,
              "allow_scrape_if_max_seconds": 3600
            },
            "groups": {
                "enabled": true,
                "canonical_relay_url": fixture.relay_url,
                "relay_secret": relay_secret,
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
                "max_query_complexity": 2048,
                "max_limit": 500,
                "default_limit": 100,
                "max_event_tags": 200,
                "max_content_length": 65536,
                "broadcast_channel_capacity": 8,
                "per_connection_outbound_queue": 8
            },
            "rate_limits": {
                "auth": {
                    "per_ip": {"window_seconds": 60, "max_hits": 120},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 30},
                    "failures": {"window_seconds": 300, "max_hits": 5},
                    "failures_per_ip": {"window_seconds": 300, "max_hits": 20}
                },
                "event": {
                    "per_ip": {"window_seconds": 60, "max_hits": 600},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 120},
                    "per_kind": {"window_seconds": 60, "max_hits": 1000}
                },
                "group": {
                    "write_per_ip": {"window_seconds": 60, "max_hits": 300},
                    "write_per_pubkey": {"window_seconds": 60, "max_hits": 60},
                    "write_per_group": {"window_seconds": 60, "max_hits": 90},
                    "write_per_kind": {"window_seconds": 60, "max_hits": 300},
                    "join_flow": {"window_seconds": 300, "max_hits": 10},
                    "join_flow_per_ip": {"window_seconds": 300, "max_hits": 30}
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
    }

    async fn nip11_response(
        router: &axum::Router,
        host: Option<&str>,
        forwarded_host: Option<&str>,
        peer_port: u16,
    ) -> http::Response<Body> {
        let mut builder = Request::builder()
            .uri("/")
            .header(header::ACCEPT, "application/nostr+json")
            .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], peer_port))));
        if let Some(host) = host {
            builder = builder.header(header::HOST, host);
        }
        if let Some(forwarded_host) = forwarded_host {
            builder = builder.header("x-forwarded-host", forwarded_host);
        }
        router
            .clone()
            .oneshot(builder.body(Body::empty()).expect("request"))
            .await
            .expect("response")
    }

    async fn host_ops_response(router: &axum::Router, path: &str) -> http::Response<Body> {
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response")
    }

    fn ready_runtime(runtime: TangleHostRuntime) -> TangleHostRuntime {
        for tenant in runtime.registry().active_tenants() {
            tenant
                .runtime()
                .readiness_handle()
                .set_server_bind(crate::ops::BaseRelayReadinessCheckStatus::Ready);
        }
        runtime
    }

    async fn response_json(response: http::Response<Body>) -> serde_json::Value {
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice::<serde_json::Value>(&body).expect("json")
    }

    async fn response_text(response: http::Response<Body>) -> String {
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        String::from_utf8(body.to_vec()).expect("utf8")
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
