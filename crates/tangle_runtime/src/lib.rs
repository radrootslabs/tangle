#![forbid(unsafe_code)]

use axum::{
    Json, Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
};
use core::fmt;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};

pub const TANGLE_SUPPORTED_NIPS: [u16; 8] = [1, 9, 11, 16, 33, 42, 50, 99];
pub const TANGLE_RELAY_SOFTWARE: &str = "https://github.com/radrootslabs/tangle";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiErrorCode {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Internal,
}

impl ApiErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Internal => "internal_error",
        }
    }

    pub fn http_status(self) -> u16 {
        match self {
            Self::InvalidRequest => 400,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::Internal => 500,
        }
    }
}

impl fmt::Display for ApiErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    code: ApiErrorCode,
    message: String,
}

impl ApiError {
    pub fn new(code: ApiErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(ApiErrorCode::InvalidRequest, message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(ApiErrorCode::Unauthorized, message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(ApiErrorCode::Forbidden, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ApiErrorCode::NotFound, message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ApiErrorCode::Conflict, message)
    }

    pub fn internal() -> Self {
        Self::new(ApiErrorCode::Internal, "internal server error")
    }

    pub fn code(&self) -> ApiErrorCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn http_status(&self) -> u16 {
        self.code.http_status()
    }

    pub fn envelope(&self) -> ApiErrorEnvelope {
        ApiErrorEnvelope {
            error: ApiErrorBody {
                code: self.code.as_str().to_owned(),
                message: self.message.clone(),
            },
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self.envelope())).into_response()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorEnvelope {
    pub error: ApiErrorBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessCheckStatus {
    Ready,
    NotReady,
}

impl ReadinessCheckStatus {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadinessState {
    pub database: ReadinessCheckStatus,
    pub migrations: ReadinessCheckStatus,
    pub repository: ReadinessCheckStatus,
}

impl ReadinessState {
    pub fn new(
        database: ReadinessCheckStatus,
        migrations: ReadinessCheckStatus,
        repository: ReadinessCheckStatus,
    ) -> Self {
        Self {
            database,
            migrations,
            repository,
        }
    }

    pub fn ready() -> Self {
        Self::new(
            ReadinessCheckStatus::Ready,
            ReadinessCheckStatus::Ready,
            ReadinessCheckStatus::Ready,
        )
    }

    pub fn is_ready(self) -> bool {
        self.database.is_ready() && self.migrations.is_ready() && self.repository.is_ready()
    }

    pub fn response(self) -> ReadinessDocument {
        ReadinessDocument {
            status: if self.is_ready() {
                "ready".to_owned()
            } else {
                "not_ready".to_owned()
            },
            checks: ReadinessChecksDocument {
                database: self.database.as_str().to_owned(),
                migrations: self.migrations.as_str().to_owned(),
                repository: self.repository.as_str().to_owned(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthDocument {
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessDocument {
    pub status: String,
    pub checks: ReadinessChecksDocument,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessChecksDocument {
    pub database: String,
    pub migrations: String,
    pub repository: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayInfoDocument {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    pub supported_nips: Vec<u16>,
    pub software: String,
    pub version: String,
    pub limitation: RelayInfoLimitationDocument,
}

impl RelayInfoDocument {
    pub fn tangle_default() -> Self {
        Self {
            id: None,
            name: "tangle".to_owned(),
            description: Some("SurrealDB-backed Nostr relay for NIP-99 marketplaces".to_owned()),
            pubkey: None,
            contact: None,
            icon: None,
            supported_nips: TANGLE_SUPPORTED_NIPS.to_vec(),
            software: TANGLE_RELAY_SOFTWARE.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            limitation: RelayInfoLimitationDocument {
                payment_required: false,
                restricted_writes: true,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayInfoLimitationDocument {
    pub payment_required: bool,
    pub restricted_writes: bool,
}

pub fn health_router(readiness: ReadinessState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(readiness)
}

pub fn relay_info_router(document: RelayInfoDocument) -> Router {
    Router::new()
        .route("/", get(relay_info))
        .with_state(document)
}

async fn healthz() -> Json<HealthDocument> {
    Json(HealthDocument {
        status: "ok".to_owned(),
    })
}

async fn readyz(State(readiness): State<ReadinessState>) -> (StatusCode, Json<ReadinessDocument>) {
    let status = if readiness.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(readiness.response()))
}

async fn relay_info(State(relay_info): State<RelayInfoDocument>, headers: HeaderMap) -> Response {
    if !accepts_nostr_json(headers.get(header::ACCEPT)) {
        return ApiError::not_found("relay information requires application/nostr+json")
            .into_response();
    }
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/nostr+json"),
        )],
        Json(relay_info),
    )
        .into_response()
}

fn accepts_nostr_json(value: Option<&HeaderValue>) -> bool {
    value
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|part| {
                part.split(';').next().is_some_and(|media_type| {
                    media_type
                        .trim()
                        .eq_ignore_ascii_case("application/nostr+json")
                })
            })
        })
}

#[cfg(test)]
mod tests {
    use super::{
        ApiError, ApiErrorBody, ApiErrorCode, ApiErrorEnvelope, ReadinessCheckStatus,
        ReadinessState, RelayInfoDocument, TANGLE_RELAY_SOFTWARE, TANGLE_SUPPORTED_NIPS,
        health_router, relay_info_router,
    };
    use axum::{body::Body, response::IntoResponse};
    use http::{HeaderValue, Request, StatusCode, header};
    use tower::ServiceExt;

    #[test]
    fn api_error_codes_have_stable_labels_and_statuses() {
        let cases = [
            (ApiErrorCode::InvalidRequest, "invalid_request", 400),
            (ApiErrorCode::Unauthorized, "unauthorized", 401),
            (ApiErrorCode::Forbidden, "forbidden", 403),
            (ApiErrorCode::NotFound, "not_found", 404),
            (ApiErrorCode::Conflict, "conflict", 409),
            (ApiErrorCode::Internal, "internal_error", 500),
        ];
        for (code, label, status) in cases {
            assert_eq!(code.as_str(), label);
            assert_eq!(code.to_string(), label);
            assert_eq!(code.http_status(), status);
        }
    }

    #[test]
    fn api_error_constructors_preserve_public_envelope_shape() {
        let errors = [
            ApiError::invalid_request("bad query"),
            ApiError::unauthorized("authentication required"),
            ApiError::forbidden("admin role required"),
            ApiError::not_found("listing not found"),
            ApiError::conflict("event already exists"),
            ApiError::internal(),
        ];
        assert_eq!(errors[0].http_status(), 400);
        assert_eq!(errors[1].http_status(), 401);
        assert_eq!(errors[2].http_status(), 403);
        assert_eq!(errors[3].http_status(), 404);
        assert_eq!(errors[4].http_status(), 409);
        assert_eq!(errors[5].http_status(), 500);
        assert_eq!(errors[0].code(), ApiErrorCode::InvalidRequest);
        assert_eq!(errors[0].message(), "bad query");
        assert_eq!(errors[0].to_string(), "invalid_request: bad query");
        assert_eq!(
            errors[5].envelope(),
            ApiErrorEnvelope {
                error: ApiErrorBody {
                    code: "internal_error".to_owned(),
                    message: "internal server error".to_owned()
                }
            }
        );
        assert_eq!(
            serde_json::to_value(errors[0].envelope()).expect("json"),
            serde_json::json!({
                "error": {
                    "code": "invalid_request",
                    "message": "bad query"
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<ApiErrorEnvelope>(serde_json::json!({
                "error": {
                    "code": "invalid_request",
                    "message": "bad query"
                }
            }))
            .expect("envelope"),
            errors[0].envelope()
        );
    }

    #[tokio::test]
    async fn api_error_into_response_keeps_public_envelope_shape() {
        let response = ApiError::not_found("listing not found").into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("json"),
            serde_json::json!({
                "error": {
                    "code": "not_found",
                    "message": "listing not found"
                }
            })
        );
    }

    #[tokio::test]
    async fn health_endpoint_reports_liveness() {
        let response = health_router(ReadinessState::ready())
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("json"),
            serde_json::json!({ "status": "ok" })
        );
    }

    #[tokio::test]
    async fn readiness_endpoint_reports_ready_checks() {
        let response = health_router(ReadinessState::ready())
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("json"),
            serde_json::json!({
                "status": "ready",
                "checks": {
                    "database": "ready",
                    "migrations": "ready",
                    "repository": "ready"
                }
            })
        );
    }

    #[tokio::test]
    async fn readiness_endpoint_reports_unavailable_checks() {
        let response = health_router(ReadinessState::new(
            ReadinessCheckStatus::NotReady,
            ReadinessCheckStatus::Ready,
            ReadinessCheckStatus::NotReady,
        ))
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("json"),
            serde_json::json!({
                "status": "not_ready",
                "checks": {
                    "database": "not_ready",
                    "migrations": "ready",
                    "repository": "not_ready"
                }
            })
        );
    }

    #[test]
    fn relay_info_default_matches_mvp_protocol_claims() {
        let relay_info = RelayInfoDocument::tangle_default();
        assert_eq!(relay_info.name, "tangle");
        assert_eq!(relay_info.supported_nips, TANGLE_SUPPORTED_NIPS);
        assert_eq!(relay_info.software, TANGLE_RELAY_SOFTWARE);
        assert_eq!(relay_info.version, "0.1.0");
        assert_eq!(relay_info.limitation.payment_required, false);
        assert_eq!(relay_info.limitation.restricted_writes, true);
        assert_eq!(
            serde_json::to_value(relay_info).expect("json"),
            serde_json::json!({
                "name": "tangle",
                "description": "SurrealDB-backed Nostr relay for NIP-99 marketplaces",
                "supported_nips": [1, 9, 11, 16, 33, 42, 50, 99],
                "software": "https://github.com/radrootslabs/tangle",
                "version": "0.1.0",
                "limitation": {
                    "payment_required": false,
                    "restricted_writes": true
                }
            })
        );
    }

    #[tokio::test]
    async fn relay_info_endpoint_requires_nostr_accept_header() {
        let response = relay_info_router(RelayInfoDocument::tangle_default())
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("json"),
            serde_json::json!({
                "error": {
                    "code": "not_found",
                    "message": "relay information requires application/nostr+json"
                }
            })
        );
    }

    #[tokio::test]
    async fn relay_info_endpoint_serves_nip11_document_for_nostr_accept() {
        let response = relay_info_router(RelayInfoDocument::tangle_default())
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(
                        header::ACCEPT,
                        "text/plain, APPLICATION/NOSTR+JSON; charset=utf-8",
                    )
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .expect("content-type"),
            HeaderValue::from_static("application/nostr+json")
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("json"),
            serde_json::json!({
                "name": "tangle",
                "description": "SurrealDB-backed Nostr relay for NIP-99 marketplaces",
                "supported_nips": [1, 9, 11, 16, 33, 42, 50, 99],
                "software": "https://github.com/radrootslabs/tangle",
                "version": "0.1.0",
                "limitation": {
                    "payment_required": false,
                    "restricted_writes": true
                }
            })
        );
    }

    #[tokio::test]
    async fn relay_info_endpoint_rejects_invalid_accept_header() {
        let response = relay_info_router(RelayInfoDocument::tangle_default())
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(
                        header::ACCEPT,
                        HeaderValue::from_bytes(b"\xff").expect("header"),
                    )
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
