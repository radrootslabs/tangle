#![forbid(unsafe_code)]

use axum::{
    Json, Router,
    extract::ws::WebSocketUpgrade,
    extract::{Path, RawQuery, State},
    response::{IntoResponse, Response},
    routing::get,
};
use core::fmt;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};
use tangle_core::{
    AuthChallengeState, FixedWindowRateLimiter, MarketplaceListingStatus, MarketplaceQuery,
    MarketplaceQueryError, MarketplaceQuerySpec, MarketplaceSort, RateLimitConfig, RuntimeLimits,
    SubscriptionManager, SubscriptionMatcher,
};
use tangle_nips::{FulfillmentMethod, ListingUnit};
use tangle_protocol::{EventId, PublicKeyHex};
use tangle_store_surreal::{ListingProjectionQuery, SearchDocumentQuery, SurrealStore};
use url::form_urlencoded;

pub const TANGLE_SUPPORTED_NIPS: [u16; 8] = [1, 9, 11, 16, 33, 42, 50, 99];
pub const TANGLE_RELAY_SOFTWARE: &str = "https://github.com/radrootslabs/tangle";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelayConnectionId(String);

impl RelayConnectionId {
    pub const MAX_LENGTH: usize = 128;

    pub fn new(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if value.is_empty() {
            return Err("connection id must not be empty".to_owned());
        }
        if value.len() > Self::MAX_LENGTH {
            return Err(format!(
                "connection id must be at most {} bytes, got {}",
                Self::MAX_LENGTH,
                value.len()
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RelayConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConnectionConfig {
    relay_url: String,
    auth_ttl_seconds: u64,
    message_rate_limit: RateLimitConfig,
    runtime_limits: RuntimeLimits,
}

impl RelayConnectionConfig {
    pub fn new(
        relay_url: impl Into<String>,
        auth_ttl_seconds: u64,
        message_rate_limit: RateLimitConfig,
        runtime_limits: RuntimeLimits,
    ) -> Result<Self, String> {
        let relay_url = relay_url.into();
        let auth = AuthChallengeState::new(&relay_url, auth_ttl_seconds)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            relay_url: auth.relay_url().to_owned(),
            auth_ttl_seconds,
            message_rate_limit,
            runtime_limits,
        })
    }

    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    pub fn auth_ttl_seconds(&self) -> u64 {
        self.auth_ttl_seconds
    }

    pub fn message_rate_limit(&self) -> RateLimitConfig {
        self.message_rate_limit
    }

    pub fn runtime_limits(&self) -> RuntimeLimits {
        self.runtime_limits
    }
}

impl Default for RelayConnectionConfig {
    fn default() -> Self {
        Self::new(
            "wss://relay.radroots.test",
            300,
            RateLimitConfig::new(120, 60).expect("default message rate limit is valid"),
            RuntimeLimits::default(),
        )
        .expect("default relay connection config is valid")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConnection {
    id: RelayConnectionId,
    remote_addr: Option<String>,
    subscriptions: SubscriptionManager,
    auth: AuthChallengeState,
    rate_limiter: FixedWindowRateLimiter,
}

impl RelayConnection {
    pub fn new(id: RelayConnectionId, config: RelayConnectionConfig) -> Self {
        Self {
            id,
            remote_addr: None,
            subscriptions: SubscriptionManager::new(
                config.runtime_limits(),
                SubscriptionMatcher::default(),
            ),
            auth: AuthChallengeState::new(config.relay_url(), config.auth_ttl_seconds())
                .expect("connection config validates auth state"),
            rate_limiter: FixedWindowRateLimiter::new(config.message_rate_limit()),
        }
    }

    pub fn id(&self) -> &RelayConnectionId {
        &self.id
    }

    pub fn remote_addr(&self) -> Option<&str> {
        self.remote_addr.as_deref()
    }

    pub fn set_remote_addr(&mut self, remote_addr: impl Into<String>) {
        self.remote_addr = Some(remote_addr.into());
    }

    pub fn subscriptions(&self) -> &SubscriptionManager {
        &self.subscriptions
    }

    pub fn subscriptions_mut(&mut self) -> &mut SubscriptionManager {
        &mut self.subscriptions
    }

    pub fn auth(&self) -> &AuthChallengeState {
        &self.auth
    }

    pub fn auth_mut(&mut self) -> &mut AuthChallengeState {
        &mut self.auth
    }

    pub fn rate_limiter(&self) -> &FixedWindowRateLimiter {
        &self.rate_limiter
    }

    pub fn rate_limiter_mut(&mut self) -> &mut FixedWindowRateLimiter {
        &mut self.rate_limiter
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketHttpState {
    connection_config: RelayConnectionConfig,
}

impl WebSocketHttpState {
    pub fn new(connection_config: RelayConnectionConfig) -> Self {
        Self { connection_config }
    }

    pub fn connection_config(&self) -> &RelayConnectionConfig {
        &self.connection_config
    }
}

impl Default for WebSocketHttpState {
    fn default() -> Self {
        Self::new(RelayConnectionConfig::default())
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingHttpQuery {
    marketplace: MarketplaceQuery,
    geohash: Option<String>,
}

impl ListingHttpQuery {
    pub fn marketplace(&self) -> &MarketplaceQuery {
        &self.marketplace
    }

    pub fn geohash(&self) -> Option<&str> {
        self.geohash.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarketplaceSearchHttpQuery {
    text: Option<String>,
    seller: Option<PublicKeyHex>,
    limit: u64,
}

impl MarketplaceSearchHttpQuery {
    pub fn text(&self) -> Option<&str> {
        self.text.as_deref()
    }

    pub fn seller(&self) -> Option<&PublicKeyHex> {
        self.seller.as_ref()
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }
}

#[derive(Debug, Clone)]
pub struct ListingsHttpState {
    store: SurrealStore,
    limits: RuntimeLimits,
}

impl ListingsHttpState {
    pub fn new(store: SurrealStore, limits: RuntimeLimits) -> Self {
        Self { store, limits }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingsDocument {
    pub items: Vec<ListingItemDocument>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingItemDocument {
    pub listing_key: String,
    pub event_id: String,
    pub seller_pubkey: String,
    pub d: String,
    pub title: String,
    pub summary: Option<String>,
    pub price: ListingPriceDocument,
    pub location: ListingLocationDocument,
    pub fulfillment: Vec<String>,
    pub status: String,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingPriceDocument {
    pub amount: String,
    pub currency: String,
    pub unit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingLocationDocument {
    pub text: Option<String>,
    pub geohash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingDetailDocument {
    pub listing: ListingItemDocument,
    pub raw_event: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SellerDocument {
    pub pubkey: String,
    pub approved: bool,
    pub blocked: bool,
    pub active_listing_count: u64,
}

pub fn parse_listing_query(
    query: &str,
    limits: RuntimeLimits,
) -> Result<ListingHttpQuery, ApiError> {
    let mut spec = MarketplaceQuerySpec {
        statuses: vec![MarketplaceListingStatus::Active],
        ..MarketplaceQuerySpec::default()
    };
    let mut geohash = None;
    let mut saw_status = false;
    let mut saw_sort = false;
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        let value = value.into_owned();
        match key.as_ref() {
            "category" => push_text_values("category", &value, &mut spec.categories)?,
            "seller" => set_once("seller", &mut spec.seller, parse_pubkey("seller", &value)?)?,
            "status" => {
                if !saw_status {
                    spec.statuses.clear();
                    saw_status = true;
                }
                push_status_values(&value, &mut spec.statuses)?;
            }
            "currency" => push_text_values("currency", &value, &mut spec.currencies)?,
            "unit" => push_unit_values(&value, &mut spec.units)?,
            "min_price" => set_once(
                "min_price",
                &mut spec.min_price,
                required_value("min_price", &value)?,
            )?,
            "max_price" => set_once(
                "max_price",
                &mut spec.max_price,
                required_value("max_price", &value)?,
            )?,
            "fulfillment" => push_fulfillment_values(&value, &mut spec.fulfillment)?,
            "delivery_only" => set_once(
                "delivery_only",
                &mut spec.delivery_only,
                parse_bool("delivery_only", &value)?,
            )?,
            "pickup" => set_once("pickup", &mut spec.pickup, parse_bool("pickup", &value)?)?,
            "geohash" => set_once("geohash", &mut geohash, parse_geohash_query_value(&value)?)?,
            "lat" => set_once(
                "lat",
                &mut spec.latitude_microdegrees,
                parse_microdegrees("lat", &value, -90_000_000, 90_000_000)?,
            )?,
            "lon" => set_once(
                "lon",
                &mut spec.longitude_microdegrees,
                parse_microdegrees("lon", &value, -180_000_000, 180_000_000)?,
            )?,
            "radius_km" => set_once(
                "radius_km",
                &mut spec.radius_meters,
                parse_radius_meters(&value)?,
            )?,
            "near" => set_once("near", &mut spec.near, required_value("near", &value)?)?,
            "sort" => {
                if saw_sort {
                    return Err(invalid_parameter("sort", "must not be repeated"));
                }
                saw_sort = true;
                spec.sort = parse_sort(&value)?;
            }
            "limit" => set_once("limit", &mut spec.limit, parse_limit(&value)?)?,
            "cursor" => {
                return Err(invalid_parameter(
                    "cursor",
                    "signed cursor decoding is not implemented",
                ));
            }
            unsupported => {
                return Err(ApiError::invalid_request(format!(
                    "query parameter `{unsupported}` is unsupported"
                )));
            }
        }
    }
    let marketplace = MarketplaceQuery::from_spec(spec, limits).map_err(ApiError::from)?;
    Ok(ListingHttpQuery {
        marketplace,
        geohash,
    })
}

pub fn parse_marketplace_search_query(
    query: &str,
    limits: RuntimeLimits,
) -> Result<MarketplaceSearchHttpQuery, ApiError> {
    let mut text = None;
    let mut seller = None;
    let mut status = None;
    let mut sort = None;
    let mut limit = None;
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        let value = value.into_owned();
        match key.as_ref() {
            "q" => set_once("q", &mut text, required_value("q", &value)?)?,
            "seller" => set_once("seller", &mut seller, parse_pubkey("seller", &value)?)?,
            "status" => set_once("status", &mut status, parse_status(&value)?)?,
            "sort" => set_once("sort", &mut sort, parse_sort(&value)?)?,
            "limit" => set_once("limit", &mut limit, parse_limit(&value)?)?,
            "category" | "currency" | "unit" | "min_price" | "max_price" | "fulfillment"
            | "delivery_only" | "pickup" | "lat" | "lon" | "radius_km" | "near" | "cursor" => {
                return Err(ApiError::invalid_request(format!(
                    "{} is not supported by marketplace search",
                    key.as_ref()
                )));
            }
            unsupported => {
                return Err(ApiError::invalid_request(format!(
                    "query parameter `{unsupported}` is unsupported"
                )));
            }
        }
    }
    limits
        .validate_search_query(text.as_deref().unwrap_or_default())
        .map_err(|violation| ApiError::invalid_request(format!("runtime limit: {violation}")))?;
    let status = status.unwrap_or(MarketplaceListingStatus::Active);
    if status != MarketplaceListingStatus::Active {
        return Err(invalid_parameter(
            "status",
            "must be active for marketplace search",
        ));
    }
    let expected_sort = if text.is_some() {
        MarketplaceSort::Relevance
    } else {
        MarketplaceSort::Freshness
    };
    if sort.is_some_and(|sort| sort != expected_sort) {
        return Err(invalid_parameter(
            "sort",
            "does not match marketplace search mode",
        ));
    }
    let limit = limit.unwrap_or(MarketplaceQuery::DEFAULT_LIMIT);
    if limit == 0 || limit > MarketplaceQuery::MAX_LIMIT {
        return Err(invalid_parameter("limit", "must be between 1 and 100"));
    }
    Ok(MarketplaceSearchHttpQuery {
        text,
        seller,
        limit,
    })
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

pub fn websocket_router(state: WebSocketHttpState) -> Router {
    Router::new()
        .route("/", get(websocket_upgrade))
        .with_state(state)
}

pub fn listings_router(state: ListingsHttpState) -> Router {
    Router::new()
        .route("/api/listings", get(listings))
        .route("/api/listings/{pubkey}/{d}", get(listing_detail))
        .route("/api/search", get(marketplace_search))
        .route("/api/sellers/{pubkey}", get(seller_detail))
        .with_state(state)
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

async fn websocket_upgrade(
    State(state): State<WebSocketHttpState>,
    websocket: WebSocketUpgrade,
) -> Response {
    websocket
        .on_upgrade(move |_socket| async move {
            let _connection_config = state.connection_config;
        })
        .into_response()
}

async fn listings(
    State(state): State<ListingsHttpState>,
    RawQuery(query): RawQuery,
) -> Result<Json<ListingsDocument>, ApiError> {
    let parsed = parse_listing_query(query.as_deref().unwrap_or_default(), state.limits)?;
    let store_query = listing_projection_query(&parsed)?;
    let rows = state
        .store
        .query_current_listings(&store_query)
        .await
        .map_err(|_| ApiError::internal())?;
    let items = rows
        .iter()
        .map(listing_item_document)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(ListingsDocument {
        items,
        next_cursor: None,
    }))
}

async fn listing_detail(
    State(state): State<ListingsHttpState>,
    Path((pubkey, d)): Path<(String, String)>,
) -> Result<Json<ListingDetailDocument>, ApiError> {
    let pubkey = parse_pubkey("pubkey", &pubkey)?;
    let d = required_value("d", &d)?;
    let listing_key = format!("30402:{}:{d}", pubkey.as_str());
    let row = state
        .store
        .listing_current_row(&listing_key)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(|| ApiError::not_found("listing not found"))?;
    if bool_field(&row, "hidden")? || bool_field(&row, "deleted")? {
        return Err(ApiError::not_found("listing not found"));
    }
    let event_id =
        EventId::new(&string_field(&row, "event_id")?).map_err(|_| ApiError::internal())?;
    let raw_row = state
        .store
        .raw_event_row(&event_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::internal)?;
    if bool_field(&raw_row, "hidden")? || bool_field(&raw_row, "deleted")? {
        return Err(ApiError::not_found("listing not found"));
    }
    let raw_event = serde_json::from_str(&string_field(&raw_row, "raw_json")?)
        .map_err(|_| ApiError::internal())?;
    Ok(Json(ListingDetailDocument {
        listing: listing_item_document(&row)?,
        raw_event,
    }))
}

async fn marketplace_search(
    State(state): State<ListingsHttpState>,
    RawQuery(query): RawQuery,
) -> Result<Json<ListingsDocument>, ApiError> {
    let parsed =
        parse_marketplace_search_query(query.as_deref().unwrap_or_default(), state.limits)?;
    let search_query = search_document_query(&parsed);
    let docs = state
        .store
        .query_search_documents(&search_query)
        .await
        .map_err(|_| ApiError::internal())?;
    let mut items = Vec::new();
    for doc in docs {
        let Some(address_key) = optional_string_field(&doc, "address_key")? else {
            continue;
        };
        let Some(row) = state
            .store
            .listing_current_row(&address_key)
            .await
            .map_err(|_| ApiError::internal())?
        else {
            continue;
        };
        if bool_field(&row, "hidden")? || bool_field(&row, "deleted")? {
            continue;
        }
        items.push(listing_item_document(&row)?);
    }
    Ok(Json(ListingsDocument {
        items,
        next_cursor: None,
    }))
}

async fn seller_detail(
    State(state): State<ListingsHttpState>,
    Path(pubkey): Path<String>,
) -> Result<Json<SellerDocument>, ApiError> {
    let pubkey = parse_pubkey("pubkey", &pubkey)?;
    let seller = seller_policy_row(&state.store, pubkey.as_str()).await?;
    let listings = state
        .store
        .query_current_listings(
            &ListingProjectionQuery::new()
                .with_effective_status("active")
                .with_seller_pubkey(pubkey.as_str()),
        )
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(SellerDocument {
        pubkey: pubkey.as_str().to_owned(),
        approved: seller
            .as_ref()
            .and_then(|row| row.get("seller_approved"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        blocked: seller
            .as_ref()
            .and_then(|row| row.get("blocked"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        active_listing_count: listings.len() as u64,
    }))
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

fn listing_projection_query(parsed: &ListingHttpQuery) -> Result<ListingProjectionQuery, ApiError> {
    let query = parsed.marketplace();
    if !query.categories.is_empty() {
        return Err(invalid_parameter(
            "category",
            "is not supported by the listings endpoint",
        ));
    }
    if parsed.geohash().is_some() {
        return Err(invalid_parameter(
            "geohash",
            "is not supported by the listings endpoint",
        ));
    }
    if !query.fulfillment.is_empty() {
        return Err(invalid_parameter(
            "fulfillment",
            "is not supported by the listings endpoint",
        ));
    }
    if query.delivery_only.is_some() {
        return Err(invalid_parameter(
            "delivery_only",
            "is not supported by the listings endpoint",
        ));
    }
    if query.pickup.is_some() {
        return Err(invalid_parameter(
            "pickup",
            "is not supported by the listings endpoint",
        ));
    }
    if query.location.point.is_some()
        || query.location.radius_meters.is_some()
        || query.location.near.is_some()
    {
        return Err(invalid_parameter(
            "location",
            "is not supported by the listings endpoint",
        ));
    }
    if !matches!(
        query.sort,
        MarketplaceSort::Relevance | MarketplaceSort::Freshness
    ) {
        return Err(invalid_parameter(
            "sort",
            "is not supported by the listings endpoint",
        ));
    }
    if query.statuses.len() != 1 {
        return Err(invalid_parameter(
            "status",
            "must contain exactly one value for the listings endpoint",
        ));
    }
    if query.currencies.len() > 1 {
        return Err(invalid_parameter(
            "currency",
            "must contain at most one value for the listings endpoint",
        ));
    }
    if query.units.len() > 1 {
        return Err(invalid_parameter(
            "unit",
            "must contain at most one value for the listings endpoint",
        ));
    }
    let mut store_query =
        ListingProjectionQuery::new().with_effective_status(query.statuses[0].as_str());
    if let Some(seller) = &query.seller {
        store_query = store_query.with_seller_pubkey(seller.as_str());
    }
    if let Some(unit) = query.units.first() {
        store_query = store_query.with_unit(unit.canonical());
    }
    if let Some(currency) = query.currencies.first() {
        store_query = store_query.with_currency_norm(currency);
    }
    if let Some(price) = &query.min_price {
        store_query = store_query.with_min_price_minor(price_minor_units(&price.raw)?);
    }
    if let Some(price) = &query.max_price {
        store_query = store_query.with_max_price_minor(price_minor_units(&price.raw)?);
    }
    Ok(store_query.with_limit(query.limit))
}

fn search_document_query(parsed: &MarketplaceSearchHttpQuery) -> SearchDocumentQuery {
    let mut query = SearchDocumentQuery::new()
        .with_doc_type("listing")
        .with_kind(30_402)
        .with_visible(true)
        .with_status("active")
        .with_limit(parsed.limit());
    if let Some(text) = parsed.text() {
        query = query.with_text(text);
    }
    if let Some(seller) = parsed.seller() {
        query = query.with_pubkey(seller.as_str());
    }
    query
}

async fn seller_policy_row(
    store: &SurrealStore,
    pubkey: &str,
) -> Result<Option<serde_json::Value>, ApiError> {
    let mut response = store
        .database()
        .query("SELECT * FROM relay_user WHERE pubkey = $pubkey LIMIT 1;")
        .bind(("pubkey", pubkey))
        .await
        .map_err(|_| ApiError::internal())?
        .check()
        .map_err(|_| ApiError::internal())?;
    let rows = response
        .take::<Vec<serde_json::Value>>(0)
        .map_err(|_| ApiError::internal())?;
    Ok(rows.into_iter().next())
}

fn listing_item_document(row: &serde_json::Value) -> Result<ListingItemDocument, ApiError> {
    Ok(ListingItemDocument {
        listing_key: string_field(row, "listing_key")?,
        event_id: string_field(row, "event_id")?,
        seller_pubkey: string_field(row, "seller_pubkey")?,
        d: string_field(row, "d")?,
        title: string_field(row, "title")?,
        summary: optional_string_field(row, "summary")?,
        price: ListingPriceDocument {
            amount: string_field(row, "price_decimal")?,
            currency: string_field(row, "currency_norm")?,
            unit: string_field(row, "unit")?,
        },
        location: ListingLocationDocument {
            text: optional_string_field(row, "location_text")?,
            geohash: optional_string_field(row, "geohash")?,
        },
        fulfillment: fulfillment_document(row)?,
        status: string_field(row, "effective_status")?,
        updated_at: u64_field(row, "updated_at")?,
    })
}

fn fulfillment_document(row: &serde_json::Value) -> Result<Vec<String>, ApiError> {
    let mut fulfillment = Vec::new();
    if bool_field(row, "pickup_available")? {
        fulfillment.push("pickup".to_owned());
    }
    if bool_field(row, "delivery_available")? {
        fulfillment.push("delivery".to_owned());
    }
    if bool_field(row, "shipping_available")? {
        fulfillment.push("shipping".to_owned());
    }
    Ok(fulfillment)
}

fn price_minor_units(raw: &str) -> Result<i64, ApiError> {
    let mut parts = raw.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some() || whole.is_empty() {
        return Err(invalid_parameter(
            "price",
            "must fit two decimal minor units",
        ));
    }
    let whole = whole
        .parse::<i64>()
        .map_err(|_| invalid_parameter("price", "must fit two decimal minor units"))?;
    let fraction = match fraction {
        Some(value) if value.len() <= 2 => format!("{value:0<2}")
            .parse::<i64>()
            .map_err(|_| invalid_parameter("price", "must fit two decimal minor units"))?,
        Some(_) => {
            return Err(invalid_parameter(
                "price",
                "must fit two decimal minor units",
            ));
        }
        None => 0,
    };
    whole
        .checked_mul(100)
        .and_then(|whole| whole.checked_add(fraction))
        .ok_or_else(|| invalid_parameter("price", "must fit two decimal minor units"))
}

fn string_field(row: &serde_json::Value, field: &'static str) -> Result<String, ApiError> {
    row.get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(ApiError::internal)
}

fn optional_string_field(
    row: &serde_json::Value,
    field: &'static str,
) -> Result<Option<String>, ApiError> {
    match row.get(field) {
        Some(value) if value.is_null() => Ok(None),
        Some(value) => value
            .as_str()
            .map(|value| Some(value.to_owned()))
            .ok_or_else(ApiError::internal),
        None => Ok(None),
    }
}

fn u64_field(row: &serde_json::Value, field: &'static str) -> Result<u64, ApiError> {
    row.get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(ApiError::internal)
}

fn bool_field(row: &serde_json::Value, field: &'static str) -> Result<bool, ApiError> {
    row.get(field)
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(ApiError::internal)
}

impl From<MarketplaceQueryError> for ApiError {
    fn from(error: MarketplaceQueryError) -> Self {
        Self::invalid_request(error.message())
    }
}

fn set_once<T>(field: &'static str, target: &mut Option<T>, value: T) -> Result<(), ApiError> {
    if target.replace(value).is_some() {
        return Err(invalid_parameter(field, "must not be repeated"));
    }
    Ok(())
}

fn push_text_values(
    field: &'static str,
    value: &str,
    target: &mut Vec<String>,
) -> Result<(), ApiError> {
    for value in split_query_list(field, value)? {
        target.push(value);
    }
    Ok(())
}

fn push_status_values(
    value: &str,
    target: &mut Vec<MarketplaceListingStatus>,
) -> Result<(), ApiError> {
    for value in split_query_list("status", value)? {
        target.push(parse_status(&value)?);
    }
    Ok(())
}

fn push_unit_values(value: &str, target: &mut Vec<ListingUnit>) -> Result<(), ApiError> {
    for value in split_query_list("unit", value)? {
        target.push(parse_unit(&value)?);
    }
    Ok(())
}

fn push_fulfillment_values(
    value: &str,
    target: &mut Vec<FulfillmentMethod>,
) -> Result<(), ApiError> {
    for value in split_query_list("fulfillment", value)? {
        target.push(parse_fulfillment(&value)?);
    }
    Ok(())
}

fn split_query_list(field: &'static str, value: &str) -> Result<Vec<String>, ApiError> {
    value
        .split(',')
        .map(|value| required_value(field, value))
        .collect()
}

fn required_value(field: &'static str, value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(invalid_parameter(field, "must not be empty"));
    }
    Ok(value.to_owned())
}

fn parse_pubkey(field: &'static str, value: &str) -> Result<PublicKeyHex, ApiError> {
    let value = required_value(field, value)?;
    PublicKeyHex::new(&value)
        .map_err(|_| invalid_parameter(field, "must be a 64-character hex public key"))
}

fn parse_status(value: &str) -> Result<MarketplaceListingStatus, ApiError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "active" => Ok(MarketplaceListingStatus::Active),
        "sold" => Ok(MarketplaceListingStatus::Sold),
        "draft" => Ok(MarketplaceListingStatus::Draft),
        "inactive" => Ok(MarketplaceListingStatus::Inactive),
        "expired" => Ok(MarketplaceListingStatus::Expired),
        "deleted" => Ok(MarketplaceListingStatus::Deleted),
        "hidden" => Ok(MarketplaceListingStatus::Hidden),
        "rejected" => Ok(MarketplaceListingStatus::Rejected),
        _ => Err(invalid_parameter("status", "is unsupported")),
    }
}

fn parse_sort(value: &str) -> Result<MarketplaceSort, ApiError> {
    match required_value("sort", value)?.to_ascii_lowercase().as_str() {
        "relevance" => Ok(MarketplaceSort::Relevance),
        "freshness" => Ok(MarketplaceSort::Freshness),
        "price_asc" => Ok(MarketplaceSort::PriceAsc),
        "price_desc" => Ok(MarketplaceSort::PriceDesc),
        "distance" => Ok(MarketplaceSort::Distance),
        "seller_trust" => Ok(MarketplaceSort::SellerTrust),
        _ => Err(invalid_parameter("sort", "is unsupported")),
    }
}

fn parse_unit(value: &str) -> Result<ListingUnit, ApiError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "lb" | "lbs" | "pound" | "pounds" => Ok(ListingUnit::Lb),
        "oz" | "ounce" | "ounces" => Ok(ListingUnit::Oz),
        "each" | "ea" => Ok(ListingUnit::Each),
        "bunch" | "bunches" => Ok(ListingUnit::Bunch),
        "dozen" => Ok(ListingUnit::Dozen),
        "kg" | "kilogram" | "kilograms" => Ok(ListingUnit::Kg),
        "g" | "gram" | "grams" => Ok(ListingUnit::G),
        "share" | "shares" => Ok(ListingUnit::Share),
        "pint" | "pints" => Ok(ListingUnit::Pint),
        "quart" | "quarts" => Ok(ListingUnit::Quart),
        "box" | "boxes" => Ok(ListingUnit::Box),
        "crate" | "crates" => Ok(ListingUnit::Crate),
        "flat" | "flats" => Ok(ListingUnit::Flat),
        _ => Err(invalid_parameter("unit", "is unsupported")),
    }
}

fn parse_fulfillment(value: &str) -> Result<FulfillmentMethod, ApiError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "pickup" => Ok(FulfillmentMethod::Pickup),
        "delivery" => Ok(FulfillmentMethod::Delivery),
        "shipping" => Ok(FulfillmentMethod::Shipping),
        _ => Err(invalid_parameter("fulfillment", "is unsupported")),
    }
}

fn parse_bool(field: &'static str, value: &str) -> Result<bool, ApiError> {
    match required_value(field, value)?.to_ascii_lowercase().as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(invalid_parameter(field, "must be true or false")),
    }
}

fn parse_geohash_query_value(value: &str) -> Result<String, ApiError> {
    let value = required_value("geohash", value)?.to_ascii_lowercase();
    if value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        Ok(value)
    } else {
        Err(invalid_parameter(
            "geohash",
            "must be lowercase alphanumeric",
        ))
    }
}

fn parse_microdegrees(
    field: &'static str,
    value: &str,
    min: i64,
    max: i64,
) -> Result<i32, ApiError> {
    let value = required_value(field, value)?;
    let (negative, value) = match value.as_bytes().first() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value.as_str()),
    };
    let unsigned = parse_unsigned_decimal_scaled(field, value, 6)? as i64;
    let signed = if negative { -unsigned } else { unsigned };
    if !(min..=max).contains(&signed) {
        return Err(invalid_parameter(field, "is out of range"));
    }
    Ok(signed as i32)
}

fn parse_radius_meters(value: &str) -> Result<u64, ApiError> {
    let kilometers = required_value("radius_km", value)?;
    let meters = parse_unsigned_decimal_scaled("radius_km", &kilometers, 3)?;
    if meters == 0 {
        return Err(invalid_parameter("radius_km", "must be greater than zero"));
    }
    Ok(meters)
}

fn parse_limit(value: &str) -> Result<u64, ApiError> {
    required_value("limit", value)?
        .parse::<u64>()
        .map_err(|_| invalid_parameter("limit", "must be an unsigned integer"))
}

fn parse_unsigned_decimal_scaled(
    field: &'static str,
    value: &str,
    scale_digits: usize,
) -> Result<u64, ApiError> {
    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > scale_digits
    {
        return Err(invalid_parameter(
            field,
            "must be an exact unsigned decimal",
        ));
    }
    let whole = whole
        .parse::<u64>()
        .map_err(|_| invalid_parameter(field, "must be an exact unsigned decimal"))?;
    let mut fraction = fraction.to_owned();
    while fraction.len() < scale_digits {
        fraction.push('0');
    }
    let fraction = fraction
        .parse::<u64>()
        .map_err(|_| invalid_parameter(field, "must be an exact unsigned decimal"))?;
    whole
        .checked_mul(10_u64.pow(scale_digits as u32))
        .and_then(|whole| whole.checked_add(fraction))
        .ok_or_else(|| invalid_parameter(field, "must fit the supported range"))
}

fn invalid_parameter(field: &'static str, requirement: &str) -> ApiError {
    ApiError::invalid_request(format!("{field} {requirement}"))
}

#[cfg(test)]
mod tests {
    use super::{
        ApiError, ApiErrorBody, ApiErrorCode, ApiErrorEnvelope, ListingsHttpState,
        ReadinessCheckStatus, ReadinessState, RelayConnection, RelayConnectionConfig,
        RelayConnectionId, RelayInfoDocument, TANGLE_RELAY_SOFTWARE, TANGLE_SUPPORTED_NIPS,
        WebSocketHttpState, health_router, listing_item_document, listing_projection_query,
        listings_router, parse_listing_query, parse_marketplace_search_query, relay_info_router,
        search_document_query, websocket_router,
    };
    use axum::{body::Body, response::IntoResponse};
    use http::{HeaderValue, Request, StatusCode, header};
    use tangle_core::{MarketplaceListingStatus, MarketplaceSort, RateLimitConfig, RuntimeLimits};
    use tangle_nips::{FulfillmentMethod, ListingUnit};
    use tangle_protocol::{UnixTimestamp, event_to_value};
    use tangle_store::StoredEvent;
    use tangle_store_surreal::{SurrealConnectionConfig, SurrealStore, base_migration_plan};
    use tangle_test_support::{build_fixture_event, valid_public_listing_spec};
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

    #[test]
    fn relay_connection_id_validates_and_displays_stable_value() {
        let id = RelayConnectionId::new(" conn-001 ").expect("id");

        assert_eq!(id.as_str(), "conn-001");
        assert_eq!(id.to_string(), "conn-001");
        assert_eq!(
            RelayConnectionId::new("").expect_err("empty"),
            "connection id must not be empty"
        );
        assert_eq!(
            RelayConnectionId::new(&"x".repeat(RelayConnectionId::MAX_LENGTH + 1))
                .expect_err("too long"),
            "connection id must be at most 128 bytes, got 129"
        );
    }

    #[test]
    fn relay_connection_config_normalizes_core_runtime_state() {
        let rate_limit = RateLimitConfig::new(10, 60).expect("rate limit");
        let config = RelayConnectionConfig::new(
            " wss://relay.radroots.test ",
            42,
            rate_limit,
            RuntimeLimits::default(),
        )
        .expect("config");

        assert_eq!(config.relay_url(), "wss://relay.radroots.test");
        assert_eq!(config.auth_ttl_seconds(), 42);
        assert_eq!(config.message_rate_limit(), rate_limit);
        assert_eq!(config.runtime_limits(), RuntimeLimits::default());
        assert_eq!(
            RelayConnectionConfig::new("", 42, rate_limit, RuntimeLimits::default())
                .expect_err("relay"),
            "relay url must not be empty"
        );
        assert_eq!(
            RelayConnectionConfig::new(
                "wss://relay.radroots.test",
                0,
                rate_limit,
                RuntimeLimits::default()
            )
            .expect_err("ttl"),
            "auth challenge ttl must be greater than zero"
        );
    }

    #[test]
    fn relay_connection_composes_subscription_auth_and_rate_state() {
        let config = RelayConnectionConfig::new(
            "wss://relay.radroots.test",
            30,
            RateLimitConfig::new(2, 60).expect("rate limit"),
            RuntimeLimits::default(),
        )
        .expect("config");
        let mut connection =
            RelayConnection::new(RelayConnectionId::new("conn-a").expect("id"), config);

        assert_eq!(connection.id().as_str(), "conn-a");
        assert_eq!(connection.remote_addr(), None);
        connection.set_remote_addr("127.0.0.1:7777");
        assert_eq!(connection.remote_addr(), Some("127.0.0.1:7777"));
        assert_eq!(connection.subscriptions().active_count(), 0);
        assert_eq!(connection.auth().relay_url(), "wss://relay.radroots.test");
        assert_eq!(connection.auth().ttl_seconds(), 30);
        assert_eq!(connection.rate_limiter().tracked_key_count(), 0);

        let challenge = connection
            .auth_mut()
            .issue_challenge("challenge-a", UnixTimestamp::new(100))
            .expect("challenge");
        let decision = connection
            .rate_limiter_mut()
            .check("conn-a", UnixTimestamp::new(100), 1)
            .expect("rate limit");

        assert_eq!(challenge.value, "challenge-a");
        assert_eq!(
            connection
                .auth()
                .active_challenge()
                .expect("active")
                .expires_at,
            UnixTimestamp::new(130)
        );
        assert_eq!(decision.allowed(), true);
        assert_eq!(decision.remaining(), 1);
        assert_eq!(connection.rate_limiter().tracked_key_count(), 1);
        assert_eq!(connection.subscriptions_mut().active_count(), 0);
    }

    #[test]
    fn websocket_state_uses_relay_connection_config() {
        let config = RelayConnectionConfig::new(
            "wss://relay.radroots.test",
            60,
            RateLimitConfig::new(5, 10).expect("rate limit"),
            RuntimeLimits::default(),
        )
        .expect("config");
        let state = WebSocketHttpState::new(config.clone());
        let default_state = WebSocketHttpState::default();

        assert_eq!(state.connection_config(), &config);
        assert_eq!(
            default_state.connection_config().relay_url(),
            "wss://relay.radroots.test"
        );
    }

    #[tokio::test]
    async fn websocket_route_requires_upgrade_headers() {
        let response = websocket_router(WebSocketHttpState::default())
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn websocket_route_requires_hyper_upgrade_extension() {
        let response = websocket_router(WebSocketHttpState::default())
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::CONNECTION, "upgrade")
                    .header(header::UPGRADE, "websocket")
                    .header("sec-websocket-version", "13")
                    .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
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

    #[test]
    fn listing_query_parser_defaults_to_active_marketplace_query() {
        let parsed = parse_listing_query("", RuntimeLimits::default()).expect("query");
        let query = parsed.marketplace();

        assert_eq!(parsed.geohash(), None);
        assert_eq!(query.statuses, [MarketplaceListingStatus::Active]);
        assert_eq!(query.limit, 50);
        assert_eq!(query.sort, MarketplaceSort::Relevance);
        assert_eq!(query.categories, Vec::<String>::new());
        assert_eq!(query.currencies, Vec::<String>::new());
        assert_eq!(query.units, Vec::<ListingUnit>::new());
        assert_eq!(query.fulfillment, Vec::<FulfillmentMethod>::new());
    }

    #[test]
    fn listing_query_parser_reads_supported_parameters() {
        let seller = "1".repeat(64);
        let query_string = format!(
            "category=vegetables,csa&category=roots&seller={seller}&status=active,sold,draft,inactive,expired,deleted,hidden,rejected&currency=usd,cad&unit=lb,oz,each,bunch,dozen,kg,g,share,pint,quart,box,crate,flat&min_price=1.50&max_price=10&fulfillment=pickup,delivery,shipping&delivery_only=false&pickup=true&geohash=C23NB62&lat=47.6062&lon=-122.332100&radius_km=25.5&near=Ballard&sort=distance&limit=25"
        );
        let parsed = parse_listing_query(&query_string, RuntimeLimits::default()).expect("query");
        let query = parsed.marketplace();
        let point = query.location.point.expect("point");

        assert_eq!(parsed.geohash(), Some("c23nb62"));
        assert_eq!(
            query.categories,
            [
                "csa".to_owned(),
                "roots".to_owned(),
                "vegetables".to_owned()
            ]
        );
        assert_eq!(query.seller.as_ref().expect("seller").as_str(), seller);
        assert_eq!(
            query.statuses,
            [
                MarketplaceListingStatus::Active,
                MarketplaceListingStatus::Sold,
                MarketplaceListingStatus::Draft,
                MarketplaceListingStatus::Inactive,
                MarketplaceListingStatus::Expired,
                MarketplaceListingStatus::Deleted,
                MarketplaceListingStatus::Hidden,
                MarketplaceListingStatus::Rejected,
            ]
        );
        assert_eq!(query.currencies, ["CAD".to_owned(), "USD".to_owned()]);
        assert_eq!(
            query
                .units
                .iter()
                .map(|unit| unit.canonical())
                .collect::<Vec<_>>(),
            [
                "box", "bunch", "crate", "dozen", "each", "flat", "g", "kg", "lb", "oz", "pint",
                "quart", "share",
            ]
        );
        assert_eq!(query.min_price.as_ref().expect("min").raw, "1.50");
        assert_eq!(query.max_price.as_ref().expect("max").raw, "10");
        assert_eq!(
            query.fulfillment,
            [
                FulfillmentMethod::Pickup,
                FulfillmentMethod::Delivery,
                FulfillmentMethod::Shipping,
            ]
        );
        assert_eq!(query.delivery_only, Some(false));
        assert_eq!(query.pickup, Some(true));
        assert_eq!(point.latitude_microdegrees, 47_606_200);
        assert_eq!(point.longitude_microdegrees, -122_332_100);
        assert_eq!(query.location.radius_meters, Some(25_500));
        assert_eq!(query.location.near.as_deref(), Some("ballard"));
        assert_eq!(query.sort, MarketplaceSort::Distance);
        assert_eq!(query.limit, 25);
    }

    #[test]
    fn listing_query_parser_accepts_all_sort_labels() {
        let cases = [
            ("relevance", MarketplaceSort::Relevance, ""),
            ("freshness", MarketplaceSort::Freshness, ""),
            ("price_asc", MarketplaceSort::PriceAsc, ""),
            ("price_desc", MarketplaceSort::PriceDesc, ""),
            ("distance", MarketplaceSort::Distance, "&lat=+0&lon=0"),
            ("seller_trust", MarketplaceSort::SellerTrust, ""),
        ];
        for (label, expected, suffix) in cases {
            let parsed =
                parse_listing_query(&format!("sort={label}{suffix}"), RuntimeLimits::default())
                    .expect("query");
            assert_eq!(parsed.marketplace().sort, expected);
        }
    }

    #[test]
    fn listing_query_parser_rejects_invalid_parameters() {
        let seller = "1".repeat(64);
        let cases = [
            (
                "banana=1".to_owned(),
                "query parameter `banana` is unsupported",
            ),
            ("category=,roots".to_owned(), "category must not be empty"),
            (
                "seller=bad".to_owned(),
                "seller must be a 64-character hex public key",
            ),
            (
                format!("seller={seller}&seller={seller}"),
                "seller must not be repeated",
            ),
            ("status=bogus".to_owned(), "status is unsupported"),
            ("currency=%20".to_owned(), "currency must not be empty"),
            ("unit=bushel".to_owned(), "unit is unsupported"),
            ("min_price=".to_owned(), "min_price must not be empty"),
            (
                "min_price=2&max_price=1.99".to_owned(),
                "min_price must not exceed max_price",
            ),
            ("fulfillment=drone".to_owned(), "fulfillment is unsupported"),
            (
                "delivery_only=yes".to_owned(),
                "delivery_only must be true or false",
            ),
            ("pickup=".to_owned(), "pickup must not be empty"),
            (
                "geohash=c23-".to_owned(),
                "geohash must be lowercase alphanumeric",
            ),
            (
                "geohash=c23&geohash=c24".to_owned(),
                "geohash must not be repeated",
            ),
            ("lat=91".to_owned(), "lat is out of range"),
            ("lon=181".to_owned(), "lon is out of range"),
            (
                "lat=999999999999999999999999&lon=0".to_owned(),
                "lat must be an exact unsigned decimal",
            ),
            (
                "lat=0&radius_km=1".to_owned(),
                "lat and lon must be provided together",
            ),
            (
                "radius_km=0".to_owned(),
                "radius_km must be greater than zero",
            ),
            (
                "radius_km=1.0000".to_owned(),
                "radius_km must be an exact unsigned decimal",
            ),
            (
                "radius_km=18446744073709551615".to_owned(),
                "radius_km must fit the supported range",
            ),
            ("near=%20".to_owned(), "near must not be empty"),
            (
                "sort=relevance&sort=freshness".to_owned(),
                "sort must not be repeated",
            ),
            ("sort=popular".to_owned(), "sort is unsupported"),
            (
                "sort=distance".to_owned(),
                "distance sort requires a point or near filter",
            ),
            ("limit=abc".to_owned(), "limit must be an unsigned integer"),
            ("limit=0".to_owned(), "limit must be between 1 and 100"),
            (
                "cursor=opaque".to_owned(),
                "cursor signed cursor decoding is not implemented",
            ),
        ];
        for (query, expected) in cases {
            let error = parse_listing_query(&query, RuntimeLimits::default()).expect_err(&query);
            assert_eq!(error.code(), ApiErrorCode::InvalidRequest);
            assert_eq!(error.message(), expected);
        }
    }

    #[test]
    fn listing_projection_query_rejects_filters_store_cannot_apply() {
        let cases = [
            (
                "category=vegetables",
                "category is not supported by the listings endpoint",
            ),
            (
                "geohash=c22yzug",
                "geohash is not supported by the listings endpoint",
            ),
            (
                "fulfillment=pickup",
                "fulfillment is not supported by the listings endpoint",
            ),
            (
                "delivery_only=true",
                "delivery_only is not supported by the listings endpoint",
            ),
            (
                "pickup=true",
                "pickup is not supported by the listings endpoint",
            ),
            (
                "lat=0&lon=0",
                "location is not supported by the listings endpoint",
            ),
            (
                "sort=price_asc",
                "sort is not supported by the listings endpoint",
            ),
            (
                "status=active,sold",
                "status must contain exactly one value for the listings endpoint",
            ),
            (
                "currency=usd,cad",
                "currency must contain at most one value for the listings endpoint",
            ),
            (
                "unit=lb,kg",
                "unit must contain at most one value for the listings endpoint",
            ),
            ("min_price=1.234", "price must fit two decimal minor units"),
            (
                "min_price=999999999999999999999999999999",
                "price must fit two decimal minor units",
            ),
            (
                "min_price=9223372036854775807",
                "price must fit two decimal minor units",
            ),
        ];
        for (raw, expected) in cases {
            let parsed = parse_listing_query(raw, RuntimeLimits::default()).expect("query");
            let error = listing_projection_query(&parsed).expect_err(raw);
            assert_eq!(error.message(), expected);
        }
    }

    #[test]
    fn marketplace_search_query_parser_accepts_supported_modes() {
        let seller = "1".repeat(64);
        let text = parse_marketplace_search_query(
            &format!("q=carrot&seller={seller}&sort=relevance&limit=25"),
            RuntimeLimits::default(),
        )
        .expect("text search");
        assert_eq!(text.text(), Some("carrot"));
        assert_eq!(text.seller().expect("seller").as_str(), seller);
        assert_eq!(text.limit(), 25);

        let browse = parse_marketplace_search_query("sort=freshness", RuntimeLimits::default())
            .expect("browse");
        assert_eq!(browse.text(), None);
        assert_eq!(browse.seller(), None);
        assert_eq!(browse.limit(), 50);

        let query = search_document_query(&text);
        assert_eq!(format!("{query:?}").contains("SearchDocumentQuery"), true);
    }

    #[test]
    fn marketplace_search_query_parser_rejects_invalid_parameters() {
        let long_query = format!("q={}", "a".repeat(300));
        let cases = [
            ("q=".to_owned(), "q must not be empty"),
            ("q=carrot&q=roots".to_owned(), "q must not be repeated"),
            (
                long_query,
                "runtime limit: search query bytes exceeded: 300 > 256",
            ),
            (
                "category=vegetables".to_owned(),
                "category is not supported by marketplace search",
            ),
            (
                "status=sold".to_owned(),
                "status must be active for marketplace search",
            ),
            (
                "q=carrot&sort=freshness".to_owned(),
                "sort does not match marketplace search mode",
            ),
            (
                "sort=relevance".to_owned(),
                "sort does not match marketplace search mode",
            ),
            (
                "sort=price_asc".to_owned(),
                "sort does not match marketplace search mode",
            ),
            ("limit=0".to_owned(), "limit must be between 1 and 100"),
            (
                "banana=1".to_owned(),
                "query parameter `banana` is unsupported",
            ),
        ];
        for (raw, expected) in cases {
            let error =
                parse_marketplace_search_query(&raw, RuntimeLimits::default()).expect_err(&raw);
            assert_eq!(error.code(), ApiErrorCode::InvalidRequest);
            assert_eq!(error.message(), expected);
        }
    }

    #[test]
    fn listing_item_document_maps_projection_rows_and_rejects_malformed_rows() {
        let row = serde_json::json!({
            "listing_key": "30402:pubkey:listing-a",
            "event_id": "event",
            "seller_pubkey": "pubkey",
            "d": "listing-a",
            "title": "Carrot bunches",
            "location_text": "Seattle",
            "price_decimal": "12.50",
            "currency_norm": "USD",
            "unit": "lb",
            "effective_status": "active",
            "updated_at": 1714124433_u64,
            "pickup_available": false,
            "delivery_available": true,
            "shipping_available": true
        });
        let item = listing_item_document(&row).expect("item");

        assert_eq!(item.summary, None);
        assert_eq!(item.location.text.as_deref(), Some("Seattle"));
        assert_eq!(item.location.geohash, None);
        assert_eq!(
            item.fulfillment,
            ["delivery".to_owned(), "shipping".to_owned()]
        );
        assert_eq!(item.price.amount, "12.50");

        for row in [
            serde_json::json!({
                "event_id": "event",
                "seller_pubkey": "pubkey",
                "d": "listing-a",
                "title": "Carrot bunches",
                "price_decimal": "12.50",
                "currency_norm": "USD",
                "unit": "lb",
                "effective_status": "active",
                "updated_at": 1714124433_u64,
                "pickup_available": false,
                "delivery_available": true,
                "shipping_available": true
            }),
            serde_json::json!({
                "listing_key": "30402:pubkey:listing-a",
                "event_id": "event",
                "seller_pubkey": "pubkey",
                "d": "listing-a",
                "title": "Carrot bunches",
                "summary": 1,
                "price_decimal": "12.50",
                "currency_norm": "USD",
                "unit": "lb",
                "effective_status": "active",
                "updated_at": 1714124433_u64,
                "pickup_available": false,
                "delivery_available": true,
                "shipping_available": true
            }),
            serde_json::json!({
                "listing_key": "30402:pubkey:listing-a",
                "event_id": "event",
                "seller_pubkey": "pubkey",
                "d": "listing-a",
                "title": "Carrot bunches",
                "price_decimal": "12.50",
                "currency_norm": "USD",
                "unit": "lb",
                "effective_status": "active",
                "updated_at": "bad",
                "pickup_available": false,
                "delivery_available": true,
                "shipping_available": true
            }),
            serde_json::json!({
                "listing_key": "30402:pubkey:listing-a",
                "event_id": "event",
                "seller_pubkey": "pubkey",
                "d": "listing-a",
                "title": "Carrot bunches",
                "price_decimal": "12.50",
                "currency_norm": "USD",
                "unit": "lb",
                "effective_status": "active",
                "updated_at": 1714124433_u64,
                "pickup_available": "bad",
                "delivery_available": true,
                "shipping_available": true
            }),
        ] {
            assert_eq!(
                listing_item_document(&row).expect_err("malformed").code(),
                ApiErrorCode::Internal
            );
        }
    }

    #[tokio::test]
    async fn listings_endpoint_queries_projection_rows_and_excludes_hidden_rows() {
        let store = runtime_memory_store().await;
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
        store
            .project_current_listing(&listing, UnixTimestamp::new(1_714_125_400))
            .await
            .expect("project listing");

        let uri = format!(
            "/api/listings?status=active&seller={}&unit=lb&currency=usd&min_price=1.5&max_price=20.25&limit=5",
            listing.unsigned().pubkey().as_str()
        );
        let response = listings_router(ListingsHttpState::new(
            store.clone(),
            RuntimeLimits::default(),
        ))
        .oneshot(
            Request::builder()
                .uri(uri)
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
                "items": [{
                    "listing_key": listing_key,
                    "event_id": listing.id().as_str(),
                    "seller_pubkey": listing.unsigned().pubkey().as_str(),
                    "d": "listing-a",
                    "title": "Carrot bunches",
                    "summary": null,
                    "price": {
                        "amount": "12.50",
                        "currency": "USD",
                        "unit": "lb"
                    },
                    "location": {
                        "text": null,
                        "geohash": "c22yzug"
                    },
                    "fulfillment": ["pickup"],
                    "status": "active",
                    "updated_at": 1714124433
                }],
                "next_cursor": null
            })
        );

        store
            .database()
            .query("UPDATE listing_current SET hidden = true WHERE listing_key = $listing_key;")
            .bind(("listing_key", listing_key.as_str()))
            .await
            .expect("hide listing")
            .check()
            .expect("hide check");
        let response = listings_router(ListingsHttpState::new(store, RuntimeLimits::default()))
            .oneshot(
                Request::builder()
                    .uri("/api/listings")
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
                "items": [],
                "next_cursor": null
            })
        );
    }

    #[tokio::test]
    async fn listing_detail_endpoint_returns_projection_and_raw_event() {
        let store = runtime_memory_store().await;
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
        store
            .store_raw_event(&StoredEvent::new(
                listing.clone(),
                UnixTimestamp::new(1_714_125_300),
            ))
            .await
            .expect("raw event");
        store
            .project_current_listing(&listing, UnixTimestamp::new(1_714_125_400))
            .await
            .expect("project listing");

        let uri = format!(
            "/api/listings/{}/listing-a",
            listing.unsigned().pubkey().as_str()
        );
        let response = listings_router(ListingsHttpState::new(
            store.clone(),
            RuntimeLimits::default(),
        ))
        .oneshot(
            Request::builder()
                .uri(uri.as_str())
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(json["listing"]["listing_key"], listing_key);
        assert_eq!(json["listing"]["event_id"], listing.id().as_str());
        assert_eq!(json["raw_event"], event_to_value(&listing));

        store
            .database()
            .query("UPDATE nostr_event SET hidden = true WHERE event_id = $event_id;")
            .bind(("event_id", listing.id().as_str()))
            .await
            .expect("hide raw")
            .check()
            .expect("hide raw check");
        let response = listings_router(ListingsHttpState::new(
            store.clone(),
            RuntimeLimits::default(),
        ))
        .oneshot(
            Request::builder()
                .uri(uri.as_str())
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        store
            .database()
            .query(
                "UPDATE nostr_event SET hidden = false WHERE event_id = $event_id;
                 UPDATE listing_current SET hidden = true WHERE listing_key = $listing_key;",
            )
            .bind(("event_id", listing.id().as_str()))
            .bind(("listing_key", listing_key.as_str()))
            .await
            .expect("hide listing")
            .check()
            .expect("hide listing check");
        let response = listings_router(ListingsHttpState::new(store, RuntimeLimits::default()))
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn listing_detail_endpoint_rejects_invalid_or_missing_listing() {
        let store = runtime_memory_store().await;
        let response = listings_router(ListingsHttpState::new(
            store.clone(),
            RuntimeLimits::default(),
        ))
        .oneshot(
            Request::builder()
                .uri("/api/listings/not-a-pubkey/listing-a")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("json"),
            serde_json::json!({
                "error": {
                    "code": "invalid_request",
                    "message": "pubkey must be a 64-character hex public key"
                }
            })
        );

        let response = listings_router(ListingsHttpState::new(store, RuntimeLimits::default()))
            .oneshot(
                Request::builder()
                    .uri(format!("/api/listings/{}/missing", "1".repeat(64)))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn marketplace_search_endpoint_queries_search_docs_and_hydrates_listings() {
        let store = runtime_memory_store().await;
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
        store
            .project_current_listing(&listing, UnixTimestamp::new(1_714_125_400))
            .await
            .expect("project listing");
        store
            .index_listing_search_document(&listing)
            .await
            .expect("index listing");

        let uri = format!(
            "/api/search?q=carrot&seller={}&sort=relevance&limit=5",
            listing.unsigned().pubkey().as_str()
        );
        let response = listings_router(ListingsHttpState::new(
            store.clone(),
            RuntimeLimits::default(),
        ))
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(json["items"][0]["listing_key"], listing_key);
        assert_eq!(json["items"][0]["title"], "Carrot bunches");
        assert_eq!(json["next_cursor"], serde_json::Value::Null);

        store
            .database()
            .query("UPDATE listing_current SET hidden = true WHERE listing_key = $listing_key;")
            .bind(("listing_key", listing_key.as_str()))
            .await
            .expect("hide listing")
            .check()
            .expect("hide check");
        let response = listings_router(ListingsHttpState::new(store, RuntimeLimits::default()))
            .oneshot(
                Request::builder()
                    .uri("/api/search?q=carrot")
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
                "items": [],
                "next_cursor": null
            })
        );
    }

    #[tokio::test]
    async fn seller_endpoint_returns_policy_state_and_active_listing_count() {
        let store = runtime_memory_store().await;
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let seller = listing.unsigned().pubkey().as_str().to_owned();
        let listing_key = format!("30402:{seller}:listing-a");
        store
            .project_current_listing(&listing, UnixTimestamp::new(1_714_125_400))
            .await
            .expect("project listing");
        store
            .database()
            .query(
                "CREATE relay_user CONTENT {
                    pubkey: $pubkey,
                    role: 'seller',
                    seller_approved: true,
                    blocked: false,
                    created_at: 1,
                    updated_at: 2
                };",
            )
            .bind(("pubkey", seller.as_str()))
            .await
            .expect("seller row")
            .check()
            .expect("seller check");

        let response = listings_router(ListingsHttpState::new(
            store.clone(),
            RuntimeLimits::default(),
        ))
        .oneshot(
            Request::builder()
                .uri(format!("/api/sellers/{seller}"))
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
                "pubkey": seller,
                "approved": true,
                "blocked": false,
                "active_listing_count": 1
            })
        );

        store
            .database()
            .query("UPDATE listing_current SET hidden = true WHERE listing_key = $listing_key;")
            .bind(("listing_key", listing_key.as_str()))
            .await
            .expect("hide listing")
            .check()
            .expect("hide check");
        let response = listings_router(ListingsHttpState::new(store, RuntimeLimits::default()))
            .oneshot(
                Request::builder()
                    .uri(format!("/api/sellers/{seller}"))
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
            serde_json::from_slice::<serde_json::Value>(&body).expect("json")["active_listing_count"],
            0
        );
    }

    #[tokio::test]
    async fn seller_endpoint_defaults_missing_seller_and_rejects_invalid_pubkey() {
        let store = runtime_memory_store().await;
        let missing = "1".repeat(64);
        let response = listings_router(ListingsHttpState::new(
            store.clone(),
            RuntimeLimits::default(),
        ))
        .oneshot(
            Request::builder()
                .uri(format!("/api/sellers/{missing}"))
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
                "pubkey": missing,
                "approved": false,
                "blocked": false,
                "active_listing_count": 0
            })
        );

        let response = listings_router(ListingsHttpState::new(store, RuntimeLimits::default()))
            .oneshot(
                Request::builder()
                    .uri("/api/sellers/not-a-pubkey")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    async fn runtime_memory_store() -> SurrealStore {
        let config = SurrealConnectionConfig::memory("tangle_runtime", "listings_endpoint")
            .expect("memory config");
        let store = SurrealStore::connect_memory(&config)
            .await
            .expect("memory store");
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        store
    }
}
