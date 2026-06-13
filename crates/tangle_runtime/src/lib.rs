#![forbid(unsafe_code)]

pub mod chorus_pocket;

use axum::{
    Json, Router,
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::{Path, RawQuery, State},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use core::fmt;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    future::Future,
    net::SocketAddr,
    path::{Component, Path as FsPath, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tangle_core::{
    AdmissionContext, AdmissionEffect, AdmissionPolicy, AuthChallengeState, EventValidator,
    FixedWindowRateLimiter, MarketplaceListingStatus, MarketplaceQuery, MarketplaceQueryError,
    MarketplaceQuerySpec, MarketplaceSort, NostrFilterCompiler, QueryExecutionMode,
    RateLimitConfig, RateLimitDecision, RuntimeLimitValues, RuntimeLimits,
    SubscriptionCloseOutcome, SubscriptionManager, SubscriptionMatcher, UnapprovedSellerAction,
};
use tangle_nips::{FulfillmentMethod, ListingUnit, parse_relay_auth_event};
use tangle_protocol::{
    ClientMessage, Event, EventId, Filter, PublicKeyHex, RawEventJson, RelayMessage,
    SubscriptionId, UnixTimestamp, parse_client_message, parse_event_json,
};
use tangle_store::{StoreEventOutcome, StoredEvent};
use tangle_store_surreal::{
    CommentProjectionOutcome, CommentProjectionQuery, DurableRateLimitDecision,
    ForumThreadProjectionOutcome, ForumThreadProjectionQuery, LabelProjectionOutcome,
    LabelProjectionQuery, ListingProjectionQuery, LongFormProjectionOutcome, MigrationApplyOutcome,
    ReactionProjectionOutcome, ReportProjectionOutcome, ReportProjectionQuery, SearchDocumentQuery,
    SellerProfileProjectionOutcome, SurrealConnectionConfig, SurrealMetricsSnapshot, SurrealStore,
    base_migration_plan,
};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use url::form_urlencoded;

pub const TANGLE_SUPPORTED_NIPS: [u16; 13] = [1, 9, 11, 16, 22, 23, 25, 32, 33, 42, 50, 56, 99];
pub const TANGLE_RELAY_SOFTWARE: &str = "https://github.com/radrootslabs/tangle";
pub const TANGLE_RELAY_VERSION: &str = env!("CARGO_PKG_VERSION");

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

#[derive(Debug, Clone)]
pub struct WebSocketHttpState {
    connection_config: RelayConnectionConfig,
    shutdown_signal: GracefulShutdownSignal,
}

impl WebSocketHttpState {
    pub fn new(connection_config: RelayConnectionConfig) -> Self {
        let (shutdown_signal, _) = GracefulShutdownSignal::new();
        Self::with_shutdown(connection_config, shutdown_signal)
    }

    pub fn with_shutdown(
        connection_config: RelayConnectionConfig,
        shutdown_signal: GracefulShutdownSignal,
    ) -> Self {
        Self {
            connection_config,
            shutdown_signal,
        }
    }

    pub fn connection_config(&self) -> &RelayConnectionConfig {
        &self.connection_config
    }

    pub fn shutdown_signal(&self) -> &GracefulShutdownSignal {
        &self.shutdown_signal
    }
}

impl Default for WebSocketHttpState {
    fn default() -> Self {
        Self::new(RelayConnectionConfig::default())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TangleRuntimeConfig {
    listen_addr: SocketAddr,
    relay_connection: RelayConnectionConfig,
    database: SurrealConnectionConfig,
    admission_policy: AdmissionPolicy,
    durable_write_rate_limit: Option<RateLimitConfig>,
    admin_pubkeys: BTreeSet<PublicKeyHex>,
    limits: RuntimeLimits,
    tracing: RuntimeTracingConfig,
}

impl TangleRuntimeConfig {
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn relay_connection_config(&self) -> &RelayConnectionConfig {
        &self.relay_connection
    }

    pub fn database_config(&self) -> &SurrealConnectionConfig {
        &self.database
    }

    pub fn admission_policy(&self) -> &AdmissionPolicy {
        &self.admission_policy
    }

    pub fn durable_write_rate_limit(&self) -> Option<RateLimitConfig> {
        self.durable_write_rate_limit
    }

    pub fn admin_pubkeys(&self) -> &BTreeSet<PublicKeyHex> {
        &self.admin_pubkeys
    }

    pub fn limits(&self) -> RuntimeLimits {
        self.limits
    }

    pub fn tracing_config(&self) -> &RuntimeTracingConfig {
        &self.tracing
    }

    pub fn websocket_state(&self, shutdown_signal: GracefulShutdownSignal) -> WebSocketHttpState {
        WebSocketHttpState::with_shutdown(self.relay_connection.clone(), shutdown_signal)
    }

    pub fn listings_state(&self, store: SurrealStore) -> ListingsHttpState {
        ListingsHttpState::new(store, self.limits)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeTracingFormat {
    Compact,
    Json,
}

impl RuntimeTracingFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Json => "json",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTracingConfig {
    enabled: bool,
    filter: String,
    format: RuntimeTracingFormat,
}

impl RuntimeTracingConfig {
    pub fn new(
        enabled: bool,
        filter: impl Into<String>,
        format: RuntimeTracingFormat,
    ) -> Result<Self, RuntimeConfigError> {
        let filter = filter.into();
        if filter.trim().is_empty() {
            return Err(RuntimeConfigError::invalid(
                "observability.tracing.filter must not be empty",
            ));
        }
        Ok(Self {
            enabled,
            filter: filter.trim().to_owned(),
            format,
        })
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            filter: "info,tangle=info,tangle_runtime=info".to_owned(),
            format: RuntimeTracingFormat::Compact,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn filter(&self) -> &str {
        &self.filter
    }

    pub fn format(&self) -> RuntimeTracingFormat {
        self.format
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeConfigErrorKind {
    Read,
    Parse,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfigError {
    kind: RuntimeConfigErrorKind,
    message: String,
}

impl RuntimeConfigError {
    pub fn new(kind: RuntimeConfigErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn read(message: impl Into<String>) -> Self {
        Self::new(RuntimeConfigErrorKind::Read, message)
    }

    pub fn parse(message: impl Into<String>) -> Self {
        Self::new(RuntimeConfigErrorKind::Parse, message)
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(RuntimeConfigErrorKind::Invalid, message)
    }

    pub fn kind(&self) -> RuntimeConfigErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RuntimeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for RuntimeConfigError {}

pub fn load_runtime_config(
    path: impl AsRef<FsPath>,
) -> Result<TangleRuntimeConfig, RuntimeConfigError> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path).map_err(|error| {
        RuntimeConfigError::read(format!(
            "failed to read runtime config `{}`: {error}",
            path.display()
        ))
    })?;
    parse_runtime_config_json(&raw)
}

pub fn parse_runtime_config_json(raw: &str) -> Result<TangleRuntimeConfig, RuntimeConfigError> {
    let document = serde_json::from_str::<RuntimeConfigDocument>(raw).map_err(|error| {
        RuntimeConfigError::parse(format!("runtime config JSON is invalid: {error}"))
    })?;
    runtime_config_from_document(document)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeMigrationReport {
    applied: u64,
    already_applied: u64,
    total: u64,
}

impl RuntimeMigrationReport {
    pub fn new(applied: u64, already_applied: u64, total: u64) -> Self {
        Self {
            applied,
            already_applied,
            total,
        }
    }

    pub fn applied(self) -> u64 {
        self.applied
    }

    pub fn already_applied(self) -> u64 {
        self.already_applied
    }

    pub fn total(self) -> u64 {
        self.total
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeCommandErrorKind {
    Unsupported,
    Input,
    Store,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCommandError {
    kind: RuntimeCommandErrorKind,
    message: String,
}

impl RuntimeCommandError {
    pub fn new(kind: RuntimeCommandErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(RuntimeCommandErrorKind::Unsupported, message)
    }

    pub fn input(message: impl Into<String>) -> Self {
        Self::new(RuntimeCommandErrorKind::Input, message)
    }

    pub fn store(message: impl Into<String>) -> Self {
        Self::new(RuntimeCommandErrorKind::Store, message)
    }

    pub fn kind(&self) -> RuntimeCommandErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RuntimeCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for RuntimeCommandError {}

pub async fn migrate_runtime_database(
    config: &TangleRuntimeConfig,
) -> Result<RuntimeMigrationReport, RuntimeCommandError> {
    tracing::info!("starting runtime database migration");
    let store = connect_runtime_store(config).await?;
    let outcomes = store
        .apply_plan(&base_migration_plan())
        .await
        .map_err(|error| RuntimeCommandError::store(error.to_string()))?;
    let applied = outcomes
        .iter()
        .filter(|outcome| **outcome == MigrationApplyOutcome::Applied)
        .count() as u64;
    let already_applied = outcomes
        .iter()
        .filter(|outcome| **outcome == MigrationApplyOutcome::AlreadyApplied)
        .count() as u64;
    tracing::info!("finished runtime database migration");
    Ok(RuntimeMigrationReport::new(
        applied,
        already_applied,
        outcomes.len() as u64,
    ))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuntimeEventImportReport {
    total: u64,
    inserted: u64,
    duplicate: u64,
    projected: u64,
    skipped: u64,
}

impl RuntimeEventImportReport {
    pub fn new(total: u64, inserted: u64, duplicate: u64, projected: u64, skipped: u64) -> Self {
        Self {
            total,
            inserted,
            duplicate,
            projected,
            skipped,
        }
    }

    pub fn total(self) -> u64 {
        self.total
    }

    pub fn inserted(self) -> u64 {
        self.inserted
    }

    pub fn duplicate(self) -> u64 {
        self.duplicate
    }

    pub fn projected(self) -> u64 {
        self.projected
    }

    pub fn skipped(self) -> u64 {
        self.skipped
    }

    fn record(&mut self, outcome: RuntimeEventImportOutcome) {
        self.total += 1;
        match outcome {
            RuntimeEventImportOutcome::Inserted { projected } => {
                self.inserted += 1;
                if projected {
                    self.projected += 1;
                }
            }
            RuntimeEventImportOutcome::Duplicate => {
                self.duplicate += 1;
            }
            RuntimeEventImportOutcome::Skipped => {
                self.skipped += 1;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeEventImportOutcome {
    Inserted { projected: bool },
    Duplicate,
    Skipped,
}

pub async fn import_events_from_path(
    config: &TangleRuntimeConfig,
    path: impl AsRef<FsPath>,
) -> Result<RuntimeEventImportReport, RuntimeCommandError> {
    let path = path.as_ref();
    tracing::info!("starting event import");
    let raw = fs::read_to_string(path).map_err(|error| {
        RuntimeCommandError::input(format!(
            "failed to read event import file `{}`: {error}",
            path.display()
        ))
    })?;
    let events = parse_event_import_document(&raw)?;
    let store = connect_runtime_store(config).await?;
    let report = import_events_into_store(config, &store, events).await?;
    tracing::info!("finished event import");
    Ok(report)
}

async fn import_events_into_store(
    config: &TangleRuntimeConfig,
    store: &SurrealStore,
    events: Vec<Event>,
) -> Result<RuntimeEventImportReport, RuntimeCommandError> {
    store
        .apply_plan(&base_migration_plan())
        .await
        .map_err(|error| RuntimeCommandError::store(error.to_string()))?;
    let validator = EventValidator::new(
        config.limits(),
        config
            .admission_policy()
            .clone()
            .with_write_auth_required(false),
    );
    let mut report = RuntimeEventImportReport::default();
    let now = now_timestamp();
    for event in events {
        let outcome = import_single_event(store, &validator, event, now).await?;
        report.record(outcome);
    }
    Ok(report)
}

async fn import_single_event(
    store: &SurrealStore,
    validator: &EventValidator,
    event: Event,
    now: UnixTimestamp,
) -> Result<RuntimeEventImportOutcome, RuntimeCommandError> {
    if is_non_auth_ephemeral(&event) {
        return Ok(RuntimeEventImportOutcome::Skipped);
    }
    let validated = match validator.validate(&event, &AdmissionContext::unauthenticated(), now) {
        Ok(validated) => validated,
        Err(_) => return Ok(RuntimeEventImportOutcome::Skipped),
    };
    if validated.admission().effect() != AdmissionEffect::AuthenticateOnly {
        let raw_outcome = store
            .store_raw_event(&StoredEvent::new(event.clone(), now))
            .await
            .map_err(|error| RuntimeCommandError::store(error.to_string()))?;
        if raw_outcome == StoreEventOutcome::Duplicate {
            return Ok(RuntimeEventImportOutcome::Duplicate);
        }
        let projected =
            project_stored_event(store, &event, validated.admission().effect(), now).await?;
        return Ok(RuntimeEventImportOutcome::Inserted { projected });
    }
    Ok(RuntimeEventImportOutcome::Skipped)
}

async fn project_stored_event(
    store: &SurrealStore,
    event: &Event,
    effect: AdmissionEffect,
    now: UnixTimestamp,
) -> Result<bool, RuntimeCommandError> {
    store
        .index_event_tags(event)
        .await
        .map_err(|_| RuntimeCommandError::store("event projection failed"))?;
    store
        .maintain_current_event(event)
        .await
        .map_err(|_| RuntimeCommandError::store("event projection failed"))?;
    store
        .apply_deletion_markers(event)
        .await
        .map_err(|_| RuntimeCommandError::store("event projection failed"))?;
    store
        .store_listing_revision(event, now)
        .await
        .map_err(|_| RuntimeCommandError::store("event projection failed"))?;
    let comment_projected = matches!(
        store
            .project_comment(event, now)
            .await
            .map_err(|_| RuntimeCommandError::store("event projection failed"))?,
        CommentProjectionOutcome::Projected
    );
    let reaction_projected = matches!(
        store
            .project_reaction(event, now)
            .await
            .map_err(|_| RuntimeCommandError::store("event projection failed"))?,
        ReactionProjectionOutcome::Projected
    );
    let long_form_projected = matches!(
        store
            .project_long_form(event, now)
            .await
            .map_err(|_| RuntimeCommandError::store("event projection failed"))?,
        LongFormProjectionOutcome::Projected
    );
    let forum_thread_projected = matches!(
        store
            .project_forum_thread(event, now)
            .await
            .map_err(|_| RuntimeCommandError::store("event projection failed"))?,
        ForumThreadProjectionOutcome::Projected
    );
    let label_projected = matches!(
        store
            .project_label(event, now)
            .await
            .map_err(|_| RuntimeCommandError::store("event projection failed"))?,
        LabelProjectionOutcome::Projected
    );
    let report_projected = matches!(
        store
            .project_report(event, now)
            .await
            .map_err(|_| RuntimeCommandError::store("event projection failed"))?,
        ReportProjectionOutcome::Projected
    );
    let seller_profile_projected = matches!(
        store
            .project_seller_profile(event, now)
            .await
            .map_err(|_| RuntimeCommandError::store("event projection failed"))?,
        SellerProfileProjectionOutcome::Projected
    );
    if effect == AdmissionEffect::StoreRawAndProjectPublicListing {
        store
            .project_current_listing(event, now)
            .await
            .map_err(|_| RuntimeCommandError::store("event projection failed"))?;
        store
            .project_listing_helpers(event)
            .await
            .map_err(|_| RuntimeCommandError::store("event projection failed"))?;
        store
            .index_listing_search_document(event)
            .await
            .map_err(|_| RuntimeCommandError::store("event projection failed"))?;
        return Ok(true);
    }
    Ok(comment_projected
        || reaction_projected
        || long_form_projected
        || forum_thread_projected
        || label_projected
        || report_projected
        || seller_profile_projected)
}

fn parse_event_import_document(raw: &str) -> Result<Vec<Event>, RuntimeCommandError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(serde_json::Value::Array(events)) => events
            .iter()
            .enumerate()
            .map(|(index, value)| event_from_import_value(value, index + 1))
            .collect(),
        Ok(value @ serde_json::Value::Object(_)) => {
            event_from_import_value(&value, 1).map(|event| vec![event])
        }
        Ok(_) => Err(RuntimeCommandError::input(
            "event import file must contain event objects",
        )),
        Err(_) => trimmed
            .lines()
            .enumerate()
            .filter_map(|(index, line)| {
                let line = line.trim();
                if line.is_empty() {
                    None
                } else {
                    Some(event_from_import_line(line, index + 1))
                }
            })
            .collect(),
    }
}

fn event_from_import_value(
    value: &serde_json::Value,
    index: usize,
) -> Result<Event, RuntimeCommandError> {
    let raw = RawEventJson::new(&value.to_string()).expect("serialized JSON value is non-empty");
    parse_event_json(&raw).map_err(|error| {
        RuntimeCommandError::input(format!("event import item {index} is invalid: {error}"))
    })
}

fn event_from_import_line(line: &str, index: usize) -> Result<Event, RuntimeCommandError> {
    let raw = RawEventJson::new(line).expect("import lines are non-empty after trimming");
    parse_event_json(&raw).map_err(|error| {
        RuntimeCommandError::input(format!("event import line {index} is invalid: {error}"))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeEventExportReport {
    exported: u64,
}

impl RuntimeEventExportReport {
    pub fn new(exported: u64) -> Self {
        Self { exported }
    }

    pub fn exported(self) -> u64 {
        self.exported
    }
}

pub async fn export_events_to_path(
    config: &TangleRuntimeConfig,
    path: impl AsRef<FsPath>,
) -> Result<RuntimeEventExportReport, RuntimeCommandError> {
    let path = path.as_ref();
    tracing::info!("starting event export");
    let store = connect_runtime_store(config).await?;
    store
        .apply_plan(&base_migration_plan())
        .await
        .map_err(|error| RuntimeCommandError::store(error.to_string()))?;
    let rows = store
        .query_raw_events(&Filter::empty())
        .await
        .map_err(|error| RuntimeCommandError::store(error.to_string()))?;
    let mut output = String::new();
    for row in &rows {
        output.push_str(&runtime_row_string(row, "raw_json")?);
        output.push('\n');
    }
    fs::write(path, output).map_err(|error| {
        RuntimeCommandError::input(format!(
            "failed to write event export file `{}`: {error}",
            path.display()
        ))
    })?;
    tracing::info!("finished event export");
    Ok(RuntimeEventExportReport::new(rows.len() as u64))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBackupReport {
    output_dir: PathBuf,
    raw_events_path: PathBuf,
    raw_event_count: u64,
    raw_events_sha256: String,
    manifest_path: PathBuf,
    manifest_sha256: String,
    surrealdb_export_available: bool,
}

impl RuntimeBackupReport {
    pub fn new(
        output_dir: PathBuf,
        raw_events_path: PathBuf,
        raw_event_count: u64,
        raw_events_sha256: String,
        manifest_path: PathBuf,
        manifest_sha256: String,
        surrealdb_export_available: bool,
    ) -> Self {
        Self {
            output_dir,
            raw_events_path,
            raw_event_count,
            raw_events_sha256,
            manifest_path,
            manifest_sha256,
            surrealdb_export_available,
        }
    }

    pub fn output_dir(&self) -> &FsPath {
        &self.output_dir
    }

    pub fn raw_events_path(&self) -> &FsPath {
        &self.raw_events_path
    }

    pub fn raw_event_count(&self) -> u64 {
        self.raw_event_count
    }

    pub fn raw_events_sha256(&self) -> &str {
        &self.raw_events_sha256
    }

    pub fn manifest_path(&self) -> &FsPath {
        &self.manifest_path
    }

    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    pub fn surrealdb_export_available(&self) -> bool {
        self.surrealdb_export_available
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RuntimeBackupManifestDocument {
    format: String,
    database: RuntimeBackupDatabaseDocument,
    raw_events: RuntimeBackupArtifactDocument,
    surrealdb_export: RuntimeBackupOptionalArtifactDocument,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RuntimeBackupDatabaseDocument {
    namespace: String,
    database: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RuntimeBackupArtifactDocument {
    path: String,
    count: u64,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RuntimeBackupOptionalArtifactDocument {
    available: bool,
    path: Option<String>,
    sha256: Option<String>,
}

pub async fn backup_runtime_database(
    config: &TangleRuntimeConfig,
    output_dir: impl AsRef<FsPath>,
) -> Result<RuntimeBackupReport, RuntimeCommandError> {
    let output_dir = output_dir.as_ref();
    tracing::info!("starting runtime backup");
    let store = connect_runtime_store(config).await?;
    let report = backup_runtime_store(config, &store, output_dir).await?;
    tracing::info!("finished runtime backup");
    Ok(report)
}

async fn backup_runtime_store(
    config: &TangleRuntimeConfig,
    store: &SurrealStore,
    output_dir: &FsPath,
) -> Result<RuntimeBackupReport, RuntimeCommandError> {
    fs::create_dir_all(output_dir).map_err(|error| {
        RuntimeCommandError::input(format!(
            "failed to create backup directory `{}`: {error}",
            output_dir.display()
        ))
    })?;
    store
        .apply_plan(&base_migration_plan())
        .await
        .map_err(|error| RuntimeCommandError::store(error.to_string()))?;
    let rows = store
        .backup_raw_events()
        .await
        .map_err(|error| RuntimeCommandError::store(error.to_string()))?;
    let mut raw_events = String::new();
    for row in &rows {
        raw_events.push_str(&runtime_row_string(row, "raw_json")?);
        raw_events.push('\n');
    }
    let raw_events_path = output_dir.join("raw-events.jsonl");
    fs::write(&raw_events_path, raw_events.as_bytes()).map_err(|error| {
        RuntimeCommandError::input(format!(
            "failed to write backup raw events file `{}`: {error}",
            raw_events_path.display()
        ))
    })?;
    let raw_events_sha256 = sha256_hex(raw_events.as_bytes());
    let manifest = RuntimeBackupManifestDocument {
        format: "tangle-backup-v1".to_owned(),
        database: RuntimeBackupDatabaseDocument {
            namespace: config.database_config().namespace().to_owned(),
            database: config.database_config().database().to_owned(),
        },
        raw_events: RuntimeBackupArtifactDocument {
            path: "raw-events.jsonl".to_owned(),
            count: rows.len() as u64,
            sha256: raw_events_sha256.clone(),
        },
        surrealdb_export: RuntimeBackupOptionalArtifactDocument {
            available: false,
            path: None,
            sha256: None,
        },
    };
    let mut manifest_json =
        serde_json::to_vec_pretty(&manifest).expect("backup manifest is serializable");
    manifest_json.push(b'\n');
    let manifest_path = output_dir.join("manifest.json");
    fs::write(&manifest_path, &manifest_json).map_err(|error| {
        RuntimeCommandError::input(format!(
            "failed to write backup manifest file `{}`: {error}",
            manifest_path.display()
        ))
    })?;
    let manifest_sha256 = sha256_hex(&manifest_json);
    Ok(RuntimeBackupReport::new(
        output_dir.to_path_buf(),
        raw_events_path,
        rows.len() as u64,
        raw_events_sha256,
        manifest_path,
        manifest_sha256,
        false,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeRestoreReport {
    input_dir: PathBuf,
    raw_event_count: u64,
    raw_events_sha256: String,
    import_report: RuntimeEventImportReport,
    rebuild_report: RuntimeProjectionRebuildReport,
}

impl RuntimeRestoreReport {
    pub fn new(
        input_dir: PathBuf,
        raw_event_count: u64,
        raw_events_sha256: String,
        import_report: RuntimeEventImportReport,
        rebuild_report: RuntimeProjectionRebuildReport,
    ) -> Self {
        Self {
            input_dir,
            raw_event_count,
            raw_events_sha256,
            import_report,
            rebuild_report,
        }
    }

    pub fn input_dir(&self) -> &FsPath {
        &self.input_dir
    }

    pub fn raw_event_count(&self) -> u64 {
        self.raw_event_count
    }

    pub fn raw_events_sha256(&self) -> &str {
        &self.raw_events_sha256
    }

    pub fn import_report(&self) -> RuntimeEventImportReport {
        self.import_report
    }

    pub fn rebuild_report(&self) -> RuntimeProjectionRebuildReport {
        self.rebuild_report
    }
}

pub async fn restore_runtime_database(
    config: &TangleRuntimeConfig,
    input_dir: impl AsRef<FsPath>,
) -> Result<RuntimeRestoreReport, RuntimeCommandError> {
    let input_dir = input_dir.as_ref();
    tracing::info!("starting runtime restore");
    let store = connect_runtime_store(config).await?;
    let report = restore_runtime_store(config, &store, input_dir).await?;
    tracing::info!("finished runtime restore");
    Ok(report)
}

async fn restore_runtime_store(
    config: &TangleRuntimeConfig,
    store: &SurrealStore,
    input_dir: &FsPath,
) -> Result<RuntimeRestoreReport, RuntimeCommandError> {
    let manifest_path = input_dir.join("manifest.json");
    let manifest_raw = fs::read_to_string(&manifest_path).map_err(|error| {
        RuntimeCommandError::input(format!(
            "failed to read backup manifest file `{}`: {error}",
            manifest_path.display()
        ))
    })?;
    let manifest: RuntimeBackupManifestDocument =
        serde_json::from_str(&manifest_raw).map_err(|error| {
            RuntimeCommandError::input(format!("backup manifest JSON is invalid: {error}"))
        })?;
    validate_backup_manifest(&manifest)?;
    let raw_events_path = backup_artifact_path(input_dir, &manifest.raw_events.path)?;
    let raw_events = fs::read_to_string(&raw_events_path).map_err(|error| {
        RuntimeCommandError::input(format!(
            "failed to read backup raw events file `{}`: {error}",
            raw_events_path.display()
        ))
    })?;
    let raw_events_sha256 = sha256_hex(raw_events.as_bytes());
    if raw_events_sha256 != manifest.raw_events.sha256 {
        return Err(RuntimeCommandError::input(format!(
            "backup raw events checksum mismatch: expected {}, got {}",
            manifest.raw_events.sha256, raw_events_sha256
        )));
    }
    let events = parse_event_import_document(&raw_events)?;
    if events.len() as u64 != manifest.raw_events.count {
        return Err(RuntimeCommandError::input(format!(
            "backup raw events count mismatch: expected {}, got {}",
            manifest.raw_events.count,
            events.len()
        )));
    }
    let import_report = import_events_into_store(config, store, events).await?;
    let rebuild_report = rebuild_projections_in_store(config, store).await?;
    Ok(RuntimeRestoreReport::new(
        input_dir.to_path_buf(),
        manifest.raw_events.count,
        raw_events_sha256,
        import_report,
        rebuild_report,
    ))
}

fn validate_backup_manifest(
    manifest: &RuntimeBackupManifestDocument,
) -> Result<(), RuntimeCommandError> {
    if manifest.format != "tangle-backup-v1" {
        return Err(RuntimeCommandError::input(format!(
            "backup manifest format is unsupported: {}",
            manifest.format
        )));
    }
    if manifest.raw_events.path.trim().is_empty() {
        return Err(RuntimeCommandError::input(
            "backup manifest raw_events.path must not be empty",
        ));
    }
    Ok(())
}

fn backup_artifact_path(
    input_dir: &FsPath,
    artifact: &str,
) -> Result<PathBuf, RuntimeCommandError> {
    let path = FsPath::new(artifact);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(RuntimeCommandError::input(
            "backup manifest artifact paths must be relative to the backup directory",
        ));
    }
    Ok(input_dir.join(path))
}

fn runtime_row_string(
    row: &serde_json::Value,
    field: &'static str,
) -> Result<String, RuntimeCommandError> {
    row.get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| RuntimeCommandError::store(format!("stored row field `{field}` is invalid")))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeProjectionRebuildReport {
    scanned: u64,
    rebuilt: u64,
    projected: u64,
    skipped: u64,
}

impl RuntimeProjectionRebuildReport {
    pub fn new(scanned: u64, rebuilt: u64, projected: u64, skipped: u64) -> Self {
        Self {
            scanned,
            rebuilt,
            projected,
            skipped,
        }
    }

    pub fn scanned(self) -> u64 {
        self.scanned
    }

    pub fn rebuilt(self) -> u64 {
        self.rebuilt
    }

    pub fn projected(self) -> u64 {
        self.projected
    }

    pub fn skipped(self) -> u64 {
        self.skipped
    }

    fn record(&mut self, outcome: RuntimeProjectionRebuildOutcome) {
        self.scanned += 1;
        match outcome {
            RuntimeProjectionRebuildOutcome::Rebuilt { projected } => {
                self.rebuilt += 1;
                if projected {
                    self.projected += 1;
                }
            }
            RuntimeProjectionRebuildOutcome::Skipped => {
                self.skipped += 1;
            }
        }
    }
}

impl Default for RuntimeProjectionRebuildReport {
    fn default() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeProjectionRebuildOutcome {
    Rebuilt { projected: bool },
    Skipped,
}

pub async fn rebuild_projections(
    config: &TangleRuntimeConfig,
) -> Result<RuntimeProjectionRebuildReport, RuntimeCommandError> {
    tracing::info!("starting projection rebuild");
    let store = connect_runtime_store(config).await?;
    let report = rebuild_projections_in_store(config, &store).await?;
    tracing::info!("finished projection rebuild");
    Ok(report)
}

async fn rebuild_projections_in_store(
    config: &TangleRuntimeConfig,
    store: &SurrealStore,
) -> Result<RuntimeProjectionRebuildReport, RuntimeCommandError> {
    store
        .apply_plan(&base_migration_plan())
        .await
        .map_err(|error| RuntimeCommandError::store(error.to_string()))?;
    let rows = store
        .query_raw_events(&Filter::empty())
        .await
        .map_err(|error| RuntimeCommandError::store(error.to_string()))?;
    let validator = EventValidator::new(
        config.limits(),
        config
            .admission_policy()
            .clone()
            .with_write_auth_required(false),
    );
    let now = now_timestamp();
    let mut report = RuntimeProjectionRebuildReport::default();
    for row in rows {
        let raw = RawEventJson::new(&runtime_row_string(&row, "raw_json")?)
            .map_err(|error| RuntimeCommandError::store(error.to_string()))?;
        let event = parse_event_json(&raw)
            .map_err(|error| RuntimeCommandError::store(error.to_string()))?;
        let outcome = rebuild_single_event_projection(store, &validator, event, now).await?;
        report.record(outcome);
    }
    Ok(report)
}

async fn rebuild_single_event_projection(
    store: &SurrealStore,
    validator: &EventValidator,
    event: Event,
    now: UnixTimestamp,
) -> Result<RuntimeProjectionRebuildOutcome, RuntimeCommandError> {
    if is_non_auth_ephemeral(&event) {
        return Ok(RuntimeProjectionRebuildOutcome::Skipped);
    }
    let validated = match validator.validate(&event, &AdmissionContext::unauthenticated(), now) {
        Ok(validated) => validated,
        Err(_) => return Ok(RuntimeProjectionRebuildOutcome::Skipped),
    };
    if validated.admission().effect() != AdmissionEffect::AuthenticateOnly {
        let projected =
            project_stored_event(store, &event, validated.admission().effect(), now).await?;
        return Ok(RuntimeProjectionRebuildOutcome::Rebuilt { projected });
    }
    Ok(RuntimeProjectionRebuildOutcome::Skipped)
}

fn is_non_auth_ephemeral(event: &Event) -> bool {
    event.unsigned().kind().is_ephemeral() && event.unsigned().kind().as_u32() != 22_242
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeServerReport {
    listen_addr: SocketAddr,
}

impl RuntimeServerReport {
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self { listen_addr }
    }

    pub fn listen_addr(self) -> SocketAddr {
        self.listen_addr
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeServer {
    config: TangleRuntimeConfig,
    shutdown_signal: GracefulShutdownSignal,
}

impl RuntimeServer {
    pub fn new(config: TangleRuntimeConfig, shutdown_signal: GracefulShutdownSignal) -> Self {
        Self {
            config,
            shutdown_signal,
        }
    }

    pub async fn run(&self) -> Result<RuntimeServerReport, RuntimeCommandError> {
        tracing::info!("starting runtime server");
        let store = connect_runtime_store(&self.config).await?;
        store
            .apply_plan(&base_migration_plan())
            .await
            .map_err(|error| RuntimeCommandError::store(error.to_string()))?;
        let listener = TcpListener::bind(self.config.listen_addr())
            .await
            .map_err(|error| RuntimeCommandError::store(format!("listen failed: {error}")))?;
        let listen_addr = listener
            .local_addr()
            .map_err(|error| RuntimeCommandError::store(format!("listen addr failed: {error}")))?;
        let mut shutdown = self.shutdown_signal.subscribe();
        let app = runtime_router(self.config.clone(), store, self.shutdown_signal.clone());
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown.wait_for_shutdown().await;
            })
            .await
            .map_err(|error| RuntimeCommandError::store(format!("server failed: {error}")))?;
        tracing::info!("runtime server stopped");
        Ok(RuntimeServerReport::new(listen_addr))
    }
}

pub async fn run_runtime_server(
    config: TangleRuntimeConfig,
    shutdown_signal: GracefulShutdownSignal,
) -> Result<RuntimeServerReport, RuntimeCommandError> {
    RuntimeServer::new(config, shutdown_signal).run().await
}

async fn connect_runtime_store(
    config: &TangleRuntimeConfig,
) -> Result<SurrealStore, RuntimeCommandError> {
    SurrealStore::connect(config.database_config())
        .await
        .map_err(|error| RuntimeCommandError::store(error.to_string()))
}

#[derive(Clone)]
struct RuntimeRelayState {
    config: TangleRuntimeConfig,
    store: SurrealStore,
    shutdown_signal: GracefulShutdownSignal,
    event_tx: broadcast::Sender<Event>,
    next_connection_id: Arc<AtomicU64>,
}

impl RuntimeRelayState {
    fn new(
        config: TangleRuntimeConfig,
        store: SurrealStore,
        shutdown_signal: GracefulShutdownSignal,
    ) -> Self {
        let (event_tx, _) = broadcast::channel(config.limits().values().live_event_buffer as usize);
        Self {
            config,
            store,
            shutdown_signal,
            event_tx,
            next_connection_id: Arc::new(AtomicU64::new(1)),
        }
    }

    fn next_connection(&self) -> RelayConnection {
        let id = self.next_connection_id.fetch_add(1, Ordering::Relaxed);
        RelayConnection::new(
            RelayConnectionId::new(&format!("conn-{id}"))
                .expect("generated connection id is valid"),
            self.config.relay_connection_config().clone(),
        )
    }

    fn validator(&self) -> EventValidator {
        EventValidator::new(self.config.limits(), self.config.admission_policy().clone())
    }
}

fn runtime_router(
    config: TangleRuntimeConfig,
    store: SurrealStore,
    shutdown_signal: GracefulShutdownSignal,
) -> Router {
    let state = RuntimeRelayState::new(config, store, shutdown_signal);
    Router::new()
        .route("/", get(runtime_relay_info))
        .route("/ws", get(runtime_websocket_upgrade))
        .route("/healthz", get(runtime_healthz))
        .route("/readyz", get(runtime_readyz))
        .route("/metrics", get(runtime_metrics))
        .route("/api/listings", get(runtime_listings))
        .route("/api/listings/{pubkey}/{d}", get(runtime_listing_detail))
        .route(
            "/api/listings/{pubkey}/{d}/comments",
            get(runtime_listing_comments),
        )
        .route(
            "/api/listings/{pubkey}/{d}/reactions",
            get(runtime_listing_reactions),
        )
        .route("/api/forum/threads", get(runtime_forum_threads))
        .route(
            "/api/forum/threads/{event_id}",
            get(runtime_forum_thread_detail),
        )
        .route(
            "/api/forum/threads/{event_id}/comments",
            get(runtime_forum_thread_comments),
        )
        .route("/api/search", get(runtime_marketplace_search))
        .route("/api/sellers/{pubkey}", get(runtime_seller_detail))
        .route(
            "/api/admin/sellers/{pubkey}/approve",
            post(runtime_admin_approve_seller),
        )
        .route(
            "/api/admin/pubkeys/{pubkey}/block",
            post(runtime_admin_block_pubkey),
        )
        .route(
            "/api/admin/events/{event_id}/hide",
            post(runtime_admin_hide_event),
        )
        .route(
            "/api/admin/events/{event_id}/unhide",
            post(runtime_admin_unhide_event),
        )
        .route(
            "/api/admin/moderation/labels",
            get(runtime_admin_moderation_labels),
        )
        .route(
            "/api/admin/moderation/reports",
            get(runtime_admin_moderation_reports),
        )
        .with_state(state)
}

async fn runtime_relay_info(headers: HeaderMap) -> Response {
    relay_info(State(RelayInfoDocument::tangle_default()), headers).await
}

async fn runtime_websocket_upgrade(
    State(state): State<RuntimeRelayState>,
    websocket: WebSocketUpgrade,
) -> Response {
    websocket
        .on_upgrade(move |socket| async move {
            handle_websocket(socket, state).await;
        })
        .into_response()
}

async fn runtime_healthz() -> Json<HealthDocument> {
    healthz().await
}

async fn runtime_readyz(
    State(state): State<RuntimeRelayState>,
) -> (StatusCode, Json<ReadinessDocument>) {
    readyz(State(runtime_readiness_state(&state.store).await)).await
}

async fn runtime_readiness_state(store: &SurrealStore) -> ReadinessState {
    let database = readiness_status(store.ping().await);
    let migrations =
        readiness_status_after(database.is_ready(), runtime_migrations_ready(store)).await;
    let repository = readiness_status_after(database.is_ready() && migrations.is_ready(), async {
        store.metrics_snapshot().await.map(|_| ())
    })
    .await;
    ReadinessState::new(database, migrations, repository)
}

async fn runtime_migrations_ready(store: &SurrealStore) -> Result<(), RuntimeCommandError> {
    let applied = store
        .applied_migrations()
        .await
        .map_err(|error| RuntimeCommandError::store(error.to_string()))?;
    let plan = base_migration_plan();
    if applied.len() != plan.migrations().len() {
        return Err(RuntimeCommandError::store(
            "runtime migrations are incomplete",
        ));
    }
    for (applied, expected) in applied.iter().zip(plan.migrations()) {
        if applied.name() != expected.name() || applied.checksum() != expected.checksum() {
            return Err(RuntimeCommandError::store(
                "runtime migrations do not match",
            ));
        }
    }
    Ok(())
}

fn readiness_status<E>(result: Result<(), E>) -> ReadinessCheckStatus {
    if result.is_ok() {
        ReadinessCheckStatus::Ready
    } else {
        ReadinessCheckStatus::NotReady
    }
}

async fn readiness_status_after<F, E>(dependencies_ready: bool, result: F) -> ReadinessCheckStatus
where
    F: Future<Output = Result<(), E>>,
{
    if dependencies_ready {
        readiness_status(result.await)
    } else {
        ReadinessCheckStatus::NotReady
    }
}

async fn runtime_metrics(State(state): State<RuntimeRelayState>) -> Result<Response, ApiError> {
    metrics(State(MetricsHttpState::new(state.store))).await
}

async fn runtime_listings(
    State(state): State<RuntimeRelayState>,
    RawQuery(query): RawQuery,
) -> Result<Json<ListingsDocument>, ApiError> {
    listings(
        State(ListingsHttpState::new(
            state.store.clone(),
            state.config.limits(),
        )),
        RawQuery(query),
    )
    .await
}

async fn runtime_listing_detail(
    State(state): State<RuntimeRelayState>,
    Path((pubkey, d)): Path<(String, String)>,
) -> Result<Json<ListingDetailDocument>, ApiError> {
    listing_detail(
        State(ListingsHttpState::new(
            state.store.clone(),
            state.config.limits(),
        )),
        Path((pubkey, d)),
    )
    .await
}

async fn runtime_listing_comments(
    State(state): State<RuntimeRelayState>,
    Path((pubkey, d)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> Result<Json<ListingCommentsDocument>, ApiError> {
    listing_comments(
        State(ListingsHttpState::new(
            state.store.clone(),
            state.config.limits(),
        )),
        Path((pubkey, d)),
        RawQuery(query),
    )
    .await
}

async fn runtime_listing_reactions(
    State(state): State<RuntimeRelayState>,
    Path((pubkey, d)): Path<(String, String)>,
) -> Result<Json<ReactionCountsDocument>, ApiError> {
    listing_reactions(
        State(ListingsHttpState::new(
            state.store.clone(),
            state.config.limits(),
        )),
        Path((pubkey, d)),
    )
    .await
}

async fn runtime_forum_threads(
    State(state): State<RuntimeRelayState>,
    RawQuery(query): RawQuery,
) -> Result<Json<ForumThreadsDocument>, ApiError> {
    forum_threads(
        State(ListingsHttpState::new(
            state.store.clone(),
            state.config.limits(),
        )),
        RawQuery(query),
    )
    .await
}

async fn runtime_forum_thread_detail(
    State(state): State<RuntimeRelayState>,
    Path(event_id): Path<String>,
) -> Result<Json<ForumThreadDetailDocument>, ApiError> {
    forum_thread_detail(
        State(ListingsHttpState::new(
            state.store.clone(),
            state.config.limits(),
        )),
        Path(event_id),
    )
    .await
}

async fn runtime_forum_thread_comments(
    State(state): State<RuntimeRelayState>,
    Path(event_id): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<Json<ListingCommentsDocument>, ApiError> {
    forum_thread_comments(
        State(ListingsHttpState::new(
            state.store.clone(),
            state.config.limits(),
        )),
        Path(event_id),
        RawQuery(query),
    )
    .await
}

async fn runtime_marketplace_search(
    State(state): State<RuntimeRelayState>,
    RawQuery(query): RawQuery,
) -> Result<Json<ListingsDocument>, ApiError> {
    marketplace_search(
        State(ListingsHttpState::new(
            state.store.clone(),
            state.config.limits(),
        )),
        RawQuery(query),
    )
    .await
}

async fn runtime_seller_detail(
    State(state): State<RuntimeRelayState>,
    Path(pubkey): Path<String>,
) -> Result<Json<SellerDocument>, ApiError> {
    seller_detail(
        State(ListingsHttpState::new(
            state.store.clone(),
            state.config.limits(),
        )),
        Path(pubkey),
    )
    .await
}

async fn runtime_admin_approve_seller(
    State(state): State<RuntimeRelayState>,
    headers: HeaderMap,
    Path(pubkey): Path<String>,
) -> Result<Json<AdminPolicyDocument>, ApiError> {
    let _admin = require_admin_pubkey(&state.config, &headers)?;
    let pubkey = parse_pubkey("pubkey", &pubkey)?;
    state
        .store
        .set_seller_approved(pubkey.as_str(), true, now_timestamp())
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(AdminPolicyDocument::new(
        "approved",
        "seller",
        pubkey.as_str(),
    )))
}

async fn runtime_admin_block_pubkey(
    State(state): State<RuntimeRelayState>,
    headers: HeaderMap,
    Path(pubkey): Path<String>,
) -> Result<Json<AdminPolicyDocument>, ApiError> {
    let _admin = require_admin_pubkey(&state.config, &headers)?;
    let pubkey = parse_pubkey("pubkey", &pubkey)?;
    state
        .store
        .set_pubkey_blocked(pubkey.as_str(), true, now_timestamp())
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(AdminPolicyDocument::new(
        "blocked",
        "pubkey",
        pubkey.as_str(),
    )))
}

async fn runtime_admin_hide_event(
    State(state): State<RuntimeRelayState>,
    headers: HeaderMap,
    Path(event_id): Path<String>,
    Json(request): Json<AdminEventPolicyRequest>,
) -> Result<Json<AdminPolicyDocument>, ApiError> {
    let admin = require_admin_pubkey(&state.config, &headers)?;
    let event_id = EventId::new(&event_id)
        .map_err(|_| invalid_parameter("event_id", "must be a 64-character hex event id"))?;
    let reason = request.reason.unwrap_or_else(|| "admin policy".to_owned());
    let outcome = state
        .store
        .hide_event(
            &event_id,
            &reason,
            "admin_api",
            admin.as_str(),
            now_timestamp(),
        )
        .await
        .map_err(|_| ApiError::internal())?;
    if outcome == tangle_store_surreal::HiddenEventOutcome::NotFound {
        return Err(ApiError::not_found("event not found"));
    }
    Ok(Json(AdminPolicyDocument::new(
        "hidden",
        "event",
        event_id.as_str(),
    )))
}

async fn runtime_admin_unhide_event(
    State(state): State<RuntimeRelayState>,
    headers: HeaderMap,
    Path(event_id): Path<String>,
    Json(request): Json<AdminEventPolicyRequest>,
) -> Result<Json<AdminPolicyDocument>, ApiError> {
    let admin = require_admin_pubkey(&state.config, &headers)?;
    let event_id = EventId::new(&event_id)
        .map_err(|_| invalid_parameter("event_id", "must be a 64-character hex event id"))?;
    let reason = request.reason.unwrap_or_else(|| "admin policy".to_owned());
    let outcome = state
        .store
        .unhide_event(&event_id, &reason, admin.as_str(), now_timestamp())
        .await
        .map_err(|_| ApiError::internal())?;
    if outcome == tangle_store_surreal::HiddenEventOutcome::NotFound {
        return Err(ApiError::not_found("event not found"));
    }
    Ok(Json(AdminPolicyDocument::new(
        "unhidden",
        "event",
        event_id.as_str(),
    )))
}

async fn runtime_admin_moderation_labels(
    State(state): State<RuntimeRelayState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Result<Json<ModerationLabelsDocument>, ApiError> {
    let _admin = require_admin_pubkey(&state.config, &headers)?;
    let query = label_projection_query(query.as_deref().unwrap_or_default())?;
    let rows = state
        .store
        .query_label_projections(&query)
        .await
        .map_err(|_| ApiError::internal())?;
    let items = rows
        .iter()
        .map(moderation_label_document)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(ModerationLabelsDocument {
        items,
        next_cursor: None,
    }))
}

async fn runtime_admin_moderation_reports(
    State(state): State<RuntimeRelayState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Result<Json<ModerationReportsDocument>, ApiError> {
    let _admin = require_admin_pubkey(&state.config, &headers)?;
    let query = report_projection_query(query.as_deref().unwrap_or_default())?;
    let rows = state
        .store
        .query_report_projections(&query)
        .await
        .map_err(|_| ApiError::internal())?;
    let items = rows
        .iter()
        .map(moderation_report_document)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(ModerationReportsDocument {
        items,
        next_cursor: None,
    }))
}

async fn handle_websocket(mut socket: WebSocket, state: RuntimeRelayState) {
    let mut shutdown = state.shutdown_signal.subscribe();
    let mut event_rx = state.event_tx.subscribe();
    let mut loop_state = ClientMessageLoop::new(state.next_connection());
    let event_handler = EventMessageHandler::new(state.store.clone(), state.validator())
        .with_durable_write_rate_limit(state.config.durable_write_rate_limit());
    let auth_handler = AuthMessageHandler;
    let req_handler = ReqMessageHandler::new(
        state.store.clone(),
        NostrFilterCompiler::new(state.config.limits()),
    );
    let close_handler = CloseMessageHandler;
    let fanout = LiveEventFanout;
    let challenge = auth_handler.issue_challenge(
        loop_state.connection_mut(),
        "challenge-001",
        UnixTimestamp::new(1_714_124_430),
    );
    let _ = send_relay_message(&mut socket, &challenge).await;
    loop {
        tokio::select! {
            _ = shutdown.wait_for_shutdown() => {
                let _ = socket.send(Message::Close(None)).await;
                break;
            }
            event = event_rx.recv() => {
                let messages = event
                    .ok()
                    .into_iter()
                    .flat_map(|event| fanout.fanout(loop_state.connection(), &event));
                for message in messages {
                    let fanout_failed = send_relay_message(&mut socket, &message).await.is_err();
                    if fanout_failed { return; }
                }
            }
            frame = socket.recv() => {
                let Some(frame) = frame else { break; };
                let Ok(frame) = frame else { break; };
                match loop_state.handle_frame_at(client_frame_from_message(frame), now_timestamp()) {
                    ClientFrameOutcome::Message(message) => {
                        let message_failed = handle_client_message(
                            &mut socket,
                            &mut loop_state,
                            ClientMessageHandlers {
                                event: &event_handler,
                                auth: &auth_handler,
                                req: &req_handler,
                                close: &close_handler,
                                event_tx: &state.event_tx,
                            },
                            message,
                        )
                        .await
                        .is_err();
                        if message_failed { break; }
                    }
                    ClientFrameOutcome::Reject(message) => {
                        let reject_failed = send_relay_message(&mut socket, &message).await.is_err();
                        if reject_failed { break; }
                    }
                    ClientFrameOutcome::Ignore => {}
                    ClientFrameOutcome::Close => break,
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
struct ClientMessageHandlers<'a> {
    event: &'a EventMessageHandler,
    auth: &'a AuthMessageHandler,
    req: &'a ReqMessageHandler,
    close: &'a CloseMessageHandler,
    event_tx: &'a broadcast::Sender<Event>,
}

async fn handle_client_message(
    socket: &mut WebSocket,
    loop_state: &mut ClientMessageLoop,
    handlers: ClientMessageHandlers<'_>,
    message: ClientMessage,
) -> Result<(), axum::Error> {
    match message {
        ClientMessage::Event(event) => {
            let accepted_event = event.clone();
            let response = handlers
                .event
                .handle_event(
                    loop_state.connection(),
                    event,
                    now_timestamp(),
                    now_timestamp(),
                )
                .await;
            let accepted = matches!(response, RelayMessage::Ok { accepted: true, .. });
            send_relay_message(socket, &response).await?;
            if accepted {
                let _ = handlers.event_tx.send(accepted_event);
            }
        }
        ClientMessage::Auth(event) => {
            let response = handlers.auth.handle_auth(
                loop_state.connection_mut(),
                event.clone(),
                event.unsigned().created_at(),
            );
            send_relay_message(socket, &response).await?;
        }
        ClientMessage::Req {
            subscription_id,
            filters,
        } => {
            for response in handlers
                .req
                .handle_req(loop_state.connection_mut(), subscription_id, filters)
                .await
            {
                send_relay_message(socket, &response).await?;
            }
        }
        ClientMessage::Close(subscription_id) => {
            handlers
                .close
                .handle_close(loop_state.connection_mut(), &subscription_id);
        }
    }
    Ok(())
}

fn client_frame_from_message(message: Message) -> ClientFrame {
    match message {
        Message::Text(value) => ClientFrame::Text(value.to_string()),
        Message::Binary(value) => ClientFrame::Binary(value.to_vec()),
        Message::Ping(value) => ClientFrame::Ping(value.to_vec()),
        Message::Pong(value) => ClientFrame::Pong(value.to_vec()),
        Message::Close(_) => ClientFrame::Close,
    }
}

async fn send_relay_message(
    socket: &mut WebSocket,
    message: &RelayMessage,
) -> Result<(), axum::Error> {
    socket.send(Message::Text(message.encode().into())).await
}

fn now_timestamp() -> UnixTimestamp {
    UnixTimestamp::new(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0),
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RuntimeConfigDocument {
    server: RuntimeServerConfigDocument,
    database: RuntimeDatabaseConfigDocument,
    auth: RuntimeAuthConfigDocument,
    limits: RuntimeLimitsConfigDocument,
    #[serde(default)]
    policy: RuntimePolicyConfigDocument,
    #[serde(default)]
    observability: RuntimeObservabilityConfigDocument,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RuntimeServerConfigDocument {
    listen_addr: String,
    relay_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RuntimeDatabaseConfigDocument {
    mode: RuntimeDatabaseModeDocument,
    endpoint: Option<String>,
    path: Option<String>,
    username: Option<String>,
    password: Option<String>,
    namespace: String,
    database: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeDatabaseModeDocument {
    Memory,
    RocksDb,
    Http,
    #[serde(alias = "websocket")]
    WebSocket,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RuntimeAuthConfigDocument {
    challenge_ttl_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RuntimeLimitsConfigDocument {
    message_rate_limit: RuntimeRateLimitConfigDocument,
    #[serde(default)]
    runtime: RuntimeLimitValuesDocument,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RuntimeRateLimitConfigDocument {
    limit: u64,
    window_seconds: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
struct RuntimeLimitValuesDocument {
    max_event_bytes: Option<u64>,
    max_content_bytes: Option<u64>,
    max_tags_per_event: Option<u64>,
    max_tag_values_per_tag: Option<u64>,
    max_tag_value_bytes: Option<u64>,
    max_filters_per_subscription: Option<u64>,
    max_subscriptions_per_connection: Option<u64>,
    max_search_query_bytes: Option<u64>,
    max_search_tokens: Option<u64>,
    max_filter_complexity: Option<u64>,
    max_future_seconds: Option<u64>,
    live_event_buffer: Option<u64>,
    pending_store_events: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
struct RuntimePolicyConfigDocument {
    require_write_auth: Option<bool>,
    unapproved_seller_action: Option<RuntimeUnapprovedSellerActionDocument>,
    write_rate_limit: Option<RuntimeRateLimitConfigDocument>,
    #[serde(default)]
    admin_pubkeys: Vec<String>,
    #[serde(default)]
    approved_sellers: Vec<String>,
    #[serde(default)]
    blocked_pubkeys: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
struct RuntimeObservabilityConfigDocument {
    #[serde(default)]
    tracing: RuntimeTracingConfigDocument,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
struct RuntimeTracingConfigDocument {
    enabled: Option<bool>,
    filter: Option<String>,
    format: Option<RuntimeTracingFormatDocument>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeTracingFormatDocument {
    Compact,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeUnapprovedSellerActionDocument {
    StoreRawOnly,
    RejectWrite,
}

fn runtime_config_from_document(
    document: RuntimeConfigDocument,
) -> Result<TangleRuntimeConfig, RuntimeConfigError> {
    let listen_addr = document
        .server
        .listen_addr
        .parse::<SocketAddr>()
        .map_err(|error| {
            RuntimeConfigError::invalid(format!("server.listen_addr is invalid: {error}"))
        })?;
    let limits = runtime_limits_from_document(document.limits)?;
    let relay_connection = RelayConnectionConfig::new(
        document.server.relay_url,
        document.auth.challenge_ttl_seconds,
        limits.message_rate_limit,
        limits.runtime,
    )
    .map_err(RuntimeConfigError::invalid)?;
    let database = database_config_from_document(document.database)?;
    let durable_write_rate_limit = durable_write_rate_limit_from_document(&document.policy)?;
    let admin_pubkeys = admin_pubkeys_from_document(&document.policy)?;
    let admission_policy = admission_policy_from_document(&document.policy)?;
    let tracing = tracing_config_from_document(document.observability.tracing)?;
    Ok(TangleRuntimeConfig {
        listen_addr,
        relay_connection,
        database,
        admission_policy,
        durable_write_rate_limit,
        admin_pubkeys,
        limits: limits.runtime,
        tracing,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResolvedRuntimeLimits {
    message_rate_limit: RateLimitConfig,
    runtime: RuntimeLimits,
}

fn runtime_limits_from_document(
    document: RuntimeLimitsConfigDocument,
) -> Result<ResolvedRuntimeLimits, RuntimeConfigError> {
    let message_rate_limit = RateLimitConfig::new(
        document.message_rate_limit.limit,
        document.message_rate_limit.window_seconds,
    )
    .map_err(|error| RuntimeConfigError::invalid(error.to_string()))?;
    let runtime = RuntimeLimits::from_values(document.runtime.apply(RuntimeLimitValues::default()))
        .map_err(|error| RuntimeConfigError::invalid(error.to_string()))?;
    Ok(ResolvedRuntimeLimits {
        message_rate_limit,
        runtime,
    })
}

fn database_config_from_document(
    document: RuntimeDatabaseConfigDocument,
) -> Result<SurrealConnectionConfig, RuntimeConfigError> {
    match document.mode {
        RuntimeDatabaseModeDocument::Memory => {
            if document.endpoint.is_some() {
                return Err(RuntimeConfigError::invalid(
                    "database.endpoint must be omitted for memory mode",
                ));
            }
            if document.path.is_some() {
                return Err(RuntimeConfigError::invalid(
                    "database.path must be omitted for memory mode",
                ));
            }
            if document.username.is_some() || document.password.is_some() {
                return Err(RuntimeConfigError::invalid(
                    "database credentials must be omitted for memory mode",
                ));
            }
            SurrealConnectionConfig::memory(&document.namespace, &document.database)
        }
        RuntimeDatabaseModeDocument::RocksDb => {
            if document.endpoint.is_some() {
                return Err(RuntimeConfigError::invalid(
                    "database.endpoint must be omitted for rocksdb mode",
                ));
            }
            if document.username.is_some() || document.password.is_some() {
                return Err(RuntimeConfigError::invalid(
                    "database credentials must be omitted for rocksdb mode",
                ));
            }
            SurrealConnectionConfig::rocksdb(
                &required_path(document.path, "rocksdb")?,
                &document.namespace,
                &document.database,
            )
        }
        RuntimeDatabaseModeDocument::Http => {
            let endpoint = required_endpoint(document.endpoint, "http")?;
            let username = required_database_credential(document.username, "username", "http")?;
            let password = required_database_credential(document.password, "password", "http")?;
            SurrealConnectionConfig::http(&endpoint, &document.namespace, &document.database)
                .and_then(|config| config.with_root_credentials(&username, &password))
        }
        RuntimeDatabaseModeDocument::WebSocket => {
            let endpoint = required_endpoint(document.endpoint, "websocket")?;
            let username =
                required_database_credential(document.username, "username", "websocket")?;
            let password =
                required_database_credential(document.password, "password", "websocket")?;
            SurrealConnectionConfig::websocket(&endpoint, &document.namespace, &document.database)
                .and_then(|config| config.with_root_credentials(&username, &password))
        }
    }
    .map_err(|error| RuntimeConfigError::invalid(error.to_string()))
}

fn required_endpoint(value: Option<String>, mode: &str) -> Result<String, RuntimeConfigError> {
    value.ok_or_else(|| {
        RuntimeConfigError::invalid(format!("database.endpoint is required for {mode} mode"))
    })
}

fn required_path(value: Option<String>, mode: &str) -> Result<String, RuntimeConfigError> {
    value.ok_or_else(|| {
        RuntimeConfigError::invalid(format!("database.path is required for {mode} mode"))
    })
}

fn required_database_credential(
    value: Option<String>,
    field: &str,
    mode: &str,
) -> Result<String, RuntimeConfigError> {
    value.ok_or_else(|| {
        RuntimeConfigError::invalid(format!("database.{field} is required for {mode} mode"))
    })
}

fn durable_write_rate_limit_from_document(
    document: &RuntimePolicyConfigDocument,
) -> Result<Option<RateLimitConfig>, RuntimeConfigError> {
    document
        .write_rate_limit
        .as_ref()
        .map(|value| {
            RateLimitConfig::new(value.limit, value.window_seconds)
                .map_err(|error| RuntimeConfigError::invalid(error.to_string()))
        })
        .transpose()
}

fn tracing_config_from_document(
    document: RuntimeTracingConfigDocument,
) -> Result<RuntimeTracingConfig, RuntimeConfigError> {
    let default = RuntimeTracingConfig::disabled();
    let format = match document.format {
        Some(RuntimeTracingFormatDocument::Compact) => RuntimeTracingFormat::Compact,
        Some(RuntimeTracingFormatDocument::Json) => RuntimeTracingFormat::Json,
        None => default.format(),
    };
    RuntimeTracingConfig::new(
        document.enabled.unwrap_or(default.enabled()),
        document
            .filter
            .unwrap_or_else(|| default.filter().to_owned()),
        format,
    )
}

fn admin_pubkeys_from_document(
    document: &RuntimePolicyConfigDocument,
) -> Result<BTreeSet<PublicKeyHex>, RuntimeConfigError> {
    document
        .admin_pubkeys
        .iter()
        .map(|pubkey| {
            PublicKeyHex::new(pubkey.as_str()).map_err(|error| {
                RuntimeConfigError::invalid(format!(
                    "policy.admin_pubkeys contains invalid pubkey: {error}"
                ))
            })
        })
        .collect()
}

fn admission_policy_from_document(
    document: &RuntimePolicyConfigDocument,
) -> Result<AdmissionPolicy, RuntimeConfigError> {
    let action = match document.unapproved_seller_action {
        Some(RuntimeUnapprovedSellerActionDocument::StoreRawOnly) | None => {
            UnapprovedSellerAction::StoreRawOnly
        }
        Some(RuntimeUnapprovedSellerActionDocument::RejectWrite) => {
            UnapprovedSellerAction::RejectWrite
        }
    };
    let mut policy = AdmissionPolicy::new()
        .with_write_auth_required(document.require_write_auth.unwrap_or(true))
        .with_unapproved_seller_action(action);
    for pubkey in &document.approved_sellers {
        policy = policy.approve_seller(PublicKeyHex::new(pubkey.as_str()).map_err(|error| {
            RuntimeConfigError::invalid(format!(
                "policy.approved_sellers contains invalid pubkey: {error}"
            ))
        })?);
    }
    for pubkey in &document.blocked_pubkeys {
        policy = policy.block_pubkey(PublicKeyHex::new(pubkey.as_str()).map_err(|error| {
            RuntimeConfigError::invalid(format!(
                "policy.blocked_pubkeys contains invalid pubkey: {error}"
            ))
        })?);
    }
    Ok(policy)
}

impl RuntimeLimitValuesDocument {
    fn apply(self, mut values: RuntimeLimitValues) -> RuntimeLimitValues {
        if let Some(value) = self.max_event_bytes {
            values.max_event_bytes = value;
        }
        if let Some(value) = self.max_content_bytes {
            values.max_content_bytes = value;
        }
        if let Some(value) = self.max_tags_per_event {
            values.max_tags_per_event = value;
        }
        if let Some(value) = self.max_tag_values_per_tag {
            values.max_tag_values_per_tag = value;
        }
        if let Some(value) = self.max_tag_value_bytes {
            values.max_tag_value_bytes = value;
        }
        if let Some(value) = self.max_filters_per_subscription {
            values.max_filters_per_subscription = value;
        }
        if let Some(value) = self.max_subscriptions_per_connection {
            values.max_subscriptions_per_connection = value;
        }
        if let Some(value) = self.max_search_query_bytes {
            values.max_search_query_bytes = value;
        }
        if let Some(value) = self.max_search_tokens {
            values.max_search_tokens = value;
        }
        if let Some(value) = self.max_filter_complexity {
            values.max_filter_complexity = value;
        }
        if let Some(value) = self.max_future_seconds {
            values.max_future_seconds = value;
        }
        if let Some(value) = self.live_event_buffer {
            values.live_event_buffer = value;
        }
        if let Some(value) = self.pending_store_events {
            values.pending_store_events = value;
        }
        values
    }
}

#[derive(Debug, Clone)]
pub struct GracefulShutdownSignal {
    sender: tokio::sync::watch::Sender<bool>,
}

impl GracefulShutdownSignal {
    pub fn new() -> (Self, GracefulShutdownListener) {
        let (sender, receiver) = tokio::sync::watch::channel(false);
        (Self { sender }, GracefulShutdownListener { receiver })
    }

    pub fn subscribe(&self) -> GracefulShutdownListener {
        GracefulShutdownListener {
            receiver: self.sender.subscribe(),
        }
    }

    pub fn request_shutdown(&self) -> bool {
        self.sender.send(true).is_ok()
    }

    pub fn is_shutdown_requested(&self) -> bool {
        *self.sender.borrow()
    }
}

#[derive(Debug, Clone)]
pub struct GracefulShutdownListener {
    receiver: tokio::sync::watch::Receiver<bool>,
}

impl GracefulShutdownListener {
    pub fn is_shutdown_requested(&self) -> bool {
        *self.receiver.borrow()
    }

    pub async fn wait_for_shutdown(&mut self) {
        while !self.is_shutdown_requested() && self.receiver.changed().await.is_ok() {}
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientFrame {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClientFrameOutcome {
    Message(ClientMessage),
    Reject(RelayMessage),
    Ignore,
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientMessageLoop {
    connection: RelayConnection,
}

impl ClientMessageLoop {
    pub fn new(connection: RelayConnection) -> Self {
        Self { connection }
    }

    pub fn connection(&self) -> &RelayConnection {
        &self.connection
    }

    pub fn connection_mut(&mut self) -> &mut RelayConnection {
        &mut self.connection
    }

    pub fn handle_frame(&mut self, frame: ClientFrame) -> ClientFrameOutcome {
        self.handle_frame_at(frame, UnixTimestamp::new(0))
    }

    pub fn handle_frame_at(
        &mut self,
        frame: ClientFrame,
        now: UnixTimestamp,
    ) -> ClientFrameOutcome {
        if matches!(frame, ClientFrame::Text(_) | ClientFrame::Binary(_)) {
            let key = self.connection.id().as_str().to_owned();
            match self
                .connection
                .rate_limiter_mut()
                .check(&key, now, 1)
                .unwrap_or(RateLimitDecision::Rejected {
                    retry_after_seconds: 0,
                    reset_at: now,
                }) {
                RateLimitDecision::Accepted { .. } => {}
                RateLimitDecision::Rejected {
                    retry_after_seconds,
                    ..
                } => {
                    return ClientFrameOutcome::Reject(RelayMessage::Notice(format!(
                        "rate-limited: retry after {retry_after_seconds} seconds"
                    )));
                }
            }
        }
        match frame {
            ClientFrame::Text(raw) => parse_client_message(&raw)
                .map(ClientFrameOutcome::Message)
                .unwrap_or_else(|error| {
                    ClientFrameOutcome::Reject(RelayMessage::Notice(format!("invalid: {error}")))
                }),
            ClientFrame::Binary(_) => ClientFrameOutcome::Reject(RelayMessage::Notice(
                "unsupported: binary websocket messages are not supported".to_owned(),
            )),
            ClientFrame::Ping(_) | ClientFrame::Pong(_) => ClientFrameOutcome::Ignore,
            ClientFrame::Close => ClientFrameOutcome::Close,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EventMessageHandler {
    store: SurrealStore,
    validator: EventValidator,
    durable_write_rate_limit: Option<RateLimitConfig>,
}

impl EventMessageHandler {
    pub fn new(store: SurrealStore, validator: EventValidator) -> Self {
        Self {
            store,
            validator,
            durable_write_rate_limit: None,
        }
    }

    pub fn store(&self) -> &SurrealStore {
        &self.store
    }

    pub fn validator(&self) -> &EventValidator {
        &self.validator
    }

    pub fn durable_write_rate_limit(&self) -> Option<RateLimitConfig> {
        self.durable_write_rate_limit
    }

    pub fn with_durable_write_rate_limit(mut self, config: Option<RateLimitConfig>) -> Self {
        self.durable_write_rate_limit = config;
        self
    }

    pub async fn handle_event(
        &self,
        connection: &RelayConnection,
        event: Event,
        received_at: UnixTimestamp,
        now: UnixTimestamp,
    ) -> RelayMessage {
        let event_id = event.id().clone();
        let context = admission_context(connection);
        let validated = match self.validator.validate(&event, &context, now) {
            Ok(validated) => validated,
            Err(error) => return ok_rejected(event_id, format!("invalid: {error}")),
        };
        if validated.admission().effect() == AdmissionEffect::AuthenticateOnly {
            return ok_rejected(event_id, "invalid: auth events must use AUTH".to_owned());
        }
        let effect = match self
            .effective_admission_effect(&event, validated.admission().effect())
            .await
        {
            Ok(effect) => effect,
            Err(_) => return ok_rejected(event_id, "error: policy unavailable".to_owned()),
        };
        if let Some(config) = self.durable_write_rate_limit {
            match self
                .store
                .check_durable_rate_limit(
                    &durable_write_rate_limit_key(validated.author_pubkey()),
                    config.limit,
                    config.window_seconds,
                    1,
                    now,
                )
                .await
            {
                Ok(DurableRateLimitDecision::Accepted { .. }) => {}
                Ok(DurableRateLimitDecision::Rejected {
                    retry_after_seconds,
                    ..
                }) => {
                    return ok_rejected(
                        event_id,
                        format!("rate-limited: retry after {retry_after_seconds} seconds"),
                    );
                }
                Err(_) => {
                    return ok_rejected(event_id, "error: rate limit unavailable".to_owned());
                }
            }
        }
        if event.unsigned().kind().is_ephemeral() {
            return ok_accepted(event_id);
        }
        let raw_outcome = match self
            .store
            .store_raw_event(&StoredEvent::new(event.clone(), received_at))
            .await
        {
            Ok(outcome) => outcome,
            Err(_) => return ok_rejected(event_id, "error: store unavailable".to_owned()),
        };
        if raw_outcome == StoreEventOutcome::Duplicate {
            return ok_accepted(event_id);
        }
        if project_stored_event(&self.store, &event, effect, now)
            .await
            .is_err()
        {
            return ok_rejected(event_id, "error: projection failed".to_owned());
        }
        ok_accepted(event_id)
    }

    async fn effective_admission_effect(
        &self,
        event: &Event,
        fallback: AdmissionEffect,
    ) -> Result<AdmissionEffect, tangle_store_surreal::SurrealStoreError> {
        if event.unsigned().kind().as_u32() != 30_402 {
            return Ok(fallback);
        }
        let Some(row) = self
            .store
            .relay_user_row(event.unsigned().pubkey().as_str())
            .await?
        else {
            return Ok(fallback);
        };
        if row
            .get("blocked")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return Ok(AdmissionEffect::StoreRawWithoutPublicListingProjection);
        }
        if row
            .get("seller_approved")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return Ok(AdmissionEffect::StoreRawAndProjectPublicListing);
        }
        Ok(fallback)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthMessageHandler;

impl AuthMessageHandler {
    pub fn issue_challenge(
        &self,
        connection: &mut RelayConnection,
        challenge: &str,
        issued_at: UnixTimestamp,
    ) -> RelayMessage {
        match connection.auth_mut().issue_challenge(challenge, issued_at) {
            Ok(challenge) => RelayMessage::Auth(challenge.value),
            Err(error) => RelayMessage::Notice(format!("error: {error}")),
        }
    }

    pub fn handle_auth(
        &self,
        connection: &mut RelayConnection,
        event: Event,
        now: UnixTimestamp,
    ) -> RelayMessage {
        let event_id = event.id().clone();
        let auth = match parse_relay_auth_event(&event) {
            Ok(Some(auth)) => auth,
            Ok(None) => {
                return ok_rejected(
                    event_id,
                    "invalid: AUTH message must contain kind 22242".to_owned(),
                );
            }
            Err(error) => return ok_rejected(event_id, format!("invalid: {error}")),
        };
        match connection.auth_mut().authenticate(&auth, now) {
            Ok(_) => ok_accepted(event_id),
            Err(error) => ok_rejected(event_id, format!("auth-required: {error}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReqMessageHandler {
    store: SurrealStore,
    compiler: NostrFilterCompiler,
}

impl ReqMessageHandler {
    pub fn new(store: SurrealStore, compiler: NostrFilterCompiler) -> Self {
        Self { store, compiler }
    }

    pub fn store(&self) -> &SurrealStore {
        &self.store
    }

    pub fn compiler(&self) -> NostrFilterCompiler {
        self.compiler
    }

    pub async fn handle_req(
        &self,
        connection: &mut RelayConnection,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
    ) -> Vec<RelayMessage> {
        let plan = match self
            .compiler
            .compile(&filters, QueryExecutionMode::HistoricalThenLive)
        {
            Ok(plan) => plan,
            Err(error) => {
                return vec![RelayMessage::Closed {
                    subscription_id,
                    message: format!("unsupported: {error}"),
                }];
            }
        };
        if let Err(error) = connection
            .subscriptions_mut()
            .subscribe(subscription_id.clone(), plan)
        {
            return vec![RelayMessage::Closed {
                subscription_id,
                message: format!("error: {error}"),
            }];
        }
        let events = match self.query_historical_events(&filters).await {
            Ok(events) => events,
            Err(error) => {
                return vec![RelayMessage::Closed {
                    subscription_id,
                    message: error.message().to_owned(),
                }];
            }
        };
        let mut messages = events
            .into_iter()
            .map(|event| RelayMessage::Event {
                subscription_id: subscription_id.clone(),
                event,
            })
            .collect::<Vec<_>>();
        messages.push(RelayMessage::Eose(subscription_id));
        messages
    }

    async fn query_historical_events(&self, filters: &[Filter]) -> Result<Vec<Event>, ApiError> {
        let mut seen = BTreeSet::new();
        let mut events = Vec::new();
        for filter in filters {
            for event in self.query_single_filter_events(filter).await? {
                if seen.insert(event.id().clone()) {
                    events.push(event);
                }
            }
        }
        Ok(events)
    }

    async fn query_single_filter_events(&self, filter: &Filter) -> Result<Vec<Event>, ApiError> {
        let rows = if filter.search().is_some() {
            self.query_search_filter_rows(filter).await?
        } else if filter.ids().is_empty()
            && filter
                .kinds()
                .iter()
                .any(|kind| kind.is_replaceable() || kind.is_addressable())
        {
            self.store
                .query_current_events(filter)
                .await
                .map_err(|_| ApiError::internal())?
        } else {
            self.store
                .query_raw_events(filter)
                .await
                .map_err(|_| ApiError::internal())?
        };
        rows.iter().map(event_from_store_row).collect()
    }

    async fn query_search_filter_rows(
        &self,
        filter: &Filter,
    ) -> Result<Vec<serde_json::Value>, ApiError> {
        let mut query = SearchDocumentQuery::new()
            .with_doc_type("listing")
            .with_visible(true);
        if let Some(search) = filter.search() {
            query = query.with_text(search);
        }
        if filter.kinds().len() == 1 {
            query = query.with_kind(filter.kinds()[0].as_u32());
        }
        if filter.authors().len() == 1 {
            query = query.with_pubkey(filter.authors()[0].as_str());
        }
        if let Some(limit) = filter.limit() {
            query = query.with_limit(limit);
        }
        let docs = self
            .store
            .query_search_documents(&query)
            .await
            .map_err(|_| ApiError::internal())?;
        let mut rows = Vec::new();
        for doc in docs {
            let event_id =
                EventId::new(&string_field(&doc, "event_id")?).map_err(|_| ApiError::internal())?;
            if let Some(row) = self
                .store
                .raw_event_row(&event_id)
                .await
                .map_err(|_| ApiError::internal())?
            {
                rows.push(row);
            }
        }
        Ok(rows)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseMessageOutcome {
    Closed,
    NotFound,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CloseMessageHandler;

impl CloseMessageHandler {
    pub fn handle_close(
        &self,
        connection: &mut RelayConnection,
        subscription_id: &SubscriptionId,
    ) -> CloseMessageOutcome {
        match connection.subscriptions_mut().close(subscription_id) {
            SubscriptionCloseOutcome::Closed => CloseMessageOutcome::Closed,
            SubscriptionCloseOutcome::NotFound => CloseMessageOutcome::NotFound,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LiveEventFanout;

impl LiveEventFanout {
    pub fn fanout(&self, connection: &RelayConnection, event: &Event) -> Vec<RelayMessage> {
        connection
            .subscriptions()
            .match_event(event)
            .into_iter()
            .map(|matched| RelayMessage::Event {
                subscription_id: matched.subscription_id,
                event: event.clone(),
            })
            .collect()
    }
}

fn admission_context(connection: &RelayConnection) -> AdmissionContext {
    connection
        .auth()
        .authenticated_pubkey()
        .cloned()
        .map(AdmissionContext::authenticated)
        .unwrap_or_else(AdmissionContext::unauthenticated)
}

fn durable_write_rate_limit_key(pubkey: &PublicKeyHex) -> String {
    format!("event_write:{}", pubkey.as_str())
}

fn ok_accepted(event_id: EventId) -> RelayMessage {
    RelayMessage::Ok {
        event_id,
        accepted: true,
        message: String::new(),
    }
}

fn ok_rejected(event_id: EventId, message: String) -> RelayMessage {
    RelayMessage::Ok {
        event_id,
        accepted: false,
        message,
    }
}

fn event_from_store_row(row: &serde_json::Value) -> Result<Event, ApiError> {
    let raw =
        RawEventJson::new(&string_field(row, "raw_json")?).map_err(|_| ApiError::internal())?;
    parse_event_json(&raw).map_err(|_| ApiError::internal())
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
            version: TANGLE_RELAY_VERSION.to_owned(),
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

#[derive(Debug, Clone)]
pub struct MetricsHttpState {
    store: SurrealStore,
}

impl MetricsHttpState {
    pub fn new(store: SurrealStore) -> Self {
        Self { store }
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
pub struct ListingCommentsDocument {
    pub items: Vec<CommentItemDocument>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommentItemDocument {
    pub event_id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub content: String,
    pub root: CommentReferenceDocument,
    pub parent: CommentReferenceDocument,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommentReferenceDocument {
    pub target_type: String,
    pub target_ref: String,
    pub kind: String,
    pub author: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactionCountsDocument {
    pub target_event_id: String,
    pub target_kind: Option<String>,
    pub like_count: u64,
    pub dislike_count: u64,
    pub emoji_count: u64,
    pub text_count: u64,
    pub total_count: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForumThreadsDocument {
    pub items: Vec<ForumThreadItemDocument>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForumThreadItemDocument {
    pub event_id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub title: Option<String>,
    pub content: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForumThreadDetailDocument {
    pub thread: ForumThreadItemDocument,
    pub raw_event: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SellerDocument {
    pub pubkey: String,
    pub event_id: Option<String>,
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub about: Option<String>,
    pub picture: Option<String>,
    pub website: Option<String>,
    pub nip05: Option<String>,
    pub lud16: Option<String>,
    pub regions: Vec<String>,
    pub categories: Vec<String>,
    pub trust_markers: Vec<String>,
    pub approved: bool,
    pub blocked: bool,
    pub active_listing_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminPolicyDocument {
    pub status: String,
    pub target_type: String,
    pub target_ref: String,
}

impl AdminPolicyDocument {
    pub fn new(status: &str, target_type: &str, target_ref: &str) -> Self {
        Self {
            status: status.to_owned(),
            target_type: target_type.to_owned(),
            target_ref: target_ref.to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModerationLabelsDocument {
    pub items: Vec<ModerationLabelDocument>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModerationLabelDocument {
    pub label_id: String,
    pub event_id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub content: String,
    pub namespace: String,
    pub label: String,
    pub target_type: String,
    pub target_ref: String,
    pub projected_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModerationReportsDocument {
    pub items: Vec<ModerationReportDocument>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModerationReportDocument {
    pub report_id: String,
    pub event_id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub content: String,
    pub target_type: String,
    pub target_ref: String,
    pub report_type: String,
    pub reported_pubkeys: Vec<String>,
    pub server_urls: Vec<String>,
    pub projected_at: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct AdminEventPolicyRequest {
    pub reason: Option<String>,
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
            "min_price" => {
                let value = required_value("min_price", &value)?;
                set_once("min_price", &mut spec.min_price, value)?;
            }
            "max_price" => {
                let value = required_value("max_price", &value)?;
                set_once("max_price", &mut spec.max_price, value)?;
            }
            "fulfillment" => push_fulfillment_values(&value, &mut spec.fulfillment)?,
            "delivery_only" => {
                let value = parse_bool("delivery_only", &value)?;
                set_once("delivery_only", &mut spec.delivery_only, value)?;
            }
            "pickup" => set_once("pickup", &mut spec.pickup, parse_bool("pickup", &value)?)?,
            "geohash" => set_once("geohash", &mut geohash, parse_geohash_query_value(&value)?)?,
            "lat" => {
                let value = parse_microdegrees("lat", &value, -90_000_000, 90_000_000)?;
                set_once("lat", &mut spec.latitude_microdegrees, value)?;
            }
            "lon" => {
                let value = parse_microdegrees("lon", &value, -180_000_000, 180_000_000)?;
                set_once("lon", &mut spec.longitude_microdegrees, value)?;
            }
            "radius_km" => {
                let value = parse_radius_meters(&value)?;
                set_once("radius_km", &mut spec.radius_meters, value)?;
            }
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

pub fn metrics_router(state: MetricsHttpState) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .with_state(state)
}

pub fn relay_info_router(document: RelayInfoDocument) -> Router {
    Router::new()
        .route("/", get(relay_info))
        .with_state(document)
}

pub fn listings_router(state: ListingsHttpState) -> Router {
    Router::new()
        .route("/api/listings", get(listings))
        .route("/api/listings/{pubkey}/{d}", get(listing_detail))
        .route("/api/listings/{pubkey}/{d}/comments", get(listing_comments))
        .route(
            "/api/listings/{pubkey}/{d}/reactions",
            get(listing_reactions),
        )
        .route("/api/forum/threads", get(forum_threads))
        .route("/api/forum/threads/{event_id}", get(forum_thread_detail))
        .route(
            "/api/forum/threads/{event_id}/comments",
            get(forum_thread_comments),
        )
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

async fn metrics(State(state): State<MetricsHttpState>) -> Result<Response, ApiError> {
    let snapshot = state
        .store
        .metrics_snapshot()
        .await
        .map_err(|_| ApiError::internal())?;
    Ok((
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4"),
        )],
        metrics_text(snapshot),
    )
        .into_response())
}

fn metrics_text(snapshot: SurrealMetricsSnapshot) -> String {
    let mut output = String::new();
    output.push_str("# HELP tangle_info Tangle relay build information\n");
    output.push_str("# TYPE tangle_info gauge\n");
    output.push_str(&format!(
        "tangle_info{{software=\"{}\",version=\"{}\"}} 1\n",
        prometheus_label_value(TANGLE_RELAY_SOFTWARE),
        prometheus_label_value(TANGLE_RELAY_VERSION)
    ));
    output.push_str("# HELP tangle_relay_ready Relay readiness gauge\n");
    output.push_str("# TYPE tangle_relay_ready gauge\n");
    output.push_str("tangle_relay_ready 1\n");
    output.push_str("# HELP tangle_store_events Stored Nostr event gauges\n");
    output.push_str("# TYPE tangle_store_events gauge\n");
    append_labeled_gauge(
        &mut output,
        "tangle_store_events",
        "stored",
        snapshot.stored_events(),
    );
    append_labeled_gauge(
        &mut output,
        "tangle_store_events",
        "visible",
        snapshot.visible_events(),
    );
    append_labeled_gauge(
        &mut output,
        "tangle_store_events",
        "hidden",
        snapshot.hidden_events(),
    );
    append_labeled_gauge(
        &mut output,
        "tangle_store_events",
        "deleted",
        snapshot.deleted_events(),
    );
    output.push_str("# HELP tangle_store_listings Current listing projection gauges\n");
    output.push_str("# TYPE tangle_store_listings gauge\n");
    append_labeled_gauge(
        &mut output,
        "tangle_store_listings",
        "current",
        snapshot.current_listings(),
    );
    append_labeled_gauge(
        &mut output,
        "tangle_store_listings",
        "active",
        snapshot.active_listings(),
    );
    output.push_str("# HELP tangle_store_seller_profiles Seller profile projection gauges\n");
    output.push_str("# TYPE tangle_store_seller_profiles gauge\n");
    append_labeled_gauge(
        &mut output,
        "tangle_store_seller_profiles",
        "stored",
        snapshot.seller_profiles(),
    );
    append_labeled_gauge(
        &mut output,
        "tangle_store_seller_profiles",
        "visible",
        snapshot.visible_seller_profiles(),
    );
    output.push_str("# HELP tangle_store_sellers Seller policy gauges\n");
    output.push_str("# TYPE tangle_store_sellers gauge\n");
    append_labeled_gauge(
        &mut output,
        "tangle_store_sellers",
        "approved",
        snapshot.approved_sellers(),
    );
    output.push_str("# HELP tangle_store_pubkeys Relay pubkey policy gauges\n");
    output.push_str("# TYPE tangle_store_pubkeys gauge\n");
    append_labeled_gauge(
        &mut output,
        "tangle_store_pubkeys",
        "blocked",
        snapshot.blocked_pubkeys(),
    );
    output
}

fn append_labeled_gauge(output: &mut String, metric: &str, state: &str, value: u64) {
    output.push_str(&format!(
        "{metric}{{state=\"{}\"}} {value}\n",
        prometheus_label_value(state)
    ));
}

fn prometheus_label_value(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('"', r#"\""#)
        .replace('\n', r"\n")
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

async fn listing_comments(
    State(state): State<ListingsHttpState>,
    Path((pubkey, d)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> Result<Json<ListingCommentsDocument>, ApiError> {
    let pubkey = parse_pubkey("pubkey", &pubkey)?;
    let d = required_value("d", &d)?;
    let limit = parse_comment_query(query.as_deref().unwrap_or_default())?;
    let listing_key = format!("30402:{}:{d}", pubkey.as_str());
    let listing = state
        .store
        .listing_current_row(&listing_key)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(|| ApiError::not_found("listing not found"))?;
    if bool_field(&listing, "hidden")? || bool_field(&listing, "deleted")? {
        return Err(ApiError::not_found("listing not found"));
    }
    let rows = state
        .store
        .query_comment_projections(
            &CommentProjectionQuery::new()
                .with_root("address", &listing_key)
                .with_limit(limit),
        )
        .await
        .map_err(|_| ApiError::internal())?;
    let items = rows
        .iter()
        .map(comment_item_document)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(ListingCommentsDocument {
        items,
        next_cursor: None,
    }))
}

async fn listing_reactions(
    State(state): State<ListingsHttpState>,
    Path((pubkey, d)): Path<(String, String)>,
) -> Result<Json<ReactionCountsDocument>, ApiError> {
    let pubkey = parse_pubkey("pubkey", &pubkey)?;
    let d = required_value("d", &d)?;
    let listing_key = format!("30402:{}:{d}", pubkey.as_str());
    let listing = state
        .store
        .listing_current_row(&listing_key)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(|| ApiError::not_found("listing not found"))?;
    if bool_field(&listing, "hidden")? || bool_field(&listing, "deleted")? {
        return Err(ApiError::not_found("listing not found"));
    }
    let event_id =
        EventId::new(&string_field(&listing, "event_id")?).map_err(|_| ApiError::internal())?;
    let row = state
        .store
        .reaction_count_row(&event_id)
        .await
        .map_err(|_| ApiError::internal())?;
    let document = reaction_counts_document(row.as_ref(), event_id.as_str(), Some("30402"))?;
    Ok(Json(document))
}

async fn forum_threads(
    State(state): State<ListingsHttpState>,
    RawQuery(query): RawQuery,
) -> Result<Json<ForumThreadsDocument>, ApiError> {
    let query = forum_thread_query(query.as_deref().unwrap_or_default())?;
    let rows = state
        .store
        .query_forum_threads(&query)
        .await
        .map_err(|_| ApiError::internal())?;
    let items = rows
        .iter()
        .map(forum_thread_item_document)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(ForumThreadsDocument {
        items,
        next_cursor: None,
    }))
}

async fn forum_thread_detail(
    State(state): State<ListingsHttpState>,
    Path(event_id): Path<String>,
) -> Result<Json<ForumThreadDetailDocument>, ApiError> {
    let event_id =
        EventId::new(&event_id).map_err(|_| invalid_parameter("event_id", "is invalid"))?;
    let row = state
        .store
        .forum_thread_row(&event_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(|| ApiError::not_found("forum thread not found"))?;
    if bool_field(&row, "hidden")? || bool_field(&row, "deleted")? {
        return Err(ApiError::not_found("forum thread not found"));
    }
    let raw_row = state
        .store
        .raw_event_row(&event_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::internal)?;
    if bool_field(&raw_row, "hidden")? || bool_field(&raw_row, "deleted")? {
        return Err(ApiError::not_found("forum thread not found"));
    }
    let raw_event = serde_json::from_str(&string_field(&raw_row, "raw_json")?)
        .map_err(|_| ApiError::internal())?;
    Ok(Json(ForumThreadDetailDocument {
        thread: forum_thread_item_document(&row)?,
        raw_event,
    }))
}

async fn forum_thread_comments(
    State(state): State<ListingsHttpState>,
    Path(event_id): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<Json<ListingCommentsDocument>, ApiError> {
    let event_id =
        EventId::new(&event_id).map_err(|_| invalid_parameter("event_id", "is invalid"))?;
    let limit = parse_comment_query(query.as_deref().unwrap_or_default())?;
    let row = state
        .store
        .forum_thread_row(&event_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(|| ApiError::not_found("forum thread not found"))?;
    if bool_field(&row, "hidden")? || bool_field(&row, "deleted")? {
        return Err(ApiError::not_found("forum thread not found"));
    }
    let rows = state
        .store
        .query_comment_projections(
            &CommentProjectionQuery::new()
                .with_root("event", event_id.as_str())
                .with_limit(limit),
        )
        .await
        .map_err(|_| ApiError::internal())?;
    let items = rows
        .iter()
        .map(comment_item_document)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(ListingCommentsDocument {
        items,
        next_cursor: None,
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
    let seller = state
        .store
        .relay_user_row(pubkey.as_str())
        .await
        .map_err(|_| ApiError::internal())?;
    let profile = state
        .store
        .seller_profile_row(pubkey.as_str())
        .await
        .map_err(|_| ApiError::internal())?;
    let visible_profile = match profile.as_ref() {
        Some(row) if !bool_field(row, "hidden")? && !bool_field(row, "deleted")? => Some(row),
        _ => None,
    };
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
        event_id: visible_profile
            .map(|row| string_field(row, "event_id"))
            .transpose()?,
        name: visible_profile
            .map(|row| optional_string_field(row, "name"))
            .transpose()?
            .flatten(),
        display_name: visible_profile
            .map(|row| optional_string_field(row, "display_name"))
            .transpose()?
            .flatten(),
        about: visible_profile
            .map(|row| optional_string_field(row, "about"))
            .transpose()?
            .flatten(),
        picture: visible_profile
            .map(|row| optional_string_field(row, "picture"))
            .transpose()?
            .flatten(),
        website: visible_profile
            .map(|row| optional_string_field(row, "website"))
            .transpose()?
            .flatten(),
        nip05: visible_profile
            .map(|row| optional_string_field(row, "nip05"))
            .transpose()?
            .flatten(),
        lud16: visible_profile
            .map(|row| optional_string_field(row, "lud16"))
            .transpose()?
            .flatten(),
        regions: visible_profile
            .map(|row| string_array_field(row, "regions"))
            .transpose()?
            .unwrap_or_default(),
        categories: visible_profile
            .map(|row| string_array_field(row, "categories"))
            .transpose()?
            .unwrap_or_default(),
        trust_markers: visible_profile
            .map(|row| string_array_field(row, "trust_markers"))
            .transpose()?
            .unwrap_or_default(),
        approved: seller
            .as_ref()
            .and_then(|row| row.get("seller_approved"))
            .and_then(serde_json::Value::as_bool)
            .or_else(|| {
                visible_profile
                    .and_then(|row| row.get("seller_approved"))
                    .and_then(serde_json::Value::as_bool)
            })
            .unwrap_or(false),
        blocked: seller
            .as_ref()
            .and_then(|row| row.get("blocked"))
            .and_then(serde_json::Value::as_bool)
            .or_else(|| {
                visible_profile
                    .and_then(|row| row.get("blocked"))
                    .and_then(serde_json::Value::as_bool)
            })
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

fn require_admin_pubkey(
    config: &TangleRuntimeConfig,
    headers: &HeaderMap,
) -> Result<PublicKeyHex, ApiError> {
    if config.admin_pubkeys().is_empty() {
        return Err(ApiError::forbidden("admin policy api is disabled"));
    }
    let value = headers
        .get("x-tangle-admin-pubkey")
        .ok_or_else(|| ApiError::unauthorized("admin pubkey header is required"))?
        .to_str()
        .map_err(|_| ApiError::unauthorized("admin pubkey header is invalid"))?;
    let pubkey = PublicKeyHex::new(value)
        .map_err(|_| ApiError::unauthorized("admin pubkey header is invalid"))?;
    if !config.admin_pubkeys().contains(&pubkey) {
        return Err(ApiError::forbidden("admin pubkey is not authorized"));
    }
    Ok(pubkey)
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

fn forum_thread_query(raw: &str) -> Result<ForumThreadProjectionQuery, ApiError> {
    let mut pubkey = None;
    let mut topic = None;
    let mut limit = None;
    for (key, value) in form_urlencoded::parse(raw.as_bytes()) {
        let value = value.into_owned();
        match key.as_ref() {
            "pubkey" => set_once("pubkey", &mut pubkey, parse_pubkey("pubkey", &value)?)?,
            "topic" => set_once("topic", &mut topic, required_value("topic", &value)?)?,
            "limit" => set_once("limit", &mut limit, parse_limit(&value)?)?,
            "cursor" => {
                return Err(invalid_parameter(
                    "cursor",
                    "signed cursor decoding is not implemented",
                ));
            }
            "" => {}
            unsupported => {
                return Err(ApiError::invalid_request(format!(
                    "query parameter `{unsupported}` is unsupported"
                )));
            }
        }
    }
    let mut query = ForumThreadProjectionQuery::new().with_limit(limit.unwrap_or(50));
    if let Some(pubkey) = pubkey {
        query = query.with_pubkey(pubkey.as_str());
    }
    if let Some(topic) = topic {
        query = query.with_topic(&topic);
    }
    Ok(query)
}

fn label_projection_query(raw: &str) -> Result<LabelProjectionQuery, ApiError> {
    let mut target_type = None;
    let mut target_ref = None;
    let mut namespace = None;
    let mut label = None;
    let mut pubkey = None;
    let mut limit = None;
    for (key, value) in form_urlencoded::parse(raw.as_bytes()) {
        let value = value.into_owned();
        match key.as_ref() {
            "target_type" => {
                let value = required_value("target_type", &value)?;
                set_once("target_type", &mut target_type, value)?;
            }
            "target_ref" => {
                let value = required_value("target_ref", &value)?;
                set_once("target_ref", &mut target_ref, value)?;
            }
            "namespace" => {
                let value = required_value("namespace", &value)?;
                set_once("namespace", &mut namespace, value)?;
            }
            "label" => set_once("label", &mut label, required_value("label", &value)?)?,
            "pubkey" => set_once("pubkey", &mut pubkey, parse_pubkey("pubkey", &value)?)?,
            "limit" => set_once("limit", &mut limit, parse_limit(&value)?)?,
            "cursor" => {
                return Err(invalid_parameter(
                    "cursor",
                    "signed cursor decoding is not implemented",
                ));
            }
            "" => {}
            unsupported => {
                return Err(ApiError::invalid_request(format!(
                    "query parameter `{unsupported}` is unsupported"
                )));
            }
        }
    }
    if target_type.is_some() != target_ref.is_some() {
        return Err(invalid_parameter(
            "target",
            "target_type and target_ref must be provided together",
        ));
    }
    let mut query = LabelProjectionQuery::new().with_limit(limit.unwrap_or(50));
    if let (Some(target_type), Some(target_ref)) = (target_type, target_ref) {
        query = query.with_target(&target_type, &target_ref);
    }
    if let Some(namespace) = namespace {
        query = query.with_namespace(&namespace);
    }
    if let Some(label) = label {
        query = query.with_label(&label);
    }
    if let Some(pubkey) = pubkey {
        query = query.with_pubkey(pubkey.as_str());
    }
    Ok(query)
}

fn report_projection_query(raw: &str) -> Result<ReportProjectionQuery, ApiError> {
    let mut target_type = None;
    let mut target_ref = None;
    let mut report_type = None;
    let mut pubkey = None;
    let mut limit = None;
    for (key, value) in form_urlencoded::parse(raw.as_bytes()) {
        let value = value.into_owned();
        match key.as_ref() {
            "target_type" => {
                let value = required_value("target_type", &value)?;
                set_once("target_type", &mut target_type, value)?;
            }
            "target_ref" => {
                let value = required_value("target_ref", &value)?;
                set_once("target_ref", &mut target_ref, value)?;
            }
            "report_type" => {
                let value = required_value("report_type", &value)?;
                set_once("report_type", &mut report_type, value)?;
            }
            "pubkey" => set_once("pubkey", &mut pubkey, parse_pubkey("pubkey", &value)?)?,
            "limit" => set_once("limit", &mut limit, parse_limit(&value)?)?,
            "cursor" => {
                return Err(invalid_parameter(
                    "cursor",
                    "signed cursor decoding is not implemented",
                ));
            }
            "" => {}
            unsupported => {
                return Err(ApiError::invalid_request(format!(
                    "query parameter `{unsupported}` is unsupported"
                )));
            }
        }
    }
    if target_type.is_some() != target_ref.is_some() {
        return Err(invalid_parameter(
            "target",
            "target_type and target_ref must be provided together",
        ));
    }
    let mut query = ReportProjectionQuery::new().with_limit(limit.unwrap_or(50));
    if let (Some(target_type), Some(target_ref)) = (target_type, target_ref) {
        query = query.with_target(&target_type, &target_ref);
    }
    if let Some(report_type) = report_type {
        query = query.with_report_type(&report_type);
    }
    if let Some(pubkey) = pubkey {
        query = query.with_pubkey(pubkey.as_str());
    }
    Ok(query)
}

fn parse_comment_query(raw: &str) -> Result<u64, ApiError> {
    let mut limit = None;
    for (key, value) in form_urlencoded::parse(raw.as_bytes()) {
        match key.as_ref() {
            "limit" => set_once("limit", &mut limit, parse_limit(value.as_ref())?)?,
            "" => {}
            _ => {
                return Err(ApiError::invalid_request(format!(
                    "{} is not supported by the listing comments endpoint",
                    key
                )));
            }
        }
    }
    Ok(limit.unwrap_or(50))
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

fn forum_thread_item_document(
    row: &serde_json::Value,
) -> Result<ForumThreadItemDocument, ApiError> {
    Ok(ForumThreadItemDocument {
        event_id: string_field(row, "event_id")?,
        pubkey: string_field(row, "pubkey")?,
        created_at: u64_field(row, "created_at")?,
        updated_at: u64_field(row, "updated_at")?,
        title: optional_string_field(row, "title")?,
        content: string_field(row, "content")?,
        tags: string_array_field(row, "tags")?,
    })
}

fn comment_item_document(row: &serde_json::Value) -> Result<CommentItemDocument, ApiError> {
    Ok(CommentItemDocument {
        event_id: string_field(row, "event_id")?,
        pubkey: string_field(row, "pubkey")?,
        created_at: u64_field(row, "created_at")?,
        content: string_field(row, "content")?,
        root: CommentReferenceDocument {
            target_type: string_field(row, "root_target_type")?,
            target_ref: string_field(row, "root_ref")?,
            kind: string_field(row, "root_kind")?,
            author: optional_string_field(row, "root_author")?,
        },
        parent: CommentReferenceDocument {
            target_type: string_field(row, "parent_target_type")?,
            target_ref: string_field(row, "parent_ref")?,
            kind: string_field(row, "parent_kind")?,
            author: optional_string_field(row, "parent_author")?,
        },
    })
}

fn moderation_label_document(row: &serde_json::Value) -> Result<ModerationLabelDocument, ApiError> {
    Ok(ModerationLabelDocument {
        label_id: string_field(row, "label_id")?,
        event_id: string_field(row, "event_id")?,
        pubkey: string_field(row, "pubkey")?,
        created_at: u64_field(row, "created_at")?,
        content: string_field(row, "content")?,
        namespace: string_field(row, "namespace")?,
        label: string_field(row, "label")?,
        target_type: string_field(row, "target_type")?,
        target_ref: string_field(row, "target_ref")?,
        projected_at: u64_field(row, "projected_at")?,
    })
}

fn moderation_report_document(
    row: &serde_json::Value,
) -> Result<ModerationReportDocument, ApiError> {
    Ok(ModerationReportDocument {
        report_id: string_field(row, "report_id")?,
        event_id: string_field(row, "event_id")?,
        pubkey: string_field(row, "pubkey")?,
        created_at: u64_field(row, "created_at")?,
        content: string_field(row, "content")?,
        target_type: string_field(row, "target_type")?,
        target_ref: string_field(row, "target_ref")?,
        report_type: string_field(row, "report_type")?,
        reported_pubkeys: string_array_field(row, "reported_pubkeys")?,
        server_urls: string_array_field(row, "server_urls")?,
        projected_at: u64_field(row, "projected_at")?,
    })
}

fn reaction_counts_document(
    row: Option<&serde_json::Value>,
    target_event_id: &str,
    target_kind: Option<&str>,
) -> Result<ReactionCountsDocument, ApiError> {
    match row {
        Some(row) => Ok(ReactionCountsDocument {
            target_event_id: string_field(row, "target_event_id")?,
            target_kind: optional_string_field(row, "target_kind")?,
            like_count: u64_field(row, "like_count")?,
            dislike_count: u64_field(row, "dislike_count")?,
            emoji_count: u64_field(row, "emoji_count")?,
            text_count: u64_field(row, "text_count")?,
            total_count: u64_field(row, "total_count")?,
            updated_at: u64_field(row, "updated_at")?,
        }),
        None => Ok(ReactionCountsDocument {
            target_event_id: target_event_id.to_owned(),
            target_kind: target_kind.map(str::to_owned),
            like_count: 0,
            dislike_count: 0,
            emoji_count: 0,
            text_count: 0,
            total_count: 0,
            updated_at: 0,
        }),
    }
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

fn string_array_field(
    row: &serde_json::Value,
    field: &'static str,
) -> Result<Vec<String>, ApiError> {
    row.get(field)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(ApiError::internal)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(ApiError::internal)
        })
        .collect()
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
        ApiError, ApiErrorBody, ApiErrorCode, ApiErrorEnvelope, AuthMessageHandler, ClientFrame,
        ClientFrameOutcome, ClientMessageLoop, CloseMessageHandler, CloseMessageOutcome,
        EventMessageHandler, GracefulShutdownSignal, ListingsHttpState, LiveEventFanout,
        MetricsHttpState, ReadinessCheckStatus, ReadinessState, RelayConnection,
        RelayConnectionConfig, RelayConnectionId, RelayInfoDocument, ReqMessageHandler,
        RuntimeCommandError, RuntimeCommandErrorKind, RuntimeConfigErrorKind,
        RuntimeEventImportOutcome, RuntimeProjectionRebuildOutcome, RuntimeServerReport,
        RuntimeTracingFormat, TANGLE_RELAY_SOFTWARE, TANGLE_RELAY_VERSION, TANGLE_SUPPORTED_NIPS,
        WebSocketHttpState, backup_runtime_store, health_router, listing_item_document,
        listing_projection_query, listings_router, load_runtime_config, metrics_router,
        migrate_runtime_database, parse_listing_query, parse_marketplace_search_query,
        parse_runtime_config_json, relay_info_router, restore_runtime_store,
        runtime_readiness_state, search_document_query,
    };
    use axum::{body::Body, response::IntoResponse};
    use futures_util::{SinkExt, StreamExt};
    use http::{HeaderValue, Request, StatusCode, header};
    use tangle_core::{
        AdmissionContext, AdmissionEffect, AdmissionPolicy, EventValidator,
        MarketplaceListingStatus, MarketplaceSort, NostrFilterCompiler, RateLimitConfig,
        RuntimeLimits,
    };
    use tangle_nips::{
        FulfillmentMethod, ListingUnit, NIP01_METADATA_KIND, parse_relay_auth_event,
    };
    use tangle_protocol::{
        ClientMessage, EventId, PublicKeyHex, RelayMessage, SubscriptionId, UnixTimestamp,
        event_to_value, filter_from_value,
    };
    use tangle_store::{StoreEventOutcome, StoredEvent};
    use tangle_store_surreal::{
        SurrealConnectionConfig, SurrealConnectionMode, SurrealStore, base_migration_plan,
    };
    use tangle_test_support::{
        FixtureKey, auth_event_spec, build_fixture_event, build_fixture_event_from_parts,
        valid_public_listing_spec,
    };
    use tokio_tungstenite::tungstenite::Message as TungsteniteMessage;
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
        assert!(decision.allowed());
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
        assert!(!state.shutdown_signal().is_shutdown_requested());
        assert!(!default_state.shutdown_signal().is_shutdown_requested());
    }

    #[tokio::test]
    async fn graceful_shutdown_signal_notifies_subscribers() {
        let (shutdown, mut first) = GracefulShutdownSignal::new();
        let mut second = shutdown.subscribe();

        assert!(!shutdown.is_shutdown_requested());
        assert!(!first.is_shutdown_requested());
        assert!(!second.is_shutdown_requested());

        assert!(shutdown.request_shutdown());
        first.wait_for_shutdown().await;
        second.wait_for_shutdown().await;

        assert!(shutdown.is_shutdown_requested());
        assert!(first.is_shutdown_requested());
        assert!(second.is_shutdown_requested());
    }

    #[tokio::test]
    async fn graceful_shutdown_listener_returns_when_already_requested() {
        let (shutdown, mut listener) = GracefulShutdownSignal::new();

        assert!(shutdown.request_shutdown());
        listener.wait_for_shutdown().await;

        assert!(listener.is_shutdown_requested());
    }

    #[tokio::test]
    async fn graceful_shutdown_listener_wakes_after_request() {
        let (shutdown, mut listener) = GracefulShutdownSignal::new();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            ready_tx.send(()).expect("ready signal");
            listener.wait_for_shutdown().await;
            listener.is_shutdown_requested()
        });

        ready_rx.await.expect("listener ready");
        tokio::task::yield_now().await;
        assert!(shutdown.request_shutdown());
        assert!(task.await.expect("listener task"));
    }

    #[tokio::test]
    async fn runtime_config_accessors_and_error_types_are_stable() {
        let config = parse_runtime_config_json(
            r#"{
                "server": {
                    "listen_addr": "127.0.0.1:7002",
                    "relay_url": "ws://127.0.0.1:7002"
                },
                "database": {
                    "mode": "memory",
                    "namespace": "tangle_accessors",
                    "database": "relay"
                },
                "auth": {
                    "challenge_ttl_seconds": 120
                },
                "limits": {
                    "message_rate_limit": {
                        "limit": 3,
                        "window_seconds": 5
                    }
                }
            }"#,
        )
        .expect("runtime config");
        let store = runtime_memory_store().await;
        let listings_state = config.listings_state(store);
        let config_error = super::RuntimeConfigError::read("missing config");
        let command_errors = [
            RuntimeCommandError::unsupported("not supported"),
            RuntimeCommandError::input("bad input"),
            RuntimeCommandError::store("store failed"),
        ];
        let server_report = RuntimeServerReport::new("127.0.0.1:7002".parse().expect("addr"));

        assert_eq!(config.tracing_config().format().as_str(), "compact");
        assert_eq!(RuntimeTracingFormat::Json.as_str(), "json");
        assert_eq!(listings_state.limits, RuntimeLimits::default());
        assert_eq!(config_error.kind(), RuntimeConfigErrorKind::Read);
        assert_eq!(config_error.message(), "missing config");
        assert_eq!(config_error.to_string(), "Read: missing config");
        assert_eq!(
            command_errors[0].kind(),
            RuntimeCommandErrorKind::Unsupported
        );
        assert_eq!(command_errors[1].kind(), RuntimeCommandErrorKind::Input);
        assert_eq!(command_errors[2].kind(), RuntimeCommandErrorKind::Store);
        assert_eq!(command_errors[0].message(), "not supported");
        assert_eq!(command_errors[1].to_string(), "Input: bad input");
        assert_eq!(server_report.listen_addr().to_string(), "127.0.0.1:7002");
    }

    #[test]
    fn runtime_config_loader_parses_memory_config() {
        let config = parse_runtime_config_json(
            r#"{
                "server": {
                    "listen_addr": "127.0.0.1:7000",
                    "relay_url": "ws://127.0.0.1:7000"
                },
                "database": {
                    "mode": "memory",
                    "namespace": "tangle_test",
                    "database": "relay"
                },
                "auth": {
                    "challenge_ttl_seconds": 120
                },
                "limits": {
                    "message_rate_limit": {
                        "limit": 3,
                        "window_seconds": 5
                    },
                    "runtime": {
                        "max_event_bytes": 2048,
                        "max_content_bytes": 1024,
                        "max_tags_per_event": 32,
                        "max_tag_values_per_tag": 8,
                        "max_tag_value_bytes": 256,
                        "max_filters_per_subscription": 4,
                        "max_subscriptions_per_connection": 8,
                        "max_search_query_bytes": 128,
                        "max_search_tokens": 6,
                        "max_filter_complexity": 64,
                        "max_future_seconds": 60,
                        "live_event_buffer": 128,
                        "pending_store_events": 256
                    }
                },
                "policy": {
                    "admin_pubkeys": [
                        "1111111111111111111111111111111111111111111111111111111111111111"
                    ],
                    "write_rate_limit": {
                        "limit": 2,
                        "window_seconds": 60
                    }
                }
            }"#,
        )
        .expect("runtime config");
        let (shutdown, _) = GracefulShutdownSignal::new();
        let websocket_state = config.websocket_state(shutdown);

        assert_eq!(config.listen_addr().to_string(), "127.0.0.1:7000");
        assert_eq!(
            config.relay_connection_config().relay_url(),
            "ws://127.0.0.1:7000"
        );
        assert_eq!(config.relay_connection_config().auth_ttl_seconds(), 120);
        assert_eq!(
            config.relay_connection_config().message_rate_limit(),
            RateLimitConfig::new(3, 5).expect("rate")
        );
        assert_eq!(config.limits().max_event_bytes(), 2048);
        assert_eq!(config.limits().max_content_bytes(), 1024);
        assert_eq!(config.limits().max_tags_per_event(), 32);
        assert_eq!(config.limits().max_tag_values_per_tag(), 8);
        assert_eq!(config.limits().max_tag_value_bytes(), 256);
        assert_eq!(config.limits().max_filters_per_subscription(), 4);
        assert_eq!(config.limits().max_subscriptions_per_connection(), 8);
        assert_eq!(config.limits().max_search_query_bytes(), 128);
        assert_eq!(config.limits().max_search_tokens(), 6);
        assert_eq!(config.limits().max_filter_complexity(), 64);
        assert_eq!(config.limits().max_future_seconds(), 60);
        assert_eq!(config.limits().live_event_buffer(), 128);
        assert_eq!(config.limits().pending_store_events(), 256);
        assert_eq!(
            config.durable_write_rate_limit(),
            Some(RateLimitConfig::new(2, 60).expect("write limit"))
        );
        assert!(
            config.admin_pubkeys().contains(
                &PublicKeyHex::new(
                    "1111111111111111111111111111111111111111111111111111111111111111"
                )
                .expect("admin pubkey")
            )
        );
        assert_eq!(config.database_config().namespace(), "tangle_test");
        assert_eq!(config.database_config().database(), "relay");
        assert_eq!(
            config.database_config().mode(),
            &SurrealConnectionMode::Memory
        );
        assert_eq!(
            websocket_state.connection_config(),
            config.relay_connection_config()
        );
        assert!(!config.tracing_config().enabled());
        assert_eq!(
            config.tracing_config().filter(),
            "info,tangle=info,tangle_runtime=info"
        );
        assert_eq!(
            config.tracing_config().format(),
            RuntimeTracingFormat::Compact
        );
    }

    #[test]
    fn runtime_config_loader_parses_websocket_database_config() {
        let config = parse_runtime_config_json(
            r#"{
                "server": {
                    "listen_addr": "127.0.0.1:7100",
                    "relay_url": "wss://relay.radroots.test"
                },
                "database": {
                    "mode": "web_socket",
                    "endpoint": "ws://127.0.0.1:8000",
                    "username": "root",
                    "password": "root",
                    "namespace": "tangle",
                    "database": "relay"
                },
                "auth": {
                    "challenge_ttl_seconds": 300
                },
                "limits": {
                    "message_rate_limit": {
                        "limit": 120,
                        "window_seconds": 60
                    }
                }
            }"#,
        )
        .expect("runtime config");

        assert_eq!(
            config.database_config().mode(),
            &SurrealConnectionMode::WebSocket {
                endpoint: "ws://127.0.0.1:8000".to_owned()
            }
        );
        let credentials = config
            .database_config()
            .root_credentials()
            .expect("root credentials");
        assert_eq!(credentials.username(), "root");
        assert_eq!(credentials.password(), "root");
        assert_eq!(config.limits(), RuntimeLimits::default());
    }

    #[test]
    fn runtime_config_loader_parses_local_surrealdb_stack_config() {
        let config = parse_runtime_config_json(include_str!(
            "../../../ops/local/surrealdb/tangle-runtime.json"
        ))
        .expect("local stack config");

        assert_eq!(config.listen_addr().to_string(), "127.0.0.1:7000");
        assert_eq!(
            config.database_config().mode(),
            &SurrealConnectionMode::Http {
                endpoint: "http://127.0.0.1:8000".to_owned()
            }
        );
        let credentials = config
            .database_config()
            .root_credentials()
            .expect("root credentials");
        assert_eq!(credentials.username(), "root");
        assert_eq!(credentials.password(), "root");
        assert_eq!(config.database_config().namespace(), "tangle_local");
        assert_eq!(config.database_config().database(), "relay");
        assert!(config.tracing_config().enabled());
        assert_eq!(config.tracing_config().format(), RuntimeTracingFormat::Json);
        assert_eq!(
            config.durable_write_rate_limit(),
            Some(RateLimitConfig::new(60, 60).expect("write limit"))
        );
        assert!(config.admission_policy().require_write_auth());
    }

    #[test]
    fn runtime_config_loader_parses_production_config_example() {
        let config = parse_runtime_config_json(include_str!(
            "../../../ops/production/tangle-runtime.example.json"
        ))
        .expect("production example config");

        assert_eq!(config.listen_addr().to_string(), "0.0.0.0:7000");
        assert_eq!(
            config.database_config().mode(),
            &SurrealConnectionMode::Http {
                endpoint: "http://surrealdb:8000".to_owned()
            }
        );
        let credentials = config
            .database_config()
            .root_credentials()
            .expect("root credentials");
        assert_eq!(credentials.username(), "replace_with_surreal_root_user");
        assert_eq!(credentials.password(), "replace_with_surreal_root_password");
        assert_eq!(config.database_config().namespace(), "tangle");
        assert_eq!(config.database_config().database(), "relay");
        assert_eq!(config.tracing_config().format(), RuntimeTracingFormat::Json);
        assert_eq!(
            config.durable_write_rate_limit(),
            Some(RateLimitConfig::new(300, 60).expect("write limit"))
        );
        assert!(config.admission_policy().require_write_auth());
        assert!(config.admin_pubkeys().contains(
            &PublicKeyHex::new(&"a".repeat(PublicKeyHex::HEX_LENGTH)).expect("admin pubkey")
        ));
    }

    #[test]
    fn runtime_config_loader_parses_observability_tracing_config() {
        let config = parse_runtime_config_json(
            r#"{
                "server": {
                    "listen_addr": "127.0.0.1:7101",
                    "relay_url": "wss://relay.radroots.test"
                },
                "database": {
                    "mode": "memory",
                    "namespace": "tangle",
                    "database": "relay"
                },
                "auth": {
                    "challenge_ttl_seconds": 300
                },
                "limits": {
                    "message_rate_limit": {
                        "limit": 120,
                        "window_seconds": 60
                    }
                },
                "observability": {
                    "tracing": {
                        "enabled": true,
                        "filter": "info,tangle=debug,tangle_runtime=debug",
                        "format": "json"
                    }
                }
            }"#,
        )
        .expect("runtime config");

        assert!(config.tracing_config().enabled());
        assert_eq!(
            config.tracing_config().filter(),
            "info,tangle=debug,tangle_runtime=debug"
        );
        assert_eq!(config.tracing_config().format(), RuntimeTracingFormat::Json);
    }

    #[test]
    fn runtime_config_loader_rejects_invalid_documents() {
        let parse_error = parse_runtime_config_json("{").expect_err("parse");
        let invalid_listen = parse_runtime_config_json(
            r#"{
                "server": {
                    "listen_addr": "not a socket",
                    "relay_url": "ws://127.0.0.1:7000"
                },
                "database": {
                    "mode": "memory",
                    "namespace": "tangle",
                    "database": "relay"
                },
                "auth": {
                    "challenge_ttl_seconds": 300
                },
                "limits": {
                    "message_rate_limit": {
                        "limit": 120,
                        "window_seconds": 60
                    }
                }
            }"#,
        )
        .expect_err("listen");
        let missing_endpoint = parse_runtime_config_json(
            r#"{
                "server": {
                    "listen_addr": "127.0.0.1:7000",
                    "relay_url": "ws://127.0.0.1:7000"
                },
                "database": {
                    "mode": "http",
                    "namespace": "tangle",
                    "database": "relay"
                },
                "auth": {
                    "challenge_ttl_seconds": 300
                },
                "limits": {
                    "message_rate_limit": {
                        "limit": 120,
                        "window_seconds": 60
                    }
                }
            }"#,
        )
        .expect_err("endpoint");
        let missing_credentials = parse_runtime_config_json(
            r#"{
                "server": {
                    "listen_addr": "127.0.0.1:7000",
                    "relay_url": "ws://127.0.0.1:7000"
                },
                "database": {
                    "mode": "http",
                    "endpoint": "http://127.0.0.1:8000",
                    "namespace": "tangle",
                    "database": "relay"
                },
                "auth": {
                    "challenge_ttl_seconds": 300
                },
                "limits": {
                    "message_rate_limit": {
                        "limit": 120,
                        "window_seconds": 60
                    }
                }
            }"#,
        )
        .expect_err("credentials");
        let empty_tracing_filter = parse_runtime_config_json(
            r#"{
                "server": {
                    "listen_addr": "127.0.0.1:7000",
                    "relay_url": "ws://127.0.0.1:7000"
                },
                "database": {
                    "mode": "memory",
                    "namespace": "tangle",
                    "database": "relay"
                },
                "auth": {
                    "challenge_ttl_seconds": 300
                },
                "limits": {
                    "message_rate_limit": {
                        "limit": 120,
                        "window_seconds": 60
                    }
                },
                "observability": {
                    "tracing": {
                        "enabled": true,
                        "filter": " "
                    }
                }
            }"#,
        )
        .expect_err("tracing filter");

        assert_eq!(parse_error.kind(), RuntimeConfigErrorKind::Parse);
        assert!(
            parse_error
                .message()
                .starts_with("runtime config JSON is invalid:")
        );
        assert_eq!(invalid_listen.kind(), RuntimeConfigErrorKind::Invalid);
        assert!(
            invalid_listen
                .message()
                .starts_with("server.listen_addr is invalid:")
        );
        assert_eq!(missing_endpoint.kind(), RuntimeConfigErrorKind::Invalid);
        assert_eq!(
            missing_endpoint.message(),
            "database.endpoint is required for http mode"
        );
        assert_eq!(missing_credentials.kind(), RuntimeConfigErrorKind::Invalid);
        assert_eq!(
            missing_credentials.message(),
            "database.username is required for http mode"
        );
        assert_eq!(empty_tracing_filter.kind(), RuntimeConfigErrorKind::Invalid);
        assert_eq!(
            empty_tracing_filter.message(),
            "observability.tracing.filter must not be empty"
        );
    }

    #[test]
    fn runtime_config_loader_rejects_mode_specific_database_and_policy_edges() {
        let cases = [
            (
                r#"{
                    "server": {"listen_addr": "127.0.0.1:7102", "relay_url": "ws://127.0.0.1:7102"},
                    "database": {"mode": "memory", "endpoint": "mem://ignored", "namespace": "tangle", "database": "relay"},
                    "auth": {"challenge_ttl_seconds": 300},
                    "limits": {"message_rate_limit": {"limit": 120, "window_seconds": 60}}
                }"#,
                "database.endpoint must be omitted for memory mode",
            ),
            (
                r#"{
                    "server": {"listen_addr": "127.0.0.1:7109", "relay_url": "ws://127.0.0.1:7109"},
                    "database": {"mode": "memory", "path": "db", "namespace": "tangle", "database": "relay"},
                    "auth": {"challenge_ttl_seconds": 300},
                    "limits": {"message_rate_limit": {"limit": 120, "window_seconds": 60}}
                }"#,
                "database.path must be omitted for memory mode",
            ),
            (
                r#"{
                    "server": {"listen_addr": "127.0.0.1:7110", "relay_url": "ws://127.0.0.1:7110"},
                    "database": {"mode": "memory", "username": "root", "namespace": "tangle", "database": "relay"},
                    "auth": {"challenge_ttl_seconds": 300},
                    "limits": {"message_rate_limit": {"limit": 120, "window_seconds": 60}}
                }"#,
                "database credentials must be omitted for memory mode",
            ),
            (
                r#"{
                    "server": {"listen_addr": "127.0.0.1:7103", "relay_url": "ws://127.0.0.1:7103"},
                    "database": {"mode": "rocks_db", "endpoint": "http://127.0.0.1:8000", "path": "db", "namespace": "tangle", "database": "relay"},
                    "auth": {"challenge_ttl_seconds": 300},
                    "limits": {"message_rate_limit": {"limit": 120, "window_seconds": 60}}
                }"#,
                "database.endpoint must be omitted for rocksdb mode",
            ),
            (
                r#"{
                    "server": {"listen_addr": "127.0.0.1:7104", "relay_url": "ws://127.0.0.1:7104"},
                    "database": {"mode": "rocks_db", "username": "root", "path": "db", "namespace": "tangle", "database": "relay"},
                    "auth": {"challenge_ttl_seconds": 300},
                    "limits": {"message_rate_limit": {"limit": 120, "window_seconds": 60}}
                }"#,
                "database credentials must be omitted for rocksdb mode",
            ),
            (
                r#"{
                    "server": {"listen_addr": "127.0.0.1:7105", "relay_url": "ws://127.0.0.1:7105"},
                    "database": {"mode": "rocks_db", "namespace": "tangle", "database": "relay"},
                    "auth": {"challenge_ttl_seconds": 300},
                    "limits": {"message_rate_limit": {"limit": 120, "window_seconds": 60}}
                }"#,
                "database.path is required for rocksdb mode",
            ),
            (
                r#"{
                    "server": {"listen_addr": "127.0.0.1:7106", "relay_url": "ws://127.0.0.1:7106"},
                    "database": {"mode": "http", "endpoint": "http://127.0.0.1:8000", "username": "root", "namespace": "tangle", "database": "relay"},
                    "auth": {"challenge_ttl_seconds": 300},
                    "limits": {"message_rate_limit": {"limit": 120, "window_seconds": 60}}
                }"#,
                "database.password is required for http mode",
            ),
            (
                r#"{
                    "server": {"listen_addr": "127.0.0.1:7107", "relay_url": "ws://127.0.0.1:7107"},
                    "database": {"mode": "web_socket", "username": "root", "password": "root", "namespace": "tangle", "database": "relay"},
                    "auth": {"challenge_ttl_seconds": 300},
                    "limits": {"message_rate_limit": {"limit": 120, "window_seconds": 60}}
                }"#,
                "database.endpoint is required for websocket mode",
            ),
            (
                r#"{
                    "server": {"listen_addr": "127.0.0.1:7108", "relay_url": "ws://127.0.0.1:7108"},
                    "database": {"mode": "memory", "namespace": "tangle", "database": "relay"},
                    "auth": {"challenge_ttl_seconds": 300},
                    "limits": {"message_rate_limit": {"limit": 120, "window_seconds": 60}},
                    "policy": {"admin_pubkeys": ["bad"]}
                }"#,
                "policy.admin_pubkeys contains invalid pubkey: public key must be 64 characters, got 3",
            ),
            (
                r#"{
                    "server": {"listen_addr": "127.0.0.1:7111", "relay_url": "ws://127.0.0.1:7111"},
                    "database": {"mode": "memory", "namespace": "tangle", "database": "relay"},
                    "auth": {"challenge_ttl_seconds": 300},
                    "limits": {"message_rate_limit": {"limit": 120, "window_seconds": 60}},
                    "policy": {"approved_sellers": ["bad"]}
                }"#,
                "policy.approved_sellers contains invalid pubkey: public key must be 64 characters, got 3",
            ),
            (
                r#"{
                    "server": {"listen_addr": "127.0.0.1:7112", "relay_url": "ws://127.0.0.1:7112"},
                    "database": {"mode": "memory", "namespace": "tangle", "database": "relay"},
                    "auth": {"challenge_ttl_seconds": 300},
                    "limits": {"message_rate_limit": {"limit": 120, "window_seconds": 60}},
                    "policy": {"blocked_pubkeys": ["bad"]}
                }"#,
                "policy.blocked_pubkeys contains invalid pubkey: public key must be 64 characters, got 3",
            ),
        ];

        for (raw, expected) in cases {
            let error = parse_runtime_config_json(raw).expect_err(expected);
            assert_eq!(error.kind(), RuntimeConfigErrorKind::Invalid);
            assert_eq!(error.message(), expected);
        }
    }

    #[test]
    fn runtime_config_loader_parses_compact_tracing_format() {
        let config = parse_runtime_config_json(
            r#"{
                "server": {"listen_addr": "127.0.0.1:7113", "relay_url": "ws://127.0.0.1:7113"},
                "database": {"mode": "memory", "namespace": "tangle", "database": "relay"},
                "auth": {"challenge_ttl_seconds": 300},
                "limits": {"message_rate_limit": {"limit": 120, "window_seconds": 60}},
                "observability": {
                    "tracing": {
                        "enabled": true,
                        "filter": "info",
                        "format": "compact"
                    }
                }
            }"#,
        )
        .expect("runtime config");

        assert!(config.tracing_config().enabled());
        assert_eq!(
            config.tracing_config().format(),
            RuntimeTracingFormat::Compact
        );
    }

    #[test]
    fn event_import_document_parser_accepts_json_and_jsonl_edges() {
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let raw = event_to_value(&listing).to_string();
        let mut report = super::RuntimeEventImportReport::default();

        assert!(
            super::parse_event_import_document(" \n ")
                .expect("empty")
                .is_empty()
        );
        assert_eq!(
            super::parse_event_import_document(&raw)
                .expect("object")
                .first()
                .expect("event")
                .id(),
            listing.id()
        );
        assert_eq!(
            super::parse_event_import_document(&format!("[{raw}]"))
                .expect("array")
                .len(),
            1
        );
        assert_eq!(
            super::parse_event_import_document(&format!("{raw}\n\n{raw}"))
                .expect("jsonl")
                .len(),
            2
        );
        assert_eq!(
            super::parse_event_import_document("42")
                .expect_err("scalar")
                .message(),
            "event import file must contain event objects"
        );
        assert!(
            super::parse_event_import_document(r#"[{"id":"bad"}]"#)
                .expect_err("bad item")
                .message()
                .starts_with("event import item 1 is invalid:")
        );
        assert!(
            super::parse_event_import_document("{bad")
                .expect_err("bad line")
                .message()
                .starts_with("event import line 1 is invalid:")
        );

        report.record(RuntimeEventImportOutcome::Inserted { projected: true });
        report.record(RuntimeEventImportOutcome::Inserted { projected: false });
        report.record(RuntimeEventImportOutcome::Duplicate);
        report.record(RuntimeEventImportOutcome::Skipped);
        assert_eq!(report.total(), 4);
        assert_eq!(report.inserted(), 2);
        assert_eq!(report.duplicate(), 1);
        assert_eq!(report.projected(), 1);
        assert_eq!(report.skipped(), 1);
    }

    #[tokio::test]
    async fn import_and_rebuild_helpers_record_skipped_event_outcomes() {
        let store = runtime_memory_store().await;
        let validator = EventValidator::new(
            RuntimeLimits::default(),
            AdmissionPolicy::new().approve_seller(FixtureKey::Seller.public_key()),
        );
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let auth = build_fixture_event_from_parts(
            FixtureKey::Seller,
            1_714_124_435,
            22_242,
            vec![
                vec!["relay".to_owned(), "ws://127.0.0.1:0".to_owned()],
                vec!["challenge".to_owned(), "challenge-001".to_owned()],
            ],
            "",
        )
        .expect("auth");
        let ephemeral = build_fixture_event_from_parts(
            FixtureKey::Seller,
            1_714_124_440,
            20_000,
            Vec::new(),
            "ephemeral",
        )
        .expect("ephemeral");
        let mut rebuild_report = super::RuntimeProjectionRebuildReport::default();
        assert_eq!(
            validator
                .validate(
                    &auth,
                    &AdmissionContext::unauthenticated(),
                    UnixTimestamp::new(1_714_124_500)
                )
                .expect("auth validates")
                .admission()
                .effect(),
            AdmissionEffect::AuthenticateOnly
        );

        assert_eq!(
            super::import_single_event(&store, &validator, listing.clone(), UnixTimestamp::new(1))
                .await
                .expect("invalid skip"),
            RuntimeEventImportOutcome::Skipped
        );
        assert_eq!(
            super::import_single_event(
                &store,
                &validator,
                auth.clone(),
                UnixTimestamp::new(1_714_124_500)
            )
            .await
            .expect("auth skip"),
            RuntimeEventImportOutcome::Skipped
        );
        assert_eq!(
            super::import_single_event(
                &store,
                &validator,
                ephemeral.clone(),
                UnixTimestamp::new(1_714_124_500)
            )
            .await
            .expect("ephemeral skip"),
            RuntimeEventImportOutcome::Skipped
        );
        assert_eq!(
            super::rebuild_single_event_projection(
                &store,
                &validator,
                listing,
                UnixTimestamp::new(1)
            )
            .await
            .expect("invalid rebuild skip"),
            RuntimeProjectionRebuildOutcome::Skipped
        );
        assert_eq!(
            super::rebuild_single_event_projection(
                &store,
                &validator,
                auth,
                UnixTimestamp::new(1_714_124_500)
            )
            .await
            .expect("auth rebuild skip"),
            RuntimeProjectionRebuildOutcome::Skipped
        );
        assert_eq!(
            super::rebuild_single_event_projection(
                &store,
                &validator,
                ephemeral,
                UnixTimestamp::new(1_714_124_500)
            )
            .await
            .expect("ephemeral rebuild skip"),
            RuntimeProjectionRebuildOutcome::Skipped
        );

        rebuild_report.record(RuntimeProjectionRebuildOutcome::Rebuilt { projected: true });
        rebuild_report.record(RuntimeProjectionRebuildOutcome::Rebuilt { projected: false });
        rebuild_report.record(RuntimeProjectionRebuildOutcome::Skipped);
        assert_eq!(rebuild_report.scanned(), 3);
        assert_eq!(rebuild_report.rebuilt(), 2);
        assert_eq!(rebuild_report.projected(), 1);
        assert_eq!(rebuild_report.skipped(), 1);
    }

    #[test]
    fn runtime_config_loader_reads_config_file() {
        let path = std::env::temp_dir().join(format!(
            "tangle-runtime-config-loader-{}.json",
            std::process::id()
        ));
        std::fs::write(
            &path,
            r#"{
                "server": {
                    "listen_addr": "127.0.0.1:7200",
                    "relay_url": "ws://127.0.0.1:7200"
                },
                "database": {
                    "mode": "memory",
                    "namespace": "tangle_file",
                    "database": "relay"
                },
                "auth": {
                    "challenge_ttl_seconds": 300
                },
                "limits": {
                    "message_rate_limit": {
                        "limit": 120,
                        "window_seconds": 60
                    }
                }
            }"#,
        )
        .expect("write config");

        let config = load_runtime_config(&path).expect("loaded config");
        std::fs::remove_file(&path).expect("remove config");

        assert_eq!(config.listen_addr().to_string(), "127.0.0.1:7200");
        assert_eq!(config.database_config().namespace(), "tangle_file");
        assert_eq!(
            load_runtime_config(&path).expect_err("missing").kind(),
            RuntimeConfigErrorKind::Read
        );
    }

    #[tokio::test]
    async fn runtime_migration_command_applies_memory_database_plan() {
        let config = parse_runtime_config_json(
            r#"{
                "server": {
                    "listen_addr": "127.0.0.1:7300",
                    "relay_url": "ws://127.0.0.1:7300"
                },
                "database": {
                    "mode": "memory",
                    "namespace": "tangle_migrate",
                    "database": "relay"
                },
                "auth": {
                    "challenge_ttl_seconds": 300
                },
                "limits": {
                    "message_rate_limit": {
                        "limit": 120,
                        "window_seconds": 60
                    }
                }
            }"#,
        )
        .expect("runtime config");

        let report = migrate_runtime_database(&config).await.expect("migrate");

        assert_eq!(
            report.applied(),
            base_migration_plan().migrations().len() as u64
        );
        assert_eq!(report.already_applied(), 0);
        assert_eq!(
            report.total(),
            base_migration_plan().migrations().len() as u64
        );
    }

    #[tokio::test]
    async fn runtime_backup_command_writes_manifest_and_raw_event_jsonl() {
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let root = std::env::temp_dir().join(format!(
            "tangle-runtime-backup-{}-{}",
            std::process::id(),
            &listing.id().as_str()[..8]
        ));
        let _ = std::fs::remove_dir_all(&root);
        let db_path = root.join("db");
        let backup_path = root.join("backup");
        std::fs::create_dir_all(&root).expect("runtime root");
        let config_json = serde_json::json!({
            "server": {
                "listen_addr": "127.0.0.1:7301",
                "relay_url": "ws://127.0.0.1:7301"
            },
            "database": {
                "mode": "rocks_db",
                "path": db_path.to_str().expect("db path"),
                "namespace": "tangle_backup",
                "database": "relay"
            },
            "auth": {
                "challenge_ttl_seconds": 300
            },
            "limits": {
                "message_rate_limit": {
                    "limit": 120,
                    "window_seconds": 60
                }
            },
            "policy": {
                "approved_sellers": [FixtureKey::Seller.public_key().as_str()]
            }
        });
        let config = parse_runtime_config_json(
            &serde_json::to_string(&config_json).expect("runtime config JSON"),
        )
        .expect("runtime config");
        let store = SurrealStore::connect(config.database_config())
            .await
            .expect("store");
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        assert_eq!(
            store
                .store_raw_event(&StoredEvent::new(
                    listing.clone(),
                    UnixTimestamp::new(1_714_124_500)
                ))
                .await
                .expect("store raw"),
            StoreEventOutcome::Inserted
        );
        let report = backup_runtime_store(&config, &store, &backup_path)
            .await
            .expect("backup");

        assert_eq!(report.output_dir(), backup_path.as_path());
        assert_eq!(
            report.raw_events_path(),
            backup_path.join("raw-events.jsonl")
        );
        assert_eq!(report.raw_event_count(), 1);
        assert_eq!(report.raw_events_sha256().len(), 64);
        assert_eq!(report.manifest_path(), backup_path.join("manifest.json"));
        assert_eq!(report.manifest_sha256().len(), 64);
        assert!(!report.surrealdb_export_available());
        assert_eq!(
            std::fs::read_to_string(report.raw_events_path()).expect("raw events"),
            format!("{}\n", event_to_value(&listing))
        );
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(report.manifest_path()).expect("manifest"),
        )
        .expect("manifest JSON");
        assert_eq!(manifest["format"], "tangle-backup-v1");
        assert_eq!(manifest["database"]["namespace"], "tangle_backup");
        assert_eq!(manifest["database"]["database"], "relay");
        assert_eq!(manifest["raw_events"]["path"], "raw-events.jsonl");
        assert_eq!(manifest["raw_events"]["count"], 1);
        assert_eq!(manifest["raw_events"]["sha256"], report.raw_events_sha256());
        assert_eq!(manifest["surrealdb_export"]["available"], false);
        assert!(manifest["surrealdb_export"]["path"].is_null());
        assert!(manifest["surrealdb_export"]["sha256"].is_null());

        assert!(
            store
                .raw_event_row(listing.id())
                .await
                .expect("raw row")
                .is_some()
        );
        drop(store);
        std::fs::remove_dir_all(&root).expect("remove runtime root");
    }

    #[tokio::test]
    async fn runtime_restore_command_imports_backup_and_rebuilds_projection_state() {
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let root = std::env::temp_dir().join(format!(
            "tangle-runtime-restore-{}-{}",
            std::process::id(),
            &listing.id().as_str()[..8]
        ));
        let _ = std::fs::remove_dir_all(&root);
        let source_db_path = root.join("source-db");
        let restore_db_path = root.join("restore-db");
        let backup_path = root.join("backup");
        std::fs::create_dir_all(&root).expect("runtime root");
        let source_config_json = serde_json::json!({
            "server": {
                "listen_addr": "127.0.0.1:7302",
                "relay_url": "ws://127.0.0.1:7302"
            },
            "database": {
                "mode": "rocks_db",
                "path": source_db_path.to_str().expect("source db path"),
                "namespace": "tangle_restore_source",
                "database": "relay"
            },
            "auth": {
                "challenge_ttl_seconds": 300
            },
            "limits": {
                "message_rate_limit": {
                    "limit": 120,
                    "window_seconds": 60
                }
            },
            "policy": {
                "approved_sellers": [FixtureKey::Seller.public_key().as_str()]
            }
        });
        let restore_config_json = serde_json::json!({
            "server": {
                "listen_addr": "127.0.0.1:7303",
                "relay_url": "ws://127.0.0.1:7303"
            },
            "database": {
                "mode": "rocks_db",
                "path": restore_db_path.to_str().expect("restore db path"),
                "namespace": "tangle_restore_destination",
                "database": "relay"
            },
            "auth": {
                "challenge_ttl_seconds": 300
            },
            "limits": {
                "message_rate_limit": {
                    "limit": 120,
                    "window_seconds": 60
                }
            },
            "policy": {
                "approved_sellers": [FixtureKey::Seller.public_key().as_str()]
            }
        });
        let source_config = parse_runtime_config_json(
            &serde_json::to_string(&source_config_json).expect("source config JSON"),
        )
        .expect("source config");
        let restore_config = parse_runtime_config_json(
            &serde_json::to_string(&restore_config_json).expect("restore config JSON"),
        )
        .expect("restore config");
        let source_store = SurrealStore::connect(source_config.database_config())
            .await
            .expect("source store");
        source_store
            .apply_plan(&base_migration_plan())
            .await
            .expect("source migrations");
        assert_eq!(
            source_store
                .store_raw_event(&StoredEvent::new(
                    listing.clone(),
                    UnixTimestamp::new(1_714_124_500)
                ))
                .await
                .expect("source raw event"),
            StoreEventOutcome::Inserted
        );
        let backup_report = backup_runtime_store(&source_config, &source_store, &backup_path)
            .await
            .expect("backup");
        assert_eq!(backup_report.raw_event_count(), 1);
        drop(source_store);

        let restore_store = SurrealStore::connect(restore_config.database_config())
            .await
            .expect("restore store");
        let restore_report = restore_runtime_store(&restore_config, &restore_store, &backup_path)
            .await
            .expect("restore");
        assert_eq!(restore_report.raw_event_count(), 1);
        assert_eq!(restore_report.import_report().inserted(), 1);
        assert_eq!(restore_report.import_report().duplicate(), 0);
        assert_eq!(restore_report.rebuild_report().rebuilt(), 1);
        assert_eq!(restore_report.rebuild_report().projected(), 1);
        assert_eq!(
            restore_report.raw_events_sha256(),
            backup_report.raw_events_sha256()
        );
        let seller = FixtureKey::Seller.public_key();
        let listing_key = format!("30402:{}:listing-a", seller.as_str());
        assert!(
            restore_store
                .raw_event_row(listing.id())
                .await
                .expect("raw row")
                .is_some()
        );
        assert!(
            restore_store
                .listing_current_row(&listing_key)
                .await
                .expect("listing row")
                .is_some()
        );
        assert!(
            restore_store
                .search_document_row(&listing_key)
                .await
                .expect("search row")
                .is_some()
        );
        drop(restore_store);
        std::fs::remove_dir_all(&root).expect("remove runtime root");
    }

    #[test]
    fn backup_manifest_validation_rejects_invalid_artifact_metadata() {
        let manifest = |format: &str, path: &str| super::RuntimeBackupManifestDocument {
            format: format.to_owned(),
            database: super::RuntimeBackupDatabaseDocument {
                namespace: "tangle".to_owned(),
                database: "relay".to_owned(),
            },
            raw_events: super::RuntimeBackupArtifactDocument {
                path: path.to_owned(),
                count: 0,
                sha256: "0".repeat(64),
            },
            surrealdb_export: super::RuntimeBackupOptionalArtifactDocument {
                available: false,
                path: None,
                sha256: None,
            },
        };

        assert_eq!(
            super::validate_backup_manifest(&manifest("old", "raw-events.jsonl"))
                .expect_err("format")
                .message(),
            "backup manifest format is unsupported: old"
        );
        assert_eq!(
            super::validate_backup_manifest(&manifest("tangle-backup-v1", " "))
                .expect_err("path")
                .message(),
            "backup manifest raw_events.path must not be empty"
        );
        assert_eq!(
            super::backup_artifact_path(std::path::Path::new("backup"), "../raw-events.jsonl")
                .expect_err("parent")
                .message(),
            "backup manifest artifact paths must be relative to the backup directory"
        );
        assert!(
            super::backup_artifact_path(std::path::Path::new("backup"), "/raw-events.jsonl")
                .expect_err("absolute")
                .message()
                .contains("relative")
        );
        assert_eq!(
            super::backup_artifact_path(std::path::Path::new("backup"), "raw-events.jsonl")
                .expect("path"),
            std::path::Path::new("backup").join("raw-events.jsonl")
        );
        assert_eq!(
            super::runtime_row_string(&serde_json::json!({"raw_json": null}), "raw_json")
                .expect_err("row")
                .message(),
            "stored row field `raw_json` is invalid"
        );
    }

    #[tokio::test]
    async fn runtime_file_commands_report_io_and_manifest_validation_failures() {
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let root = std::env::temp_dir().join(format!(
            "tangle-runtime-file-errors-{}-{}",
            std::process::id(),
            &listing.id().as_str()[..8]
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("runtime root");
        let config = runtime_memory_config("tangle_file_errors");
        let store = SurrealStore::connect(config.database_config())
            .await
            .expect("store");

        assert!(
            super::import_events_from_path(&config, root.join("missing.jsonl"))
                .await
                .expect_err("missing import")
                .message()
                .starts_with("failed to read event import file `")
        );
        assert!(
            super::export_events_to_path(&config, &root)
                .await
                .expect_err("export dir")
                .message()
                .starts_with("failed to write event export file `")
        );

        let file_output = root.join("file-output");
        std::fs::write(&file_output, "not a directory").expect("file output");
        assert!(
            super::backup_runtime_store(&config, &store, &file_output)
                .await
                .expect_err("backup create dir")
                .message()
                .starts_with("failed to create backup directory `")
        );

        let raw_dir_output = root.join("raw-dir-output");
        std::fs::create_dir_all(raw_dir_output.join("raw-events.jsonl")).expect("raw dir");
        assert!(
            super::backup_runtime_store(&config, &store, &raw_dir_output)
                .await
                .expect_err("backup raw write")
                .message()
                .starts_with("failed to write backup raw events file `")
        );

        let manifest_dir_output = root.join("manifest-dir-output");
        std::fs::create_dir_all(manifest_dir_output.join("manifest.json")).expect("manifest dir");
        assert!(
            super::backup_runtime_store(&config, &store, &manifest_dir_output)
                .await
                .expect_err("backup manifest write")
                .message()
                .starts_with("failed to write backup manifest file `")
        );

        let missing_manifest = root.join("missing-manifest");
        std::fs::create_dir_all(&missing_manifest).expect("missing manifest dir");
        assert!(
            super::restore_runtime_store(&config, &store, &missing_manifest)
                .await
                .expect_err("missing manifest")
                .message()
                .starts_with("failed to read backup manifest file `")
        );

        let invalid_manifest = root.join("invalid-manifest");
        std::fs::create_dir_all(&invalid_manifest).expect("invalid manifest dir");
        std::fs::write(invalid_manifest.join("manifest.json"), "{").expect("invalid manifest");
        assert!(
            super::restore_runtime_store(&config, &store, &invalid_manifest)
                .await
                .expect_err("invalid manifest")
                .message()
                .starts_with("backup manifest JSON is invalid:")
        );

        let restore_case = |name: &str, raw_events: &str, manifest: serde_json::Value| {
            let path = root.join(name);
            std::fs::create_dir_all(&path).expect("restore case dir");
            std::fs::write(path.join("raw-events.jsonl"), raw_events).expect("raw events");
            std::fs::write(
                path.join("manifest.json"),
                serde_json::to_string_pretty(&manifest).expect("manifest JSON"),
            )
            .expect("manifest");
            path
        };
        let missing_raw = restore_case(
            "missing-raw",
            "",
            serde_json::json!({
                "format": "tangle-backup-v1",
                "database": {"namespace": "tangle", "database": "relay"},
                "raw_events": {"path": "absent.jsonl", "count": 0, "sha256": "0".repeat(64)},
                "surrealdb_export": {"available": false, "path": null, "sha256": null}
            }),
        );
        assert!(
            super::restore_runtime_store(&config, &store, &missing_raw)
                .await
                .expect_err("missing raw")
                .message()
                .starts_with("failed to read backup raw events file `")
        );
        let checksum = restore_case(
            "checksum",
            "",
            serde_json::json!({
                "format": "tangle-backup-v1",
                "database": {"namespace": "tangle", "database": "relay"},
                "raw_events": {"path": "raw-events.jsonl", "count": 0, "sha256": "1".repeat(64)},
                "surrealdb_export": {"available": false, "path": null, "sha256": null}
            }),
        );
        assert!(
            super::restore_runtime_store(&config, &store, &checksum)
                .await
                .expect_err("checksum")
                .message()
                .starts_with("backup raw events checksum mismatch:")
        );
        let raw = format!("{}\n", event_to_value(&listing));
        let count = restore_case(
            "count",
            &raw,
            serde_json::json!({
                "format": "tangle-backup-v1",
                "database": {"namespace": "tangle", "database": "relay"},
                "raw_events": {"path": "raw-events.jsonl", "count": 2, "sha256": super::sha256_hex(raw.as_bytes())},
                "surrealdb_export": {"available": false, "path": null, "sha256": null}
            }),
        );
        assert!(
            super::restore_runtime_store(&config, &store, &count)
                .await
                .expect_err("count")
                .message()
                .starts_with("backup raw events count mismatch:")
        );

        std::fs::remove_dir_all(&root).expect("remove runtime root");
    }

    #[tokio::test]
    async fn runtime_websocket_route_requires_upgrade_headers() {
        let store = runtime_memory_store().await;
        let (shutdown, _) = GracefulShutdownSignal::new();
        let response =
            super::runtime_router(runtime_memory_config("ws_missing_upgrade"), store, shutdown)
                .oneshot(
                    Request::builder()
                        .uri("/ws")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn runtime_server_reports_listener_bind_failures() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind reserved listener");
        let address = listener.local_addr().expect("reserved listener address");
        let mut config = runtime_memory_config("runtime_listen_failure");
        config.listen_addr = address;
        let (shutdown, _) = GracefulShutdownSignal::new();
        let error = super::RuntimeServer::new(config, shutdown)
            .run()
            .await
            .expect_err("listen failure");

        assert!(error.message().contains("listen failed:"));
        drop(listener);
    }

    #[tokio::test]
    async fn runtime_websocket_route_handles_client_frame_edges() {
        let store = runtime_memory_store().await;
        let (shutdown, _) = GracefulShutdownSignal::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let app = super::runtime_router(runtime_memory_config("ws_frame_edges"), store, shutdown);
        let server =
            tokio::spawn(async move { axum::serve(listener, app).await.expect("serve runtime") });

        let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{address}/ws"))
            .await
            .expect("websocket connect");
        assert_eq!(next_ws_json(&mut client, "initial auth").await[0], "AUTH");
        let listing = listing_event_at(1_714_124_436);
        client
            .send(TungsteniteMessage::Text(
                serde_json::json!([
                    "REQ",
                    "sub-live",
                    {
                        "kinds": [30402],
                        "authors": [listing.unsigned().pubkey().as_str()]
                    }
                ])
                .to_string()
                .into(),
            ))
            .await
            .expect("subscription send");
        assert_eq!(
            next_ws_json(&mut client, "subscription eose").await[0],
            "EOSE"
        );

        let auth = build_fixture_event_from_parts(
            FixtureKey::Seller,
            1_714_124_435,
            22_242,
            vec![
                vec!["relay".to_owned(), "ws://127.0.0.1:0".to_owned()],
                vec!["challenge".to_owned(), "challenge-001".to_owned()],
            ],
            "",
        )
        .expect("auth");
        let (mut publisher, _) = tokio_tungstenite::connect_async(format!("ws://{address}/ws"))
            .await
            .expect("publisher connect");
        assert_eq!(
            next_ws_json(&mut publisher, "publisher auth").await[0],
            "AUTH"
        );
        publisher
            .send(TungsteniteMessage::Text(
                serde_json::json!(["AUTH", event_to_value(&auth)])
                    .to_string()
                    .into(),
            ))
            .await
            .expect("auth send");
        let auth_ok = next_ws_json(&mut publisher, "auth ok").await;
        assert_eq!(auth_ok[0], "OK");
        assert_eq!(auth_ok[2], true, "{auth_ok:?}");
        publisher
            .send(TungsteniteMessage::Text(
                serde_json::json!(["EVENT", event_to_value(&listing)])
                    .to_string()
                    .into(),
            ))
            .await
            .expect("listing send");
        let listing_ok = next_ws_json(&mut publisher, "listing ok").await;
        assert_eq!(listing_ok[0], "OK");
        assert_eq!(listing_ok[2], true);
        let live = next_ws_json(&mut client, "live event").await;
        assert_eq!(live[0], "EVENT");
        assert_eq!(live[1], "sub-live");
        assert_eq!(live[2]["id"], listing.id().as_str());
        client
            .send(TungsteniteMessage::Ping(vec![1].into()))
            .await
            .expect("ping send");
        client
            .send(TungsteniteMessage::Binary(vec![1].into()))
            .await
            .expect("binary send");
        let notice = next_ws_json(&mut client, "binary notice").await;
        assert_eq!(notice[0], "NOTICE");
        assert!(
            notice[1]
                .as_str()
                .expect("notice message")
                .contains("binary websocket messages are not supported")
        );
        client
            .send(TungsteniteMessage::Close(None))
            .await
            .expect("close send");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        server.abort();
    }

    #[test]
    fn client_message_loop_dispatches_supported_text_messages() {
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let auth = build_fixture_event(&auth_event_spec()).expect("auth");
        let mut loop_state = runtime_client_message_loop();

        let outcome = loop_state.handle_frame(ClientFrame::Text(
            serde_json::json!(["EVENT", event_to_value(&listing)]).to_string(),
        ));
        assert!(matches!(
            outcome,
            ClientFrameOutcome::Message(ClientMessage::Event(_))
        ));
        assert!(format!("{outcome:?}").contains(listing.id().as_str()));
        let outcome = loop_state.handle_frame(ClientFrame::Text(
            serde_json::json!(["AUTH", event_to_value(&auth)]).to_string(),
        ));
        assert!(matches!(
            outcome,
            ClientFrameOutcome::Message(ClientMessage::Auth(_))
        ));
        assert!(format!("{outcome:?}").contains(auth.id().as_str()));
        let outcome = loop_state.handle_frame(ClientFrame::Text(
            r#"["REQ","sub-a",{"kinds":[30402],"limit":1}]"#.to_owned(),
        ));
        assert!(matches!(
            outcome,
            ClientFrameOutcome::Message(ClientMessage::Req { .. })
        ));
        assert!(format!("{outcome:?}").contains("sub-a"));
        assert!(format!("{outcome:?}").contains("limit: Some(1)"));
        let outcome = loop_state.handle_frame(ClientFrame::Text(r#"["CLOSE","sub-a"]"#.to_owned()));
        assert!(matches!(
            outcome,
            ClientFrameOutcome::Message(ClientMessage::Close(_))
        ));
        assert!(format!("{outcome:?}").contains("sub-a"));
        assert_eq!(loop_state.connection().id().as_str(), "client-loop");
        assert_eq!(
            loop_state.connection_mut().remote_addr(),
            Some("127.0.0.1:7777")
        );
    }

    #[test]
    fn client_message_loop_rejects_or_ignores_non_message_frames() {
        let mut loop_state = runtime_client_message_loop();

        let outcome = loop_state.handle_frame(ClientFrame::Text("not json".to_owned()));
        assert!(matches!(
            outcome,
            ClientFrameOutcome::Reject(RelayMessage::Notice(_))
        ));
        assert!(format!("{outcome:?}").contains("client message JSON is invalid"));
        assert_eq!(
            loop_state.handle_frame(ClientFrame::Binary(vec![1, 2, 3])),
            ClientFrameOutcome::Reject(RelayMessage::Notice(
                "unsupported: binary websocket messages are not supported".to_owned()
            ))
        );
        assert_eq!(
            loop_state.handle_frame(ClientFrame::Ping(vec![1])),
            ClientFrameOutcome::Ignore
        );
        assert_eq!(
            loop_state.handle_frame(ClientFrame::Pong(vec![2])),
            ClientFrameOutcome::Ignore
        );
        assert_eq!(
            loop_state.handle_frame(ClientFrame::Close),
            ClientFrameOutcome::Close
        );
    }

    #[test]
    fn websocket_messages_convert_to_client_frames() {
        assert_eq!(
            super::client_frame_from_message(axum::extract::ws::Message::Text("hi".into())),
            ClientFrame::Text("hi".to_owned())
        );
        assert_eq!(
            super::client_frame_from_message(axum::extract::ws::Message::Binary(vec![1].into())),
            ClientFrame::Binary(vec![1])
        );
        assert_eq!(
            super::client_frame_from_message(axum::extract::ws::Message::Ping(vec![2].into())),
            ClientFrame::Ping(vec![2])
        );
        assert_eq!(
            super::client_frame_from_message(axum::extract::ws::Message::Pong(vec![3].into())),
            ClientFrame::Pong(vec![3])
        );
        assert_eq!(
            super::client_frame_from_message(axum::extract::ws::Message::Close(None)),
            ClientFrame::Close
        );
    }

    #[test]
    fn client_message_loop_enforces_backpressure_limits() {
        let config = RelayConnectionConfig::new(
            "wss://relay.radroots.test",
            300,
            RateLimitConfig::new(2, 60).expect("rate limit"),
            RuntimeLimits::default(),
        )
        .expect("config");
        let connection =
            RelayConnection::new(RelayConnectionId::new("backpressure").expect("id"), config);
        let mut loop_state = ClientMessageLoop::new(connection);
        let frame = || ClientFrame::Text(r#"["REQ","sub-a",{"kinds":[30402]}]"#.to_owned());

        assert!(matches!(
            loop_state.handle_frame_at(frame(), UnixTimestamp::new(100)),
            ClientFrameOutcome::Message(ClientMessage::Req { .. })
        ));
        assert!(matches!(
            loop_state.handle_frame_at(frame(), UnixTimestamp::new(100)),
            ClientFrameOutcome::Message(ClientMessage::Req { .. })
        ));
        assert_eq!(
            loop_state.handle_frame_at(frame(), UnixTimestamp::new(100)),
            ClientFrameOutcome::Reject(RelayMessage::Notice(
                "rate-limited: retry after 60 seconds".to_owned()
            ))
        );
        assert_eq!(
            loop_state.handle_frame_at(ClientFrame::Ping(vec![1]), UnixTimestamp::new(100)),
            ClientFrameOutcome::Ignore
        );
        assert!(matches!(
            loop_state.handle_frame_at(frame(), UnixTimestamp::new(160)),
            ClientFrameOutcome::Message(ClientMessage::Req { .. })
        ));
    }

    #[tokio::test]
    async fn event_message_handler_stores_and_projects_authenticated_listing() {
        let store = runtime_memory_store().await;
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let mut connection = authenticated_connection();
        let handler = EventMessageHandler::new(
            store.clone(),
            EventValidator::new(
                RuntimeLimits::default(),
                AdmissionPolicy::new().approve_seller(listing.unsigned().pubkey().clone()),
            ),
        );
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());

        let outcome = handler
            .handle_event(
                &connection,
                listing.clone(),
                UnixTimestamp::new(1_714_125_300),
                UnixTimestamp::new(1_714_125_400),
            )
            .await;

        assert_eq!(
            outcome,
            RelayMessage::Ok {
                event_id: listing.id().clone(),
                accepted: true,
                message: String::new()
            }
        );
        assert_eq!(
            handler
                .store()
                .raw_event_row(listing.id())
                .await
                .expect("raw")
                .expect("raw exists")["event_id"],
            listing.id().as_str()
        );
        assert_eq!(
            store
                .listing_current_row(&listing_key)
                .await
                .expect("current")
                .expect("current exists")["event_id"],
            listing.id().as_str()
        );
        assert_eq!(
            store
                .search_document_row(&listing_key)
                .await
                .expect("search")
                .expect("search exists")["event_id"],
            listing.id().as_str()
        );
        assert_eq!(
            handler
                .handle_event(
                    &connection,
                    listing.clone(),
                    UnixTimestamp::new(1_714_125_301),
                    UnixTimestamp::new(1_714_125_401),
                )
                .await,
            RelayMessage::Ok {
                event_id: listing.id().clone(),
                accepted: true,
                message: String::new()
            }
        );
        assert_eq!(handler.validator().limits(), RuntimeLimits::default());
        connection.auth_mut().clear_authentication();
        let rejected = handler
            .handle_event(
                &connection,
                listing.clone(),
                UnixTimestamp::new(1_714_125_302),
                UnixTimestamp::new(1_714_125_402),
            )
            .await;
        assert!(matches!(
            rejected,
            RelayMessage::Ok {
                accepted: false,
                ..
            }
        ));
        assert!(format!("{rejected:?}").contains("write authentication required"));
    }

    #[tokio::test]
    async fn event_message_handler_persists_durable_write_rate_limits() {
        let store = runtime_memory_store().await;
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let connection = authenticated_connection();
        let handler = EventMessageHandler::new(
            store.clone(),
            EventValidator::new(
                RuntimeLimits::default(),
                AdmissionPolicy::new().approve_seller(listing.unsigned().pubkey().clone()),
            ),
        )
        .with_durable_write_rate_limit(Some(RateLimitConfig::new(1, 60).expect("write rate")));

        let accepted = handler
            .handle_event(
                &connection,
                listing.clone(),
                UnixTimestamp::new(1_714_125_500),
                UnixTimestamp::new(1_714_125_500),
            )
            .await;
        let rejected = handler
            .handle_event(
                &connection,
                listing.clone(),
                UnixTimestamp::new(1_714_125_501),
                UnixTimestamp::new(1_714_125_501),
            )
            .await;

        assert_eq!(
            handler.durable_write_rate_limit(),
            Some(RateLimitConfig::new(1, 60).expect("write rate"))
        );
        assert_eq!(
            accepted,
            RelayMessage::Ok {
                event_id: listing.id().clone(),
                accepted: true,
                message: String::new()
            }
        );
        assert!(matches!(
            rejected,
            RelayMessage::Ok {
                accepted: false,
                ..
            }
        ));
        assert!(format!("{rejected:?}").contains("rate-limited: retry after 59 seconds"));
        let key = format!("event_write:{}", listing.unsigned().pubkey().as_str());
        let row = store
            .rate_limit_state_row(&key)
            .await
            .expect("rate row")
            .expect("rate row exists");
        assert_eq!(row["key"], key);
        assert_eq!(row["expires_at"], 1_714_125_560_u64);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(row["state"].as_str().expect("state"))
                .expect("state json"),
            serde_json::json!({
                "started_at": 1714125500_u64,
                "used": 1
            })
        );
    }

    #[tokio::test]
    async fn event_message_handler_reports_store_policy_failures() {
        let config = SurrealConnectionConfig::memory("tangle_runtime", "event_policy_failure")
            .expect("memory config");
        let store = SurrealStore::connect_memory(&config)
            .await
            .expect("memory store");
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let connection = authenticated_connection();
        let handler = EventMessageHandler::new(
            store,
            EventValidator::new(
                RuntimeLimits::default(),
                AdmissionPolicy::new().approve_seller(listing.unsigned().pubkey().clone()),
            ),
        );

        assert!(
            format!(
                "{:?}",
                handler
                    .handle_event(
                        &connection,
                        listing,
                        UnixTimestamp::new(1_714_125_600),
                        UnixTimestamp::new(1_714_125_601),
                    )
                    .await
            )
            .contains("policy unavailable")
        );
    }

    #[tokio::test]
    async fn event_message_handler_reports_rate_limit_store_and_projection_failures() {
        let connection = authenticated_connection();
        let rate_limit_store = SurrealStore::connect_memory(
            &SurrealConnectionConfig::memory("tangle_runtime", "rate_limit_failure")
                .expect("rate limit config"),
        )
        .await
        .expect("rate limit store");
        rate_limit_store
            .database()
            .query(
                "DEFINE TABLE rate_limit_state SCHEMAFULL; DEFINE FIELD key ON TABLE rate_limit_state TYPE int;",
            )
            .await
            .expect("rate limit schema")
            .check()
            .expect("rate limit schema check");
        let rate_limited = EventMessageHandler::new(
            rate_limit_store,
            EventValidator::new(RuntimeLimits::default(), AdmissionPolicy::new()),
        )
        .with_durable_write_rate_limit(Some(RateLimitConfig::new(1, 60).expect("rate limit")));
        let outcome = rate_limited
            .handle_event(
                &connection,
                note_event(1_714_125_610, "rate limit unavailable"),
                UnixTimestamp::new(1_714_125_611),
                UnixTimestamp::new(1_714_125_611),
            )
            .await;
        assert!(format!("{outcome:?}").contains("rate limit unavailable"));

        let store_failure = SurrealStore::connect_memory(
            &SurrealConnectionConfig::memory("tangle_runtime", "store_failure")
                .expect("store config"),
        )
        .await
        .expect("store failure store");
        store_failure
            .database()
            .query(
                "DEFINE TABLE nostr_event SCHEMAFULL; DEFINE FIELD event_id ON TABLE nostr_event TYPE int;",
            )
            .await
            .expect("store schema")
            .check()
            .expect("store schema check");
        let store_handler = EventMessageHandler::new(
            store_failure,
            EventValidator::new(RuntimeLimits::default(), AdmissionPolicy::new()),
        );
        let outcome = store_handler
            .handle_event(
                &connection,
                note_event(1_714_125_620, "store unavailable"),
                UnixTimestamp::new(1_714_125_621),
                UnixTimestamp::new(1_714_125_621),
            )
            .await;
        assert!(format!("{outcome:?}").contains("store unavailable"));

        let projection_store = runtime_memory_store().await;
        projection_store
            .database()
            .query(
                "REMOVE TABLE event_tag_index; DEFINE TABLE event_tag_index SCHEMAFULL; DEFINE FIELD event_id ON TABLE event_tag_index TYPE int;",
            )
            .await
            .expect("projection schema")
            .check()
            .expect("projection schema check");
        let listing = listing_event_at(1_714_125_630);
        let projection_handler = EventMessageHandler::new(
            projection_store,
            EventValidator::new(
                RuntimeLimits::default(),
                AdmissionPolicy::new().approve_seller(listing.unsigned().pubkey().clone()),
            ),
        );
        let outcome = projection_handler
            .handle_event(
                &connection,
                listing,
                UnixTimestamp::new(1_714_125_631),
                UnixTimestamp::new(1_714_125_631),
            )
            .await;
        assert!(format!("{outcome:?}").contains("projection failed"));
    }

    #[tokio::test]
    async fn event_message_handler_accepts_ephemeral_events_without_persistence() {
        let store = runtime_memory_store().await;
        let event = build_fixture_event_from_parts(
            FixtureKey::Seller,
            1_714_125_640,
            20_000,
            Vec::new(),
            "ephemeral",
        )
        .expect("ephemeral event");
        let handler = EventMessageHandler::new(
            store.clone(),
            EventValidator::new(RuntimeLimits::default(), AdmissionPolicy::new()),
        );

        let outcome = handler
            .handle_event(
                &authenticated_connection(),
                event.clone(),
                UnixTimestamp::new(1_714_125_641),
                UnixTimestamp::new(1_714_125_641),
            )
            .await;

        assert_eq!(
            outcome,
            RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: true,
                message: String::new()
            }
        );
        assert!(
            store
                .raw_event_row(event.id())
                .await
                .expect("raw row")
                .is_none()
        );
    }

    #[tokio::test]
    async fn event_message_handler_applies_dynamic_seller_policy_rows() {
        let store = runtime_memory_store().await;
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
        let connection = authenticated_connection();
        let handler = EventMessageHandler::new(
            store.clone(),
            EventValidator::new(RuntimeLimits::default(), AdmissionPolicy::new()),
        );

        store
            .set_seller_approved(
                listing.unsigned().pubkey().as_str(),
                true,
                UnixTimestamp::new(1_714_126_200),
            )
            .await
            .expect("approve seller");
        let accepted = handler
            .handle_event(
                &connection,
                listing.clone(),
                UnixTimestamp::new(1_714_126_201),
                UnixTimestamp::new(1_714_126_201),
            )
            .await;

        assert_eq!(
            accepted,
            RelayMessage::Ok {
                event_id: listing.id().clone(),
                accepted: true,
                message: String::new()
            }
        );
        assert!(
            store
                .listing_current_row(&listing_key)
                .await
                .expect("listing row")
                .is_some()
        );
        assert!(
            store
                .search_document_row(&listing_key)
                .await
                .expect("search row")
                .is_some()
        );

        store
            .set_pubkey_blocked(
                listing.unsigned().pubkey().as_str(),
                true,
                UnixTimestamp::new(1_714_126_202),
            )
            .await
            .expect("block seller");
        let blocked_listing = listing_event_at(1_714_126_203);
        let blocked = handler
            .handle_event(
                &connection,
                blocked_listing.clone(),
                UnixTimestamp::new(1_714_126_204),
                UnixTimestamp::new(1_714_126_204),
            )
            .await;
        assert_eq!(
            blocked,
            RelayMessage::Ok {
                event_id: blocked_listing.id().clone(),
                accepted: true,
                message: String::new()
            }
        );
        assert_ne!(
            store
                .listing_current_row(&listing_key)
                .await
                .expect("blocked current")
                .expect("current row")["event_id"],
            blocked_listing.id().as_str()
        );

        let fallback_store = runtime_memory_store().await;
        fallback_store
            .set_seller_approved(
                listing.unsigned().pubkey().as_str(),
                false,
                UnixTimestamp::new(1_714_126_205),
            )
            .await
            .expect("fallback row");
        let fallback_handler = EventMessageHandler::new(
            fallback_store.clone(),
            EventValidator::new(
                RuntimeLimits::default(),
                AdmissionPolicy::new().approve_seller(listing.unsigned().pubkey().clone()),
            ),
        );
        let fallback_listing = listing_event_at(1_714_126_206);
        let fallback = fallback_handler
            .handle_event(
                &connection,
                fallback_listing.clone(),
                UnixTimestamp::new(1_714_126_207),
                UnixTimestamp::new(1_714_126_207),
            )
            .await;
        assert_eq!(
            fallback,
            RelayMessage::Ok {
                event_id: fallback_listing.id().clone(),
                accepted: true,
                message: String::new()
            }
        );
        assert_eq!(
            fallback_store
                .listing_current_row(&listing_key)
                .await
                .expect("fallback current")
                .expect("fallback current row")["event_id"],
            fallback_listing.id().as_str()
        );
    }

    #[test]
    fn auth_message_handler_issues_and_accepts_auth_events() {
        let handler = AuthMessageHandler;
        let mut connection = RelayConnection::new(
            RelayConnectionId::new("auth").expect("connection id"),
            RelayConnectionConfig::default(),
        );
        let auth = build_fixture_event(&auth_event_spec()).expect("auth");

        assert_eq!(
            handler.issue_challenge(
                &mut connection,
                " challenge-001 ",
                UnixTimestamp::new(1_714_124_430)
            ),
            RelayMessage::Auth("challenge-001".to_owned())
        );
        assert_eq!(
            handler.handle_auth(
                &mut connection,
                auth.clone(),
                UnixTimestamp::new(1_714_124_435)
            ),
            RelayMessage::Ok {
                event_id: auth.id().clone(),
                accepted: true,
                message: String::new()
            }
        );
        assert_eq!(
            connection.auth().authenticated_pubkey(),
            Some(auth.unsigned().pubkey())
        );
        assert_eq!(
            handler.issue_challenge(&mut connection, " ", UnixTimestamp::new(1_714_124_436)),
            RelayMessage::Notice("error: auth challenge must not be empty".to_owned())
        );
    }

    #[test]
    fn auth_message_handler_rejects_invalid_auth_messages() {
        let handler = AuthMessageHandler;
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let auth = build_fixture_event(&auth_event_spec()).expect("auth");
        let mut missing_challenge = RelayConnection::new(
            RelayConnectionId::new("missing-challenge").expect("connection id"),
            RelayConnectionConfig::default(),
        );
        let mut wrong_kind = RelayConnection::new(
            RelayConnectionId::new("wrong-kind").expect("connection id"),
            RelayConnectionConfig::default(),
        );

        let outcome = handler.handle_auth(
            &mut missing_challenge,
            auth.clone(),
            UnixTimestamp::new(1_714_124_435),
        );
        assert!(matches!(
            outcome,
            RelayMessage::Ok {
                accepted: false,
                ..
            }
        ));
        assert!(format!("{outcome:?}").contains("auth challenge is missing"));
        let outcome = handler.handle_auth(
            &mut wrong_kind,
            listing.clone(),
            UnixTimestamp::new(1_714_124_435),
        );
        assert!(matches!(
            outcome,
            RelayMessage::Ok {
                accepted: false,
                ..
            }
        ));
        assert!(format!("{outcome:?}").contains("AUTH message must contain kind 22242"));
        let malformed_auth = build_fixture_event_from_parts(
            FixtureKey::Relay,
            1_714_124_436,
            22_242,
            Vec::new(),
            "",
        )
        .expect("malformed auth");
        let outcome = handler.handle_auth(
            &mut wrong_kind,
            malformed_auth,
            UnixTimestamp::new(1_714_124_436),
        );
        assert!(format!("{outcome:?}").contains("invalid:"));
    }

    #[tokio::test]
    async fn req_message_handler_returns_raw_events_and_eose() {
        let store = runtime_memory_store().await;
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        store
            .store_raw_event(&StoredEvent::new(
                listing.clone(),
                UnixTimestamp::new(1_714_125_300),
            ))
            .await
            .expect("raw event");
        let handler = ReqMessageHandler::new(store, NostrFilterCompiler::default());
        let mut connection = runtime_connection("req-raw");
        let subscription_id = SubscriptionId::new("sub-raw").expect("subscription");
        let filter = filter_from_value(&serde_json::json!({
            "ids": [listing.id().as_str()],
            "limit": 10
        }))
        .expect("filter");

        let messages = handler
            .handle_req(&mut connection, subscription_id.clone(), vec![filter])
            .await;

        assert_eq!(messages.len(), 2);
        assert!(matches!(&messages[0], RelayMessage::Event { .. }));
        assert!(format!("{:?}", messages[0]).contains(subscription_id.as_str()));
        assert!(format!("{:?}", messages[0]).contains(listing.id().as_str()));
        assert_eq!(messages[1], RelayMessage::Eose(subscription_id.clone()));
        assert!(connection.subscriptions().plan(&subscription_id).is_some());
        assert_eq!(handler.compiler(), NostrFilterCompiler::default());
    }

    #[tokio::test]
    async fn req_message_handler_hydrates_search_results_and_closes_bad_requests() {
        let store = runtime_memory_store().await;
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        store
            .store_raw_event(&StoredEvent::new(
                listing.clone(),
                UnixTimestamp::new(1_714_125_300),
            ))
            .await
            .expect("raw event");
        store
            .index_listing_search_document(&listing)
            .await
            .expect("search");
        let handler = ReqMessageHandler::new(store.clone(), NostrFilterCompiler::default());
        let mut connection = runtime_connection("req-search");
        let search_id = SubscriptionId::new("sub-search").expect("subscription");
        let search_filter = filter_from_value(&serde_json::json!({
            "search": "carrot",
            "kinds": [30402],
            "authors": [listing.unsigned().pubkey().as_str()],
            "limit": 5
        }))
        .expect("filter");

        let messages = handler
            .handle_req(&mut connection, search_id.clone(), vec![search_filter])
            .await;

        assert_eq!(messages.len(), 2);
        assert!(matches!(&messages[0], RelayMessage::Event { .. }));
        assert!(format!("{:?}", messages[0]).contains(listing.id().as_str()));
        assert_eq!(messages[1], RelayMessage::Eose(search_id));
        let bad_id = SubscriptionId::new("sub-bad").expect("subscription");
        let bad = handler
            .handle_req(&mut connection, bad_id.clone(), Vec::new())
            .await;
        assert_eq!(
            bad,
            vec![RelayMessage::Closed {
                subscription_id: bad_id,
                message: "unsupported: query plan: query plan must include at least one branch"
                    .to_owned()
            }]
        );
        assert!(
            handler
                .store()
                .raw_event_row(listing.id())
                .await
                .expect("raw")
                .is_some()
        );
    }

    #[tokio::test]
    async fn req_message_handler_closes_when_store_query_fails() {
        let config = SurrealConnectionConfig::memory("tangle_runtime", "req_store_failure")
            .expect("memory config");
        let store = SurrealStore::connect_memory(&config)
            .await
            .expect("memory store");
        let handler = ReqMessageHandler::new(store, NostrFilterCompiler::default());
        let mut connection = runtime_connection("req-error");
        let subscription_id = SubscriptionId::new("sub-error").expect("subscription");
        let filter =
            filter_from_value(&serde_json::json!({"kinds": [30402], "limit": 1})).expect("filter");

        assert_eq!(
            handler
                .handle_req(&mut connection, subscription_id.clone(), vec![filter])
                .await,
            vec![RelayMessage::Closed {
                subscription_id,
                message: "internal server error".to_owned()
            }]
        );
    }

    #[tokio::test]
    async fn close_message_handler_removes_subscriptions() {
        let store = runtime_memory_store().await;
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        store
            .store_raw_event(&StoredEvent::new(
                listing.clone(),
                UnixTimestamp::new(1_714_125_300),
            ))
            .await
            .expect("raw event");
        let req_handler = ReqMessageHandler::new(store, NostrFilterCompiler::default());
        let close_handler = CloseMessageHandler;
        let mut connection = runtime_connection("close");
        let subscription_id = SubscriptionId::new("sub-close").expect("subscription");
        let filter = filter_from_value(&serde_json::json!({
            "ids": [listing.id().as_str()]
        }))
        .expect("filter");

        req_handler
            .handle_req(&mut connection, subscription_id.clone(), vec![filter])
            .await;

        assert_eq!(connection.subscriptions().active_count(), 1);
        assert_eq!(
            close_handler.handle_close(&mut connection, &subscription_id),
            CloseMessageOutcome::Closed
        );
        assert_eq!(connection.subscriptions().active_count(), 0);
        assert_eq!(
            close_handler.handle_close(&mut connection, &subscription_id),
            CloseMessageOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn live_event_fanout_delivers_matching_subscription_events() {
        let store = runtime_memory_store().await;
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let handler = ReqMessageHandler::new(store, NostrFilterCompiler::default());
        let fanout = LiveEventFanout;
        let mut connection = runtime_connection("fanout");
        let matching_id = SubscriptionId::new("sub-matching").expect("matching subscription");
        let miss_id = SubscriptionId::new("sub-miss").expect("miss subscription");
        let matching_filter = filter_from_value(&serde_json::json!({
            "kinds": [30402],
            "authors": [listing.unsigned().pubkey().as_str()]
        }))
        .expect("matching filter");
        let miss_filter = filter_from_value(&serde_json::json!({
            "ids": ["cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]
        }))
        .expect("miss filter");

        handler
            .handle_req(&mut connection, matching_id.clone(), vec![matching_filter])
            .await;
        handler
            .handle_req(&mut connection, miss_id, vec![miss_filter])
            .await;

        let messages = fanout.fanout(&connection, &listing);

        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages,
            vec![RelayMessage::Event {
                subscription_id: matching_id,
                event: listing
            }]
        );
    }

    #[test]
    fn live_event_fanout_ignores_connections_without_matches() {
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let fanout = LiveEventFanout;
        let connection = runtime_connection("fanout-empty");

        assert_eq!(fanout.fanout(&connection, &listing), Vec::new());
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

    #[tokio::test]
    async fn runtime_readiness_checks_database_migrations_and_repository() {
        let config = SurrealConnectionConfig::memory("tangle_runtime", "readiness_gates")
            .expect("memory config");
        let store = SurrealStore::connect_memory(&config)
            .await
            .expect("memory store");

        let missing = runtime_readiness_state(&store).await;
        assert_eq!(
            missing,
            ReadinessState::new(
                ReadinessCheckStatus::Ready,
                ReadinessCheckStatus::NotReady,
                ReadinessCheckStatus::NotReady
            )
        );

        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        assert_eq!(
            runtime_readiness_state(&store).await,
            ReadinessState::ready()
        );
    }

    #[tokio::test]
    async fn runtime_readiness_rejects_migration_checksum_mismatch() {
        let store = runtime_memory_store().await;

        store
            .database()
            .query("UPDATE migration SET checksum = 'bad' WHERE name = '0001_migration_tracking';")
            .await
            .expect("checksum update")
            .check()
            .expect("checksum update check");

        assert_eq!(
            super::runtime_migrations_ready(&store)
                .await
                .expect_err("checksum mismatch")
                .message(),
            "runtime migrations do not match"
        );
        assert_eq!(
            runtime_readiness_state(&store).await,
            ReadinessState::new(
                ReadinessCheckStatus::Ready,
                ReadinessCheckStatus::NotReady,
                ReadinessCheckStatus::NotReady
            )
        );
    }

    #[tokio::test]
    async fn readiness_status_after_respects_dependency_gates() {
        assert_eq!(
            super::readiness_status_after(true, std::future::ready(Ok::<(), ()>(()))).await,
            ReadinessCheckStatus::Ready
        );
        assert_eq!(
            super::readiness_status_after(true, std::future::ready(Err::<(), ()>(()))).await,
            ReadinessCheckStatus::NotReady
        );
        assert_eq!(
            super::readiness_status_after(false, std::future::ready(Ok::<(), ()>(()))).await,
            ReadinessCheckStatus::NotReady
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_reports_store_snapshot() {
        let store = runtime_memory_store().await;
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let profile = seller_profile(1_714_125_300, "radroots-market", Some("Radroots Market"));
        let seller = listing.unsigned().pubkey().as_str().to_owned();
        store
            .store_raw_event(&StoredEvent::new(
                listing.clone(),
                UnixTimestamp::new(1_714_125_301),
            ))
            .await
            .expect("store listing");
        store
            .store_raw_event(&StoredEvent::new(
                profile.clone(),
                UnixTimestamp::new(1_714_125_302),
            ))
            .await
            .expect("store profile");
        store
            .project_current_listing(&listing, UnixTimestamp::new(1_714_125_303))
            .await
            .expect("project listing");
        store
            .project_seller_profile(&profile, UnixTimestamp::new(1_714_125_304))
            .await
            .expect("project profile");
        store
            .set_seller_approved(seller.as_str(), true, UnixTimestamp::new(1_714_125_305))
            .await
            .expect("approve seller");

        let response = metrics_router(MetricsHttpState::new(store))
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("text/plain; version=0.0.4"))
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = String::from_utf8(body.to_vec()).expect("utf8");
        assert!(body.contains(&format!(
            "tangle_info{{software=\"{}\",version=\"{}\"}} 1",
            TANGLE_RELAY_SOFTWARE, TANGLE_RELAY_VERSION
        )));
        assert!(body.contains("tangle_relay_ready 1"));
        assert!(body.contains("tangle_store_events{state=\"stored\"} 2"));
        assert!(body.contains("tangle_store_events{state=\"visible\"} 2"));
        assert!(body.contains("tangle_store_listings{state=\"active\"} 1"));
        assert!(body.contains("tangle_store_seller_profiles{state=\"visible\"} 1"));
        assert!(body.contains("tangle_store_sellers{state=\"approved\"} 1"));
    }

    #[test]
    fn admin_pubkey_requirement_rejects_disabled_and_unauthorized_access() {
        let admin = FixtureKey::Relay.public_key();
        let seller = FixtureKey::Seller.public_key();
        let disabled = runtime_memory_config("admin_disabled");
        let enabled = runtime_admin_config("admin_enabled");
        let mut headers = http::HeaderMap::new();

        assert_eq!(
            super::require_admin_pubkey(&disabled, &headers)
                .expect_err("disabled admin")
                .message(),
            "admin policy api is disabled"
        );
        headers.insert(
            "x-tangle-admin-pubkey",
            HeaderValue::from_str(seller.as_str()).expect("seller header"),
        );
        assert_eq!(
            super::require_admin_pubkey(&enabled, &headers)
                .expect_err("wrong admin")
                .message(),
            "admin pubkey is not authorized"
        );
        headers.insert(
            "x-tangle-admin-pubkey",
            HeaderValue::from_str(admin.as_str()).expect("admin header"),
        );
        assert_eq!(
            super::require_admin_pubkey(&enabled, &headers).expect("admin"),
            admin
        );
        headers.insert(
            "x-tangle-admin-pubkey",
            HeaderValue::from_static("not-a-pubkey"),
        );
        assert_eq!(
            super::require_admin_pubkey(&enabled, &headers)
                .expect_err("invalid admin")
                .message(),
            "admin pubkey header is invalid"
        );
    }

    #[tokio::test]
    async fn admin_event_policy_routes_report_missing_events() {
        let store = runtime_memory_store().await;
        let (shutdown, _) = GracefulShutdownSignal::new();
        let state =
            super::RuntimeRelayState::new(runtime_admin_config("admin_missing"), store, shutdown);
        let missing = "1".repeat(EventId::HEX_LENGTH);
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-tangle-admin-pubkey",
            HeaderValue::from_str(FixtureKey::Relay.public_key().as_str()).expect("admin header"),
        );

        assert_eq!(
            super::runtime_admin_hide_event(
                axum::extract::State(state.clone()),
                headers.clone(),
                axum::extract::Path(missing.clone()),
                axum::Json(super::AdminEventPolicyRequest::default()),
            )
            .await
            .expect_err("hide missing")
            .message(),
            "event not found"
        );
        assert_eq!(
            super::runtime_admin_unhide_event(
                axum::extract::State(state),
                headers,
                axum::extract::Path(missing),
                axum::Json(super::AdminEventPolicyRequest::default()),
            )
            .await
            .expect_err("unhide missing")
            .message(),
            "event not found"
        );
    }

    #[tokio::test]
    async fn admin_policy_routes_reject_invalid_pubkey_paths() {
        let store = runtime_memory_store().await;
        let (shutdown, _) = GracefulShutdownSignal::new();
        let state = super::RuntimeRelayState::new(
            runtime_admin_config("admin_invalid_path"),
            store,
            shutdown,
        );
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-tangle-admin-pubkey",
            HeaderValue::from_str(FixtureKey::Relay.public_key().as_str()).expect("admin header"),
        );

        assert_eq!(
            super::runtime_admin_approve_seller(
                axum::extract::State(state.clone()),
                headers.clone(),
                axum::extract::Path("not-a-pubkey".to_owned()),
            )
            .await
            .expect_err("approve invalid")
            .message(),
            "pubkey must be a 64-character hex public key"
        );
        assert_eq!(
            super::runtime_admin_block_pubkey(
                axum::extract::State(state),
                headers,
                axum::extract::Path("not-a-pubkey".to_owned()),
            )
            .await
            .expect_err("block invalid")
            .message(),
            "pubkey must be a 64-character hex public key"
        );
    }

    #[test]
    fn relay_info_default_matches_production_v1_protocol_claims() {
        let relay_info = RelayInfoDocument::tangle_default();
        assert_eq!(relay_info.name, "tangle");
        assert_eq!(relay_info.supported_nips, TANGLE_SUPPORTED_NIPS);
        assert_eq!(relay_info.software, TANGLE_RELAY_SOFTWARE);
        assert_eq!(relay_info.version, "0.1.0");
        assert!(!relay_info.limitation.payment_required);
        assert!(relay_info.limitation.restricted_writes);
        assert_eq!(
            serde_json::to_value(relay_info).expect("json"),
            serde_json::json!({
                "name": "tangle",
                "description": "SurrealDB-backed Nostr relay for NIP-99 marketplaces",
                "supported_nips": [1, 9, 11, 16, 22, 23, 25, 32, 33, 42, 50, 56, 99],
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
                "supported_nips": [1, 9, 11, 16, 22, 23, 25, 32, 33, 42, 50, 56, 99],
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
            "category=vegetables,csa&category=roots&seller={seller}&status=active,sold,draft,inactive,expired,deleted,hidden,rejected&currency=usd,cad&unit=lb,oz,each,bunch,dozen,kg,g,share,pint,quart,box,crate,flat&min_price=1.50&max_price=10&fulfillment=pickup,delivery,shipping&delivery_only=false&pickup=true&geohash=C23NB62&lat=%2B47.6062&lon=-122.332100&radius_km=25.5&near=Ballard&sort=distance&limit=25"
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
        assert!(format!("{query:?}").contains("SearchDocumentQuery"));
    }

    #[test]
    fn marketplace_search_query_parser_rejects_invalid_parameters() {
        let seller = "1".repeat(64);
        let long_query = format!("q={}", "a".repeat(300));
        let cases = [
            ("q=".to_owned(), "q must not be empty"),
            ("q=carrot&q=roots".to_owned(), "q must not be repeated"),
            (
                format!("seller={seller}&seller={seller}"),
                "seller must not be repeated",
            ),
            (
                "status=active&status=active".to_owned(),
                "status must not be repeated",
            ),
            (
                "sort=freshness&sort=freshness".to_owned(),
                "sort must not be repeated",
            ),
            ("limit=1&limit=2".to_owned(), "limit must not be repeated"),
            (
                long_query,
                "runtime limit: search query bytes exceeded: 300 > 256",
            ),
            (
                "category=vegetables".to_owned(),
                "category is not supported by marketplace search",
            ),
            (
                "cursor=opaque".to_owned(),
                "cursor is not supported by marketplace search",
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
    fn projection_query_parsers_reject_cursor_and_unsupported_comment_parameters() {
        let seller = "1".repeat(PublicKeyHex::HEX_LENGTH);
        let cases = [
            (
                super::forum_thread_query("cursor=opaque").expect_err("forum cursor"),
                "cursor signed cursor decoding is not implemented",
            ),
            (
                super::forum_thread_query("banana=1").expect_err("forum unsupported"),
                "query parameter `banana` is unsupported",
            ),
            (
                super::label_projection_query("cursor=opaque").expect_err("label cursor"),
                "cursor signed cursor decoding is not implemented",
            ),
            (
                super::label_projection_query("target_type=event").expect_err("label target"),
                "target target_type and target_ref must be provided together",
            ),
            (
                super::label_projection_query("banana=1").expect_err("label unsupported"),
                "query parameter `banana` is unsupported",
            ),
            (
                super::report_projection_query("cursor=opaque").expect_err("report cursor"),
                "cursor signed cursor decoding is not implemented",
            ),
            (
                super::report_projection_query("target_ref=abc").expect_err("report target"),
                "target target_type and target_ref must be provided together",
            ),
            (
                super::report_projection_query("banana=1").expect_err("report unsupported"),
                "query parameter `banana` is unsupported",
            ),
            (
                super::parse_comment_query("cursor=opaque").expect_err("comment cursor"),
                "cursor is not supported by the listing comments endpoint",
            ),
        ];

        assert!(
            super::forum_thread_query(&format!("pubkey={seller}&topic=market&limit=2")).is_ok()
        );
        assert!(
            super::label_projection_query(&format!(
                "target_type=event&target_ref={}&namespace=ugc&label=approve&pubkey={seller}&limit=2",
                "2".repeat(EventId::HEX_LENGTH)
            ))
            .is_ok()
        );
        assert!(
            super::report_projection_query(&format!(
                "target_type=event&target_ref={}&report_type=spam&pubkey={seller}&limit=2",
                "2".repeat(EventId::HEX_LENGTH)
            ))
            .is_ok()
        );
        assert!(super::label_projection_query("=1").is_ok());
        assert!(super::report_projection_query("=1").is_ok());
        assert_eq!(super::parse_comment_query("=1").expect("empty key"), 50);

        for (error, expected) in cases {
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
        assert_eq!(
            super::price_minor_units("1.2.3")
                .expect_err("invalid price")
                .message(),
            "price must fit two decimal minor units"
        );
        assert_eq!(
            super::fulfillment_document(&serde_json::json!({
                "pickup_available": true,
                "delivery_available": false,
                "shipping_available": false
            }))
            .expect("fulfillment"),
            ["pickup".to_owned()]
        );
        assert_eq!(
            listing_item_document(&serde_json::json!({
                "listing_key": "30402:pubkey:listing-a",
                "event_id": "event",
                "seller_pubkey": "pubkey",
                "d": "listing-a",
                "title": "Carrot bunches",
                "summary": null,
                "geohash": null,
                "price_decimal": "12.50",
                "currency_norm": "USD",
                "unit": "lb",
                "effective_status": "active",
                "updated_at": 1714124433_u64,
                "pickup_available": false,
                "delivery_available": false,
                "shipping_available": false
            }))
            .expect("nullable listing")
            .fulfillment,
            Vec::<String>::new()
        );
    }

    #[test]
    fn read_model_document_helpers_reject_malformed_rows() {
        let malformed = serde_json::json!({"event_id": "event"});

        assert_eq!(
            super::forum_thread_item_document(&malformed)
                .expect_err("forum thread")
                .code(),
            ApiErrorCode::Internal
        );
        assert_eq!(
            super::comment_item_document(&malformed)
                .expect_err("comment")
                .code(),
            ApiErrorCode::Internal
        );
        assert_eq!(
            super::moderation_label_document(&malformed)
                .expect_err("label")
                .code(),
            ApiErrorCode::Internal
        );
        assert_eq!(
            super::moderation_report_document(&malformed)
                .expect_err("report")
                .code(),
            ApiErrorCode::Internal
        );
        assert_eq!(
            super::reaction_counts_document(
                Some(&serde_json::json!({
                    "target_event_id": "event",
                    "like_count": "bad"
                })),
                "event",
                Some("30402"),
            )
            .expect_err("reaction count")
            .code(),
            ApiErrorCode::Internal
        );
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
        let response = listings_router(ListingsHttpState::new(
            store.clone(),
            RuntimeLimits::default(),
        ))
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
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn listing_comments_endpoint_returns_visible_projected_comments() {
        let store = runtime_memory_store().await;
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
        let comment = listing_comment(&listing, 1_714_125_410, "Can I pickup Saturday?");
        store
            .project_current_listing(&listing, UnixTimestamp::new(1_714_125_409))
            .await
            .expect("project listing");
        store
            .project_comment(&comment, UnixTimestamp::new(1_714_125_411))
            .await
            .expect("project comment");

        let uri = format!(
            "/api/listings/{}/listing-a/comments?limit=5",
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
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("json"),
            serde_json::json!({
                "items": [{
                    "event_id": comment.id().as_str(),
                    "pubkey": FixtureKey::Buyer.public_key().as_str(),
                    "created_at": 1714125410_u64,
                    "content": "Can I pickup Saturday?",
                    "root": {
                        "target_type": "address",
                        "target_ref": listing_key,
                        "kind": "30402",
                        "author": listing.unsigned().pubkey().as_str()
                    },
                    "parent": {
                        "target_type": "address",
                        "target_ref": listing_key,
                        "kind": "30402",
                        "author": listing.unsigned().pubkey().as_str()
                    }
                }],
                "next_cursor": null
            })
        );

        store
            .database()
            .query("UPDATE comment_projection SET hidden = true WHERE event_id = $event_id;")
            .bind(("event_id", comment.id().as_str()))
            .await
            .expect("hide comment")
            .check()
            .expect("hide comment check");
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
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("json"),
            serde_json::json!({
                "items": [],
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
            .expect("hide listing check");
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
    }

    #[tokio::test]
    async fn listing_reactions_endpoint_returns_aggregate_counts() {
        let store = runtime_memory_store().await;
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let reaction = listing_reaction(&listing, 1_714_125_420, "+");
        store
            .project_current_listing(&listing, UnixTimestamp::new(1_714_125_419))
            .await
            .expect("project listing");

        let uri = format!(
            "/api/listings/{}/listing-a/reactions",
            listing.unsigned().pubkey().as_str()
        );
        let empty = listings_router(ListingsHttpState::new(
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
        assert_eq!(empty.status(), StatusCode::OK);
        let body = axum::body::to_bytes(empty.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("json"),
            serde_json::json!({
                "target_event_id": listing.id().as_str(),
                "target_kind": "30402",
                "like_count": 0,
                "dislike_count": 0,
                "emoji_count": 0,
                "text_count": 0,
                "total_count": 0,
                "updated_at": 0
            })
        );

        store
            .project_reaction(&reaction, UnixTimestamp::new(1_714_125_421))
            .await
            .expect("project reaction");
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
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("json"),
            serde_json::json!({
                "target_event_id": listing.id().as_str(),
                "target_kind": "30402",
                "like_count": 1,
                "dislike_count": 0,
                "emoji_count": 0,
                "text_count": 0,
                "total_count": 1,
                "updated_at": 1714125421
            })
        );
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
        store
            .database()
            .query("UPDATE listing_current SET hidden = true WHERE listing_key = $listing_key;")
            .bind(("listing_key", listing_key.as_str()))
            .await
            .expect("hide listing")
            .check()
            .expect("hide listing check");
        let response = listings_router(ListingsHttpState::new(store, RuntimeLimits::default()))
            .oneshot(
                Request::builder()
                    .uri(uri.as_str())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn forum_threads_endpoint_returns_visible_projected_threads() {
        let store = runtime_memory_store().await;
        let thread = forum_thread(1_714_125_430, Some("Market day thread"), &["Market", "CSA"]);
        store
            .project_forum_thread(&thread, UnixTimestamp::new(1_714_125_431))
            .await
            .expect("project thread");

        let response = listings_router(ListingsHttpState::new(
            store.clone(),
            RuntimeLimits::default(),
        ))
        .oneshot(
            Request::builder()
                .uri("/api/forum/threads?topic=market&limit=5")
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
                    "event_id": thread.id().as_str(),
                    "pubkey": FixtureKey::Buyer.public_key().as_str(),
                    "created_at": 1714125430_u64,
                    "updated_at": 1714125430_u64,
                    "title": "Market day thread",
                    "content": "What is everyone bringing this weekend?",
                    "tags": ["csa", "market"]
                }],
                "next_cursor": null
            })
        );

        store
            .database()
            .query("UPDATE forum_thread_projection SET hidden = true WHERE event_id = $event_id;")
            .bind(("event_id", thread.id().as_str()))
            .await
            .expect("hide thread")
            .check()
            .expect("hide thread check");
        let response = listings_router(ListingsHttpState::new(store, RuntimeLimits::default()))
            .oneshot(
                Request::builder()
                    .uri("/api/forum/threads?topic=market&limit=5")
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
    async fn forum_thread_detail_and_comments_endpoints_return_visible_rows() {
        let store = runtime_memory_store().await;
        let thread = forum_thread(1_714_125_440, Some("Market day thread"), &["market"]);
        let comment = forum_thread_comment(&thread, 1_714_125_441, "I can bring greens.");
        store
            .store_raw_event(&StoredEvent::new(
                thread.clone(),
                UnixTimestamp::new(1_714_125_442),
            ))
            .await
            .expect("raw thread");
        store
            .project_forum_thread(&thread, UnixTimestamp::new(1_714_125_443))
            .await
            .expect("project thread");
        store
            .project_comment(&comment, UnixTimestamp::new(1_714_125_444))
            .await
            .expect("project comment");

        let detail_uri = format!("/api/forum/threads/{}", thread.id().as_str());
        let response = listings_router(ListingsHttpState::new(
            store.clone(),
            RuntimeLimits::default(),
        ))
        .oneshot(
            Request::builder()
                .uri(detail_uri.as_str())
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let detail = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert_eq!(detail["thread"]["event_id"], thread.id().as_str());
        assert_eq!(detail["thread"]["title"], "Market day thread");
        assert_eq!(detail["raw_event"]["id"], thread.id().as_str());

        let comments_uri = format!(
            "/api/forum/threads/{}/comments?limit=5",
            thread.id().as_str()
        );
        let response = listings_router(ListingsHttpState::new(
            store.clone(),
            RuntimeLimits::default(),
        ))
        .oneshot(
            Request::builder()
                .uri(comments_uri.as_str())
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
                    "event_id": comment.id().as_str(),
                    "pubkey": FixtureKey::Seller.public_key().as_str(),
                    "created_at": 1714125441_u64,
                    "content": "I can bring greens.",
                    "root": {
                        "target_type": "event",
                        "target_ref": thread.id().as_str(),
                        "kind": "11",
                        "author": thread.unsigned().pubkey().as_str()
                    },
                    "parent": {
                        "target_type": "event",
                        "target_ref": thread.id().as_str(),
                        "kind": "11",
                        "author": thread.unsigned().pubkey().as_str()
                    }
                }],
                "next_cursor": null
            })
        );
        store
            .database()
            .query("UPDATE nostr_event SET hidden = true WHERE event_id = $event_id;")
            .bind(("event_id", thread.id().as_str()))
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
                .uri(detail_uri.as_str())
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
                 UPDATE forum_thread_projection SET hidden = true WHERE event_id = $event_id;",
            )
            .bind(("event_id", thread.id().as_str()))
            .await
            .expect("hide thread")
            .check()
            .expect("hide thread check");
        let detail = listings_router(ListingsHttpState::new(
            store.clone(),
            RuntimeLimits::default(),
        ))
        .oneshot(
            Request::builder()
                .uri(detail_uri.as_str())
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
        let comments = listings_router(ListingsHttpState::new(store, RuntimeLimits::default()))
            .oneshot(
                Request::builder()
                    .uri(comments_uri.as_str())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(detail.status(), StatusCode::NOT_FOUND);
        assert_eq!(comments.status(), StatusCode::NOT_FOUND);
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
        store
            .database()
            .query(
                "CREATE search_doc CONTENT {
                    doc_key: 'no-address',
                    event_id: 'no-address-event',
                    current_event_id: 'no-address-event',
                    doc_type: 'listing',
                    kind: 30402,
                    pubkey: $pubkey,
                    address_key: NONE,
                    title: 'carrot no address',
                    summary: NONE,
                    body: 'carrot',
                    category_text: 'carrot',
                    location_text: NONE,
                    tags: [],
                    categories: [],
                    created_at: 1,
                    updated_at: 1,
                    visible: true,
                    status: 'active',
                    seller_trust_score: NONE
                };
                CREATE search_doc CONTENT {
                    doc_key: 'orphan-address',
                    event_id: 'orphan-address-event',
                    current_event_id: 'orphan-address-event',
                    doc_type: 'listing',
                    kind: 30402,
                    pubkey: $pubkey,
                    address_key: '30402:orphan:missing',
                    title: 'carrot orphan',
                    summary: NONE,
                    body: 'carrot',
                    category_text: 'carrot',
                    location_text: NONE,
                    tags: [],
                    categories: [],
                    created_at: 2,
                    updated_at: 2,
                    visible: true,
                    status: 'active',
                    seller_trust_score: NONE
                };",
            )
            .bind(("pubkey", listing.unsigned().pubkey().as_str()))
            .await
            .expect("extra search docs")
            .check()
            .expect("extra search docs check");

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
        let profile = seller_profile(1_714_125_300, "radroots-market", Some("Radroots Market"));
        let seller = listing.unsigned().pubkey().as_str().to_owned();
        let listing_key = format!("30402:{seller}:listing-a");
        store
            .store_raw_event(&StoredEvent::new(
                profile.clone(),
                UnixTimestamp::new(1_714_125_301),
            ))
            .await
            .expect("store profile");
        store
            .project_seller_profile(&profile, UnixTimestamp::new(1_714_125_302))
            .await
            .expect("project profile");
        store
            .project_current_listing(&listing, UnixTimestamp::new(1_714_125_400))
            .await
            .expect("project listing");
        store
            .set_seller_approved(seller.as_str(), true, UnixTimestamp::new(2))
            .await
            .expect("seller row");

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
                "event_id": profile.id().as_str(),
                "name": "radroots-market",
                "display_name": "Radroots Market",
                "about": "Local food seller profile",
                "picture": "https://fixtures.radroots.test/seller.png",
                "website": "https://seller.radroots.test",
                "nip05": "seller@radroots.test",
                "lud16": "seller@pay.radroots.test",
                "regions": ["cascadia", "pnw"],
                "categories": ["produce"],
                "trust_markers": ["csa", "regenerative"],
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
            serde_json::from_slice::<serde_json::Value>(&body).expect("json")["active_listing_count"],
            0
        );

        let admin_pubkey = "a".repeat(PublicKeyHex::HEX_LENGTH);
        store
            .hide_event(
                profile.id(),
                "profile moderation",
                "admin_api",
                admin_pubkey.as_str(),
                UnixTimestamp::new(1_714_125_600),
            )
            .await
            .expect("hide profile");
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
        let document = serde_json::from_slice::<serde_json::Value>(&body).expect("json");
        assert!(document["event_id"].is_null());
        assert!(document["name"].is_null());
        assert_eq!(document["regions"], serde_json::json!([]));
        assert_eq!(document["approved"], true);
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
                "event_id": null,
                "name": null,
                "display_name": null,
                "about": null,
                "picture": null,
                "website": null,
                "nip05": null,
                "lud16": null,
                "regions": [],
                "categories": [],
                "trust_markers": [],
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

    fn runtime_memory_config(namespace: &str) -> super::TangleRuntimeConfig {
        parse_runtime_config_json(
            &serde_json::json!({
                "server": {
                    "listen_addr": "127.0.0.1:0",
                    "relay_url": "ws://127.0.0.1:0"
                },
                "database": {
                    "mode": "memory",
                    "namespace": namespace,
                    "database": "relay"
                },
                "auth": {
                    "challenge_ttl_seconds": 300
                },
                "limits": {
                    "message_rate_limit": {
                        "limit": 120,
                        "window_seconds": 60
                    }
                },
                "policy": {
                    "approved_sellers": [FixtureKey::Seller.public_key().as_str()]
                }
            })
            .to_string(),
        )
        .expect("runtime memory config")
    }

    fn runtime_admin_config(namespace: &str) -> super::TangleRuntimeConfig {
        parse_runtime_config_json(
            &serde_json::json!({
                "server": {
                    "listen_addr": "127.0.0.1:0",
                    "relay_url": "ws://127.0.0.1:0"
                },
                "database": {
                    "mode": "memory",
                    "namespace": namespace,
                    "database": "relay"
                },
                "auth": {
                    "challenge_ttl_seconds": 300
                },
                "limits": {
                    "message_rate_limit": {
                        "limit": 120,
                        "window_seconds": 60
                    }
                },
                "policy": {
                    "admin_pubkeys": [FixtureKey::Relay.public_key().as_str()],
                    "approved_sellers": [FixtureKey::Seller.public_key().as_str()]
                }
            })
            .to_string(),
        )
        .expect("runtime admin config")
    }

    fn seller_profile(
        created_at: u64,
        name: &str,
        display_name: Option<&str>,
    ) -> tangle_protocol::Event {
        let mut content = serde_json::json!({
            "name": name,
            "about": "Local food seller profile",
            "picture": "https://fixtures.radroots.test/seller.png",
            "website": "https://seller.radroots.test",
            "nip05": "seller@radroots.test",
            "lud16": "seller@pay.radroots.test"
        });
        if let Some(display_name) = display_name {
            content["display_name"] = serde_json::Value::String(display_name.to_owned());
        }
        build_fixture_event_from_parts(
            FixtureKey::Seller,
            created_at,
            u64::from(NIP01_METADATA_KIND),
            vec![
                vec!["region".to_owned(), "PNW".to_owned()],
                vec!["region".to_owned(), "Cascadia".to_owned()],
                vec!["category".to_owned(), "Produce".to_owned()],
                vec!["trust".to_owned(), "CSA".to_owned()],
                vec!["trust".to_owned(), "regenerative".to_owned()],
            ],
            &content.to_string(),
        )
        .expect("seller profile")
    }

    fn listing_event_at(created_at: u64) -> tangle_protocol::Event {
        let spec = valid_public_listing_spec();
        build_fixture_event_from_parts(
            FixtureKey::Seller,
            created_at,
            spec.kind(),
            spec.tags().to_vec(),
            spec.content(),
        )
        .expect("listing event")
    }

    fn note_event(created_at: u64, content: &str) -> tangle_protocol::Event {
        build_fixture_event_from_parts(FixtureKey::Seller, created_at, 1, Vec::new(), content)
            .expect("note event")
    }

    fn listing_comment(
        listing: &tangle_protocol::Event,
        created_at: u64,
        content: &str,
    ) -> tangle_protocol::Event {
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
        build_fixture_event_from_parts(
            FixtureKey::Buyer,
            created_at,
            1_111,
            vec![
                vec!["A".to_owned(), listing_key.clone()],
                vec!["K".to_owned(), "30402".to_owned()],
                vec![
                    "P".to_owned(),
                    listing.unsigned().pubkey().as_str().to_owned(),
                ],
                vec!["a".to_owned(), listing_key],
                vec!["k".to_owned(), "30402".to_owned()],
                vec![
                    "p".to_owned(),
                    listing.unsigned().pubkey().as_str().to_owned(),
                ],
            ],
            content,
        )
        .expect("comment event")
    }

    fn listing_reaction(
        listing: &tangle_protocol::Event,
        created_at: u64,
        content: &str,
    ) -> tangle_protocol::Event {
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
        build_fixture_event_from_parts(
            FixtureKey::Buyer,
            created_at,
            7,
            vec![
                vec![
                    "e".to_owned(),
                    listing.id().as_str().to_owned(),
                    "wss://relay.radroots.test".to_owned(),
                    listing.unsigned().pubkey().as_str().to_owned(),
                ],
                vec![
                    "p".to_owned(),
                    listing.unsigned().pubkey().as_str().to_owned(),
                ],
                vec!["a".to_owned(), listing_key],
                vec!["k".to_owned(), "30402".to_owned()],
            ],
            content,
        )
        .expect("reaction event")
    }

    fn forum_thread(
        created_at: u64,
        title: Option<&str>,
        topics: &[&str],
    ) -> tangle_protocol::Event {
        let mut tags = vec![
            vec!["e".to_owned(), "5".repeat(EventId::HEX_LENGTH)],
            vec![
                "p".to_owned(),
                FixtureKey::Seller.public_key().as_str().to_owned(),
            ],
        ];
        if let Some(title) = title {
            tags.push(vec!["title".to_owned(), title.to_owned()]);
        }
        tags.extend(
            topics
                .iter()
                .map(|topic| vec!["t".to_owned(), (*topic).to_owned()]),
        );
        build_fixture_event_from_parts(
            FixtureKey::Buyer,
            created_at,
            11,
            tags,
            "What is everyone bringing this weekend?",
        )
        .expect("forum thread")
    }

    fn forum_thread_comment(
        thread: &tangle_protocol::Event,
        created_at: u64,
        content: &str,
    ) -> tangle_protocol::Event {
        build_fixture_event_from_parts(
            FixtureKey::Seller,
            created_at,
            1_111,
            vec![
                vec![
                    "E".to_owned(),
                    thread.id().as_str().to_owned(),
                    "wss://relay.radroots.test".to_owned(),
                    thread.unsigned().pubkey().as_str().to_owned(),
                ],
                vec!["K".to_owned(), "11".to_owned()],
                vec![
                    "P".to_owned(),
                    thread.unsigned().pubkey().as_str().to_owned(),
                ],
                vec![
                    "e".to_owned(),
                    thread.id().as_str().to_owned(),
                    "wss://relay.radroots.test".to_owned(),
                    thread.unsigned().pubkey().as_str().to_owned(),
                ],
                vec!["k".to_owned(), "11".to_owned()],
                vec![
                    "p".to_owned(),
                    thread.unsigned().pubkey().as_str().to_owned(),
                ],
            ],
            content,
        )
        .expect("forum comment event")
    }

    async fn next_ws_json(
        client: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        phase: &'static str,
    ) -> serde_json::Value {
        loop {
            let message = tokio::time::timeout(std::time::Duration::from_secs(2), client.next())
                .await
                .expect(phase)
                .expect("websocket message")
                .expect("websocket frame");
            if let TungsteniteMessage::Text(raw) = message {
                return serde_json::from_str(&raw).expect("websocket JSON");
            }
        }
    }

    fn runtime_client_message_loop() -> ClientMessageLoop {
        let mut connection = runtime_connection("client-loop");
        connection.set_remote_addr("127.0.0.1:7777");
        ClientMessageLoop::new(connection)
    }

    fn runtime_connection(id: &str) -> RelayConnection {
        RelayConnection::new(
            RelayConnectionId::new(id).expect("connection id"),
            RelayConnectionConfig::default(),
        )
    }

    fn authenticated_connection() -> RelayConnection {
        let mut connection = runtime_connection("authenticated");
        let auth = build_fixture_event(&auth_event_spec()).expect("auth");
        connection
            .auth_mut()
            .issue_challenge("challenge-001", UnixTimestamp::new(1_714_124_430))
            .expect("challenge");
        let auth = parse_relay_auth_event(&auth)
            .expect("auth parses")
            .expect("auth event");
        connection
            .auth_mut()
            .authenticate(&auth, UnixTimestamp::new(1_714_124_435))
            .expect("authenticate");
        connection
    }
}
