#![forbid(unsafe_code)]

#[cfg(test)]
use crate::relay::outbound::protocol_messages_for_test;
use crate::{
    client_message::RuntimeClientMessage,
    config::BaseRelayRuntimeConfig,
    errors::BaseRelayError,
    event_bus::{TangleEventBus, TangleEventReceiver},
    groups::GroupServiceHandle,
    logging,
    ops::{BaseRelayReadinessHandle, BaseRelayReadinessState},
    pocket_event_validation::{pocket_event_id, pocket_event_kind, pocket_event_pubkey},
    rate_limits::{
        TangleQueryRateLimitConfig, TangleRateLimitDecision, TangleRateLimitKey,
        TangleRateLimitQueryClass, TangleRateLimitRule, TangleRateLimitScope, TangleRateLimiter,
    },
    relay::{
        auth::BaseAuthState,
        core::{
            BaseRelay, BaseRelayCountQuery, BaseRelayCountReport, BaseRelayEventWrite,
            BaseRelayFilterLimitMode, BaseRelayLimits, BaseRelayQueryMetrics, BaseRelayQueryReport,
            BaseRelayReqQuery, BaseRelayShutdownReport, matched_filter_context,
        },
        filter::{BaseRelayMatchedFilterContext, BaseRelayRequestedKinds},
        live::LiveSubscriptionSet,
        outbound::{RuntimeRelayMessage, protocol_control_messages},
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fmt, fs,
    net::IpAddr,
    num::NonZeroU32,
    path::Path,
    str,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Instant,
};
use tangle_groups::{
    GroupAuthContext, GroupEventClass, GroupId, KIND_GROUP_JOIN_REQUEST, StoreOffset,
    validate_client_group_event_structure,
};
use tangle_protocol::{Kind, PublicKeyHex, RelayMessage, SubscriptionId, UnixTimestamp};
use tangle_store_pocket::{
    PocketEvent, PocketFilter, PocketOwnedEvent, PocketOwnedFilter, PocketStoreHandle, PocketTime,
};
use tokio::sync::watch;

pub struct RelayRuntime {
    config: BaseRelayRuntimeConfig,
    relay: BaseRelay,
    readiness: BaseRelayReadinessHandle,
    limits: TangleRuntimeLimits,
    event_bus: TangleEventBus,
    rate_limiter: TangleRateLimiter,
    metrics: TangleRuntimeMetrics,
    shutdown: TangleShutdownSignal,
    hooks: Arc<dyn RelayRuntimeHooks>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TangleClientRateLimitContext {
    peer_ip: Option<IpAddr>,
    connection_id: Option<u64>,
}

impl TangleClientRateLimitContext {
    pub fn new(peer_ip: Option<IpAddr>, connection_id: Option<u64>) -> Self {
        Self {
            peer_ip,
            connection_id,
        }
    }

    pub fn peer_ip(self) -> Option<IpAddr> {
        self.peer_ip
    }

    pub fn connection_id(self) -> Option<u64> {
        self.connection_id
    }
}

pub trait RelayRuntimeHooks: Send + Sync {
    fn admit_event(&self, _context: &RelayEventAdmissionContext) -> EventAdmissionDecision {
        EventAdmissionDecision::Accept
    }

    fn event_stored(&self, _context: &RelayEventStoredContext) {}

    fn storage_used_bytes(&self) -> Option<u64> {
        None
    }

    fn plan_query(&self, _context: &RelayQueryProjectionContext) -> RelayProjectionQueryPlan {
        RelayProjectionQueryPlan::default()
    }

    fn live_projection_candidates(
        &self,
        _context: &RelayLiveProjectionContext,
    ) -> Vec<RelayLiveProjectionCandidate> {
        Vec::new()
    }

    fn project_event(
        &self,
        _context: &RelayEventProjectionContext,
    ) -> RelayEventProjectionDecision {
        RelayEventProjectionDecision::Emit
    }

    fn sanitize_public_message(&self, message: RelayMessage) -> RelayMessage {
        message
    }
}

#[derive(Debug, Default)]
pub struct NoopRelayRuntimeHooks;

impl RelayRuntimeHooks for NoopRelayRuntimeHooks {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventAdmissionDecision {
    Accept,
    Reject { message: String },
}

impl EventAdmissionDecision {
    pub fn reject(message: impl Into<String>) -> Self {
        Self::Reject {
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayProjectionContext {
    identifier: Option<String>,
}

impl RelayProjectionContext {
    pub fn named(identifier: impl Into<String>) -> Result<Self, BaseRelayError> {
        let identifier = identifier.into();
        if identifier.is_empty() {
            return Err(BaseRelayError::invalid(
                "relay projection identifier must not be empty",
            ));
        }
        if identifier.chars().any(char::is_control) {
            return Err(BaseRelayError::invalid(
                "relay projection identifier must not contain control characters",
            ));
        }
        Ok(Self {
            identifier: Some(identifier),
        })
    }

    pub fn identifier(&self) -> Option<&str> {
        self.identifier.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEventProjectionSource {
    HistoricalQuery,
    LiveFanout { store_offset: u64 },
}

impl RelayEventProjectionSource {
    pub fn store_offset(self) -> Option<u64> {
        match self {
            Self::HistoricalQuery => None,
            Self::LiveFanout { store_offset } => Some(store_offset),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEventProjectionDecision {
    Emit,
    Suppress,
    ReplaceWithStoredOffset { store_offset: u64 },
}

impl RelayEventProjectionDecision {
    pub fn replace_with_stored_offset(store_offset: u64) -> Self {
        Self::ReplaceWithStoredOffset { store_offset }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayProjectionQueryPlan {
    limit: RelayProjectionQueryLimit,
}

impl RelayProjectionQueryPlan {
    pub fn limit_after_projection(candidate_limit: NonZeroU32) -> Self {
        Self {
            limit: RelayProjectionQueryLimit::AfterProjection { candidate_limit },
        }
    }

    pub fn limit(&self) -> RelayProjectionQueryLimit {
        self.limit
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RelayProjectionQueryLimit {
    #[default]
    BeforeProjection,
    AfterProjection {
        candidate_limit: NonZeroU32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayQueryProjectionContext {
    subscription_id: SubscriptionId,
    projection: RelayProjectionContext,
    filters: Vec<RelayMatchedFilterContext>,
    authenticated_pubkeys: Vec<PublicKeyHex>,
}

impl RelayQueryProjectionContext {
    pub fn new(
        subscription_id: SubscriptionId,
        projection: RelayProjectionContext,
        filters: Vec<RelayMatchedFilterContext>,
    ) -> Self {
        Self::new_with_authenticated_pubkeys(subscription_id, projection, filters, Vec::new())
    }

    pub fn new_with_authenticated_pubkeys(
        subscription_id: SubscriptionId,
        projection: RelayProjectionContext,
        filters: Vec<RelayMatchedFilterContext>,
        authenticated_pubkeys: Vec<PublicKeyHex>,
    ) -> Self {
        Self {
            subscription_id,
            projection,
            filters,
            authenticated_pubkeys,
        }
    }

    pub fn subscription_id(&self) -> &SubscriptionId {
        &self.subscription_id
    }

    pub fn projection(&self) -> &RelayProjectionContext {
        &self.projection
    }

    pub fn filters(&self) -> &[RelayMatchedFilterContext] {
        &self.filters
    }

    pub fn authenticated_pubkeys(&self) -> &[PublicKeyHex] {
        &self.authenticated_pubkeys
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayMatchedFilterContext {
    filter_index: usize,
    requested_kinds: RelayRequestedKinds,
}

impl RelayMatchedFilterContext {
    fn from_base(context: &BaseRelayMatchedFilterContext) -> Self {
        let requested_kinds = match context.requested_kinds() {
            BaseRelayRequestedKinds::Absent => RelayRequestedKinds::Absent,
            BaseRelayRequestedKinds::Explicit(kinds) => {
                RelayRequestedKinds::Explicit(kinds.clone())
            }
        };
        Self {
            filter_index: context.filter_index(),
            requested_kinds,
        }
    }

    pub fn filter_index(&self) -> usize {
        self.filter_index
    }

    pub fn requested_kinds(&self) -> &RelayRequestedKinds {
        &self.requested_kinds
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayRequestedKinds {
    Absent,
    Explicit(BTreeSet<u32>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLiveProjectionContext {
    projection: RelayProjectionContext,
    source_store_offset: u64,
    event: RelayEventContext,
    authenticated_pubkeys: Vec<PublicKeyHex>,
}

impl RelayLiveProjectionContext {
    pub fn new(
        projection: RelayProjectionContext,
        source_store_offset: u64,
        event: RelayEventContext,
    ) -> Self {
        Self::new_with_authenticated_pubkeys(projection, source_store_offset, event, Vec::new())
    }

    pub fn new_with_authenticated_pubkeys(
        projection: RelayProjectionContext,
        source_store_offset: u64,
        event: RelayEventContext,
        authenticated_pubkeys: Vec<PublicKeyHex>,
    ) -> Self {
        Self {
            projection,
            source_store_offset,
            event,
            authenticated_pubkeys,
        }
    }

    pub fn projection(&self) -> &RelayProjectionContext {
        &self.projection
    }

    pub fn source_store_offset(&self) -> u64 {
        self.source_store_offset
    }

    pub fn event(&self) -> &RelayEventContext {
        &self.event
    }

    pub fn authenticated_pubkeys(&self) -> &[PublicKeyHex] {
        &self.authenticated_pubkeys
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLiveProjectionCandidate {
    store_offset: u64,
}

impl RelayLiveProjectionCandidate {
    pub fn stored_offset(store_offset: u64) -> Self {
        Self { store_offset }
    }

    pub fn store_offset(self) -> u64 {
        self.store_offset
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEventContext {
    event_id: String,
    pubkey: String,
    created_at: u64,
    kind: u32,
    tags: Vec<Vec<String>>,
    content: String,
}

impl RelayEventContext {
    pub fn new(
        event_id: String,
        pubkey: String,
        created_at: u64,
        kind: u32,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Self {
        Self {
            event_id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
        }
    }

    fn from_pocket_event(event: &PocketEvent) -> Result<Self, BaseRelayError> {
        let tags = event
            .tags()
            .map_err(|error| BaseRelayError::invalid(error.to_string()))?
            .iter()
            .map(|tag| {
                tag.map(|value| {
                    str::from_utf8(value)
                        .map(str::to_owned)
                        .map_err(|error| BaseRelayError::invalid(error.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let content = str::from_utf8(event.content())
            .map(str::to_owned)
            .map_err(|error| BaseRelayError::invalid(error.to_string()))?;
        Ok(Self {
            event_id: event.id().to_string(),
            pubkey: event.pubkey().to_string(),
            created_at: event.created_at().as_u64(),
            kind: u32::from(event.kind().as_u16()),
            tags,
            content,
        })
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn pubkey(&self) -> &str {
        &self.pubkey
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    pub fn kind(&self) -> u32 {
        self.kind
    }

    pub fn tags(&self) -> &[Vec<String>] {
        &self.tags
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    pub fn has_tag(&self, name: &str, value: &str) -> bool {
        self.tags.iter().any(|tag| {
            tag.first().is_some_and(|tag_name| tag_name == name)
                && tag.iter().skip(1).any(|tag_value| tag_value == value)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEventAdmissionContext {
    event: RelayEventContext,
    authenticated_pubkeys: Vec<String>,
    peer_ip: Option<IpAddr>,
    connection_id: Option<u64>,
    now: u64,
}

impl RelayEventAdmissionContext {
    pub fn new(
        event: RelayEventContext,
        authenticated_pubkeys: Vec<String>,
        peer_ip: Option<IpAddr>,
        connection_id: Option<u64>,
        now: u64,
    ) -> Self {
        Self {
            event,
            authenticated_pubkeys,
            peer_ip,
            connection_id,
            now,
        }
    }

    pub fn event(&self) -> &RelayEventContext {
        &self.event
    }

    pub fn authenticated_pubkeys(&self) -> &[String] {
        &self.authenticated_pubkeys
    }

    pub fn peer_ip(&self) -> Option<IpAddr> {
        self.peer_ip
    }

    pub fn connection_id(&self) -> Option<u64> {
        self.connection_id
    }

    pub fn now(&self) -> u64 {
        self.now
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEventStoredContext {
    event: RelayEventContext,
    store_offsets: Vec<u64>,
}

struct RelayEventProjectionRequest<'a> {
    subscription_id: &'a SubscriptionId,
    projection: &'a RelayProjectionContext,
    source: RelayEventProjectionSource,
    event: &'a PocketEvent,
    auth: &'a BaseAuthState,
    matched_filters: Vec<(BaseRelayMatchedFilterContext, &'a PocketFilter)>,
}

struct RelayLiveProjectionDelivery<'a> {
    subscriptions: &'a LiveSubscriptionSet,
    auth: &'a BaseAuthState,
    projection: &'a RelayProjectionContext,
    group_auth: &'a GroupAuthContext,
    delivered: &'a mut BTreeSet<(SubscriptionId, String)>,
    messages: &'a mut Vec<RuntimeRelayMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEventProjectionContext {
    subscription_id: SubscriptionId,
    projection: RelayProjectionContext,
    source: RelayEventProjectionSource,
    matched_filters: Vec<RelayMatchedFilterContext>,
    event: RelayEventContext,
    authenticated_pubkeys: Vec<PublicKeyHex>,
}

impl RelayEventProjectionContext {
    pub fn new(
        subscription_id: SubscriptionId,
        projection: RelayProjectionContext,
        source: RelayEventProjectionSource,
        matched_filter: RelayMatchedFilterContext,
        event: RelayEventContext,
    ) -> Self {
        Self::new_with_authenticated_pubkeys(
            subscription_id,
            projection,
            source,
            matched_filter,
            event,
            Vec::new(),
        )
    }

    pub fn new_with_authenticated_pubkeys(
        subscription_id: SubscriptionId,
        projection: RelayProjectionContext,
        source: RelayEventProjectionSource,
        matched_filter: RelayMatchedFilterContext,
        event: RelayEventContext,
        authenticated_pubkeys: Vec<PublicKeyHex>,
    ) -> Self {
        Self::new_with_matched_filters_and_authenticated_pubkeys(
            subscription_id,
            projection,
            source,
            vec![matched_filter],
            event,
            authenticated_pubkeys,
        )
    }

    pub fn new_with_matched_filters(
        subscription_id: SubscriptionId,
        projection: RelayProjectionContext,
        source: RelayEventProjectionSource,
        matched_filters: Vec<RelayMatchedFilterContext>,
        event: RelayEventContext,
    ) -> Self {
        Self::new_with_matched_filters_and_authenticated_pubkeys(
            subscription_id,
            projection,
            source,
            matched_filters,
            event,
            Vec::new(),
        )
    }

    pub fn new_with_matched_filters_and_authenticated_pubkeys(
        subscription_id: SubscriptionId,
        projection: RelayProjectionContext,
        source: RelayEventProjectionSource,
        matched_filters: Vec<RelayMatchedFilterContext>,
        event: RelayEventContext,
        authenticated_pubkeys: Vec<PublicKeyHex>,
    ) -> Self {
        Self {
            subscription_id,
            projection,
            source,
            matched_filters,
            event,
            authenticated_pubkeys,
        }
    }

    pub fn subscription_id(&self) -> &SubscriptionId {
        &self.subscription_id
    }

    pub fn projection(&self) -> &RelayProjectionContext {
        &self.projection
    }

    pub fn source(&self) -> RelayEventProjectionSource {
        self.source
    }

    pub fn matched_filter(&self) -> &RelayMatchedFilterContext {
        self.matched_filters
            .first()
            .expect("projection context must include at least one matched filter")
    }

    pub fn matched_filters(&self) -> &[RelayMatchedFilterContext] {
        &self.matched_filters
    }

    pub fn event(&self) -> &RelayEventContext {
        &self.event
    }

    pub fn authenticated_pubkeys(&self) -> &[PublicKeyHex] {
        &self.authenticated_pubkeys
    }
}

impl RelayEventStoredContext {
    pub fn new(event: RelayEventContext, store_offsets: Vec<u64>) -> Self {
        Self {
            event,
            store_offsets,
        }
    }

    pub fn event(&self) -> &RelayEventContext {
        &self.event
    }

    pub fn store_offsets(&self) -> &[u64] {
        &self.store_offsets
    }
}

struct TanglePocketQueryRateLimitRequest<'a> {
    scope: TangleRateLimitScope,
    rules: TangleQueryRateLimitConfig,
    label: &'static str,
    subscription_id: &'a SubscriptionId,
    filters: &'a [PocketOwnedFilter],
    auth: &'a BaseAuthState,
    context: TangleClientRateLimitContext,
    now: UnixTimestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TangleQueryClassification {
    Bounded,
    Broad(TangleBroadQueryReason),
}

impl TangleQueryClassification {
    fn is_broad(self) -> bool {
        matches!(self, Self::Broad(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TangleBroadQueryReason {
    EmptyFilters,
    MissingPrimaryConstraint,
    MissingBoundedSelector,
    HighLimit,
    BroadTimeWindow,
}

#[derive(Debug, Clone, Copy)]
struct TangleQueryClassifier {
    limits: BaseRelayLimits,
}

const BROAD_QUERY_TIME_WINDOW_SECONDS: u64 = 31 * 24 * 60 * 60;

impl TangleQueryClassifier {
    fn new(limits: BaseRelayLimits) -> Self {
        Self { limits }
    }

    fn classify_pocket_query(self, filters: &[PocketOwnedFilter]) -> TangleQueryClassification {
        if filters.is_empty() {
            return TangleQueryClassification::Broad(TangleBroadQueryReason::EmptyFilters);
        }
        filters
            .iter()
            .map(|filter| self.classify_pocket_query_filter(filter))
            .find(|classification| classification.is_broad())
            .unwrap_or(TangleQueryClassification::Bounded)
    }

    fn classify_pocket_count(self, filters: &[PocketOwnedFilter]) -> TangleQueryClassification {
        if filters.is_empty() {
            return TangleQueryClassification::Broad(TangleBroadQueryReason::EmptyFilters);
        }
        filters
            .iter()
            .map(|filter| self.classify_pocket_count_filter(filter))
            .find(|classification| classification.is_broad())
            .unwrap_or(TangleQueryClassification::Bounded)
    }

    fn classify_pocket_query_filter(self, filter: &PocketFilter) -> TangleQueryClassification {
        if !self.has_pocket_primary_constraint(filter) {
            return TangleQueryClassification::Broad(
                TangleBroadQueryReason::MissingPrimaryConstraint,
            );
        }
        if self.has_pocket_high_limit(filter) {
            return TangleQueryClassification::Broad(TangleBroadQueryReason::HighLimit);
        }
        if self.has_pocket_broad_time_window(filter) && !self.has_pocket_strong_constraint(filter) {
            return TangleQueryClassification::Broad(TangleBroadQueryReason::BroadTimeWindow);
        }
        TangleQueryClassification::Bounded
    }

    fn classify_pocket_count_filter(self, filter: &PocketFilter) -> TangleQueryClassification {
        if !self.has_pocket_primary_constraint(filter) {
            return TangleQueryClassification::Broad(
                TangleBroadQueryReason::MissingPrimaryConstraint,
            );
        }
        if self.has_pocket_high_limit(filter) {
            return TangleQueryClassification::Broad(TangleBroadQueryReason::HighLimit);
        }
        if self.has_pocket_broad_time_window(filter) {
            return TangleQueryClassification::Broad(TangleBroadQueryReason::BroadTimeWindow);
        }
        if !self.has_pocket_count_bounded_selector(filter) {
            return TangleQueryClassification::Broad(
                TangleBroadQueryReason::MissingBoundedSelector,
            );
        }
        TangleQueryClassification::Bounded
    }

    fn has_pocket_primary_constraint(self, filter: &PocketFilter) -> bool {
        filter.num_ids() > 0
            || filter.num_authors() > 0
            || filter.num_kinds() > 0
            || self.has_pocket_group_constraint(filter)
    }

    fn has_pocket_strong_constraint(self, filter: &PocketFilter) -> bool {
        filter.num_ids() > 0 || filter.num_authors() > 0 || self.has_pocket_group_constraint(filter)
    }

    fn has_pocket_count_bounded_selector(self, filter: &PocketFilter) -> bool {
        self.has_pocket_strong_constraint(filter)
            || (filter.num_kinds() > 0 && self.has_pocket_bounded_time_window(filter))
            || self.has_pocket_hll_count_selector(filter)
    }

    fn has_pocket_hll_count_selector(self, filter: &PocketFilter) -> bool {
        filter
            .hyperloglog_offset()
            .is_ok_and(|offset| offset.is_some())
    }

    fn has_pocket_group_constraint(self, filter: &PocketFilter) -> bool {
        filter
            .tags()
            .map(|tags| {
                tags.iter().any(|mut tag| {
                    let name = tag.next();
                    let has_value = tag.next().is_some();
                    matches!(name, Some(value) if matches!(value, b"h" | b"d")) && has_value
                })
            })
            .unwrap_or(false)
    }

    fn has_pocket_high_limit(self, filter: &PocketFilter) -> bool {
        let limit = if filter.limit() == u32::MAX {
            self.limits.default_limit()
        } else {
            u64::from(filter.limit())
        };
        limit >= self.limits.max_limit()
    }

    fn has_pocket_bounded_time_window(self, filter: &PocketFilter) -> bool {
        if filter.since() == PocketTime::min() || filter.until() == PocketTime::max() {
            return false;
        }
        filter
            .until()
            .as_ref()
            .saturating_sub(*filter.since().as_ref())
            <= BROAD_QUERY_TIME_WINDOW_SECONDS
    }

    fn has_pocket_broad_time_window(self, filter: &PocketFilter) -> bool {
        if filter.since() == PocketTime::min() || filter.until() == PocketTime::max() {
            return false;
        }
        filter
            .until()
            .as_ref()
            .saturating_sub(*filter.since().as_ref())
            > BROAD_QUERY_TIME_WINDOW_SECONDS
    }
}

impl RelayRuntime {
    pub fn open(config: BaseRelayRuntimeConfig) -> Result<Self, BaseRelayError> {
        Self::open_with_hooks(config, Arc::new(NoopRelayRuntimeHooks))
    }

    pub fn open_with_hooks(
        config: BaseRelayRuntimeConfig,
        hooks: Arc<dyn RelayRuntimeHooks>,
    ) -> Result<Self, BaseRelayError> {
        let limits = TangleRuntimeLimits::from_config(&config)?;
        let relay = config.open_relay()?;
        let readiness = BaseRelayReadinessHandle::new(relay.readiness_state());
        let event_bus = TangleEventBus::new(limits.event_bus_capacity())?;
        let rate_limiter = TangleRateLimiter::new();
        let metrics = TangleRuntimeMetrics::new();
        metrics.record_disk_used_bytes(directory_size_bytes(
            config.pocket_config().data_directory(),
        ));
        metrics.record_event_bus_receivers(event_bus.receiver_count());
        metrics.record_outbox_pending_events(relay.group_outbox_pending_events());
        logging::log_runtime_opened(&config);
        Ok(Self {
            config,
            relay,
            readiness,
            event_bus,
            rate_limiter,
            metrics,
            limits,
            shutdown: TangleShutdownSignal::new(),
            hooks,
        })
    }

    pub fn config(&self) -> &BaseRelayRuntimeConfig {
        &self.config
    }

    pub fn relay(&self) -> &BaseRelay {
        &self.relay
    }

    pub fn relay_mut(&mut self) -> &mut BaseRelay {
        &mut self.relay
    }

    pub fn auth_state(&self) -> Result<BaseAuthState, BaseRelayError> {
        self.config.auth_state()
    }

    pub fn readiness_state(&self) -> BaseRelayReadinessState {
        self.readiness.snapshot()
    }

    pub fn readiness_handle(&self) -> BaseRelayReadinessHandle {
        self.readiness.clone()
    }

    pub fn limits(&self) -> TangleRuntimeLimits {
        self.limits
    }

    pub fn event_bus(&self) -> &TangleEventBus {
        &self.event_bus
    }

    pub fn rate_limiter(&self) -> &TangleRateLimiter {
        &self.rate_limiter
    }

    pub fn metrics(&self) -> &TangleRuntimeMetrics {
        &self.metrics
    }

    pub fn shutdown_signal(&self) -> &TangleShutdownSignal {
        &self.shutdown
    }

    pub fn shutdown(&mut self) -> Result<BaseRelayShutdownReport, BaseRelayError> {
        self.shutdown.request_shutdown();
        self.relay.shutdown()
    }
}

struct RelayRuntimeShared {
    config: Arc<BaseRelayRuntimeConfig>,
    store: PocketStoreHandle,
    groups: Option<GroupServiceHandle>,
    readiness: BaseRelayReadinessHandle,
    limits: TangleRuntimeLimits,
    event_bus: TangleEventBus,
    rate_limiter: TangleRateLimiter,
    metrics: TangleRuntimeMetrics,
    shutdown: TangleShutdownSignal,
    hooks: Arc<dyn RelayRuntimeHooks>,
}

impl RelayRuntimeShared {
    fn from_runtime(runtime: RelayRuntime) -> Self {
        let RelayRuntime {
            config,
            relay,
            readiness,
            limits,
            event_bus,
            rate_limiter,
            metrics,
            shutdown,
            hooks,
        } = runtime;
        let store = relay.store_handle();
        let groups = relay.group_service_handle();
        Self {
            config: Arc::new(config),
            store,
            groups,
            readiness,
            limits,
            event_bus,
            rate_limiter,
            metrics,
            shutdown,
            hooks,
        }
    }

    fn rate_limit_event_pocket(
        &self,
        event: &PocketEvent,
        context: TangleClientRateLimitContext,
        now: UnixTimestamp,
    ) -> Result<Option<RelayMessage>, BaseRelayError> {
        let rules = self.config.rate_limits().event();
        if let Some(peer_ip) = context.peer_ip
            && let Some(message) = self.rate_limit_ok_pocket(
                event,
                TangleRateLimitKey::ip(TangleRateLimitScope::Event, peer_ip),
                rules.per_ip(),
                "event ip",
                now,
            )?
        {
            return Ok(Some(message));
        }
        self.rate_limit_ok_pocket(
            event,
            TangleRateLimitKey::pubkey(TangleRateLimitScope::Event, pocket_event_pubkey(event)?),
            rules.per_pubkey(),
            "event pubkey",
            now,
        )
        .and_then(|message| {
            if message.is_some() {
                return Ok(message);
            }
            self.rate_limit_ok_pocket(
                event,
                TangleRateLimitKey::kind(TangleRateLimitScope::Event, pocket_event_kind(event)?),
                rules.per_kind(),
                "event kind",
                now,
            )
        })
    }

    fn rate_limit_auth_attempt_pocket(
        &self,
        event: &PocketEvent,
        context: TangleClientRateLimitContext,
        now: UnixTimestamp,
    ) -> Result<Option<RelayMessage>, BaseRelayError> {
        let rules = self.config.rate_limits().auth();
        if let Some(peer_ip) = context.peer_ip
            && let Some(message) = self.rate_limit_ok_pocket(
                event,
                TangleRateLimitKey::ip(TangleRateLimitScope::Auth, peer_ip),
                rules.per_ip(),
                "auth ip",
                now,
            )?
        {
            return Ok(Some(message));
        }
        self.rate_limit_ok_pocket(
            event,
            TangleRateLimitKey::pubkey(TangleRateLimitScope::Auth, pocket_event_pubkey(event)?),
            rules.per_pubkey(),
            "auth pubkey",
            now,
        )
    }

    fn rate_limit_auth_failure_pocket(
        &self,
        event: &PocketEvent,
        context: TangleClientRateLimitContext,
        now: UnixTimestamp,
    ) -> Result<Option<RelayMessage>, BaseRelayError> {
        let rules = self.config.rate_limits().auth();
        if let Some(peer_ip) = context.peer_ip
            && let Some(message) = self.rate_limit_ok_pocket(
                event,
                TangleRateLimitKey::auth_failure(Some(peer_ip), None),
                rules.failures_per_ip(),
                "auth failure ip",
                now,
            )?
        {
            return Ok(Some(message));
        }
        self.rate_limit_ok_pocket(
            event,
            TangleRateLimitKey::auth_failure(None, Some(pocket_event_pubkey(event)?)),
            rules.failures(),
            "auth failure",
            now,
        )
    }

    fn rate_limit_group_write_pocket(
        &self,
        event: &PocketEvent,
        context: TangleClientRateLimitContext,
        now: UnixTimestamp,
    ) -> Result<Option<RelayMessage>, BaseRelayError> {
        if !self.config.groups().enabled() {
            return Ok(None);
        }
        let class =
            validate_client_group_event_structure(event, self.config.groups().limits()).ok();
        let Some(class) = class else {
            return Ok(None);
        };
        let Some(group_id) = class.group_id().cloned() else {
            return Ok(None);
        };
        let rules = self.config.rate_limits().group();
        let kind = pocket_event_kind(event)?;
        let pubkey = pocket_event_pubkey(event)?;
        if kind.as_u32() == KIND_GROUP_JOIN_REQUEST {
            if let Some(peer_ip) = context.peer_ip
                && let Some(message) = self.rate_limit_ok_pocket(
                    event,
                    TangleRateLimitKey::join_flow_ip(group_id.clone(), peer_ip),
                    rules.join_flow_per_ip(),
                    "group join ip",
                    now,
                )?
            {
                return Ok(Some(message));
            }
            if let Some(message) = self.rate_limit_ok_pocket(
                event,
                TangleRateLimitKey::join_flow(group_id.clone(), pubkey.clone()),
                rules.join_flow(),
                "group join",
                now,
            )? {
                return Ok(Some(message));
            }
        }
        if let Some(peer_ip) = context.peer_ip
            && let Some(message) = self.rate_limit_ok_pocket(
                event,
                TangleRateLimitKey::ip(TangleRateLimitScope::GroupWrite, peer_ip),
                rules.write_per_ip(),
                "group ip",
                now,
            )?
        {
            return Ok(Some(message));
        }
        if let Some(message) = self.rate_limit_ok_pocket(
            event,
            TangleRateLimitKey::pubkey(TangleRateLimitScope::GroupWrite, pubkey),
            rules.write_per_pubkey(),
            "group pubkey",
            now,
        )? {
            return Ok(Some(message));
        }
        if let Some(message) = self.rate_limit_ok_pocket(
            event,
            TangleRateLimitKey::group(TangleRateLimitScope::GroupWrite, group_id),
            rules.write_per_group(),
            "group write",
            now,
        )? {
            return Ok(Some(message));
        }
        self.rate_limit_ok_pocket(
            event,
            TangleRateLimitKey::kind(TangleRateLimitScope::GroupWrite, kind),
            rules.write_per_kind(),
            "group kind",
            now,
        )
    }

    fn is_group_event_pocket(&self, event: &PocketEvent) -> bool {
        self.config.groups().enabled()
            && validate_client_group_event_structure(event, self.config.groups().limits())
                .is_ok_and(|class| !matches!(class, GroupEventClass::NonGroup))
    }

    fn handle_pocket_event_with_auth_report(
        &self,
        event: &PocketEvent,
        auth: &BaseAuthState,
    ) -> Result<BaseRelayEventWrite, BaseRelayError> {
        BaseRelay::handle_pocket_event_with_shared_services(
            &self.store,
            self.groups.as_ref(),
            self.limits.base_relay_limits(),
            event,
            auth,
        )
    }

    fn group_outbox_pending_events(&self) -> usize {
        self.groups
            .as_ref()
            .map(GroupServiceHandle::outbox_pending_events)
            .unwrap_or(0)
    }

    fn query_req_with_auth_report(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<PocketOwnedFilter>,
        search_present: bool,
        auth: &BaseAuthState,
    ) -> Result<BaseRelayQueryReport, BaseRelayError> {
        BaseRelay::query_req_with_shared_services(
            &self.store,
            self.groups.as_ref(),
            self.limits.base_relay_limits(),
            self.config.pocket_query_config(),
            BaseRelayReqQuery::new(subscription_id, filters, search_present, auth),
        )
    }

    fn project_query_report(
        &self,
        report: BaseRelayQueryReport,
        filters: &[PocketOwnedFilter],
        projection: &RelayProjectionContext,
        auth: &BaseAuthState,
    ) -> Result<BaseRelayQueryReport, BaseRelayError> {
        let group_read_denied = report.group_read_denied();
        let query_metrics = report.query_metrics();
        let messages =
            self.project_runtime_messages(report.into_messages(), filters, projection, auth)?;
        let returned_events = messages
            .iter()
            .filter(|message| matches!(message, RuntimeRelayMessage::Event { .. }))
            .count();
        let query_metrics = query_metrics.with_returned_events(returned_events);
        Ok(BaseRelayQueryReport::new(
            messages,
            group_read_denied,
            query_metrics,
        ))
    }

    fn project_runtime_messages(
        &self,
        messages: Vec<RuntimeRelayMessage>,
        filters: &[PocketOwnedFilter],
        projection: &RelayProjectionContext,
        auth: &BaseAuthState,
    ) -> Result<Vec<RuntimeRelayMessage>, BaseRelayError> {
        let mut output = Vec::with_capacity(messages.len());
        let mut event_ids = BTreeSet::new();
        for message in messages {
            match message {
                RuntimeRelayMessage::Event {
                    subscription_id,
                    event,
                } => {
                    let matched_filters = self.matched_filters_for_event(filters, &event)?;
                    if let Some(projected) =
                        self.project_event_output(RelayEventProjectionRequest {
                            subscription_id: &subscription_id,
                            projection,
                            source: RelayEventProjectionSource::HistoricalQuery,
                            event: &event,
                            auth,
                            matched_filters,
                        })?
                        && event_ids.insert(projected.id())
                    {
                        output.push(RuntimeRelayMessage::event(subscription_id, projected));
                    }
                }
                message => output.push(message),
            }
        }
        Ok(output)
    }

    fn project_event_output(
        &self,
        request: RelayEventProjectionRequest<'_>,
    ) -> Result<Option<PocketOwnedEvent>, BaseRelayError> {
        let RelayEventProjectionRequest {
            subscription_id,
            projection,
            source,
            event,
            auth,
            matched_filters,
        } = request;
        let context =
            RelayEventProjectionContext::new_with_matched_filters_and_authenticated_pubkeys(
                subscription_id.clone(),
                projection.clone(),
                source,
                matched_filters
                    .iter()
                    .map(|(matched_filter, _)| RelayMatchedFilterContext::from_base(matched_filter))
                    .collect(),
                RelayEventContext::from_pocket_event(event)?,
                auth.authenticated_pubkeys().iter().cloned().collect(),
            );
        match self.hooks.project_event(&context) {
            RelayEventProjectionDecision::Emit => Ok(Some(event.to_owned())),
            RelayEventProjectionDecision::Suppress => Ok(None),
            RelayEventProjectionDecision::ReplaceWithStoredOffset { store_offset } => {
                let Ok(replacement) = self.store.event_by_offset(store_offset) else {
                    return Ok(None);
                };
                let group_auth =
                    GroupAuthContext::new(auth.authenticated_pubkeys().iter().cloned());
                if BaseRelay::group_read_gate_visible_to_auth(
                    self.groups.as_ref(),
                    &replacement,
                    &group_auth,
                )? && matched_filters
                    .iter()
                    .try_fold(false, |matched, (_, filter)| {
                        if matched {
                            return Ok(true);
                        }
                        filter
                            .event_matches(&replacement)
                            .map_err(|error| BaseRelayError::error(error.to_string()))
                    })?
                {
                    Ok(Some(replacement))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn matched_filters_for_event<'a>(
        &self,
        filters: &'a [PocketOwnedFilter],
        event: &PocketEvent,
    ) -> Result<Vec<(BaseRelayMatchedFilterContext, &'a PocketFilter)>, BaseRelayError> {
        let mut matched_filters = Vec::new();
        for (filter_index, filter) in filters.iter().enumerate() {
            if filter
                .event_matches(event)
                .map_err(|error| BaseRelayError::error(error.to_string()))?
            {
                let filter: &PocketFilter = filter;
                matched_filters.push((matched_filter_context(filter_index, filter), filter));
            }
        }
        if matched_filters.is_empty() {
            return Err(BaseRelayError::error(
                "query output did not match any request filter",
            ));
        }
        Ok(matched_filters)
    }

    fn query_projected_req_with_auth_report(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<PocketOwnedFilter>,
        search_present: bool,
        auth: &BaseAuthState,
        projection: &RelayProjectionContext,
        candidate_limit: NonZeroU32,
    ) -> Result<BaseRelayQueryReport, BaseRelayError> {
        self.limits
            .base_relay_limits()
            .validate_subscription_id(&subscription_id)?;
        self.limits
            .base_relay_limits()
            .validate_pocket_filters(&filters)?;
        if let Some(message) =
            BaseRelay::unsupported_search_present_closed(&subscription_id, search_present)
        {
            return Ok(BaseRelayQueryReport::new(
                vec![message.into()],
                false,
                BaseRelayQueryMetrics::default(),
            ));
        }
        let group_auth = GroupAuthContext::new(auth.authenticated_pubkeys().iter().cloned());
        let mut output = Vec::new();
        let mut group_read_denied = false;
        let mut query_metrics = BaseRelayQueryMetrics::default();
        for filter in &filters {
            let report = BaseRelay::query_filter_events_report_with_services(
                &self.store,
                self.groups.as_ref(),
                self.limits.base_relay_limits(),
                self.config.pocket_query_config(),
                filter,
                &group_auth,
                BaseRelayFilterLimitMode::Override(candidate_limit.get()),
            )?;
            group_read_denied |= report.group_read_denied();
            query_metrics = query_metrics.add(report.query_metrics());
            let events = BaseRelay::sort_and_dedupe_query_events(report.into_events());
            let mut projected = Vec::new();
            for event in events {
                let matched_filters = self.matched_filters_for_event(&filters, &event)?;
                if let Some(event) = self.project_event_output(RelayEventProjectionRequest {
                    subscription_id: &subscription_id,
                    projection,
                    source: RelayEventProjectionSource::HistoricalQuery,
                    event: &event,
                    auth,
                    matched_filters,
                })? {
                    projected.push(event);
                }
            }
            let mut projected = BaseRelay::sort_and_dedupe_query_events(projected);
            projected.truncate(
                self.limits
                    .base_relay_limits()
                    .effective_pocket_filter_limit_for_query(filter),
            );
            output.extend(projected);
        }
        let events = BaseRelay::sort_and_dedupe_query_events(output);
        let query_metrics = query_metrics.with_returned_events(events.len());
        let mut messages = events
            .into_iter()
            .map(|event| RuntimeRelayMessage::event(subscription_id.clone(), event))
            .collect::<Vec<_>>();
        if group_read_denied {
            let group_auth = GroupAuthContext::new(auth.authenticated_pubkeys().iter().cloned());
            messages.push(BaseRelay::redacted_req_closed(subscription_id, &group_auth).into());
        } else {
            messages.push(RelayMessage::Eose(subscription_id).into());
        }
        Ok(BaseRelayQueryReport::new(
            messages,
            group_read_denied,
            query_metrics,
        ))
    }

    fn handle_count_with_auth_report(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<PocketOwnedFilter>,
        search_present: bool,
        auth: &BaseAuthState,
    ) -> Result<BaseRelayCountReport, BaseRelayError> {
        BaseRelay::handle_count_with_shared_services(
            &self.store,
            self.groups.as_ref(),
            self.limits.base_relay_limits(),
            self.config.pocket_query_config(),
            BaseRelayCountQuery::new(subscription_id, filters, search_present, auth),
        )
    }

    fn rate_limit_req_pocket(
        &self,
        subscription_id: &SubscriptionId,
        filters: &[PocketOwnedFilter],
        auth: &BaseAuthState,
        context: TangleClientRateLimitContext,
        now: UnixTimestamp,
    ) -> Option<RelayMessage> {
        self.rate_limit_pocket_query(TanglePocketQueryRateLimitRequest {
            scope: TangleRateLimitScope::Req,
            rules: self.config.rate_limits().req(),
            label: "req",
            subscription_id,
            filters,
            auth,
            context,
            now,
        })
    }

    fn rate_limit_count_pocket(
        &self,
        subscription_id: &SubscriptionId,
        filters: &[PocketOwnedFilter],
        auth: &BaseAuthState,
        context: TangleClientRateLimitContext,
        now: UnixTimestamp,
    ) -> Option<RelayMessage> {
        self.rate_limit_pocket_query(TanglePocketQueryRateLimitRequest {
            scope: TangleRateLimitScope::Count,
            rules: self.config.rate_limits().count(),
            label: "count",
            subscription_id,
            filters,
            auth,
            context,
            now,
        })
    }

    fn refuse_broad_count(
        &self,
        subscription_id: &SubscriptionId,
        filters: &[PocketOwnedFilter],
    ) -> Option<RelayMessage> {
        if TangleQueryClassifier::new(self.limits.base_relay_limits())
            .classify_pocket_count(filters)
            .is_broad()
        {
            self.metrics.record_count_refusal();
            self.metrics.record_broad_query_rejection();
            return Some(RelayMessage::Closed {
                subscription_id: subscription_id.clone(),
                message: BaseRelayError::restricted("count filters are too broad or expensive")
                    .prefixed_message(),
            });
        }
        None
    }

    fn rate_limit_pocket_query(
        &self,
        request: TanglePocketQueryRateLimitRequest<'_>,
    ) -> Option<RelayMessage> {
        if let Some(peer_ip) = request.context.peer_ip
            && let Some(message) = self.rate_limit_closed(
                request.subscription_id,
                TangleRateLimitKey::ip(request.scope, peer_ip),
                request.rules.per_ip(),
                request.label,
                "ip",
                request.now,
            )
        {
            return Some(message);
        }
        if let Some(connection_id) = request.context.connection_id
            && let Some(message) = self.rate_limit_closed(
                request.subscription_id,
                TangleRateLimitKey::connection(request.scope, connection_id),
                request.rules.per_connection(),
                request.label,
                "connection",
                request.now,
            )
        {
            return Some(message);
        }
        for pubkey in request.auth.authenticated_pubkeys() {
            if let Some(message) = self.rate_limit_closed(
                request.subscription_id,
                TangleRateLimitKey::pubkey(request.scope, pubkey.clone()),
                request.rules.per_pubkey(),
                request.label,
                "pubkey",
                request.now,
            ) {
                return Some(message);
            }
        }
        for group_id in pocket_filter_group_ids(request.filters) {
            if let Some(message) = self.rate_limit_closed(
                request.subscription_id,
                TangleRateLimitKey::group(request.scope, group_id),
                request.rules.per_group(),
                request.label,
                "group",
                request.now,
            ) {
                return Some(message);
            }
        }
        for kind in pocket_filter_kinds(request.filters) {
            if let Some(message) = self.rate_limit_closed(
                request.subscription_id,
                TangleRateLimitKey::kind(request.scope, kind),
                request.rules.per_kind(),
                request.label,
                "kind",
                request.now,
            ) {
                return Some(message);
            }
        }
        let classifier = TangleQueryClassifier::new(self.limits.base_relay_limits());
        let query_classification = match request.scope {
            TangleRateLimitScope::Req => classifier.classify_pocket_query(request.filters),
            TangleRateLimitScope::Count => classifier.classify_pocket_count(request.filters),
            TangleRateLimitScope::Auth
            | TangleRateLimitScope::Event
            | TangleRateLimitScope::GroupWrite => classifier.classify_pocket_query(request.filters),
        };
        if query_classification.is_broad()
            && let Some(message) = self.rate_limit_closed(
                request.subscription_id,
                TangleRateLimitKey::query_class(request.scope, TangleRateLimitQueryClass::Broad),
                request.rules.broad(),
                request.label,
                "broad",
                request.now,
            )
        {
            self.metrics.record_broad_query_rejection();
            return Some(message);
        }
        None
    }

    fn rate_limit_closed(
        &self,
        subscription_id: &SubscriptionId,
        key: TangleRateLimitKey,
        rule: TangleRateLimitRule,
        label: &'static str,
        dimension: &'static str,
        now: UnixTimestamp,
    ) -> Option<RelayMessage> {
        match self.rate_limiter.record(key, rule, now) {
            TangleRateLimitDecision::Allowed { .. } => None,
            TangleRateLimitDecision::Rejected { reset_at } => {
                self.metrics.record_rate_limit_rejection();
                logging::log_rate_limit_rejected(label, dimension, reset_at);
                Some(RelayMessage::Closed {
                    subscription_id: subscription_id.clone(),
                    message: BaseRelayError::rate_limited(format!(
                        "{label} {dimension} rate limit exceeded until {reset_at}"
                    ))
                    .prefixed_message(),
                })
            }
        }
    }

    fn rate_limit_ok_pocket(
        &self,
        event: &PocketEvent,
        key: TangleRateLimitKey,
        rule: TangleRateLimitRule,
        label: &'static str,
        now: UnixTimestamp,
    ) -> Result<Option<RelayMessage>, BaseRelayError> {
        Ok(match self.rate_limiter.record(key, rule, now) {
            TangleRateLimitDecision::Allowed { .. } => None,
            TangleRateLimitDecision::Rejected { reset_at } => {
                self.metrics.record_rate_limit_rejection();
                logging::log_rate_limit_rejected(label, "event", reset_at);
                Some(RelayMessage::Ok {
                    event_id: pocket_event_id(event)?,
                    accepted: false,
                    message: BaseRelayError::rate_limited(format!(
                        "{label} rate limit exceeded until {reset_at}"
                    ))
                    .prefixed_message(),
                })
            }
        })
    }
}

#[derive(Clone)]
pub struct RelayRuntimeHandle {
    inner: Arc<RelayRuntimeShared>,
}

impl RelayRuntimeHandle {
    pub fn new(runtime: RelayRuntime) -> Self {
        Self {
            inner: Arc::new(RelayRuntimeShared::from_runtime(runtime)),
        }
    }

    pub fn metrics(&self) -> TangleRuntimeMetrics {
        self.inner.metrics.clone()
    }

    pub fn readiness_handle(&self) -> BaseRelayReadinessHandle {
        self.inner.readiness.clone()
    }

    pub(crate) fn sanitize_public_message(
        &self,
        message: RuntimeRelayMessage,
    ) -> RuntimeRelayMessage {
        message.map_protocol(|message| self.inner.hooks.sanitize_public_message(message))
    }

    pub fn limits(&self) -> TangleRuntimeLimits {
        self.inner.limits
    }

    pub async fn auth_state(&self) -> Result<BaseAuthState, BaseRelayError> {
        self.inner.config.auth_state()
    }

    pub async fn handle_count_pocket(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<PocketOwnedFilter>,
        auth: &mut BaseAuthState,
        now: UnixTimestamp,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        let messages = self
            .handle_client_message_with_rate_limit_context(
                RuntimeClientMessage::Count {
                    subscription_id,
                    filters,
                    search_present: false,
                },
                auth,
                TangleClientRateLimitContext::default(),
                now,
            )
            .await?;
        protocol_control_messages(messages)
    }

    #[cfg(test)]
    pub(crate) async fn handle_client_message(
        &self,
        message: RuntimeClientMessage,
        auth: &mut BaseAuthState,
        now: UnixTimestamp,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        let messages = self
            .handle_client_message_with_rate_limit_context(
                message,
                auth,
                TangleClientRateLimitContext::default(),
                now,
            )
            .await?;
        protocol_messages_for_test(messages)
    }

    #[cfg(test)]
    pub(crate) async fn handle_protocol_client_message_for_test(
        &self,
        message: tangle_protocol::ClientMessage,
        auth: &mut BaseAuthState,
        now: UnixTimestamp,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        self.handle_client_message(
            protocol_client_message_to_runtime_for_test(message)?,
            auth,
            now,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn handle_protocol_client_message_with_rate_limit_context_for_test(
        &self,
        message: tangle_protocol::ClientMessage,
        auth: &mut BaseAuthState,
        rate_limit_context: TangleClientRateLimitContext,
        now: UnixTimestamp,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        let messages = self
            .handle_client_message_with_rate_limit_context(
                protocol_client_message_to_runtime_for_test(message)?,
                auth,
                rate_limit_context,
                now,
            )
            .await?;
        protocol_messages_for_test(messages)
    }

    pub(crate) async fn handle_client_message_with_rate_limit_context(
        &self,
        message: RuntimeClientMessage,
        auth: &mut BaseAuthState,
        rate_limit_context: TangleClientRateLimitContext,
        now: UnixTimestamp,
    ) -> Result<Vec<RuntimeRelayMessage>, BaseRelayError> {
        self.inner
            .metrics
            .record_client_message(runtime_client_message_metric_kind(&message));
        match message {
            RuntimeClientMessage::Event(pocket_event) => {
                let started_at = Instant::now();
                let event_id = pocket_event_id(&pocket_event)?;
                let event_context = RelayEventContext::from_pocket_event(&pocket_event)?;
                let is_group_event = self.inner.is_group_event_pocket(&pocket_event);
                if let Some(message) =
                    self.inner
                        .rate_limit_event_pocket(&pocket_event, rate_limit_context, now)?
                {
                    record_event_metrics(&self.inner.metrics, &message, is_group_event, started_at);
                    return Ok(vec![message.into()]);
                }
                if let Some(message) = self.inner.rate_limit_group_write_pocket(
                    &pocket_event,
                    rate_limit_context,
                    now,
                )? {
                    record_event_metrics(&self.inner.metrics, &message, is_group_event, started_at);
                    return Ok(vec![message.into()]);
                }
                let authenticated_pubkeys = auth
                    .authenticated_pubkeys()
                    .iter()
                    .map(ToString::to_string)
                    .collect();
                let admission = RelayEventAdmissionContext::new(
                    event_context.clone(),
                    authenticated_pubkeys,
                    rate_limit_context.peer_ip(),
                    rate_limit_context.connection_id(),
                    now.as_u64(),
                );
                let admission_decision = self.inner.hooks.admit_event(&admission);
                if let Some(used_bytes) = self.inner.hooks.storage_used_bytes() {
                    self.inner.metrics.record_disk_used_bytes(used_bytes);
                }
                if let EventAdmissionDecision::Reject { message } = admission_decision {
                    let message = RelayMessage::Ok {
                        event_id,
                        accepted: false,
                        message: BaseRelayError::restricted(message).prefixed_message(),
                    };
                    record_event_metrics(&self.inner.metrics, &message, is_group_event, started_at);
                    return Ok(vec![message.into()]);
                }
                let result = self
                    .inner
                    .handle_pocket_event_with_auth_report(&pocket_event, auth)?;
                let group_outbox_pending_events =
                    is_group_event.then(|| self.inner.group_outbox_pending_events());
                if is_group_event {
                    for _ in 0..result.stored_offsets().len().saturating_sub(1) {
                        self.inner.metrics.record_outbox_replayed_event();
                    }
                    self.inner
                        .metrics
                        .record_outbox_pending_events(group_outbox_pending_events.unwrap_or(0));
                }
                if !result.stored_offsets().is_empty() {
                    logging::log_event_stored(
                        &event_id,
                        result.stored_offsets().len(),
                        self.inner.metrics.stored_event_offsets(),
                    );
                    self.inner.hooks.event_stored(&RelayEventStoredContext::new(
                        event_context,
                        result
                            .stored_offsets()
                            .iter()
                            .map(|offset| offset.as_u64())
                            .collect(),
                    ));
                    if let Some(used_bytes) = self.inner.hooks.storage_used_bytes() {
                        self.inner.metrics.record_disk_used_bytes(used_bytes);
                    }
                }
                for offset in result.stored_offsets() {
                    self.inner.metrics.record_stored_event_offset();
                    let receivers = self.inner.event_bus.publish(*offset);
                    self.inner.metrics.record_event_bus_publish(receivers);
                }
                let message = result.into_message();
                record_event_metrics(&self.inner.metrics, &message, is_group_event, started_at);
                Ok(vec![message.into()])
            }
            RuntimeClientMessage::Req {
                subscription_id,
                filters,
                search_present,
            } => {
                let started_at = Instant::now();
                self.inner
                    .limits
                    .base_relay_limits()
                    .validate_subscription_id(&subscription_id)?;
                self.inner
                    .limits
                    .base_relay_limits()
                    .validate_pocket_filters(&filters)?;
                if let Some(message) =
                    BaseRelay::unsupported_search_present_closed(&subscription_id, search_present)
                {
                    self.inner
                        .metrics
                        .record_query_latency(elapsed_micros(started_at));
                    return Ok(vec![message.into()]);
                }
                if let Some(message) = self.inner.rate_limit_req_pocket(
                    &subscription_id,
                    &filters,
                    auth,
                    rate_limit_context,
                    now,
                ) {
                    self.inner
                        .metrics
                        .record_query_latency(elapsed_micros(started_at));
                    return Ok(vec![message.into()]);
                }
                let report = self.inner.query_req_with_auth_report(
                    subscription_id,
                    filters.clone(),
                    search_present,
                    auth,
                )?;
                let report = self.inner.project_query_report(
                    report,
                    &filters,
                    &RelayProjectionContext::default(),
                    auth,
                )?;
                self.inner
                    .metrics
                    .record_query_metrics(report.query_metrics());
                if report.group_read_denied() {
                    self.inner.metrics.record_group_read_denial();
                }
                self.inner
                    .metrics
                    .record_query_latency(elapsed_micros(started_at));
                Ok(report.into_messages())
            }
            RuntimeClientMessage::Count {
                subscription_id,
                filters,
                search_present,
            } => {
                let started_at = Instant::now();
                self.inner
                    .limits
                    .base_relay_limits()
                    .validate_subscription_id(&subscription_id)?;
                self.inner
                    .limits
                    .base_relay_limits()
                    .validate_pocket_filters(&filters)?;
                if let Some(message) =
                    BaseRelay::unsupported_search_present_closed(&subscription_id, search_present)
                {
                    self.inner
                        .metrics
                        .record_query_latency(elapsed_micros(started_at));
                    return Ok(vec![message.into()]);
                }
                if let Some(message) = self.inner.refuse_broad_count(&subscription_id, &filters) {
                    self.inner
                        .metrics
                        .record_query_latency(elapsed_micros(started_at));
                    return Ok(vec![message.into()]);
                }
                if let Some(message) = self.inner.rate_limit_count_pocket(
                    &subscription_id,
                    &filters,
                    auth,
                    rate_limit_context,
                    now,
                ) {
                    self.inner
                        .metrics
                        .record_query_latency(elapsed_micros(started_at));
                    return Ok(vec![message.into()]);
                }
                let report = self.inner.handle_count_with_auth_report(
                    subscription_id,
                    filters,
                    search_present,
                    auth,
                )?;
                self.inner
                    .metrics
                    .record_query_metrics(report.query_metrics());
                if report.group_read_denied() {
                    self.inner.metrics.record_group_read_denial();
                }
                self.inner
                    .metrics
                    .record_query_latency(elapsed_micros(started_at));
                Ok(vec![report.into_message().into()])
            }
            RuntimeClientMessage::Auth(pocket_event) => {
                let event_id = pocket_event_id(&pocket_event)?;
                if let Err(error) = self
                    .inner
                    .limits
                    .base_relay_limits()
                    .validate_pocket_event(&pocket_event)
                {
                    self.inner.metrics.record_auth_failure();
                    return Ok(vec![RuntimeRelayMessage::from(RelayMessage::Ok {
                        event_id,
                        accepted: false,
                        message: error.prefixed_message(),
                    })]);
                }
                if let Some(message) = self.inner.rate_limit_auth_attempt_pocket(
                    &pocket_event,
                    rate_limit_context,
                    now,
                )? {
                    self.inner.metrics.record_auth_failure();
                    return Ok(vec![message.into()]);
                }
                let event_for_failure = pocket_event.clone();
                let replies = BaseRelay::handle_pocket_auth_with_limits(
                    self.inner.limits.base_relay_limits(),
                    &pocket_event,
                    auth,
                    now,
                );
                if auth_response_failed(&replies) {
                    self.inner.metrics.record_auth_failure();
                    if let Some(message) = self.inner.rate_limit_auth_failure_pocket(
                        &event_for_failure,
                        rate_limit_context,
                        now,
                    )? {
                        return Ok(vec![message.into()]);
                    }
                } else {
                    self.inner.metrics.record_auth_success();
                }
                Ok(replies.into_iter().map(Into::into).collect())
            }
            RuntimeClientMessage::Close(subscription_id) => {
                self.inner
                    .limits
                    .base_relay_limits()
                    .validate_subscription_id(&subscription_id)?;
                Ok(Vec::new())
            }
            RuntimeClientMessage::NegOpen {
                subscription_id, ..
            }
            | RuntimeClientMessage::NegMsg {
                subscription_id, ..
            } => {
                self.inner
                    .limits
                    .base_relay_limits()
                    .validate_subscription_id(&subscription_id)?;
                Ok(vec![
                    BaseRelay::disabled_negentropy_message(subscription_id).into(),
                ])
            }
            RuntimeClientMessage::NegClose(subscription_id) => {
                self.inner
                    .limits
                    .base_relay_limits()
                    .validate_subscription_id(&subscription_id)?;
                Ok(Vec::new())
            }
        }
    }

    pub async fn subscribe_events(&self) -> TangleEventReceiver {
        let receiver = self.inner.event_bus.subscribe();
        self.inner
            .metrics
            .record_event_bus_receivers(self.inner.event_bus.receiver_count());
        receiver
    }

    pub async fn rate_limiter(&self) -> TangleRateLimiter {
        self.inner.rate_limiter.clone()
    }

    pub(crate) async fn rate_limit_req_pocket(
        &self,
        subscription_id: &SubscriptionId,
        filters: &[PocketOwnedFilter],
        auth: &BaseAuthState,
        rate_limit_context: TangleClientRateLimitContext,
        now: UnixTimestamp,
    ) -> Option<RelayMessage> {
        self.inner
            .rate_limit_req_pocket(subscription_id, filters, auth, rate_limit_context, now)
    }

    pub(crate) async fn query_req_with_auth_report_with_projection_context(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<PocketOwnedFilter>,
        search_present: bool,
        auth: &BaseAuthState,
        projection: &RelayProjectionContext,
    ) -> Result<BaseRelayQueryReport, BaseRelayError> {
        let started_at = Instant::now();
        let context = RelayQueryProjectionContext::new_with_authenticated_pubkeys(
            subscription_id.clone(),
            projection.clone(),
            filters
                .iter()
                .enumerate()
                .map(|(index, filter)| {
                    RelayMatchedFilterContext::from_base(&matched_filter_context(index, filter))
                })
                .collect(),
            auth.authenticated_pubkeys().iter().cloned().collect(),
        );
        let plan = self.inner.hooks.plan_query(&context);
        let report = match plan.limit() {
            RelayProjectionQueryLimit::BeforeProjection => {
                let report = self.inner.query_req_with_auth_report(
                    subscription_id,
                    filters.clone(),
                    search_present,
                    auth,
                )?;
                self.inner
                    .project_query_report(report, &filters, projection, auth)?
            }
            RelayProjectionQueryLimit::AfterProjection { candidate_limit } => {
                self.inner.query_projected_req_with_auth_report(
                    subscription_id,
                    filters,
                    search_present,
                    auth,
                    projection,
                    candidate_limit,
                )?
            }
        };
        if report.group_read_denied() {
            self.inner.metrics.record_group_read_denial();
        }
        self.inner
            .metrics
            .record_query_latency(elapsed_micros(started_at));
        Ok(report)
    }

    pub async fn event_by_offset_with_auth(
        &self,
        offset: StoreOffset,
        auth: &BaseAuthState,
    ) -> Result<Option<PocketOwnedEvent>, BaseRelayError> {
        let pocket_event = self.inner.store.event_by_offset(offset.as_u64())?;
        let group_auth = GroupAuthContext::new(auth.authenticated_pubkeys().iter().cloned());
        let visible = BaseRelay::group_read_gate_visible_to_auth(
            self.inner.groups.as_ref(),
            &pocket_event,
            &group_auth,
        )?;
        if !visible {
            self.inner.metrics.record_group_read_denial();
            return Ok(None);
        }
        Ok(Some(pocket_event))
    }

    pub(crate) async fn fanout_event_offset_with_projection_context(
        &self,
        offset: StoreOffset,
        subscriptions: &mut LiveSubscriptionSet,
        auth: &BaseAuthState,
        projection: &RelayProjectionContext,
    ) -> Result<Vec<RuntimeRelayMessage>, BaseRelayError> {
        let pocket_event = self.inner.store.event_by_offset(offset.as_u64())?;
        let group_auth = GroupAuthContext::new(auth.authenticated_pubkeys().iter().cloned());
        let mut messages = Vec::new();
        let mut delivered = BTreeSet::new();
        let mut delivery = RelayLiveProjectionDelivery {
            subscriptions,
            auth,
            projection,
            group_auth: &group_auth,
            delivered: &mut delivered,
            messages: &mut messages,
        };
        self.fanout_projected_live_event(&pocket_event, offset.as_u64(), &mut delivery)?;
        let context = RelayLiveProjectionContext::new_with_authenticated_pubkeys(
            projection.clone(),
            offset.as_u64(),
            RelayEventContext::from_pocket_event(&pocket_event)?,
            auth.authenticated_pubkeys().iter().cloned().collect(),
        );
        for candidate in self.inner.hooks.live_projection_candidates(&context) {
            let Ok(candidate_event) = self.inner.store.event_by_offset(candidate.store_offset())
            else {
                continue;
            };
            self.fanout_projected_live_event(
                &candidate_event,
                candidate.store_offset(),
                &mut delivery,
            )?;
        }
        Ok(messages)
    }

    fn fanout_projected_live_event(
        &self,
        event: &PocketEvent,
        store_offset: u64,
        delivery: &mut RelayLiveProjectionDelivery<'_>,
    ) -> Result<(), BaseRelayError> {
        let subscriptions =
            delivery
                .subscriptions
                .fanout(event, delivery.group_auth, |event, auth| {
                    BaseRelay::group_read_gate_visible_to_auth(
                        self.inner.groups.as_ref(),
                        event,
                        auth,
                    )
                    .unwrap_or(false)
                })?;
        for matched in subscriptions {
            let subscription_id = matched.subscription_id().clone();
            if let Some(projected) =
                self.inner
                    .project_event_output(RelayEventProjectionRequest {
                        subscription_id: matched.subscription_id(),
                        projection: delivery.projection,
                        source: RelayEventProjectionSource::LiveFanout { store_offset },
                        event,
                        auth: delivery.auth,
                        matched_filters: matched
                            .matched_filter_contexts()
                            .into_iter()
                            .zip(matched.filters())
                            .collect(),
                    })?
            {
                let event_id = projected.id().as_hex_string();
                if delivery
                    .delivered
                    .insert((subscription_id.clone(), event_id))
                {
                    delivery
                        .messages
                        .push(RuntimeRelayMessage::event(subscription_id, projected));
                }
            }
        }
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<BaseRelayShutdownReport, BaseRelayError> {
        self.inner.shutdown.request_shutdown();
        self.inner.store.sync()?;
        Ok(BaseRelayShutdownReport::new(0))
    }
}

fn auth_response_failed(replies: &[RelayMessage]) -> bool {
    replies.iter().any(|reply| {
        matches!(
            reply,
            RelayMessage::Ok {
                accepted: false,
                ..
            }
        )
    })
}

fn record_event_metrics(
    metrics: &TangleRuntimeMetrics,
    message: &RelayMessage,
    is_group_event: bool,
    started_at: Instant,
) {
    metrics.record_event_admission_latency(elapsed_micros(started_at));
    if let RelayMessage::Ok { accepted, .. } = message {
        if *accepted {
            metrics.record_event_admission();
        } else {
            metrics.record_event_rejection();
            if is_group_event {
                metrics.record_group_write_denial();
            }
        }
    }
}

fn elapsed_micros(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn directory_size_bytes(path: &Path) -> u64 {
    let Ok(metadata) = fs::metadata(path) else {
        return 0;
    };
    if metadata.is_file() {
        return metadata.len();
    }
    if !metadata.is_dir() {
        return 0;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| directory_size_bytes(&entry.path()))
        .sum()
}

#[cfg(test)]
fn protocol_client_message_to_runtime_for_test(
    message: tangle_protocol::ClientMessage,
) -> Result<RuntimeClientMessage, BaseRelayError> {
    match message {
        tangle_protocol::ClientMessage::Event(event) => Ok(RuntimeClientMessage::Event(
            crate::pocket_conversion::tangle_event_to_pocket(&event)?,
        )),
        tangle_protocol::ClientMessage::Req {
            subscription_id,
            filters,
        } => Ok(RuntimeClientMessage::Req {
            subscription_id,
            search_present: filters.iter().any(|filter| filter.search().is_some()),
            filters: filters
                .iter()
                .map(crate::pocket_conversion::tangle_filter_to_pocket)
                .collect::<Result<Vec<_>, _>>()?,
        }),
        tangle_protocol::ClientMessage::Count {
            subscription_id,
            filters,
        } => Ok(RuntimeClientMessage::Count {
            subscription_id,
            search_present: filters.iter().any(|filter| filter.search().is_some()),
            filters: filters
                .iter()
                .map(crate::pocket_conversion::tangle_filter_to_pocket)
                .collect::<Result<Vec<_>, _>>()?,
        }),
        tangle_protocol::ClientMessage::Close(subscription_id) => {
            Ok(RuntimeClientMessage::Close(subscription_id))
        }
        tangle_protocol::ClientMessage::Auth(event) => Ok(RuntimeClientMessage::Auth(
            crate::pocket_conversion::tangle_event_to_pocket(&event)?,
        )),
        tangle_protocol::ClientMessage::NegOpen {
            subscription_id,
            filter,
            message,
        } => Ok(RuntimeClientMessage::NegOpen {
            subscription_id,
            filter: crate::pocket_conversion::tangle_filter_to_pocket(&filter)?,
            message,
        }),
        tangle_protocol::ClientMessage::NegMsg {
            subscription_id,
            message,
        } => Ok(RuntimeClientMessage::NegMsg {
            subscription_id,
            message,
        }),
        tangle_protocol::ClientMessage::NegClose(subscription_id) => {
            Ok(RuntimeClientMessage::NegClose(subscription_id))
        }
    }
}

fn runtime_client_message_metric_kind(
    message: &RuntimeClientMessage,
) -> TangleClientMessageMetricKind {
    match message {
        RuntimeClientMessage::Event(_) => TangleClientMessageMetricKind::Event,
        RuntimeClientMessage::Req { .. } => TangleClientMessageMetricKind::Req,
        RuntimeClientMessage::Count { .. } => TangleClientMessageMetricKind::Count,
        RuntimeClientMessage::Auth(_) => TangleClientMessageMetricKind::Auth,
        RuntimeClientMessage::Close(_) => TangleClientMessageMetricKind::Close,
        RuntimeClientMessage::NegOpen { .. }
        | RuntimeClientMessage::NegMsg { .. }
        | RuntimeClientMessage::NegClose(_) => TangleClientMessageMetricKind::Negentropy,
    }
}

fn pocket_filter_group_ids(filters: &[PocketOwnedFilter]) -> Vec<GroupId> {
    let mut group_ids = BTreeSet::new();
    for filter in filters {
        let Ok(tags) = filter.tags() else {
            continue;
        };
        for mut tag in tags.iter() {
            let name = tag.next();
            if !matches!(name, Some(value) if matches!(value, b"h" | b"d")) {
                continue;
            }
            for value in tag {
                if let Ok(value) = std::str::from_utf8(value)
                    && let Ok(group_id) = GroupId::new(value)
                {
                    group_ids.insert(group_id);
                }
            }
        }
    }
    group_ids.into_iter().collect()
}

fn pocket_filter_kinds(filters: &[PocketOwnedFilter]) -> Vec<Kind> {
    filters
        .iter()
        .flat_map(|filter| filter.kinds())
        .filter_map(|kind| Kind::new(u64::from(kind.as_u16())).ok())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

impl fmt::Debug for RelayRuntimeHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelayRuntimeHandle")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TangleRuntimeLimits {
    max_message_length: usize,
    base_relay_limits: BaseRelayLimits,
    event_bus_capacity: usize,
    outbound_queue_capacity: usize,
}

impl TangleRuntimeLimits {
    pub fn new(
        max_message_length: usize,
        base_relay_limits: BaseRelayLimits,
        event_bus_capacity: usize,
        outbound_queue_capacity: usize,
    ) -> Result<Self, BaseRelayError> {
        if max_message_length == 0 {
            return Err(BaseRelayError::invalid(
                "runtime max message length must be greater than zero",
            ));
        }
        if event_bus_capacity == 0 {
            return Err(BaseRelayError::invalid(
                "runtime event bus capacity must be greater than zero",
            ));
        }
        if outbound_queue_capacity == 0 {
            return Err(BaseRelayError::invalid(
                "runtime outbound queue capacity must be greater than zero",
            ));
        }
        Ok(Self {
            max_message_length,
            base_relay_limits,
            event_bus_capacity,
            outbound_queue_capacity,
        })
    }

    pub fn from_config(config: &BaseRelayRuntimeConfig) -> Result<Self, BaseRelayError> {
        let limits = config.limits();
        Self::new(
            limits.max_message_length(),
            limits.base_relay_limits()?,
            limits.broadcast_channel_capacity(),
            limits.per_connection_outbound_queue(),
        )
    }

    pub fn max_message_length(self) -> usize {
        self.max_message_length
    }

    pub fn base_relay_limits(self) -> BaseRelayLimits {
        self.base_relay_limits
    }

    pub fn max_pending_events(self) -> usize {
        self.base_relay_limits.max_pending_events()
    }

    pub fn event_bus_capacity(self) -> usize {
        self.event_bus_capacity
    }

    pub fn outbound_queue_capacity(self) -> usize {
        self.outbound_queue_capacity
    }
}

#[derive(Debug, Clone)]
pub struct TangleRuntimeMetrics {
    inner: Arc<TangleRuntimeMetricsInner>,
}

#[derive(Debug)]
struct TangleRuntimeMetricsInner {
    started_at: Instant,
    active_sessions: AtomicUsize,
    total_sessions: AtomicU64,
    client_messages: AtomicU64,
    event_messages: AtomicU64,
    req_messages: AtomicU64,
    count_messages: AtomicU64,
    auth_messages: AtomicU64,
    close_messages: AtomicU64,
    active_subscriptions: AtomicUsize,
    opened_subscriptions: AtomicU64,
    closed_subscriptions: AtomicU64,
    stored_event_offsets: AtomicU64,
    rate_limit_rejections: AtomicU64,
    auth_successes: AtomicU64,
    auth_failures: AtomicU64,
    event_admissions: AtomicU64,
    event_rejections: AtomicU64,
    group_read_denials: AtomicU64,
    group_write_denials: AtomicU64,
    event_bus_receivers_current: AtomicUsize,
    event_bus_published_offsets: AtomicU64,
    event_bus_lagged_receivers: AtomicU64,
    event_bus_lagged_offsets: AtomicU64,
    outbound_queue_full_closes: AtomicU64,
    outbox_pending_events: AtomicUsize,
    outbox_replayed_events: AtomicU64,
    disk_used_bytes: AtomicU64,
    event_admission_latency_total_micros: AtomicU64,
    event_admission_latency_count: AtomicU64,
    query_latency_total_micros: AtomicU64,
    query_latency_count: AtomicU64,
    query_candidates_scanned: AtomicU64,
    query_returned_events: AtomicU64,
    query_redacted_events: AtomicU64,
    count_refusals: AtomicU64,
    broad_query_rejections: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TangleClientMessageMetricKind {
    Event,
    Req,
    Count,
    Auth,
    Close,
    Negentropy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TangleRuntimeMetricsSnapshot {
    tangle_runtime_uptime_seconds: u64,
    tangle_readiness_ready: bool,
    tangle_ws_connections_current: usize,
    tangle_ws_connections_total: u64,
    tangle_client_messages_total: u64,
    tangle_event_messages_total: u64,
    tangle_req_messages_total: u64,
    tangle_count_messages_total: u64,
    tangle_auth_messages_total: u64,
    tangle_close_messages_total: u64,
    tangle_subscriptions_current: usize,
    tangle_subscriptions_opened_total: u64,
    tangle_subscriptions_closed_total: u64,
    tangle_stored_event_offsets_total: u64,
    tangle_rate_limit_rejections_total: u64,
    tangle_auth_success_total: u64,
    tangle_auth_failure_total: u64,
    tangle_event_admitted_total: u64,
    tangle_event_rejected_total: u64,
    tangle_group_read_denied_total: u64,
    tangle_group_write_denied_total: u64,
    tangle_event_bus_receivers_current: usize,
    tangle_event_bus_published_offsets_total: u64,
    tangle_event_bus_lagged_receivers_total: u64,
    tangle_event_bus_lagged_offsets_total: u64,
    tangle_outbound_queue_full_closes_total: u64,
    tangle_outbox_pending_events: usize,
    tangle_outbox_replayed_events_total: u64,
    tangle_disk_used_bytes: u64,
    tangle_event_admission_latency_total_micros: u64,
    tangle_event_admission_latency_count: u64,
    tangle_query_latency_total_micros: u64,
    tangle_query_latency_count: u64,
    tangle_query_candidates_scanned_total: u64,
    tangle_query_returned_events_total: u64,
    tangle_query_redacted_events_total: u64,
    tangle_count_refusals_total: u64,
    tangle_broad_query_rejections_total: u64,
}

impl TangleRuntimeMetricsSnapshot {
    pub fn prometheus_text(&self) -> String {
        let samples = [
            (
                "tangle_runtime_uptime_seconds",
                "gauge",
                self.tangle_runtime_uptime_seconds.to_string(),
            ),
            (
                "tangle_readiness_ready",
                "gauge",
                u8::from(self.tangle_readiness_ready).to_string(),
            ),
            (
                "tangle_ws_connections_current",
                "gauge",
                self.tangle_ws_connections_current.to_string(),
            ),
            (
                "tangle_ws_connections_total",
                "counter",
                self.tangle_ws_connections_total.to_string(),
            ),
            (
                "tangle_client_messages_total",
                "counter",
                self.tangle_client_messages_total.to_string(),
            ),
            (
                "tangle_event_messages_total",
                "counter",
                self.tangle_event_messages_total.to_string(),
            ),
            (
                "tangle_req_messages_total",
                "counter",
                self.tangle_req_messages_total.to_string(),
            ),
            (
                "tangle_count_messages_total",
                "counter",
                self.tangle_count_messages_total.to_string(),
            ),
            (
                "tangle_auth_messages_total",
                "counter",
                self.tangle_auth_messages_total.to_string(),
            ),
            (
                "tangle_close_messages_total",
                "counter",
                self.tangle_close_messages_total.to_string(),
            ),
            (
                "tangle_subscriptions_current",
                "gauge",
                self.tangle_subscriptions_current.to_string(),
            ),
            (
                "tangle_subscriptions_opened_total",
                "counter",
                self.tangle_subscriptions_opened_total.to_string(),
            ),
            (
                "tangle_subscriptions_closed_total",
                "counter",
                self.tangle_subscriptions_closed_total.to_string(),
            ),
            (
                "tangle_stored_event_offsets_total",
                "counter",
                self.tangle_stored_event_offsets_total.to_string(),
            ),
            (
                "tangle_rate_limit_rejections_total",
                "counter",
                self.tangle_rate_limit_rejections_total.to_string(),
            ),
            (
                "tangle_auth_success_total",
                "counter",
                self.tangle_auth_success_total.to_string(),
            ),
            (
                "tangle_auth_failure_total",
                "counter",
                self.tangle_auth_failure_total.to_string(),
            ),
            (
                "tangle_event_admitted_total",
                "counter",
                self.tangle_event_admitted_total.to_string(),
            ),
            (
                "tangle_event_rejected_total",
                "counter",
                self.tangle_event_rejected_total.to_string(),
            ),
            (
                "tangle_group_read_denied_total",
                "counter",
                self.tangle_group_read_denied_total.to_string(),
            ),
            (
                "tangle_group_write_denied_total",
                "counter",
                self.tangle_group_write_denied_total.to_string(),
            ),
            (
                "tangle_event_bus_receivers_current",
                "gauge",
                self.tangle_event_bus_receivers_current.to_string(),
            ),
            (
                "tangle_event_bus_published_offsets_total",
                "counter",
                self.tangle_event_bus_published_offsets_total.to_string(),
            ),
            (
                "tangle_event_bus_lagged_receivers_total",
                "counter",
                self.tangle_event_bus_lagged_receivers_total.to_string(),
            ),
            (
                "tangle_event_bus_lagged_offsets_total",
                "counter",
                self.tangle_event_bus_lagged_offsets_total.to_string(),
            ),
            (
                "tangle_outbound_queue_full_closes_total",
                "counter",
                self.tangle_outbound_queue_full_closes_total.to_string(),
            ),
            (
                "tangle_outbox_pending_events",
                "gauge",
                self.tangle_outbox_pending_events.to_string(),
            ),
            (
                "tangle_outbox_replayed_events_total",
                "counter",
                self.tangle_outbox_replayed_events_total.to_string(),
            ),
            (
                "tangle_disk_used_bytes",
                "gauge",
                self.tangle_disk_used_bytes.to_string(),
            ),
            (
                "tangle_event_admission_latency_total_micros",
                "counter",
                self.tangle_event_admission_latency_total_micros.to_string(),
            ),
            (
                "tangle_event_admission_latency_count",
                "counter",
                self.tangle_event_admission_latency_count.to_string(),
            ),
            (
                "tangle_query_latency_total_micros",
                "counter",
                self.tangle_query_latency_total_micros.to_string(),
            ),
            (
                "tangle_query_latency_count",
                "counter",
                self.tangle_query_latency_count.to_string(),
            ),
            (
                "tangle_query_candidates_scanned_total",
                "counter",
                self.tangle_query_candidates_scanned_total.to_string(),
            ),
            (
                "tangle_query_returned_events_total",
                "counter",
                self.tangle_query_returned_events_total.to_string(),
            ),
            (
                "tangle_query_redacted_events_total",
                "counter",
                self.tangle_query_redacted_events_total.to_string(),
            ),
            (
                "tangle_count_refusals_total",
                "counter",
                self.tangle_count_refusals_total.to_string(),
            ),
            (
                "tangle_broad_query_rejections_total",
                "counter",
                self.tangle_broad_query_rejections_total.to_string(),
            ),
        ];
        let mut output = String::with_capacity(samples.len() * 128);
        for (name, metric_type, value) in samples {
            output.push_str("# TYPE ");
            output.push_str(name);
            output.push(' ');
            output.push_str(metric_type);
            output.push('\n');
            output.push_str(name);
            output.push(' ');
            output.push_str(&value);
            output.push('\n');
        }
        output
    }

    pub fn active_sessions(&self) -> usize {
        self.tangle_ws_connections_current
    }

    pub fn total_sessions(&self) -> u64 {
        self.tangle_ws_connections_total
    }

    pub fn client_messages(&self) -> u64 {
        self.tangle_client_messages_total
    }

    pub fn event_messages(&self) -> u64 {
        self.tangle_event_messages_total
    }

    pub fn req_messages(&self) -> u64 {
        self.tangle_req_messages_total
    }

    pub fn count_messages(&self) -> u64 {
        self.tangle_count_messages_total
    }

    pub fn auth_messages(&self) -> u64 {
        self.tangle_auth_messages_total
    }

    pub fn close_messages(&self) -> u64 {
        self.tangle_close_messages_total
    }

    pub fn opened_subscriptions(&self) -> u64 {
        self.tangle_subscriptions_opened_total
    }

    pub fn active_subscriptions(&self) -> usize {
        self.tangle_subscriptions_current
    }

    pub fn closed_subscriptions(&self) -> u64 {
        self.tangle_subscriptions_closed_total
    }

    pub fn stored_event_offsets(&self) -> u64 {
        self.tangle_stored_event_offsets_total
    }

    pub fn rate_limit_rejections(&self) -> u64 {
        self.tangle_rate_limit_rejections_total
    }
}

impl TangleRuntimeMetrics {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(TangleRuntimeMetricsInner {
                started_at: Instant::now(),
                active_sessions: AtomicUsize::new(0),
                total_sessions: AtomicU64::new(0),
                client_messages: AtomicU64::new(0),
                event_messages: AtomicU64::new(0),
                req_messages: AtomicU64::new(0),
                count_messages: AtomicU64::new(0),
                auth_messages: AtomicU64::new(0),
                close_messages: AtomicU64::new(0),
                active_subscriptions: AtomicUsize::new(0),
                opened_subscriptions: AtomicU64::new(0),
                closed_subscriptions: AtomicU64::new(0),
                stored_event_offsets: AtomicU64::new(0),
                rate_limit_rejections: AtomicU64::new(0),
                auth_successes: AtomicU64::new(0),
                auth_failures: AtomicU64::new(0),
                event_admissions: AtomicU64::new(0),
                event_rejections: AtomicU64::new(0),
                group_read_denials: AtomicU64::new(0),
                group_write_denials: AtomicU64::new(0),
                event_bus_receivers_current: AtomicUsize::new(0),
                event_bus_published_offsets: AtomicU64::new(0),
                event_bus_lagged_receivers: AtomicU64::new(0),
                event_bus_lagged_offsets: AtomicU64::new(0),
                outbound_queue_full_closes: AtomicU64::new(0),
                outbox_pending_events: AtomicUsize::new(0),
                outbox_replayed_events: AtomicU64::new(0),
                disk_used_bytes: AtomicU64::new(0),
                event_admission_latency_total_micros: AtomicU64::new(0),
                event_admission_latency_count: AtomicU64::new(0),
                query_latency_total_micros: AtomicU64::new(0),
                query_latency_count: AtomicU64::new(0),
                query_candidates_scanned: AtomicU64::new(0),
                query_returned_events: AtomicU64::new(0),
                query_redacted_events: AtomicU64::new(0),
                count_refusals: AtomicU64::new(0),
                broad_query_rejections: AtomicU64::new(0),
            }),
        }
    }

    pub fn snapshot(&self) -> TangleRuntimeMetricsSnapshot {
        self.snapshot_with_readiness(false)
    }

    pub fn snapshot_with_readiness(&self, readiness_ready: bool) -> TangleRuntimeMetricsSnapshot {
        TangleRuntimeMetricsSnapshot {
            tangle_runtime_uptime_seconds: self.started_at().elapsed().as_secs(),
            tangle_readiness_ready: readiness_ready,
            tangle_ws_connections_current: self.active_sessions(),
            tangle_ws_connections_total: self.total_sessions(),
            tangle_client_messages_total: self.client_messages(),
            tangle_event_messages_total: self.event_messages(),
            tangle_req_messages_total: self.req_messages(),
            tangle_count_messages_total: self.count_messages(),
            tangle_auth_messages_total: self.auth_messages(),
            tangle_close_messages_total: self.close_messages(),
            tangle_subscriptions_current: self.active_subscriptions(),
            tangle_subscriptions_opened_total: self.opened_subscriptions(),
            tangle_subscriptions_closed_total: self.closed_subscriptions(),
            tangle_stored_event_offsets_total: self.stored_event_offsets(),
            tangle_rate_limit_rejections_total: self.rate_limit_rejections(),
            tangle_auth_success_total: self.auth_successes(),
            tangle_auth_failure_total: self.auth_failures(),
            tangle_event_admitted_total: self.event_admissions(),
            tangle_event_rejected_total: self.event_rejections(),
            tangle_group_read_denied_total: self.group_read_denials(),
            tangle_group_write_denied_total: self.group_write_denials(),
            tangle_event_bus_receivers_current: self.event_bus_receivers_current(),
            tangle_event_bus_published_offsets_total: self.event_bus_published_offsets(),
            tangle_event_bus_lagged_receivers_total: self.event_bus_lagged_receivers(),
            tangle_event_bus_lagged_offsets_total: self.event_bus_lagged_offsets(),
            tangle_outbound_queue_full_closes_total: self.outbound_queue_full_closes(),
            tangle_outbox_pending_events: self.outbox_pending_events(),
            tangle_outbox_replayed_events_total: self.outbox_replayed_events(),
            tangle_disk_used_bytes: self.disk_used_bytes(),
            tangle_event_admission_latency_total_micros: self
                .event_admission_latency_total_micros(),
            tangle_event_admission_latency_count: self.event_admission_latency_count(),
            tangle_query_latency_total_micros: self.query_latency_total_micros(),
            tangle_query_latency_count: self.query_latency_count(),
            tangle_query_candidates_scanned_total: self.query_candidates_scanned(),
            tangle_query_returned_events_total: self.query_returned_events(),
            tangle_query_redacted_events_total: self.query_redacted_events(),
            tangle_count_refusals_total: self.count_refusals(),
            tangle_broad_query_rejections_total: self.broad_query_rejections(),
        }
    }

    pub fn started_at(&self) -> Instant {
        self.inner.started_at
    }

    pub fn active_sessions(&self) -> usize {
        self.inner.active_sessions.load(Ordering::Relaxed)
    }

    pub fn total_sessions(&self) -> u64 {
        self.inner.total_sessions.load(Ordering::Relaxed)
    }

    pub fn client_messages(&self) -> u64 {
        self.inner.client_messages.load(Ordering::Relaxed)
    }

    pub fn event_messages(&self) -> u64 {
        self.inner.event_messages.load(Ordering::Relaxed)
    }

    pub fn req_messages(&self) -> u64 {
        self.inner.req_messages.load(Ordering::Relaxed)
    }

    pub fn count_messages(&self) -> u64 {
        self.inner.count_messages.load(Ordering::Relaxed)
    }

    pub fn auth_messages(&self) -> u64 {
        self.inner.auth_messages.load(Ordering::Relaxed)
    }

    pub fn close_messages(&self) -> u64 {
        self.inner.close_messages.load(Ordering::Relaxed)
    }

    pub fn opened_subscriptions(&self) -> u64 {
        self.inner.opened_subscriptions.load(Ordering::Relaxed)
    }

    pub fn active_subscriptions(&self) -> usize {
        self.inner.active_subscriptions.load(Ordering::Relaxed)
    }

    pub fn closed_subscriptions(&self) -> u64 {
        self.inner.closed_subscriptions.load(Ordering::Relaxed)
    }

    pub fn stored_event_offsets(&self) -> u64 {
        self.inner.stored_event_offsets.load(Ordering::Relaxed)
    }

    pub fn rate_limit_rejections(&self) -> u64 {
        self.inner.rate_limit_rejections.load(Ordering::Relaxed)
    }

    pub fn auth_successes(&self) -> u64 {
        self.inner.auth_successes.load(Ordering::Relaxed)
    }

    pub fn auth_failures(&self) -> u64 {
        self.inner.auth_failures.load(Ordering::Relaxed)
    }

    pub fn event_admissions(&self) -> u64 {
        self.inner.event_admissions.load(Ordering::Relaxed)
    }

    pub fn event_rejections(&self) -> u64 {
        self.inner.event_rejections.load(Ordering::Relaxed)
    }

    pub fn group_read_denials(&self) -> u64 {
        self.inner.group_read_denials.load(Ordering::Relaxed)
    }

    pub fn group_write_denials(&self) -> u64 {
        self.inner.group_write_denials.load(Ordering::Relaxed)
    }

    pub fn event_bus_receivers_current(&self) -> usize {
        self.inner
            .event_bus_receivers_current
            .load(Ordering::Relaxed)
    }

    pub fn event_bus_published_offsets(&self) -> u64 {
        self.inner
            .event_bus_published_offsets
            .load(Ordering::Relaxed)
    }

    pub fn event_bus_lagged_receivers(&self) -> u64 {
        self.inner
            .event_bus_lagged_receivers
            .load(Ordering::Relaxed)
    }

    pub fn event_bus_lagged_offsets(&self) -> u64 {
        self.inner.event_bus_lagged_offsets.load(Ordering::Relaxed)
    }

    pub fn outbound_queue_full_closes(&self) -> u64 {
        self.inner
            .outbound_queue_full_closes
            .load(Ordering::Relaxed)
    }

    pub fn outbox_pending_events(&self) -> usize {
        self.inner.outbox_pending_events.load(Ordering::Relaxed)
    }

    pub fn outbox_replayed_events(&self) -> u64 {
        self.inner.outbox_replayed_events.load(Ordering::Relaxed)
    }

    pub fn disk_used_bytes(&self) -> u64 {
        self.inner.disk_used_bytes.load(Ordering::Relaxed)
    }

    pub fn event_admission_latency_total_micros(&self) -> u64 {
        self.inner
            .event_admission_latency_total_micros
            .load(Ordering::Relaxed)
    }

    pub fn event_admission_latency_count(&self) -> u64 {
        self.inner
            .event_admission_latency_count
            .load(Ordering::Relaxed)
    }

    pub fn query_latency_total_micros(&self) -> u64 {
        self.inner
            .query_latency_total_micros
            .load(Ordering::Relaxed)
    }

    pub fn query_latency_count(&self) -> u64 {
        self.inner.query_latency_count.load(Ordering::Relaxed)
    }

    pub fn query_candidates_scanned(&self) -> u64 {
        self.inner.query_candidates_scanned.load(Ordering::Relaxed)
    }

    pub fn query_returned_events(&self) -> u64 {
        self.inner.query_returned_events.load(Ordering::Relaxed)
    }

    pub fn query_redacted_events(&self) -> u64 {
        self.inner.query_redacted_events.load(Ordering::Relaxed)
    }

    pub fn count_refusals(&self) -> u64 {
        self.inner.count_refusals.load(Ordering::Relaxed)
    }

    pub fn broad_query_rejections(&self) -> u64 {
        self.inner.broad_query_rejections.load(Ordering::Relaxed)
    }

    pub fn record_session_opened(&self) -> usize {
        self.inner.total_sessions.fetch_add(1, Ordering::Relaxed);
        self.inner.active_sessions.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn record_session_closed(&self) -> usize {
        let mut current = self.inner.active_sessions.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return 0;
            }
            match self.inner.active_sessions.compare_exchange(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return current - 1,
                Err(actual) => current = actual,
            }
        }
    }

    pub fn record_client_message(&self, kind: TangleClientMessageMetricKind) -> u64 {
        let total = self.inner.client_messages.fetch_add(1, Ordering::Relaxed) + 1;
        match kind {
            TangleClientMessageMetricKind::Event => {
                self.inner.event_messages.fetch_add(1, Ordering::Relaxed);
            }
            TangleClientMessageMetricKind::Req => {
                self.inner.req_messages.fetch_add(1, Ordering::Relaxed);
            }
            TangleClientMessageMetricKind::Count => {
                self.inner.count_messages.fetch_add(1, Ordering::Relaxed);
            }
            TangleClientMessageMetricKind::Auth => {
                self.inner.auth_messages.fetch_add(1, Ordering::Relaxed);
            }
            TangleClientMessageMetricKind::Close => {
                self.inner.close_messages.fetch_add(1, Ordering::Relaxed);
            }
            TangleClientMessageMetricKind::Negentropy => {}
        };
        total
    }

    pub fn record_subscription_opened(&self) -> u64 {
        self.inner
            .active_subscriptions
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .opened_subscriptions
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    pub fn record_subscriptions_closed(&self, count: usize) -> u64 {
        let mut current = self.active_subscriptions();
        loop {
            let remaining = current.saturating_sub(count);
            match self.inner.active_subscriptions.compare_exchange(
                current,
                remaining,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        self.inner.closed_subscriptions.fetch_add(
            u64::try_from(count).expect("subscription count fits in u64"),
            Ordering::Relaxed,
        ) + u64::try_from(count).expect("subscription count fits in u64")
    }

    pub fn record_stored_event_offset(&self) -> u64 {
        self.inner
            .stored_event_offsets
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    pub fn record_rate_limit_rejection(&self) -> u64 {
        self.inner
            .rate_limit_rejections
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    pub fn record_auth_success(&self) -> u64 {
        self.inner.auth_successes.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn record_auth_failure(&self) -> u64 {
        self.inner.auth_failures.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn record_event_admission(&self) -> u64 {
        self.inner.event_admissions.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn record_event_rejection(&self) -> u64 {
        self.inner.event_rejections.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn record_group_read_denial(&self) -> u64 {
        self.inner
            .group_read_denials
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    pub fn record_group_write_denial(&self) -> u64 {
        self.inner
            .group_write_denials
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    pub fn record_event_bus_receivers(&self, count: usize) {
        self.inner
            .event_bus_receivers_current
            .store(count, Ordering::Relaxed);
    }

    pub fn record_event_bus_publish(&self, receivers: usize) -> u64 {
        self.record_event_bus_receivers(receivers);
        self.inner
            .event_bus_published_offsets
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    pub fn record_event_bus_lagged(&self, skipped: u64) {
        self.inner
            .event_bus_lagged_receivers
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .event_bus_lagged_offsets
            .fetch_add(skipped, Ordering::Relaxed);
    }

    pub fn record_outbound_queue_full_close(&self) -> u64 {
        self.inner
            .outbound_queue_full_closes
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    pub fn record_outbox_pending_events(&self, count: usize) {
        self.inner
            .outbox_pending_events
            .store(count, Ordering::Relaxed);
    }

    pub fn record_outbox_replayed_event(&self) -> u64 {
        self.inner
            .outbox_replayed_events
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    pub fn record_disk_used_bytes(&self, bytes: u64) {
        self.inner.disk_used_bytes.store(bytes, Ordering::Relaxed);
    }

    pub fn record_event_admission_latency(&self, micros: u64) {
        self.inner
            .event_admission_latency_total_micros
            .fetch_add(micros, Ordering::Relaxed);
        self.inner
            .event_admission_latency_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_query_latency(&self, micros: u64) {
        self.inner
            .query_latency_total_micros
            .fetch_add(micros, Ordering::Relaxed);
        self.inner
            .query_latency_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_query_metrics(&self, metrics: BaseRelayQueryMetrics) {
        self.inner
            .query_candidates_scanned
            .fetch_add(metrics.candidates_scanned(), Ordering::Relaxed);
        self.inner
            .query_returned_events
            .fetch_add(metrics.returned_events(), Ordering::Relaxed);
        self.inner
            .query_redacted_events
            .fetch_add(metrics.redacted_events(), Ordering::Relaxed);
    }

    pub fn record_count_refusal(&self) -> u64 {
        self.inner.count_refusals.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn record_broad_query_rejection(&self) -> u64 {
        self.inner
            .broad_query_rejections
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }
}

impl Default for TangleRuntimeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct TangleShutdownSignal {
    sender: watch::Sender<bool>,
}

impl TangleShutdownSignal {
    pub fn new() -> Self {
        let (sender, _) = watch::channel(false);
        Self { sender }
    }

    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.sender.subscribe()
    }

    pub fn request_shutdown(&self) {
        self.sender.send_replace(true);
    }

    pub fn requested(&self) -> bool {
        *self.sender.borrow()
    }
}

impl Default for TangleShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BROAD_QUERY_TIME_WINDOW_SECONDS, EventAdmissionDecision, RelayEventAdmissionContext,
        RelayEventProjectionContext, RelayEventProjectionDecision, RelayEventProjectionSource,
        RelayEventStoredContext, RelayLiveProjectionCandidate, RelayLiveProjectionContext,
        RelayProjectionContext, RelayProjectionQueryPlan, RelayQueryProjectionContext,
        RelayRequestedKinds, RelayRuntime, RelayRuntimeHandle, RelayRuntimeHooks,
        RuntimeClientMessage, TangleBroadQueryReason, TangleClientRateLimitContext,
        TangleQueryClassification, TangleQueryClassifier, TangleRuntimeLimits,
    };
    use crate::config::{BaseRelayRuntimeConfig, parse_base_relay_runtime_config_json};
    use crate::event_bus::{TangleEventBus, TangleEventReceiveError, TangleEventReceiver};
    use crate::rate_limits::{TangleRateLimitKey, TangleRateLimitQueryClass, TangleRateLimitScope};
    use crate::relay::auth::BaseAuthState;
    use crate::relay::core::{BaseRelayLimitSettings, BaseRelayLimits, BaseRelayQueryMetrics};
    use crate::relay::live::LiveSubscriptionSet;
    use crate::relay::outbound::RuntimeRelayMessage;
    use serde_json::json;
    use std::{
        collections::{BTreeMap, BTreeSet},
        net::{IpAddr, Ipv4Addr},
        num::NonZeroU32,
        path::{Path, PathBuf},
        sync::{Arc, Mutex, mpsc},
        time::Duration,
    };
    use tangle_crypto::RelaySigner;
    use tangle_groups::{
        CanonicalGroupEvent, GroupEventClass, GroupId, GroupProjection, KIND_GROUP_ADMINS,
        KIND_GROUP_CREATE_GROUP, KIND_GROUP_DELETE_GROUP, KIND_GROUP_JOIN_REQUEST,
        KIND_GROUP_LEAVE_REQUEST, KIND_GROUP_MEMBERS, KIND_GROUP_METADATA, KIND_GROUP_PUT_USER,
        KIND_GROUP_REMOVE_USER, MemberStatus, StoreOffset, rebuild_group_projection,
    };
    use tangle_protocol::{
        ClientMessage, Event, EventId, Filter, Kind, PublicKeyHex, RelayMessage, SignatureHex,
        SubscriptionId, Tag, UnixTimestamp, UnsignedEvent, filter_from_value,
    };
    use tangle_store_pocket::{
        PocketEvent, PocketKind, PocketOwnedEvent, PocketOwnedTags, PocketTime,
    };
    use tangle_test_support::FixtureKey;

    #[test]
    fn tangle_runtime_opens_owned_process_shell_from_config() {
        let root = temp_root("owned-runtime");
        let _ = std::fs::remove_dir_all(&root);
        let config = runtime_config(&root, 8);

        let mut runtime = RelayRuntime::open(config).expect("runtime");
        let mut offsets = runtime.event_bus().subscribe();
        let shutdown = runtime.shutdown_signal().subscribe();

        assert_eq!(runtime.config().relay_url(), "wss://relay.radroots.test");
        assert_eq!(runtime.config().listen_addr().to_string(), "127.0.0.1:0");
        assert_eq!(runtime.limits().max_pending_events(), 8);
        assert_eq!(runtime.limits().max_message_length(), 1_048_576);
        assert_eq!(runtime.limits().event_bus_capacity(), 16);
        assert_eq!(runtime.limits().outbound_queue_capacity(), 8);
        assert_eq!(runtime.event_bus().capacity(), 16);
        assert_eq!(runtime.event_bus().receiver_count(), 1);
        assert_eq!(runtime.rate_limiter().tracked_key_count(), 0);
        assert_eq!(runtime.metrics().active_sessions(), 0);
        assert_eq!(runtime.metrics().stored_event_offsets(), 0);
        assert!(runtime.relay().groups_enabled());
        assert!(!runtime.readiness_state().is_ready());
        assert_eq!(
            runtime.readiness_state().response().checks.server_bind,
            "not_ready"
        );
        assert_eq!(
            runtime
                .readiness_state()
                .response()
                .checks
                .group_outbox_replay,
            "ready"
        );
        assert_eq!(
            runtime.readiness_state().response().checks.event_bus,
            "ready"
        );
        assert!(!*shutdown.borrow());

        assert_eq!(runtime.event_bus().publish(StoreOffset::new(42)), 1);
        assert_eq!(offsets.try_recv().expect("offset"), StoreOffset::new(42));
        assert_eq!(
            runtime
                .auth_state()
                .expect("auth")
                .authenticated_pubkeys()
                .len(),
            0
        );
        assert_eq!(
            runtime.config().pocket_config().data_directory(),
            Path::new(&root).join("pocket")
        );

        assert_eq!(runtime.metrics().record_session_opened(), 1);
        assert_eq!(runtime.metrics().active_sessions(), 1);
        assert_eq!(runtime.metrics().total_sessions(), 1);
        assert_eq!(runtime.metrics().record_session_closed(), 0);
        assert_eq!(runtime.metrics().active_sessions(), 0);
        assert_eq!(runtime.metrics().total_sessions(), 1);
        assert_eq!(
            runtime
                .metrics()
                .record_client_message(super::TangleClientMessageMetricKind::Req),
            1
        );
        assert_eq!(runtime.metrics().client_messages(), 1);
        assert_eq!(runtime.metrics().req_messages(), 1);
        assert_eq!(runtime.metrics().record_subscription_opened(), 1);
        assert_eq!(runtime.metrics().active_subscriptions(), 1);
        assert_eq!(runtime.metrics().opened_subscriptions(), 1);
        assert_eq!(runtime.metrics().record_subscriptions_closed(1), 1);
        assert_eq!(runtime.metrics().active_subscriptions(), 0);
        assert_eq!(runtime.metrics().closed_subscriptions(), 1);
        assert_eq!(runtime.metrics().record_stored_event_offset(), 1);
        assert_eq!(runtime.metrics().stored_event_offsets(), 1);
        assert_eq!(runtime.metrics().record_rate_limit_rejection(), 1);
        assert_eq!(runtime.metrics().rate_limit_rejections(), 1);
        assert_eq!(runtime.metrics().record_auth_success(), 1);
        assert_eq!(runtime.metrics().record_auth_failure(), 1);
        assert_eq!(runtime.metrics().record_event_admission(), 1);
        assert_eq!(runtime.metrics().record_event_rejection(), 1);
        assert_eq!(runtime.metrics().record_group_read_denial(), 1);
        assert_eq!(runtime.metrics().record_group_write_denial(), 1);
        runtime.metrics().record_event_bus_receivers(3);
        assert_eq!(runtime.metrics().record_event_bus_publish(3), 1);
        runtime.metrics().record_event_bus_lagged(4);
        assert_eq!(runtime.metrics().record_outbound_queue_full_close(), 1);
        runtime.metrics().record_outbox_pending_events(2);
        assert_eq!(runtime.metrics().record_outbox_replayed_event(), 1);
        runtime.metrics().record_disk_used_bytes(5);
        runtime.metrics().record_event_admission_latency(13);
        runtime.metrics().record_query_latency(17);
        runtime
            .metrics()
            .record_query_metrics(BaseRelayQueryMetrics::new(5, 3, 2));
        assert_eq!(runtime.metrics().record_count_refusal(), 1);
        assert_eq!(runtime.metrics().record_broad_query_rejection(), 1);
        let snapshot = runtime.metrics().snapshot_with_readiness(true);
        assert_eq!(snapshot.active_sessions(), 0);
        assert_eq!(snapshot.total_sessions(), 1);
        assert_eq!(snapshot.client_messages(), 1);
        assert_eq!(snapshot.req_messages(), 1);
        assert_eq!(snapshot.active_subscriptions(), 0);
        assert_eq!(snapshot.opened_subscriptions(), 1);
        assert_eq!(snapshot.closed_subscriptions(), 1);
        assert_eq!(snapshot.stored_event_offsets(), 1);
        assert_eq!(snapshot.rate_limit_rejections(), 1);
        let snapshot_value = serde_json::to_value(snapshot).expect("snapshot json");
        assert_eq!(snapshot_value["tangle_readiness_ready"], true);
        assert_eq!(snapshot_value["tangle_auth_success_total"], 1);
        assert_eq!(snapshot_value["tangle_auth_failure_total"], 1);
        assert_eq!(snapshot_value["tangle_event_admitted_total"], 1);
        assert_eq!(snapshot_value["tangle_event_rejected_total"], 1);
        assert_eq!(snapshot_value["tangle_group_read_denied_total"], 1);
        assert_eq!(snapshot_value["tangle_group_write_denied_total"], 1);
        assert_eq!(snapshot_value["tangle_event_bus_receivers_current"], 3);
        assert_eq!(
            snapshot_value["tangle_event_bus_published_offsets_total"],
            1
        );
        assert_eq!(snapshot_value["tangle_event_bus_lagged_receivers_total"], 1);
        assert_eq!(snapshot_value["tangle_event_bus_lagged_offsets_total"], 4);
        assert_eq!(snapshot_value["tangle_outbound_queue_full_closes_total"], 1);
        assert_eq!(snapshot_value["tangle_outbox_pending_events"], 2);
        assert_eq!(snapshot_value["tangle_outbox_replayed_events_total"], 1);
        assert_eq!(snapshot_value["tangle_disk_used_bytes"], 5);
        assert_eq!(
            snapshot_value["tangle_event_admission_latency_total_micros"],
            13
        );
        assert_eq!(snapshot_value["tangle_event_admission_latency_count"], 1);
        assert_eq!(snapshot_value["tangle_query_latency_total_micros"], 17);
        assert_eq!(snapshot_value["tangle_query_latency_count"], 1);
        assert_eq!(snapshot_value["tangle_query_candidates_scanned_total"], 5);
        assert_eq!(snapshot_value["tangle_query_returned_events_total"], 3);
        assert_eq!(snapshot_value["tangle_query_redacted_events_total"], 2);
        assert_eq!(snapshot_value["tangle_count_refusals_total"], 1);
        assert_eq!(snapshot_value["tangle_broad_query_rejections_total"], 1);

        let report = runtime.shutdown().expect("shutdown");

        assert_eq!(report.closed_subscriptions(), 0);
        assert!(runtime.shutdown_signal().requested());
        assert!(*shutdown.borrow());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_metrics_snapshot_serializes_tangle_contract_keys() {
        let metrics = super::TangleRuntimeMetrics::new();
        metrics.record_session_opened();
        metrics.record_auth_success();
        metrics.record_event_admission();
        metrics.record_event_bus_publish(1);
        metrics.record_disk_used_bytes(42);
        let snapshot = metrics.snapshot_with_readiness(true);
        let value = serde_json::to_value(snapshot).expect("snapshot");

        assert_eq!(value["tangle_readiness_ready"], true);
        assert_eq!(value["tangle_ws_connections_current"], 1);
        assert_eq!(value["tangle_subscriptions_current"], 0);
        assert_eq!(value["tangle_auth_success_total"], 1);
        assert_eq!(value["tangle_event_admitted_total"], 1);
        assert_eq!(value["tangle_event_bus_published_offsets_total"], 1);
        assert_eq!(value["tangle_disk_used_bytes"], 42);
        assert_eq!(value["tangle_outbound_queue_full_closes_total"], 0);
        assert_eq!(value["tangle_query_candidates_scanned_total"], 0);
        assert_eq!(value["tangle_query_returned_events_total"], 0);
        assert_eq!(value["tangle_query_redacted_events_total"], 0);
        assert_eq!(value["tangle_count_refusals_total"], 0);
        assert_eq!(value["tangle_broad_query_rejections_total"], 0);
        assert!(value.get("active_sessions").is_none());
        assert!(value.get("stored_event_offsets").is_none());
    }

    #[test]
    fn runtime_limits_and_event_bus_reject_zero_capacity() {
        assert!(TangleRuntimeLimits::new(0, runtime_relay_limits(1), 1, 1).is_err());
        assert!(TangleRuntimeLimits::new(1, runtime_relay_limits(1), 0, 1).is_err());
        assert!(TangleRuntimeLimits::new(1, runtime_relay_limits(1), 1, 0).is_err());
        assert!(TangleEventBus::new(0).is_err());
    }

    #[tokio::test]
    async fn runtime_publishes_stored_event_offsets_for_live_fanout() {
        let root = temp_root("runtime-offset-fanout");
        let _ = std::fs::remove_dir_all(&root);
        let handle =
            RelayRuntimeHandle::new(RelayRuntime::open(runtime_config(&root, 8)).expect("runtime"));
        let mut offsets = handle.subscribe_events().await;
        let mut auth = handle.auth_state().await.expect("auth");
        let mut subscriptions = LiveSubscriptionSet::new(8, 64).expect("subscriptions");
        let subscription_id = SubscriptionId::new("live-offset").expect("subscription");
        subscriptions
            .subscribe(
                subscription_id.clone(),
                vec![pocket_filter(json!({"kinds":[1]}))],
            )
            .expect("subscribe");
        let event = tangle_v2_event(FixtureKey::Member, 1_714_124_433, 1, Vec::new(), "live")
            .expect("event");

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Event(event.clone()),
                    &mut auth,
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("event"),
            vec![RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        let offset = offsets.try_recv().expect("offset");
        assert!(matches!(
            handle
                .fanout_event_offset_with_projection_context(
                    offset,
                    &mut subscriptions,
                    &auth,
                    &RelayProjectionContext::default(),
                )
                .await
                .expect("fanout")
                .as_slice(),
            [RuntimeRelayMessage::Event {
                subscription_id: delivered,
                event: found
            }] if delivered == &subscription_id && found.id().as_hex_string() == event.id().as_str()
        ));

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Event(event.clone()),
                    &mut auth,
                    UnixTimestamp::new(1_714_124_434)
                )
                .await
                .expect("duplicate"),
            vec![RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: true,
                message: "duplicate: already have this event".to_owned()
            }]
        );
        assert_eq!(
            offsets.try_recv().expect_err("no duplicate offset"),
            TangleEventReceiveError::Empty
        );
        let snapshot = handle.metrics().snapshot();
        assert_eq!(snapshot.client_messages(), 2);
        assert_eq!(snapshot.event_messages(), 2);
        assert_eq!(snapshot.stored_event_offsets(), 1);
        assert_eq!(handle.metrics().event_admissions(), 2);
        assert_eq!(handle.metrics().event_bus_receivers_current(), 1);
        assert_eq!(handle.metrics().event_bus_published_offsets(), 1);
        assert_eq!(handle.metrics().event_admission_latency_count(), 2);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_runs_stored_event_hook_before_offset_publish() {
        let root = temp_root("runtime-stored-hook-before-offset-publish");
        let _ = std::fs::remove_dir_all(&root);
        let (started_sender, started_receiver) = mpsc::sync_channel(1);
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        let hooks = Arc::new(BlockingStoredHooks {
            started_sender: Mutex::new(Some(started_sender)),
            release_receiver: Mutex::new(release_receiver),
        });
        let runtime =
            RelayRuntime::open_with_hooks(runtime_config(&root, 8), hooks).expect("runtime");
        let handle = RelayRuntimeHandle::new(runtime);
        let mut offsets = handle.subscribe_events().await;
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            Vec::new(),
            "stored hook before publish",
        )
        .expect("event");
        let task_handle = handle.clone();
        let event_for_task = event.clone();
        let task = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime");
            runtime.block_on(async move {
                let mut auth = task_handle.auth_state().await.expect("auth");
                runtime_event_reply(&task_handle, event_for_task, &mut auth, 1_714_124_433).await
            })
        });

        started_receiver
            .recv_timeout(Duration::from_secs(3))
            .expect("stored hook started");
        assert!(offsets.try_recv().is_err());
        release_sender.send(()).expect("release hook");
        assert_accepted_reply(task.join().expect("event task"), &event);
        offsets.try_recv().expect("offset after hook release");
        handle.shutdown().await.expect("shutdown");

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_hooks_reject_events_and_observe_stored_offsets() {
        let root = temp_root("runtime-hooks");
        let _ = std::fs::remove_dir_all(&root);
        let hooks = Arc::new(RecordingHooks::default());
        let handle = RelayRuntimeHandle::new(
            RelayRuntime::open_with_hooks(runtime_config(&root, 8), hooks.clone())
                .expect("runtime"),
        );
        let mut offsets = handle.subscribe_events().await;
        let mut auth = handle.auth_state().await.expect("auth");
        let rejected = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            vec![Tag::from_parts("policy", &["reject"]).expect("policy")],
            "rejected",
        )
        .expect("rejected event");

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Event(rejected.clone()),
                    &mut auth,
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("rejected"),
            vec![RelayMessage::Ok {
                event_id: rejected.id().clone(),
                accepted: false,
                message: "restricted: hook rejected event".to_owned()
            }]
        );
        assert_eq!(
            offsets.try_recv().expect_err("no rejected offset"),
            TangleEventReceiveError::Empty
        );

        let accepted = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_434,
            1,
            vec![Tag::from_parts("policy", &["accept"]).expect("policy")],
            "accepted",
        )
        .expect("accepted event");

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Event(accepted.clone()),
                    &mut auth,
                    UnixTimestamp::new(1_714_124_434)
                )
                .await
                .expect("accepted"),
            vec![RelayMessage::Ok {
                event_id: accepted.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        assert!(offsets.try_recv().is_ok());
        let admissions = hooks.admissions.lock().expect("admissions");
        assert_eq!(admissions.len(), 2);
        assert_eq!(admissions[0].event().event_id(), rejected.id().as_str());
        assert_eq!(admissions[0].event().created_at(), 1_714_124_433);
        assert_eq!(admissions[1].event().event_id(), accepted.id().as_str());
        assert_eq!(admissions[1].event().created_at(), 1_714_124_434);
        drop(admissions);
        let stored = hooks.stored.lock().expect("stored");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].event().event_id(), accepted.id().as_str());
        assert_eq!(stored[0].event().created_at(), 1_714_124_434);
        assert_eq!(stored[0].store_offsets().len(), 1);
        assert_eq!(handle.metrics().disk_used_bytes(), 144);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_projection_default_keeps_query_and_live_output() {
        let root = temp_root("runtime-projection-default");
        let _ = std::fs::remove_dir_all(&root);
        let handle =
            RelayRuntimeHandle::new(RelayRuntime::open(runtime_config(&root, 8)).expect("runtime"));
        let mut offsets = handle.subscribe_events().await;
        let mut auth = handle.auth_state().await.expect("auth");
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            Vec::new(),
            "default projection",
        )
        .expect("event");

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Event(event.clone()),
                    &mut auth,
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("event"),
            vec![RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        let offset = offsets.try_recv().expect("offset");
        let query_sub = SubscriptionId::new("projection-default-query").expect("subscription");
        let report = handle
            .query_req_with_auth_report_with_projection_context(
                query_sub.clone(),
                vec![pocket_filter(json!({"ids": [event.id().as_str()]}))],
                false,
                &auth,
                &RelayProjectionContext::default(),
            )
            .await
            .expect("query");
        assert!(matches!(
            report.into_messages().as_slice(),
            [
                RuntimeRelayMessage::Event {
                    subscription_id,
                    event: found
                },
                RuntimeRelayMessage::Protocol(RelayMessage::Eose(eose))
            ] if subscription_id == &query_sub
                && found.id().as_hex_string() == event.id().as_str()
                && eose == &query_sub
        ));

        let live_sub = SubscriptionId::new("projection-default-live").expect("subscription");
        let mut subscriptions = LiveSubscriptionSet::new(8, 64).expect("subscriptions");
        subscriptions
            .subscribe(live_sub.clone(), vec![pocket_filter(json!({"kinds": [1]}))])
            .expect("subscribe");
        assert!(matches!(
            handle
                .fanout_event_offset_with_projection_context(
                    offset,
                    &mut subscriptions,
                    &auth,
                    &RelayProjectionContext::default()
                )
                .await
                .expect("fanout")
                .as_slice(),
            [RuntimeRelayMessage::Event {
                subscription_id,
                event: found
            }] if subscription_id == &live_sub && found.id().as_hex_string() == event.id().as_str()
        ));

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_projection_can_suppress_historical_query_events() {
        let root = temp_root("runtime-projection-query-suppress");
        let _ = std::fs::remove_dir_all(&root);
        let hooks = Arc::new(ProjectingHooks::new(
            "quiet",
            ProjectionHookScope::Historical,
            None,
            RelayEventProjectionDecision::Suppress,
        ));
        let handle = RelayRuntimeHandle::new(
            RelayRuntime::open_with_hooks(runtime_config(&root, 8), hooks.clone())
                .expect("runtime"),
        );
        let mut auth = handle.auth_state().await.expect("auth");
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            Vec::new(),
            "suppress query",
        )
        .expect("event");
        assert_accepted_reply(
            runtime_event_reply(&handle, event.clone(), &mut auth, 1_714_124_433).await,
            &event,
        );
        let subscription_id = SubscriptionId::new("query-suppressed").expect("subscription");

        let report = handle
            .query_req_with_auth_report_with_projection_context(
                subscription_id.clone(),
                vec![pocket_filter(json!({"ids": [event.id().as_str()]}))],
                false,
                &auth,
                &RelayProjectionContext::named("quiet").expect("projection"),
            )
            .await
            .expect("query");
        assert_eq!(
            report.into_messages(),
            vec![RuntimeRelayMessage::from(RelayMessage::Eose(
                subscription_id
            ))]
        );
        let contexts = hooks.contexts();
        assert_eq!(contexts.len(), 1);
        assert_eq!(contexts[0].projection().identifier(), Some("quiet"));
        assert_eq!(
            contexts[0].source(),
            RelayEventProjectionSource::HistoricalQuery
        );
        assert_eq!(contexts[0].matched_filter().filter_index(), 0);
        assert_eq!(
            contexts[0].matched_filter().requested_kinds(),
            &RelayRequestedKinds::Absent
        );
        assert_eq!(contexts[0].event().event_id(), event.id().as_str());
        let query_contexts = hooks.query_contexts();
        assert_eq!(query_contexts.len(), 1);
        assert_eq!(
            query_contexts[0].filters()[0].requested_kinds(),
            &RelayRequestedKinds::Absent
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_projection_context_reports_all_matching_query_filters() {
        let root = temp_root("runtime-projection-query-all-matched-filters");
        let _ = std::fs::remove_dir_all(&root);
        let hooks = Arc::new(ProjectingHooks::new(
            "multi-filter",
            ProjectionHookScope::Historical,
            None,
            RelayEventProjectionDecision::Emit,
        ));
        let handle = RelayRuntimeHandle::new(
            RelayRuntime::open_with_hooks(runtime_config(&root, 8), hooks.clone())
                .expect("runtime"),
        );
        let mut auth = handle.auth_state().await.expect("auth");
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            Vec::new(),
            "multi filter query",
        )
        .expect("event");
        assert_accepted_reply(
            runtime_event_reply(&handle, event.clone(), &mut auth, 1_714_124_433).await,
            &event,
        );
        let subscription_id = SubscriptionId::new("query-multi-filter").expect("subscription");

        let report = handle
            .query_req_with_auth_report_with_projection_context(
                subscription_id.clone(),
                vec![
                    pocket_filter(json!({"ids": [event.id().as_str()]})),
                    pocket_filter(json!({"kinds": [1]})),
                ],
                false,
                &auth,
                &RelayProjectionContext::named("multi-filter").expect("projection"),
            )
            .await
            .expect("query");
        assert!(matches!(
            report.into_messages().as_slice(),
            [
                RuntimeRelayMessage::Event {
                    subscription_id: delivered,
                    event: delivered_event
                },
                RuntimeRelayMessage::Protocol(RelayMessage::Eose(eose))
            ] if delivered == &subscription_id
                && delivered_event.id().as_hex_string() == event.id().as_str()
                && eose == &subscription_id
        ));
        let contexts = hooks.contexts();
        assert_eq!(contexts.len(), 1);
        assert_eq!(contexts[0].matched_filter().filter_index(), 0);
        let matched_filters = contexts[0].matched_filters();
        assert_eq!(matched_filters.len(), 2);
        assert_eq!(matched_filters[0].filter_index(), 0);
        assert_eq!(
            matched_filters[0].requested_kinds(),
            &RelayRequestedKinds::Absent
        );
        assert_eq!(matched_filters[1].filter_index(), 1);
        assert_eq!(
            matched_filters[1].requested_kinds(),
            &RelayRequestedKinds::Explicit(BTreeSet::from([1]))
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_projection_post_limit_reports_all_matching_query_filters() {
        let root = temp_root("runtime-projection-post-limit-all-matched-filters");
        let _ = std::fs::remove_dir_all(&root);
        let hooks = Arc::new(ProjectingHooks::new(
            "post-limit-multi-filter",
            ProjectionHookScope::Historical,
            None,
            RelayEventProjectionDecision::Emit,
        ));
        hooks.set_query_plan(RelayProjectionQueryPlan::limit_after_projection(
            NonZeroU32::new(10).expect("candidate limit"),
        ));
        let handle = RelayRuntimeHandle::new(
            RelayRuntime::open_with_hooks(runtime_config(&root, 8), hooks.clone())
                .expect("runtime"),
        );
        let mut auth = handle.auth_state().await.expect("auth");
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            30078,
            Vec::new(),
            "post limit multi filter query",
        )
        .expect("event");
        assert_accepted_reply(
            runtime_event_reply(&handle, event.clone(), &mut auth, 1_714_124_433).await,
            &event,
        );
        let subscription_id =
            SubscriptionId::new("post-limit-query-multi-filter").expect("subscription");

        let report = handle
            .query_req_with_auth_report_with_projection_context(
                subscription_id.clone(),
                vec![
                    pocket_filter(json!({"kinds": [30078]})),
                    pocket_filter(json!({"ids": [event.id().as_str()]})),
                ],
                false,
                &auth,
                &RelayProjectionContext::named("post-limit-multi-filter").expect("projection"),
            )
            .await
            .expect("query");
        assert!(matches!(
            report.into_messages().as_slice(),
            [
                RuntimeRelayMessage::Event {
                    subscription_id: delivered,
                    event: delivered_event
                },
                RuntimeRelayMessage::Protocol(RelayMessage::Eose(eose))
            ] if delivered == &subscription_id
                && delivered_event.id().as_hex_string() == event.id().as_str()
                && eose == &subscription_id
        ));
        let contexts = hooks.contexts();
        assert_eq!(contexts.len(), 2);
        for context in contexts {
            let matched_filters = context.matched_filters();
            assert_eq!(matched_filters.len(), 2);
            assert_eq!(matched_filters[0].filter_index(), 0);
            assert_eq!(
                matched_filters[0].requested_kinds(),
                &RelayRequestedKinds::Explicit(BTreeSet::from([30078]))
            );
            assert_eq!(matched_filters[1].filter_index(), 1);
            assert_eq!(
                matched_filters[1].requested_kinds(),
                &RelayRequestedKinds::Absent
            );
        }

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_projection_can_suppress_live_fanout_events() {
        let root = temp_root("runtime-projection-live-suppress");
        let _ = std::fs::remove_dir_all(&root);
        let hooks = Arc::new(ProjectingHooks::new(
            "quiet-live",
            ProjectionHookScope::Live,
            None,
            RelayEventProjectionDecision::Suppress,
        ));
        let handle = RelayRuntimeHandle::new(
            RelayRuntime::open_with_hooks(runtime_config(&root, 8), hooks.clone())
                .expect("runtime"),
        );
        let mut offsets = handle.subscribe_events().await;
        let mut auth = handle.auth_state().await.expect("auth");
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            Vec::new(),
            "suppress live",
        )
        .expect("event");
        assert_accepted_reply(
            runtime_event_reply(&handle, event.clone(), &mut auth, 1_714_124_433).await,
            &event,
        );
        let offset = offsets.try_recv().expect("offset");
        let mut subscriptions = LiveSubscriptionSet::new(8, 64).expect("subscriptions");
        subscriptions
            .subscribe(
                SubscriptionId::new("live-suppressed").expect("subscription"),
                vec![pocket_filter(json!({"kinds": [1]}))],
            )
            .expect("subscribe");

        assert!(
            handle
                .fanout_event_offset_with_projection_context(
                    offset,
                    &mut subscriptions,
                    &auth,
                    &RelayProjectionContext::named("quiet-live").expect("projection")
                )
                .await
                .expect("fanout")
                .is_empty()
        );
        let contexts = hooks.contexts();
        assert_eq!(contexts.len(), 1);
        assert_eq!(contexts[0].projection().identifier(), Some("quiet-live"));
        assert_eq!(
            contexts[0].source(),
            RelayEventProjectionSource::LiveFanout {
                store_offset: offset.as_u64()
            }
        );
        assert_eq!(contexts[0].matched_filter().filter_index(), 0);
        assert_eq!(
            contexts[0].matched_filter().requested_kinds(),
            &RelayRequestedKinds::Explicit(BTreeSet::from([1]))
        );
        assert_eq!(contexts[0].event().event_id(), event.id().as_str());

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_projection_contexts_include_authenticated_pubkeys() {
        let root = temp_root("runtime-projection-authenticated-pubkeys");
        let _ = std::fs::remove_dir_all(&root);
        let hooks = Arc::new(ProjectingHooks::new(
            "auth-context",
            ProjectionHookScope::Historical,
            None,
            RelayEventProjectionDecision::Emit,
        ));
        let handle = RelayRuntimeHandle::new(
            RelayRuntime::open_with_hooks(runtime_config(&root, 8), hooks.clone())
                .expect("runtime"),
        );
        let mut offsets = handle.subscribe_events().await;
        let mut auth =
            authenticated_runtime_state(&handle, FixtureKey::Owner, "challenge-auth-context", 100)
                .await;
        let expected_pubkeys = auth
            .authenticated_pubkeys()
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            Vec::new(),
            "authenticated projection context",
        )
        .expect("event");
        assert_accepted_reply(
            runtime_event_reply(&handle, event.clone(), &mut auth, 1_714_124_433).await,
            &event,
        );
        let offset = offsets.try_recv().expect("offset");
        let query_sub = SubscriptionId::new("query-auth-context").expect("subscription");
        let projection = RelayProjectionContext::named("auth-context").expect("projection");

        let report = handle
            .query_req_with_auth_report_with_projection_context(
                query_sub.clone(),
                vec![pocket_filter(json!({"ids": [event.id().as_str()]}))],
                false,
                &auth,
                &projection,
            )
            .await
            .expect("query");
        assert!(matches!(
            report.into_messages().as_slice(),
            [
                RuntimeRelayMessage::Event {
                    subscription_id,
                    event: found
                },
                RuntimeRelayMessage::Protocol(RelayMessage::Eose(eose))
            ] if subscription_id == &query_sub
                && found.id().as_hex_string() == event.id().as_str()
                && eose == &query_sub
        ));

        let mut subscriptions = LiveSubscriptionSet::new(8, 64).expect("subscriptions");
        subscriptions
            .subscribe(
                SubscriptionId::new("live-auth-context").expect("subscription"),
                vec![pocket_filter(json!({"kinds": [1]}))],
            )
            .expect("subscribe");
        assert_eq!(
            handle
                .fanout_event_offset_with_projection_context(
                    offset,
                    &mut subscriptions,
                    &auth,
                    &projection,
                )
                .await
                .expect("fanout")
                .len(),
            1
        );

        let query_contexts = hooks.query_contexts();
        assert_eq!(query_contexts.len(), 1);
        assert_eq!(
            query_contexts[0].authenticated_pubkeys(),
            expected_pubkeys.as_slice()
        );
        let live_contexts = hooks.live_contexts();
        assert_eq!(live_contexts.len(), 1);
        assert_eq!(
            live_contexts[0].authenticated_pubkeys(),
            expected_pubkeys.as_slice()
        );
        let contexts = hooks.contexts();
        assert_eq!(contexts.len(), 2);
        assert_eq!(
            contexts[0].source(),
            RelayEventProjectionSource::HistoricalQuery
        );
        assert_eq!(
            contexts[0].authenticated_pubkeys(),
            expected_pubkeys.as_slice()
        );
        assert_eq!(
            contexts[1].source(),
            RelayEventProjectionSource::LiveFanout {
                store_offset: offset.as_u64()
            }
        );
        assert_eq!(
            contexts[1].authenticated_pubkeys(),
            expected_pubkeys.as_slice()
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_projection_replaces_with_existing_stored_events_only() {
        let root = temp_root("runtime-projection-replace");
        let _ = std::fs::remove_dir_all(&root);
        let hooks = Arc::new(ProjectingHooks::new(
            "replace",
            ProjectionHookScope::Historical,
            Some("source"),
            RelayEventProjectionDecision::Emit,
        ));
        let handle = RelayRuntimeHandle::new(
            RelayRuntime::open_with_hooks(runtime_config(&root, 8), hooks.clone())
                .expect("runtime"),
        );
        let mut offsets = handle.subscribe_events().await;
        let mut auth = handle.auth_state().await.expect("auth");
        let source = tangle_v2_event(FixtureKey::Member, 1_714_124_433, 1, Vec::new(), "source")
            .expect("source");
        let replacement = tangle_v2_event(
            FixtureKey::Admin,
            1_714_124_434,
            1,
            Vec::new(),
            "replacement",
        )
        .expect("replacement");
        assert_accepted_reply(
            runtime_event_reply(&handle, source.clone(), &mut auth, 1_714_124_433).await,
            &source,
        );
        let _source_offset = offsets.try_recv().expect("source offset");
        assert_accepted_reply(
            runtime_event_reply(&handle, replacement.clone(), &mut auth, 1_714_124_434).await,
            &replacement,
        );
        let replacement_offset = offsets.try_recv().expect("replacement offset");
        hooks.set_decision(RelayEventProjectionDecision::replace_with_stored_offset(
            replacement_offset.as_u64(),
        ));
        let subscription_id = SubscriptionId::new("replace-existing").expect("subscription");

        let report = handle
            .query_req_with_auth_report_with_projection_context(
                subscription_id.clone(),
                vec![pocket_filter(json!({"kinds": [1]}))],
                false,
                &auth,
                &RelayProjectionContext::named("replace").expect("projection"),
            )
            .await
            .expect("query");
        assert!(matches!(
            report.into_messages().as_slice(),
            [
                RuntimeRelayMessage::Event {
                    subscription_id: delivered,
                    event
                },
                RuntimeRelayMessage::Protocol(RelayMessage::Eose(eose))
            ] if delivered == &subscription_id
                && event.id().as_hex_string() == replacement.id().as_str()
                && eose == &subscription_id
        ));

        hooks.set_decision(RelayEventProjectionDecision::replace_with_stored_offset(
            u64::MAX,
        ));
        let missing_subscription = SubscriptionId::new("replace-missing").expect("subscription");
        let report = handle
            .query_req_with_auth_report_with_projection_context(
                missing_subscription.clone(),
                vec![pocket_filter(json!({"ids": [source.id().as_str()]}))],
                false,
                &auth,
                &RelayProjectionContext::named("replace").expect("projection"),
            )
            .await
            .expect("missing query");
        assert_eq!(
            report.into_messages(),
            vec![RuntimeRelayMessage::from(RelayMessage::Eose(
                missing_subscription
            ))]
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_projection_can_apply_query_limit_after_projection() {
        let root = temp_root("runtime-projection-post-limit");
        let _ = std::fs::remove_dir_all(&root);
        let hooks = Arc::new(ProjectingHooks::new(
            "post-limit",
            ProjectionHookScope::Historical,
            Some("drop"),
            RelayEventProjectionDecision::Suppress,
        ));
        hooks.set_query_plan(RelayProjectionQueryPlan::limit_after_projection(
            NonZeroU32::new(2).expect("candidate limit"),
        ));
        let handle = RelayRuntimeHandle::new(
            RelayRuntime::open_with_hooks(runtime_config(&root, 8), hooks.clone())
                .expect("runtime"),
        );
        let mut auth = handle.auth_state().await.expect("auth");
        let dropped = tangle_v2_event(FixtureKey::Member, 1_714_124_435, 1, Vec::new(), "drop")
            .expect("drop");
        let kept =
            tangle_v2_event(FixtureKey::Admin, 1_714_124_434, 1, Vec::new(), "keep").expect("keep");
        assert_accepted_reply(
            runtime_event_reply(&handle, kept.clone(), &mut auth, 1_714_124_434).await,
            &kept,
        );
        assert_accepted_reply(
            runtime_event_reply(&handle, dropped.clone(), &mut auth, 1_714_124_435).await,
            &dropped,
        );
        let subscription_id = SubscriptionId::new("post-limit").expect("subscription");

        let report = handle
            .query_req_with_auth_report_with_projection_context(
                subscription_id.clone(),
                vec![pocket_filter(json!({"kinds": [1], "limit": 1}))],
                false,
                &auth,
                &RelayProjectionContext::named("post-limit").expect("projection"),
            )
            .await
            .expect("query");
        assert!(matches!(
            report.into_messages().as_slice(),
            [
                RuntimeRelayMessage::Event {
                    subscription_id: delivered,
                    event
                },
                RuntimeRelayMessage::Protocol(RelayMessage::Eose(eose))
            ] if delivered == &subscription_id
                && event.id().as_hex_string() == kept.id().as_str()
                && eose == &subscription_id
        ));
        let query_contexts = hooks.query_contexts();
        assert_eq!(query_contexts.len(), 1);
        assert_eq!(
            query_contexts[0].filters()[0].requested_kinds(),
            &RelayRequestedKinds::Explicit(BTreeSet::from([1]))
        );
        assert_eq!(hooks.contexts().len(), 2);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_projection_live_replacement_must_match_original_filter() {
        let root = temp_root("runtime-projection-live-replace-rematch");
        let _ = std::fs::remove_dir_all(&root);
        let hooks = Arc::new(ProjectingHooks::new(
            "live-replace",
            ProjectionHookScope::Live,
            Some("source"),
            RelayEventProjectionDecision::Emit,
        ));
        let handle = RelayRuntimeHandle::new(
            RelayRuntime::open_with_hooks(runtime_config(&root, 8), hooks.clone())
                .expect("runtime"),
        );
        let mut offsets = handle.subscribe_events().await;
        let mut auth = handle.auth_state().await.expect("auth");
        let source = tangle_v2_event(FixtureKey::Member, 1_714_124_433, 7, Vec::new(), "source")
            .expect("source");
        let replacement = tangle_v2_event(
            FixtureKey::Admin,
            1_714_124_434,
            1,
            Vec::new(),
            "replacement",
        )
        .expect("replacement");
        assert_accepted_reply(
            runtime_event_reply(&handle, source.clone(), &mut auth, 1_714_124_433).await,
            &source,
        );
        let source_offset = offsets.try_recv().expect("source offset");
        assert_accepted_reply(
            runtime_event_reply(&handle, replacement.clone(), &mut auth, 1_714_124_434).await,
            &replacement,
        );
        let replacement_offset = offsets.try_recv().expect("replacement offset");
        hooks.set_decision(RelayEventProjectionDecision::replace_with_stored_offset(
            replacement_offset.as_u64(),
        ));
        let mut subscriptions = LiveSubscriptionSet::new(8, 64).expect("subscriptions");
        let source_only = SubscriptionId::new("source-only").expect("source subscription");
        let source_or_note = SubscriptionId::new("source-or-note").expect("mixed subscription");
        subscriptions
            .subscribe(source_only, vec![pocket_filter(json!({"kinds": [7]}))])
            .expect("source subscribe");
        subscriptions
            .subscribe(
                source_or_note.clone(),
                vec![pocket_filter(json!({"kinds": [1, 7]}))],
            )
            .expect("mixed subscribe");

        let messages = handle
            .fanout_event_offset_with_projection_context(
                source_offset,
                &mut subscriptions,
                &auth,
                &RelayProjectionContext::named("live-replace").expect("projection"),
            )
            .await
            .expect("fanout");
        assert!(matches!(
            messages.as_slice(),
            [RuntimeRelayMessage::Event {
                subscription_id,
                event
            }] if subscription_id == &source_or_note
                && event.id().as_hex_string() == replacement.id().as_str()
        ));
        let contexts = hooks.contexts();
        assert_eq!(contexts.len(), 2);
        assert_eq!(
            contexts[0].matched_filter().requested_kinds(),
            &RelayRequestedKinds::Explicit(BTreeSet::from([7]))
        );
        assert_eq!(
            contexts[1].matched_filter().requested_kinds(),
            &RelayRequestedKinds::Explicit(BTreeSet::from([1, 7]))
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_projection_live_candidates_match_candidate_filter() {
        let root = temp_root("runtime-projection-live-candidate");
        let _ = std::fs::remove_dir_all(&root);
        let hooks = Arc::new(ProjectingHooks::new(
            "live-candidate",
            ProjectionHookScope::Live,
            None,
            RelayEventProjectionDecision::Emit,
        ));
        let handle = RelayRuntimeHandle::new(
            RelayRuntime::open_with_hooks(runtime_config(&root, 8), hooks.clone())
                .expect("runtime"),
        );
        let mut offsets = handle.subscribe_events().await;
        let mut auth = handle.auth_state().await.expect("auth");
        let source = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            30078,
            Vec::new(),
            "source",
        )
        .expect("source");
        let candidate =
            tangle_v2_event(FixtureKey::Admin, 1_714_124_434, 1, Vec::new(), "candidate")
                .expect("candidate");
        assert_accepted_reply(
            runtime_event_reply(&handle, source.clone(), &mut auth, 1_714_124_433).await,
            &source,
        );
        let source_offset = offsets.try_recv().expect("source offset");
        assert_accepted_reply(
            runtime_event_reply(&handle, candidate.clone(), &mut auth, 1_714_124_434).await,
            &candidate,
        );
        let candidate_offset = offsets.try_recv().expect("candidate offset");
        hooks.set_live_candidates(vec![RelayLiveProjectionCandidate::stored_offset(
            candidate_offset.as_u64(),
        )]);
        let mut subscriptions = LiveSubscriptionSet::new(8, 64).expect("subscriptions");
        let subscription_id = SubscriptionId::new("candidate-note").expect("subscription");
        subscriptions
            .subscribe(
                subscription_id.clone(),
                vec![pocket_filter(json!({"kinds": [1]}))],
            )
            .expect("subscribe");

        let messages = handle
            .fanout_event_offset_with_projection_context(
                source_offset,
                &mut subscriptions,
                &auth,
                &RelayProjectionContext::named("live-candidate").expect("projection"),
            )
            .await
            .expect("fanout");

        assert!(matches!(
            messages.as_slice(),
            [RuntimeRelayMessage::Event {
                subscription_id: delivered,
                event
            }] if delivered == &subscription_id
                && event.id().as_hex_string() == candidate.id().as_str()
        ));
        let live_contexts = hooks.live_contexts();
        assert_eq!(live_contexts.len(), 1);
        assert_eq!(
            live_contexts[0].source_store_offset(),
            source_offset.as_u64()
        );
        assert_eq!(live_contexts[0].event().event_id(), source.id().as_str());
        let contexts = hooks.contexts();
        assert_eq!(contexts.len(), 1);
        assert_eq!(contexts[0].event().event_id(), candidate.id().as_str());
        assert_eq!(
            contexts[0].matched_filter().requested_kinds(),
            &RelayRequestedKinds::Explicit(BTreeSet::from([1]))
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_projection_runs_after_group_read_gates() {
        let root = temp_root("runtime-projection-group-gate");
        let _ = std::fs::remove_dir_all(&root);
        let hooks = Arc::new(ProjectingHooks::new(
            "group-gate",
            ProjectionHookScope::Historical,
            None,
            RelayEventProjectionDecision::Suppress,
        ));
        let handle = RelayRuntimeHandle::new(
            RelayRuntime::open_with_hooks(runtime_config(&root, 8), hooks.clone())
                .expect("runtime"),
        );
        let mut owner_auth =
            authenticated_runtime_state(&handle, FixtureKey::Owner, "group-gate-owner", 120).await;
        let public_auth = handle.auth_state().await.expect("public auth");
        let create =
            tangle_v2_group_create_event(FixtureKey::Owner, "ProjectionPrivate", 121, &["private"])
                .expect("create");
        assert_accepted_reply(
            runtime_event_reply(&handle, create.clone(), &mut owner_auth, 121).await,
            &create,
        );
        let private_event = tangle_v2_group_event(
            FixtureKey::Owner,
            "ProjectionPrivate",
            122,
            1,
            "private projection",
        )
        .expect("private event");
        assert_accepted_reply(
            runtime_event_reply(&handle, private_event.clone(), &mut owner_auth, 122).await,
            &private_event,
        );
        let subscription_id = SubscriptionId::new("group-gate").expect("subscription");

        let report = handle
            .query_req_with_auth_report_with_projection_context(
                subscription_id.clone(),
                vec![pocket_filter(json!({
                    "kinds": [1],
                    "#h": ["ProjectionPrivate"]
                }))],
                false,
                &public_auth,
                &RelayProjectionContext::named("group-gate").expect("projection"),
            )
            .await
            .expect("query");
        assert_eq!(
            report.into_messages(),
            vec![RuntimeRelayMessage::from(RelayMessage::Closed {
                subscription_id,
                message: "auth-required: authentication required to read group events".to_owned()
            })]
        );
        assert!(hooks.contexts().is_empty());

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_rate_limits_event_pubkeys_before_storage() {
        let root = temp_root("runtime-event-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let event = tangle_v2_event(FixtureKey::Member, 1_714_124_433, 1, Vec::new(), "limited")
            .expect("event");
        let rule = runtime.config().rate_limits().event().per_pubkey();
        let key = TangleRateLimitKey::pubkey(
            TangleRateLimitScope::Event,
            event.unsigned().pubkey().clone(),
        );
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Event(event.clone()),
                    &mut auth,
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("event"),
            vec![RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: false,
                message: "rate-limited: event pubkey rate limit exceeded until 1714124493"
                    .to_owned()
            }]
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_rate_limits_event_kinds_before_storage() {
        let root = temp_root("runtime-event-kind-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let event = tangle_v2_event(FixtureKey::Admin, 1_714_124_433, 1, Vec::new(), "limited")
            .expect("event");
        let rule = runtime.config().rate_limits().event().per_kind();
        let key = TangleRateLimitKey::kind(TangleRateLimitScope::Event, event.unsigned().kind());
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Event(event.clone()),
                    &mut auth,
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("event"),
            vec![RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: false,
                message: "rate-limited: event kind rate limit exceeded until 1714124493".to_owned()
            }]
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_rate_limits_event_peer_ips_partition_peers_and_precede_identity_keys() {
        let root = temp_root("runtime-event-ip-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let rule = runtime.config().rate_limits().event().per_ip();
        let saturated_peer_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 20));
        let other_peer_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 21));
        let key = TangleRateLimitKey::ip(TangleRateLimitScope::Event, saturated_peer_ip);
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let limited_event =
            tangle_v2_event(FixtureKey::Member, 1_714_124_433, 1, Vec::new(), "limited")
                .expect("limited event");
        let rotated_event =
            tangle_v2_event(FixtureKey::Admin, 1_714_124_434, 2, Vec::new(), "rotated")
                .expect("rotated event");
        let allowed_event =
            tangle_v2_event(FixtureKey::Owner, 1_714_124_435, 2, Vec::new(), "allowed")
                .expect("allowed event");
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");

        assert_eq!(
            handle
                .handle_protocol_client_message_with_rate_limit_context_for_test(
                    ClientMessage::Event(limited_event.clone()),
                    &mut auth,
                    TangleClientRateLimitContext::new(Some(saturated_peer_ip), None),
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("event"),
            vec![RelayMessage::Ok {
                event_id: limited_event.id().clone(),
                accepted: false,
                message: "rate-limited: event ip rate limit exceeded until 1714124493".to_owned()
            }]
        );
        assert_eq!(
            handle
                .handle_protocol_client_message_with_rate_limit_context_for_test(
                    ClientMessage::Event(rotated_event.clone()),
                    &mut auth,
                    TangleClientRateLimitContext::new(Some(saturated_peer_ip), None),
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("event"),
            vec![RelayMessage::Ok {
                event_id: rotated_event.id().clone(),
                accepted: false,
                message: "rate-limited: event ip rate limit exceeded until 1714124493".to_owned()
            }]
        );
        assert_eq!(
            handle
                .handle_protocol_client_message_with_rate_limit_context_for_test(
                    ClientMessage::Event(allowed_event.clone()),
                    &mut auth,
                    TangleClientRateLimitContext::new(Some(other_peer_ip), None),
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("event"),
            vec![RelayMessage::Ok {
                event_id: allowed_event.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        assert_eq!(handle.metrics().rate_limit_rejections(), 2);
        assert_eq!(handle.metrics().event_rejections(), 2);
        assert_eq!(handle.metrics().event_admissions(), 1);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_rate_limits_auth_pubkeys_before_authentication() {
        let root = temp_root("runtime-auth-pubkey-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let auth_event =
            tangle_v2_auth_event(FixtureKey::Member, "challenge-a", 120).expect("auth event");
        let rule = runtime.config().rate_limits().auth().per_pubkey();
        let key = TangleRateLimitKey::pubkey(
            TangleRateLimitScope::Auth,
            auth_event.unsigned().pubkey().clone(),
        );
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(120));
        }
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");
        auth.issue_challenge("challenge-a", UnixTimestamp::new(100))
            .expect("challenge");

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Auth(auth_event.clone()),
                    &mut auth,
                    UnixTimestamp::new(120)
                )
                .await
                .expect("auth"),
            vec![RelayMessage::Ok {
                event_id: auth_event.id().clone(),
                accepted: false,
                message: "rate-limited: auth pubkey rate limit exceeded until 180".to_owned()
            }]
        );
        assert!(auth.authenticated_pubkeys().is_empty());

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_rate_limits_auth_peer_ips_before_authentication() {
        let root = temp_root("runtime-auth-ip-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let auth_event =
            tangle_v2_auth_event(FixtureKey::Member, "challenge-a", 120).expect("auth event");
        let rule = runtime.config().rate_limits().auth().per_ip();
        let peer_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 30));
        let key = TangleRateLimitKey::ip(TangleRateLimitScope::Auth, peer_ip);
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(120));
        }
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");
        auth.issue_challenge("challenge-a", UnixTimestamp::new(100))
            .expect("challenge");

        assert_eq!(
            handle
                .handle_protocol_client_message_with_rate_limit_context_for_test(
                    ClientMessage::Auth(auth_event.clone()),
                    &mut auth,
                    TangleClientRateLimitContext::new(Some(peer_ip), None),
                    UnixTimestamp::new(120)
                )
                .await
                .expect("auth"),
            vec![RelayMessage::Ok {
                event_id: auth_event.id().clone(),
                accepted: false,
                message: "rate-limited: auth ip rate limit exceeded until 180".to_owned()
            }]
        );
        assert!(auth.authenticated_pubkeys().is_empty());
        assert_eq!(handle.metrics().rate_limit_rejections(), 1);
        assert_eq!(handle.metrics().auth_failures(), 1);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_rate_limits_auth_failures() {
        let root = temp_root("runtime-auth-failure-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let auth_event = tangle_v2_event(FixtureKey::Member, 1_714_124_433, 22_242, Vec::new(), "")
            .expect("auth event");
        let key =
            TangleRateLimitKey::auth_failure(None, Some(auth_event.unsigned().pubkey().clone()));
        let rule = runtime.config().rate_limits().auth().failures();
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Auth(auth_event.clone()),
                    &mut auth,
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("auth"),
            vec![RelayMessage::Ok {
                event_id: auth_event.id().clone(),
                accepted: false,
                message: "rate-limited: auth failure rate limit exceeded until 1714124733"
                    .to_owned()
            }]
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_rate_limits_auth_failures_by_peer_ip() {
        let root = temp_root("runtime-auth-failure-ip-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let auth_event = tangle_v2_event(FixtureKey::Admin, 1_714_124_433, 22_242, Vec::new(), "")
            .expect("auth event");
        let peer_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 31));
        let key = TangleRateLimitKey::auth_failure(Some(peer_ip), None);
        let rule = runtime.config().rate_limits().auth().failures_per_ip();
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");

        assert_eq!(
            handle
                .handle_protocol_client_message_with_rate_limit_context_for_test(
                    ClientMessage::Auth(auth_event.clone()),
                    &mut auth,
                    TangleClientRateLimitContext::new(Some(peer_ip), None),
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("auth"),
            vec![RelayMessage::Ok {
                event_id: auth_event.id().clone(),
                accepted: false,
                message: "rate-limited: auth failure ip rate limit exceeded until 1714124733"
                    .to_owned()
            }]
        );
        assert_eq!(handle.metrics().rate_limit_rejections(), 1);
        assert_eq!(handle.metrics().auth_failures(), 1);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_preserves_chorus_auth_failure_rate_limit_parity() {
        let root = temp_root("runtime-chorus-auth-rate-limit-parity");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let pubkey_event =
            tangle_v2_event(FixtureKey::Member, 1_714_124_433, 22_242, Vec::new(), "")
                .expect("pubkey auth event");
        let pubkey_rule = runtime.config().rate_limits().auth().failures();
        let pubkey_key =
            TangleRateLimitKey::auth_failure(None, Some(pubkey_event.unsigned().pubkey().clone()));
        for _ in 0..pubkey_rule.max_hits() {
            runtime.rate_limiter().record(
                pubkey_key.clone(),
                pubkey_rule,
                UnixTimestamp::new(1_714_124_433),
            );
        }
        let peer_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 41));
        let peer_event = tangle_v2_event(FixtureKey::Admin, 1_714_124_434, 22_242, Vec::new(), "")
            .expect("peer auth event");
        let peer_rule = runtime.config().rate_limits().auth().failures_per_ip();
        let peer_key = TangleRateLimitKey::auth_failure(Some(peer_ip), None);
        for _ in 0..peer_rule.max_hits() {
            runtime.rate_limiter().record(
                peer_key.clone(),
                peer_rule,
                UnixTimestamp::new(1_714_124_434),
            );
        }
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Auth(pubkey_event.clone()),
                    &mut auth,
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("pubkey failure"),
            vec![RelayMessage::Ok {
                event_id: pubkey_event.id().clone(),
                accepted: false,
                message: "rate-limited: auth failure rate limit exceeded until 1714124733"
                    .to_owned()
            }]
        );
        assert_eq!(
            handle
                .handle_protocol_client_message_with_rate_limit_context_for_test(
                    ClientMessage::Auth(peer_event.clone()),
                    &mut auth,
                    TangleClientRateLimitContext::new(Some(peer_ip), None),
                    UnixTimestamp::new(1_714_124_434)
                )
                .await
                .expect("peer failure"),
            vec![RelayMessage::Ok {
                event_id: peer_event.id().clone(),
                accepted: false,
                message: "rate-limited: auth failure ip rate limit exceeded until 1714124734"
                    .to_owned()
            }]
        );
        assert!(auth.authenticated_pubkeys().is_empty());
        let snapshot = handle.metrics().snapshot();
        assert_eq!(snapshot.client_messages(), 2);
        assert_eq!(snapshot.auth_messages(), 2);
        assert_eq!(snapshot.rate_limit_rejections(), 2);
        assert_eq!(handle.metrics().auth_successes(), 0);
        assert_eq!(handle.metrics().auth_failures(), 2);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_rate_limits_group_writes_by_pubkey() {
        let root = temp_root("runtime-group-pubkey-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            vec![Tag::from_parts("h", &["Farm"]).expect("h")],
            "limited",
        )
        .expect("event");
        let rule = runtime.config().rate_limits().group().write_per_pubkey();
        let key = TangleRateLimitKey::pubkey(
            TangleRateLimitScope::GroupWrite,
            event.unsigned().pubkey().clone(),
        );
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Event(event.clone()),
                    &mut auth,
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("event"),
            vec![RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: false,
                message: "rate-limited: group pubkey rate limit exceeded until 1714124493"
                    .to_owned()
            }]
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_rate_limits_group_writes_by_peer_ip() {
        let root = temp_root("runtime-group-ip-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            vec![Tag::from_parts("h", &["Farm"]).expect("h")],
            "limited",
        )
        .expect("event");
        let rule = runtime.config().rate_limits().group().write_per_ip();
        let peer_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 40));
        let key = TangleRateLimitKey::ip(TangleRateLimitScope::GroupWrite, peer_ip);
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");

        assert_eq!(
            handle
                .handle_protocol_client_message_with_rate_limit_context_for_test(
                    ClientMessage::Event(event.clone()),
                    &mut auth,
                    TangleClientRateLimitContext::new(Some(peer_ip), None),
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("event"),
            vec![RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: false,
                message: "rate-limited: group ip rate limit exceeded until 1714124493".to_owned()
            }]
        );
        assert_eq!(handle.metrics().rate_limit_rejections(), 1);
        assert_eq!(handle.metrics().event_rejections(), 1);
        assert_eq!(handle.metrics().group_write_denials(), 1);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_rate_limits_group_writes_by_group_id() {
        let root = temp_root("runtime-group-write-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let group_id = GroupId::new("Farm").expect("group");
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            vec![Tag::from_parts("h", &[group_id.as_str()]).expect("h")],
            "limited",
        )
        .expect("event");
        let rule = runtime.config().rate_limits().group().write_per_group();
        let key = TangleRateLimitKey::group(TangleRateLimitScope::GroupWrite, group_id);
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Event(event.clone()),
                    &mut auth,
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("event"),
            vec![RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: false,
                message: "rate-limited: group write rate limit exceeded until 1714124493"
                    .to_owned()
            }]
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_rate_limits_group_writes_by_kind() {
        let root = temp_root("runtime-group-kind-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            vec![Tag::from_parts("h", &["Farm"]).expect("h")],
            "limited",
        )
        .expect("event");
        let rule = runtime.config().rate_limits().group().write_per_kind();
        let key =
            TangleRateLimitKey::kind(TangleRateLimitScope::GroupWrite, event.unsigned().kind());
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Event(event.clone()),
                    &mut auth,
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("event"),
            vec![RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: false,
                message: "rate-limited: group kind rate limit exceeded until 1714124493".to_owned()
            }]
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_rate_limits_group_join_flows() {
        let root = temp_root("runtime-group-join-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let group_id = GroupId::new("Farm").expect("group");
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            KIND_GROUP_JOIN_REQUEST.into(),
            vec![Tag::from_parts("h", &[group_id.as_str()]).expect("h")],
            "",
        )
        .expect("event");
        let rule = runtime.config().rate_limits().group().join_flow();
        let key = TangleRateLimitKey::join_flow(group_id, event.unsigned().pubkey().clone());
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Event(event.clone()),
                    &mut auth,
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("event"),
            vec![RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: false,
                message: "rate-limited: group join rate limit exceeded until 1714124733".to_owned()
            }]
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_rate_limits_group_join_flows_by_peer_ip() {
        let root = temp_root("runtime-group-join-ip-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let group_id = GroupId::new("Farm").expect("group");
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            KIND_GROUP_JOIN_REQUEST.into(),
            vec![Tag::from_parts("h", &[group_id.as_str()]).expect("h")],
            "",
        )
        .expect("event");
        let rule = runtime.config().rate_limits().group().join_flow_per_ip();
        let peer_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 41));
        let key = TangleRateLimitKey::join_flow_ip(group_id, peer_ip);
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");

        assert_eq!(
            handle
                .handle_protocol_client_message_with_rate_limit_context_for_test(
                    ClientMessage::Event(event.clone()),
                    &mut auth,
                    TangleClientRateLimitContext::new(Some(peer_ip), None),
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("event"),
            vec![RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: false,
                message: "rate-limited: group join ip rate limit exceeded until 1714124733"
                    .to_owned()
            }]
        );
        assert_eq!(handle.metrics().rate_limit_rejections(), 1);
        assert_eq!(handle.metrics().event_rejections(), 1);
        assert_eq!(handle.metrics().group_write_denials(), 1);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_rate_limits_req_authenticated_pubkeys() {
        let root = temp_root("runtime-req-pubkey-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let rule = runtime.config().rate_limits().req().per_pubkey();
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");
        auth.issue_challenge("challenge-a", UnixTimestamp::new(100))
            .expect("challenge");
        let auth_event =
            tangle_v2_auth_event(FixtureKey::Member, "challenge-a", 120).expect("auth event");

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Auth(auth_event.clone()),
                    &mut auth,
                    UnixTimestamp::new(120)
                )
                .await
                .expect("auth"),
            vec![RelayMessage::Ok {
                event_id: auth_event.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        let key =
            TangleRateLimitKey::pubkey(TangleRateLimitScope::Req, FixtureKey::Member.public_key());
        let limiter = handle.rate_limiter().await;
        for _ in 0..rule.max_hits() {
            limiter.record(key.clone(), rule, UnixTimestamp::new(120));
        }
        let subscription_id = SubscriptionId::new("limited-req-pubkey").expect("subscription");
        let filters = vec![filter_from_value(&json!({"limit": 1})).expect("filter")];

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Req {
                        subscription_id: subscription_id.clone(),
                        filters
                    },
                    &mut auth,
                    UnixTimestamp::new(120)
                )
                .await
                .expect("req"),
            vec![RelayMessage::Closed {
                subscription_id,
                message: "rate-limited: req pubkey rate limit exceeded until 180".to_owned()
            }]
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_rate_limits_req_connections() {
        let root = temp_root("runtime-req-connection-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let rule = runtime.config().rate_limits().req().per_connection();
        let key = TangleRateLimitKey::connection(TangleRateLimitScope::Req, 77);
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");
        let subscription_id = SubscriptionId::new("limited-req-connection").expect("subscription");
        let filters = vec![filter_from_value(&json!({"kinds": [1], "limit": 1})).expect("filter")];

        assert_eq!(
            handle
                .handle_protocol_client_message_with_rate_limit_context_for_test(
                    ClientMessage::Req {
                        subscription_id: subscription_id.clone(),
                        filters
                    },
                    &mut auth,
                    TangleClientRateLimitContext::new(None, Some(77)),
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("req"),
            vec![RelayMessage::Closed {
                subscription_id,
                message: "rate-limited: req connection rate limit exceeded until 1714124493"
                    .to_owned()
            }]
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_rate_limits_req_filter_groups() {
        let root = temp_root("runtime-req-group-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let group_id = GroupId::new("Farm").expect("group");
        let rule = runtime.config().rate_limits().req().per_group();
        let key = TangleRateLimitKey::group(TangleRateLimitScope::Req, group_id);
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");
        let subscription_id = SubscriptionId::new("limited-req-group").expect("subscription");
        let filters =
            vec![filter_from_value(&json!({"#h": ["Farm"], "limit": 1})).expect("filter")];

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Req {
                        subscription_id: subscription_id.clone(),
                        filters
                    },
                    &mut auth,
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("req"),
            vec![RelayMessage::Closed {
                subscription_id,
                message: "rate-limited: req group rate limit exceeded until 1714124493".to_owned()
            }]
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn query_classifier_identifies_broad_count_shapes() {
        let classifier = TangleQueryClassifier::new(runtime_relay_limits(8));
        let empty_filter = pocket_filter(json!({}));
        let tag_only_filter = pocket_filter(json!({"#t": ["market"], "limit": 1}));
        let kind_only_filter = pocket_filter(json!({"kinds": [1], "limit": 1}));
        let high_limit_filter = pocket_filter(json!({"kinds": [1], "#h": ["Farm"], "limit": 500}));
        let broad_time_filter = pocket_filter(json!({
            "kinds": [1],
            "since": 1,
            "until": BROAD_QUERY_TIME_WINDOW_SECONDS + 2,
            "limit": 1
        }));
        let bounded_group_filter = pocket_filter(json!({"kinds": [1], "#h": ["Farm"], "limit": 1}));
        let bounded_time_filter = pocket_filter(json!({
            "kinds": [1],
            "since": 1,
            "until": BROAD_QUERY_TIME_WINDOW_SECONDS,
            "limit": 1
        }));
        let hll_reaction_filter = pocket_filter(json!({"kinds": [7], "#e": ["a".repeat(64)]}));

        assert_eq!(
            classifier.classify_pocket_count(&[]),
            TangleQueryClassification::Broad(TangleBroadQueryReason::EmptyFilters)
        );
        assert_eq!(
            classifier.classify_pocket_count(&[empty_filter]),
            TangleQueryClassification::Broad(TangleBroadQueryReason::MissingPrimaryConstraint)
        );
        assert_eq!(
            classifier.classify_pocket_count(&[tag_only_filter]),
            TangleQueryClassification::Broad(TangleBroadQueryReason::MissingPrimaryConstraint)
        );
        assert_eq!(
            classifier.classify_pocket_count(&[kind_only_filter]),
            TangleQueryClassification::Broad(TangleBroadQueryReason::MissingBoundedSelector)
        );
        assert_eq!(
            classifier.classify_pocket_count(&[high_limit_filter]),
            TangleQueryClassification::Broad(TangleBroadQueryReason::HighLimit)
        );
        assert_eq!(
            classifier.classify_pocket_count(&[broad_time_filter]),
            TangleQueryClassification::Broad(TangleBroadQueryReason::BroadTimeWindow)
        );
        assert_eq!(
            classifier.classify_pocket_count(&[bounded_group_filter]),
            TangleQueryClassification::Bounded
        );
        assert_eq!(
            classifier.classify_pocket_count(&[bounded_time_filter]),
            TangleQueryClassification::Bounded
        );
        assert_eq!(
            classifier.classify_pocket_count(&[hll_reaction_filter]),
            TangleQueryClassification::Bounded
        );
    }

    #[tokio::test]
    async fn runtime_count_hll_accepts_public_pocket_selector() {
        let root = temp_root("runtime-count-hll");
        let _ = std::fs::remove_dir_all(&root);
        let handle =
            RelayRuntimeHandle::new(RelayRuntime::open(runtime_config(&root, 8)).expect("runtime"));
        let mut auth = handle.auth_state().await.expect("auth");
        let target = "c".repeat(64);
        let tags = PocketOwnedTags::new(&[["e", target.as_str()]]).expect("tags");
        let first = signed_pocket_event(12, 1_714_124_433, 7, &tags, b"first reaction");
        let second = signed_pocket_event(11, 1_714_124_434, 7, &tags, b"second reaction");

        assert_accepted_pocket_reply(
            runtime_pocket_event_reply(&handle, &first, &mut auth),
            &first,
        );
        assert_accepted_pocket_reply(
            runtime_pocket_event_reply(&handle, &second, &mut auth),
            &second,
        );

        let subscription_id = SubscriptionId::new("count-hll-runtime").expect("subscription");
        let replies = handle
            .handle_protocol_client_message_for_test(
                ClientMessage::Count {
                    subscription_id: subscription_id.clone(),
                    filters: vec![
                        filter_from_value(&json!({"kinds":[7],"#e":[target]})).expect("filter"),
                    ],
                },
                &mut auth,
                UnixTimestamp::new(1_714_124_437),
            )
            .await
            .expect("count");
        let [
            RelayMessage::Count {
                subscription_id: actual,
                count,
                hll: Some(hll),
            },
        ] = replies.as_slice()
        else {
            panic!("count hll expected: {replies:?}")
        };

        assert_eq!(actual, &subscription_id);
        assert_eq!(*count, 2);
        assert_eq!(hll.len(), 512);
        assert_ne!(hll, &"00".repeat(256));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_count_source_stays_exact() {
        let sources = [
            include_str!("runtime.rs"),
            include_str!("relay/core.rs"),
            include_str!("../../tangle_protocol/src/lib.rs"),
        ];
        let forbidden = [
            concat!("approximate", "_count"),
            concat!("approx", "_count"),
            concat!("estimated", "_count"),
            concat!("count", "_estimate"),
            concat!("private", "_count", "_estimate"),
        ];

        for source in sources {
            for needle in forbidden {
                assert!(!source.contains(needle));
            }
        }
    }

    #[tokio::test]
    async fn runtime_rate_limits_count_peer_ips() {
        let root = temp_root("runtime-count-ip-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let rule = runtime.config().rate_limits().count().per_ip();
        let peer_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9));
        let key = TangleRateLimitKey::ip(TangleRateLimitScope::Count, peer_ip);
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");
        let subscription_id = SubscriptionId::new("limited-count-ip").expect("subscription");
        let filters = vec![
            filter_from_value(&json!({"kinds": [1], "#h": ["Farm"], "limit": 1})).expect("filter"),
        ];

        assert_eq!(
            handle
                .handle_protocol_client_message_with_rate_limit_context_for_test(
                    ClientMessage::Count {
                        subscription_id: subscription_id.clone(),
                        filters
                    },
                    &mut auth,
                    TangleClientRateLimitContext::new(Some(peer_ip), None),
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("count"),
            vec![RelayMessage::Closed {
                subscription_id,
                message: "rate-limited: count ip rate limit exceeded until 1714124493".to_owned()
            }]
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_rejects_search_req_and_count_as_unsupported() {
        let root = temp_root("runtime-search-unsupported");
        let _ = std::fs::remove_dir_all(&root);
        let handle =
            RelayRuntimeHandle::new(RelayRuntime::open(runtime_config(&root, 8)).expect("runtime"));
        let mut auth = handle.auth_state().await.expect("auth");
        let req_id = SubscriptionId::new("search-req").expect("req");
        let count_id = SubscriptionId::new("search-count").expect("count");
        let search =
            filter_from_value(&json!({"search": "fresh carrots", "limit": 1})).expect("filter");

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Req {
                        subscription_id: req_id.clone(),
                        filters: vec![search.clone()]
                    },
                    &mut auth,
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("req"),
            vec![RelayMessage::Closed {
                subscription_id: req_id,
                message: "unsupported: search filters are not supported".to_owned()
            }]
        );
        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Count {
                        subscription_id: count_id.clone(),
                        filters: vec![search]
                    },
                    &mut auth,
                    UnixTimestamp::new(1_714_124_434)
                )
                .await
                .expect("count"),
            vec![RelayMessage::Closed {
                subscription_id: count_id,
                message: "unsupported: search filters are not supported".to_owned()
            }]
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_rate_limits_count_filter_kinds() {
        let root = temp_root("runtime-count-kind-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let kind = Kind::new(1).expect("kind");
        let rule = runtime.config().rate_limits().count().per_kind();
        let key = TangleRateLimitKey::kind(TangleRateLimitScope::Count, kind);
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");
        let subscription_id = SubscriptionId::new("limited-count-kind").expect("subscription");
        let filters = vec![
            filter_from_value(&json!({"kinds": [1], "#h": ["Farm"], "limit": 1})).expect("filter"),
        ];

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Count {
                        subscription_id: subscription_id.clone(),
                        filters
                    },
                    &mut auth,
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("count"),
            vec![RelayMessage::Closed {
                subscription_id,
                message: "rate-limited: count kind rate limit exceeded until 1714124493".to_owned()
            }]
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_refuses_broad_count_queries_before_rate_limits() {
        let root = temp_root("runtime-count-broad-refusal");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = RelayRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let rule = runtime.config().rate_limits().count().broad();
        let key = TangleRateLimitKey::query_class(
            TangleRateLimitScope::Count,
            TangleRateLimitQueryClass::Broad,
        );
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = RelayRuntimeHandle::new(runtime);
        let mut auth = handle.auth_state().await.expect("auth");
        let subscription_id = SubscriptionId::new("limited-count-broad").expect("subscription");
        let filters = vec![filter_from_value(&json!({"limit": 1})).expect("filter")];

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Count {
                        subscription_id: subscription_id.clone(),
                        filters
                    },
                    &mut auth,
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("count"),
            vec![RelayMessage::Closed {
                subscription_id,
                message: "restricted: count filters are too broad or expensive".to_owned()
            }]
        );
        assert_eq!(handle.metrics().count_refusals(), 1);
        assert_eq!(handle.metrics().broad_query_rejections(), 1);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_refuses_expensive_count_queries_deterministically() {
        let root = temp_root("runtime-count-expensive-refusal");
        let _ = std::fs::remove_dir_all(&root);
        let handle =
            RelayRuntimeHandle::new(RelayRuntime::open(runtime_config(&root, 8)).expect("runtime"));
        let mut auth = handle.auth_state().await.expect("auth");
        let cases = [
            ("missing-selector", json!({"kinds": [1], "limit": 1})),
            (
                "high-limit",
                json!({"kinds": [1], "#h": ["Farm"], "limit": 500}),
            ),
            (
                "broad-window",
                json!({
                    "kinds": [1],
                    "since": 1,
                    "until": BROAD_QUERY_TIME_WINDOW_SECONDS + 2,
                    "limit": 1
                }),
            ),
        ];

        for (name, value) in cases {
            let subscription_id = SubscriptionId::new(name).expect("subscription");
            let filters = vec![filter_from_value(&value).expect("filter")];

            assert_eq!(
                handle
                    .handle_protocol_client_message_for_test(
                        ClientMessage::Count {
                            subscription_id: subscription_id.clone(),
                            filters
                        },
                        &mut auth,
                        UnixTimestamp::new(1_714_124_433)
                    )
                    .await
                    .expect("count"),
                vec![RelayMessage::Closed {
                    subscription_id,
                    message: "restricted: count filters are too broad or expensive".to_owned()
                }]
            );
        }
        assert_eq!(handle.metrics().count_refusals(), 3);
        assert_eq!(handle.metrics().broad_query_rejections(), 3);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_publishes_generated_group_event_offsets_for_live_fanout() {
        let root = temp_root("runtime-generated-offset-fanout");
        let _ = std::fs::remove_dir_all(&root);
        let handle =
            RelayRuntimeHandle::new(RelayRuntime::open(runtime_config(&root, 8)).expect("runtime"));
        let mut offsets = handle.subscribe_events().await;
        let mut auth = handle.auth_state().await.expect("auth");
        auth.issue_challenge("challenge-a", UnixTimestamp::new(100))
            .expect("challenge");
        let auth_event =
            tangle_v2_auth_event(FixtureKey::Owner, "challenge-a", 120).expect("auth event");
        let create = tangle_v2_group_create_event(FixtureKey::Owner, "RuntimeFarm", 121, &[])
            .expect("create");
        let mut subscriptions = LiveSubscriptionSet::new(8, 64).expect("subscriptions");
        let subscription_id = SubscriptionId::new("generated-offsets").expect("subscription");
        subscriptions
            .subscribe(
                subscription_id.clone(),
                vec![pocket_filter(json!({
                    "kinds":[KIND_GROUP_METADATA, KIND_GROUP_ADMINS, KIND_GROUP_MEMBERS],
                    "#d":["RuntimeFarm"]
                }))],
            )
            .expect("subscribe");

        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Auth(auth_event.clone()),
                    &mut auth,
                    UnixTimestamp::new(120)
                )
                .await
                .expect("auth"),
            vec![RelayMessage::Ok {
                event_id: auth_event.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Event(create.clone()),
                    &mut auth,
                    UnixTimestamp::new(121)
                )
                .await
                .expect("create"),
            vec![RelayMessage::Ok {
                event_id: create.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        let source_offset = offsets.try_recv().expect("source offset");
        let generated_offsets = [
            offsets.try_recv().expect("first generated offset"),
            offsets.try_recv().expect("second generated offset"),
        ];
        assert!(source_offset < generated_offsets[0]);
        assert!(generated_offsets[0] < generated_offsets[1]);
        let put_member =
            tangle_v2_put_user_event(FixtureKey::Owner, "RuntimeFarm", FixtureKey::Member, 122)
                .expect("put member");
        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Event(put_member.clone()),
                    &mut auth,
                    UnixTimestamp::new(122)
                )
                .await
                .expect("put member"),
            vec![RelayMessage::Ok {
                event_id: put_member.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        let put_source_offset = offsets.try_recv().expect("put source offset");
        let member_generated_offset = offsets.try_recv().expect("member generated offset");
        assert!(generated_offsets[1] < put_source_offset);
        assert!(put_source_offset < member_generated_offset);
        let generated_offsets = [
            generated_offsets[0],
            generated_offsets[1],
            member_generated_offset,
        ];
        let mut generated_kinds = BTreeSet::new();
        for offset in generated_offsets {
            let messages = handle
                .fanout_event_offset_with_projection_context(
                    offset,
                    &mut subscriptions,
                    &auth,
                    &RelayProjectionContext::default(),
                )
                .await
                .expect("fanout");
            assert!(matches!(
                messages.as_slice(),
                [RuntimeRelayMessage::Event {
                    subscription_id: delivered,
                    event
                }] if delivered == &subscription_id
                    && generated_kinds.insert(u32::from(event.kind().as_u16()))
            ));
        }
        assert_eq!(
            generated_kinds,
            BTreeSet::from([KIND_GROUP_METADATA, KIND_GROUP_ADMINS, KIND_GROUP_MEMBERS])
        );
        assert_eq!(handle.metrics().outbox_replayed_events(), 3);
        assert_eq!(handle.metrics().outbox_pending_events(), 0);
        assert_eq!(handle.metrics().event_bus_published_offsets(), 5);
        assert_eq!(
            offsets.try_recv().expect_err("only source plus generated"),
            TangleEventReceiveError::Empty
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_group_concurrency_duplicate_create_accepts_one_projection() {
        let root = temp_root("runtime-group-concurrency-duplicate-create");
        let _ = std::fs::remove_dir_all(&root);
        let handle = RelayRuntimeHandle::new(
            RelayRuntime::open(runtime_config(&root, 32)).expect("runtime"),
        );
        let mut offsets = handle.subscribe_events().await;
        let owner_auth =
            authenticated_runtime_state(&handle, FixtureKey::Owner, "owner-create", 1_714_126_100)
                .await;
        let first =
            tangle_v2_group_create_event(FixtureKey::Owner, "RaceCreate", 1_714_126_101, &[])
                .expect("first create");
        let second =
            tangle_v2_group_create_event(FixtureKey::Owner, "RaceCreate", 1_714_126_102, &[])
                .expect("second create");
        let first_task = {
            let handle = handle.clone();
            let mut auth = owner_auth.clone();
            let event = first.clone();
            tokio::spawn(async move {
                runtime_event_reply(&handle, event, &mut auth, 1_714_126_101).await
            })
        };
        let second_task = {
            let handle = handle.clone();
            let mut auth = owner_auth.clone();
            let event = second.clone();
            tokio::spawn(async move {
                runtime_event_reply(&handle, event, &mut auth, 1_714_126_102).await
            })
        };
        let replies = tokio::time::timeout(Duration::from_secs(3), async {
            vec![
                first_task.await.expect("first task"),
                second_task.await.expect("second task"),
            ]
        })
        .await
        .expect("duplicate create race");

        assert_eq!(accepted_count(&replies), 1);
        assert_eq!(
            rejected_messages(&replies),
            vec!["invalid: group already exists".to_owned()]
        );
        assert_eq!(drain_offsets(&mut offsets, 3).await.len(), 3);
        assert_eq!(
            offsets
                .try_recv()
                .expect_err("one create source plus generated"),
            TangleEventReceiveError::Empty
        );
        let mut auth = owner_auth.clone();
        assert_eq!(
            runtime_group_count(
                &handle,
                "duplicate-create-count",
                "RaceCreate",
                KIND_GROUP_METADATA,
                "d",
                &mut auth,
                1_714_126_103,
            )
            .await,
            1
        );
        assert_live_projection_matches_rebuild(&handle, "RaceCreate");

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_group_concurrency_duplicate_join_accepts_one_membership() {
        let root = temp_root("runtime-group-concurrency-duplicate-join");
        let _ = std::fs::remove_dir_all(&root);
        let handle = RelayRuntimeHandle::new(
            RelayRuntime::open(runtime_config_with_public_join(&root, 32)).expect("runtime"),
        );
        let mut offsets = handle.subscribe_events().await;
        let mut owner_auth =
            authenticated_runtime_state(&handle, FixtureKey::Owner, "owner-join", 1_714_126_200)
                .await;
        let member_auth =
            authenticated_runtime_state(&handle, FixtureKey::Member, "member-join", 1_714_126_201)
                .await;
        let create =
            tangle_v2_group_create_event(FixtureKey::Owner, "RaceJoin", 1_714_126_202, &[])
                .expect("create");
        assert_accepted_reply(
            runtime_event_reply(&handle, create.clone(), &mut owner_auth, 1_714_126_202).await,
            &create,
        );
        assert_eq!(drain_offsets(&mut offsets, 3).await.len(), 3);
        let join_a =
            tangle_v2_join_event(FixtureKey::Member, "RaceJoin", 1_714_126_203).expect("join a");
        let join_b =
            tangle_v2_join_event(FixtureKey::Member, "RaceJoin", 1_714_126_204).expect("join b");
        let first_task = {
            let handle = handle.clone();
            let mut auth = member_auth.clone();
            let event = join_a.clone();
            tokio::spawn(async move {
                runtime_event_reply(&handle, event, &mut auth, 1_714_126_203).await
            })
        };
        let second_task = {
            let handle = handle.clone();
            let mut auth = member_auth.clone();
            let event = join_b.clone();
            tokio::spawn(async move {
                runtime_event_reply(&handle, event, &mut auth, 1_714_126_204).await
            })
        };
        let replies = tokio::time::timeout(Duration::from_secs(3), async {
            vec![
                first_task.await.expect("first task"),
                second_task.await.expect("second task"),
            ]
        })
        .await
        .expect("duplicate join race");

        assert_eq!(accepted_count(&replies), 1);
        assert_eq!(
            rejected_messages(&replies),
            vec!["duplicate: group member already exists".to_owned()]
        );
        assert_eq!(drain_offsets(&mut offsets, 2).await.len(), 2);
        assert_runtime_member_status(
            &handle,
            "RaceJoin",
            &FixtureKey::Member.public_key(),
            MemberStatus::Member,
        );
        assert_live_projection_matches_rebuild(&handle, "RaceJoin");

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_group_concurrency_join_and_leave_match_rebuild() {
        let root = temp_root("runtime-group-concurrency-join-leave");
        let _ = std::fs::remove_dir_all(&root);
        let handle = RelayRuntimeHandle::new(
            RelayRuntime::open(runtime_config_with_public_join(&root, 32)).expect("runtime"),
        );
        let mut owner_auth = authenticated_runtime_state(
            &handle,
            FixtureKey::Owner,
            "owner-join-leave",
            1_714_126_300,
        )
        .await;
        let member_auth = authenticated_runtime_state(
            &handle,
            FixtureKey::Member,
            "member-join-leave",
            1_714_126_301,
        )
        .await;
        let create =
            tangle_v2_group_create_event(FixtureKey::Owner, "RaceJoinLeave", 1_714_126_302, &[])
                .expect("create");
        let put_member = tangle_v2_put_user_event(
            FixtureKey::Owner,
            "RaceJoinLeave",
            FixtureKey::Member,
            1_714_126_303,
        )
        .expect("put member");
        assert_accepted_reply(
            runtime_event_reply(&handle, create.clone(), &mut owner_auth, 1_714_126_302).await,
            &create,
        );
        assert_accepted_reply(
            runtime_event_reply(&handle, put_member.clone(), &mut owner_auth, 1_714_126_303).await,
            &put_member,
        );
        let leave = tangle_v2_leave_event(FixtureKey::Member, "RaceJoinLeave", 1_714_126_304)
            .expect("leave");
        let join =
            tangle_v2_join_event(FixtureKey::Member, "RaceJoinLeave", 1_714_126_305).expect("join");
        let leave_task = {
            let handle = handle.clone();
            let mut auth = member_auth.clone();
            let event = leave.clone();
            tokio::spawn(async move {
                runtime_event_reply(&handle, event, &mut auth, 1_714_126_304).await
            })
        };
        let join_task = {
            let handle = handle.clone();
            let mut auth = member_auth.clone();
            let event = join.clone();
            tokio::spawn(async move {
                runtime_event_reply(&handle, event, &mut auth, 1_714_126_305).await
            })
        };
        let replies = tokio::time::timeout(Duration::from_secs(3), async {
            vec![
                leave_task.await.expect("leave task"),
                join_task.await.expect("join task"),
            ]
        })
        .await
        .expect("join leave race");
        let join_accepted = reply_is_accepted(&replies[1]);

        assert_eq!(accepted_count(&replies), if join_accepted { 2 } else { 1 });
        if join_accepted {
            assert!(rejected_messages(&replies).is_empty());
        } else {
            assert_eq!(
                rejected_messages(&replies),
                vec!["duplicate: group member already exists".to_owned()]
            );
        }
        assert_runtime_member_status(
            &handle,
            "RaceJoinLeave",
            &FixtureKey::Member.public_key(),
            if join_accepted {
                MemberStatus::Member
            } else {
                MemberStatus::Removed
            },
        );
        assert_live_projection_matches_rebuild(&handle, "RaceJoinLeave");

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_group_concurrency_delete_tombstone_blocks_normal_write() {
        let root = temp_root("runtime-group-concurrency-delete-write");
        let _ = std::fs::remove_dir_all(&root);
        let handle = RelayRuntimeHandle::new(
            RelayRuntime::open(runtime_config(&root, 32)).expect("runtime"),
        );
        let mut owner_auth =
            authenticated_runtime_state(&handle, FixtureKey::Owner, "owner-delete", 1_714_126_400)
                .await;
        let create =
            tangle_v2_group_create_event(FixtureKey::Owner, "RaceDelete", 1_714_126_401, &[])
                .expect("create");
        assert_accepted_reply(
            runtime_event_reply(&handle, create.clone(), &mut owner_auth, 1_714_126_401).await,
            &create,
        );
        let normal =
            tangle_v2_group_event(FixtureKey::Owner, "RaceDelete", 1_714_126_402, 1, "normal")
                .expect("normal");
        let delete = tangle_v2_delete_group_event(FixtureKey::Owner, "RaceDelete", 1_714_126_403)
            .expect("delete");
        let normal_task = {
            let handle = handle.clone();
            let mut auth = owner_auth.clone();
            let event = normal.clone();
            tokio::spawn(async move {
                runtime_event_reply(&handle, event, &mut auth, 1_714_126_402).await
            })
        };
        let delete_task = {
            let handle = handle.clone();
            let mut auth = owner_auth.clone();
            let event = delete.clone();
            tokio::spawn(async move {
                runtime_event_reply(&handle, event, &mut auth, 1_714_126_403).await
            })
        };
        let replies = tokio::time::timeout(Duration::from_secs(3), async {
            vec![
                normal_task.await.expect("normal task"),
                delete_task.await.expect("delete task"),
            ]
        })
        .await
        .expect("delete write race");
        let delete_reply = &replies[1];

        assert!(reply_is_accepted(delete_reply));
        assert!(
            reply_is_accepted(&replies[0])
                || rejected_messages(&replies) == vec!["blocked: group is deleted".to_owned()]
        );
        let mut auth = owner_auth.clone();
        assert_eq!(
            runtime_group_count(
                &handle,
                "deleted-normal-count",
                "RaceDelete",
                1,
                "h",
                &mut auth,
                1_714_126_404,
            )
            .await,
            0
        );
        assert_eq!(
            runtime_group_count(
                &handle,
                "deleted-marker-count",
                "RaceDelete",
                KIND_GROUP_DELETE_GROUP,
                "h",
                &mut auth,
                1_714_126_405,
            )
            .await,
            1
        );
        assert_live_projection_matches_rebuild(&handle, "RaceDelete");

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_group_concurrency_membership_mutation_matches_rebuild() {
        let root = temp_root("runtime-group-concurrency-membership-mutation");
        let _ = std::fs::remove_dir_all(&root);
        let handle = RelayRuntimeHandle::new(
            RelayRuntime::open(runtime_config(&root, 32)).expect("runtime"),
        );
        let mut owner_auth = authenticated_runtime_state(
            &handle,
            FixtureKey::Owner,
            "owner-membership",
            1_714_126_500,
        )
        .await;
        let create =
            tangle_v2_group_create_event(FixtureKey::Owner, "RaceMember", 1_714_126_501, &[])
                .expect("create");
        assert_accepted_reply(
            runtime_event_reply(&handle, create.clone(), &mut owner_auth, 1_714_126_501).await,
            &create,
        );
        let put_member = tangle_v2_put_user_event(
            FixtureKey::Owner,
            "RaceMember",
            FixtureKey::Member,
            1_714_126_502,
        )
        .expect("put member");
        let remove_member = tangle_v2_remove_user_event(
            FixtureKey::Owner,
            "RaceMember",
            FixtureKey::Member,
            1_714_126_503,
        )
        .expect("remove member");
        let put_task = {
            let handle = handle.clone();
            let mut auth = owner_auth.clone();
            let event = put_member.clone();
            tokio::spawn(async move {
                runtime_event_reply(&handle, event, &mut auth, 1_714_126_502).await
            })
        };
        let remove_task = {
            let handle = handle.clone();
            let mut auth = owner_auth.clone();
            let event = remove_member.clone();
            tokio::spawn(async move {
                runtime_event_reply(&handle, event, &mut auth, 1_714_126_503).await
            })
        };
        let replies = tokio::time::timeout(Duration::from_secs(3), async {
            vec![
                put_task.await.expect("put task"),
                remove_task.await.expect("remove task"),
            ]
        })
        .await
        .expect("membership mutation race");
        let remove_accepted = reply_is_accepted(&replies[1]);

        assert!(reply_is_accepted(&replies[0]));
        if remove_accepted {
            assert!(rejected_messages(&replies).is_empty());
        } else {
            assert_eq!(
                rejected_messages(&replies),
                vec!["duplicate: group member does not exist".to_owned()]
            );
        }
        assert_runtime_member_status(
            &handle,
            "RaceMember",
            &FixtureKey::Member.public_key(),
            if remove_accepted {
                MemberStatus::Removed
            } else {
                MemberStatus::Member
            },
        );
        assert_live_projection_matches_rebuild(&handle, "RaceMember");

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn runtime_shared_services_progress_under_concurrent_event_query_count_and_fanout() {
        let root = temp_root("runtime-shared-concurrency");
        let _ = std::fs::remove_dir_all(&root);
        let handle = RelayRuntimeHandle::new(
            RelayRuntime::open(runtime_config(&root, 32)).expect("runtime"),
        );
        let base_time = 1_714_126_000;
        let mut owner_auth = handle.auth_state().await.expect("owner auth");
        owner_auth
            .issue_challenge("owner-stress", UnixTimestamp::new(base_time))
            .expect("owner challenge");
        let owner_auth_event =
            runtime_pocket_auth_event(FixtureKey::Owner, "owner-stress", base_time);
        assert_eq!(
            handle
                .handle_client_message(
                    RuntimeClientMessage::Auth(owner_auth_event.clone()),
                    &mut owner_auth,
                    UnixTimestamp::new(base_time)
                )
                .await
                .expect("owner auth"),
            vec![RelayMessage::Ok {
                event_id: runtime_pocket_event_id(&owner_auth_event),
                accepted: true,
                message: String::new()
            }]
        );
        let create = runtime_pocket_group_create_event(
            FixtureKey::Owner,
            "StressPrivate",
            base_time + 1,
            &["private"],
        );
        assert_eq!(
            handle
                .handle_client_message(
                    RuntimeClientMessage::Event(create.clone()),
                    &mut owner_auth,
                    UnixTimestamp::new(base_time + 1)
                )
                .await
                .expect("create"),
            vec![RelayMessage::Ok {
                event_id: runtime_pocket_event_id(&create),
                accepted: true,
                message: String::new()
            }]
        );
        let put_member = runtime_pocket_put_user_event(
            FixtureKey::Owner,
            "StressPrivate",
            FixtureKey::Member,
            base_time + 2,
        );
        assert_eq!(
            handle
                .handle_client_message(
                    RuntimeClientMessage::Event(put_member.clone()),
                    &mut owner_auth,
                    UnixTimestamp::new(base_time + 2)
                )
                .await
                .expect("put member"),
            vec![RelayMessage::Ok {
                event_id: runtime_pocket_event_id(&put_member),
                accepted: true,
                message: String::new()
            }]
        );
        let mut member_auth = handle.auth_state().await.expect("member auth");
        member_auth
            .issue_challenge("member-stress", UnixTimestamp::new(base_time + 3))
            .expect("member challenge");
        let member_auth_event =
            runtime_pocket_auth_event(FixtureKey::Member, "member-stress", base_time + 3);
        assert_eq!(
            handle
                .handle_client_message(
                    RuntimeClientMessage::Auth(member_auth_event.clone()),
                    &mut member_auth,
                    UnixTimestamp::new(base_time + 3)
                )
                .await
                .expect("member auth"),
            vec![RelayMessage::Ok {
                event_id: runtime_pocket_event_id(&member_auth_event),
                accepted: true,
                message: String::new()
            }]
        );
        let public_auth = handle.auth_state().await.expect("public auth");
        let mut offsets = handle.subscribe_events().await;
        let group_write_count = 6_usize;
        let public_write_count = 4_usize;
        let mut write_tasks = Vec::new();
        for index in 0..group_write_count {
            let handle = handle.clone();
            let mut auth = member_auth.clone();
            write_tasks.push(tokio::spawn(async move {
                let event = runtime_pocket_group_event(
                    FixtureKey::Member,
                    "StressPrivate",
                    base_time + 10 + u64::try_from(index).expect("index"),
                    1,
                    &format!("private stress {index}"),
                );
                assert_eq!(
                    handle
                        .handle_client_message(
                            RuntimeClientMessage::Event(event.clone()),
                            &mut auth,
                            UnixTimestamp::new(
                                base_time + 10 + u64::try_from(index).expect("index")
                            )
                        )
                        .await
                        .expect("group write"),
                    vec![RelayMessage::Ok {
                        event_id: runtime_pocket_event_id(&event),
                        accepted: true,
                        message: String::new()
                    }]
                );
                (true, runtime_pocket_event_id(&event))
            }));
        }
        for index in 0..public_write_count {
            let handle = handle.clone();
            let mut auth = public_auth.clone();
            write_tasks.push(tokio::spawn(async move {
                let event = runtime_pocket_event(
                    FixtureKey::Admin,
                    base_time + 40 + u64::try_from(index).expect("index"),
                    1,
                    Vec::new(),
                    &format!("public stress {index}"),
                );
                assert_eq!(
                    handle
                        .handle_client_message(
                            RuntimeClientMessage::Event(event.clone()),
                            &mut auth,
                            UnixTimestamp::new(
                                base_time + 40 + u64::try_from(index).expect("index")
                            )
                        )
                        .await
                        .expect("public write"),
                    vec![RelayMessage::Ok {
                        event_id: runtime_pocket_event_id(&event),
                        accepted: true,
                        message: String::new()
                    }]
                );
                (false, runtime_pocket_event_id(&event))
            }));
        }
        let stored_events = tokio::time::timeout(Duration::from_secs(3), async {
            let mut stored_events = Vec::new();
            for task in write_tasks {
                stored_events.push(task.await.expect("write task"));
            }
            stored_events
        })
        .await
        .expect("write concurrency timeout");
        assert_eq!(
            stored_events
                .iter()
                .filter(|(is_group, _)| *is_group)
                .count(),
            group_write_count
        );
        assert_eq!(
            stored_events
                .iter()
                .filter(|(is_group, _)| !*is_group)
                .count(),
            public_write_count
        );
        let group_event_ids = stored_events
            .iter()
            .filter(|(is_group, _)| *is_group)
            .map(|(_, event_id)| event_id.clone())
            .collect::<BTreeSet<_>>();
        let mut published_offsets = Vec::new();
        for _ in 0..stored_events.len() {
            published_offsets.push(
                tokio::time::timeout(Duration::from_secs(1), offsets.recv())
                    .await
                    .expect("offset timeout")
                    .expect("offset"),
            );
        }
        assert_eq!(
            offsets.try_recv().expect_err("no extra offsets"),
            TangleEventReceiveError::Empty
        );
        let mut visibility_tasks = Vec::new();
        for offset in published_offsets.iter().copied() {
            let handle = handle.clone();
            let member_auth = member_auth.clone();
            let public_auth = public_auth.clone();
            let group_event_ids = group_event_ids.clone();
            visibility_tasks.push(tokio::spawn(async move {
                let member_event = handle
                    .event_by_offset_with_auth(offset, &member_auth)
                    .await
                    .expect("member offset")
                    .expect("member visible");
                let public_event = handle
                    .event_by_offset_with_auth(offset, &public_auth)
                    .await
                    .expect("public offset");
                let member_event_id =
                    EventId::new(&member_event.id().as_hex_string()).expect("pocket id");
                let is_group_event = group_event_ids.contains(&member_event_id);
                if is_group_event {
                    assert!(public_event.is_none());
                } else {
                    assert!(public_event.is_some());
                }
                is_group_event
            }));
        }
        let visible_group_offsets = tokio::time::timeout(Duration::from_secs(3), async {
            let mut visible_group_offsets = 0;
            for task in visibility_tasks {
                if task.await.expect("visibility task") {
                    visible_group_offsets += 1;
                }
            }
            visible_group_offsets
        })
        .await
        .expect("visibility timeout");
        assert_eq!(visible_group_offsets, group_write_count);
        let member_subscription = SubscriptionId::new("member-stress-live").expect("subscription");
        let public_subscription = SubscriptionId::new("public-stress-live").expect("subscription");
        let mut member_subscriptions = LiveSubscriptionSet::new(32, 64).expect("member live set");
        let mut public_subscriptions = LiveSubscriptionSet::new(32, 64).expect("public live set");
        let stress_filter = pocket_filter(json!({"kinds":[1], "#h":["StressPrivate"]}));
        member_subscriptions
            .subscribe(member_subscription.clone(), vec![stress_filter.clone()])
            .expect("member subscribe");
        public_subscriptions
            .subscribe(public_subscription, vec![stress_filter])
            .expect("public subscribe");
        let mut member_fanout_count = 0;
        for offset in &published_offsets {
            let public_replies = handle
                .fanout_event_offset_with_projection_context(
                    *offset,
                    &mut public_subscriptions,
                    &public_auth,
                    &RelayProjectionContext::default(),
                )
                .await
                .expect("public fanout");
            assert!(public_replies.is_empty());
            let member_replies = handle
                .fanout_event_offset_with_projection_context(
                    *offset,
                    &mut member_subscriptions,
                    &member_auth,
                    &RelayProjectionContext::default(),
                )
                .await
                .expect("member fanout");
            for reply in member_replies {
                match reply {
                    RuntimeRelayMessage::Event {
                        subscription_id,
                        event,
                    } => {
                        assert_eq!(subscription_id, member_subscription);
                        let event_id =
                            EventId::new(&event.id().as_hex_string()).expect("pocket id");
                        assert!(group_event_ids.contains(&event_id));
                        member_fanout_count += 1;
                    }
                    other => panic!("unexpected fanout reply {other:?}"),
                }
            }
        }
        assert_eq!(member_fanout_count, group_write_count);
        let mut query_tasks = Vec::new();
        for index in 0..3_u64 {
            let member_req_handle = handle.clone();
            let mut auth = member_auth.clone();
            let group_event_ids = group_event_ids.clone();
            query_tasks.push(tokio::spawn(async move {
                let subscription_id =
                    SubscriptionId::new(&format!("member-req-{index}")).expect("subscription");
                let replies = member_req_handle
                    .handle_protocol_client_message_for_test(
                        ClientMessage::Req {
                            subscription_id: subscription_id.clone(),
                            filters: vec![
                                filter_from_value(&json!({
                                    "kinds":[1],
                                    "#h":["StressPrivate"],
                                    "limit": 20
                                }))
                                .expect("filter"),
                            ],
                        },
                        &mut auth,
                        UnixTimestamp::new(base_time + 100 + index),
                    )
                    .await
                    .expect("member req");
                assert_eq!(
                    replies
                        .iter()
                        .filter(|reply| matches!(
                            reply,
                            RelayMessage::Event {
                                subscription_id: delivered,
                                event
                            } if delivered == &subscription_id && group_event_ids.contains(event.id())
                        ))
                        .count(),
                    group_event_ids.len()
                );
                assert!(matches!(
                    replies.last(),
                    Some(RelayMessage::Eose(delivered)) if delivered == &subscription_id
                ));
            }));
            let public_req_handle = handle.clone();
            let mut auth = public_auth.clone();
            query_tasks.push(tokio::spawn(async move {
                let subscription_id =
                    SubscriptionId::new(&format!("public-req-{index}")).expect("subscription");
                let replies = public_req_handle
                    .handle_protocol_client_message_for_test(
                        ClientMessage::Req {
                            subscription_id: subscription_id.clone(),
                            filters: vec![
                                filter_from_value(&json!({
                                    "kinds":[1],
                                    "#h":["StressPrivate"],
                                    "limit": 20
                                }))
                                .expect("filter"),
                            ],
                        },
                        &mut auth,
                        UnixTimestamp::new(base_time + 110 + index),
                    )
                    .await
                    .expect("public req");
                assert_eq!(
                    replies,
                    vec![RelayMessage::Closed {
                        subscription_id,
                        message: "auth-required: authentication required to read group events"
                            .to_owned()
                    }]
                );
            }));
            let member_count_handle = handle.clone();
            let mut auth = member_auth.clone();
            query_tasks.push(tokio::spawn(async move {
                let subscription_id =
                    SubscriptionId::new(&format!("member-count-{index}")).expect("subscription");
                let replies = member_count_handle
                    .handle_protocol_client_message_for_test(
                        ClientMessage::Count {
                            subscription_id: subscription_id.clone(),
                            filters: vec![
                                filter_from_value(&json!({
                                    "kinds":[1],
                                    "#h":["StressPrivate"]
                                }))
                                .expect("filter"),
                            ],
                        },
                        &mut auth,
                        UnixTimestamp::new(base_time + 120 + index),
                    )
                    .await
                    .expect("member count");
                assert_eq!(
                    replies,
                    vec![RelayMessage::Count {
                        subscription_id,
                        count: u64::try_from(group_write_count).expect("group count"),
                        hll: None
                    }]
                );
            }));
            let public_count_handle = handle.clone();
            let mut auth = public_auth.clone();
            query_tasks.push(tokio::spawn(async move {
                let subscription_id =
                    SubscriptionId::new(&format!("public-count-{index}")).expect("subscription");
                let replies = public_count_handle
                    .handle_protocol_client_message_for_test(
                        ClientMessage::Count {
                            subscription_id: subscription_id.clone(),
                            filters: vec![
                                filter_from_value(&json!({
                                    "kinds":[1],
                                    "#h":["StressPrivate"]
                                }))
                                .expect("filter"),
                            ],
                        },
                        &mut auth,
                        UnixTimestamp::new(base_time + 130 + index),
                    )
                    .await
                    .expect("public count");
                assert_eq!(
                    replies,
                    vec![RelayMessage::Count {
                        subscription_id,
                        count: 0,
                        hll: None
                    }]
                );
            }));
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            for task in query_tasks {
                task.await.expect("query task");
            }
        })
        .await
        .expect("query concurrency timeout");
        assert!(handle.metrics().query_candidates_scanned() > 0);
        assert!(
            handle.metrics().query_returned_events()
                >= u64::try_from(group_write_count * 3).expect("returned event count")
        );
        assert!(handle.metrics().query_redacted_events() > 0);
        handle.shutdown().await.expect("shutdown");

        let _ = std::fs::remove_dir_all(root);
    }

    fn runtime_config(root: &Path, per_connection_outbound_queue: usize) -> BaseRelayRuntimeConfig {
        runtime_config_with_group_policy(root, per_connection_outbound_queue, false)
    }

    fn runtime_config_with_public_join(
        root: &Path,
        per_connection_outbound_queue: usize,
    ) -> BaseRelayRuntimeConfig {
        runtime_config_with_group_policy(root, per_connection_outbound_queue, true)
    }

    #[derive(Default)]
    struct RecordingHooks {
        admissions: Mutex<Vec<RelayEventAdmissionContext>>,
        stored: Mutex<Vec<RelayEventStoredContext>>,
        stored_bytes: std::sync::atomic::AtomicU64,
    }

    impl RelayRuntimeHooks for RecordingHooks {
        fn admit_event(&self, context: &RelayEventAdmissionContext) -> EventAdmissionDecision {
            self.admissions
                .lock()
                .expect("admissions")
                .push(context.clone());
            if context.event().has_tag("policy", "reject") {
                EventAdmissionDecision::reject("hook rejected event")
            } else {
                EventAdmissionDecision::Accept
            }
        }

        fn event_stored(&self, context: &RelayEventStoredContext) {
            self.stored.lock().expect("stored").push(context.clone());
            self.stored_bytes
                .store(144, std::sync::atomic::Ordering::Relaxed);
        }

        fn storage_used_bytes(&self) -> Option<u64> {
            Some(self.stored_bytes.load(std::sync::atomic::Ordering::Relaxed))
        }
    }

    struct BlockingStoredHooks {
        started_sender: Mutex<Option<mpsc::SyncSender<()>>>,
        release_receiver: Mutex<mpsc::Receiver<()>>,
    }

    impl RelayRuntimeHooks for BlockingStoredHooks {
        fn event_stored(&self, _context: &RelayEventStoredContext) {
            if let Some(sender) = self.started_sender.lock().expect("started sender").take() {
                sender.send(()).expect("send hook start");
            }
            self.release_receiver
                .lock()
                .expect("release receiver")
                .recv()
                .expect("receive hook release");
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ProjectionHookScope {
        Historical,
        Live,
    }

    struct ProjectingHooks {
        projection_identifier: &'static str,
        scope: ProjectionHookScope,
        source_content: Option<&'static str>,
        decision: Mutex<RelayEventProjectionDecision>,
        query_plan: Mutex<RelayProjectionQueryPlan>,
        live_candidates: Mutex<Vec<RelayLiveProjectionCandidate>>,
        contexts: Mutex<Vec<RelayEventProjectionContext>>,
        live_contexts: Mutex<Vec<RelayLiveProjectionContext>>,
        query_contexts: Mutex<Vec<RelayQueryProjectionContext>>,
    }

    impl ProjectingHooks {
        fn new(
            projection_identifier: &'static str,
            scope: ProjectionHookScope,
            source_content: Option<&'static str>,
            decision: RelayEventProjectionDecision,
        ) -> Self {
            Self {
                projection_identifier,
                scope,
                source_content,
                decision: Mutex::new(decision),
                query_plan: Mutex::new(RelayProjectionQueryPlan::default()),
                live_candidates: Mutex::new(Vec::new()),
                contexts: Mutex::new(Vec::new()),
                live_contexts: Mutex::new(Vec::new()),
                query_contexts: Mutex::new(Vec::new()),
            }
        }

        fn set_decision(&self, decision: RelayEventProjectionDecision) {
            *self.decision.lock().expect("decision") = decision;
        }

        fn set_query_plan(&self, plan: RelayProjectionQueryPlan) {
            *self.query_plan.lock().expect("query plan") = plan;
        }

        fn set_live_candidates(&self, candidates: Vec<RelayLiveProjectionCandidate>) {
            *self.live_candidates.lock().expect("live candidates") = candidates;
        }

        fn contexts(&self) -> Vec<RelayEventProjectionContext> {
            self.contexts.lock().expect("contexts").clone()
        }

        fn live_contexts(&self) -> Vec<RelayLiveProjectionContext> {
            self.live_contexts.lock().expect("live contexts").clone()
        }

        fn query_contexts(&self) -> Vec<RelayQueryProjectionContext> {
            self.query_contexts.lock().expect("query contexts").clone()
        }

        fn scope_matches(&self, source: RelayEventProjectionSource) -> bool {
            matches!(
                (self.scope, source),
                (
                    ProjectionHookScope::Historical,
                    RelayEventProjectionSource::HistoricalQuery
                ) | (
                    ProjectionHookScope::Live,
                    RelayEventProjectionSource::LiveFanout { .. }
                )
            )
        }

        fn content_matches(&self, context: &RelayEventProjectionContext) -> bool {
            match self.source_content {
                Some(content) => context.event().content() == content,
                None => true,
            }
        }
    }

    impl RelayRuntimeHooks for ProjectingHooks {
        fn plan_query(&self, context: &RelayQueryProjectionContext) -> RelayProjectionQueryPlan {
            self.query_contexts
                .lock()
                .expect("query contexts")
                .push(context.clone());
            *self.query_plan.lock().expect("query plan")
        }

        fn live_projection_candidates(
            &self,
            context: &RelayLiveProjectionContext,
        ) -> Vec<RelayLiveProjectionCandidate> {
            self.live_contexts
                .lock()
                .expect("live contexts")
                .push(context.clone());
            if context.projection().identifier() == Some(self.projection_identifier) {
                self.live_candidates
                    .lock()
                    .expect("live candidates")
                    .clone()
            } else {
                Vec::new()
            }
        }

        fn project_event(
            &self,
            context: &RelayEventProjectionContext,
        ) -> RelayEventProjectionDecision {
            self.contexts
                .lock()
                .expect("contexts")
                .push(context.clone());
            if context.projection().identifier() == Some(self.projection_identifier)
                && self.scope_matches(context.source())
                && self.content_matches(context)
            {
                *self.decision.lock().expect("decision")
            } else {
                RelayEventProjectionDecision::Emit
            }
        }
    }

    fn runtime_config_with_group_policy(
        root: &Path,
        per_connection_outbound_queue: usize,
        public_join: bool,
    ) -> BaseRelayRuntimeConfig {
        let raw = json!({
            "server": {
                "listen_addr": "127.0.0.1:0",
                "relay_url": "wss://relay.radroots.test"
            },
            "pocket": {
                "data_directory": root.join("pocket"),
                "sync_policy": "flush_on_shutdown",
                "query": {
                  "allow_scraping": false,
                  "allow_scrape_if_limited_to": 100,
                  "allow_scrape_if_max_seconds": 3600
                }
            },
            "groups": {
                "enabled": true,
                "canonical_relay_url": "wss://relay.radroots.test",
                "relay_secret": "7777777777777777777777777777777777777777777777777777777777777777",
                "owner_pubkeys": [FixtureKey::Owner.public_key().as_str()],
                "policy": {
                    "public_join": public_join,
                    "invites_enabled": false
                }
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
                "broadcast_channel_capacity": 16,
                "per_connection_outbound_queue": per_connection_outbound_queue
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
        .to_string();
        parse_base_relay_runtime_config_json(&raw).expect("config")
    }

    async fn authenticated_runtime_state(
        handle: &RelayRuntimeHandle,
        key: FixtureKey,
        challenge: &str,
        now: u64,
    ) -> BaseAuthState {
        let mut auth = handle.auth_state().await.expect("auth");
        auth.issue_challenge(challenge, UnixTimestamp::new(now))
            .expect("challenge");
        let event = tangle_v2_auth_event(key, challenge, now).expect("auth event");
        let replies = handle
            .handle_protocol_client_message_for_test(
                ClientMessage::Auth(event.clone()),
                &mut auth,
                UnixTimestamp::new(now),
            )
            .await
            .expect("auth message");

        assert_eq!(
            replies,
            vec![RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        auth
    }

    async fn runtime_event_reply(
        handle: &RelayRuntimeHandle,
        event: Event,
        auth: &mut BaseAuthState,
        now: u64,
    ) -> RelayMessage {
        let replies = handle
            .handle_protocol_client_message_for_test(
                ClientMessage::Event(event),
                auth,
                UnixTimestamp::new(now),
            )
            .await
            .expect("event message");

        assert_eq!(replies.len(), 1);
        replies.into_iter().next().expect("reply")
    }

    fn runtime_pocket_event_reply(
        handle: &RelayRuntimeHandle,
        event: &PocketEvent,
        auth: &mut BaseAuthState,
    ) -> RelayMessage {
        handle
            .inner
            .handle_pocket_event_with_auth_report(event, auth)
            .expect("event message")
            .into_message()
    }

    async fn runtime_group_count(
        handle: &RelayRuntimeHandle,
        subscription_id: &str,
        group_id: &str,
        kind: u32,
        tag_name: &str,
        auth: &mut BaseAuthState,
        now: u64,
    ) -> u64 {
        let replies = handle
            .handle_protocol_client_message_for_test(
                ClientMessage::Count {
                    subscription_id: SubscriptionId::new(subscription_id).expect("subscription"),
                    filters: vec![runtime_group_filter(group_id, kind, tag_name)],
                },
                auth,
                UnixTimestamp::new(now),
            )
            .await
            .expect("count");

        match replies.as_slice() {
            [RelayMessage::Count { count, .. }] => *count,
            other => panic!("count reply expected, got {other:?}"),
        }
    }

    fn runtime_group_filter(group_id: &str, kind: u32, tag_name: &str) -> Filter {
        let mut value = json!({"kinds": [kind]});
        value
            .as_object_mut()
            .expect("filter")
            .insert(format!("#{tag_name}"), json!([group_id]));
        filter_from_value(&value).expect("filter")
    }

    async fn drain_offsets(receiver: &mut TangleEventReceiver, count: usize) -> Vec<StoreOffset> {
        let mut offsets = Vec::with_capacity(count);
        for _ in 0..count {
            offsets.push(
                tokio::time::timeout(Duration::from_secs(1), receiver.recv())
                    .await
                    .expect("offset timeout")
                    .expect("offset"),
            );
        }
        offsets
    }

    fn accepted_count(replies: &[RelayMessage]) -> usize {
        replies
            .iter()
            .filter(|reply| reply_is_accepted(reply))
            .count()
    }

    fn reply_is_accepted(reply: &RelayMessage) -> bool {
        matches!(
            reply,
            RelayMessage::Ok {
                accepted: true,
                message,
                ..
            } if message.is_empty()
        )
    }

    fn rejected_messages(replies: &[RelayMessage]) -> Vec<String> {
        replies
            .iter()
            .filter_map(|reply| match reply {
                RelayMessage::Ok {
                    accepted: false,
                    message,
                    ..
                } => Some(message.clone()),
                _ => None,
            })
            .collect()
    }

    fn assert_accepted_reply(reply: RelayMessage, event: &Event) {
        assert_eq!(
            reply,
            RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: true,
                message: String::new()
            }
        );
    }

    fn assert_accepted_pocket_reply(reply: RelayMessage, event: &PocketEvent) {
        assert_eq!(
            reply,
            RelayMessage::Ok {
                event_id: runtime_pocket_event_id(event),
                accepted: true,
                message: String::new()
            }
        );
    }

    fn runtime_pocket_event_id(event: &PocketEvent) -> EventId {
        EventId::new(&event.id().as_hex_string()).expect("event id")
    }

    fn assert_runtime_member_status(
        handle: &RelayRuntimeHandle,
        group_id: &str,
        pubkey: &PublicKeyHex,
        status: MemberStatus,
    ) {
        let group_id = GroupId::new(group_id).expect("group");
        let groups = handle.inner.groups.as_ref().expect("groups");
        let projection = groups.projection();

        assert_eq!(
            projection
                .member(&group_id, pubkey)
                .expect("member")
                .status(),
            status
        );
    }

    fn assert_live_projection_matches_rebuild(handle: &RelayRuntimeHandle, group_id: &str) {
        let group_id = GroupId::new(group_id).expect("group");
        let groups = handle.inner.groups.as_ref().expect("groups");
        let live = groups.projection();
        let rebuilt = rebuilt_projection(handle);
        let live_group = live.group(&group_id);
        let rebuilt_group = rebuilt.group(&group_id);

        assert_eq!(
            live_group.map(|group| group.lifecycle()),
            rebuilt_group.map(|group| group.lifecycle())
        );
        assert_eq!(
            live_group.map(|group| group.metadata()),
            rebuilt_group.map(|group| group.metadata())
        );
        assert_eq!(
            live_group.and_then(|group| group.delete_event_id()),
            rebuilt_group.and_then(|group| group.delete_event_id())
        );
        assert_eq!(live.tombstone(&group_id), rebuilt.tombstone(&group_id));
        assert_eq!(
            projection_member_statuses(&live, &group_id),
            projection_member_statuses(&rebuilt, &group_id)
        );
    }

    fn rebuilt_projection(handle: &RelayRuntimeHandle) -> GroupProjection {
        let groups = handle.inner.groups.as_ref().expect("groups");
        let limits = groups.limits();
        let events = handle
            .inner
            .store
            .scan_events()
            .expect("scan")
            .into_iter()
            .filter_map(|stored| {
                let store_offset = StoreOffset::new(stored.store_offset());
                match tangle_groups::classify_group_event(stored.event(), limits).expect("classify")
                {
                    GroupEventClass::NonGroup => None,
                    _ => Some(CanonicalGroupEvent::new(stored.into_event(), store_offset)),
                }
            })
            .collect::<Vec<_>>();

        rebuild_group_projection(events, limits, UnixTimestamp::new(1_714_199_999))
            .expect("rebuild")
            .into_projection()
    }

    fn projection_member_statuses(
        projection: &GroupProjection,
        group_id: &GroupId,
    ) -> BTreeMap<String, MemberStatus> {
        projection
            .members()
            .iter()
            .filter(|((candidate, _), _)| candidate == group_id)
            .map(|((_, pubkey), member)| (pubkey.as_str().to_owned(), member.status()))
            .collect()
    }

    fn runtime_relay_limits(max_pending_events: usize) -> BaseRelayLimits {
        BaseRelayLimits::new(BaseRelayLimitSettings {
            max_pending_events,
            max_subscription_id_length: 64,
            max_subscriptions: 64,
            max_filters_per_request: 10,
            max_tag_values_per_filter: 100,
            max_query_complexity: 610,
            max_event_tags: 200,
            max_content_length: 65_536,
            max_limit: 500,
            default_limit: 100,
        })
        .expect("limits")
    }

    fn pocket_filter(value: serde_json::Value) -> tangle_store_pocket::PocketOwnedFilter {
        let filter = filter_from_value(&value).expect("filter");
        crate::pocket_conversion::tangle_filter_to_pocket(&filter).expect("pocket filter")
    }

    fn tangle_v2_event(
        key: FixtureKey,
        created_at: u64,
        kind: u64,
        tags: Vec<Tag>,
        content: &str,
    ) -> Result<Event, String> {
        let event = runtime_pocket_event(key, created_at, kind, tags, content);
        runtime_pocket_event_to_protocol(&event)
    }

    fn tangle_v2_auth_event(
        key: FixtureKey,
        challenge: &str,
        created_at: u64,
    ) -> Result<Event, String> {
        tangle_v2_event(
            key,
            created_at,
            22_242,
            vec![
                Tag::from_parts("relay", &["wss://relay.radroots.test"])?,
                Tag::from_parts("challenge", &[challenge])?,
            ],
            "",
        )
    }

    fn tangle_v2_group_create_event(
        key: FixtureKey,
        group_id: &str,
        created_at: u64,
        flags: &[&str],
    ) -> Result<Event, String> {
        let mut tags = vec![
            Tag::from_parts("h", &[group_id])?,
            Tag::from_parts("name", &[group_id])?,
        ];
        for flag in flags {
            tags.push(Tag::from_parts(flag, &[])?);
        }
        tangle_v2_event(key, created_at, KIND_GROUP_CREATE_GROUP.into(), tags, "")
    }

    fn tangle_v2_put_user_event(
        key: FixtureKey,
        group_id: &str,
        target: FixtureKey,
        created_at: u64,
    ) -> Result<Event, String> {
        let target_pubkey = target.public_key();
        tangle_v2_event(
            key,
            created_at,
            KIND_GROUP_PUT_USER.into(),
            vec![
                Tag::from_parts("h", &[group_id])?,
                Tag::from_parts("p", &[target_pubkey.as_str()])?,
            ],
            "",
        )
    }

    fn tangle_v2_remove_user_event(
        key: FixtureKey,
        group_id: &str,
        target: FixtureKey,
        created_at: u64,
    ) -> Result<Event, String> {
        let target_pubkey = target.public_key();
        tangle_v2_event(
            key,
            created_at,
            KIND_GROUP_REMOVE_USER.into(),
            vec![
                Tag::from_parts("h", &[group_id])?,
                Tag::from_parts("p", &[target_pubkey.as_str()])?,
            ],
            "",
        )
    }

    fn tangle_v2_join_event(
        key: FixtureKey,
        group_id: &str,
        created_at: u64,
    ) -> Result<Event, String> {
        tangle_v2_group_event(
            key,
            group_id,
            created_at,
            KIND_GROUP_JOIN_REQUEST.into(),
            "",
        )
    }

    fn tangle_v2_leave_event(
        key: FixtureKey,
        group_id: &str,
        created_at: u64,
    ) -> Result<Event, String> {
        tangle_v2_group_event(
            key,
            group_id,
            created_at,
            KIND_GROUP_LEAVE_REQUEST.into(),
            "",
        )
    }

    fn tangle_v2_delete_group_event(
        key: FixtureKey,
        group_id: &str,
        created_at: u64,
    ) -> Result<Event, String> {
        tangle_v2_group_event(
            key,
            group_id,
            created_at,
            KIND_GROUP_DELETE_GROUP.into(),
            "",
        )
    }

    fn tangle_v2_group_event(
        key: FixtureKey,
        group_id: &str,
        created_at: u64,
        kind: u64,
        content: &str,
    ) -> Result<Event, String> {
        tangle_v2_event(
            key,
            created_at,
            kind,
            vec![Tag::from_parts("h", &[group_id])?],
            content,
        )
    }

    fn runtime_pocket_group_create_event(
        key: FixtureKey,
        group_id: &str,
        created_at: u64,
        flags: &[&str],
    ) -> PocketOwnedEvent {
        let mut tags = vec![
            Tag::from_parts("h", &[group_id]).expect("h"),
            Tag::from_parts("name", &[group_id]).expect("name"),
        ];
        for flag in flags {
            tags.push(Tag::from_parts(flag, &[]).expect("flag"));
        }
        runtime_pocket_event(key, created_at, KIND_GROUP_CREATE_GROUP.into(), tags, "")
    }

    fn runtime_pocket_auth_event(
        key: FixtureKey,
        challenge: &str,
        created_at: u64,
    ) -> PocketOwnedEvent {
        runtime_pocket_event(
            key,
            created_at,
            22_242,
            vec![
                Tag::from_parts("relay", &["wss://relay.radroots.test"]).expect("relay"),
                Tag::from_parts("challenge", &[challenge]).expect("challenge"),
            ],
            "",
        )
    }

    fn runtime_pocket_put_user_event(
        key: FixtureKey,
        group_id: &str,
        target: FixtureKey,
        created_at: u64,
    ) -> PocketOwnedEvent {
        let target_pubkey = target.public_key();
        runtime_pocket_event(
            key,
            created_at,
            KIND_GROUP_PUT_USER.into(),
            vec![
                Tag::from_parts("h", &[group_id]).expect("h"),
                Tag::from_parts("p", &[target_pubkey.as_str()]).expect("p"),
            ],
            "",
        )
    }

    fn runtime_pocket_group_event(
        key: FixtureKey,
        group_id: &str,
        created_at: u64,
        kind: u64,
        content: &str,
    ) -> PocketOwnedEvent {
        runtime_pocket_event(
            key,
            created_at,
            kind,
            vec![Tag::from_parts("h", &[group_id]).expect("h")],
            content,
        )
    }

    fn runtime_pocket_event(
        key: FixtureKey,
        created_at: u64,
        kind: u64,
        tags: Vec<Tag>,
        content: &str,
    ) -> PocketOwnedEvent {
        let tags = pocket_tags_from_protocol(&tags);
        signed_pocket_event(
            fixture_secret_byte(key),
            created_at,
            u16::try_from(kind).expect("pocket kind"),
            &tags,
            content.as_bytes(),
        )
    }

    fn runtime_pocket_event_to_protocol(event: &PocketEvent) -> Result<Event, String> {
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

    fn pocket_tags_from_protocol(tags: &[Tag]) -> PocketOwnedTags {
        let parts = tags
            .iter()
            .map(|tag| tag.values().iter().map(String::as_str).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        PocketOwnedTags::new(&parts).expect("pocket tags")
    }

    fn fixture_secret_byte(key: FixtureKey) -> u8 {
        match key {
            FixtureKey::Relay => 9,
            FixtureKey::Admin => 11,
            FixtureKey::Member => 12,
            FixtureKey::Outsider => 13,
            FixtureKey::Owner => 10,
        }
    }

    fn signed_pocket_event(
        secret_byte: u8,
        created_at: u64,
        kind: u16,
        tags: &PocketOwnedTags,
        content: &[u8],
    ) -> PocketOwnedEvent {
        let secret = format!("{secret_byte:02x}").repeat(32);
        RelaySigner::from_secret_hex(&secret)
            .expect("signer")
            .sign_pocket_event(
                PocketKind::from_u16(kind),
                tags,
                PocketTime::from_u64(created_at),
                content,
            )
            .expect("pocket event")
    }

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("tangle-runtime-{name}-{}", std::process::id()))
    }
}
