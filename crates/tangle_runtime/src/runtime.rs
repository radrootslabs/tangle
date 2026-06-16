#![forbid(unsafe_code)]

use crate::{
    client_message::RuntimeClientMessage,
    config::BaseRelayRuntimeConfig,
    errors::BaseRelayError,
    event_bus::{TangleEventBus, TangleEventReceiver},
    groups::GroupServiceHandle,
    logging,
    ops::{BaseRelayReadinessHandle, BaseRelayReadinessState},
    pocket_conversion::{pocket_event_to_tangle, pocket_filter_to_tangle},
    pocket_event_validation::{
        is_pocket_nip70_protected_event, pocket_event_id, pocket_event_pubkey,
    },
    rate_limits::{
        TangleQueryRateLimitConfig, TangleRateLimitDecision, TangleRateLimitKey,
        TangleRateLimitQueryClass, TangleRateLimitRule, TangleRateLimitScope, TangleRateLimiter,
    },
    relay::{
        auth::BaseAuthState,
        core::{
            BaseRelay, BaseRelayCountReport, BaseRelayEventWrite, BaseRelayLimits,
            BaseRelayQueryMetrics, BaseRelayQueryReport, BaseRelayShutdownReport,
        },
        live::LiveSubscriptionSet,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fmt, fs,
    net::IpAddr,
    path::Path,
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
use tangle_protocol::{
    Event, EventId, Filter, Kind, PublicKeyHex, RelayMessage, SubscriptionId, UnixTimestamp,
};
use tangle_store_pocket::{PocketEvent, PocketOwnedFilter, PocketStoreHandle};
use tokio::sync::watch;

pub struct TangleRuntime {
    config: BaseRelayRuntimeConfig,
    relay: BaseRelay,
    readiness: BaseRelayReadinessHandle,
    limits: TangleRuntimeLimits,
    event_bus: TangleEventBus,
    rate_limiter: TangleRateLimiter,
    metrics: TangleRuntimeMetrics,
    shutdown: TangleShutdownSignal,
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
}

struct TangleQueryRateLimitRequest<'a> {
    scope: TangleRateLimitScope,
    rules: TangleQueryRateLimitConfig,
    label: &'static str,
    subscription_id: &'a SubscriptionId,
    filters: &'a [Filter],
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

    fn classify(
        self,
        scope: TangleRateLimitScope,
        filters: &[Filter],
    ) -> TangleQueryClassification {
        match scope {
            TangleRateLimitScope::Req => self.classify_query(filters),
            TangleRateLimitScope::Count => self.classify_count(filters),
            TangleRateLimitScope::Auth
            | TangleRateLimitScope::Event
            | TangleRateLimitScope::GroupWrite => self.classify_query(filters),
        }
    }

    fn classify_query(self, filters: &[Filter]) -> TangleQueryClassification {
        self.classify_filters(filters, Self::classify_query_filter)
    }

    fn classify_count(self, filters: &[Filter]) -> TangleQueryClassification {
        self.classify_filters(filters, Self::classify_count_filter)
    }

    fn classify_filters(
        self,
        filters: &[Filter],
        classify_filter: fn(Self, &Filter) -> TangleQueryClassification,
    ) -> TangleQueryClassification {
        if filters.is_empty() {
            return TangleQueryClassification::Broad(TangleBroadQueryReason::EmptyFilters);
        }
        filters
            .iter()
            .map(|filter| classify_filter(self, filter))
            .find(|classification| classification.is_broad())
            .unwrap_or(TangleQueryClassification::Bounded)
    }

    fn classify_query_filter(self, filter: &Filter) -> TangleQueryClassification {
        if !self.has_primary_constraint(filter) {
            return TangleQueryClassification::Broad(
                TangleBroadQueryReason::MissingPrimaryConstraint,
            );
        }
        if self.has_high_limit(filter) {
            return TangleQueryClassification::Broad(TangleBroadQueryReason::HighLimit);
        }
        if self.has_broad_time_window(filter) && !self.has_strong_constraint(filter) {
            return TangleQueryClassification::Broad(TangleBroadQueryReason::BroadTimeWindow);
        }
        TangleQueryClassification::Bounded
    }

    fn classify_count_filter(self, filter: &Filter) -> TangleQueryClassification {
        if !self.has_primary_constraint(filter) {
            return TangleQueryClassification::Broad(
                TangleBroadQueryReason::MissingPrimaryConstraint,
            );
        }
        if self.has_high_limit(filter) {
            return TangleQueryClassification::Broad(TangleBroadQueryReason::HighLimit);
        }
        if self.has_broad_time_window(filter) {
            return TangleQueryClassification::Broad(TangleBroadQueryReason::BroadTimeWindow);
        }
        if !self.has_count_bounded_selector(filter) {
            return TangleQueryClassification::Broad(
                TangleBroadQueryReason::MissingBoundedSelector,
            );
        }
        TangleQueryClassification::Bounded
    }

    fn has_primary_constraint(self, filter: &Filter) -> bool {
        !filter.ids().is_empty()
            || !filter.authors().is_empty()
            || !filter.kinds().is_empty()
            || self.has_group_constraint(filter)
    }

    fn has_strong_constraint(self, filter: &Filter) -> bool {
        !filter.ids().is_empty()
            || !filter.authors().is_empty()
            || self.has_group_constraint(filter)
    }

    fn has_count_bounded_selector(self, filter: &Filter) -> bool {
        self.has_strong_constraint(filter)
            || (!filter.kinds().is_empty() && self.has_bounded_time_window(filter))
            || self.has_hll_count_selector(filter)
    }

    fn has_hll_count_selector(self, filter: &Filter) -> bool {
        let [kind] = filter.kinds() else {
            return false;
        };
        let mut tags = filter.tag_filters().iter();
        let Some((name, values)) = tags.next() else {
            return false;
        };
        if tags.next().is_some() || values.len() != 1 {
            return false;
        }
        match (kind.as_u32(), name.as_str()) {
            (3, "p") => PublicKeyHex::new(values[0].as_str()).is_ok(),
            (7, "e") => EventId::new(values[0].as_str()).is_ok(),
            _ => false,
        }
    }

    fn has_group_constraint(self, filter: &Filter) -> bool {
        filter
            .tag_filters()
            .iter()
            .any(|(name, values)| matches!(name.as_str(), "h" | "d") && !values.is_empty())
    }

    fn has_high_limit(self, filter: &Filter) -> bool {
        filter.limit().unwrap_or(self.limits.default_limit()) >= self.limits.max_limit()
    }

    fn has_bounded_time_window(self, filter: &Filter) -> bool {
        match (filter.since(), filter.until()) {
            (Some(since), Some(until)) => {
                until.as_u64().saturating_sub(since.as_u64()) <= BROAD_QUERY_TIME_WINDOW_SECONDS
            }
            _ => false,
        }
    }

    fn has_broad_time_window(self, filter: &Filter) -> bool {
        match (filter.since(), filter.until()) {
            (Some(since), Some(until)) => {
                until.as_u64().saturating_sub(since.as_u64()) > BROAD_QUERY_TIME_WINDOW_SECONDS
            }
            _ => false,
        }
    }
}

impl TangleRuntime {
    pub fn open(config: BaseRelayRuntimeConfig) -> Result<Self, BaseRelayError> {
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

struct TangleRuntimeShared {
    config: Arc<BaseRelayRuntimeConfig>,
    store: PocketStoreHandle,
    groups: Option<GroupServiceHandle>,
    readiness: BaseRelayReadinessHandle,
    limits: TangleRuntimeLimits,
    event_bus: TangleEventBus,
    rate_limiter: TangleRateLimiter,
    metrics: TangleRuntimeMetrics,
    shutdown: TangleShutdownSignal,
}

impl TangleRuntimeShared {
    fn from_runtime(runtime: TangleRuntime) -> Self {
        let TangleRuntime {
            config,
            relay,
            readiness,
            limits,
            event_bus,
            rate_limiter,
            metrics,
            shutdown,
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
        }
    }

    fn rate_limit_event(
        &self,
        event: &Event,
        context: TangleClientRateLimitContext,
        now: UnixTimestamp,
    ) -> Option<RelayMessage> {
        let rules = self.config.rate_limits().event();
        if let Some(peer_ip) = context.peer_ip
            && let Some(message) = self.rate_limit_ok(
                event,
                TangleRateLimitKey::ip(TangleRateLimitScope::Event, peer_ip),
                rules.per_ip(),
                "event ip",
                now,
            )
        {
            return Some(message);
        }
        self.rate_limit_ok(
            event,
            TangleRateLimitKey::pubkey(
                TangleRateLimitScope::Event,
                event.unsigned().pubkey().clone(),
            ),
            rules.per_pubkey(),
            "event pubkey",
            now,
        )
        .or_else(|| {
            self.rate_limit_ok(
                event,
                TangleRateLimitKey::kind(TangleRateLimitScope::Event, event.unsigned().kind()),
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

    fn rate_limit_group_write(
        &self,
        event: &Event,
        context: TangleClientRateLimitContext,
        now: UnixTimestamp,
    ) -> Option<RelayMessage> {
        if !self.config.groups().enabled() {
            return None;
        }
        let class =
            validate_client_group_event_structure(event, self.config.groups().limits()).ok()?;
        let group_id = class.group_id()?.clone();
        let rules = self.config.rate_limits().group();
        if event.unsigned().kind().as_u32() == KIND_GROUP_JOIN_REQUEST {
            if let Some(peer_ip) = context.peer_ip
                && let Some(message) = self.rate_limit_ok(
                    event,
                    TangleRateLimitKey::join_flow_ip(group_id.clone(), peer_ip),
                    rules.join_flow_per_ip(),
                    "group join ip",
                    now,
                )
            {
                return Some(message);
            }
            if let Some(message) = self.rate_limit_ok(
                event,
                TangleRateLimitKey::join_flow(group_id.clone(), event.unsigned().pubkey().clone()),
                rules.join_flow(),
                "group join",
                now,
            ) {
                return Some(message);
            }
        }
        if let Some(peer_ip) = context.peer_ip
            && let Some(message) = self.rate_limit_ok(
                event,
                TangleRateLimitKey::ip(TangleRateLimitScope::GroupWrite, peer_ip),
                rules.write_per_ip(),
                "group ip",
                now,
            )
        {
            return Some(message);
        }
        if let Some(message) = self.rate_limit_ok(
            event,
            TangleRateLimitKey::pubkey(
                TangleRateLimitScope::GroupWrite,
                event.unsigned().pubkey().clone(),
            ),
            rules.write_per_pubkey(),
            "group pubkey",
            now,
        ) {
            return Some(message);
        }
        if let Some(message) = self.rate_limit_ok(
            event,
            TangleRateLimitKey::group(TangleRateLimitScope::GroupWrite, group_id),
            rules.write_per_group(),
            "group write",
            now,
        ) {
            return Some(message);
        }
        self.rate_limit_ok(
            event,
            TangleRateLimitKey::kind(TangleRateLimitScope::GroupWrite, event.unsigned().kind()),
            rules.write_per_kind(),
            "group kind",
            now,
        )
    }

    fn is_group_event(&self, event: &Event) -> bool {
        self.config.groups().enabled()
            && validate_client_group_event_structure(event, self.config.groups().limits())
                .is_ok_and(|class| !matches!(class, GroupEventClass::NonGroup))
    }

    fn handle_event_with_auth_report(
        &self,
        event: Event,
        auth: &BaseAuthState,
    ) -> Result<BaseRelayEventWrite, BaseRelayError> {
        BaseRelay::handle_event_with_shared_services(
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
        filters: Vec<Filter>,
        auth: &BaseAuthState,
    ) -> Result<BaseRelayQueryReport, BaseRelayError> {
        BaseRelay::query_req_with_shared_services(
            &self.store,
            self.groups.as_ref(),
            self.limits.base_relay_limits(),
            self.config.pocket_query_config(),
            subscription_id,
            filters,
            auth,
        )
    }

    fn handle_count_with_auth_report(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &BaseAuthState,
    ) -> Result<BaseRelayCountReport, BaseRelayError> {
        BaseRelay::handle_count_with_shared_services(
            &self.store,
            self.groups.as_ref(),
            self.limits.base_relay_limits(),
            self.config.pocket_query_config(),
            subscription_id,
            filters,
            auth,
        )
    }

    fn rate_limit_req(
        &self,
        subscription_id: &SubscriptionId,
        filters: &[Filter],
        auth: &BaseAuthState,
        context: TangleClientRateLimitContext,
        now: UnixTimestamp,
    ) -> Option<RelayMessage> {
        self.rate_limit_query(TangleQueryRateLimitRequest {
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

    fn rate_limit_count(
        &self,
        subscription_id: &SubscriptionId,
        filters: &[Filter],
        auth: &BaseAuthState,
        context: TangleClientRateLimitContext,
        now: UnixTimestamp,
    ) -> Option<RelayMessage> {
        self.rate_limit_query(TangleQueryRateLimitRequest {
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
        filters: &[Filter],
    ) -> Option<RelayMessage> {
        if TangleQueryClassifier::new(self.limits.base_relay_limits())
            .classify_count(filters)
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

    fn rate_limit_query(&self, request: TangleQueryRateLimitRequest<'_>) -> Option<RelayMessage> {
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
        for group_id in filter_group_ids(request.filters) {
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
        for kind in filter_kinds(request.filters) {
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
        let query_classification = TangleQueryClassifier::new(self.limits.base_relay_limits())
            .classify(request.scope, request.filters);
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

    fn rate_limit_ok(
        &self,
        event: &Event,
        key: TangleRateLimitKey,
        rule: TangleRateLimitRule,
        label: &'static str,
        now: UnixTimestamp,
    ) -> Option<RelayMessage> {
        match self.rate_limiter.record(key, rule, now) {
            TangleRateLimitDecision::Allowed { .. } => None,
            TangleRateLimitDecision::Rejected { reset_at } => {
                self.metrics.record_rate_limit_rejection();
                logging::log_rate_limit_rejected(label, "event", reset_at);
                Some(RelayMessage::Ok {
                    event_id: event.id().clone(),
                    accepted: false,
                    message: BaseRelayError::rate_limited(format!(
                        "{label} rate limit exceeded until {reset_at}"
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
pub struct TangleRuntimeHandle {
    inner: Arc<TangleRuntimeShared>,
}

impl TangleRuntimeHandle {
    pub fn new(runtime: TangleRuntime) -> Self {
        Self {
            inner: Arc::new(TangleRuntimeShared::from_runtime(runtime)),
        }
    }

    pub fn metrics(&self) -> TangleRuntimeMetrics {
        self.inner.metrics.clone()
    }

    pub fn readiness_handle(&self) -> BaseRelayReadinessHandle {
        self.inner.readiness.clone()
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
        self.handle_client_message_with_rate_limit_context(
            RuntimeClientMessage::Count {
                subscription_id,
                filters,
                search_present: false,
            },
            auth,
            TangleClientRateLimitContext::default(),
            now,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn handle_client_message(
        &self,
        message: RuntimeClientMessage,
        auth: &mut BaseAuthState,
        now: UnixTimestamp,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        self.handle_client_message_with_rate_limit_context(
            message,
            auth,
            TangleClientRateLimitContext::default(),
            now,
        )
        .await
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
        self.handle_client_message_with_rate_limit_context(
            protocol_client_message_to_runtime_for_test(message)?,
            auth,
            rate_limit_context,
            now,
        )
        .await
    }

    pub(crate) async fn handle_client_message_with_rate_limit_context(
        &self,
        message: RuntimeClientMessage,
        auth: &mut BaseAuthState,
        rate_limit_context: TangleClientRateLimitContext,
        now: UnixTimestamp,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        self.inner
            .metrics
            .record_client_message(runtime_client_message_metric_kind(&message));
        match message {
            RuntimeClientMessage::Event(pocket_event) => {
                let event = pocket_event_to_tangle(&pocket_event)?;
                debug_assert_eq!(
                    is_pocket_nip70_protected_event(&pocket_event)?,
                    event
                        .unsigned()
                        .tags()
                        .iter()
                        .any(|tag| tag.name().as_str() == "-")
                );
                let started_at = Instant::now();
                let event_id = event.id().clone();
                let is_group_event = self.inner.is_group_event(&event);
                if let Some(message) = self.inner.rate_limit_event(&event, rate_limit_context, now)
                {
                    record_event_metrics(&self.inner.metrics, &message, is_group_event, started_at);
                    return Ok(vec![message]);
                }
                if let Some(message) =
                    self.inner
                        .rate_limit_group_write(&event, rate_limit_context, now)
                {
                    record_event_metrics(&self.inner.metrics, &message, is_group_event, started_at);
                    return Ok(vec![message]);
                }
                let result = self.inner.handle_event_with_auth_report(event, auth)?;
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
                for offset in result.stored_offsets() {
                    self.inner.metrics.record_stored_event_offset();
                    let receivers = self.inner.event_bus.publish(*offset);
                    self.inner.metrics.record_event_bus_publish(receivers);
                }
                if !result.stored_offsets().is_empty() {
                    logging::log_event_stored(
                        &event_id,
                        result.stored_offsets().len(),
                        self.inner.metrics.stored_event_offsets(),
                    );
                }
                let message = result.into_message();
                record_event_metrics(&self.inner.metrics, &message, is_group_event, started_at);
                Ok(vec![message])
            }
            RuntimeClientMessage::Req {
                subscription_id,
                filters,
                search_present,
            } => {
                let filters = runtime_filters_to_protocol(filters, search_present)?;
                let started_at = Instant::now();
                self.inner
                    .limits
                    .base_relay_limits()
                    .validate_subscription_id(&subscription_id)?;
                self.inner
                    .limits
                    .base_relay_limits()
                    .validate_filters(&filters)?;
                if let Some(message) =
                    BaseRelay::unsupported_search_closed(&subscription_id, &filters)
                {
                    self.inner
                        .metrics
                        .record_query_latency(elapsed_micros(started_at));
                    return Ok(vec![message]);
                }
                if let Some(message) = self.inner.rate_limit_req(
                    &subscription_id,
                    &filters,
                    auth,
                    rate_limit_context,
                    now,
                ) {
                    self.inner
                        .metrics
                        .record_query_latency(elapsed_micros(started_at));
                    return Ok(vec![message]);
                }
                let report =
                    self.inner
                        .query_req_with_auth_report(subscription_id, filters, auth)?;
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
                let filters = runtime_filters_to_protocol(filters, search_present)?;
                let started_at = Instant::now();
                self.inner
                    .limits
                    .base_relay_limits()
                    .validate_subscription_id(&subscription_id)?;
                self.inner
                    .limits
                    .base_relay_limits()
                    .validate_filters(&filters)?;
                if let Some(message) =
                    BaseRelay::unsupported_search_closed(&subscription_id, &filters)
                {
                    self.inner
                        .metrics
                        .record_query_latency(elapsed_micros(started_at));
                    return Ok(vec![message]);
                }
                if let Some(message) = self.inner.refuse_broad_count(&subscription_id, &filters) {
                    self.inner
                        .metrics
                        .record_query_latency(elapsed_micros(started_at));
                    return Ok(vec![message]);
                }
                if let Some(message) = self.inner.rate_limit_count(
                    &subscription_id,
                    &filters,
                    auth,
                    rate_limit_context,
                    now,
                ) {
                    self.inner
                        .metrics
                        .record_query_latency(elapsed_micros(started_at));
                    return Ok(vec![message]);
                }
                let report =
                    self.inner
                        .handle_count_with_auth_report(subscription_id, filters, auth)?;
                self.inner
                    .metrics
                    .record_query_metrics(report.query_metrics());
                if report.group_read_denied() {
                    self.inner.metrics.record_group_read_denial();
                }
                self.inner
                    .metrics
                    .record_query_latency(elapsed_micros(started_at));
                Ok(vec![report.into_message()])
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
                    return Ok(vec![RelayMessage::Ok {
                        event_id,
                        accepted: false,
                        message: error.prefixed_message(),
                    }]);
                }
                if let Some(message) = self.inner.rate_limit_auth_attempt_pocket(
                    &pocket_event,
                    rate_limit_context,
                    now,
                )? {
                    self.inner.metrics.record_auth_failure();
                    return Ok(vec![message]);
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
                        return Ok(vec![message]);
                    }
                } else {
                    self.inner.metrics.record_auth_success();
                }
                Ok(replies)
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
                Ok(vec![BaseRelay::disabled_negentropy_message(
                    subscription_id,
                )])
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

    pub async fn rate_limit_req(
        &self,
        subscription_id: &SubscriptionId,
        filters: &[Filter],
        auth: &BaseAuthState,
        rate_limit_context: TangleClientRateLimitContext,
        now: UnixTimestamp,
    ) -> Option<RelayMessage> {
        self.inner
            .rate_limit_req(subscription_id, filters, auth, rate_limit_context, now)
    }

    pub(crate) async fn query_req_with_auth_report(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &BaseAuthState,
    ) -> Result<BaseRelayQueryReport, BaseRelayError> {
        let started_at = Instant::now();
        let report = self
            .inner
            .query_req_with_auth_report(subscription_id, filters, auth)?;
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
    ) -> Result<Option<Event>, BaseRelayError> {
        let pocket_event = self.inner.store.event_by_offset(offset.as_u64())?;
        let event = pocket_event_to_tangle(&pocket_event)?;
        let group_auth = GroupAuthContext::new(auth.authenticated_pubkeys().iter().cloned());
        let visible = BaseRelay::group_read_gate_visible_to_auth(
            self.inner.groups.as_ref(),
            &event,
            &group_auth,
        )?;
        if !visible {
            self.inner.metrics.record_group_read_denial();
            return Ok(None);
        }
        Ok(Some(event))
    }

    pub(crate) async fn fanout_event_offset(
        &self,
        offset: StoreOffset,
        subscriptions: &mut LiveSubscriptionSet,
        auth: &BaseAuthState,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        let pocket_event = self.inner.store.event_by_offset(offset.as_u64())?;
        let event = pocket_event_to_tangle(&pocket_event)?;
        let group_auth = GroupAuthContext::new(auth.authenticated_pubkeys().iter().cloned());
        Ok(subscriptions.fanout(&event, &group_auth, |event, auth| {
            BaseRelay::group_read_gate_visible_to_auth(self.inner.groups.as_ref(), event, auth)
                .unwrap_or(false)
        }))
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

fn runtime_filters_to_protocol(
    filters: Vec<tangle_store_pocket::PocketOwnedFilter>,
    search_present: bool,
) -> Result<Vec<Filter>, BaseRelayError> {
    filters
        .into_iter()
        .enumerate()
        .map(|(index, filter)| {
            let search = (search_present && index == 0).then(String::new);
            pocket_filter_to_tangle(&filter, search)
        })
        .collect()
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

fn filter_group_ids(filters: &[Filter]) -> Vec<GroupId> {
    filters
        .iter()
        .flat_map(|filter| filter.tag_filters())
        .filter(|(name, _)| matches!(name.as_str(), "h" | "d"))
        .flat_map(|(_, values)| values)
        .filter_map(|value| GroupId::new(value.as_str()).ok())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn filter_kinds(filters: &[Filter]) -> Vec<Kind> {
    filters
        .iter()
        .flat_map(Filter::kinds)
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

impl fmt::Debug for TangleRuntimeHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TangleRuntimeHandle")
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
            .opened_subscriptions
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    pub fn record_subscriptions_closed(&self, count: usize) -> u64 {
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
        BROAD_QUERY_TIME_WINDOW_SECONDS, TangleBroadQueryReason, TangleClientRateLimitContext,
        TangleQueryClassification, TangleQueryClassifier, TangleRuntime, TangleRuntimeHandle,
        TangleRuntimeLimits,
    };
    use crate::config::{BaseRelayRuntimeConfig, parse_base_relay_runtime_config_json};
    use crate::event_bus::{TangleEventBus, TangleEventReceiveError, TangleEventReceiver};
    use crate::pocket_conversion::pocket_event_to_tangle;
    use crate::rate_limits::{TangleRateLimitKey, TangleRateLimitQueryClass, TangleRateLimitScope};
    use crate::relay::auth::BaseAuthState;
    use crate::relay::core::{BaseRelayLimitSettings, BaseRelayLimits, BaseRelayQueryMetrics};
    use crate::relay::live::LiveSubscriptionSet;
    use serde_json::json;
    use std::{
        collections::{BTreeMap, BTreeSet},
        net::{IpAddr, Ipv4Addr},
        path::{Path, PathBuf},
        time::Duration,
    };
    use tangle_groups::{
        CanonicalGroupEvent, GroupEventClass, GroupId, GroupProjection, KIND_GROUP_ADMINS,
        KIND_GROUP_DELETE_GROUP, KIND_GROUP_JOIN_REQUEST, KIND_GROUP_MEMBERS, KIND_GROUP_METADATA,
        MemberStatus, StoreOffset, rebuild_group_projection,
    };
    use tangle_protocol::{
        ClientMessage, Event, Filter, Kind, PublicKeyHex, RelayMessage, SubscriptionId, Tag,
        UnixTimestamp, filter_from_value,
    };
    use tangle_test_support::{
        FixtureKey, tangle_v2_auth_event, tangle_v2_delete_group_event, tangle_v2_event,
        tangle_v2_group_create_event, tangle_v2_group_event, tangle_v2_join_event,
        tangle_v2_leave_event, tangle_v2_put_user_event, tangle_v2_remove_user_event,
    };

    #[test]
    fn tangle_runtime_opens_owned_process_shell_from_config() {
        let root = temp_root("owned-runtime");
        let _ = std::fs::remove_dir_all(&root);
        let config = runtime_config(&root, 8);

        let mut runtime = TangleRuntime::open(config).expect("runtime");
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
        assert_eq!(runtime.metrics().opened_subscriptions(), 1);
        assert_eq!(runtime.metrics().record_subscriptions_closed(1), 1);
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
        let handle = TangleRuntimeHandle::new(
            TangleRuntime::open(runtime_config(&root, 8)).expect("runtime"),
        );
        let mut offsets = handle.subscribe_events().await;
        let mut auth = handle.auth_state().await.expect("auth");
        let mut subscriptions = LiveSubscriptionSet::new(8, 64).expect("subscriptions");
        let subscription_id = SubscriptionId::new("live-offset").expect("subscription");
        subscriptions
            .subscribe(
                subscription_id.clone(),
                vec![filter_from_value(&json!({"kinds":[1]})).expect("filter")],
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
                .fanout_event_offset(offset, &mut subscriptions, &auth)
                .await
                .expect("fanout")
                .as_slice(),
            [RelayMessage::Event {
                subscription_id: delivered,
                event: found
            }] if delivered == &subscription_id && found.id() == event.id()
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
    async fn runtime_rate_limits_event_pubkeys_before_storage() {
        let root = temp_root("runtime-event-rate-limit");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
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
        let handle = TangleRuntimeHandle::new(runtime);
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let event = tangle_v2_event(FixtureKey::Admin, 1_714_124_433, 1, Vec::new(), "limited")
            .expect("event");
        let rule = runtime.config().rate_limits().event().per_kind();
        let key = TangleRateLimitKey::kind(TangleRateLimitScope::Event, event.unsigned().kind());
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = TangleRuntimeHandle::new(runtime);
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
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
        let handle = TangleRuntimeHandle::new(runtime);
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
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
        let handle = TangleRuntimeHandle::new(runtime);
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
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
        let handle = TangleRuntimeHandle::new(runtime);
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
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
        let handle = TangleRuntimeHandle::new(runtime);
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
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
        let handle = TangleRuntimeHandle::new(runtime);
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
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
        let handle = TangleRuntimeHandle::new(runtime);
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
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
        let handle = TangleRuntimeHandle::new(runtime);
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
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
        let handle = TangleRuntimeHandle::new(runtime);
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
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
        let handle = TangleRuntimeHandle::new(runtime);
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
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
        let handle = TangleRuntimeHandle::new(runtime);
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
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
        let handle = TangleRuntimeHandle::new(runtime);
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
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
        let handle = TangleRuntimeHandle::new(runtime);
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let rule = runtime.config().rate_limits().req().per_pubkey();
        let handle = TangleRuntimeHandle::new(runtime);
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let rule = runtime.config().rate_limits().req().per_connection();
        let key = TangleRateLimitKey::connection(TangleRateLimitScope::Req, 77);
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = TangleRuntimeHandle::new(runtime);
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let group_id = GroupId::new("Farm").expect("group");
        let rule = runtime.config().rate_limits().req().per_group();
        let key = TangleRateLimitKey::group(TangleRateLimitScope::Req, group_id);
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = TangleRuntimeHandle::new(runtime);
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
        let empty_filter = filter_from_value(&json!({})).expect("filter");
        let tag_only_filter =
            filter_from_value(&json!({"#t": ["market"], "limit": 1})).expect("filter");
        let kind_only_filter =
            filter_from_value(&json!({"kinds": [1], "limit": 1})).expect("filter");
        let high_limit_filter =
            filter_from_value(&json!({"kinds": [1], "#h": ["Farm"], "limit": 500}))
                .expect("filter");
        let broad_time_filter = filter_from_value(&json!({
            "kinds": [1],
            "since": 1,
            "until": BROAD_QUERY_TIME_WINDOW_SECONDS + 2,
            "limit": 1
        }))
        .expect("filter");
        let bounded_group_filter =
            filter_from_value(&json!({"kinds": [1], "#h": ["Farm"], "limit": 1})).expect("filter");
        let bounded_time_filter = filter_from_value(&json!({
            "kinds": [1],
            "since": 1,
            "until": BROAD_QUERY_TIME_WINDOW_SECONDS,
            "limit": 1
        }))
        .expect("filter");
        let hll_reaction_filter =
            filter_from_value(&json!({"kinds": [7], "#e": ["a".repeat(64)]})).expect("filter");

        assert_eq!(
            classifier.classify_count(&[]),
            TangleQueryClassification::Broad(TangleBroadQueryReason::EmptyFilters)
        );
        assert_eq!(
            classifier.classify_count(&[empty_filter]),
            TangleQueryClassification::Broad(TangleBroadQueryReason::MissingPrimaryConstraint)
        );
        assert_eq!(
            classifier.classify_count(&[tag_only_filter]),
            TangleQueryClassification::Broad(TangleBroadQueryReason::MissingPrimaryConstraint)
        );
        assert_eq!(
            classifier.classify_count(&[kind_only_filter]),
            TangleQueryClassification::Broad(TangleBroadQueryReason::MissingBoundedSelector)
        );
        assert_eq!(
            classifier.classify_count(&[high_limit_filter]),
            TangleQueryClassification::Broad(TangleBroadQueryReason::HighLimit)
        );
        assert_eq!(
            classifier.classify_count(&[broad_time_filter]),
            TangleQueryClassification::Broad(TangleBroadQueryReason::BroadTimeWindow)
        );
        assert_eq!(
            classifier.classify_count(&[bounded_group_filter]),
            TangleQueryClassification::Bounded
        );
        assert_eq!(
            classifier.classify_count(&[bounded_time_filter]),
            TangleQueryClassification::Bounded
        );
        assert_eq!(
            classifier.classify_count(&[hll_reaction_filter]),
            TangleQueryClassification::Bounded
        );
    }

    #[tokio::test]
    async fn runtime_count_hll_accepts_public_pocket_selector() {
        let root = temp_root("runtime-count-hll");
        let _ = std::fs::remove_dir_all(&root);
        let handle = TangleRuntimeHandle::new(
            TangleRuntime::open(runtime_config(&root, 8)).expect("runtime"),
        );
        let mut auth = handle.auth_state().await.expect("auth");
        let target = "c".repeat(64);
        let first = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            7,
            vec![Tag::from_parts("e", &[&target]).expect("tag")],
            "first reaction",
        )
        .expect("first");
        let second = tangle_v2_event(
            FixtureKey::Admin,
            1_714_124_434,
            7,
            vec![Tag::from_parts("e", &[&target]).expect("tag")],
            "second reaction",
        )
        .expect("second");

        assert_accepted_reply(
            runtime_event_reply(&handle, first.clone(), &mut auth, 1_714_124_435).await,
            &first,
        );
        assert_accepted_reply(
            runtime_event_reply(&handle, second.clone(), &mut auth, 1_714_124_436).await,
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let rule = runtime.config().rate_limits().count().per_ip();
        let peer_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9));
        let key = TangleRateLimitKey::ip(TangleRateLimitScope::Count, peer_ip);
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = TangleRuntimeHandle::new(runtime);
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
        let handle = TangleRuntimeHandle::new(
            TangleRuntime::open(runtime_config(&root, 8)).expect("runtime"),
        );
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
        let kind = Kind::new(1).expect("kind");
        let rule = runtime.config().rate_limits().count().per_kind();
        let key = TangleRateLimitKey::kind(TangleRateLimitScope::Count, kind);
        for _ in 0..rule.max_hits() {
            runtime
                .rate_limiter()
                .record(key.clone(), rule, UnixTimestamp::new(1_714_124_433));
        }
        let handle = TangleRuntimeHandle::new(runtime);
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
        let runtime = TangleRuntime::open(runtime_config(&root, 8)).expect("runtime");
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
        let handle = TangleRuntimeHandle::new(runtime);
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
        let handle = TangleRuntimeHandle::new(
            TangleRuntime::open(runtime_config(&root, 8)).expect("runtime"),
        );
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
        let handle = TangleRuntimeHandle::new(
            TangleRuntime::open(runtime_config(&root, 8)).expect("runtime"),
        );
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
                vec![
                    filter_from_value(&json!({
                        "kinds":[KIND_GROUP_METADATA, KIND_GROUP_ADMINS, KIND_GROUP_MEMBERS],
                        "#d":["RuntimeFarm"]
                    }))
                    .expect("filter"),
                ],
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
                .fanout_event_offset(offset, &mut subscriptions, &auth)
                .await
                .expect("fanout");
            assert!(matches!(
                messages.as_slice(),
                [RelayMessage::Event {
                    subscription_id: delivered,
                    event
                }] if delivered == &subscription_id
                    && generated_kinds.insert(event.unsigned().kind().as_u32())
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
        let handle = TangleRuntimeHandle::new(
            TangleRuntime::open(runtime_config(&root, 32)).expect("runtime"),
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
        let handle = TangleRuntimeHandle::new(
            TangleRuntime::open(runtime_config_with_public_join(&root, 32)).expect("runtime"),
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
        let handle = TangleRuntimeHandle::new(
            TangleRuntime::open(runtime_config_with_public_join(&root, 32)).expect("runtime"),
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
        let handle = TangleRuntimeHandle::new(
            TangleRuntime::open(runtime_config(&root, 32)).expect("runtime"),
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
        let handle = TangleRuntimeHandle::new(
            TangleRuntime::open(runtime_config(&root, 32)).expect("runtime"),
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
        let handle = TangleRuntimeHandle::new(
            TangleRuntime::open(runtime_config(&root, 32)).expect("runtime"),
        );
        let base_time = 1_714_126_000;
        let mut owner_auth = handle.auth_state().await.expect("owner auth");
        owner_auth
            .issue_challenge("owner-stress", UnixTimestamp::new(base_time))
            .expect("owner challenge");
        let owner_auth_event = tangle_v2_auth_event(FixtureKey::Owner, "owner-stress", base_time)
            .expect("owner auth event");
        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Auth(owner_auth_event.clone()),
                    &mut owner_auth,
                    UnixTimestamp::new(base_time)
                )
                .await
                .expect("owner auth"),
            vec![RelayMessage::Ok {
                event_id: owner_auth_event.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        let create = tangle_v2_group_create_event(
            FixtureKey::Owner,
            "StressPrivate",
            base_time + 1,
            &["private"],
        )
        .expect("create");
        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Event(create.clone()),
                    &mut owner_auth,
                    UnixTimestamp::new(base_time + 1)
                )
                .await
                .expect("create"),
            vec![RelayMessage::Ok {
                event_id: create.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        let put_member = tangle_v2_put_user_event(
            FixtureKey::Owner,
            "StressPrivate",
            FixtureKey::Member,
            base_time + 2,
        )
        .expect("put member");
        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Event(put_member.clone()),
                    &mut owner_auth,
                    UnixTimestamp::new(base_time + 2)
                )
                .await
                .expect("put member"),
            vec![RelayMessage::Ok {
                event_id: put_member.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        let mut member_auth = handle.auth_state().await.expect("member auth");
        member_auth
            .issue_challenge("member-stress", UnixTimestamp::new(base_time + 3))
            .expect("member challenge");
        let member_auth_event =
            tangle_v2_auth_event(FixtureKey::Member, "member-stress", base_time + 3)
                .expect("member auth event");
        assert_eq!(
            handle
                .handle_protocol_client_message_for_test(
                    ClientMessage::Auth(member_auth_event.clone()),
                    &mut member_auth,
                    UnixTimestamp::new(base_time + 3)
                )
                .await
                .expect("member auth"),
            vec![RelayMessage::Ok {
                event_id: member_auth_event.id().clone(),
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
                let event = tangle_v2_group_event(
                    FixtureKey::Member,
                    "StressPrivate",
                    base_time + 10 + u64::try_from(index).expect("index"),
                    1,
                    &format!("private stress {index}"),
                )
                .expect("group event");
                assert_eq!(
                    handle
                        .handle_protocol_client_message_for_test(
                            ClientMessage::Event(event.clone()),
                            &mut auth,
                            UnixTimestamp::new(
                                base_time + 10 + u64::try_from(index).expect("index")
                            )
                        )
                        .await
                        .expect("group write"),
                    vec![RelayMessage::Ok {
                        event_id: event.id().clone(),
                        accepted: true,
                        message: String::new()
                    }]
                );
                (true, event)
            }));
        }
        for index in 0..public_write_count {
            let handle = handle.clone();
            let mut auth = public_auth.clone();
            write_tasks.push(tokio::spawn(async move {
                let event = tangle_v2_event(
                    FixtureKey::Admin,
                    base_time + 40 + u64::try_from(index).expect("index"),
                    1,
                    Vec::new(),
                    &format!("public stress {index}"),
                )
                .expect("public event");
                assert_eq!(
                    handle
                        .handle_protocol_client_message_for_test(
                            ClientMessage::Event(event.clone()),
                            &mut auth,
                            UnixTimestamp::new(
                                base_time + 40 + u64::try_from(index).expect("index")
                            )
                        )
                        .await
                        .expect("public write"),
                    vec![RelayMessage::Ok {
                        event_id: event.id().clone(),
                        accepted: true,
                        message: String::new()
                    }]
                );
                (false, event)
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
            .map(|(_, event)| event.id().clone())
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
                let is_group_event = group_event_ids.contains(member_event.id());
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
        let stress_filter =
            filter_from_value(&json!({"kinds":[1], "#h":["StressPrivate"]})).expect("filter");
        member_subscriptions
            .subscribe(member_subscription.clone(), vec![stress_filter.clone()])
            .expect("member subscribe");
        public_subscriptions
            .subscribe(public_subscription, vec![stress_filter])
            .expect("public subscribe");
        let mut member_fanout_count = 0;
        for offset in &published_offsets {
            let public_replies = handle
                .fanout_event_offset(*offset, &mut public_subscriptions, &public_auth)
                .await
                .expect("public fanout");
            assert!(public_replies.is_empty());
            let member_replies = handle
                .fanout_event_offset(*offset, &mut member_subscriptions, &member_auth)
                .await
                .expect("member fanout");
            for reply in member_replies {
                match reply {
                    RelayMessage::Event {
                        subscription_id,
                        event,
                    } => {
                        assert_eq!(subscription_id, member_subscription);
                        assert!(group_event_ids.contains(event.id()));
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
        handle: &TangleRuntimeHandle,
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
        handle: &TangleRuntimeHandle,
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

    async fn runtime_group_count(
        handle: &TangleRuntimeHandle,
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

    fn assert_runtime_member_status(
        handle: &TangleRuntimeHandle,
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

    fn assert_live_projection_matches_rebuild(handle: &TangleRuntimeHandle, group_id: &str) {
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

    fn rebuilt_projection(handle: &TangleRuntimeHandle) -> GroupProjection {
        let groups = handle.inner.groups.as_ref().expect("groups");
        let limits = groups.limits();
        let events = handle
            .inner
            .store
            .scan_events()
            .expect("scan")
            .into_iter()
            .filter_map(|stored| {
                let event = pocket_event_to_tangle(stored.event()).expect("event");
                match tangle_groups::classify_group_event(&event, limits).expect("classify") {
                    GroupEventClass::NonGroup => None,
                    _ => Some(CanonicalGroupEvent::new(
                        event,
                        StoreOffset::new(stored.store_offset()),
                    )),
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

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("tangle-runtime-{name}-{}", std::process::id()))
    }
}
