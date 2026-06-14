#![forbid(unsafe_code)]

use crate::{
    config::BaseRelayRuntimeConfig,
    errors::BaseRelayError,
    event_bus::{TangleEventBus, TangleEventReceiver},
    logging,
    ops::BaseRelayReadinessState,
    rate_limits::{
        TangleQueryRateLimitConfig, TangleRateLimitDecision, TangleRateLimitKey,
        TangleRateLimitQueryClass, TangleRateLimitRule, TangleRateLimitScope, TangleRateLimiter,
    },
    relay::{
        auth::BaseAuthState,
        core::{BaseRelay, BaseRelayLimits, BaseRelayShutdownReport},
        live::LiveSubscriptionSet,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fmt,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Instant,
};
use tangle_groups::{
    GroupId, KIND_GROUP_JOIN_REQUEST, StoreOffset, validate_client_group_event_structure,
};
use tangle_protocol::{
    ClientMessage, Event, Filter, Kind, RelayMessage, SubscriptionId, UnixTimestamp,
};
use tokio::sync::{Mutex, watch};

pub struct TangleRuntime {
    config: BaseRelayRuntimeConfig,
    relay: BaseRelay,
    readiness: BaseRelayReadinessState,
    limits: TangleRuntimeLimits,
    event_bus: TangleEventBus,
    rate_limiter: TangleRateLimiter,
    metrics: TangleRuntimeMetrics,
    shutdown: TangleShutdownSignal,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TangleQueryRateLimitContext {
    peer_ip: Option<IpAddr>,
    connection_id: Option<u64>,
}

impl TangleQueryRateLimitContext {
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
    context: TangleQueryRateLimitContext,
    now: UnixTimestamp,
}

impl TangleRuntime {
    pub fn open(config: BaseRelayRuntimeConfig) -> Result<Self, BaseRelayError> {
        let limits = TangleRuntimeLimits::from_config(&config)?;
        let relay = config.open_relay()?;
        let readiness = relay.readiness_state();
        let rate_limiter = TangleRateLimiter::new();
        logging::log_runtime_opened(&config);
        Ok(Self {
            config,
            relay,
            readiness,
            event_bus: TangleEventBus::new(limits.event_bus_capacity())?,
            rate_limiter,
            metrics: TangleRuntimeMetrics::new(),
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

    pub fn readiness_state(&self) -> &BaseRelayReadinessState {
        &self.readiness
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

    fn rate_limit_event(&self, event: &Event, now: UnixTimestamp) -> Option<RelayMessage> {
        let rules = self.config.rate_limits().event();
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

    fn rate_limit_auth_attempt(&self, event: &Event, now: UnixTimestamp) -> Option<RelayMessage> {
        let rules = self.config.rate_limits().auth();
        self.rate_limit_ok(
            event,
            TangleRateLimitKey::pubkey(
                TangleRateLimitScope::Auth,
                event.unsigned().pubkey().clone(),
            ),
            rules.per_pubkey(),
            "auth pubkey",
            now,
        )
    }

    fn rate_limit_auth_failure(&self, event: &Event, now: UnixTimestamp) -> Option<RelayMessage> {
        let rules = self.config.rate_limits().auth();
        self.rate_limit_ok(
            event,
            TangleRateLimitKey::auth_failure(None, Some(event.unsigned().pubkey().clone())),
            rules.failures(),
            "auth failure",
            now,
        )
    }

    fn rate_limit_group_write(&self, event: &Event, now: UnixTimestamp) -> Option<RelayMessage> {
        if !self.config.groups().enabled() {
            return None;
        }
        let class =
            validate_client_group_event_structure(event, self.config.groups().limits()).ok()?;
        let group_id = class.group_id()?.clone();
        let rules = self.config.rate_limits().group();
        if event.unsigned().kind().as_u32() == KIND_GROUP_JOIN_REQUEST
            && let Some(message) = self.rate_limit_ok(
                event,
                TangleRateLimitKey::join_flow(group_id.clone(), event.unsigned().pubkey().clone()),
                rules.join_flow(),
                "group join",
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

    fn rate_limit_req(
        &self,
        subscription_id: &SubscriptionId,
        filters: &[Filter],
        auth: &BaseAuthState,
        context: TangleQueryRateLimitContext,
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
        context: TangleQueryRateLimitContext,
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
        if query_is_broad(request.filters)
            && let Some(message) = self.rate_limit_closed(
                request.subscription_id,
                TangleRateLimitKey::query_class(request.scope, TangleRateLimitQueryClass::Broad),
                request.rules.broad(),
                request.label,
                "broad",
                request.now,
            )
        {
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
}

#[derive(Clone)]
pub struct TangleRuntimeHandle {
    inner: Arc<Mutex<TangleRuntime>>,
    metrics: TangleRuntimeMetrics,
}

impl TangleRuntimeHandle {
    pub fn new(runtime: TangleRuntime) -> Self {
        let metrics = runtime.metrics().clone();
        Self {
            inner: Arc::new(Mutex::new(runtime)),
            metrics,
        }
    }

    pub fn metrics(&self) -> TangleRuntimeMetrics {
        self.metrics.clone()
    }

    pub async fn auth_state(&self) -> Result<BaseAuthState, BaseRelayError> {
        self.inner.lock().await.auth_state()
    }

    pub async fn handle_client_message(
        &self,
        message: ClientMessage,
        auth: &mut BaseAuthState,
        now: UnixTimestamp,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        self.handle_client_message_with_query_context(
            message,
            auth,
            TangleQueryRateLimitContext::default(),
            now,
        )
        .await
    }

    pub async fn handle_client_message_with_query_context(
        &self,
        message: ClientMessage,
        auth: &mut BaseAuthState,
        query_context: TangleQueryRateLimitContext,
        now: UnixTimestamp,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        self.metrics
            .record_client_message(client_message_metric_kind(&message));
        let mut runtime = self.inner.lock().await;
        match message {
            ClientMessage::Event(event) => {
                let event_id = event.id().clone();
                if let Some(message) = runtime.rate_limit_event(&event, now) {
                    return Ok(vec![message]);
                }
                if let Some(message) = runtime.rate_limit_group_write(&event, now) {
                    return Ok(vec![message]);
                }
                let result = runtime
                    .relay_mut()
                    .handle_event_with_auth_report(event, auth)?;
                for offset in result.stored_offsets() {
                    runtime.metrics().record_stored_event_offset();
                    runtime.event_bus().publish(*offset);
                }
                if !result.stored_offsets().is_empty() {
                    logging::log_event_stored(
                        &event_id,
                        result.stored_offsets().len(),
                        runtime.metrics().stored_event_offsets(),
                    );
                }
                Ok(vec![result.into_message()])
            }
            ClientMessage::Req {
                subscription_id,
                filters,
            } => {
                runtime
                    .limits()
                    .base_relay_limits()
                    .validate_subscription_id(&subscription_id)?;
                runtime
                    .limits()
                    .base_relay_limits()
                    .validate_filters(&filters)?;
                if let Some(message) =
                    runtime.rate_limit_req(&subscription_id, &filters, auth, query_context, now)
                {
                    return Ok(vec![message]);
                }
                runtime.relay_mut().handle_client_message(
                    ClientMessage::Req {
                        subscription_id,
                        filters,
                    },
                    auth,
                    now,
                )
            }
            ClientMessage::Count {
                subscription_id,
                filters,
            } => {
                runtime
                    .limits()
                    .base_relay_limits()
                    .validate_subscription_id(&subscription_id)?;
                runtime
                    .limits()
                    .base_relay_limits()
                    .validate_filters(&filters)?;
                if let Some(message) =
                    runtime.rate_limit_count(&subscription_id, &filters, auth, query_context, now)
                {
                    return Ok(vec![message]);
                }
                runtime.relay_mut().handle_client_message(
                    ClientMessage::Count {
                        subscription_id,
                        filters,
                    },
                    auth,
                    now,
                )
            }
            ClientMessage::Auth(event) => {
                if let Err(error) = runtime.limits().base_relay_limits().validate_event(&event) {
                    return Ok(vec![RelayMessage::Ok {
                        event_id: event.id().clone(),
                        accepted: false,
                        message: error.prefixed_message(),
                    }]);
                }
                if let Some(message) = runtime.rate_limit_auth_attempt(&event, now) {
                    return Ok(vec![message]);
                }
                let event_for_failure = event.clone();
                let replies = runtime.relay_mut().handle_client_message(
                    ClientMessage::Auth(event),
                    auth,
                    now,
                )?;
                if auth_response_failed(&replies)
                    && let Some(message) = runtime.rate_limit_auth_failure(&event_for_failure, now)
                {
                    return Ok(vec![message]);
                }
                Ok(replies)
            }
            message => runtime
                .relay_mut()
                .handle_client_message(message, auth, now),
        }
    }

    pub async fn subscribe_events(&self) -> TangleEventReceiver {
        self.inner.lock().await.event_bus().subscribe()
    }

    pub async fn rate_limiter(&self) -> TangleRateLimiter {
        self.inner.lock().await.rate_limiter().clone()
    }

    pub async fn rate_limit_req(
        &self,
        subscription_id: &SubscriptionId,
        filters: &[Filter],
        auth: &BaseAuthState,
        query_context: TangleQueryRateLimitContext,
        now: UnixTimestamp,
    ) -> Option<RelayMessage> {
        self.inner
            .lock()
            .await
            .rate_limit_req(subscription_id, filters, auth, query_context, now)
    }

    pub(crate) async fn query_req_with_auth(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &BaseAuthState,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        self.inner
            .lock()
            .await
            .relay()
            .query_req_with_auth(subscription_id, filters, auth)
    }

    pub async fn event_by_offset_with_auth(
        &self,
        offset: StoreOffset,
        auth: &BaseAuthState,
    ) -> Result<Option<Event>, BaseRelayError> {
        self.inner
            .lock()
            .await
            .relay()
            .event_by_offset_with_auth(offset, auth)
    }

    pub(crate) async fn fanout_event_offset(
        &self,
        offset: StoreOffset,
        subscriptions: &mut LiveSubscriptionSet,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        self.inner
            .lock()
            .await
            .relay()
            .fanout_offset(offset, subscriptions)
    }

    pub async fn shutdown(&self) -> Result<BaseRelayShutdownReport, BaseRelayError> {
        self.inner.lock().await.shutdown()
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

fn client_message_metric_kind(message: &ClientMessage) -> TangleClientMessageMetricKind {
    match message {
        ClientMessage::Event(_) => TangleClientMessageMetricKind::Event,
        ClientMessage::Req { .. } => TangleClientMessageMetricKind::Req,
        ClientMessage::Count { .. } => TangleClientMessageMetricKind::Count,
        ClientMessage::Auth(_) => TangleClientMessageMetricKind::Auth,
        ClientMessage::Close(_) => TangleClientMessageMetricKind::Close,
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

fn query_is_broad(filters: &[Filter]) -> bool {
    filters.iter().any(|filter| {
        filter.ids().is_empty()
            && filter.authors().is_empty()
            && filter.kinds().is_empty()
            && filter.tag_filters().is_empty()
            && filter.search().is_none()
    })
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TangleClientMessageMetricKind {
    Event,
    Req,
    Count,
    Auth,
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TangleRuntimeMetricsSnapshot {
    uptime_seconds: u64,
    active_sessions: usize,
    total_sessions: u64,
    client_messages: u64,
    event_messages: u64,
    req_messages: u64,
    count_messages: u64,
    auth_messages: u64,
    close_messages: u64,
    opened_subscriptions: u64,
    closed_subscriptions: u64,
    stored_event_offsets: u64,
    rate_limit_rejections: u64,
}

impl TangleRuntimeMetricsSnapshot {
    pub fn active_sessions(&self) -> usize {
        self.active_sessions
    }

    pub fn total_sessions(&self) -> u64 {
        self.total_sessions
    }

    pub fn client_messages(&self) -> u64 {
        self.client_messages
    }

    pub fn event_messages(&self) -> u64 {
        self.event_messages
    }

    pub fn req_messages(&self) -> u64 {
        self.req_messages
    }

    pub fn count_messages(&self) -> u64 {
        self.count_messages
    }

    pub fn auth_messages(&self) -> u64 {
        self.auth_messages
    }

    pub fn close_messages(&self) -> u64 {
        self.close_messages
    }

    pub fn opened_subscriptions(&self) -> u64 {
        self.opened_subscriptions
    }

    pub fn closed_subscriptions(&self) -> u64 {
        self.closed_subscriptions
    }

    pub fn stored_event_offsets(&self) -> u64 {
        self.stored_event_offsets
    }

    pub fn rate_limit_rejections(&self) -> u64 {
        self.rate_limit_rejections
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
            }),
        }
    }

    pub fn snapshot(&self) -> TangleRuntimeMetricsSnapshot {
        TangleRuntimeMetricsSnapshot {
            uptime_seconds: self.started_at().elapsed().as_secs(),
            active_sessions: self.active_sessions(),
            total_sessions: self.total_sessions(),
            client_messages: self.client_messages(),
            event_messages: self.event_messages(),
            req_messages: self.req_messages(),
            count_messages: self.count_messages(),
            auth_messages: self.auth_messages(),
            close_messages: self.close_messages(),
            opened_subscriptions: self.opened_subscriptions(),
            closed_subscriptions: self.closed_subscriptions(),
            stored_event_offsets: self.stored_event_offsets(),
            rate_limit_rejections: self.rate_limit_rejections(),
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
        TangleQueryRateLimitContext, TangleRuntime, TangleRuntimeHandle, TangleRuntimeLimits,
    };
    use crate::config::{BaseRelayRuntimeConfig, parse_base_relay_runtime_config_json};
    use crate::event_bus::{TangleEventBus, TangleEventReceiveError};
    use crate::rate_limits::{TangleRateLimitKey, TangleRateLimitQueryClass, TangleRateLimitScope};
    use crate::relay::core::{BaseRelayLimitSettings, BaseRelayLimits};
    use crate::relay::live::LiveSubscriptionSet;
    use serde_json::json;
    use std::{
        net::{IpAddr, Ipv4Addr},
        path::{Path, PathBuf},
    };
    use tangle_groups::{
        GroupAuthContext, GroupId, KIND_GROUP_ADMINS, KIND_GROUP_JOIN_REQUEST, KIND_GROUP_METADATA,
        StoreOffset,
    };
    use tangle_protocol::{
        ClientMessage, Kind, RelayMessage, SubscriptionId, Tag, UnixTimestamp, filter_from_value,
    };
    use tangle_test_support::{
        FixtureKey, tangle_v2_auth_event, tangle_v2_event, tangle_v2_group_create_event,
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
        let snapshot = runtime.metrics().snapshot();
        assert_eq!(snapshot.active_sessions(), 0);
        assert_eq!(snapshot.total_sessions(), 1);
        assert_eq!(snapshot.client_messages(), 1);
        assert_eq!(snapshot.req_messages(), 1);
        assert_eq!(snapshot.opened_subscriptions(), 1);
        assert_eq!(snapshot.closed_subscriptions(), 1);
        assert_eq!(snapshot.stored_event_offsets(), 1);
        assert_eq!(snapshot.rate_limit_rejections(), 1);

        let report = runtime.shutdown().expect("shutdown");

        assert_eq!(report.closed_subscriptions(), 0);
        assert!(runtime.shutdown_signal().requested());
        assert!(*shutdown.borrow());

        let _ = std::fs::remove_dir_all(root);
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
                GroupAuthContext::unauthenticated(),
            )
            .expect("subscribe");
        let event = tangle_v2_event(FixtureKey::Member, 1_714_124_433, 1, Vec::new(), "live")
            .expect("event");

        assert_eq!(
            handle
                .handle_client_message(
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
                .fanout_event_offset(offset, &mut subscriptions)
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
                .handle_client_message(
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
                .handle_client_message(
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
                .handle_client_message(
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
                .handle_client_message(
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
                .handle_client_message(
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
                .handle_client_message(
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
                .handle_client_message(
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
                .handle_client_message(
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
                .handle_client_message(
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
                .handle_client_message(
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
                .handle_client_message(
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
                .handle_client_message_with_query_context(
                    ClientMessage::Req {
                        subscription_id: subscription_id.clone(),
                        filters
                    },
                    &mut auth,
                    TangleQueryRateLimitContext::new(None, Some(77)),
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
                .handle_client_message(
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
        let filters = vec![filter_from_value(&json!({"kinds": [1], "limit": 1})).expect("filter")];

        assert_eq!(
            handle
                .handle_client_message_with_query_context(
                    ClientMessage::Count {
                        subscription_id: subscription_id.clone(),
                        filters
                    },
                    &mut auth,
                    TangleQueryRateLimitContext::new(Some(peer_ip), None),
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
        let filters = vec![filter_from_value(&json!({"kinds": [1], "limit": 1})).expect("filter")];

        assert_eq!(
            handle
                .handle_client_message(
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
    async fn runtime_rate_limits_count_broad_queries() {
        let root = temp_root("runtime-count-broad-rate-limit");
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
                .handle_client_message(
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
                message: "rate-limited: count broad rate limit exceeded until 1714124493"
                    .to_owned()
            }]
        );

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
                    filter_from_value(&json!({"kinds":[KIND_GROUP_METADATA, KIND_GROUP_ADMINS]}))
                        .expect("filter"),
                ],
                GroupAuthContext::unauthenticated(),
            )
            .expect("subscribe");

        assert_eq!(
            handle
                .handle_client_message(
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
                .handle_client_message(
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
        for offset in generated_offsets {
            assert!(matches!(
                handle
                    .fanout_event_offset(offset, &mut subscriptions)
                    .await
                    .expect("fanout")
                    .as_slice(),
                [RelayMessage::Event {
                    subscription_id: delivered,
                    event
                }] if delivered == &subscription_id
                    && [KIND_GROUP_METADATA, KIND_GROUP_ADMINS]
                        .contains(&event.unsigned().kind().as_u32())
            ));
        }
        assert_eq!(
            offsets.try_recv().expect_err("only source plus generated"),
            TangleEventReceiveError::Empty
        );

        let _ = std::fs::remove_dir_all(root);
    }

    fn runtime_config(root: &Path, per_connection_outbound_queue: usize) -> BaseRelayRuntimeConfig {
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
                "owner_pubkeys": [FixtureKey::Owner.public_key().as_str()]
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
                "broadcast_channel_capacity": 16,
                "per_connection_outbound_queue": per_connection_outbound_queue
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
