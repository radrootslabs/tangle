#![forbid(unsafe_code)]

use crate::{
    config::BaseRelayRuntimeConfig,
    errors::BaseRelayError,
    event_bus::{TangleEventBus, TangleEventReceiver},
    groups::GroupServiceHandle,
    logging,
    ops::{BaseRelayReadinessHandle, BaseRelayReadinessState},
    pocket_conversion::pocket_event_to_tangle,
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
    ClientMessage, Event, Filter, Kind, RelayMessage, SubscriptionId, UnixTimestamp,
};
use tangle_store_pocket::PocketStoreHandle;
use tokio::sync::{Mutex, watch};

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
    relay: Mutex<BaseRelay>,
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
            relay: Mutex::new(relay),
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

    fn rate_limit_auth_attempt(
        &self,
        event: &Event,
        context: TangleClientRateLimitContext,
        now: UnixTimestamp,
    ) -> Option<RelayMessage> {
        let rules = self.config.rate_limits().auth();
        if let Some(peer_ip) = context.peer_ip
            && let Some(message) = self.rate_limit_ok(
                event,
                TangleRateLimitKey::ip(TangleRateLimitScope::Auth, peer_ip),
                rules.per_ip(),
                "auth ip",
                now,
            )
        {
            return Some(message);
        }
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

    fn rate_limit_auth_failure(
        &self,
        event: &Event,
        context: TangleClientRateLimitContext,
        now: UnixTimestamp,
    ) -> Option<RelayMessage> {
        let rules = self.config.rate_limits().auth();
        if let Some(peer_ip) = context.peer_ip
            && let Some(message) = self.rate_limit_ok(
                event,
                TangleRateLimitKey::auth_failure(Some(peer_ip), None),
                rules.failures_per_ip(),
                "auth failure ip",
                now,
            )
        {
            return Some(message);
        }
        self.rate_limit_ok(
            event,
            TangleRateLimitKey::auth_failure(None, Some(event.unsigned().pubkey().clone())),
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

    pub async fn handle_client_message(
        &self,
        message: ClientMessage,
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

    pub async fn handle_client_message_with_rate_limit_context(
        &self,
        message: ClientMessage,
        auth: &mut BaseAuthState,
        rate_limit_context: TangleClientRateLimitContext,
        now: UnixTimestamp,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        self.inner
            .metrics
            .record_client_message(client_message_metric_kind(&message));
        match message {
            ClientMessage::Event(event) => {
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
                let (result, group_outbox_pending_events) = {
                    let mut relay = self.inner.relay.lock().await;
                    let result = relay.handle_event_with_auth_report(event, auth)?;
                    let pending_events =
                        is_group_event.then(|| relay.group_outbox_pending_events());
                    (result, pending_events)
                };
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
            ClientMessage::Req {
                subscription_id,
                filters,
            } => {
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
                let report = self.inner.relay.lock().await.query_req_with_auth_report(
                    subscription_id,
                    filters,
                    auth,
                )?;
                if report.group_read_denied() {
                    self.inner.metrics.record_group_read_denial();
                }
                self.inner
                    .metrics
                    .record_query_latency(elapsed_micros(started_at));
                Ok(report.into_messages())
            }
            ClientMessage::Count {
                subscription_id,
                filters,
            } => {
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
                let report = self
                    .inner
                    .relay
                    .lock()
                    .await
                    .handle_count_with_auth_report(subscription_id, filters, auth)?;
                if report.group_read_denied() {
                    self.inner.metrics.record_group_read_denial();
                }
                self.inner
                    .metrics
                    .record_query_latency(elapsed_micros(started_at));
                Ok(vec![report.into_message()])
            }
            ClientMessage::Auth(event) => {
                if let Err(error) = self.inner.limits.base_relay_limits().validate_event(&event) {
                    self.inner.metrics.record_auth_failure();
                    return Ok(vec![RelayMessage::Ok {
                        event_id: event.id().clone(),
                        accepted: false,
                        message: error.prefixed_message(),
                    }]);
                }
                if let Some(message) =
                    self.inner
                        .rate_limit_auth_attempt(&event, rate_limit_context, now)
                {
                    self.inner.metrics.record_auth_failure();
                    return Ok(vec![message]);
                }
                let event_for_failure = event.clone();
                let replies = self.inner.relay.lock().await.handle_client_message(
                    ClientMessage::Auth(event),
                    auth,
                    now,
                )?;
                if auth_response_failed(&replies) {
                    self.inner.metrics.record_auth_failure();
                    if let Some(message) = self.inner.rate_limit_auth_failure(
                        &event_for_failure,
                        rate_limit_context,
                        now,
                    ) {
                        return Ok(vec![message]);
                    }
                } else {
                    self.inner.metrics.record_auth_success();
                }
                Ok(replies)
            }
            message => self
                .inner
                .relay
                .lock()
                .await
                .handle_client_message(message, auth, now),
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

    pub(crate) async fn query_req_with_auth(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &BaseAuthState,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        let started_at = Instant::now();
        let report = self.inner.relay.lock().await.query_req_with_auth_report(
            subscription_id,
            filters,
            auth,
        )?;
        if report.group_read_denied() {
            self.inner.metrics.record_group_read_denial();
        }
        self.inner
            .metrics
            .record_query_latency(elapsed_micros(started_at));
        Ok(report.into_messages())
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
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        let pocket_event = self.inner.store.event_by_offset(offset.as_u64())?;
        let event = pocket_event_to_tangle(&pocket_event)?;
        Ok(subscriptions.fanout(&event, |event, auth| {
            BaseRelay::group_read_gate_visible_to_auth(self.inner.groups.as_ref(), event, auth)
                .unwrap_or(false)
        }))
    }

    pub async fn shutdown(&self) -> Result<BaseRelayShutdownReport, BaseRelayError> {
        self.inner.shutdown.request_shutdown();
        self.inner.relay.lock().await.shutdown()
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
    outbox_pending_events: AtomicUsize,
    outbox_replayed_events: AtomicU64,
    disk_used_bytes: AtomicU64,
    event_admission_latency_total_micros: AtomicU64,
    event_admission_latency_count: AtomicU64,
    query_latency_total_micros: AtomicU64,
    query_latency_count: AtomicU64,
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
    tangle_outbox_pending_events: usize,
    tangle_outbox_replayed_events_total: u64,
    tangle_disk_used_bytes: u64,
    tangle_event_admission_latency_total_micros: u64,
    tangle_event_admission_latency_count: u64,
    tangle_query_latency_total_micros: u64,
    tangle_query_latency_count: u64,
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
                outbox_pending_events: AtomicUsize::new(0),
                outbox_replayed_events: AtomicU64::new(0),
                disk_used_bytes: AtomicU64::new(0),
                event_admission_latency_total_micros: AtomicU64::new(0),
                event_admission_latency_count: AtomicU64::new(0),
                query_latency_total_micros: AtomicU64::new(0),
                query_latency_count: AtomicU64::new(0),
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
            tangle_outbox_pending_events: self.outbox_pending_events(),
            tangle_outbox_replayed_events_total: self.outbox_replayed_events(),
            tangle_disk_used_bytes: self.disk_used_bytes(),
            tangle_event_admission_latency_total_micros: self
                .event_admission_latency_total_micros(),
            tangle_event_admission_latency_count: self.event_admission_latency_count(),
            tangle_query_latency_total_micros: self.query_latency_total_micros(),
            tangle_query_latency_count: self.query_latency_count(),
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
        TangleClientRateLimitContext, TangleRuntime, TangleRuntimeHandle, TangleRuntimeLimits,
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
        runtime.metrics().record_outbox_pending_events(2);
        assert_eq!(runtime.metrics().record_outbox_replayed_event(), 1);
        runtime.metrics().record_disk_used_bytes(5);
        runtime.metrics().record_event_admission_latency(13);
        runtime.metrics().record_query_latency(17);
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
                .handle_client_message_with_rate_limit_context(
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
                .handle_client_message_with_rate_limit_context(
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
                .handle_client_message_with_rate_limit_context(
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
                .handle_client_message_with_rate_limit_context(
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
                .handle_client_message_with_rate_limit_context(
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
                .handle_client_message_with_rate_limit_context(
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
                .handle_client_message_with_rate_limit_context(
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
                .handle_client_message_with_rate_limit_context(
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
                .handle_client_message_with_rate_limit_context(
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
                .handle_client_message(
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
                .handle_client_message(
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
        assert_eq!(handle.metrics().outbox_replayed_events(), 2);
        assert_eq!(handle.metrics().outbox_pending_events(), 0);
        assert_eq!(handle.metrics().event_bus_published_offsets(), 3);
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
