use crate::errors::{BaseRelayError, ok_accepted, ok_rejected};
use crate::groups::{
    GroupEventWrite, GroupEventWriteError, GroupProjectionReadGuard, GroupServiceHandle,
};
use crate::logging::{self, TangleModerationAuditResult};
use crate::ops::BaseRelayReadinessState;
use crate::pocket_conversion::{
    pocket_event_id, pocket_event_to_tangle, tangle_event_to_pocket, tangle_filter_to_pocket,
};
use crate::relay::{
    auth::BaseAuthState,
    live::{CloseResult, LiveSubscriptionSet},
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
};
use tangle_crypto::verify_event_signature;
use tangle_groups::{
    GroupAuthContext, GroupEventClass, GroupEventView, GroupRuntimeConfig, StoreOffset,
    classify_group_event, validate_client_group_event_structure,
};
use tangle_protocol::{ClientMessage, Event, Filter, RelayMessage, SubscriptionId, UnixTimestamp};
use tangle_store_pocket::{
    PocketQueryConfig, PocketScreenResult, PocketStoreConfig, PocketStoreHandle,
};

pub struct BaseRelay {
    store: PocketStoreHandle,
    subscriptions: LiveSubscriptionSet,
    groups: Option<GroupServiceHandle>,
    readiness: BaseRelayReadinessState,
    limits: BaseRelayLimits,
    query: PocketQueryConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BaseRelayEventWrite {
    message: RelayMessage,
    stored_offsets: Vec<StoreOffset>,
}

impl BaseRelayEventWrite {
    fn stored(message: RelayMessage, stored_offsets: Vec<StoreOffset>) -> Self {
        Self {
            message,
            stored_offsets,
        }
    }

    fn unstored(message: RelayMessage) -> Self {
        Self {
            message,
            stored_offsets: Vec::new(),
        }
    }

    pub(crate) fn stored_offsets(&self) -> &[StoreOffset] {
        &self.stored_offsets
    }

    pub(crate) fn into_message(self) -> RelayMessage {
        self.message
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BaseRelayQueryReport {
    messages: Vec<RelayMessage>,
    group_read_denied: bool,
    query_metrics: BaseRelayQueryMetrics,
}

impl BaseRelayQueryReport {
    fn new(
        messages: Vec<RelayMessage>,
        group_read_denied: bool,
        query_metrics: BaseRelayQueryMetrics,
    ) -> Self {
        Self {
            messages,
            group_read_denied,
            query_metrics,
        }
    }

    pub(crate) fn group_read_denied(&self) -> bool {
        self.group_read_denied
    }

    pub(crate) fn query_metrics(&self) -> BaseRelayQueryMetrics {
        self.query_metrics
    }

    pub(crate) fn into_messages(self) -> Vec<RelayMessage> {
        self.messages
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BaseRelayCountReport {
    message: RelayMessage,
    group_read_denied: bool,
    query_metrics: BaseRelayQueryMetrics,
}

impl BaseRelayCountReport {
    fn new(
        message: RelayMessage,
        group_read_denied: bool,
        query_metrics: BaseRelayQueryMetrics,
    ) -> Self {
        Self {
            message,
            group_read_denied,
            query_metrics,
        }
    }

    pub(crate) fn group_read_denied(&self) -> bool {
        self.group_read_denied
    }

    pub(crate) fn query_metrics(&self) -> BaseRelayQueryMetrics {
        self.query_metrics
    }

    pub(crate) fn into_message(self) -> RelayMessage {
        self.message
    }
}

#[derive(Debug, Clone, PartialEq)]
struct BaseRelayEventQueryReport {
    events: Vec<Event>,
    group_read_denied: bool,
    query_metrics: BaseRelayQueryMetrics,
}

impl BaseRelayEventQueryReport {
    fn new(
        events: Vec<Event>,
        group_read_denied: bool,
        query_metrics: BaseRelayQueryMetrics,
    ) -> Self {
        Self {
            events,
            group_read_denied,
            query_metrics,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct BaseRelayQueryMetrics {
    candidates_scanned: u64,
    returned_events: u64,
    redacted_events: u64,
}

impl BaseRelayQueryMetrics {
    pub(crate) fn new(candidates_scanned: u64, returned_events: u64, redacted_events: u64) -> Self {
        Self {
            candidates_scanned,
            returned_events,
            redacted_events,
        }
    }

    fn add(self, other: Self) -> Self {
        Self {
            candidates_scanned: self
                .candidates_scanned
                .saturating_add(other.candidates_scanned),
            returned_events: self.returned_events.saturating_add(other.returned_events),
            redacted_events: self.redacted_events.saturating_add(other.redacted_events),
        }
    }

    fn with_returned_events(self, returned_events: usize) -> Self {
        Self {
            returned_events: u64::try_from(returned_events).expect("returned events fit in u64"),
            ..self
        }
    }

    pub(crate) fn candidates_scanned(self) -> u64 {
        self.candidates_scanned
    }

    pub(crate) fn returned_events(self) -> u64 {
        self.returned_events
    }

    pub(crate) fn redacted_events(self) -> u64 {
        self.redacted_events
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BaseRelayCountEventsReport {
    count: u64,
    group_read_denied: bool,
    query_metrics: BaseRelayQueryMetrics,
}

impl BaseRelayCountEventsReport {
    fn new(count: u64, group_read_denied: bool, query_metrics: BaseRelayQueryMetrics) -> Self {
        Self {
            count,
            group_read_denied,
            query_metrics,
        }
    }
}

fn is_nip70_protected_event(event: &Event) -> bool {
    event
        .unsigned()
        .tags()
        .iter()
        .any(|tag| tag.name().as_str() == "-")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseRelayShutdownReport {
    closed_subscriptions: usize,
}

impl BaseRelayShutdownReport {
    pub fn new(closed_subscriptions: usize) -> Self {
        Self {
            closed_subscriptions,
        }
    }

    pub fn closed_subscriptions(self) -> usize {
        self.closed_subscriptions
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseRelayLimits {
    max_pending_events: usize,
    max_subscription_id_length: usize,
    max_subscriptions: usize,
    max_filters_per_request: usize,
    max_tag_values_per_filter: usize,
    max_query_complexity: usize,
    max_event_tags: usize,
    max_content_length: usize,
    max_limit: u64,
    default_limit: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseRelayLimitSettings {
    pub max_pending_events: usize,
    pub max_subscription_id_length: usize,
    pub max_subscriptions: usize,
    pub max_filters_per_request: usize,
    pub max_tag_values_per_filter: usize,
    pub max_query_complexity: usize,
    pub max_event_tags: usize,
    pub max_content_length: usize,
    pub max_limit: u64,
    pub default_limit: u64,
}

impl BaseRelayLimits {
    pub fn new(settings: BaseRelayLimitSettings) -> Result<Self, BaseRelayError> {
        let max_pending_events = settings.max_pending_events;
        let max_subscription_id_length = settings.max_subscription_id_length;
        let max_subscriptions = settings.max_subscriptions;
        let max_filters_per_request = settings.max_filters_per_request;
        let max_tag_values_per_filter = settings.max_tag_values_per_filter;
        let max_query_complexity = settings.max_query_complexity;
        let max_event_tags = settings.max_event_tags;
        let max_content_length = settings.max_content_length;
        let max_limit = settings.max_limit;
        let default_limit = settings.default_limit;
        if max_pending_events == 0 {
            return Err(BaseRelayError::invalid(
                "runtime max pending events must be greater than zero",
            ));
        }
        if max_subscription_id_length == 0 {
            return Err(BaseRelayError::invalid(
                "runtime max subscription id length must be greater than zero",
            ));
        }
        if max_subscriptions == 0 {
            return Err(BaseRelayError::invalid(
                "runtime max subscriptions per connection must be greater than zero",
            ));
        }
        if max_filters_per_request == 0 {
            return Err(BaseRelayError::invalid(
                "runtime max filters per request must be greater than zero",
            ));
        }
        if max_tag_values_per_filter == 0 {
            return Err(BaseRelayError::invalid(
                "runtime max tag values per filter must be greater than zero",
            ));
        }
        if max_query_complexity == 0 {
            return Err(BaseRelayError::invalid(
                "runtime max query complexity must be greater than zero",
            ));
        }
        if max_event_tags == 0 {
            return Err(BaseRelayError::invalid(
                "runtime max event tags must be greater than zero",
            ));
        }
        if max_content_length == 0 {
            return Err(BaseRelayError::invalid(
                "runtime max content length must be greater than zero",
            ));
        }
        if max_limit == 0 {
            return Err(BaseRelayError::invalid(
                "runtime max filter limit must be greater than zero",
            ));
        }
        if default_limit == 0 {
            return Err(BaseRelayError::invalid(
                "runtime default filter limit must be greater than zero",
            ));
        }
        if default_limit > max_limit {
            return Err(BaseRelayError::invalid(
                "runtime default filter limit must not exceed max filter limit",
            ));
        }
        if usize::try_from(default_limit).is_ok_and(|limit| limit > max_query_complexity) {
            return Err(BaseRelayError::invalid(
                "runtime default filter limit must not exceed max query complexity",
            ));
        }
        Ok(Self {
            max_pending_events,
            max_subscription_id_length,
            max_subscriptions,
            max_filters_per_request,
            max_tag_values_per_filter,
            max_query_complexity,
            max_event_tags,
            max_content_length,
            max_limit,
            default_limit,
        })
    }

    pub fn max_pending_events(self) -> usize {
        self.max_pending_events
    }

    pub fn max_subscription_id_length(self) -> usize {
        self.max_subscription_id_length
    }

    pub fn max_subscriptions(self) -> usize {
        self.max_subscriptions
    }

    pub fn max_filters_per_request(self) -> usize {
        self.max_filters_per_request
    }

    pub fn max_tag_values_per_filter(self) -> usize {
        self.max_tag_values_per_filter
    }

    pub fn max_query_complexity(self) -> usize {
        self.max_query_complexity
    }

    pub fn max_event_tags(self) -> usize {
        self.max_event_tags
    }

    pub fn max_content_length(self) -> usize {
        self.max_content_length
    }

    pub fn max_limit(self) -> u64 {
        self.max_limit
    }

    pub fn default_limit(self) -> u64 {
        self.default_limit
    }

    pub fn validate_event(&self, event: &Event) -> Result<(), BaseRelayError> {
        if event.unsigned().tags().len() > self.max_event_tags {
            return Err(BaseRelayError::invalid(format!(
                "event tag count exceeds runtime max_event_tags {}",
                self.max_event_tags
            )));
        }
        if event.unsigned().content().len() > self.max_content_length {
            return Err(BaseRelayError::invalid(format!(
                "event content length exceeds runtime max_content_length {}",
                self.max_content_length
            )));
        }
        Ok(())
    }

    pub fn validate_subscription_id(
        &self,
        subscription_id: &SubscriptionId,
    ) -> Result<(), BaseRelayError> {
        let actual = subscription_id.as_str().chars().count();
        if actual > self.max_subscription_id_length {
            return Err(BaseRelayError::invalid(format!(
                "subscription id length exceeds runtime max_subid_length {}",
                self.max_subscription_id_length
            )));
        }
        Ok(())
    }

    pub fn validate_filters(&self, filters: &[Filter]) -> Result<(), BaseRelayError> {
        if filters.is_empty() {
            return Err(BaseRelayError::invalid(
                "request must include at least one filter",
            ));
        }
        if filters.len() > self.max_filters_per_request {
            return Err(BaseRelayError::invalid(format!(
                "filter count exceeds runtime max_filters_per_request {}",
                self.max_filters_per_request
            )));
        }
        for filter in filters {
            let tag_values = filter.tag_filters().values().map(Vec::len).sum::<usize>();
            if tag_values > self.max_tag_values_per_filter {
                return Err(BaseRelayError::invalid(format!(
                    "filter tag value count exceeds runtime max_tag_values_per_filter {}",
                    self.max_tag_values_per_filter
                )));
            }
            if filter.limit().is_some_and(|limit| limit > self.max_limit) {
                return Err(BaseRelayError::invalid(format!(
                    "filter limit exceeds runtime max_limit {}",
                    self.max_limit
                )));
            }
        }
        self.validate_query_complexity(filters)?;
        Ok(())
    }

    fn effective_filter_limit(self, filter: &Filter) -> usize {
        usize::try_from(filter.limit().unwrap_or(self.default_limit)).unwrap_or(usize::MAX)
    }

    fn validate_query_complexity(&self, filters: &[Filter]) -> Result<(), BaseRelayError> {
        let score = filters
            .iter()
            .map(|filter| self.filter_complexity(filter))
            .fold(0_usize, usize::saturating_add);
        if score > self.max_query_complexity {
            return Err(BaseRelayError::invalid(format!(
                "query complexity {score} exceeds runtime max_query_complexity {}",
                self.max_query_complexity
            )));
        }
        Ok(())
    }

    fn filter_complexity(&self, filter: &Filter) -> usize {
        let tag_score = filter
            .tag_filters()
            .values()
            .map(|values| 1_usize.saturating_add(values.len()))
            .fold(0_usize, usize::saturating_add);
        1_usize
            .saturating_add(filter.ids().len())
            .saturating_add(filter.authors().len())
            .saturating_add(filter.kinds().len())
            .saturating_add(tag_score)
            .saturating_add(usize::from(filter.since().is_some()))
            .saturating_add(usize::from(filter.until().is_some()))
            .saturating_add(filter.search().map(str::len).unwrap_or(0))
            .saturating_add(self.effective_filter_limit(filter))
    }
}

impl BaseRelay {
    pub(crate) fn unsupported_search_closed(
        subscription_id: &SubscriptionId,
        filters: &[Filter],
    ) -> Option<RelayMessage> {
        filters
            .iter()
            .any(|filter| filter.search().is_some())
            .then(|| RelayMessage::Closed {
                subscription_id: subscription_id.clone(),
                message: "unsupported: search filters are not supported".to_owned(),
            })
    }

    pub fn open(
        config: &PocketStoreConfig,
        limits: BaseRelayLimits,
        query: PocketQueryConfig,
    ) -> Result<Self, BaseRelayError> {
        let store = PocketStoreHandle::open(config).map_err(BaseRelayError::from)?;
        Self::new(store, limits, query)
    }

    pub fn open_with_groups(
        config: &PocketStoreConfig,
        limits: BaseRelayLimits,
        groups: &GroupRuntimeConfig,
        query: PocketQueryConfig,
    ) -> Result<Self, BaseRelayError> {
        let store = PocketStoreHandle::open(config).map_err(BaseRelayError::from)?;
        Self::new_with_groups(store, limits, groups, query)
    }

    pub fn new(
        store: PocketStoreHandle,
        limits: BaseRelayLimits,
        query: PocketQueryConfig,
    ) -> Result<Self, BaseRelayError> {
        Self::new_with_groups(store, limits, &GroupRuntimeConfig::disabled(), query)
    }

    pub fn new_with_groups(
        store: PocketStoreHandle,
        limits: BaseRelayLimits,
        groups: &GroupRuntimeConfig,
        query: PocketQueryConfig,
    ) -> Result<Self, BaseRelayError> {
        let groups = GroupServiceHandle::from_config(&store, groups)?;
        let subscriptions =
            LiveSubscriptionSet::new(limits.max_pending_events(), limits.max_subscriptions())?;
        let readiness = BaseRelayReadinessState::runtime_ready_before_bind();
        Ok(Self {
            store,
            subscriptions,
            groups,
            readiness,
            limits,
            query,
        })
    }

    pub fn handle_client_message(
        &mut self,
        message: ClientMessage,
        auth: &mut BaseAuthState,
        now: UnixTimestamp,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        match message {
            ClientMessage::Event(event) => self
                .handle_event_with_auth(event, auth)
                .map(|message| vec![message]),
            ClientMessage::Req {
                subscription_id,
                filters,
            } => self.handle_req_with_auth(subscription_id, filters, auth),
            ClientMessage::Count {
                subscription_id,
                filters,
            } => self
                .handle_count_with_auth(subscription_id, filters, auth)
                .map(|message| vec![message]),
            ClientMessage::Close(subscription_id) => {
                self.handle_close(&subscription_id);
                Ok(Vec::new())
            }
            ClientMessage::Auth(event) => Ok(self.handle_auth_message(event, auth, now)),
        }
    }

    pub(crate) fn query_req_with_shared_services(
        store: &PocketStoreHandle,
        groups: Option<&GroupServiceHandle>,
        limits: BaseRelayLimits,
        query: PocketQueryConfig,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &BaseAuthState,
    ) -> Result<BaseRelayQueryReport, BaseRelayError> {
        Self::query_req_with_group_auth_shared_services(
            store,
            groups,
            limits,
            query,
            subscription_id,
            filters,
            &GroupAuthContext::new(auth.authenticated_pubkeys().iter().cloned()),
        )
    }

    fn event_by_offset(&self, offset: StoreOffset) -> Result<Event, BaseRelayError> {
        let event = self.store.event_by_offset(offset.as_u64())?;
        pocket_event_to_tangle(&event)
    }

    pub fn event_by_offset_with_auth(
        &self,
        offset: StoreOffset,
        auth: &BaseAuthState,
    ) -> Result<Option<Event>, BaseRelayError> {
        let event = self.event_by_offset(offset)?;
        if Self::group_read_gate_visible_to_auth(
            self.groups.as_ref(),
            &event,
            &GroupAuthContext::new(auth.authenticated_pubkeys().iter().cloned()),
        )? {
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }

    pub fn query_events_with_auth(
        &self,
        filters: &[Filter],
        auth: &BaseAuthState,
    ) -> Result<Vec<Event>, BaseRelayError> {
        self.limits.validate_filters(filters)?;
        self.query_events(
            filters,
            &GroupAuthContext::new(auth.authenticated_pubkeys().iter().cloned()),
        )
    }

    fn handle_auth_message(
        &self,
        event: Event,
        auth: &mut BaseAuthState,
        now: UnixTimestamp,
    ) -> Vec<RelayMessage> {
        Self::handle_auth_with_limits(self.limits, event, auth, now)
    }

    pub(crate) fn handle_auth_with_limits(
        limits: BaseRelayLimits,
        event: Event,
        auth: &mut BaseAuthState,
        now: UnixTimestamp,
    ) -> Vec<RelayMessage> {
        if let Err(error) = limits.validate_event(&event) {
            return vec![RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: false,
                message: error.prefixed_message(),
            }];
        }
        auth.authenticate(&event, now)
            .map(|_| {
                vec![RelayMessage::Ok {
                    event_id: event.id().clone(),
                    accepted: true,
                    message: String::new(),
                }]
            })
            .unwrap_or_else(|error| {
                vec![RelayMessage::Ok {
                    event_id: event.id().clone(),
                    accepted: false,
                    message: error.prefixed_message(),
                }]
            })
    }

    pub fn handle_event(&self, event: Event) -> Result<RelayMessage, BaseRelayError> {
        self.handle_event_with_group_auth(event, &GroupAuthContext::unauthenticated())
            .map(BaseRelayEventWrite::into_message)
    }

    pub fn handle_event_with_auth(
        &self,
        event: Event,
        auth: &BaseAuthState,
    ) -> Result<RelayMessage, BaseRelayError> {
        self.handle_event_with_auth_report(event, auth)
            .map(BaseRelayEventWrite::into_message)
    }

    pub(crate) fn handle_event_with_auth_report(
        &self,
        event: Event,
        auth: &BaseAuthState,
    ) -> Result<BaseRelayEventWrite, BaseRelayError> {
        Self::handle_event_with_shared_services(
            &self.store,
            self.groups.as_ref(),
            self.limits,
            event,
            auth,
        )
    }

    pub(crate) fn handle_event_with_shared_services(
        store: &PocketStoreHandle,
        groups: Option<&GroupServiceHandle>,
        limits: BaseRelayLimits,
        event: Event,
        auth: &BaseAuthState,
    ) -> Result<BaseRelayEventWrite, BaseRelayError> {
        Self::handle_event_with_group_auth_and_services(
            store,
            groups,
            limits,
            event,
            &GroupAuthContext::new(auth.authenticated_pubkeys().iter().cloned()),
        )
    }

    pub fn groups_enabled(&self) -> bool {
        self.groups.is_some()
    }

    pub(crate) fn store_handle(&self) -> PocketStoreHandle {
        self.store.clone()
    }

    pub fn group_projection(&self) -> Option<GroupProjectionReadGuard<'_>> {
        self.groups.as_ref().map(GroupServiceHandle::projection)
    }

    pub(crate) fn group_service_handle(&self) -> Option<GroupServiceHandle> {
        self.groups.clone()
    }

    pub(crate) fn group_outbox_pending_events(&self) -> usize {
        self.groups
            .as_ref()
            .map(GroupServiceHandle::outbox_pending_events)
            .unwrap_or(0)
    }

    pub fn readiness_state(&self) -> BaseRelayReadinessState {
        self.readiness.clone()
    }

    pub fn shutdown(&mut self) -> Result<BaseRelayShutdownReport, BaseRelayError> {
        let closed = self.subscriptions.close_all();
        self.store.sync()?;
        Ok(BaseRelayShutdownReport::new(closed))
    }

    fn handle_event_with_group_auth(
        &self,
        event: Event,
        auth: &GroupAuthContext,
    ) -> Result<BaseRelayEventWrite, BaseRelayError> {
        Self::handle_event_with_group_auth_and_services(
            &self.store,
            self.groups.as_ref(),
            self.limits,
            event,
            auth,
        )
    }

    fn handle_event_with_group_auth_and_services(
        store: &PocketStoreHandle,
        groups: Option<&GroupServiceHandle>,
        limits: BaseRelayLimits,
        event: Event,
        auth: &GroupAuthContext,
    ) -> Result<BaseRelayEventWrite, BaseRelayError> {
        let event_id = event.id().clone();
        if let Err(error) = limits.validate_event(&event) {
            return Ok(BaseRelayEventWrite::unstored(ok_rejected(
                event_id,
                error.prefixed_message(),
            )));
        }
        if let Err(error) = verify_event_signature(&event) {
            return Ok(BaseRelayEventWrite::unstored(ok_rejected(
                event_id,
                format!("invalid: {error}"),
            )));
        }
        if is_nip70_protected_event(&event) && !auth.contains(event.unsigned().pubkey()) {
            return Ok(BaseRelayEventWrite::unstored(ok_rejected(
                event_id,
                BaseRelayError::auth_required(
                    "protected event requires authenticated event author",
                )
                .prefixed_message(),
            )));
        }
        let group_limits = groups.map(GroupServiceHandle::limits).unwrap_or_default();
        let audit_class = classify_group_event(&event, group_limits).ok();
        let class = match validate_client_group_event_structure(&event, group_limits) {
            Ok(class) => class,
            Err(error) => {
                if let Some(class) = audit_class.as_ref() {
                    logging::log_group_moderation_audit(
                        &event,
                        class,
                        TangleModerationAuditResult::Rejected,
                    );
                }
                return Ok(BaseRelayEventWrite::unstored(ok_rejected(
                    event_id,
                    error.prefixed_message(),
                )));
            }
        };
        if !matches!(class, GroupEventClass::NonGroup) {
            let Some(groups) = groups else {
                logging::log_group_moderation_audit(
                    &event,
                    &class,
                    TangleModerationAuditResult::Rejected,
                );
                return Ok(BaseRelayEventWrite::unstored(ok_rejected(
                    event_id,
                    "blocked: NIP-29 group events are not accepted before group service".to_owned(),
                )));
            };
            match groups.store_group_event(store, &event, &class, auth) {
                Ok(GroupEventWrite::Stored(stored_offsets)) => {
                    logging::log_group_moderation_audit(
                        &event,
                        &class,
                        TangleModerationAuditResult::Accepted,
                    );
                    return Ok(BaseRelayEventWrite::stored(
                        ok_accepted(event_id, String::new()),
                        stored_offsets,
                    ));
                }
                Ok(GroupEventWrite::Duplicate) => {
                    logging::log_group_moderation_audit(
                        &event,
                        &class,
                        TangleModerationAuditResult::Accepted,
                    );
                    return Ok(BaseRelayEventWrite::unstored(ok_accepted(
                        event_id,
                        "duplicate: already have this event".to_owned(),
                    )));
                }
                Err(GroupEventWriteError::Rejected(error)) => {
                    logging::log_group_moderation_audit(
                        &event,
                        &class,
                        TangleModerationAuditResult::Rejected,
                    );
                    return Ok(BaseRelayEventWrite::unstored(ok_rejected(
                        event_id,
                        error.prefixed_message(),
                    )));
                }
                Err(GroupEventWriteError::Storage(error)) => return Err(error),
            }
        }
        if event.unsigned().kind().is_ephemeral() {
            return Ok(BaseRelayEventWrite::unstored(ok_accepted(
                event_id,
                String::new(),
            )));
        }
        if store.event_by_id(pocket_event_id(&event_id)?)?.is_some() {
            return Ok(BaseRelayEventWrite::unstored(ok_accepted(
                event_id,
                "duplicate: already have this event".to_owned(),
            )));
        }
        let pocket_event = tangle_event_to_pocket(&event)?;
        let store_offset = StoreOffset::new(store.store_event(&pocket_event)?);
        Ok(BaseRelayEventWrite::stored(
            ok_accepted(event_id, String::new()),
            vec![store_offset],
        ))
    }

    pub fn handle_req(
        &mut self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        self.handle_req_with_group_auth(
            subscription_id,
            filters,
            &GroupAuthContext::unauthenticated(),
        )
    }

    pub fn handle_req_with_auth(
        &mut self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &BaseAuthState,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        self.handle_req_with_group_auth(
            subscription_id,
            filters,
            &GroupAuthContext::new(auth.authenticated_pubkeys().iter().cloned()),
        )
    }

    fn handle_req_with_group_auth(
        &mut self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &GroupAuthContext,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        self.handle_req_with_group_auth_report(subscription_id, filters, auth)
            .map(BaseRelayQueryReport::into_messages)
    }

    fn handle_req_with_group_auth_report(
        &mut self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &GroupAuthContext,
    ) -> Result<BaseRelayQueryReport, BaseRelayError> {
        self.limits.validate_subscription_id(&subscription_id)?;
        self.limits.validate_filters(&filters)?;
        if let Some(message) = Self::unsupported_search_closed(&subscription_id, &filters) {
            return Ok(BaseRelayQueryReport::new(
                vec![message],
                false,
                BaseRelayQueryMetrics::default(),
            ));
        }
        self.subscriptions
            .subscribe(subscription_id.clone(), filters.clone(), auth.clone())?;
        self.query_req_with_group_auth_report(subscription_id, filters, auth)
    }

    fn query_req_with_group_auth_report(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &GroupAuthContext,
    ) -> Result<BaseRelayQueryReport, BaseRelayError> {
        Self::query_req_with_group_auth_shared_services(
            &self.store,
            self.groups.as_ref(),
            self.limits,
            self.query,
            subscription_id,
            filters,
            auth,
        )
    }

    fn query_req_with_group_auth_shared_services(
        store: &PocketStoreHandle,
        groups: Option<&GroupServiceHandle>,
        limits: BaseRelayLimits,
        query: PocketQueryConfig,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &GroupAuthContext,
    ) -> Result<BaseRelayQueryReport, BaseRelayError> {
        limits.validate_subscription_id(&subscription_id)?;
        limits.validate_filters(&filters)?;
        if let Some(message) = Self::unsupported_search_closed(&subscription_id, &filters) {
            return Ok(BaseRelayQueryReport::new(
                vec![message],
                false,
                BaseRelayQueryMetrics::default(),
            ));
        }
        let report =
            Self::query_events_report_with_services(store, groups, limits, query, &filters, auth)?;
        let group_read_denied = report.group_read_denied;
        let query_metrics = report.query_metrics;
        let mut messages = report
            .events
            .into_iter()
            .map(|event| RelayMessage::Event {
                subscription_id: subscription_id.clone(),
                event,
            })
            .collect::<Vec<_>>();
        messages.push(RelayMessage::Eose(subscription_id));
        Ok(BaseRelayQueryReport::new(
            messages,
            group_read_denied,
            query_metrics,
        ))
    }

    pub fn handle_count(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
    ) -> Result<RelayMessage, BaseRelayError> {
        self.handle_count_with_group_auth(
            subscription_id,
            filters,
            &GroupAuthContext::unauthenticated(),
        )
    }

    pub fn handle_count_with_auth(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &BaseAuthState,
    ) -> Result<RelayMessage, BaseRelayError> {
        self.handle_count_with_auth_report(subscription_id, filters, auth)
            .map(BaseRelayCountReport::into_message)
    }

    pub(crate) fn handle_count_with_auth_report(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &BaseAuthState,
    ) -> Result<BaseRelayCountReport, BaseRelayError> {
        Self::handle_count_with_shared_services(
            &self.store,
            self.groups.as_ref(),
            self.limits,
            self.query,
            subscription_id,
            filters,
            auth,
        )
    }

    pub(crate) fn handle_count_with_shared_services(
        store: &PocketStoreHandle,
        groups: Option<&GroupServiceHandle>,
        limits: BaseRelayLimits,
        query: PocketQueryConfig,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &BaseAuthState,
    ) -> Result<BaseRelayCountReport, BaseRelayError> {
        Self::handle_count_with_group_auth_shared_services(
            store,
            groups,
            limits,
            query,
            subscription_id,
            filters,
            &GroupAuthContext::new(auth.authenticated_pubkeys().iter().cloned()),
        )
    }

    fn handle_count_with_group_auth(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &GroupAuthContext,
    ) -> Result<RelayMessage, BaseRelayError> {
        self.handle_count_with_group_auth_report(subscription_id, filters, auth)
            .map(BaseRelayCountReport::into_message)
    }

    fn handle_count_with_group_auth_report(
        &self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &GroupAuthContext,
    ) -> Result<BaseRelayCountReport, BaseRelayError> {
        Self::handle_count_with_group_auth_shared_services(
            &self.store,
            self.groups.as_ref(),
            self.limits,
            self.query,
            subscription_id,
            filters,
            auth,
        )
    }

    fn handle_count_with_group_auth_shared_services(
        store: &PocketStoreHandle,
        groups: Option<&GroupServiceHandle>,
        limits: BaseRelayLimits,
        query: PocketQueryConfig,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: &GroupAuthContext,
    ) -> Result<BaseRelayCountReport, BaseRelayError> {
        limits.validate_subscription_id(&subscription_id)?;
        limits.validate_filters(&filters)?;
        if let Some(message) = Self::unsupported_search_closed(&subscription_id, &filters) {
            return Ok(BaseRelayCountReport::new(
                message,
                false,
                BaseRelayQueryMetrics::default(),
            ));
        }
        let report =
            Self::count_events_report_with_services(store, groups, limits, query, &filters, auth)?;
        Ok(BaseRelayCountReport::new(
            RelayMessage::Count {
                subscription_id,
                count: report.count,
            },
            report.group_read_denied,
            report.query_metrics,
        ))
    }

    pub fn handle_close(&mut self, subscription_id: &SubscriptionId) -> CloseResult {
        self.subscriptions.close(subscription_id)
    }

    pub fn fanout(&mut self, event: &Event) -> Vec<RelayMessage> {
        let groups = self.groups.as_ref();
        self.subscriptions.fanout(event, |event, auth| {
            Self::group_read_gate_visible_to_auth(groups, event, auth).unwrap_or(false)
        })
    }

    pub fn active_subscription_count(&self) -> usize {
        self.subscriptions.active_count()
    }

    fn query_events(
        &self,
        filters: &[Filter],
        auth: &GroupAuthContext,
    ) -> Result<Vec<Event>, BaseRelayError> {
        self.query_events_report(filters, auth)
            .map(|report| report.events)
    }

    fn query_events_report(
        &self,
        filters: &[Filter],
        auth: &GroupAuthContext,
    ) -> Result<BaseRelayEventQueryReport, BaseRelayError> {
        Self::query_events_report_with_services(
            &self.store,
            self.groups.as_ref(),
            self.limits,
            self.query,
            filters,
            auth,
        )
    }

    fn query_events_report_with_services(
        store: &PocketStoreHandle,
        groups: Option<&GroupServiceHandle>,
        limits: BaseRelayLimits,
        query: PocketQueryConfig,
        filters: &[Filter],
        auth: &GroupAuthContext,
    ) -> Result<BaseRelayEventQueryReport, BaseRelayError> {
        let mut output = Vec::new();
        let mut group_read_denied = false;
        let mut query_metrics = BaseRelayQueryMetrics::default();
        for filter in filters {
            let report = Self::query_filter_events_report_with_services(
                store, groups, limits, query, filter, auth,
            )?;
            group_read_denied |= report.group_read_denied;
            query_metrics = query_metrics.add(report.query_metrics);
            let mut events = Self::sort_and_dedupe_query_events(report.events);
            events.truncate(limits.effective_filter_limit(filter));
            output.extend(events);
        }
        let events = Self::sort_and_dedupe_query_events(output);
        query_metrics = query_metrics.with_returned_events(events.len());
        Ok(BaseRelayEventQueryReport::new(
            events,
            group_read_denied,
            query_metrics,
        ))
    }

    fn count_events_report_with_services(
        store: &PocketStoreHandle,
        groups: Option<&GroupServiceHandle>,
        limits: BaseRelayLimits,
        query: PocketQueryConfig,
        filters: &[Filter],
        auth: &GroupAuthContext,
    ) -> Result<BaseRelayCountEventsReport, BaseRelayError> {
        let mut seen = BTreeSet::new();
        let mut group_read_denied = false;
        let mut query_metrics = BaseRelayQueryMetrics::default();
        for filter in filters {
            let filter = filter.without_limit();
            let report = Self::query_filter_events_report_with_services(
                store, groups, limits, query, &filter, auth,
            )?;
            group_read_denied |= report.group_read_denied;
            query_metrics = query_metrics.add(report.query_metrics);
            for event in report.events {
                seen.insert(event.id().clone());
            }
        }
        let count = u64::try_from(seen.len())
            .map_err(|_| BaseRelayError::error("visible event count overflow"))?;
        Ok(BaseRelayCountEventsReport::new(
            count,
            group_read_denied,
            query_metrics,
        ))
    }

    fn query_filter_events_report_with_services(
        store: &PocketStoreHandle,
        groups: Option<&GroupServiceHandle>,
        limits: BaseRelayLimits,
        query: PocketQueryConfig,
        filter: &Filter,
        auth: &GroupAuthContext,
    ) -> Result<BaseRelayEventQueryReport, BaseRelayError> {
        let effective_filter = Self::filter_with_limits(limits, filter);
        let pocket_filter = tangle_filter_to_pocket(&effective_filter)?;
        let screen_error = RefCell::new(None);
        let candidates_scanned = Cell::new(0_u64);
        let redacted_events = Cell::new(0_u64);
        let screened = store.find_events_with_screen(&pocket_filter, query, |pocket_event| {
            candidates_scanned.set(candidates_scanned.get().saturating_add(1));
            if screen_error.borrow().is_some() {
                return PocketScreenResult::Mismatch;
            }
            match pocket_filter.event_matches(pocket_event) {
                Ok(false) => PocketScreenResult::Mismatch,
                Ok(true) => {
                    match Self::group_read_gate_visible_to_auth(groups, pocket_event, auth) {
                        Ok(true) => PocketScreenResult::Match,
                        Ok(false) => {
                            redacted_events.set(redacted_events.get().saturating_add(1));
                            PocketScreenResult::Redacted
                        }
                        Err(error) => {
                            *screen_error.borrow_mut() = Some(error);
                            PocketScreenResult::Mismatch
                        }
                    }
                }
                Err(error) => {
                    *screen_error.borrow_mut() = Some(BaseRelayError::error(error.to_string()));
                    PocketScreenResult::Mismatch
                }
            }
        })?;
        if let Some(error) = screen_error.into_inner() {
            return Err(error);
        }
        let group_read_denied = screened.redacted();
        let events = screened
            .into_events()
            .into_iter()
            .map(|pocket_event| pocket_event_to_tangle(&pocket_event))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(BaseRelayEventQueryReport::new(
            events,
            group_read_denied,
            BaseRelayQueryMetrics::new(candidates_scanned.get(), 0, redacted_events.get()),
        ))
    }

    fn filter_with_limits(limits: BaseRelayLimits, filter: &Filter) -> Filter {
        match filter.limit() {
            Some(_) => filter.clone(),
            None => filter.with_limit(limits.default_limit()),
        }
    }

    fn sort_and_dedupe_query_events(mut events: Vec<Event>) -> Vec<Event> {
        events.sort_by(|left, right| {
            right
                .unsigned()
                .created_at()
                .cmp(&left.unsigned().created_at())
                .then_with(|| left.id().cmp(right.id()))
        });
        let mut seen = BTreeSet::new();
        events
            .into_iter()
            .filter(|event| seen.insert(event.id().clone()))
            .collect()
    }

    pub(crate) fn group_read_gate_visible_to_auth(
        groups: Option<&GroupServiceHandle>,
        event: &(impl GroupEventView + ?Sized),
        auth: &GroupAuthContext,
    ) -> Result<bool, BaseRelayError> {
        groups
            .map(|groups| groups.event_visible_to_auth(event, auth))
            .unwrap_or(Ok(true))
            .map_err(BaseRelayError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::{BaseRelay, BaseRelayLimitSettings, BaseRelayLimits};
    use crate::pocket_conversion::tangle_event_to_pocket;
    use crate::relay::auth::BaseAuthState;
    use crate::relay::live::CloseResult;
    use tangle_crypto::RelaySigner;
    use tangle_groups::{
        GroupId, KIND_GROUP_ADMINS, KIND_GROUP_CREATE_GROUP, KIND_GROUP_CREATE_INVITE,
        KIND_GROUP_DELETE_EVENT, KIND_GROUP_DELETE_GROUP, KIND_GROUP_EDIT_METADATA,
        KIND_GROUP_JOIN_REQUEST, KIND_GROUP_LEAVE_REQUEST, KIND_GROUP_MEMBERS, KIND_GROUP_METADATA,
        KIND_GROUP_PUT_USER, KIND_GROUP_REMOVE_USER, MemberStatus,
        NIP29_RELAY_GENERATED_KIND_VALUES, StoreOffset, parse_group_runtime_config_json,
    };
    use tangle_protocol::{
        ClientMessage, Event, EventId, Filter, Kind, PublicKeyHex, RelayMessage, SubscriptionId,
        Tag, UnixTimestamp, UnsignedEvent, filter_from_value,
    };
    use tangle_store_pocket::{PocketQueryConfig, PocketStoreConfig, PocketSyncPolicy};
    #[test]
    fn base_relay_stores_queries_counts_closes_and_fans_out_public_events() {
        let mut relay = test_relay("base-relay-public", 4);
        let event = signed_public_event(7, 1, Vec::new(), "hello");
        let subscription_id = SubscriptionId::new("sub-a").expect("sub");
        let filter = filter_from_value(&serde_json::json!({"kinds":[1]})).expect("filter");

        assert_eq!(
            relay.handle_event(event.clone()).expect("event"),
            RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: true,
                message: String::new()
            }
        );
        assert_eq!(
            relay.handle_event(event.clone()).expect("duplicate"),
            RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: true,
                message: "duplicate: already have this event".to_owned()
            }
        );

        let messages = relay
            .handle_req(subscription_id.clone(), vec![filter.clone()])
            .expect("req");
        assert!(
            matches!(&messages[0], RelayMessage::Event { event: found, .. } if found.id() == event.id())
        );
        assert_eq!(messages[1], RelayMessage::Eose(subscription_id.clone()));
        assert_eq!(
            relay
                .handle_count(subscription_id.clone(), vec![filter])
                .expect("count"),
            RelayMessage::Count {
                subscription_id: subscription_id.clone(),
                count: 1
            }
        );
        assert!(matches!(
            relay.fanout(&event).as_slice(),
            [RelayMessage::Event { subscription_id: delivered, event: found }]
                if delivered == &subscription_id && found.id() == event.id()
        ));
        assert_eq!(relay.handle_close(&subscription_id), CloseResult::Closed);
        assert_eq!(relay.active_subscription_count(), 0);
        assert!(relay.fanout(&event).is_empty());
    }

    #[test]
    fn base_relay_uses_configured_pocket_query_scrape_controls() {
        let strict_config = test_store_config("base-relay-query-strict");
        let mut strict = BaseRelay::open(
            &strict_config,
            relay_limits(4),
            PocketQueryConfig::new(false, 0, 0),
        )
        .expect("strict");
        let strict_event = signed_public_event(7, 1, Vec::new(), "strict");
        let broad = filter_from_value(&serde_json::json!({"limit":1})).expect("filter");

        assert_accepted(
            strict
                .handle_event(strict_event.clone())
                .expect("strict event"),
            &strict_event,
        );
        assert!(
            strict
                .handle_req(
                    SubscriptionId::new("strict").expect("sub"),
                    vec![broad.clone()]
                )
                .expect_err("strict scrape")
                .prefixed_message()
                .to_lowercase()
                .contains("scraper")
        );

        let limited_config = test_store_config("base-relay-query-limited");
        let mut limited = BaseRelay::open(
            &limited_config,
            relay_limits(4),
            PocketQueryConfig::new(false, 1, 0),
        )
        .expect("limited");
        let limited_event = signed_public_event(8, 1, Vec::new(), "limited");

        assert_accepted(
            limited
                .handle_event(limited_event.clone())
                .expect("limited event"),
            &limited_event,
        );
        let messages = limited
            .handle_req(SubscriptionId::new("limited").expect("sub"), vec![broad])
            .expect("limited scrape");

        assert!(
            matches!(&messages[0], RelayMessage::Event { event, .. } if event.id() == limited_event.id())
        );
    }

    #[test]
    fn base_relay_rejects_search_req_and_count_as_unsupported() {
        let mut relay = test_relay("base-relay-search-unsupported", 4);
        let req_id = SubscriptionId::new("search-req").expect("req");
        let count_id = SubscriptionId::new("search-count").expect("count");
        let search = filter_from_value(&serde_json::json!({
            "search": "fresh carrots",
            "limit": 1
        }))
        .expect("filter");

        assert_eq!(
            relay
                .handle_req(req_id.clone(), vec![search.clone()])
                .expect("req"),
            vec![RelayMessage::Closed {
                subscription_id: req_id,
                message: "unsupported: search filters are not supported".to_owned()
            }]
        );
        assert_eq!(relay.active_subscription_count(), 0);
        assert_eq!(
            relay
                .handle_count(count_id.clone(), vec![search])
                .expect("count"),
            RelayMessage::Closed {
                subscription_id: count_id,
                message: "unsupported: search filters are not supported".to_owned()
            }
        );
    }

    #[test]
    fn base_relay_fetches_events_by_store_offset() {
        let relay = test_relay("base-relay-offset-lookup", 4);
        let event = signed_public_event(7, 1, Vec::new(), "offset");
        let pocket = tangle_event_to_pocket(&event).expect("pocket");
        let offset = StoreOffset::new(relay.store.store_event(&pocket).expect("store"));

        assert_eq!(relay.event_by_offset(offset).expect("offset"), event);
    }

    #[test]
    fn base_relay_req_merges_filters_with_order_dedupe_and_limits() {
        let mut relay = test_relay("base-relay-req-order", 8);
        let market_tag = Tag::from_parts("t", &["market"]).expect("tag");
        let old_market =
            signed_event_at(7, 1, vec![market_tag.clone()], "old market", 1_714_124_433);
        let tied_author =
            signed_event_at(7, 1, vec![market_tag.clone()], "tied author", 1_714_124_434);
        let tied_other =
            signed_event_at(8, 1, vec![market_tag.clone()], "tied other", 1_714_124_434);
        let kind_two = signed_event_at(7, 2, Vec::new(), "kind two", 1_714_124_435);
        let wrong_tag = signed_event_at(
            9,
            1,
            vec![Tag::from_parts("t", &["other"]).expect("tag")],
            "wrong tag",
            1_714_124_436,
        );

        for event in [
            &old_market,
            &tied_other,
            &kind_two,
            &wrong_tag,
            &tied_author,
        ] {
            assert_accepted(relay.handle_event(event.clone()).expect("event"), event);
        }

        let subscription_id = SubscriptionId::new("req-order").expect("sub");
        let market_limit =
            filter_from_value(&serde_json::json!({"kinds":[1],"#t":["market"],"limit":2}))
                .expect("market filter");
        let author_limit = filter_from_value(&serde_json::json!({
            "authors":[tied_author.unsigned().pubkey().as_str()],
            "kinds":[1,2],
            "limit":2
        }))
        .expect("author filter");
        let messages = relay
            .handle_req(subscription_id.clone(), vec![market_limit, author_limit])
            .expect("req");
        let mut tied = [tied_author.clone(), tied_other.clone()];
        tied.sort_by(|left, right| left.id().cmp(right.id()));
        let expected = [kind_two.clone(), tied[0].clone(), tied[1].clone()];

        assert_eq!(messages.len(), expected.len() + 1);
        for (message, event) in messages.iter().zip(expected.iter()) {
            assert!(matches!(
                message,
                RelayMessage::Event {
                    subscription_id: actual,
                    event: found
                } if actual == &subscription_id && found.id() == event.id()
            ));
        }
        assert_eq!(
            messages.last(),
            Some(&RelayMessage::Eose(subscription_id.clone()))
        );
        assert!(!messages.iter().any(|message| matches!(
            message,
            RelayMessage::Event { event, .. }
                if event.id() == old_market.id() || event.id() == wrong_tag.id()
        )));
    }

    #[test]
    fn base_relay_req_count_paths_preserve_chorus_parity() {
        let owner = signer(7).public_key().clone();
        let auth = authenticated_state(7);
        let mut relay = test_relay_with_groups(
            "base-relay-req-count-chorus-parity",
            8,
            &enabled_groups_for_owner(&owner),
        );
        let market_tag = Tag::from_parts("t", &["market"]).expect("tag");
        let old_market =
            signed_event_at(7, 1, vec![market_tag.clone()], "old market", 1_714_124_433);
        let tied_author =
            signed_event_at(7, 1, vec![market_tag.clone()], "tied author", 1_714_124_434);
        let tied_other =
            signed_event_at(8, 1, vec![market_tag.clone()], "tied other", 1_714_124_434);
        let kind_two = signed_event_at(7, 2, Vec::new(), "kind two", 1_714_124_435);
        let wrong_tag = signed_event_at(
            9,
            1,
            vec![Tag::from_parts("t", &["other"]).expect("tag")],
            "wrong tag",
            1_714_124_436,
        );
        for event in [
            &old_market,
            &tied_other,
            &kind_two,
            &wrong_tag,
            &tied_author,
        ] {
            assert_accepted(relay.handle_event(event.clone()).expect("event"), event);
        }
        relay
            .handle_event_with_auth(signed_private_group_create_event(7, "Private"), &auth)
            .expect("private create");
        let private_market = signed_event_at(
            7,
            1,
            vec![h("Private"), market_tag.clone()],
            "private market",
            1_714_124_437,
        );
        assert_accepted(
            relay
                .handle_event_with_auth(private_market.clone(), &auth)
                .expect("private event"),
            &private_market,
        );

        let subscription_id = SubscriptionId::new("req-count-parity").expect("sub");
        let market_limit =
            filter_from_value(&serde_json::json!({"kinds":[1],"#t":["market"],"limit":2}))
                .expect("market filter");
        let author_limit = filter_from_value(&serde_json::json!({
            "authors":[tied_author.unsigned().pubkey().as_str()],
            "kinds":[1,2],
            "limit":2
        }))
        .expect("author filter");
        let messages = relay
            .handle_req(
                subscription_id.clone(),
                vec![market_limit.clone(), author_limit.clone()],
            )
            .expect("req");
        let mut tied = [tied_author.clone(), tied_other.clone()];
        tied.sort_by(|left, right| left.id().cmp(right.id()));
        let expected = [kind_two.clone(), tied[0].clone(), tied[1].clone()];
        let event_ids = messages
            .iter()
            .filter_map(|message| match message {
                RelayMessage::Event {
                    subscription_id: actual,
                    event,
                } if actual == &subscription_id => Some(event.id().clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let expected_ids = expected
            .iter()
            .map(|event| event.id().clone())
            .collect::<Vec<_>>();

        assert_eq!(event_ids, expected_ids);
        assert_eq!(messages.last(), Some(&RelayMessage::Eose(subscription_id)));
        assert!(!event_ids.contains(private_market.id()));
        assert!(!event_ids.contains(old_market.id()));
        assert!(!event_ids.contains(wrong_tag.id()));

        let private_sub = SubscriptionId::new("private-screened").expect("sub");
        assert_eq!(
            relay
                .handle_req(
                    private_sub.clone(),
                    vec![filter_group_tag(1, "h", "Private")]
                )
                .expect("private unauth req"),
            vec![RelayMessage::Eose(private_sub)]
        );
        let private_auth_sub = SubscriptionId::new("private-auth").expect("sub");
        assert!(matches!(
            relay
                .handle_req_with_auth(
                    private_auth_sub.clone(),
                    vec![filter_group_tag(1, "h", "Private")],
                    &auth
                )
                .expect("private auth req")
                .as_slice(),
            [RelayMessage::Event { subscription_id, event }, RelayMessage::Eose(eose)]
                if subscription_id == &private_auth_sub && event.id() == private_market.id() && eose == &private_auth_sub
        ));

        let market_notes =
            filter_from_value(&serde_json::json!({"kinds":[1],"#t":["market"],"limit":10}))
                .expect("market count filter");
        let author_events = filter_from_value(&serde_json::json!({
            "authors":[tied_author.unsigned().pubkey().as_str()],
            "kinds":[1,2],
            "limit":10
        }))
        .expect("author count filter");
        assert_eq!(
            relay
                .handle_count(
                    SubscriptionId::new("count-visible").expect("sub"),
                    vec![market_notes.clone(), author_events.clone()]
                )
                .expect("visible count"),
            RelayMessage::Count {
                subscription_id: SubscriptionId::new("count-visible").expect("sub"),
                count: 4
            }
        );
        assert_eq!(
            relay
                .handle_count_with_auth(
                    SubscriptionId::new("count-auth").expect("sub"),
                    vec![market_notes, author_events],
                    &auth
                )
                .expect("auth count"),
            RelayMessage::Count {
                subscription_id: SubscriptionId::new("count-auth").expect("sub"),
                count: 5
            }
        );

        let too_large_limit =
            filter_from_value(&serde_json::json!({"limit":501})).expect("limit filter");
        assert!(
            relay
                .handle_req(
                    SubscriptionId::new("limit-req").expect("sub"),
                    vec![too_large_limit.clone()]
                )
                .expect_err("req limit")
                .prefixed_message()
                .contains("max_limit 500")
        );
        assert!(
            relay
                .handle_count(
                    SubscriptionId::new("limit-count").expect("sub"),
                    vec![too_large_limit]
                )
                .expect_err("count limit")
                .prefixed_message()
                .contains("max_limit 500")
        );

        let search = filter_from_value(&serde_json::json!({"search":"carrots","limit":1}))
            .expect("search filter");
        let search_req = SubscriptionId::new("search-req").expect("sub");
        assert_eq!(
            relay
                .handle_req(search_req.clone(), vec![search.clone()])
                .expect("search req"),
            vec![RelayMessage::Closed {
                subscription_id: search_req,
                message: "unsupported: search filters are not supported".to_owned()
            }]
        );
        let search_count = SubscriptionId::new("search-count").expect("sub");
        assert_eq!(
            relay
                .handle_count(search_count.clone(), vec![search])
                .expect("search count"),
            RelayMessage::Closed {
                subscription_id: search_count,
                message: "unsupported: search filters are not supported".to_owned()
            }
        );
    }

    #[test]
    fn base_relay_enforces_runtime_limits() {
        let config = test_store_config("base-relay-runtime-limits");
        let mut relay = BaseRelay::open(
            &config,
            BaseRelayLimits::new(BaseRelayLimitSettings {
                max_pending_events: 2,
                max_subscription_id_length: 3,
                max_subscriptions: 1,
                max_filters_per_request: 1,
                max_tag_values_per_filter: 1,
                max_query_complexity: 4,
                max_event_tags: 1,
                max_content_length: 4,
                max_limit: 2,
                default_limit: 1,
            })
            .expect("limits"),
            PocketQueryConfig::default(),
        )
        .expect("relay");
        let first = signed_event_at(7, 1, Vec::new(), "one", 1_714_124_430);
        let second = signed_event_at(8, 1, Vec::new(), "two", 1_714_124_431);

        assert_accepted(relay.handle_event(first.clone()).expect("first"), &first);
        assert_accepted(relay.handle_event(second.clone()).expect("second"), &second);

        let limited = relay
            .handle_req(
                SubscriptionId::new("lim").expect("sub"),
                vec![Filter::empty()],
            )
            .expect("limited");
        assert_eq!(
            limited
                .iter()
                .filter(|message| matches!(message, RelayMessage::Event { .. }))
                .count(),
            1
        );
        assert_eq!(
            relay.handle_close(&SubscriptionId::new("lim").expect("sub")),
            CloseResult::Closed
        );

        assert!(
            relay
                .handle_req(
                    SubscriptionId::new("long").expect("sub"),
                    vec![Filter::empty()]
                )
                .expect_err("subscription id length")
                .prefixed_message()
                .contains("max_subid_length 3")
        );
        assert!(
            relay
                .handle_count(
                    SubscriptionId::new("cnt").expect("sub"),
                    vec![Filter::empty(), Filter::empty()]
                )
                .expect_err("filter count")
                .prefixed_message()
                .contains("max_filters_per_request 1")
        );
        assert!(
            relay
                .handle_count(
                    SubscriptionId::new("tag").expect("sub"),
                    vec![
                        filter_from_value(&serde_json::json!({"#t":["one", "two"]}))
                            .expect("filter")
                    ]
                )
                .expect_err("tag values")
                .prefixed_message()
                .contains("max_tag_values_per_filter 1")
        );
        assert!(
            relay
                .handle_count(
                    SubscriptionId::new("max").expect("sub"),
                    vec![filter_from_value(&serde_json::json!({"limit":3})).expect("filter")]
                )
                .expect_err("max limit")
                .prefixed_message()
                .contains("max_limit 2")
        );

        let too_many_tags = signed_event_at(
            9,
            1,
            vec![
                Tag::from_parts("t", &["one"]).expect("tag"),
                Tag::from_parts("p", &["two"]).expect("tag"),
            ],
            "ok",
            1_714_124_432,
        );
        assert!(matches!(
            relay.handle_event(too_many_tags).expect("tags"),
            RelayMessage::Ok { accepted: false, message, .. }
                if message.contains("max_event_tags 1")
        ));

        let too_much_content = signed_event_at(10, 1, Vec::new(), "12345", 1_714_124_433);
        assert!(matches!(
            relay.handle_event(too_much_content).expect("content"),
            RelayMessage::Ok { accepted: false, message, .. }
                if message.contains("max_content_length 4")
        ));
    }

    #[test]
    fn base_relay_rejects_over_budget_req_and_count() {
        let config = test_store_config("base-relay-query-complexity");
        let mut relay = BaseRelay::open(
            &config,
            BaseRelayLimits::new(BaseRelayLimitSettings {
                max_pending_events: 4,
                max_subscription_id_length: 64,
                max_subscriptions: 64,
                max_filters_per_request: 10,
                max_tag_values_per_filter: 10,
                max_query_complexity: 4,
                max_event_tags: 200,
                max_content_length: 65_536,
                max_limit: 10,
                default_limit: 1,
            })
            .expect("limits"),
            PocketQueryConfig::default(),
        )
        .expect("relay");
        let complex = filter_from_value(&serde_json::json!({
            "kinds": [1],
            "#t": ["market"],
            "limit": 2
        }))
        .expect("filter");

        assert!(
            relay
                .handle_req(
                    SubscriptionId::new("req").expect("sub"),
                    vec![complex.clone()]
                )
                .expect_err("req complexity")
                .prefixed_message()
                .contains("max_query_complexity 4")
        );
        assert_eq!(relay.active_subscription_count(), 0);
        assert!(
            relay
                .handle_count(SubscriptionId::new("cnt").expect("sub"), vec![complex])
                .expect_err("count complexity")
                .prefixed_message()
                .contains("max_query_complexity 4")
        );
    }

    #[test]
    fn base_relay_count_dedupes_overlapping_visible_filters() {
        let relay = test_relay("base-relay-count-dedupe", 8);
        let market_tag = Tag::from_parts("t", &["market"]).expect("tag");
        let first = signed_event_at(7, 1, vec![market_tag.clone()], "first", 1_714_124_433);
        let second = signed_event_at(8, 1, vec![market_tag], "second", 1_714_124_434);
        let third = signed_event_at(7, 2, Vec::new(), "third", 1_714_124_435);

        for event in [&first, &second, &third] {
            assert_accepted(relay.handle_event(event.clone()).expect("event"), event);
        }

        let market_notes =
            filter_from_value(&serde_json::json!({"kinds":[1],"#t":["market"],"limit":2}))
                .expect("market filter");
        let author_events = filter_from_value(&serde_json::json!({
            "authors":[first.unsigned().pubkey().as_str()],
            "kinds":[1,2],
            "limit":10
        }))
        .expect("author filter");
        let limited_market =
            filter_from_value(&serde_json::json!({"kinds":[1],"#t":["market"],"limit":1}))
                .expect("limited filter");

        assert_eq!(
            relay
                .handle_count(
                    SubscriptionId::new("count-limit").expect("sub"),
                    vec![limited_market]
                )
                .expect("count"),
            RelayMessage::Count {
                subscription_id: SubscriptionId::new("count-limit").expect("sub"),
                count: 2
            }
        );

        assert_eq!(
            relay
                .handle_count(
                    SubscriptionId::new("count-dedupe").expect("sub"),
                    vec![market_notes, author_events]
                )
                .expect("count"),
            RelayMessage::Count {
                subscription_id: SubscriptionId::new("count-dedupe").expect("sub"),
                count: 3
            }
        );
    }

    #[test]
    fn base_relay_event_path_rejects_invalid_signatures_and_skips_ephemeral_storage() {
        let relay = test_relay("base-relay-event-store-path", 8);
        let valid = signed_public_event(7, 1, Vec::new(), "valid");
        let signature_source = signed_public_event(8, 1, Vec::new(), "signature source");
        let invalid = Event::new(
            valid.id().clone(),
            valid.unsigned().clone(),
            signature_source.sig().clone(),
        );
        let ephemeral = signed_public_event(7, 20_001, Vec::new(), "ephemeral");

        assert!(matches!(
            relay.handle_event(invalid.clone()).expect("invalid"),
            RelayMessage::Ok {
                event_id,
                accepted: false,
                message
            } if event_id == *invalid.id()
                && message == "invalid: event signature verification failed"
        ));
        assert_eq!(count_kind(&relay, 1), 0);

        assert_accepted(relay.handle_event(valid.clone()).expect("valid"), &valid);
        assert_eq!(
            relay.handle_event(valid.clone()).expect("duplicate"),
            RelayMessage::Ok {
                event_id: valid.id().clone(),
                accepted: true,
                message: "duplicate: already have this event".to_owned()
            }
        );
        assert_eq!(count_kind(&relay, 1), 1);

        assert_accepted(
            relay.handle_event(ephemeral.clone()).expect("ephemeral"),
            &ephemeral,
        );
        assert_eq!(count_kind(&relay, 20_001), 0);
    }

    #[test]
    fn group_write_source_uses_atomic_service_boundary() {
        let core_source = include_str!("core.rs");
        let group_source = include_str!("../groups.rs");

        assert!(core_source.contains("groups.store_group_event"));
        assert!(!core_source.contains(concat!("groups.", "check_event")));
        assert!(!core_source.contains(concat!("groups.", "after_source_event_stored")));
        assert!(!group_source.contains("pub(crate) fn check_event("));
        assert!(!group_source.contains("pub(crate) fn after_source_event_stored("));
    }

    #[test]
    fn base_relay_event_path_preserves_chorus_parity() {
        let owner = signer(7).public_key().clone();
        let relay = test_relay_with_groups(
            "base-relay-event-chorus-parity",
            8,
            &enabled_groups_for_owner(&owner),
        );
        let valid = signed_public_event(7, 1, Vec::new(), "valid");
        let signature_source = signed_public_event(8, 1, Vec::new(), "signature source");
        let invalid = Event::new(
            valid.id().clone(),
            valid.unsigned().clone(),
            signature_source.sig().clone(),
        );
        let ephemeral = signed_public_event(7, 20_001, Vec::new(), "ephemeral");
        let protected = signed_public_event(
            7,
            1,
            vec![Tag::from_parts("-", &[]).expect("protected")],
            "protected",
        );
        let group_create = signed_group_create_event(7, "ParityFarm");
        let empty_auth = BaseAuthState::new("wss://relay.radroots.test", 60, 600).expect("auth");

        assert_eq!(
            rejected_message(relay.handle_event(invalid.clone()).expect("invalid")),
            "invalid: event signature verification failed"
        );
        assert_eq!(count_kind(&relay, 1), 0);

        assert_accepted(relay.handle_event(valid.clone()).expect("valid"), &valid);
        assert_eq!(count_kind(&relay, 1), 1);
        assert_eq!(
            relay.handle_event(valid.clone()).expect("duplicate"),
            RelayMessage::Ok {
                event_id: valid.id().clone(),
                accepted: true,
                message: "duplicate: already have this event".to_owned()
            }
        );
        assert_eq!(count_kind(&relay, 1), 1);

        assert_accepted(
            relay.handle_event(ephemeral.clone()).expect("ephemeral"),
            &ephemeral,
        );
        assert_eq!(count_kind(&relay, 20_001), 0);

        assert_eq!(
            rejected_message(relay.handle_event(protected.clone()).expect("protected")),
            "auth-required: protected event requires authenticated event author"
        );
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(group_create.clone(), &empty_auth)
                    .expect("group unauth")
            ),
            "auth-required: group event author must authenticate with AUTH"
        );
        assert_eq!(count_kind(&relay, KIND_GROUP_CREATE_GROUP), 0);

        assert_accepted(
            relay
                .handle_event_with_auth(group_create.clone(), &authenticated_state(7))
                .expect("group auth"),
            &group_create,
        );
        assert_eq!(count_kind(&relay, KIND_GROUP_CREATE_GROUP), 1);
        assert!(
            relay
                .group_projection()
                .expect("projection")
                .group(&GroupId::new("ParityFarm").expect("group"))
                .is_some()
        );
    }

    #[test]
    fn base_relay_enforces_nip70_protected_event_author_auth() {
        let relay = test_relay("base-relay-nip70-protected", 8);
        let protected = signed_public_event(
            7,
            1,
            vec![Tag::from_parts("-", &[]).expect("protected")],
            "protected",
        );

        assert_eq!(
            rejected_message(relay.handle_event(protected.clone()).expect("unauth")),
            "auth-required: protected event requires authenticated event author"
        );
        assert_eq!(count_kind(&relay, 1), 0);
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(protected.clone(), &authenticated_state(8))
                    .expect("wrong auth")
            ),
            "auth-required: protected event requires authenticated event author"
        );
        assert_eq!(count_kind(&relay, 1), 0);
        assert_accepted(
            relay
                .handle_event_with_auth(protected.clone(), &authenticated_state(7))
                .expect("author auth"),
            &protected,
        );
        assert_eq!(count_kind(&relay, 1), 1);
    }

    #[test]
    fn base_relay_rejects_group_marked_events_before_group_service() {
        let relay = test_relay("base-relay-group-reject", 4);
        let event = signed_public_event(
            7,
            1,
            vec![Tag::from_parts("h", &["public-group"]).expect("group")],
            "hello",
        );

        assert_eq!(
            relay.handle_event(event.clone()).expect("event"),
            RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: false,
                message: "blocked: NIP-29 group events are not accepted before group service"
                    .to_owned()
            }
        );
    }

    #[test]
    fn base_relay_rejects_client_submitted_relay_generated_group_state() {
        let relay = test_relay("base-relay-generated-group-reject", 4);
        for kind in NIP29_RELAY_GENERATED_KIND_VALUES {
            let event = signed_public_event(
                7,
                kind.into(),
                vec![Tag::from_parts("d", &["public-group"]).expect("group")],
                "",
            );

            assert_eq!(
                relay.handle_event(event.clone()).expect("event"),
                RelayMessage::Ok {
                    event_id: event.id().clone(),
                    accepted: false,
                    message:
                        "blocked: relay-generated group state events cannot be submitted by clients"
                            .to_owned()
                }
            );
        }
    }

    #[test]
    fn base_relay_initializes_group_service_from_config() {
        let owner = signer(7).public_key().clone();
        let relay = test_relay_with_groups(
            "base-relay-groups-enabled",
            4,
            &enabled_groups_for_owner(&owner),
        );
        let disabled = test_relay_with_groups("base-relay-groups-disabled", 4, &disabled_groups());

        assert!(relay.groups_enabled());
        assert_eq!(
            relay
                .readiness_state()
                .response()
                .checks
                .group_outbox_replay,
            "ready"
        );
        assert!(
            relay
                .group_projection()
                .expect("projection")
                .groups()
                .is_empty()
        );
        assert!(!disabled.groups_enabled());
        assert_eq!(
            disabled
                .readiness_state()
                .response()
                .checks
                .group_outbox_replay,
            "ready"
        );
        assert!(disabled.group_projection().is_none());
    }

    #[test]
    fn group_event_write_requires_auth_before_storage() {
        let owner = signer(7).public_key().clone();
        let relay = test_relay_with_groups(
            "base-relay-group-auth-required",
            4,
            &enabled_groups_for_owner(&owner),
        );
        let auth = BaseAuthState::new("wss://relay.radroots.test", 60, 600).expect("auth");
        let event = signed_group_create_event(7, "Farm");

        assert_eq!(
            relay
                .handle_event_with_auth(event.clone(), &auth)
                .expect("event"),
            RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: false,
                message: "auth-required: group event author must authenticate with AUTH".to_owned()
            }
        );
        assert!(
            relay
                .group_projection()
                .expect("projection")
                .group(&GroupId::new("Farm").expect("group"))
                .is_none()
        );
        assert_eq!(count_kind(&relay, KIND_GROUP_CREATE_GROUP), 0);
    }

    #[test]
    fn group_create_updates_projection_and_stores_generated_snapshots() {
        let owner = signer(7).public_key().clone();
        let relay = test_relay_with_groups(
            "base-relay-group-create",
            4,
            &enabled_groups_for_owner(&owner),
        );
        let auth = authenticated_state(7);
        let event = signed_group_create_event(7, "Farm");

        assert_eq!(
            relay
                .handle_event_with_auth(event.clone(), &auth)
                .expect("event"),
            RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: true,
                message: String::new()
            }
        );

        let group_id = GroupId::new("Farm").expect("group");
        assert!(
            relay
                .group_projection()
                .expect("projection")
                .group(&group_id)
                .is_some()
        );
        assert_eq!(count_kind(&relay, KIND_GROUP_CREATE_GROUP), 1);
        assert_eq!(count_kind(&relay, KIND_GROUP_METADATA), 1);
        assert_eq!(count_kind(&relay, KIND_GROUP_ADMINS), 1);
    }

    #[test]
    fn group_join_materializes_relay_membership_event() {
        let owner = signer(7).public_key().clone();
        let joiner = signer(8).public_key().clone();
        let relay = test_relay_with_groups(
            "base-relay-group-join",
            4,
            &enabled_groups_for_owner_with_public_join(&owner),
        );
        let create = signed_group_create_event(7, "Farm");
        assert_accepted(
            relay
                .handle_event_with_auth(create.clone(), &authenticated_state(7))
                .expect("create"),
            &create,
        );
        let join = signed_event_at(
            8,
            KIND_GROUP_JOIN_REQUEST.into(),
            vec![Tag::from_parts("h", &["Farm"]).expect("h")],
            "",
            1_714_124_434,
        );

        assert_eq!(
            relay
                .handle_event_with_auth(join.clone(), &authenticated_state(8))
                .expect("join"),
            RelayMessage::Ok {
                event_id: join.id().clone(),
                accepted: true,
                message: String::new()
            }
        );

        assert_eq!(count_kind(&relay, KIND_GROUP_PUT_USER), 1);
        assert_eq!(
            relay
                .group_projection()
                .expect("projection")
                .member(&GroupId::new("Farm").expect("group"), &joiner)
                .expect("member")
                .status(),
            MemberStatus::Member
        );
    }

    #[test]
    fn group_join_requires_public_join_policy() {
        let owner = signer(7).public_key().clone();
        let relay = test_relay_with_groups(
            "base-relay-group-join-default-deny",
            4,
            &enabled_groups_for_owner(&owner),
        );
        let create = signed_group_create_event(7, "Farm");
        relay
            .handle_event_with_auth(create, &authenticated_state(7))
            .expect("create");
        let join = signed_event_at(
            8,
            KIND_GROUP_JOIN_REQUEST.into(),
            vec![Tag::from_parts("h", &["Farm"]).expect("h")],
            "",
            1_714_124_434,
        );

        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(join, &authenticated_state(8))
                    .expect("join")
            ),
            "restricted: group is unavailable"
        );
        assert_eq!(count_kind(&relay, KIND_GROUP_PUT_USER), 0);
    }

    #[test]
    fn group_metadata_edit_replaces_generated_metadata_snapshot() {
        let owner = signer(7).public_key().clone();
        let mut relay = test_relay_with_groups(
            "base-relay-group-metadata-edit",
            4,
            &enabled_groups_for_owner(&owner),
        );
        let auth = authenticated_state(7);
        let create = signed_group_create_event(7, "Farm");
        assert_accepted(
            relay
                .handle_event_with_auth(create.clone(), &auth)
                .expect("create"),
            &create,
        );
        let edit = signed_event_at(
            7,
            KIND_GROUP_EDIT_METADATA.into(),
            vec![h("Farm"), name("Market")],
            "",
            1_714_124_436,
        );
        assert_accepted(
            relay
                .handle_event_with_auth(edit.clone(), &auth)
                .expect("edit"),
            &edit,
        );

        let group_id = GroupId::new("Farm").expect("group");
        {
            let projection = relay.group_projection().expect("projection");
            let group = projection.group(&group_id).expect("group");
            assert_eq!(group.metadata().name(), Some("Market"));
        }
        let metadata = query_filter(
            &mut relay,
            "metadata-edit",
            filter_group_tag(KIND_GROUP_METADATA, "d", "Farm"),
        );
        assert_eq!(metadata.len(), 1);
        assert!(has_tag(&metadata[0], "d", &["Farm"]));
        assert!(has_tag(&metadata[0], "name", &["Market"]));
        assert_eq!(count_kind(&relay, KIND_GROUP_METADATA), 1);
    }

    #[test]
    fn group_member_moderation_join_leave_and_snapshots_flow() {
        let owner = signer(7).public_key().clone();
        let member = signer(8).public_key().clone();
        let target = signer(9).public_key().clone();
        let relay = test_relay_with_groups(
            "base-relay-group-member-flow",
            4,
            &enabled_groups_for_owner_with_public_join(&owner),
        );
        let owner_auth = authenticated_state(7);
        let member_auth = authenticated_state(8);
        let target_auth = authenticated_state(9);
        relay
            .handle_event_with_auth(signed_group_create_event(7, "Farm"), &owner_auth)
            .expect("create");
        let rejected_add = signed_event_at(
            9,
            KIND_GROUP_PUT_USER.into(),
            vec![h("Farm"), p(&target)],
            "",
            1_714_124_434,
        );
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(rejected_add.clone(), &target_auth)
                    .expect("rejected add")
            ),
            "restricted: missing group capability manage_members"
        );
        let add = signed_event_at(
            7,
            KIND_GROUP_PUT_USER.into(),
            vec![h("Farm"), p(&member)],
            "",
            1_714_124_435,
        );
        assert_accepted(
            relay
                .handle_event_with_auth(add.clone(), &owner_auth)
                .expect("add"),
            &add,
        );
        assert_member_status(&relay, "Farm", &member, MemberStatus::Member);
        assert_eq!(count_kind(&relay, KIND_GROUP_MEMBERS), 1);

        let remove = signed_event_at(
            7,
            KIND_GROUP_REMOVE_USER.into(),
            vec![h("Farm"), p(&member)],
            "",
            1_714_124_436,
        );
        assert_accepted(
            relay
                .handle_event_with_auth(remove.clone(), &owner_auth)
                .expect("remove"),
            &remove,
        );
        assert_member_status(&relay, "Farm", &member, MemberStatus::Removed);
        assert_eq!(count_kind(&relay, KIND_GROUP_MEMBERS), 1);

        let join = signed_event_at(
            8,
            KIND_GROUP_JOIN_REQUEST.into(),
            vec![h("Farm")],
            "",
            1_714_124_437,
        );
        assert_accepted(
            relay
                .handle_event_with_auth(join.clone(), &member_auth)
                .expect("join"),
            &join,
        );
        assert_member_status(&relay, "Farm", &member, MemberStatus::Member);
        let duplicate_join = signed_event_at(
            8,
            KIND_GROUP_JOIN_REQUEST.into(),
            vec![h("Farm")],
            "",
            1_714_124_438,
        );
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(duplicate_join, &member_auth)
                    .expect("duplicate join")
            ),
            "duplicate: group member already exists"
        );

        let leave = signed_event_at(
            8,
            KIND_GROUP_LEAVE_REQUEST.into(),
            vec![h("Farm")],
            "",
            1_714_124_439,
        );
        assert_accepted(
            relay
                .handle_event_with_auth(leave.clone(), &member_auth)
                .expect("leave"),
            &leave,
        );
        assert_member_status(&relay, "Farm", &member, MemberStatus::Removed);
        assert_eq!(count_kind(&relay, KIND_GROUP_REMOVE_USER), 2);
        let duplicate_leave = signed_event_at(
            8,
            KIND_GROUP_LEAVE_REQUEST.into(),
            vec![h("Farm")],
            "",
            1_714_124_440,
        );
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(duplicate_leave, &member_auth)
                    .expect("duplicate leave")
            ),
            "duplicate: group member does not exist"
        );
    }

    #[test]
    fn group_delete_event_moderation_hides_target_and_validates_group() {
        let owner = signer(7).public_key().clone();
        let outsider_auth = authenticated_state(8);
        let owner_auth = authenticated_state(7);
        let relay = test_relay_with_groups(
            "base-relay-group-delete-event",
            4,
            &enabled_groups_for_owner(&owner),
        );
        relay
            .handle_event_with_auth(signed_group_create_event(7, "Farm"), &owner_auth)
            .expect("create farm");
        relay
            .handle_event_with_auth(signed_group_create_event(7, "Other"), &owner_auth)
            .expect("create other");
        let target = signed_event_at(7, 1, vec![h("Farm")], "harvest", 1_714_124_434);
        let other = signed_event_at(7, 1, vec![h("Other")], "other", 1_714_124_435);
        relay
            .handle_event_with_auth(target.clone(), &owner_auth)
            .expect("target");
        relay
            .handle_event_with_auth(other.clone(), &owner_auth)
            .expect("other");

        let wrong_group = signed_event_at(
            7,
            KIND_GROUP_DELETE_EVENT.into(),
            vec![h("Farm"), e(other.id())],
            "",
            1_714_124_436,
        );
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(wrong_group, &owner_auth)
                    .expect("wrong group")
            ),
            "invalid: delete target event is not in group"
        );
        let unauthorized = signed_event_at(
            8,
            KIND_GROUP_DELETE_EVENT.into(),
            vec![h("Farm"), e(target.id())],
            "",
            1_714_124_437,
        );
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(unauthorized, &outsider_auth)
                    .expect("unauthorized")
            ),
            "restricted: missing group capability delete_events"
        );
        assert_eq!(
            count_filter(
                &relay,
                "target-before-delete",
                filter_group_tag(1, "h", "Farm")
            ),
            1
        );

        let delete = signed_event_at(
            7,
            KIND_GROUP_DELETE_EVENT.into(),
            vec![h("Farm"), e(target.id())],
            "",
            1_714_124_438,
        );
        assert_accepted(
            relay
                .handle_event_with_auth(delete.clone(), &owner_auth)
                .expect("delete"),
            &delete,
        );

        assert_eq!(
            count_filter(
                &relay,
                "target-after-delete",
                filter_group_tag(1, "h", "Farm")
            ),
            0
        );
        assert_eq!(
            count_filter(
                &relay,
                "delete-event-marker",
                filter_group_tag(KIND_GROUP_DELETE_EVENT, "h", "Farm")
            ),
            1
        );
    }

    #[test]
    fn group_delete_tombstone_hides_events_and_rejects_future_writes() {
        let owner = signer(7).public_key().clone();
        let auth = authenticated_state(7);
        let relay = test_relay_with_groups(
            "base-relay-group-delete-tombstone",
            4,
            &enabled_groups_for_owner(&owner),
        );
        relay
            .handle_event_with_auth(signed_group_create_event(7, "Farm"), &auth)
            .expect("create");
        let normal = signed_event_at(7, 1, vec![h("Farm")], "harvest", 1_714_124_434);
        relay.handle_event_with_auth(normal, &auth).expect("normal");
        let delete_group = signed_event_at(
            7,
            KIND_GROUP_DELETE_GROUP.into(),
            vec![h("Farm")],
            "",
            1_714_124_435,
        );
        assert_accepted(
            relay
                .handle_event_with_auth(delete_group.clone(), &auth)
                .expect("delete group"),
            &delete_group,
        );

        let future = signed_event_at(7, 1, vec![h("Farm")], "future", 1_714_124_436);
        assert_eq!(
            rejected_message(relay.handle_event_with_auth(future, &auth).expect("future")),
            "blocked: group is deleted"
        );
        assert_eq!(
            count_filter(
                &relay,
                "deleted-group-normal",
                filter_group_tag(1, "h", "Farm")
            ),
            0
        );
        assert_eq!(
            count_filter(
                &relay,
                "deleted-group-marker",
                filter_group_tag(KIND_GROUP_DELETE_GROUP, "h", "Farm")
            ),
            1
        );
    }

    #[test]
    fn strict_closed_restricted_hidden_and_disabled_invite_flows() {
        let owner = signer(7).public_key().clone();
        let outsider_auth = authenticated_state(8);
        let owner_auth = authenticated_state(7);
        let relay = test_relay_with_groups(
            "base-relay-group-strict-policy-flow",
            4,
            &enabled_groups_for_owner(&owner),
        );
        relay
            .handle_event_with_auth(
                signed_group_create_event_with_tags(7, "Restricted", vec![restricted()], 1),
                &owner_auth,
            )
            .expect("restricted create");
        let restricted_write =
            signed_event_at(8, 1, vec![h("Restricted")], "restricted", 1_714_124_434);
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(restricted_write, &outsider_auth)
                    .expect("restricted write")
            ),
            "restricted: group is unavailable"
        );

        relay
            .handle_event_with_auth(
                signed_group_create_event_with_tags(7, "Closed", vec![closed()], 2),
                &owner_auth,
            )
            .expect("closed create");
        let closed_join = signed_event_at(
            8,
            KIND_GROUP_JOIN_REQUEST.into(),
            vec![h("Closed")],
            "",
            1_714_124_435,
        );
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(closed_join, &outsider_auth)
                    .expect("closed join")
            ),
            "restricted: group is unavailable"
        );
        let closed_normal = signed_event_at(8, 1, vec![h("Closed")], "open", 1_714_124_436);
        assert_accepted(
            relay
                .handle_event_with_auth(closed_normal.clone(), &outsider_auth)
                .expect("closed normal"),
            &closed_normal,
        );

        relay
            .handle_event_with_auth(
                signed_group_create_event_with_tags(7, "Hidden", vec![hidden()], 3),
                &owner_auth,
            )
            .expect("hidden create");
        assert_eq!(
            count_filter(
                &relay,
                "hidden-unauth",
                filter_group_tag(KIND_GROUP_METADATA, "d", "Hidden")
            ),
            0
        );
        assert_eq!(
            count_filter_with_auth(
                &relay,
                "hidden-owner",
                filter_group_tag(KIND_GROUP_METADATA, "d", "Hidden"),
                &owner_auth
            ),
            1
        );

        let invite = signed_event_at(
            7,
            KIND_GROUP_CREATE_INVITE.into(),
            vec![h("Closed")],
            "",
            1_714_124_437,
        );
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(invite, &owner_auth)
                    .expect("invite")
            ),
            "restricted: invites not enabled"
        );
    }

    #[test]
    fn private_group_req_and_count_use_reader_auth() {
        let owner = signer(7).public_key().clone();
        let auth = authenticated_state(7);
        let mut relay = test_relay_with_groups(
            "base-relay-private-read",
            4,
            &enabled_groups_for_owner(&owner),
        );
        relay
            .handle_event_with_auth(signed_private_group_create_event(7, "Farm"), &auth)
            .expect("create");
        let private_event = signed_event_at(
            7,
            1,
            vec![Tag::from_parts("h", &["Farm"]).expect("h")],
            "private harvest",
            1_714_124_435,
        );
        relay
            .handle_event_with_auth(private_event.clone(), &auth)
            .expect("private event");

        let unauth_sub = SubscriptionId::new("private-unauth").expect("sub");
        let auth_sub = SubscriptionId::new("private-auth").expect("sub");
        assert_eq!(
            relay
                .handle_req(unauth_sub.clone(), vec![filter_kind(1)])
                .expect("unauth req"),
            vec![RelayMessage::Eose(unauth_sub)]
        );
        assert!(matches!(
            relay
                .handle_req_with_auth(auth_sub.clone(), vec![filter_kind(1)], &auth)
                .expect("auth req")
                .as_slice(),
            [RelayMessage::Event { subscription_id, event }, RelayMessage::Eose(eose)]
                if subscription_id == &auth_sub && event.id() == private_event.id() && eose == &auth_sub
        ));
        assert_eq!(count_kind(&relay, 1), 0);
        assert_eq!(count_kind_with_auth(&relay, 1, &auth), 1);
        assert_eq!(count_kind(&relay, KIND_GROUP_METADATA), 1);
        assert_eq!(count_kind(&relay, KIND_GROUP_ADMINS), 1);
        assert_eq!(count_kind(&relay, KIND_GROUP_MEMBERS), 0);
        assert_eq!(count_kind_with_auth(&relay, KIND_GROUP_METADATA, &auth), 1);
        assert_eq!(count_kind_with_auth(&relay, KIND_GROUP_ADMINS, &auth), 1);
    }

    #[test]
    fn private_and_hidden_group_offset_lookup_uses_reader_auth() {
        let owner = signer(7).public_key().clone();
        let owner_auth = authenticated_state(7);
        let unauth = BaseAuthState::new("wss://relay.radroots.test", 60, 600).expect("auth state");
        let relay = test_relay_with_groups(
            "base-relay-private-offset-read",
            4,
            &enabled_groups_for_owner(&owner),
        );
        relay
            .handle_event_with_auth(signed_private_group_create_event(7, "Farm"), &owner_auth)
            .expect("create");
        let private_event = signed_event_at(
            7,
            1,
            vec![Tag::from_parts("h", &["Farm"]).expect("h")],
            "private harvest",
            1_714_124_435,
        );
        let pocket = tangle_event_to_pocket(&private_event).expect("pocket");
        let offset = StoreOffset::new(relay.store.store_event(&pocket).expect("store"));

        assert_eq!(
            relay
                .event_by_offset_with_auth(offset, &unauth)
                .expect("unauth offset"),
            None
        );
        let visible = relay
            .event_by_offset_with_auth(offset, &owner_auth)
            .expect("owner offset")
            .expect("visible");
        assert_eq!(visible.id(), private_event.id());

        relay
            .handle_event_with_auth(
                signed_group_create_event_with_tags(7, "HiddenFarm", vec![hidden()], 1_714_124_436),
                &owner_auth,
            )
            .expect("hidden create");
        let hidden_event = signed_event_at(
            7,
            1,
            vec![Tag::from_parts("h", &["HiddenFarm"]).expect("h")],
            "hidden harvest",
            1_714_124_437,
        );
        let pocket = tangle_event_to_pocket(&hidden_event).expect("hidden pocket");
        let offset = StoreOffset::new(relay.store.store_event(&pocket).expect("store hidden"));

        assert_eq!(
            relay
                .event_by_offset_with_auth(offset, &unauth)
                .expect("hidden unauth offset"),
            None
        );
        let visible = relay
            .event_by_offset_with_auth(offset, &owner_auth)
            .expect("hidden owner offset")
            .expect("hidden visible");
        assert_eq!(visible.id(), hidden_event.id());
    }

    #[test]
    fn private_group_live_fanout_uses_subscription_auth() {
        let owner = signer(7).public_key().clone();
        let auth = authenticated_state(7);
        let mut relay = test_relay_with_groups(
            "base-relay-private-fanout",
            4,
            &enabled_groups_for_owner(&owner),
        );
        relay
            .handle_event_with_auth(signed_private_group_create_event(7, "Farm"), &auth)
            .expect("create");
        let unauth_sub = SubscriptionId::new("fanout-unauth").expect("sub");
        let auth_sub = SubscriptionId::new("fanout-auth").expect("sub");
        relay
            .handle_req(unauth_sub, vec![filter_kind(1)])
            .expect("unauth sub");
        relay
            .handle_req_with_auth(auth_sub.clone(), vec![filter_kind(1)], &auth)
            .expect("auth sub");
        let private_event = signed_event_at(
            7,
            1,
            vec![Tag::from_parts("h", &["Farm"]).expect("h")],
            "private harvest",
            1_714_124_435,
        );
        relay
            .handle_event_with_auth(private_event.clone(), &auth)
            .expect("private event");

        assert!(matches!(
            relay.fanout(&private_event).as_slice(),
            [RelayMessage::Event { subscription_id, event }]
                if subscription_id == &auth_sub && event.id() == private_event.id()
        ));
    }

    #[test]
    fn live_subscription_delivery_volume_does_not_close_subscription() {
        let mut relay = test_relay("base-relay-delivery-volume", 1);
        let subscription_id = SubscriptionId::new("sub-volume").expect("sub");
        let filter = filter_from_value(&serde_json::json!({"kinds":[1]})).expect("filter");
        relay
            .handle_req(subscription_id.clone(), vec![filter])
            .expect("req");
        let first = signed_public_event(7, 1, Vec::new(), "first");
        let second = signed_public_event(7, 1, Vec::new(), "second");

        assert!(matches!(
            relay.fanout(&first).as_slice(),
            [RelayMessage::Event { .. }]
        ));
        assert!(matches!(
            relay.fanout(&second).as_slice(),
            [RelayMessage::Event { .. }]
        ));
        assert_eq!(relay.active_subscription_count(), 1);
    }

    #[test]
    fn base_relay_shutdown_closes_live_subscriptions_and_syncs_store() {
        let config = test_store_config("base-relay-shutdown");
        let mut relay =
            BaseRelay::open(&config, relay_limits(4), PocketQueryConfig::default()).expect("relay");
        let event = signed_public_event(7, 1, Vec::new(), "shutdown");
        let subscription_id = SubscriptionId::new("sub-shutdown").expect("sub");

        assert_accepted(relay.handle_event(event.clone()).expect("event"), &event);
        relay
            .handle_req(subscription_id, vec![filter_kind(1)])
            .expect("req");

        assert_eq!(relay.active_subscription_count(), 1);

        let report = relay.shutdown().expect("shutdown");

        assert_eq!(report.closed_subscriptions(), 1);
        assert_eq!(relay.active_subscription_count(), 0);
        assert!(relay.fanout(&event).is_empty());

        let reopened = BaseRelay::open(&config, relay_limits(4), PocketQueryConfig::default())
            .expect("reopened");
        assert_eq!(count_kind(&reopened, 1), 1);
    }

    #[test]
    fn base_relay_client_message_dispatch_handles_count_and_auth() {
        let mut relay = test_relay("base-relay-dispatch", 4);
        let mut auth =
            BaseAuthState::new("wss://relay.radroots.test", 60, 600).expect("auth state");
        auth.issue_challenge("challenge-a", UnixTimestamp::new(100))
            .expect("challenge");
        let auth_event = signed_auth_event(7, "challenge-a", 120);
        let count_id = SubscriptionId::new("count-a").expect("sub");

        assert_eq!(
            relay
                .handle_client_message(
                    ClientMessage::Auth(auth_event.clone()),
                    &mut auth,
                    UnixTimestamp::new(120)
                )
                .expect("auth"),
            vec![RelayMessage::Ok {
                event_id: auth_event.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        assert_eq!(
            relay
                .handle_client_message(
                    ClientMessage::Count {
                        subscription_id: count_id.clone(),
                        filters: vec![Filter::empty()]
                    },
                    &mut auth,
                    UnixTimestamp::new(130)
                )
                .expect("count"),
            vec![RelayMessage::Count {
                subscription_id: count_id,
                count: 0
            }]
        );
    }

    #[test]
    fn base_relay_enforces_event_and_filter_runtime_limits() {
        let config = test_store_config("base-relay-event-filter-runtime-limits");
        let mut relay =
            BaseRelay::open(&config, strict_relay_limits(), PocketQueryConfig::default())
                .expect("relay");
        let first = signed_public_event(7, 1, Vec::new(), "a");
        let second = signed_event_at(8, 1, Vec::new(), "b", 1_714_124_434);

        assert_accepted(relay.handle_event(first.clone()).expect("first"), &first);
        assert_accepted(relay.handle_event(second.clone()).expect("second"), &second);
        assert_eq!(
            rejected_message(
                relay
                    .handle_event(signed_public_event(7, 1, Vec::new(), "abcde"))
                    .expect("content")
            ),
            "invalid: event content length exceeds runtime max_content_length 4"
        );
        assert_eq!(
            rejected_message(
                relay
                    .handle_event(signed_public_event(
                        7,
                        1,
                        vec![
                            Tag::from_parts("t", &["one"]).expect("tag"),
                            Tag::from_parts("r", &["two"]).expect("tag"),
                        ],
                        "",
                    ))
                    .expect("tags")
            ),
            "invalid: event tag count exceeds runtime max_event_tags 1"
        );
        assert_eq!(
            relay
                .handle_req(
                    SubscriptionId::new("a").expect("sub"),
                    vec![Filter::empty()]
                )
                .expect("default limit")
                .len(),
            2
        );
        assert!(
            relay
                .handle_req(
                    SubscriptionId::new("a").expect("sub"),
                    vec![Filter::empty(), Filter::empty()],
                )
                .expect_err("filter count")
                .prefixed_message()
                .contains("max_filters_per_request 1")
        );
        assert!(
            relay
                .handle_count(
                    SubscriptionId::new("a").expect("sub"),
                    vec![
                        filter_from_value(&serde_json::json!({"#t":["one", "two"]}))
                            .expect("filter"),
                    ],
                )
                .expect_err("tag values")
                .prefixed_message()
                .contains("max_tag_values_per_filter 1")
        );
        assert!(
            relay
                .handle_req(
                    SubscriptionId::new("a").expect("sub"),
                    vec![filter_from_value(&serde_json::json!({"limit": 3})).expect("filter")],
                )
                .expect_err("max limit")
                .prefixed_message()
                .contains("max_limit 2")
        );
    }

    #[test]
    fn base_relay_enforces_subscription_id_and_count_limits() {
        let config = test_store_config("base-relay-subscription-limits");
        let mut relay =
            BaseRelay::open(&config, strict_relay_limits(), PocketQueryConfig::default())
                .expect("relay");

        assert!(
            relay
                .handle_req(
                    SubscriptionId::new("abcde").expect("sub"),
                    vec![Filter::empty()],
                )
                .expect_err("sub id length")
                .prefixed_message()
                .contains("max_subid_length 4")
        );
        relay
            .handle_req(
                SubscriptionId::new("a").expect("sub"),
                vec![Filter::empty()],
            )
            .expect("first subscription");
        assert!(
            relay
                .handle_req(
                    SubscriptionId::new("b").expect("sub"),
                    vec![Filter::empty()]
                )
                .expect_err("subscription count")
                .prefixed_message()
                .contains("connection subscription limit exceeded")
        );
        relay
            .handle_req(
                SubscriptionId::new("a").expect("sub"),
                vec![Filter::empty()],
            )
            .expect("replace subscription");
    }

    fn test_relay(name: &str, max_pending_events: usize) -> BaseRelay {
        let config = test_store_config(name);
        BaseRelay::open(
            &config,
            relay_limits(max_pending_events),
            PocketQueryConfig::default(),
        )
        .expect("relay")
    }

    fn test_relay_with_groups(
        name: &str,
        max_pending_events: usize,
        groups: &tangle_groups::GroupRuntimeConfig,
    ) -> BaseRelay {
        let config = test_store_config(name);
        BaseRelay::open_with_groups(
            &config,
            relay_limits(max_pending_events),
            groups,
            PocketQueryConfig::default(),
        )
        .expect("relay")
    }

    fn relay_limits(max_pending_events: usize) -> BaseRelayLimits {
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

    fn strict_relay_limits() -> BaseRelayLimits {
        BaseRelayLimits::new(BaseRelayLimitSettings {
            max_pending_events: 4,
            max_subscription_id_length: 4,
            max_subscriptions: 1,
            max_filters_per_request: 1,
            max_tag_values_per_filter: 1,
            max_query_complexity: 4,
            max_event_tags: 1,
            max_content_length: 4,
            max_limit: 2,
            default_limit: 1,
        })
        .expect("limits")
    }

    fn test_store_config(name: &str) -> PocketStoreConfig {
        let root = std::env::temp_dir().join(format!("tangle-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        PocketStoreConfig::new(root.join("pocket"), PocketSyncPolicy::FlushOnShutdown)
            .expect("config")
    }

    fn enabled_groups_for_owner(owner: &PublicKeyHex) -> tangle_groups::GroupRuntimeConfig {
        parse_group_runtime_config_json(&format!(
            r#"{{
                "enabled": true,
                "canonical_relay_url": "wss://relay.radroots.test",
                "relay_secret": "{}",
                "owner_pubkeys": ["{}"]
            }}"#,
            "7".repeat(64),
            owner.as_str()
        ))
        .expect("groups")
    }

    fn enabled_groups_for_owner_with_public_join(
        owner: &PublicKeyHex,
    ) -> tangle_groups::GroupRuntimeConfig {
        parse_group_runtime_config_json(&format!(
            r#"{{
                "enabled": true,
                "canonical_relay_url": "wss://relay.radroots.test",
                "relay_secret": "{}",
                "owner_pubkeys": ["{}"],
                "policy": {{"public_join": true, "invites_enabled": false}}
            }}"#,
            "7".repeat(64),
            owner.as_str()
        ))
        .expect("groups")
    }

    fn disabled_groups() -> tangle_groups::GroupRuntimeConfig {
        parse_group_runtime_config_json(r#"{"enabled": false}"#).expect("groups")
    }

    fn signed_auth_event(secret_byte: u8, challenge: &str, created_at: u64) -> Event {
        signed_event_at(
            secret_byte,
            22_242,
            vec![
                Tag::from_parts("relay", &["wss://relay.radroots.test"]).expect("relay"),
                Tag::from_parts("challenge", &[challenge]).expect("challenge"),
            ],
            "",
            created_at,
        )
    }

    fn signed_public_event(secret_byte: u8, kind: u64, tags: Vec<Tag>, content: &str) -> Event {
        signed_event_at(secret_byte, kind, tags, content, 1_714_124_433)
    }

    fn signed_group_create_event(secret_byte: u8, group_id: &str) -> Event {
        signed_group_create_event_with_tags(secret_byte, group_id, Vec::new(), 1_714_124_433)
    }

    fn signed_group_create_event_with_tags(
        secret_byte: u8,
        group_id: &str,
        mut extra_tags: Vec<Tag>,
        created_at: u64,
    ) -> Event {
        let mut tags = vec![h(group_id), name(group_id)];
        tags.append(&mut extra_tags);
        signed_event_at(
            secret_byte,
            KIND_GROUP_CREATE_GROUP.into(),
            tags,
            "",
            created_at,
        )
    }

    fn signed_private_group_create_event(secret_byte: u8, group_id: &str) -> Event {
        signed_event_at(
            secret_byte,
            KIND_GROUP_CREATE_GROUP.into(),
            vec![h(group_id), name(group_id), private()],
            "",
            1_714_124_433,
        )
    }

    fn signed_event_at(
        secret_byte: u8,
        kind: u64,
        tags: Vec<Tag>,
        content: &str,
        created_at: u64,
    ) -> Event {
        let secret = format!("{:02x}", secret_byte).repeat(32);
        let signer = RelaySigner::from_secret_hex(&secret).expect("signer");
        let unsigned = UnsignedEvent::new(
            signer.public_key().clone(),
            UnixTimestamp::new(created_at),
            Kind::new(kind).expect("kind"),
            tags,
            content,
        );
        signer.sign_unsigned_event(unsigned)
    }

    fn authenticated_state(secret_byte: u8) -> BaseAuthState {
        let mut auth =
            BaseAuthState::new("wss://relay.radroots.test", 60, 600).expect("auth state");
        auth.issue_challenge("challenge-a", UnixTimestamp::new(100))
            .expect("challenge");
        let event = signed_auth_event(secret_byte, "challenge-a", 120);
        auth.authenticate(&event, UnixTimestamp::new(120))
            .expect("authenticate");
        auth
    }

    fn count_kind(relay: &BaseRelay, kind: u32) -> u64 {
        let subscription_id = SubscriptionId::new(&format!("count-{kind}")).expect("sub");
        let filter = filter_kind(kind);
        match relay
            .handle_count(subscription_id, vec![filter])
            .expect("count")
        {
            RelayMessage::Count { count, .. } => count,
            _ => panic!("count response expected"),
        }
    }

    fn count_kind_with_auth(relay: &BaseRelay, kind: u32, auth: &BaseAuthState) -> u64 {
        let subscription_id = SubscriptionId::new(&format!("count-auth-{kind}")).expect("sub");
        match relay
            .handle_count_with_auth(subscription_id, vec![filter_kind(kind)], auth)
            .expect("count")
        {
            RelayMessage::Count { count, .. } => count,
            _ => panic!("count response expected"),
        }
    }

    fn count_filter(relay: &BaseRelay, subscription_id: &str, filter: Filter) -> u64 {
        match relay
            .handle_count(
                SubscriptionId::new(subscription_id).expect("sub"),
                vec![filter],
            )
            .expect("count")
        {
            RelayMessage::Count { count, .. } => count,
            _ => panic!("count response expected"),
        }
    }

    fn count_filter_with_auth(
        relay: &BaseRelay,
        subscription_id: &str,
        filter: Filter,
        auth: &BaseAuthState,
    ) -> u64 {
        match relay
            .handle_count_with_auth(
                SubscriptionId::new(subscription_id).expect("sub"),
                vec![filter],
                auth,
            )
            .expect("count")
        {
            RelayMessage::Count { count, .. } => count,
            _ => panic!("count response expected"),
        }
    }

    fn query_filter(relay: &mut BaseRelay, subscription_id: &str, filter: Filter) -> Vec<Event> {
        relay
            .handle_req(
                SubscriptionId::new(subscription_id).expect("sub"),
                vec![filter],
            )
            .expect("query")
            .into_iter()
            .filter_map(|message| match message {
                RelayMessage::Event { event, .. } => Some(event),
                _ => None,
            })
            .collect()
    }

    fn filter_kind(kind: u32) -> Filter {
        filter_from_value(&serde_json::json!({"kinds":[kind]})).expect("filter")
    }

    fn filter_group_tag(kind: u32, tag: &str, group_id: &str) -> Filter {
        let mut value = serde_json::json!({"kinds":[kind]});
        value
            .as_object_mut()
            .expect("object")
            .insert(format!("#{tag}"), serde_json::json!([group_id]));
        filter_from_value(&value).expect("filter")
    }

    fn assert_accepted(message: RelayMessage, event: &Event) {
        assert_eq!(
            message,
            RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: true,
                message: String::new()
            }
        );
    }

    fn rejected_message(message: RelayMessage) -> String {
        match message {
            RelayMessage::Ok {
                accepted: false,
                message,
                ..
            } => message,
            _ => panic!("rejected OK expected"),
        }
    }

    fn assert_member_status(
        relay: &BaseRelay,
        group_id: &str,
        pubkey: &PublicKeyHex,
        status: MemberStatus,
    ) {
        assert_eq!(
            relay
                .group_projection()
                .expect("projection")
                .member(&GroupId::new(group_id).expect("group"), pubkey)
                .expect("member")
                .status(),
            status
        );
    }

    fn has_tag(event: &Event, name: &str, values: &[&str]) -> bool {
        event.unsigned().tags().iter().any(|tag| {
            tag.values().first().is_some_and(|value| value == name)
                && tag.values().len() == values.len() + 1
                && values.iter().enumerate().all(|(index, expected)| {
                    tag.values()
                        .get(index + 1)
                        .is_some_and(|value| value == expected)
                })
        })
    }

    fn h(group_id: &str) -> Tag {
        Tag::from_parts("h", &[group_id]).expect("h")
    }

    fn p(pubkey: &PublicKeyHex) -> Tag {
        Tag::from_parts("p", &[pubkey.as_str()]).expect("p")
    }

    fn e(event_id: &EventId) -> Tag {
        Tag::from_parts("e", &[event_id.as_str()]).expect("e")
    }

    fn name(value: &str) -> Tag {
        Tag::from_parts("name", &[value]).expect("name")
    }

    fn private() -> Tag {
        Tag::from_parts("private", &[]).expect("private")
    }

    fn restricted() -> Tag {
        Tag::from_parts("restricted", &[]).expect("restricted")
    }

    fn hidden() -> Tag {
        Tag::from_parts("hidden", &[]).expect("hidden")
    }

    fn closed() -> Tag {
        Tag::from_parts("closed", &[]).expect("closed")
    }

    fn signer(secret_byte: u8) -> RelaySigner {
        RelaySigner::from_secret_hex(&format!("{:02x}", secret_byte).repeat(32)).expect("signer")
    }
}
