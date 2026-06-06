#![forbid(unsafe_code)]

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use tangle_crypto::verify_event_signature;
use tangle_nips::{
    DeletionRequest, ListingProjectionEvaluation, RelayAuthEvent, evaluate_listing_projection,
    parse_deletion_request, parse_nip50_filter_search, parse_relay_auth_event,
};
use tangle_protocol::{Event, EventId, Filter, PublicKeyHex, UnixTimestamp, event_to_value};
use tangle_store::{
    DeletionMarker, DeletionMarkerRepository, ListingProjectionRepository, RawEventRepository,
    RepositoryError, StoreEventOutcome, StoreProjectionOutcome, StoredEvent,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeLimitValues {
    pub max_event_bytes: u64,
    pub max_content_bytes: u64,
    pub max_tags_per_event: u64,
    pub max_tag_values_per_tag: u64,
    pub max_tag_value_bytes: u64,
    pub max_filters_per_subscription: u64,
    pub max_subscriptions_per_connection: u64,
    pub max_search_query_bytes: u64,
    pub max_search_tokens: u64,
    pub max_filter_complexity: u64,
    pub max_future_seconds: u64,
    pub live_event_buffer: u64,
    pub pending_store_events: u64,
}

impl Default for RuntimeLimitValues {
    fn default() -> Self {
        Self {
            max_event_bytes: 131_072,
            max_content_bytes: 65_536,
            max_tags_per_event: 128,
            max_tag_values_per_tag: 16,
            max_tag_value_bytes: 1_024,
            max_filters_per_subscription: 16,
            max_subscriptions_per_connection: 64,
            max_search_query_bytes: 256,
            max_search_tokens: 16,
            max_filter_complexity: 512,
            max_future_seconds: 900,
            live_event_buffer: 1_024,
            pending_store_events: 4_096,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeLimits {
    values: RuntimeLimitValues,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self::from_values(RuntimeLimitValues::default()).expect("default runtime limits are valid")
    }
}

impl RuntimeLimits {
    pub fn from_values(values: RuntimeLimitValues) -> Result<Self, RuntimeLimitConfigError> {
        require_positive("max_event_bytes", values.max_event_bytes)?;
        require_positive("max_content_bytes", values.max_content_bytes)?;
        require_positive("max_tags_per_event", values.max_tags_per_event)?;
        require_positive("max_tag_values_per_tag", values.max_tag_values_per_tag)?;
        require_positive("max_tag_value_bytes", values.max_tag_value_bytes)?;
        require_positive(
            "max_filters_per_subscription",
            values.max_filters_per_subscription,
        )?;
        require_positive(
            "max_subscriptions_per_connection",
            values.max_subscriptions_per_connection,
        )?;
        require_positive("max_search_query_bytes", values.max_search_query_bytes)?;
        require_positive("max_search_tokens", values.max_search_tokens)?;
        require_positive("max_filter_complexity", values.max_filter_complexity)?;
        require_positive("live_event_buffer", values.live_event_buffer)?;
        require_positive("pending_store_events", values.pending_store_events)?;
        if values.max_content_bytes > values.max_event_bytes {
            return Err(RuntimeLimitConfigError::Inconsistent {
                field: "max_content_bytes",
                maximum_field: "max_event_bytes",
                value: values.max_content_bytes,
                maximum: values.max_event_bytes,
            });
        }
        Ok(Self { values })
    }

    pub fn values(self) -> RuntimeLimitValues {
        self.values
    }

    pub fn max_event_bytes(self) -> u64 {
        self.values.max_event_bytes
    }

    pub fn max_content_bytes(self) -> u64 {
        self.values.max_content_bytes
    }

    pub fn max_tags_per_event(self) -> u64 {
        self.values.max_tags_per_event
    }

    pub fn max_tag_values_per_tag(self) -> u64 {
        self.values.max_tag_values_per_tag
    }

    pub fn max_tag_value_bytes(self) -> u64 {
        self.values.max_tag_value_bytes
    }

    pub fn max_filters_per_subscription(self) -> u64 {
        self.values.max_filters_per_subscription
    }

    pub fn max_subscriptions_per_connection(self) -> u64 {
        self.values.max_subscriptions_per_connection
    }

    pub fn max_search_query_bytes(self) -> u64 {
        self.values.max_search_query_bytes
    }

    pub fn max_search_tokens(self) -> u64 {
        self.values.max_search_tokens
    }

    pub fn max_filter_complexity(self) -> u64 {
        self.values.max_filter_complexity
    }

    pub fn max_future_seconds(self) -> u64 {
        self.values.max_future_seconds
    }

    pub fn live_event_buffer(self) -> u64 {
        self.values.live_event_buffer
    }

    pub fn pending_store_events(self) -> u64 {
        self.values.pending_store_events
    }

    pub fn validate_event(&self, event: &Event) -> Result<(), RuntimeLimitViolation> {
        let event_bytes = event_to_value(event).to_string().len() as u64;
        require_within(
            RuntimeLimitKind::EventBytes,
            event_bytes,
            self.values.max_event_bytes,
        )?;
        let content_bytes = event.unsigned().content().len() as u64;
        require_within(
            RuntimeLimitKind::ContentBytes,
            content_bytes,
            self.values.max_content_bytes,
        )?;
        let tag_count = event.unsigned().tags().len() as u64;
        require_within(
            RuntimeLimitKind::TagsPerEvent,
            tag_count,
            self.values.max_tags_per_event,
        )?;
        for tag in event.unsigned().tags() {
            let value_count = tag.values().len() as u64;
            require_within(
                RuntimeLimitKind::TagValuesPerTag,
                value_count,
                self.values.max_tag_values_per_tag,
            )?;
            for value in tag.values() {
                require_within(
                    RuntimeLimitKind::TagValueBytes,
                    value.len() as u64,
                    self.values.max_tag_value_bytes,
                )?;
            }
        }
        Ok(())
    }

    pub fn validate_filters(
        &self,
        filter_count: u64,
        complexity: u64,
    ) -> Result<(), RuntimeLimitViolation> {
        require_within(
            RuntimeLimitKind::FiltersPerSubscription,
            filter_count,
            self.values.max_filters_per_subscription,
        )?;
        require_within(
            RuntimeLimitKind::FilterComplexity,
            complexity,
            self.values.max_filter_complexity,
        )
    }

    pub fn validate_search_query(&self, query: &str) -> Result<(), RuntimeLimitViolation> {
        require_within(
            RuntimeLimitKind::SearchQueryBytes,
            query.len() as u64,
            self.values.max_search_query_bytes,
        )?;
        require_within(
            RuntimeLimitKind::SearchTokens,
            query.split_whitespace().count() as u64,
            self.values.max_search_tokens,
        )
    }

    pub fn validate_subscription_count(
        &self,
        active_subscriptions: u64,
    ) -> Result<(), RuntimeLimitViolation> {
        require_within(
            RuntimeLimitKind::SubscriptionsPerConnection,
            active_subscriptions,
            self.values.max_subscriptions_per_connection,
        )
    }

    pub fn validate_event_timestamp(
        &self,
        event: &Event,
        now: UnixTimestamp,
    ) -> Result<(), RuntimeLimitViolation> {
        let created_at = event.unsigned().created_at().as_u64();
        let now = now.as_u64();
        if created_at <= now {
            return Ok(());
        }
        require_within(
            RuntimeLimitKind::FutureSeconds,
            created_at - now,
            self.values.max_future_seconds,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeLimitConfigError {
    Zero {
        field: &'static str,
    },
    Inconsistent {
        field: &'static str,
        maximum_field: &'static str,
        value: u64,
        maximum: u64,
    },
}

impl fmt::Display for RuntimeLimitConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero { field } => write!(formatter, "`{field}` must be greater than zero"),
            Self::Inconsistent {
                field,
                maximum_field,
                value,
                maximum,
            } => write!(
                formatter,
                "`{field}` must not exceed `{maximum_field}` ({value} > {maximum})"
            ),
        }
    }
}

impl std::error::Error for RuntimeLimitConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeLimitViolation {
    kind: RuntimeLimitKind,
    actual: u64,
    maximum: u64,
}

impl RuntimeLimitViolation {
    pub fn new(kind: RuntimeLimitKind, actual: u64, maximum: u64) -> Self {
        Self {
            kind,
            actual,
            maximum,
        }
    }

    pub fn kind(self) -> RuntimeLimitKind {
        self.kind
    }

    pub fn actual(self) -> u64 {
        self.actual
    }

    pub fn maximum(self) -> u64 {
        self.maximum
    }
}

impl fmt::Display for RuntimeLimitViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} exceeded: {} > {}",
            self.kind.as_str(),
            self.actual,
            self.maximum
        )
    }
}

impl std::error::Error for RuntimeLimitViolation {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeLimitKind {
    EventBytes,
    ContentBytes,
    TagsPerEvent,
    TagValuesPerTag,
    TagValueBytes,
    FiltersPerSubscription,
    SubscriptionsPerConnection,
    SearchQueryBytes,
    SearchTokens,
    FilterComplexity,
    FutureSeconds,
}

impl RuntimeLimitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EventBytes => "event bytes",
            Self::ContentBytes => "content bytes",
            Self::TagsPerEvent => "tags per event",
            Self::TagValuesPerTag => "tag values per tag",
            Self::TagValueBytes => "tag value bytes",
            Self::FiltersPerSubscription => "filters per subscription",
            Self::SubscriptionsPerConnection => "subscriptions per connection",
            Self::SearchQueryBytes => "search query bytes",
            Self::SearchTokens => "search tokens",
            Self::FilterComplexity => "filter complexity",
            Self::FutureSeconds => "future seconds",
        }
    }
}

impl fmt::Display for RuntimeLimitKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionPolicy {
    require_write_auth: bool,
    unapproved_seller_action: UnapprovedSellerAction,
    approved_sellers: BTreeSet<PublicKeyHex>,
    blocked_pubkeys: BTreeSet<PublicKeyHex>,
}

impl Default for AdmissionPolicy {
    fn default() -> Self {
        Self {
            require_write_auth: true,
            unapproved_seller_action: UnapprovedSellerAction::StoreRawOnly,
            approved_sellers: BTreeSet::new(),
            blocked_pubkeys: BTreeSet::new(),
        }
    }
}

impl AdmissionPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn require_write_auth(&self) -> bool {
        self.require_write_auth
    }

    pub fn unapproved_seller_action(&self) -> UnapprovedSellerAction {
        self.unapproved_seller_action
    }

    pub fn approved_sellers(&self) -> &BTreeSet<PublicKeyHex> {
        &self.approved_sellers
    }

    pub fn blocked_pubkeys(&self) -> &BTreeSet<PublicKeyHex> {
        &self.blocked_pubkeys
    }

    pub fn with_write_auth_required(mut self, required: bool) -> Self {
        self.require_write_auth = required;
        self
    }

    pub fn with_unapproved_seller_action(mut self, action: UnapprovedSellerAction) -> Self {
        self.unapproved_seller_action = action;
        self
    }

    pub fn approve_seller(mut self, pubkey: PublicKeyHex) -> Self {
        self.approved_sellers.insert(pubkey);
        self
    }

    pub fn block_pubkey(mut self, pubkey: PublicKeyHex) -> Self {
        self.blocked_pubkeys.insert(pubkey);
        self
    }

    pub fn is_seller_approved(&self, pubkey: &PublicKeyHex) -> bool {
        self.approved_sellers.contains(pubkey)
    }

    pub fn is_pubkey_blocked(&self, pubkey: &PublicKeyHex) -> bool {
        self.blocked_pubkeys.contains(pubkey)
    }

    pub fn admit(&self, event: &AdmissionEvent, context: &AdmissionContext) -> AdmissionDecision {
        if event.kind() == AdmissionEventKind::RelayAuth {
            return AdmissionDecision::Accepted(AdmissionAcceptance::new(
                AdmissionEffect::AuthenticateOnly,
                None,
            ));
        }
        if let Some(rejection) = self.write_auth_rejection(event.author_pubkey(), context) {
            return AdmissionDecision::Rejected(rejection);
        }
        if self.is_pubkey_blocked(event.author_pubkey()) {
            if event.kind() == AdmissionEventKind::PublicListing {
                return AdmissionDecision::Accepted(AdmissionAcceptance::new(
                    AdmissionEffect::StoreRawWithoutPublicListingProjection,
                    Some(ProjectionExclusionReason::BlockedSeller),
                ));
            }
            return AdmissionDecision::Rejected(AdmissionRejection::new(
                AdmissionRejectionKind::BlockedPubkey,
                "blocked pubkey",
            ));
        }
        if event.kind() == AdmissionEventKind::PublicListing {
            return self.admit_public_listing(event.author_pubkey());
        }
        AdmissionDecision::Accepted(AdmissionAcceptance::new(AdmissionEffect::StoreRaw, None))
    }

    fn write_auth_rejection(
        &self,
        author_pubkey: &PublicKeyHex,
        context: &AdmissionContext,
    ) -> Option<AdmissionRejection> {
        if !self.require_write_auth {
            return None;
        }
        match context.authenticated_pubkey() {
            Some(authenticated_pubkey) if authenticated_pubkey == author_pubkey => None,
            Some(_) => Some(AdmissionRejection::new(
                AdmissionRejectionKind::AuthenticatedPubkeyMismatch,
                "authenticated pubkey does not match event author",
            )),
            None => Some(AdmissionRejection::new(
                AdmissionRejectionKind::AuthenticationRequired,
                "write authentication required",
            )),
        }
    }

    fn admit_public_listing(&self, seller_pubkey: &PublicKeyHex) -> AdmissionDecision {
        if self.is_seller_approved(seller_pubkey) {
            return AdmissionDecision::Accepted(AdmissionAcceptance::new(
                AdmissionEffect::StoreRawAndProjectPublicListing,
                None,
            ));
        }
        match self.unapproved_seller_action {
            UnapprovedSellerAction::StoreRawOnly => {
                AdmissionDecision::Accepted(AdmissionAcceptance::new(
                    AdmissionEffect::StoreRawWithoutPublicListingProjection,
                    Some(ProjectionExclusionReason::UnapprovedSeller),
                ))
            }
            UnapprovedSellerAction::RejectWrite => {
                AdmissionDecision::Rejected(AdmissionRejection::new(
                    AdmissionRejectionKind::UnapprovedSeller,
                    "seller is not approved",
                ))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionContext {
    authenticated_pubkey: Option<PublicKeyHex>,
}

impl AdmissionContext {
    pub fn unauthenticated() -> Self {
        Self {
            authenticated_pubkey: None,
        }
    }

    pub fn authenticated(pubkey: PublicKeyHex) -> Self {
        Self {
            authenticated_pubkey: Some(pubkey),
        }
    }

    pub fn authenticated_pubkey(&self) -> Option<&PublicKeyHex> {
        self.authenticated_pubkey.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionEvent {
    author_pubkey: PublicKeyHex,
    kind: AdmissionEventKind,
}

impl AdmissionEvent {
    pub fn new(author_pubkey: PublicKeyHex, kind: AdmissionEventKind) -> Self {
        Self {
            author_pubkey,
            kind,
        }
    }

    pub fn author_pubkey(&self) -> &PublicKeyHex {
        &self.author_pubkey
    }

    pub fn kind(&self) -> AdmissionEventKind {
        self.kind
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionEventKind {
    RelayAuth,
    Write,
    PublicListing,
    DraftListing,
}

impl AdmissionEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RelayAuth => "relay auth",
            Self::Write => "write",
            Self::PublicListing => "public listing",
            Self::DraftListing => "draft listing",
        }
    }
}

impl fmt::Display for AdmissionEventKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnapprovedSellerAction {
    StoreRawOnly,
    RejectWrite,
}

impl UnapprovedSellerAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StoreRawOnly => "store raw only",
            Self::RejectWrite => "reject write",
        }
    }
}

impl fmt::Display for UnapprovedSellerAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecision {
    Accepted(AdmissionAcceptance),
    Rejected(AdmissionRejection),
}

impl AdmissionDecision {
    pub fn accepted(&self) -> Option<&AdmissionAcceptance> {
        match self {
            Self::Accepted(acceptance) => Some(acceptance),
            Self::Rejected(_) => None,
        }
    }

    pub fn rejection(&self) -> Option<&AdmissionRejection> {
        match self {
            Self::Accepted(_) => None,
            Self::Rejected(rejection) => Some(rejection),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionAcceptance {
    effect: AdmissionEffect,
    projection_exclusion: Option<ProjectionExclusionReason>,
}

impl AdmissionAcceptance {
    pub fn new(
        effect: AdmissionEffect,
        projection_exclusion: Option<ProjectionExclusionReason>,
    ) -> Self {
        Self {
            effect,
            projection_exclusion,
        }
    }

    pub fn effect(&self) -> AdmissionEffect {
        self.effect
    }

    pub fn projection_exclusion(&self) -> Option<ProjectionExclusionReason> {
        self.projection_exclusion
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionEffect {
    AuthenticateOnly,
    StoreRaw,
    StoreRawAndProjectPublicListing,
    StoreRawWithoutPublicListingProjection,
}

impl AdmissionEffect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticateOnly => "authenticate only",
            Self::StoreRaw => "store raw",
            Self::StoreRawAndProjectPublicListing => "store raw and project public listing",
            Self::StoreRawWithoutPublicListingProjection => {
                "store raw without public listing projection"
            }
        }
    }
}

impl fmt::Display for AdmissionEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionExclusionReason {
    UnapprovedSeller,
    BlockedSeller,
}

impl ProjectionExclusionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnapprovedSeller => "unapproved seller",
            Self::BlockedSeller => "blocked seller",
        }
    }
}

impl fmt::Display for ProjectionExclusionReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRejection {
    kind: AdmissionRejectionKind,
    message: String,
}

impl AdmissionRejection {
    pub fn new(kind: AdmissionRejectionKind, message: &str) -> Self {
        Self {
            kind,
            message: message.to_owned(),
        }
    }

    pub fn kind(&self) -> AdmissionRejectionKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for AdmissionRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for AdmissionRejection {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionRejectionKind {
    AuthenticationRequired,
    AuthenticatedPubkeyMismatch,
    BlockedPubkey,
    UnapprovedSeller,
}

impl AdmissionRejectionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticationRequired => "authentication required",
            Self::AuthenticatedPubkeyMismatch => "authenticated pubkey mismatch",
            Self::BlockedPubkey => "blocked pubkey",
            Self::UnapprovedSeller => "unapproved seller",
        }
    }
}

impl fmt::Display for AdmissionRejectionKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventValidator {
    limits: RuntimeLimits,
    admission_policy: AdmissionPolicy,
}

impl EventValidator {
    pub fn new(limits: RuntimeLimits, admission_policy: AdmissionPolicy) -> Self {
        Self {
            limits,
            admission_policy,
        }
    }

    pub fn limits(&self) -> RuntimeLimits {
        self.limits
    }

    pub fn admission_policy(&self) -> &AdmissionPolicy {
        &self.admission_policy
    }

    pub fn validate(
        &self,
        event: &Event,
        context: &AdmissionContext,
        now: UnixTimestamp,
    ) -> Result<ValidatedEvent, EventValidationRejection> {
        self.limits
            .validate_event(event)
            .map_err(EventValidationRejection::RuntimeLimit)?;
        self.limits
            .validate_event_timestamp(event, now)
            .map_err(EventValidationRejection::RuntimeLimit)?;
        verify_event_signature(event).map_err(EventValidationRejection::Crypto)?;
        let payload = validation_payload(event)?;
        let admission_event =
            AdmissionEvent::new(event.unsigned().pubkey().clone(), payload.admission_kind());
        let admission = match self.admission_policy.admit(&admission_event, context) {
            AdmissionDecision::Accepted(acceptance) => acceptance,
            AdmissionDecision::Rejected(rejection) => {
                return Err(EventValidationRejection::Admission(rejection));
            }
        };
        Ok(ValidatedEvent {
            event_id: event.id().clone(),
            author_pubkey: event.unsigned().pubkey().clone(),
            admission_kind: admission_event.kind(),
            admission,
            payload,
        })
    }
}

impl Default for EventValidator {
    fn default() -> Self {
        Self::new(RuntimeLimits::default(), AdmissionPolicy::default())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedEvent {
    event_id: EventId,
    author_pubkey: PublicKeyHex,
    admission_kind: AdmissionEventKind,
    admission: AdmissionAcceptance,
    payload: ValidatedEventPayload,
}

impl ValidatedEvent {
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }

    pub fn author_pubkey(&self) -> &PublicKeyHex {
        &self.author_pubkey
    }

    pub fn admission_kind(&self) -> AdmissionEventKind {
        self.admission_kind
    }

    pub fn admission(&self) -> &AdmissionAcceptance {
        &self.admission
    }

    pub fn payload(&self) -> &ValidatedEventPayload {
        &self.payload
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatedEventPayload {
    RelayAuth(Box<RelayAuthEvent>),
    Deletion(Box<DeletionRequest>),
    Listing {
        admission_kind: AdmissionEventKind,
        evaluation: Box<ListingProjectionEvaluation>,
    },
    Other,
}

impl ValidatedEventPayload {
    pub fn admission_kind(&self) -> AdmissionEventKind {
        match self {
            Self::RelayAuth(_) => AdmissionEventKind::RelayAuth,
            Self::Deletion(_) | Self::Other => AdmissionEventKind::Write,
            Self::Listing { admission_kind, .. } => *admission_kind,
        }
    }

    pub fn relay_auth(&self) -> Option<&RelayAuthEvent> {
        match self {
            Self::RelayAuth(event) => Some(event),
            Self::Deletion(_) | Self::Listing { .. } | Self::Other => None,
        }
    }

    pub fn deletion_request(&self) -> Option<&DeletionRequest> {
        match self {
            Self::Deletion(request) => Some(request),
            Self::RelayAuth(_) | Self::Listing { .. } | Self::Other => None,
        }
    }

    pub fn listing_evaluation(&self) -> Option<&ListingProjectionEvaluation> {
        match self {
            Self::Listing { evaluation, .. } => Some(evaluation),
            Self::RelayAuth(_) | Self::Deletion(_) | Self::Other => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventValidationRejection {
    RuntimeLimit(RuntimeLimitViolation),
    Crypto(String),
    Parser(EventParserRejection),
    Admission(AdmissionRejection),
}

impl EventValidationRejection {
    pub fn kind(&self) -> EventValidationRejectionKind {
        match self {
            Self::RuntimeLimit(_) => EventValidationRejectionKind::RuntimeLimit,
            Self::Crypto(_) => EventValidationRejectionKind::Crypto,
            Self::Parser(_) => EventValidationRejectionKind::Parser,
            Self::Admission(_) => EventValidationRejectionKind::Admission,
        }
    }
}

impl fmt::Display for EventValidationRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeLimit(violation) => write!(formatter, "runtime limit: {violation}"),
            Self::Crypto(message) => write!(formatter, "crypto: {message}"),
            Self::Parser(rejection) => write!(formatter, "parser: {rejection}"),
            Self::Admission(rejection) => write!(formatter, "admission: {rejection}"),
        }
    }
}

impl std::error::Error for EventValidationRejection {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventValidationRejectionKind {
    RuntimeLimit,
    Crypto,
    Parser,
    Admission,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventParserRejection {
    parser: EventParser,
    message: String,
}

impl EventParserRejection {
    pub fn new(parser: EventParser, message: String) -> Self {
        Self { parser, message }
    }

    pub fn parser(&self) -> EventParser {
        self.parser
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for EventParserRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.parser, self.message)
    }
}

impl std::error::Error for EventParserRejection {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventParser {
    RelayAuth,
    Deletion,
}

impl EventParser {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RelayAuth => "relay auth",
            Self::Deletion => "deletion",
        }
    }
}

impl fmt::Display for EventParser {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

fn validation_payload(event: &Event) -> Result<ValidatedEventPayload, EventValidationRejection> {
    if event.unsigned().kind().as_u32() == 22_242 {
        let auth = parse_relay_auth_event(event)
            .map_err(|message| {
                EventValidationRejection::Parser(EventParserRejection::new(
                    EventParser::RelayAuth,
                    message,
                ))
            })?
            .expect("relay auth kind must parse as relay auth");
        return Ok(ValidatedEventPayload::RelayAuth(Box::new(auth)));
    }
    if event.unsigned().kind().as_u32() == 5 {
        let deletion = parse_deletion_request(event)
            .map_err(|message| {
                EventValidationRejection::Parser(EventParserRejection::new(
                    EventParser::Deletion,
                    message,
                ))
            })?
            .expect("deletion kind must parse as deletion request");
        return Ok(ValidatedEventPayload::Deletion(Box::new(deletion)));
    }
    match event.unsigned().kind().as_u32() {
        30_402 => Ok(ValidatedEventPayload::Listing {
            admission_kind: AdmissionEventKind::PublicListing,
            evaluation: Box::new(evaluate_listing_projection(event)),
        }),
        30_403 => Ok(ValidatedEventPayload::Listing {
            admission_kind: AdmissionEventKind::DraftListing,
            evaluation: Box::new(evaluate_listing_projection(event)),
        }),
        _ => Ok(ValidatedEventPayload::Other),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventIngestor {
    validator: EventValidator,
}

impl EventIngestor {
    pub fn new(validator: EventValidator) -> Self {
        Self { validator }
    }

    pub fn validator(&self) -> &EventValidator {
        &self.validator
    }

    pub fn ingest<R>(
        &self,
        repository: &mut R,
        event: Event,
        context: &AdmissionContext,
        received_at: UnixTimestamp,
        now: UnixTimestamp,
    ) -> Result<EventIngestion, EventIngestionRejection>
    where
        R: RawEventRepository + ListingProjectionRepository + DeletionMarkerRepository,
    {
        let validated = self
            .validator
            .validate(&event, context, now)
            .map_err(EventIngestionRejection::Validation)?;
        if validated.admission().effect() == AdmissionEffect::AuthenticateOnly {
            return Ok(EventIngestion::new(
                validated.event_id().clone(),
                EventIngestionEffect::Authenticated,
                None,
                None,
                0,
            ));
        }
        if event.unsigned().kind().is_ephemeral() {
            return Ok(EventIngestion::new(
                validated.event_id().clone(),
                EventIngestionEffect::EphemeralAccepted,
                None,
                None,
                0,
            ));
        }
        let raw_outcome = repository
            .put_event(StoredEvent::new(event.clone(), received_at))
            .map_err(EventIngestionRejection::Repository)?;
        if raw_outcome == StoreEventOutcome::Duplicate {
            return Ok(EventIngestion::new(
                validated.event_id().clone(),
                EventIngestionEffect::Duplicate,
                Some(raw_outcome),
                None,
                0,
            ));
        }
        let projection_outcome = ingest_projection(repository, &validated)?;
        let deletion_marker_count = ingest_deletion_markers(repository, &validated, &event)?;
        Ok(EventIngestion::new(
            validated.event_id().clone(),
            EventIngestionEffect::Stored,
            Some(raw_outcome),
            projection_outcome,
            deletion_marker_count,
        ))
    }
}

impl Default for EventIngestor {
    fn default() -> Self {
        Self::new(EventValidator::default())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventIngestion {
    event_id: EventId,
    effect: EventIngestionEffect,
    raw_event_outcome: Option<StoreEventOutcome>,
    projection_outcome: Option<StoreProjectionOutcome>,
    deletion_marker_count: usize,
}

impl EventIngestion {
    pub fn new(
        event_id: EventId,
        effect: EventIngestionEffect,
        raw_event_outcome: Option<StoreEventOutcome>,
        projection_outcome: Option<StoreProjectionOutcome>,
        deletion_marker_count: usize,
    ) -> Self {
        Self {
            event_id,
            effect,
            raw_event_outcome,
            projection_outcome,
            deletion_marker_count,
        }
    }

    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }

    pub fn effect(&self) -> EventIngestionEffect {
        self.effect
    }

    pub fn raw_event_outcome(&self) -> Option<StoreEventOutcome> {
        self.raw_event_outcome
    }

    pub fn projection_outcome(&self) -> Option<StoreProjectionOutcome> {
        self.projection_outcome
    }

    pub fn deletion_marker_count(&self) -> usize {
        self.deletion_marker_count
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventIngestionEffect {
    Authenticated,
    EphemeralAccepted,
    Stored,
    Duplicate,
}

impl EventIngestionEffect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authenticated => "authenticated",
            Self::EphemeralAccepted => "ephemeral accepted",
            Self::Stored => "stored",
            Self::Duplicate => "duplicate",
        }
    }
}

impl fmt::Display for EventIngestionEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventIngestionRejection {
    Validation(EventValidationRejection),
    Repository(RepositoryError),
}

impl EventIngestionRejection {
    pub fn kind(&self) -> EventIngestionRejectionKind {
        match self {
            Self::Validation(_) => EventIngestionRejectionKind::Validation,
            Self::Repository(_) => EventIngestionRejectionKind::Repository,
        }
    }
}

impl fmt::Display for EventIngestionRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(rejection) => write!(formatter, "validation: {rejection}"),
            Self::Repository(rejection) => write!(formatter, "repository: {rejection}"),
        }
    }
}

impl std::error::Error for EventIngestionRejection {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventIngestionRejectionKind {
    Validation,
    Repository,
}

fn ingest_projection<R>(
    repository: &mut R,
    validated: &ValidatedEvent,
) -> Result<Option<StoreProjectionOutcome>, EventIngestionRejection>
where
    R: ListingProjectionRepository,
{
    if validated.admission().effect() != AdmissionEffect::StoreRawAndProjectPublicListing {
        return Ok(None);
    }
    let Some(ListingProjectionEvaluation::Eligible(projection)) =
        validated.payload().listing_evaluation()
    else {
        return Ok(None);
    };
    repository
        .put_listing_projection(projection.as_ref().clone())
        .map(Some)
        .map_err(EventIngestionRejection::Repository)
}

fn ingest_deletion_markers<R>(
    repository: &mut R,
    validated: &ValidatedEvent,
    event: &Event,
) -> Result<usize, EventIngestionRejection>
where
    R: DeletionMarkerRepository,
{
    let Some(request) = validated.payload().deletion_request() else {
        return Ok(0);
    };
    for target in request.targets() {
        repository
            .put_deletion_marker(DeletionMarker::new(
                request.event_id().clone(),
                event.unsigned().pubkey().clone(),
                target.clone(),
                event.unsigned().created_at(),
            ))
            .map_err(EventIngestionRejection::Repository)?;
    }
    Ok(request.targets().len())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryPlan {
    source: QuerySource,
    mode: QueryExecutionMode,
    sort: QuerySort,
    branches: Vec<QueryPlanBranch>,
}

impl QueryPlan {
    pub fn new(
        source: QuerySource,
        mode: QueryExecutionMode,
        sort: QuerySort,
        branches: Vec<QueryPlanBranch>,
    ) -> Result<Self, QueryPlanError> {
        if branches.is_empty() {
            return Err(QueryPlanError::EmptyBranches);
        }
        Ok(Self {
            source,
            mode,
            sort,
            branches,
        })
    }

    pub fn source(&self) -> QuerySource {
        self.source
    }

    pub fn mode(&self) -> QueryExecutionMode {
        self.mode
    }

    pub fn sort(&self) -> QuerySort {
        self.sort
    }

    pub fn branches(&self) -> &[QueryPlanBranch] {
        &self.branches
    }

    pub fn requires_historical_query(&self) -> bool {
        self.mode != QueryExecutionMode::Live
            && self.branches.iter().any(|branch| branch.limit() != Some(0))
    }

    pub fn subscribes_to_live_events(&self) -> bool {
        self.mode != QueryExecutionMode::Historical
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryPlanBranch {
    ids: Vec<EventId>,
    authors: Vec<PublicKeyHex>,
    kinds: Vec<tangle_protocol::Kind>,
    tag_filters: BTreeMap<char, Vec<String>>,
    since: Option<UnixTimestamp>,
    until: Option<UnixTimestamp>,
    limit: Option<u64>,
    search: Option<QuerySearch>,
}

impl QueryPlanBranch {
    pub fn from_spec(spec: QueryPlanBranchSpec) -> Result<Self, QueryPlanError> {
        if let (Some(since), Some(until)) = (spec.since, spec.until)
            && since > until
        {
            return Err(QueryPlanError::InvalidTimeRange { since, until });
        }
        let mut tag_filters = BTreeMap::new();
        for filter in spec.tag_filters {
            tag_filters
                .entry(filter.name())
                .or_insert_with(Vec::new)
                .extend(filter.values().iter().cloned());
        }
        for values in tag_filters.values_mut() {
            let unique = values.drain(..).collect::<BTreeSet<_>>();
            values.extend(unique);
        }
        Ok(Self {
            ids: unique_sorted(spec.ids),
            authors: unique_sorted(spec.authors),
            kinds: unique_sorted(spec.kinds),
            tag_filters,
            since: spec.since,
            until: spec.until,
            limit: spec.limit,
            search: spec.search,
        })
    }

    pub fn ids(&self) -> &[EventId] {
        &self.ids
    }

    pub fn authors(&self) -> &[PublicKeyHex] {
        &self.authors
    }

    pub fn kinds(&self) -> &[tangle_protocol::Kind] {
        &self.kinds
    }

    pub fn tag_filters(&self) -> &BTreeMap<char, Vec<String>> {
        &self.tag_filters
    }

    pub fn since(&self) -> Option<UnixTimestamp> {
        self.since
    }

    pub fn until(&self) -> Option<UnixTimestamp> {
        self.until
    }

    pub fn limit(&self) -> Option<u64> {
        self.limit
    }

    pub fn search(&self) -> Option<&QuerySearch> {
        self.search.as_ref()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryPlanBranchSpec {
    pub ids: Vec<EventId>,
    pub authors: Vec<PublicKeyHex>,
    pub kinds: Vec<tangle_protocol::Kind>,
    pub tag_filters: Vec<QueryTagFilter>,
    pub since: Option<UnixTimestamp>,
    pub until: Option<UnixTimestamp>,
    pub limit: Option<u64>,
    pub search: Option<QuerySearch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryTagFilter {
    name: char,
    values: Vec<String>,
}

impl QueryTagFilter {
    pub fn new(name: char, values: Vec<String>) -> Result<Self, QueryPlanError> {
        if !name.is_ascii_alphabetic() {
            return Err(QueryPlanError::InvalidTagName { name });
        }
        if values.is_empty() {
            return Err(QueryPlanError::EmptyTagValues { name });
        }
        if values.iter().any(String::is_empty) {
            return Err(QueryPlanError::EmptyTagValue { name });
        }
        Ok(Self {
            name,
            values: unique_sorted(values),
        })
    }

    pub fn name(&self) -> char {
        self.name
    }

    pub fn values(&self) -> &[String] {
        &self.values
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuerySearch {
    raw: String,
    terms: Vec<String>,
}

impl QuerySearch {
    pub fn new(raw: &str, terms: Vec<String>) -> Result<Self, QueryPlanError> {
        let raw = raw.trim();
        if raw.is_empty() || terms.is_empty() || terms.iter().any(String::is_empty) {
            return Err(QueryPlanError::EmptySearch);
        }
        Ok(Self {
            raw: raw.to_owned(),
            terms: unique_sorted(terms),
        })
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn terms(&self) -> &[String] {
        &self.terms
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuerySource {
    RawEvents,
    ListingProjections,
    SearchDocuments,
}

impl QuerySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RawEvents => "raw events",
            Self::ListingProjections => "listing projections",
            Self::SearchDocuments => "search documents",
        }
    }
}

impl fmt::Display for QuerySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryExecutionMode {
    Historical,
    Live,
    HistoricalThenLive,
}

impl QueryExecutionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Historical => "historical",
            Self::Live => "live",
            Self::HistoricalThenLive => "historical then live",
        }
    }
}

impl fmt::Display for QueryExecutionMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuerySort {
    CreatedAtDescEventIdAsc,
    ScoreDescCreatedAtDescEventIdAsc,
}

impl QuerySort {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CreatedAtDescEventIdAsc => "created_at desc event_id asc",
            Self::ScoreDescCreatedAtDescEventIdAsc => "score desc created_at desc event_id asc",
        }
    }
}

impl fmt::Display for QuerySort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryPlanError {
    EmptyBranches,
    InvalidTimeRange {
        since: UnixTimestamp,
        until: UnixTimestamp,
    },
    InvalidTagName {
        name: char,
    },
    EmptyTagValues {
        name: char,
    },
    EmptyTagValue {
        name: char,
    },
    EmptySearch,
}

impl fmt::Display for QueryPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBranches => {
                formatter.write_str("query plan must include at least one branch")
            }
            Self::InvalidTimeRange { since, until } => {
                write!(
                    formatter,
                    "query time range is invalid: since {since} > until {until}"
                )
            }
            Self::InvalidTagName { name } => {
                write!(
                    formatter,
                    "tag filter name must be ASCII alphabetic, got `{name}`"
                )
            }
            Self::EmptyTagValues { name } => {
                write!(
                    formatter,
                    "tag filter `{name}` must include at least one value"
                )
            }
            Self::EmptyTagValue { name } => {
                write!(formatter, "tag filter `{name}` values must not be empty")
            }
            Self::EmptySearch => formatter.write_str("search query must include terms"),
        }
    }
}

impl std::error::Error for QueryPlanError {}

fn unique_sorted<T>(values: Vec<T>) -> Vec<T>
where
    T: Ord,
{
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NostrFilterCompiler {
    limits: RuntimeLimits,
}

impl NostrFilterCompiler {
    pub fn new(limits: RuntimeLimits) -> Self {
        Self { limits }
    }

    pub fn limits(self) -> RuntimeLimits {
        self.limits
    }

    pub fn compile(
        &self,
        filters: &[Filter],
        mode: QueryExecutionMode,
    ) -> Result<QueryPlan, NostrFilterCompileError> {
        self.limits
            .validate_filters(filters.len() as u64, filter_complexity(filters))
            .map_err(NostrFilterCompileError::RuntimeLimit)?;
        let branches = filters
            .iter()
            .map(compile_filter_branch)
            .collect::<Result<Vec<_>, _>>()?;
        let source = if branches.iter().any(|branch| branch.search().is_some()) {
            QuerySource::SearchDocuments
        } else {
            QuerySource::RawEvents
        };
        let sort = if source == QuerySource::SearchDocuments {
            QuerySort::ScoreDescCreatedAtDescEventIdAsc
        } else {
            QuerySort::CreatedAtDescEventIdAsc
        };
        QueryPlan::new(source, mode, sort, branches).map_err(NostrFilterCompileError::QueryPlan)
    }
}

impl Default for NostrFilterCompiler {
    fn default() -> Self {
        Self::new(RuntimeLimits::default())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NostrFilterCompileError {
    RuntimeLimit(RuntimeLimitViolation),
    QueryPlan(QueryPlanError),
}

impl NostrFilterCompileError {
    pub fn kind(&self) -> NostrFilterCompileErrorKind {
        match self {
            Self::RuntimeLimit(_) => NostrFilterCompileErrorKind::RuntimeLimit,
            Self::QueryPlan(_) => NostrFilterCompileErrorKind::QueryPlan,
        }
    }
}

impl fmt::Display for NostrFilterCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeLimit(violation) => write!(formatter, "runtime limit: {violation}"),
            Self::QueryPlan(error) => write!(formatter, "query plan: {error}"),
        }
    }
}

impl std::error::Error for NostrFilterCompileError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NostrFilterCompileErrorKind {
    RuntimeLimit,
    QueryPlan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nip50QueryCompiler {
    limits: RuntimeLimits,
}

impl Nip50QueryCompiler {
    pub fn new(limits: RuntimeLimits) -> Self {
        Self { limits }
    }

    pub fn limits(self) -> RuntimeLimits {
        self.limits
    }

    pub fn compile(
        &self,
        filters: &[Filter],
        mode: QueryExecutionMode,
    ) -> Result<QueryPlan, Nip50QueryCompileError> {
        self.limits
            .validate_filters(filters.len() as u64, filter_complexity(filters))
            .map_err(Nip50QueryCompileError::RuntimeLimit)?;
        let branches = filters
            .iter()
            .map(|filter| compile_nip50_filter_branch(filter, self.limits))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        if branches.is_empty() {
            return Err(Nip50QueryCompileError::MissingSearchTerms);
        }
        QueryPlan::new(
            QuerySource::SearchDocuments,
            mode,
            QuerySort::ScoreDescCreatedAtDescEventIdAsc,
            branches,
        )
        .map_err(Nip50QueryCompileError::QueryPlan)
    }
}

impl Default for Nip50QueryCompiler {
    fn default() -> Self {
        Self::new(RuntimeLimits::default())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nip50QueryCompileError {
    RuntimeLimit(RuntimeLimitViolation),
    QueryPlan(QueryPlanError),
    MissingSearchTerms,
}

impl Nip50QueryCompileError {
    pub fn kind(&self) -> Nip50QueryCompileErrorKind {
        match self {
            Self::RuntimeLimit(_) => Nip50QueryCompileErrorKind::RuntimeLimit,
            Self::QueryPlan(_) => Nip50QueryCompileErrorKind::QueryPlan,
            Self::MissingSearchTerms => Nip50QueryCompileErrorKind::MissingSearchTerms,
        }
    }
}

impl fmt::Display for Nip50QueryCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeLimit(violation) => write!(formatter, "runtime limit: {violation}"),
            Self::QueryPlan(error) => write!(formatter, "query plan: {error}"),
            Self::MissingSearchTerms => {
                formatter.write_str("nip50 query must include plain search terms")
            }
        }
    }
}

impl std::error::Error for Nip50QueryCompileError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nip50QueryCompileErrorKind {
    RuntimeLimit,
    QueryPlan,
    MissingSearchTerms,
}

fn compile_filter_branch(filter: &Filter) -> Result<QueryPlanBranch, NostrFilterCompileError> {
    let tag_filters =
        compile_filter_tag_constraints(filter).map_err(NostrFilterCompileError::QueryPlan)?;
    let search = filter
        .search()
        .map(|raw| {
            QuerySearch::new(
                raw,
                raw.split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            )
            .map_err(NostrFilterCompileError::QueryPlan)
        })
        .transpose()?;
    QueryPlanBranch::from_spec(QueryPlanBranchSpec {
        ids: filter.ids().to_vec(),
        authors: filter.authors().to_vec(),
        kinds: filter.kinds().to_vec(),
        tag_filters,
        since: filter.since(),
        until: filter.until(),
        limit: filter.limit(),
        search,
    })
    .map_err(NostrFilterCompileError::QueryPlan)
}

fn compile_nip50_filter_branch(
    filter: &Filter,
    limits: RuntimeLimits,
) -> Result<Option<QueryPlanBranch>, Nip50QueryCompileError> {
    if let Some(raw) = filter.search() {
        limits
            .validate_search_query(raw)
            .map_err(Nip50QueryCompileError::RuntimeLimit)?;
    }
    let search = match parse_nip50_filter_search(filter)
        .expect("validated protocol filters are valid nip50 parser input")
    {
        Some(search) => search,
        None => return Ok(None),
    };
    let search = QuerySearch::new(search.text(), search.terms().to_vec())
        .expect("nip50 parser only returns search queries with plain terms");
    let tag_filters =
        compile_filter_tag_constraints(filter).map_err(Nip50QueryCompileError::QueryPlan)?;
    QueryPlanBranch::from_spec(QueryPlanBranchSpec {
        ids: filter.ids().to_vec(),
        authors: filter.authors().to_vec(),
        kinds: filter.kinds().to_vec(),
        tag_filters,
        since: filter.since(),
        until: filter.until(),
        limit: filter.limit(),
        search: Some(search),
    })
    .map(Some)
    .map_err(Nip50QueryCompileError::QueryPlan)
}

fn compile_filter_tag_constraints(filter: &Filter) -> Result<Vec<QueryTagFilter>, QueryPlanError> {
    filter
        .tag_filters()
        .iter()
        .map(|(name, values)| {
            let name = name
                .as_str()
                .chars()
                .next()
                .expect("protocol tag filters are non-empty");
            QueryTagFilter::new(
                name,
                values
                    .iter()
                    .map(|value| value.as_str().to_owned())
                    .collect(),
            )
        })
        .collect()
}

fn filter_complexity(filters: &[Filter]) -> u64 {
    filters
        .iter()
        .map(|filter| {
            let tag_value_count = filter.tag_filters().values().map(Vec::len).sum::<usize>();
            let search_terms = filter
                .search()
                .map_or(0, |search| search.split_whitespace().count());
            1 + filter.ids().len()
                + filter.authors().len()
                + filter.kinds().len()
                + filter.tag_filters().len()
                + tag_value_count
                + usize::from(filter.since().is_some())
                + usize::from(filter.until().is_some())
                + usize::from(filter.limit().is_some())
                + search_terms
        })
        .sum::<usize>() as u64
}

fn require_positive(field: &'static str, value: u64) -> Result<(), RuntimeLimitConfigError> {
    if value == 0 {
        Err(RuntimeLimitConfigError::Zero { field })
    } else {
        Ok(())
    }
}

fn require_within(
    kind: RuntimeLimitKind,
    actual: u64,
    maximum: u64,
) -> Result<(), RuntimeLimitViolation> {
    if actual > maximum {
        Err(RuntimeLimitViolation::new(kind, actual, maximum))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AdmissionContext, AdmissionEffect, AdmissionEvent, AdmissionEventKind, AdmissionPolicy,
        AdmissionRejectionKind, EventIngestionEffect, EventIngestionRejectionKind, EventIngestor,
        EventParser, EventValidationRejection, EventValidationRejectionKind, EventValidator,
        Nip50QueryCompileErrorKind, Nip50QueryCompiler, NostrFilterCompileErrorKind,
        NostrFilterCompiler, ProjectionExclusionReason, QueryExecutionMode, QueryPlan,
        QueryPlanBranch, QueryPlanBranchSpec, QueryPlanError, QuerySearch, QuerySort, QuerySource,
        QueryTagFilter, RuntimeLimitConfigError, RuntimeLimitKind, RuntimeLimitValues,
        RuntimeLimits, UnapprovedSellerAction,
    };
    use tangle_nips::{ListingProjection, evaluate_listing_projection, parse_deletion_request};
    use tangle_protocol::{
        AddressCoordinate, Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp,
        UnsignedEvent, filter_from_value,
    };
    use tangle_store::{
        DeletionMarker, DeletionMarkerRepository, ListingProjectionRepository, RawEventRepository,
        RepositoryError, StoreEventOutcome, StoreProjectionOutcome, StoredEvent,
    };
    use tangle_test_support::{
        FixtureKey, InMemoryRepository, auth_event_spec, build_fixture_event, deletion_event_spec,
        fixture_spec_from_json, projection_ineligible_listing_spec, valid_public_listing_spec,
    };

    #[test]
    fn default_runtime_limits_expose_reference_aligned_boundaries() {
        let limits = RuntimeLimits::default();
        let values = limits.values();

        assert_eq!(limits.max_event_bytes(), 131_072);
        assert_eq!(limits.max_content_bytes(), 65_536);
        assert_eq!(limits.max_tags_per_event(), 128);
        assert_eq!(limits.max_tag_values_per_tag(), 16);
        assert_eq!(limits.max_tag_value_bytes(), 1_024);
        assert_eq!(limits.max_filters_per_subscription(), 16);
        assert_eq!(limits.max_subscriptions_per_connection(), 64);
        assert_eq!(limits.max_search_query_bytes(), 256);
        assert_eq!(limits.max_search_tokens(), 16);
        assert_eq!(limits.max_filter_complexity(), 512);
        assert_eq!(limits.max_future_seconds(), 900);
        assert_eq!(limits.live_event_buffer(), 1_024);
        assert_eq!(limits.pending_store_events(), 4_096);
        assert_eq!(values.max_event_bytes, 131_072);
    }

    #[test]
    fn runtime_limit_config_rejects_zero_and_inconsistent_values() {
        let zero_cases = [
            (
                "max_event_bytes",
                RuntimeLimitValues {
                    max_event_bytes: 0,
                    ..RuntimeLimitValues::default()
                },
            ),
            (
                "max_content_bytes",
                RuntimeLimitValues {
                    max_content_bytes: 0,
                    ..RuntimeLimitValues::default()
                },
            ),
            (
                "max_tags_per_event",
                RuntimeLimitValues {
                    max_tags_per_event: 0,
                    ..RuntimeLimitValues::default()
                },
            ),
            (
                "max_tag_values_per_tag",
                RuntimeLimitValues {
                    max_tag_values_per_tag: 0,
                    ..RuntimeLimitValues::default()
                },
            ),
            (
                "max_tag_value_bytes",
                RuntimeLimitValues {
                    max_tag_value_bytes: 0,
                    ..RuntimeLimitValues::default()
                },
            ),
            (
                "max_filters_per_subscription",
                RuntimeLimitValues {
                    max_filters_per_subscription: 0,
                    ..RuntimeLimitValues::default()
                },
            ),
            (
                "max_subscriptions_per_connection",
                RuntimeLimitValues {
                    max_subscriptions_per_connection: 0,
                    ..RuntimeLimitValues::default()
                },
            ),
            (
                "max_search_query_bytes",
                RuntimeLimitValues {
                    max_search_query_bytes: 0,
                    ..RuntimeLimitValues::default()
                },
            ),
            (
                "max_search_tokens",
                RuntimeLimitValues {
                    max_search_tokens: 0,
                    ..RuntimeLimitValues::default()
                },
            ),
            (
                "max_filter_complexity",
                RuntimeLimitValues {
                    max_filter_complexity: 0,
                    ..RuntimeLimitValues::default()
                },
            ),
            (
                "live_event_buffer",
                RuntimeLimitValues {
                    live_event_buffer: 0,
                    ..RuntimeLimitValues::default()
                },
            ),
            (
                "pending_store_events",
                RuntimeLimitValues {
                    pending_store_events: 0,
                    ..RuntimeLimitValues::default()
                },
            ),
        ];
        let inconsistent = RuntimeLimitValues {
            max_event_bytes: 10,
            max_content_bytes: 11,
            ..RuntimeLimitValues::default()
        };

        for (field, values) in zero_cases {
            assert_eq!(
                RuntimeLimits::from_values(values).expect_err(field),
                RuntimeLimitConfigError::Zero { field }
            );
        }
        assert_eq!(
            RuntimeLimits::from_values(zero_cases[0].1)
                .expect_err("zero")
                .to_string(),
            "`max_event_bytes` must be greater than zero"
        );
        assert_eq!(
            RuntimeLimits::from_values(inconsistent).expect_err("inconsistent"),
            RuntimeLimitConfigError::Inconsistent {
                field: "max_content_bytes",
                maximum_field: "max_event_bytes",
                value: 11,
                maximum: 10,
            }
        );
        assert_eq!(
            RuntimeLimits::from_values(inconsistent)
                .expect_err("inconsistent")
                .to_string(),
            "`max_content_bytes` must not exceed `max_event_bytes` (11 > 10)"
        );
    }

    #[test]
    fn runtime_limits_accept_fixture_event_inside_boundaries() {
        let event = build_fixture_event(&valid_public_listing_spec()).expect("event");

        assert_eq!(RuntimeLimits::default().validate_event(&event), Ok(()));
        assert_eq!(
            RuntimeLimits::default()
                .validate_event_timestamp(&event, UnixTimestamp::new(1_714_124_433)),
            Ok(())
        );
    }

    #[test]
    fn runtime_limits_reject_event_shape_boundaries() {
        assert_eq!(
            limits_with(|values| {
                values.max_event_bytes = 10;
                values.max_content_bytes = 10;
            })
            .validate_event(&event_with(vec![], "small", UnixTimestamp::new(10)))
            .expect_err("event bytes")
            .kind(),
            RuntimeLimitKind::EventBytes
        );
        assert_eq!(
            limits_with(|values| values.max_content_bytes = 3)
                .validate_event(&event_with(vec![], "large", UnixTimestamp::new(10)))
                .expect_err("content bytes")
                .kind(),
            RuntimeLimitKind::ContentBytes
        );
        assert_eq!(
            limits_with(|values| values.max_tags_per_event = 1)
                .validate_event(&event_with(
                    vec![
                        Tag::from_parts("d", &["one"]).expect("d"),
                        Tag::from_parts("t", &["two"]).expect("t"),
                    ],
                    "",
                    UnixTimestamp::new(10),
                ))
                .expect_err("tag count")
                .kind(),
            RuntimeLimitKind::TagsPerEvent
        );
        assert_eq!(
            limits_with(|values| values.max_tag_values_per_tag = 1)
                .validate_event(&event_with(
                    vec![Tag::from_parts("t", &["one"]).expect("t")],
                    "",
                    UnixTimestamp::new(10),
                ))
                .expect_err("tag values")
                .kind(),
            RuntimeLimitKind::TagValuesPerTag
        );
        assert_eq!(
            limits_with(|values| values.max_tag_value_bytes = 1)
                .validate_event(&event_with(
                    vec![Tag::from_parts("t", &["two"]).expect("t")],
                    "",
                    UnixTimestamp::new(10),
                ))
                .expect_err("tag value bytes")
                .kind(),
            RuntimeLimitKind::TagValueBytes
        );
    }

    #[test]
    fn runtime_limits_reject_filter_subscription_search_and_future_boundaries() {
        let limits = limits_with(|values| {
            values.max_filters_per_subscription = 2;
            values.max_filter_complexity = 3;
            values.max_subscriptions_per_connection = 4;
            values.max_search_query_bytes = 32;
            values.max_search_tokens = 2;
            values.max_future_seconds = 10;
        });

        assert_eq!(limits.validate_filters(2, 3), Ok(()));
        assert_eq!(
            limits.validate_filters(3, 3).expect_err("filters").kind(),
            RuntimeLimitKind::FiltersPerSubscription
        );
        assert_eq!(
            limits
                .validate_filters(2, 4)
                .expect_err("complexity")
                .kind(),
            RuntimeLimitKind::FilterComplexity
        );
        assert_eq!(limits.validate_subscription_count(4), Ok(()));
        assert_eq!(
            limits
                .validate_subscription_count(5)
                .expect_err("subscriptions")
                .kind(),
            RuntimeLimitKind::SubscriptionsPerConnection
        );
        assert_eq!(limits.validate_search_query("one two"), Ok(()));
        assert_eq!(
            limits
                .validate_search_query("123456789012345678901234567890123")
                .expect_err("search bytes")
                .kind(),
            RuntimeLimitKind::SearchQueryBytes
        );
        assert_eq!(
            limits
                .validate_search_query("a b c")
                .expect_err("search tokens")
                .kind(),
            RuntimeLimitKind::SearchTokens
        );
        assert_eq!(
            limits
                .validate_event_timestamp(
                    &event_with(vec![], "", UnixTimestamp::new(111)),
                    UnixTimestamp::new(100),
                )
                .expect_err("future")
                .kind(),
            RuntimeLimitKind::FutureSeconds
        );
        assert_eq!(
            limits.validate_event_timestamp(
                &event_with(vec![], "", UnixTimestamp::new(100)),
                UnixTimestamp::new(100),
            ),
            Ok(())
        );
    }

    #[test]
    fn runtime_limit_violation_reports_stable_values() {
        let violation = limits_with(|values| values.max_search_tokens = 1)
            .validate_search_query("one two")
            .expect_err("tokens");

        assert_eq!(violation.kind(), RuntimeLimitKind::SearchTokens);
        assert_eq!(violation.actual(), 2);
        assert_eq!(violation.maximum(), 1);
        assert_eq!(violation.to_string(), "search tokens exceeded: 2 > 1");
        assert_eq!(
            [
                RuntimeLimitKind::EventBytes.as_str(),
                RuntimeLimitKind::ContentBytes.as_str(),
                RuntimeLimitKind::TagsPerEvent.as_str(),
                RuntimeLimitKind::TagValuesPerTag.as_str(),
                RuntimeLimitKind::TagValueBytes.as_str(),
                RuntimeLimitKind::FiltersPerSubscription.as_str(),
                RuntimeLimitKind::SubscriptionsPerConnection.as_str(),
                RuntimeLimitKind::SearchQueryBytes.as_str(),
                RuntimeLimitKind::SearchTokens.as_str(),
                RuntimeLimitKind::FilterComplexity.as_str(),
                RuntimeLimitKind::FutureSeconds.as_str(),
            ],
            [
                "event bytes",
                "content bytes",
                "tags per event",
                "tag values per tag",
                "tag value bytes",
                "filters per subscription",
                "subscriptions per connection",
                "search query bytes",
                "search tokens",
                "filter complexity",
                "future seconds",
            ]
        );
        assert_eq!(
            RuntimeLimitKind::FutureSeconds.to_string(),
            "future seconds"
        );
    }

    #[test]
    fn admission_policy_defaults_require_matching_write_auth() {
        let author = pubkey("1");
        let other = pubkey("2");
        let event = AdmissionEvent::new(author.clone(), AdmissionEventKind::Write);
        let policy = AdmissionPolicy::new();

        assert!(policy.require_write_auth());
        assert_eq!(
            policy.unapproved_seller_action(),
            UnapprovedSellerAction::StoreRawOnly
        );
        assert!(policy.approved_sellers().is_empty());
        assert!(policy.blocked_pubkeys().is_empty());
        assert_eq!(
            policy
                .admit(&event, &AdmissionContext::unauthenticated())
                .rejection()
                .expect("unauthenticated")
                .kind(),
            AdmissionRejectionKind::AuthenticationRequired
        );
        assert_eq!(
            policy
                .admit(&event, &AdmissionContext::authenticated(other))
                .rejection()
                .expect("mismatch")
                .kind(),
            AdmissionRejectionKind::AuthenticatedPubkeyMismatch
        );
        assert_eq!(
            policy
                .admit(&event, &AdmissionContext::authenticated(author.clone()))
                .accepted()
                .expect("accepted")
                .effect(),
            AdmissionEffect::StoreRaw
        );
        assert_eq!(event.author_pubkey(), &author);
        assert_eq!(event.kind(), AdmissionEventKind::Write);
    }

    #[test]
    fn admission_policy_accepts_auth_events_without_prior_authentication() {
        let event = AdmissionEvent::new(pubkey("1"), AdmissionEventKind::RelayAuth);
        let decision = AdmissionPolicy::new().admit(&event, &AdmissionContext::unauthenticated());

        assert_eq!(
            decision.accepted().expect("accepted").effect(),
            AdmissionEffect::AuthenticateOnly
        );
        assert_eq!(
            decision
                .accepted()
                .expect("accepted")
                .projection_exclusion(),
            None
        );
        assert!(decision.rejection().is_none());
    }

    #[test]
    fn admission_policy_projects_public_listings_for_approved_sellers() {
        let seller = pubkey("3");
        let event = AdmissionEvent::new(seller.clone(), AdmissionEventKind::PublicListing);
        let policy = AdmissionPolicy::new().approve_seller(seller.clone());
        let decision = policy.admit(&event, &AdmissionContext::authenticated(seller.clone()));

        assert!(policy.is_seller_approved(&seller));
        assert_eq!(
            decision.accepted().expect("accepted").effect(),
            AdmissionEffect::StoreRawAndProjectPublicListing
        );
        assert_eq!(
            decision
                .accepted()
                .expect("accepted")
                .projection_exclusion(),
            None
        );
    }

    #[test]
    fn admission_policy_handles_unapproved_sellers_by_configured_action() {
        let seller = pubkey("4");
        let event = AdmissionEvent::new(seller.clone(), AdmissionEventKind::PublicListing);
        let context = AdmissionContext::authenticated(seller.clone());
        let raw_only = AdmissionPolicy::new().admit(&event, &context);
        let reject = AdmissionPolicy::new()
            .with_unapproved_seller_action(UnapprovedSellerAction::RejectWrite)
            .admit(&event, &context);

        assert_eq!(
            raw_only.accepted().expect("raw only").effect(),
            AdmissionEffect::StoreRawWithoutPublicListingProjection
        );
        assert_eq!(
            raw_only
                .accepted()
                .expect("raw only")
                .projection_exclusion(),
            Some(ProjectionExclusionReason::UnapprovedSeller)
        );
        assert_eq!(
            reject.rejection().expect("reject").kind(),
            AdmissionRejectionKind::UnapprovedSeller
        );
        assert!(reject.accepted().is_none());
        assert_eq!(
            reject.rejection().expect("reject").message(),
            "seller is not approved"
        );
    }

    #[test]
    fn admission_policy_applies_blocked_pubkey_policy() {
        let seller = pubkey("5");
        let write = AdmissionEvent::new(seller.clone(), AdmissionEventKind::Write);
        let listing = AdmissionEvent::new(seller.clone(), AdmissionEventKind::PublicListing);
        let context = AdmissionContext::authenticated(seller.clone());
        let policy = AdmissionPolicy::new()
            .approve_seller(seller.clone())
            .block_pubkey(seller.clone());

        assert!(policy.is_pubkey_blocked(&seller));
        assert_eq!(policy.blocked_pubkeys().len(), 1);
        assert_eq!(
            policy
                .admit(&write, &context)
                .rejection()
                .expect("blocked")
                .kind(),
            AdmissionRejectionKind::BlockedPubkey
        );
        assert_eq!(
            policy
                .admit(&listing, &context)
                .accepted()
                .expect("listing")
                .effect(),
            AdmissionEffect::StoreRawWithoutPublicListingProjection
        );
        assert_eq!(
            policy
                .admit(&listing, &context)
                .accepted()
                .expect("listing")
                .projection_exclusion(),
            Some(ProjectionExclusionReason::BlockedSeller)
        );
    }

    #[test]
    fn admission_policy_can_disable_write_auth_for_internal_tests() {
        let event = AdmissionEvent::new(pubkey("6"), AdmissionEventKind::DraftListing);
        let decision = AdmissionPolicy::new()
            .with_write_auth_required(false)
            .admit(&event, &AdmissionContext::unauthenticated());

        assert_eq!(
            decision.accepted().expect("accepted").effect(),
            AdmissionEffect::StoreRaw
        );
    }

    #[test]
    fn admission_policy_labels_and_rejections_are_stable() {
        let rejection = AdmissionPolicy::new()
            .admit(
                &AdmissionEvent::new(pubkey("7"), AdmissionEventKind::Write),
                &AdmissionContext::unauthenticated(),
            )
            .rejection()
            .expect("rejection")
            .clone();

        assert_eq!(
            [
                AdmissionEventKind::RelayAuth.as_str(),
                AdmissionEventKind::Write.as_str(),
                AdmissionEventKind::PublicListing.as_str(),
                AdmissionEventKind::DraftListing.as_str(),
            ],
            ["relay auth", "write", "public listing", "draft listing"]
        );
        assert_eq!(
            [
                UnapprovedSellerAction::StoreRawOnly.as_str(),
                UnapprovedSellerAction::RejectWrite.as_str(),
            ],
            ["store raw only", "reject write"]
        );
        assert_eq!(
            [
                AdmissionEffect::AuthenticateOnly.as_str(),
                AdmissionEffect::StoreRaw.as_str(),
                AdmissionEffect::StoreRawAndProjectPublicListing.as_str(),
                AdmissionEffect::StoreRawWithoutPublicListingProjection.as_str(),
            ],
            [
                "authenticate only",
                "store raw",
                "store raw and project public listing",
                "store raw without public listing projection",
            ]
        );
        assert_eq!(
            [
                ProjectionExclusionReason::UnapprovedSeller.as_str(),
                ProjectionExclusionReason::BlockedSeller.as_str(),
            ],
            ["unapproved seller", "blocked seller"]
        );
        assert_eq!(
            [
                AdmissionRejectionKind::AuthenticationRequired.as_str(),
                AdmissionRejectionKind::AuthenticatedPubkeyMismatch.as_str(),
                AdmissionRejectionKind::BlockedPubkey.as_str(),
                AdmissionRejectionKind::UnapprovedSeller.as_str(),
            ],
            [
                "authentication required",
                "authenticated pubkey mismatch",
                "blocked pubkey",
                "unapproved seller",
            ]
        );
        assert_eq!(AdmissionEventKind::Write.to_string(), "write");
        assert_eq!(
            UnapprovedSellerAction::RejectWrite.to_string(),
            "reject write"
        );
        assert_eq!(AdmissionEffect::StoreRaw.to_string(), "store raw");
        assert_eq!(
            ProjectionExclusionReason::BlockedSeller.to_string(),
            "blocked seller"
        );
        assert_eq!(
            AdmissionRejectionKind::BlockedPubkey.to_string(),
            "blocked pubkey"
        );
        assert_eq!(
            rejection.to_string(),
            "authentication required: write authentication required"
        );
    }

    #[test]
    fn event_validator_accepts_approved_public_listing_with_projection_payload() {
        let event = build_fixture_event(&valid_public_listing_spec()).expect("event");
        let seller = FixtureKey::Seller.public_key();
        let validator = EventValidator::new(
            RuntimeLimits::default(),
            AdmissionPolicy::new().approve_seller(seller.clone()),
        );
        let validated = validator
            .validate(
                &event,
                &AdmissionContext::authenticated(seller.clone()),
                UnixTimestamp::new(1_714_124_500),
            )
            .expect("validated");

        assert_eq!(validator.limits(), RuntimeLimits::default());
        assert!(validator.admission_policy().is_seller_approved(&seller));
        assert_eq!(validated.event_id(), event.id());
        assert_eq!(validated.author_pubkey(), &seller);
        assert_eq!(
            validated.admission_kind(),
            AdmissionEventKind::PublicListing
        );
        assert_eq!(
            validated.admission().effect(),
            AdmissionEffect::StoreRawAndProjectPublicListing
        );
        assert!(
            validated
                .payload()
                .listing_evaluation()
                .expect("listing")
                .is_eligible()
        );
        assert!(validated.payload().relay_auth().is_none());
        assert!(validated.payload().deletion_request().is_none());
    }

    #[test]
    fn event_validator_accepts_projection_ineligible_listing_as_raw_store_candidate() {
        let event = build_fixture_event(&projection_ineligible_listing_spec()).expect("event");
        let seller = FixtureKey::Seller.public_key();
        let validated = EventValidator::new(
            RuntimeLimits::default(),
            AdmissionPolicy::new().approve_seller(seller.clone()),
        )
        .validate(
            &event,
            &AdmissionContext::authenticated(seller),
            UnixTimestamp::new(1_714_124_500),
        )
        .expect("validated");
        let rejection = validated
            .payload()
            .listing_evaluation()
            .expect("listing")
            .rejection()
            .expect("projection rejection");

        assert_eq!(
            validated.admission_kind(),
            AdmissionEventKind::PublicListing
        );
        assert_eq!(rejection.reasons(), &["tag `title` is required".to_owned()]);
    }

    #[test]
    fn event_validator_accepts_auth_deletion_and_other_write_payloads() {
        let seller = FixtureKey::Seller.public_key();
        let auth = build_fixture_event(&auth_event_spec()).expect("auth");
        let deletion = build_fixture_event(&deletion_event_spec()).expect("deletion");
        let draft_listing = build_fixture_event(
            &fixture_spec_from_json(
                r#"{"name":"draft_listing","key":"seller","created_at":1714124438,"kind":30403,"tags":[["d","draft-carrots"],["title","Draft carrots"],["price","3.25","USD"],["unit","lb"],["fulfillment","pickup"]],"content":"Draft storage carrots."}"#,
            )
            .expect("draft listing"),
        )
        .expect("draft listing event");
        let note = build_fixture_event(
            &fixture_spec_from_json(
                r#"{"name":"note","key":"seller","created_at":1714124437,"kind":1,"tags":[],"content":"hello"}"#,
            )
            .expect("note"),
        )
        .expect("note event");
        let validator = EventValidator::default();
        let auth = validator
            .validate(
                &auth,
                &AdmissionContext::unauthenticated(),
                UnixTimestamp::new(1_714_124_500),
            )
            .expect("auth validated");
        let deletion = validator
            .validate(
                &deletion,
                &AdmissionContext::authenticated(seller.clone()),
                UnixTimestamp::new(1_714_124_500),
            )
            .expect("deletion validated");
        let draft_listing = validator
            .validate(
                &draft_listing,
                &AdmissionContext::authenticated(seller.clone()),
                UnixTimestamp::new(1_714_124_500),
            )
            .expect("draft listing validated");
        let note = validator
            .validate(
                &note,
                &AdmissionContext::authenticated(seller),
                UnixTimestamp::new(1_714_124_500),
            )
            .expect("note validated");

        assert_eq!(auth.admission_kind(), AdmissionEventKind::RelayAuth);
        assert_eq!(
            auth.payload().relay_auth().expect("auth").challenge(),
            "challenge-001"
        );
        assert!(auth.payload().listing_evaluation().is_none());
        assert_eq!(deletion.admission_kind(), AdmissionEventKind::Write);
        assert_eq!(
            deletion
                .payload()
                .deletion_request()
                .expect("deletion")
                .targets()
                .len(),
            1
        );
        assert_eq!(
            draft_listing.admission_kind(),
            AdmissionEventKind::DraftListing
        );
        assert_eq!(
            draft_listing.admission().effect(),
            AdmissionEffect::StoreRaw
        );
        assert!(
            draft_listing
                .payload()
                .listing_evaluation()
                .expect("draft listing")
                .rejection()
                .is_some()
        );
        assert_eq!(note.admission_kind(), AdmissionEventKind::Write);
        assert_eq!(note.payload(), &super::ValidatedEventPayload::Other);
    }

    #[test]
    fn event_validator_rejects_limits_crypto_parser_and_admission_failures() {
        let seller = FixtureKey::Seller.public_key();
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let bad_id = Event::new(
            EventId::new(&"f".repeat(EventId::HEX_LENGTH)).expect("id"),
            listing.unsigned().clone(),
            listing.sig().clone(),
        );
        let bad_auth = build_fixture_event(
            &fixture_spec_from_json(
                r#"{"name":"bad_auth","key":"seller","created_at":1714124435,"kind":22242,"tags":[["relay","wss://relay.radroots.test"]],"content":""}"#,
            )
            .expect("bad auth"),
        )
        .expect("bad auth event");
        let note = build_fixture_event(
            &fixture_spec_from_json(
                r#"{"name":"note","key":"seller","created_at":1714124437,"kind":1,"tags":[],"content":"hello"}"#,
            )
            .expect("note"),
        )
        .expect("note event");
        let limit_rejection = EventValidator::new(
            limits_with(|values| {
                values.max_event_bytes = 1;
                values.max_content_bytes = 1;
            }),
            AdmissionPolicy::new(),
        )
        .validate(
            &listing,
            &AdmissionContext::authenticated(seller.clone()),
            UnixTimestamp::new(1_714_124_500),
        )
        .expect_err("limit");
        let crypto_rejection = EventValidator::default()
            .validate(
                &bad_id,
                &AdmissionContext::authenticated(seller.clone()),
                UnixTimestamp::new(1_714_124_500),
            )
            .expect_err("crypto");
        let parser_rejection = EventValidator::default()
            .validate(
                &bad_auth,
                &AdmissionContext::unauthenticated(),
                UnixTimestamp::new(1_714_124_500),
            )
            .expect_err("parser");
        let admission_rejection = EventValidator::default()
            .validate(
                &note,
                &AdmissionContext::unauthenticated(),
                UnixTimestamp::new(1_714_124_500),
            )
            .expect_err("admission");

        assert_eq!(
            limit_rejection.kind(),
            EventValidationRejectionKind::RuntimeLimit
        );
        assert_eq!(
            crypto_rejection.kind(),
            EventValidationRejectionKind::Crypto
        );
        assert_eq!(
            parser_rejection.kind(),
            EventValidationRejectionKind::Parser
        );
        assert_eq!(
            admission_rejection.kind(),
            EventValidationRejectionKind::Admission
        );
        assert!(limit_rejection.to_string().starts_with("runtime limit:"));
        assert!(crypto_rejection.to_string().starts_with("crypto:"));
        assert_eq!(
            parser_rejection.to_string(),
            "parser: relay auth: tag `challenge` is required"
        );
        assert_eq!(
            admission_rejection.to_string(),
            "admission: authentication required: write authentication required"
        );
        let expected_parser = super::EventParserRejection::new(
            EventParser::RelayAuth,
            "tag `challenge` is required".to_owned(),
        );
        assert_eq!(expected_parser.parser(), EventParser::RelayAuth);
        assert_eq!(expected_parser.message(), "tag `challenge` is required");
        assert_eq!(
            parser_rejection,
            EventValidationRejection::Parser(expected_parser)
        );
    }

    #[test]
    fn event_validator_rejects_malformed_deletion_and_future_timestamp() {
        let seller = FixtureKey::Seller.public_key();
        let bad_deletion = build_fixture_event(
            &fixture_spec_from_json(
                r#"{"name":"bad_deletion","key":"seller","created_at":1714124436,"kind":5,"tags":[],"content":""}"#,
            )
            .expect("bad deletion"),
        )
        .expect("bad deletion event");
        let future_note = build_fixture_event(
            &fixture_spec_from_json(
                r#"{"name":"future_note","key":"seller","created_at":1714125400,"kind":1,"tags":[],"content":"hello"}"#,
            )
            .expect("future note"),
        )
        .expect("future note event");
        let deletion_rejection = EventValidator::default()
            .validate(
                &bad_deletion,
                &AdmissionContext::authenticated(seller.clone()),
                UnixTimestamp::new(1_714_124_500),
            )
            .expect_err("deletion");
        let future_rejection = EventValidator::default()
            .validate(
                &future_note,
                &AdmissionContext::authenticated(seller),
                UnixTimestamp::new(1_714_124_433),
            )
            .expect_err("future");

        assert_eq!(
            deletion_rejection.kind(),
            EventValidationRejectionKind::Parser
        );
        assert_eq!(
            deletion_rejection.to_string(),
            "parser: deletion: deletion event must target at least one e or a tag"
        );
        assert_eq!(
            future_rejection.kind(),
            EventValidationRejectionKind::RuntimeLimit
        );
        assert_eq!(EventParser::RelayAuth.as_str(), "relay auth");
        assert_eq!(EventParser::Deletion.to_string(), "deletion");
    }

    #[test]
    fn event_ingestor_keeps_auth_and_ephemeral_events_out_of_raw_storage() {
        let seller = FixtureKey::Seller.public_key();
        let auth = build_fixture_event(&auth_event_spec()).expect("auth");
        let ephemeral = build_fixture_event(
            &fixture_spec_from_json(
                r#"{"name":"ephemeral","key":"seller","created_at":1714124440,"kind":20000,"tags":[],"content":"typing"}"#,
            )
            .expect("ephemeral"),
        )
        .expect("ephemeral event");
        let mut repository = InMemoryRepository::new();
        let ingestor = EventIngestor::default();
        let auth = ingestor
            .ingest(
                &mut repository,
                auth,
                &AdmissionContext::unauthenticated(),
                UnixTimestamp::new(1_714_124_501),
                UnixTimestamp::new(1_714_124_501),
            )
            .expect("auth");
        let ephemeral = ingestor
            .ingest(
                &mut repository,
                ephemeral,
                &AdmissionContext::authenticated(seller),
                UnixTimestamp::new(1_714_124_502),
                UnixTimestamp::new(1_714_124_502),
            )
            .expect("ephemeral");

        assert_eq!(ingestor.validator().limits(), RuntimeLimits::default());
        assert_eq!(auth.effect(), EventIngestionEffect::Authenticated);
        assert_eq!(ephemeral.effect(), EventIngestionEffect::EphemeralAccepted);
        assert_eq!(auth.raw_event_outcome(), None);
        assert_eq!(ephemeral.raw_event_outcome(), None);
        assert_eq!(repository.events().expect("events"), Vec::new());
    }

    #[test]
    fn event_ingestor_stores_raw_events_and_projects_approved_listings() {
        let event = build_fixture_event(&valid_public_listing_spec()).expect("event");
        let seller = FixtureKey::Seller.public_key();
        let projection_address = AddressCoordinate::from_event(&event)
            .expect("address")
            .expect("address");
        let mut repository = InMemoryRepository::new();
        let ingestor = EventIngestor::new(EventValidator::new(
            RuntimeLimits::default(),
            AdmissionPolicy::new().approve_seller(seller.clone()),
        ));
        let ingestion = ingestor
            .ingest(
                &mut repository,
                event.clone(),
                &AdmissionContext::authenticated(seller),
                UnixTimestamp::new(1_714_124_501),
                UnixTimestamp::new(1_714_124_501),
            )
            .expect("ingestion");

        assert_eq!(ingestion.event_id(), event.id());
        assert_eq!(ingestion.effect(), EventIngestionEffect::Stored);
        assert_eq!(
            ingestion.raw_event_outcome(),
            Some(StoreEventOutcome::Inserted)
        );
        assert_eq!(
            ingestion.projection_outcome(),
            Some(StoreProjectionOutcome::Inserted)
        );
        assert_eq!(ingestion.deletion_marker_count(), 0);
        assert_eq!(
            repository
                .event_by_id(event.id())
                .expect("event")
                .expect("stored")
                .event(),
            &event
        );
        assert!(
            repository
                .listing_projection(&projection_address)
                .expect("projection")
                .is_some()
        );
    }

    #[test]
    fn event_ingestor_stores_projection_ineligible_listing_without_projection() {
        let event = build_fixture_event(&projection_ineligible_listing_spec()).expect("event");
        let seller = FixtureKey::Seller.public_key();
        let mut repository = InMemoryRepository::new();
        let ingestor = EventIngestor::new(EventValidator::new(
            RuntimeLimits::default(),
            AdmissionPolicy::new().approve_seller(seller.clone()),
        ));
        let ingestion = ingestor
            .ingest(
                &mut repository,
                event,
                &AdmissionContext::authenticated(seller),
                UnixTimestamp::new(1_714_124_501),
                UnixTimestamp::new(1_714_124_501),
            )
            .expect("ingestion");

        assert_eq!(ingestion.effect(), EventIngestionEffect::Stored);
        assert_eq!(
            ingestion.raw_event_outcome(),
            Some(StoreEventOutcome::Inserted)
        );
        assert_eq!(ingestion.projection_outcome(), None);
    }

    #[test]
    fn event_ingestor_creates_deletion_markers_after_raw_insert() {
        let event = build_fixture_event(&deletion_event_spec()).expect("deletion");
        let seller = FixtureKey::Seller.public_key();
        let mut repository = InMemoryRepository::new();
        let ingestion = EventIngestor::default()
            .ingest(
                &mut repository,
                event.clone(),
                &AdmissionContext::authenticated(seller.clone()),
                UnixTimestamp::new(1_714_124_501),
                UnixTimestamp::new(1_714_124_501),
            )
            .expect("ingestion");
        let markers = repository.deletion_markers().expect("markers");

        assert_eq!(ingestion.effect(), EventIngestionEffect::Stored);
        assert_eq!(ingestion.deletion_marker_count(), 1);
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].deletion_event_id(), event.id());
        assert_eq!(markers[0].author_pubkey(), &seller);
        assert_eq!(markers[0].deleted_at(), event.unsigned().created_at());
    }

    #[test]
    fn event_ingestor_skips_duplicate_side_effects() {
        let event = build_fixture_event(&valid_public_listing_spec()).expect("event");
        let seller = FixtureKey::Seller.public_key();
        let mut repository = InMemoryRepository::new();
        let ingestor = EventIngestor::new(EventValidator::new(
            RuntimeLimits::default(),
            AdmissionPolicy::new().approve_seller(seller.clone()),
        ));
        let first = ingestor
            .ingest(
                &mut repository,
                event.clone(),
                &AdmissionContext::authenticated(seller.clone()),
                UnixTimestamp::new(1_714_124_501),
                UnixTimestamp::new(1_714_124_501),
            )
            .expect("first");
        let duplicate = ingestor
            .ingest(
                &mut repository,
                event,
                &AdmissionContext::authenticated(seller),
                UnixTimestamp::new(1_714_124_502),
                UnixTimestamp::new(1_714_124_502),
            )
            .expect("duplicate");

        assert_eq!(
            first.projection_outcome(),
            Some(StoreProjectionOutcome::Inserted)
        );
        assert_eq!(duplicate.effect(), EventIngestionEffect::Duplicate);
        assert_eq!(
            duplicate.raw_event_outcome(),
            Some(StoreEventOutcome::Duplicate)
        );
        assert_eq!(duplicate.projection_outcome(), None);
    }

    #[test]
    fn event_ingestor_reports_validation_and_repository_rejections() {
        let seller = FixtureKey::Seller.public_key();
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let deletion = build_fixture_event(&deletion_event_spec()).expect("deletion");
        let note = build_fixture_event(
            &fixture_spec_from_json(
                r#"{"name":"note","key":"seller","created_at":1714124437,"kind":1,"tags":[],"content":"hello"}"#,
            )
            .expect("note"),
        )
        .expect("note event");
        let validation_rejection = EventIngestor::default()
            .ingest(
                &mut InMemoryRepository::new(),
                note.clone(),
                &AdmissionContext::unauthenticated(),
                UnixTimestamp::new(1_714_124_501),
                UnixTimestamp::new(1_714_124_501),
            )
            .expect_err("validation");
        let repository_rejection = EventIngestor::default()
            .ingest(
                &mut RawFailingRepository,
                note,
                &AdmissionContext::authenticated(seller),
                UnixTimestamp::new(1_714_124_501),
                UnixTimestamp::new(1_714_124_501),
            )
            .expect_err("repository");
        let projection_rejection = EventIngestor::new(EventValidator::new(
            RuntimeLimits::default(),
            AdmissionPolicy::new().approve_seller(FixtureKey::Seller.public_key()),
        ))
        .ingest(
            &mut ProjectionFailingRepository::new(),
            listing,
            &AdmissionContext::authenticated(FixtureKey::Seller.public_key()),
            UnixTimestamp::new(1_714_124_501),
            UnixTimestamp::new(1_714_124_501),
        )
        .expect_err("projection repository");
        let deletion_rejection = EventIngestor::default()
            .ingest(
                &mut DeletionFailingRepository::new(),
                deletion,
                &AdmissionContext::authenticated(FixtureKey::Seller.public_key()),
                UnixTimestamp::new(1_714_124_501),
                UnixTimestamp::new(1_714_124_501),
            )
            .expect_err("deletion repository");

        assert_eq!(
            validation_rejection.kind(),
            EventIngestionRejectionKind::Validation
        );
        assert_eq!(
            repository_rejection.kind(),
            EventIngestionRejectionKind::Repository
        );
        assert!(validation_rejection.to_string().starts_with("validation:"));
        assert_eq!(
            repository_rejection.to_string(),
            "repository: repository unavailable"
        );
        assert_eq!(
            projection_rejection.kind(),
            EventIngestionRejectionKind::Repository
        );
        assert_eq!(
            projection_rejection.to_string(),
            "repository: projection unavailable"
        );
        assert_eq!(
            deletion_rejection.kind(),
            EventIngestionRejectionKind::Repository
        );
        assert_eq!(
            deletion_rejection.to_string(),
            "repository: deletion unavailable"
        );
        assert_eq!(EventIngestionEffect::Stored.to_string(), "stored");
        assert_eq!(
            [
                EventIngestionEffect::Authenticated.as_str(),
                EventIngestionEffect::EphemeralAccepted.as_str(),
                EventIngestionEffect::Stored.as_str(),
                EventIngestionEffect::Duplicate.as_str(),
            ],
            ["authenticated", "ephemeral accepted", "stored", "duplicate",]
        );
    }

    #[test]
    fn failing_repository_helpers_cover_trait_surfaces() {
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let deletion = build_fixture_event(&deletion_event_spec()).expect("deletion");
        let projection = evaluate_listing_projection(&listing)
            .projection()
            .expect("projection")
            .clone();
        let address = projection.identity().address().clone();
        let deletion_request = parse_deletion_request(&deletion)
            .expect("deletion parse")
            .expect("deletion request");
        let marker = DeletionMarker::new(
            deletion.id().clone(),
            deletion.unsigned().pubkey().clone(),
            deletion_request.targets()[0].clone(),
            deletion.unsigned().created_at(),
        );
        let stored = StoredEvent::new(listing.clone(), UnixTimestamp::new(1_714_124_501));
        let mut raw = RawFailingRepository;

        assert!(raw.event_by_id(listing.id()).is_err());
        assert!(raw.events().is_err());
        assert!(raw.put_listing_projection(projection.clone()).is_err());
        assert!(raw.listing_projection(&address).is_err());
        assert!(raw.put_deletion_marker(marker.clone()).is_err());
        assert!(raw.deletion_markers().is_err());

        let mut projection_failing = ProjectionFailingRepository::new();
        assert_eq!(
            projection_failing.put_event(stored.clone()).expect("raw"),
            StoreEventOutcome::Inserted
        );
        assert_eq!(
            projection_failing
                .event_by_id(listing.id())
                .expect("event")
                .expect("stored")
                .event(),
            &listing
        );
        assert_eq!(projection_failing.events().expect("events").len(), 1);
        assert!(
            projection_failing
                .put_listing_projection(projection.clone())
                .is_err()
        );
        assert_eq!(
            projection_failing
                .listing_projection(&address)
                .expect("projection"),
            None
        );
        assert_eq!(
            projection_failing.put_deletion_marker(marker.clone()),
            Ok(())
        );
        assert_eq!(
            projection_failing.deletion_markers().expect("markers"),
            vec![marker.clone()]
        );

        let mut deletion_failing = DeletionFailingRepository::new();
        assert_eq!(
            deletion_failing.put_event(stored).expect("raw"),
            StoreEventOutcome::Inserted
        );
        assert_eq!(
            deletion_failing
                .put_listing_projection(projection.clone())
                .expect("projection"),
            StoreProjectionOutcome::Inserted
        );
        assert_eq!(
            deletion_failing
                .listing_projection(&address)
                .expect("projection"),
            Some(projection)
        );
        assert!(deletion_failing.put_deletion_marker(marker).is_err());
        assert_eq!(
            deletion_failing.deletion_markers().expect("markers"),
            Vec::new()
        );
        assert!(
            deletion_failing
                .event_by_id(listing.id())
                .expect("event")
                .is_some()
        );
        assert_eq!(deletion_failing.events().expect("events").len(), 1);
    }

    #[test]
    fn query_plan_model_accepts_multi_branch_historical_live_plans() {
        let search = QuerySearch::new(
            " carrots local ",
            vec![
                "local".to_owned(),
                "carrots".to_owned(),
                "carrots".to_owned(),
            ],
        )
        .expect("search");
        let tag_filter = QueryTagFilter::new(
            't',
            vec![
                "vegetables".to_owned(),
                "carrots".to_owned(),
                "vegetables".to_owned(),
            ],
        )
        .expect("tag");
        let branch = QueryPlanBranch::from_spec(QueryPlanBranchSpec {
            ids: vec![
                EventId::new(&"b".repeat(EventId::HEX_LENGTH)).expect("id"),
                EventId::new(&"a".repeat(EventId::HEX_LENGTH)).expect("id"),
                EventId::new(&"a".repeat(EventId::HEX_LENGTH)).expect("id"),
            ],
            authors: vec![pubkey("2"), pubkey("1"), pubkey("1")],
            kinds: vec![
                Kind::new(30_402).expect("kind"),
                Kind::new(1).expect("kind"),
                Kind::new(1).expect("kind"),
            ],
            tag_filters: vec![
                tag_filter.clone(),
                QueryTagFilter::new('t', vec!["local".to_owned()]).expect("tag"),
            ],
            since: Some(UnixTimestamp::new(10)),
            until: Some(UnixTimestamp::new(20)),
            limit: Some(50),
            search: Some(search.clone()),
        })
        .expect("branch");
        let second_branch =
            QueryPlanBranch::from_spec(QueryPlanBranchSpec::default()).expect("second branch");
        let plan = QueryPlan::new(
            QuerySource::RawEvents,
            QueryExecutionMode::HistoricalThenLive,
            QuerySort::CreatedAtDescEventIdAsc,
            vec![branch.clone(), second_branch],
        )
        .expect("plan");

        assert_eq!(search.raw(), "carrots local");
        assert_eq!(search.terms(), &["carrots".to_owned(), "local".to_owned()]);
        assert_eq!(tag_filter.name(), 't');
        assert_eq!(
            tag_filter.values(),
            &["carrots".to_owned(), "vegetables".to_owned()]
        );
        assert_eq!(plan.source(), QuerySource::RawEvents);
        assert_eq!(plan.mode(), QueryExecutionMode::HistoricalThenLive);
        assert_eq!(plan.sort(), QuerySort::CreatedAtDescEventIdAsc);
        assert_eq!(plan.branches().len(), 2);
        assert!(plan.requires_historical_query());
        assert!(plan.subscribes_to_live_events());
        assert_eq!(branch.ids()[0].as_str(), &"a".repeat(EventId::HEX_LENGTH));
        assert_eq!(branch.authors()[0], pubkey("1"));
        assert_eq!(branch.kinds()[0], Kind::new(1).expect("kind"));
        assert_eq!(
            branch.tag_filters().get(&'t').expect("tag values"),
            &[
                "carrots".to_owned(),
                "local".to_owned(),
                "vegetables".to_owned(),
            ]
        );
        assert_eq!(branch.since(), Some(UnixTimestamp::new(10)));
        assert_eq!(branch.until(), Some(UnixTimestamp::new(20)));
        assert_eq!(branch.limit(), Some(50));
        assert_eq!(branch.search(), Some(&search));
    }

    #[test]
    fn query_plan_model_distinguishes_historical_and_live_execution() {
        let zero_limit_branch = QueryPlanBranch::from_spec(QueryPlanBranchSpec {
            limit: Some(0),
            ..QueryPlanBranchSpec::default()
        })
        .expect("branch");
        let historical_then_live = QueryPlan::new(
            QuerySource::RawEvents,
            QueryExecutionMode::HistoricalThenLive,
            QuerySort::CreatedAtDescEventIdAsc,
            vec![zero_limit_branch.clone()],
        )
        .expect("historical then live");
        let live = QueryPlan::new(
            QuerySource::RawEvents,
            QueryExecutionMode::Live,
            QuerySort::CreatedAtDescEventIdAsc,
            vec![zero_limit_branch.clone()],
        )
        .expect("live");
        let historical = QueryPlan::new(
            QuerySource::ListingProjections,
            QueryExecutionMode::Historical,
            QuerySort::ScoreDescCreatedAtDescEventIdAsc,
            vec![zero_limit_branch],
        )
        .expect("historical");

        assert!(!historical_then_live.requires_historical_query());
        assert!(historical_then_live.subscribes_to_live_events());
        assert!(!live.requires_historical_query());
        assert!(live.subscribes_to_live_events());
        assert!(!historical.requires_historical_query());
        assert!(!historical.subscribes_to_live_events());
        assert_eq!(historical.source(), QuerySource::ListingProjections);
        assert_eq!(
            historical.sort(),
            QuerySort::ScoreDescCreatedAtDescEventIdAsc
        );
    }

    #[test]
    fn query_plan_model_rejects_invalid_shapes_and_has_stable_labels() {
        let empty_branches = QueryPlan::new(
            QuerySource::RawEvents,
            QueryExecutionMode::Historical,
            QuerySort::CreatedAtDescEventIdAsc,
            Vec::new(),
        )
        .expect_err("empty");
        let invalid_time = QueryPlanBranch::from_spec(QueryPlanBranchSpec {
            since: Some(UnixTimestamp::new(20)),
            until: Some(UnixTimestamp::new(10)),
            ..QueryPlanBranchSpec::default()
        })
        .expect_err("time");
        let invalid_tag = QueryTagFilter::new('1', vec!["value".to_owned()]).expect_err("tag");
        let empty_tag_values = QueryTagFilter::new('t', Vec::new()).expect_err("tag values");
        let empty_tag_value = QueryTagFilter::new('t', vec![String::new()]).expect_err("tag value");
        let empty_search = QuerySearch::new(" ", vec!["carrots".to_owned()]).expect_err("search");
        let empty_search_terms = QuerySearch::new("carrots", Vec::new()).expect_err("terms");
        let empty_search_term = QuerySearch::new("carrots", vec![String::new()]).expect_err("term");

        assert_eq!(empty_branches, QueryPlanError::EmptyBranches);
        assert_eq!(
            invalid_time,
            QueryPlanError::InvalidTimeRange {
                since: UnixTimestamp::new(20),
                until: UnixTimestamp::new(10),
            }
        );
        assert_eq!(invalid_tag, QueryPlanError::InvalidTagName { name: '1' });
        assert_eq!(
            empty_tag_values,
            QueryPlanError::EmptyTagValues { name: 't' }
        );
        assert_eq!(empty_tag_value, QueryPlanError::EmptyTagValue { name: 't' });
        assert_eq!(empty_search, QueryPlanError::EmptySearch);
        assert_eq!(empty_search_terms, QueryPlanError::EmptySearch);
        assert_eq!(empty_search_term, QueryPlanError::EmptySearch);
        assert_eq!(
            empty_branches.to_string(),
            "query plan must include at least one branch"
        );
        assert_eq!(
            invalid_time.to_string(),
            "query time range is invalid: since 20 > until 10"
        );
        assert_eq!(
            invalid_tag.to_string(),
            "tag filter name must be ASCII alphabetic, got `1`"
        );
        assert_eq!(
            empty_tag_values.to_string(),
            "tag filter `t` must include at least one value"
        );
        assert_eq!(
            empty_tag_value.to_string(),
            "tag filter `t` values must not be empty"
        );
        assert_eq!(empty_search.to_string(), "search query must include terms");
        assert_eq!(
            [
                QuerySource::RawEvents.as_str(),
                QuerySource::ListingProjections.as_str(),
                QuerySource::SearchDocuments.as_str(),
            ],
            ["raw events", "listing projections", "search documents"]
        );
        assert_eq!(
            [
                QueryExecutionMode::Historical.as_str(),
                QueryExecutionMode::Live.as_str(),
                QueryExecutionMode::HistoricalThenLive.as_str(),
            ],
            ["historical", "live", "historical then live"]
        );
        assert_eq!(
            [
                QuerySort::CreatedAtDescEventIdAsc.as_str(),
                QuerySort::ScoreDescCreatedAtDescEventIdAsc.as_str(),
            ],
            [
                "created_at desc event_id asc",
                "score desc created_at desc event_id asc",
            ]
        );
        assert_eq!(QuerySource::SearchDocuments.to_string(), "search documents");
        assert_eq!(QueryExecutionMode::Live.to_string(), "live");
        assert_eq!(
            QuerySort::ScoreDescCreatedAtDescEventIdAsc.to_string(),
            "score desc created_at desc event_id asc"
        );
    }

    #[test]
    fn nostr_filter_compiler_builds_search_backed_query_plans() {
        let filter = filter_from_value(&serde_json::json!({
            "ids": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
            "authors": ["1111111111111111111111111111111111111111111111111111111111111111"],
            "kinds": [1, 30402],
            "#t": ["vegetables", "carrots", "vegetables"],
            "since": 10,
            "until": 20,
            "limit": 25,
            "search": "fresh carrots"
        }))
        .expect("filter");
        let compiler = NostrFilterCompiler::default();
        let plan = compiler
            .compile(&[filter], QueryExecutionMode::HistoricalThenLive)
            .expect("plan");
        let branch = &plan.branches()[0];

        assert_eq!(compiler.limits(), RuntimeLimits::default());
        assert_eq!(plan.source(), QuerySource::SearchDocuments);
        assert_eq!(plan.sort(), QuerySort::ScoreDescCreatedAtDescEventIdAsc);
        assert_eq!(plan.mode(), QueryExecutionMode::HistoricalThenLive);
        assert!(plan.requires_historical_query());
        assert!(plan.subscribes_to_live_events());
        assert_eq!(branch.ids()[0].as_str(), &"b".repeat(EventId::HEX_LENGTH));
        assert_eq!(branch.authors()[0], pubkey("1"));
        assert_eq!(
            branch.kinds(),
            &[
                Kind::new(1).expect("kind"),
                Kind::new(30_402).expect("kind")
            ]
        );
        assert_eq!(
            branch.tag_filters().get(&'t').expect("tag"),
            &["carrots".to_owned(), "vegetables".to_owned()]
        );
        assert_eq!(branch.since(), Some(UnixTimestamp::new(10)));
        assert_eq!(branch.until(), Some(UnixTimestamp::new(20)));
        assert_eq!(branch.limit(), Some(25));
        assert_eq!(
            branch.search().expect("search").terms(),
            &["carrots".to_owned(), "fresh".to_owned()]
        );
    }

    #[test]
    fn nostr_filter_compiler_preserves_limit_zero_historical_skip() {
        let filter = filter_from_value(&serde_json::json!({
            "limit": 0,
            "#p": ["1111111111111111111111111111111111111111111111111111111111111111"]
        }))
        .expect("filter");
        let plan = NostrFilterCompiler::default()
            .compile(&[filter], QueryExecutionMode::HistoricalThenLive)
            .expect("plan");

        assert_eq!(plan.source(), QuerySource::RawEvents);
        assert_eq!(plan.sort(), QuerySort::CreatedAtDescEventIdAsc);
        assert!(!plan.requires_historical_query());
        assert!(plan.subscribes_to_live_events());
        assert_eq!(
            plan.branches()[0].tag_filters().get(&'p').expect("p"),
            &["1111111111111111111111111111111111111111111111111111111111111111".to_owned()]
        );
    }

    #[test]
    fn nostr_filter_compiler_rejects_limit_and_plan_errors() {
        let empty_filters = NostrFilterCompiler::default()
            .compile(&[], QueryExecutionMode::Historical)
            .expect_err("empty filters");
        let too_many_filters = NostrFilterCompiler::new(limits_with(|values| {
            values.max_filters_per_subscription = 1;
        }))
        .compile(
            &[
                tangle_protocol::Filter::empty(),
                tangle_protocol::Filter::empty(),
            ],
            QueryExecutionMode::Historical,
        )
        .expect_err("filter count");
        let too_complex = NostrFilterCompiler::new(limits_with(|values| {
            values.max_filter_complexity = 1;
        }))
        .compile(
            &[filter_from_value(&serde_json::json!({
                "ids": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                "authors": ["1111111111111111111111111111111111111111111111111111111111111111"]
            }))
            .expect("filter")],
            QueryExecutionMode::Historical,
        )
        .expect_err("complexity");
        let blank_search = NostrFilterCompiler::default()
            .compile(
                &[filter_from_value(&serde_json::json!({ "search": " " })).expect("filter")],
                QueryExecutionMode::Historical,
            )
            .expect_err("blank search");
        let empty_tag = NostrFilterCompiler::default()
            .compile(
                &[filter_from_value(&serde_json::json!({ "#t": [""] })).expect("filter")],
                QueryExecutionMode::Historical,
            )
            .expect_err("empty tag");

        assert_eq!(empty_filters.kind(), NostrFilterCompileErrorKind::QueryPlan);
        assert_eq!(
            too_many_filters.kind(),
            NostrFilterCompileErrorKind::RuntimeLimit
        );
        assert_eq!(
            too_complex.kind(),
            NostrFilterCompileErrorKind::RuntimeLimit
        );
        assert_eq!(blank_search.kind(), NostrFilterCompileErrorKind::QueryPlan);
        assert_eq!(empty_tag.kind(), NostrFilterCompileErrorKind::QueryPlan);
        assert_eq!(
            empty_filters.to_string(),
            "query plan: query plan must include at least one branch"
        );
        assert!(too_many_filters.to_string().starts_with("runtime limit:"));
        assert!(too_complex.to_string().starts_with("runtime limit:"));
        assert_eq!(
            blank_search.to_string(),
            "query plan: search query must include terms"
        );
        assert_eq!(
            empty_tag.to_string(),
            "query plan: tag filter `t` values must not be empty"
        );
    }

    #[test]
    fn nip50_query_compiler_builds_search_document_plan_from_plain_terms() {
        let filter = filter_from_value(&serde_json::json!({
            "authors": ["1111111111111111111111111111111111111111111111111111111111111111"],
            "kinds": [30402],
            "#t": ["carrots", "vegetables"],
            "since": 10,
            "until": 20,
            "limit": 10,
            "search": "fresh seller:ignored carrots status:ignored carrots"
        }))
        .expect("filter");
        let compiler = Nip50QueryCompiler::default();
        let plan = compiler
            .compile(&[filter], QueryExecutionMode::Historical)
            .expect("plan");
        let branch = &plan.branches()[0];

        assert_eq!(compiler.limits(), RuntimeLimits::default());
        assert_eq!(plan.source(), QuerySource::SearchDocuments);
        assert_eq!(plan.sort(), QuerySort::ScoreDescCreatedAtDescEventIdAsc);
        assert_eq!(plan.mode(), QueryExecutionMode::Historical);
        assert!(plan.requires_historical_query());
        assert!(!plan.subscribes_to_live_events());
        assert_eq!(branch.authors()[0], pubkey("1"));
        assert_eq!(branch.kinds(), &[Kind::new(30_402).expect("kind")]);
        assert_eq!(
            branch.tag_filters().get(&'t').expect("tag"),
            &["carrots".to_owned(), "vegetables".to_owned()]
        );
        assert_eq!(branch.since(), Some(UnixTimestamp::new(10)));
        assert_eq!(branch.until(), Some(UnixTimestamp::new(20)));
        assert_eq!(branch.limit(), Some(10));
        assert_eq!(
            branch.search().expect("search").raw(),
            "fresh carrots carrots"
        );
        assert_eq!(
            branch.search().expect("search").terms(),
            &["carrots".to_owned(), "fresh".to_owned()]
        );
    }

    #[test]
    fn nip50_query_compiler_ignores_extension_only_filters() {
        let extension_only = filter_from_value(&serde_json::json!({
            "search": "seller:ignored status:ignored",
            "limit": 0
        }))
        .expect("extension");
        let searchable = filter_from_value(&serde_json::json!({
            "search": "greens",
            "kinds": [1]
        }))
        .expect("search");
        let plan = Nip50QueryCompiler::default()
            .compile(
                &[extension_only, tangle_protocol::Filter::empty(), searchable],
                QueryExecutionMode::HistoricalThenLive,
            )
            .expect("plan");

        assert_eq!(plan.branches().len(), 1);
        assert_eq!(plan.branches()[0].search().expect("search").raw(), "greens");
        assert_eq!(plan.branches()[0].kinds(), &[Kind::new(1).expect("kind")]);
        assert!(plan.requires_historical_query());
        assert!(plan.subscribes_to_live_events());
    }

    #[test]
    fn nip50_query_compiler_rejects_missing_terms_limits_and_bad_plans() {
        let empty = Nip50QueryCompiler::default()
            .compile(&[], QueryExecutionMode::Historical)
            .expect_err("empty");
        let extension_only = Nip50QueryCompiler::default()
            .compile(
                &[filter_from_value(&serde_json::json!({
                    "search": "seller:ignored status:ignored"
                }))
                .expect("filter")],
                QueryExecutionMode::Historical,
            )
            .expect_err("extension only");
        let too_many_filters = Nip50QueryCompiler::new(limits_with(|values| {
            values.max_filters_per_subscription = 1;
        }))
        .compile(
            &[
                filter_from_value(&serde_json::json!({ "search": "carrots" })).expect("filter"),
                filter_from_value(&serde_json::json!({ "search": "greens" })).expect("filter"),
            ],
            QueryExecutionMode::Historical,
        )
        .expect_err("filter count");
        let too_many_tokens = Nip50QueryCompiler::new(limits_with(|values| {
            values.max_search_tokens = 1;
        }))
        .compile(
            &[
                filter_from_value(&serde_json::json!({ "search": "fresh carrots" }))
                    .expect("filter"),
            ],
            QueryExecutionMode::Historical,
        )
        .expect_err("tokens");
        let bad_plan = Nip50QueryCompiler::default()
            .compile(
                &[filter_from_value(&serde_json::json!({
                    "search": "carrots",
                    "since": 20,
                    "until": 10
                }))
                .expect("filter")],
                QueryExecutionMode::Historical,
            )
            .expect_err("plan");
        let empty_tag = Nip50QueryCompiler::default()
            .compile(
                &[filter_from_value(&serde_json::json!({
                    "search": "carrots",
                    "#t": [""]
                }))
                .expect("filter")],
                QueryExecutionMode::Historical,
            )
            .expect_err("tag");

        assert_eq!(empty.kind(), Nip50QueryCompileErrorKind::MissingSearchTerms);
        assert_eq!(
            extension_only.kind(),
            Nip50QueryCompileErrorKind::MissingSearchTerms
        );
        assert_eq!(
            too_many_filters.kind(),
            Nip50QueryCompileErrorKind::RuntimeLimit
        );
        assert_eq!(
            too_many_tokens.kind(),
            Nip50QueryCompileErrorKind::RuntimeLimit
        );
        assert_eq!(bad_plan.kind(), Nip50QueryCompileErrorKind::QueryPlan);
        assert_eq!(empty_tag.kind(), Nip50QueryCompileErrorKind::QueryPlan);
        assert_eq!(
            empty.to_string(),
            "nip50 query must include plain search terms"
        );
        assert!(
            too_many_filters
                .to_string()
                .contains("filters per subscription")
        );
        assert!(too_many_tokens.to_string().contains("search tokens"));
        assert_eq!(
            bad_plan.to_string(),
            "query plan: query time range is invalid: since 20 > until 10"
        );
        assert_eq!(
            empty_tag.to_string(),
            "query plan: tag filter `t` values must not be empty"
        );
    }

    fn limits_with(update: impl FnOnce(&mut RuntimeLimitValues)) -> RuntimeLimits {
        let mut values = RuntimeLimitValues::default();
        update(&mut values);
        RuntimeLimits::from_values(values).expect("limits")
    }

    fn event_with(tags: Vec<Tag>, content: &str, created_at: UnixTimestamp) -> Event {
        Event::new(
            EventId::new(&"a".repeat(EventId::HEX_LENGTH)).expect("id"),
            UnsignedEvent::new(
                PublicKeyHex::new(&"1".repeat(PublicKeyHex::HEX_LENGTH)).expect("pubkey"),
                created_at,
                Kind::new(30_402).expect("kind"),
                tags,
                content,
            ),
            SignatureHex::new(&"b".repeat(SignatureHex::HEX_LENGTH)).expect("sig"),
        )
    }

    struct RawFailingRepository;

    impl RawEventRepository for RawFailingRepository {
        fn put_event(
            &mut self,
            _record: StoredEvent,
        ) -> Result<StoreEventOutcome, RepositoryError> {
            Err(RepositoryError::new("repository unavailable"))
        }

        fn event_by_id(&self, _event_id: &EventId) -> Result<Option<StoredEvent>, RepositoryError> {
            Err(RepositoryError::new("repository unavailable"))
        }

        fn events(&self) -> Result<Vec<StoredEvent>, RepositoryError> {
            Err(RepositoryError::new("repository unavailable"))
        }
    }

    impl ListingProjectionRepository for RawFailingRepository {
        fn put_listing_projection(
            &mut self,
            _projection: ListingProjection,
        ) -> Result<StoreProjectionOutcome, RepositoryError> {
            Err(RepositoryError::new("repository unavailable"))
        }

        fn listing_projection(
            &self,
            _address: &AddressCoordinate,
        ) -> Result<Option<ListingProjection>, RepositoryError> {
            Err(RepositoryError::new("repository unavailable"))
        }
    }

    impl DeletionMarkerRepository for RawFailingRepository {
        fn put_deletion_marker(&mut self, _marker: DeletionMarker) -> Result<(), RepositoryError> {
            Err(RepositoryError::new("repository unavailable"))
        }

        fn deletion_markers(&self) -> Result<Vec<DeletionMarker>, RepositoryError> {
            Err(RepositoryError::new("repository unavailable"))
        }
    }

    struct ProjectionFailingRepository {
        inner: InMemoryRepository,
    }

    impl ProjectionFailingRepository {
        fn new() -> Self {
            Self {
                inner: InMemoryRepository::new(),
            }
        }
    }

    impl RawEventRepository for ProjectionFailingRepository {
        fn put_event(&mut self, record: StoredEvent) -> Result<StoreEventOutcome, RepositoryError> {
            self.inner.put_event(record)
        }

        fn event_by_id(&self, event_id: &EventId) -> Result<Option<StoredEvent>, RepositoryError> {
            self.inner.event_by_id(event_id)
        }

        fn events(&self) -> Result<Vec<StoredEvent>, RepositoryError> {
            self.inner.events()
        }
    }

    impl ListingProjectionRepository for ProjectionFailingRepository {
        fn put_listing_projection(
            &mut self,
            _projection: ListingProjection,
        ) -> Result<StoreProjectionOutcome, RepositoryError> {
            Err(RepositoryError::new("projection unavailable"))
        }

        fn listing_projection(
            &self,
            address: &AddressCoordinate,
        ) -> Result<Option<ListingProjection>, RepositoryError> {
            self.inner.listing_projection(address)
        }
    }

    impl DeletionMarkerRepository for ProjectionFailingRepository {
        fn put_deletion_marker(&mut self, marker: DeletionMarker) -> Result<(), RepositoryError> {
            self.inner.put_deletion_marker(marker)
        }

        fn deletion_markers(&self) -> Result<Vec<DeletionMarker>, RepositoryError> {
            self.inner.deletion_markers()
        }
    }

    struct DeletionFailingRepository {
        inner: InMemoryRepository,
    }

    impl DeletionFailingRepository {
        fn new() -> Self {
            Self {
                inner: InMemoryRepository::new(),
            }
        }
    }

    impl RawEventRepository for DeletionFailingRepository {
        fn put_event(&mut self, record: StoredEvent) -> Result<StoreEventOutcome, RepositoryError> {
            self.inner.put_event(record)
        }

        fn event_by_id(&self, event_id: &EventId) -> Result<Option<StoredEvent>, RepositoryError> {
            self.inner.event_by_id(event_id)
        }

        fn events(&self) -> Result<Vec<StoredEvent>, RepositoryError> {
            self.inner.events()
        }
    }

    impl ListingProjectionRepository for DeletionFailingRepository {
        fn put_listing_projection(
            &mut self,
            projection: ListingProjection,
        ) -> Result<StoreProjectionOutcome, RepositoryError> {
            self.inner.put_listing_projection(projection)
        }

        fn listing_projection(
            &self,
            address: &AddressCoordinate,
        ) -> Result<Option<ListingProjection>, RepositoryError> {
            self.inner.listing_projection(address)
        }
    }

    impl DeletionMarkerRepository for DeletionFailingRepository {
        fn put_deletion_marker(&mut self, _marker: DeletionMarker) -> Result<(), RepositoryError> {
            Err(RepositoryError::new("deletion unavailable"))
        }

        fn deletion_markers(&self) -> Result<Vec<DeletionMarker>, RepositoryError> {
            self.inner.deletion_markers()
        }
    }

    fn pubkey(hex: &str) -> PublicKeyHex {
        PublicKeyHex::new(&hex.repeat(PublicKeyHex::HEX_LENGTH)).expect("pubkey")
    }
}
