#![forbid(unsafe_code)]

use core::fmt;
use std::collections::BTreeSet;
use tangle_crypto::verify_event_signature;
use tangle_nips::{
    DeletionRequest, ListingProjectionEvaluation, RelayAuthEvent, evaluate_listing_projection,
    parse_deletion_request, parse_relay_auth_event,
};
use tangle_protocol::{Event, PublicKeyHex, UnixTimestamp, event_to_value};

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
    event_id: tangle_protocol::EventId,
    author_pubkey: PublicKeyHex,
    admission_kind: AdmissionEventKind,
    admission: AdmissionAcceptance,
    payload: ValidatedEventPayload,
}

impl ValidatedEvent {
    pub fn event_id(&self) -> &tangle_protocol::EventId {
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
        AdmissionRejectionKind, EventParser, EventValidationRejection,
        EventValidationRejectionKind, EventValidator, ProjectionExclusionReason,
        RuntimeLimitConfigError, RuntimeLimitKind, RuntimeLimitValues, RuntimeLimits,
        UnapprovedSellerAction,
    };
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
    };
    use tangle_test_support::{
        FixtureKey, auth_event_spec, build_fixture_event, deletion_event_spec,
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

    fn pubkey(hex: &str) -> PublicKeyHex {
        PublicKeyHex::new(&hex.repeat(PublicKeyHex::HEX_LENGTH)).expect("pubkey")
    }
}
