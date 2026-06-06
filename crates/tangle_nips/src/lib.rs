#![forbid(unsafe_code)]

use core::str::FromStr;
use tangle_protocol::{
    AddressCoordinate, DTag, Event, EventId, Filter, PublicKeyHex, TagName, UnixTimestamp,
};

pub const NIP99_PUBLIC_LISTING_KIND: u32 = 30_402;
pub const NIP99_DRAFT_LISTING_KIND: u32 = 30_403;
pub const NIP22_COMMENT_KIND: u32 = 1_111;
pub const NIP25_REACTION_KIND: u32 = 7;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTag {
    name: String,
    values: Vec<String>,
}

impl ParsedTag {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn values(&self) -> &[String] {
        &self.values
    }

    pub fn first_value(&self) -> Option<&str> {
        self.values.first().map(String::as_str)
    }
}

pub fn matching_tags(event: &Event, name: &str) -> Vec<ParsedTag> {
    event
        .unsigned()
        .tags()
        .iter()
        .filter(|tag| tag.name().as_str() == name)
        .map(|tag| ParsedTag {
            name: tag.name().to_string(),
            values: tag.values().iter().skip(1).cloned().collect(),
        })
        .collect()
}

pub fn tag_count(event: &Event, name: &str) -> usize {
    matching_tags(event, name).len()
}

pub fn optional_tag_value(event: &Event, name: &str) -> Result<Option<String>, String> {
    let tags = matching_tags(event, name);
    match tags.as_slice() {
        [] => Ok(None),
        [tag] => tag
            .first_value()
            .map(|value| Some(value.to_owned()))
            .ok_or_else(|| format!("tag `{name}` must include a value")),
        _ => Err(format!("tag `{name}` must not be repeated")),
    }
}

pub fn required_tag_value(event: &Event, name: &str) -> Result<String, String> {
    optional_tag_value(event, name)?.ok_or_else(|| format!("tag `{name}` is required"))
}

pub fn optional_tag_values(event: &Event, name: &str) -> Result<Option<Vec<String>>, String> {
    let tags = matching_tags(event, name);
    match tags.as_slice() {
        [] => Ok(None),
        [tag] => Ok(Some(tag.values().to_vec())),
        _ => Err(format!("tag `{name}` must not be repeated")),
    }
}

pub fn required_tag_values(event: &Event, name: &str) -> Result<Vec<String>, String> {
    optional_tag_values(event, name)?.ok_or_else(|| format!("tag `{name}` is required"))
}

pub fn parse_u64_field(field: &str, value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("field `{field}` must be an unsigned integer"))
}

pub fn parse_required_u64_tag(event: &Event, name: &str) -> Result<u64, String> {
    parse_u64_field(name, &required_tag_value(event, name)?)
}

pub fn repeated_or_missing_policy_boundary(
    event: &Event,
    name: &str,
) -> Result<Option<String>, String> {
    optional_tag_value(event, name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleLetterTagValue {
    name: String,
    value: String,
}

impl SingleLetterTagValue {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

pub fn single_letter_tag_values(event: &Event) -> Vec<SingleLetterTagValue> {
    event
        .unsigned()
        .tags()
        .iter()
        .filter_map(|tag| {
            tag.indexed_pair()
                .map(|(name, value)| SingleLetterTagValue {
                    name: name.to_owned(),
                    value: value.to_owned(),
                })
        })
        .collect()
}

pub fn single_letter_values_for(event: &Event, name: &str) -> Result<Vec<String>, String> {
    if !TagName::is_indexable_name(name) {
        return Err(format!(
            "single-letter tag name `{name}` must be one ASCII letter"
        ));
    }
    Ok(single_letter_tag_values(event)
        .into_iter()
        .filter(|tag| tag.name() == name)
        .map(|tag| tag.value)
        .collect())
}

pub fn first_single_letter_value(event: &Event, name: &str) -> Result<Option<String>, String> {
    Ok(single_letter_values_for(event, name)?.into_iter().next())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeletionTarget {
    Event(EventId),
    Address(AddressCoordinate),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletionRequest {
    event_id: EventId,
    targets: Vec<DeletionTarget>,
}

impl DeletionRequest {
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }

    pub fn targets(&self) -> &[DeletionTarget] {
        &self.targets
    }
}

pub fn parse_deletion_request(event: &Event) -> Result<Option<DeletionRequest>, String> {
    if event.unsigned().kind().as_u32() != 5 {
        return Ok(None);
    }
    let mut targets = single_letter_values_for(event, "e")?
        .into_iter()
        .map(|value| EventId::new(&value).map(DeletionTarget::Event))
        .collect::<Result<Vec<_>, _>>()?;
    let address_targets = single_letter_values_for(event, "a")?
        .into_iter()
        .map(|value| AddressCoordinate::from_str(&value).map(DeletionTarget::Address))
        .collect::<Result<Vec<_>, _>>()?;
    targets.extend(address_targets);
    if targets.is_empty() {
        return Err("deletion event must target at least one e or a tag".to_owned());
    }
    Ok(Some(DeletionRequest {
        event_id: event.id().clone(),
        targets,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAuthEvent {
    event_id: EventId,
    pubkey: PublicKeyHex,
    created_at: UnixTimestamp,
    relay: String,
    challenge: String,
}

impl RelayAuthEvent {
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }

    pub fn pubkey(&self) -> &PublicKeyHex {
        &self.pubkey
    }

    pub fn created_at(&self) -> UnixTimestamp {
        self.created_at
    }

    pub fn relay(&self) -> &str {
        &self.relay
    }

    pub fn challenge(&self) -> &str {
        &self.challenge
    }
}

pub fn parse_relay_auth_event(event: &Event) -> Result<Option<RelayAuthEvent>, String> {
    if event.unsigned().kind().as_u32() != 22_242 {
        return Ok(None);
    }
    let relay = required_tag_value(event, "relay")?;
    let challenge = required_tag_value(event, "challenge")?;
    if relay.is_empty() {
        return Err("relay auth relay tag must not be empty".to_owned());
    }
    if challenge.is_empty() {
        return Err("relay auth challenge tag must not be empty".to_owned());
    }
    Ok(Some(RelayAuthEvent {
        event_id: event.id().clone(),
        pubkey: event.unsigned().pubkey().clone(),
        created_at: event.unsigned().created_at(),
        relay,
        challenge,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nip50SearchQuery {
    text: String,
    terms: Vec<String>,
}

impl Nip50SearchQuery {
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn terms(&self) -> &[String] {
        &self.terms
    }
}

pub fn parse_nip50_search(search: &str) -> Result<Option<Nip50SearchQuery>, String> {
    let terms = search
        .split_whitespace()
        .filter(|term| !term.contains(':'))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if terms.is_empty() {
        return Ok(None);
    }
    Ok(Some(Nip50SearchQuery {
        text: terms.join(" "),
        terms,
    }))
}

pub fn parse_nip50_filter_search(filter: &Filter) -> Result<Option<Nip50SearchQuery>, String> {
    match filter.search() {
        Some(search) => parse_nip50_search(search),
        None => Ok(None),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommentTarget {
    Event {
        event_id: EventId,
        relay_hint: Option<String>,
        pubkey_hint: Option<PublicKeyHex>,
    },
    Address {
        address: AddressCoordinate,
        relay_hint: Option<String>,
    },
    External {
        identity: String,
        relay_hint: Option<String>,
    },
}

impl CommentTarget {
    pub fn target_type(&self) -> &'static str {
        match self {
            Self::Event { .. } => "event",
            Self::Address { .. } => "address",
            Self::External { .. } => "external",
        }
    }

    pub fn target_ref(&self) -> String {
        match self {
            Self::Event { event_id, .. } => event_id.as_str().to_owned(),
            Self::Address { address, .. } => address.key().to_string(),
            Self::External { identity, .. } => identity.clone(),
        }
    }

    pub fn relay_hint(&self) -> Option<&str> {
        match self {
            Self::Event { relay_hint, .. }
            | Self::Address { relay_hint, .. }
            | Self::External { relay_hint, .. } => relay_hint.as_deref(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentReference {
    target: CommentTarget,
    kind: String,
    author: Option<PublicKeyHex>,
}

impl CommentReference {
    pub fn target(&self) -> &CommentTarget {
        &self.target
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn author(&self) -> Option<&PublicKeyHex> {
        self.author.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentEvent {
    event_id: EventId,
    pubkey: PublicKeyHex,
    created_at: UnixTimestamp,
    content: String,
    root: CommentReference,
    parent: CommentReference,
    cited_events: Vec<String>,
    mentioned_pubkeys: Vec<PublicKeyHex>,
}

impl CommentEvent {
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }

    pub fn pubkey(&self) -> &PublicKeyHex {
        &self.pubkey
    }

    pub fn created_at(&self) -> UnixTimestamp {
        self.created_at
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    pub fn root(&self) -> &CommentReference {
        &self.root
    }

    pub fn parent(&self) -> &CommentReference {
        &self.parent
    }

    pub fn cited_events(&self) -> &[String] {
        &self.cited_events
    }

    pub fn mentioned_pubkeys(&self) -> &[PublicKeyHex] {
        &self.mentioned_pubkeys
    }
}

pub fn parse_comment_event(event: &Event) -> Result<Option<CommentEvent>, String> {
    if event.unsigned().kind().as_u32() != NIP22_COMMENT_KIND {
        return Ok(None);
    }
    let root_kind = required_tag_value(event, "K")?;
    let parent_kind = required_tag_value(event, "k")?;
    if root_kind.is_empty() {
        return Err("comment root kind tag must not be empty".to_owned());
    }
    if parent_kind.is_empty() {
        return Err("comment parent kind tag must not be empty".to_owned());
    }
    if root_kind == "1" || parent_kind == "1" {
        return Err("NIP-22 comments must not reply to kind 1 notes".to_owned());
    }
    Ok(Some(CommentEvent {
        event_id: event.id().clone(),
        pubkey: event.unsigned().pubkey().clone(),
        created_at: event.unsigned().created_at(),
        content: event.unsigned().content().to_owned(),
        root: CommentReference {
            target: parse_scoped_comment_target(event, &["A", "E", "I"], "root")?,
            kind: root_kind,
            author: optional_single_pubkey(event, "P", "root author")?,
        },
        parent: CommentReference {
            target: parse_scoped_comment_target(event, &["a", "e", "i"], "parent")?,
            kind: parent_kind,
            author: first_optional_pubkey(event, "p", "parent author")?,
        },
        cited_events: single_letter_values_for(event, "q")?,
        mentioned_pubkeys: parse_pubkey_values(event, "p", "mentioned pubkey")?,
    }))
}

fn parse_scoped_comment_target(
    event: &Event,
    names: &[&str],
    scope: &str,
) -> Result<CommentTarget, String> {
    let mut found = Vec::new();
    for name in names {
        for tag in matching_tags(event, name) {
            found.push((*name, tag));
        }
    }
    match found.len() {
        0 => Err(format!("comment {scope} target tag is required")),
        1 => {
            let (name, tag) = found.remove(0);
            parse_comment_target_tag(name, &tag, scope)
        }
        _ => Err(format!("comment {scope} target tag must not be repeated")),
    }
}

fn parse_comment_target_tag(
    name: &str,
    tag: &ParsedTag,
    scope: &str,
) -> Result<CommentTarget, String> {
    let values = tag.values();
    let target = values
        .first()
        .ok_or_else(|| format!("comment {scope} target tag `{name}` must include a value"))?;
    if target.is_empty() {
        return Err(format!(
            "comment {scope} target tag `{name}` must not be empty"
        ));
    }
    let relay_hint = normalized_optional_hint(values.get(1), scope, "relay")?;
    match name {
        "E" | "e" => {
            if values.len() > 3 {
                return Err(format!(
                    "comment {scope} event target tag `{name}` must include at most event relay and pubkey values"
                ));
            }
            let pubkey_hint = values
                .get(2)
                .map(|value| parse_pubkey_value(value, scope, "event pubkey hint"))
                .transpose()?;
            Ok(CommentTarget::Event {
                event_id: EventId::new(target)?,
                relay_hint,
                pubkey_hint,
            })
        }
        "A" | "a" => {
            if values.len() > 2 {
                return Err(format!(
                    "comment {scope} address target tag `{name}` must include at most address and relay values"
                ));
            }
            Ok(CommentTarget::Address {
                address: AddressCoordinate::from_str(target)?,
                relay_hint,
            })
        }
        "I" | "i" => {
            if values.len() > 2 {
                return Err(format!(
                    "comment {scope} external target tag `{name}` must include at most identity and relay values"
                ));
            }
            Ok(CommentTarget::External {
                identity: target.to_owned(),
                relay_hint,
            })
        }
        _ => Err(format!(
            "comment {scope} target tag `{name}` is unsupported"
        )),
    }
}

fn optional_single_pubkey(
    event: &Event,
    name: &str,
    description: &str,
) -> Result<Option<PublicKeyHex>, String> {
    let values = single_letter_values_for(event, name)?;
    match values.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some(parse_pubkey_value(value, description, "pubkey")?)),
        _ => Err(format!(
            "comment {description} tag `{name}` must not be repeated"
        )),
    }
}

fn first_optional_pubkey(
    event: &Event,
    name: &str,
    description: &str,
) -> Result<Option<PublicKeyHex>, String> {
    match single_letter_values_for(event, name)?.first() {
        Some(value) => Ok(Some(parse_pubkey_value(value, description, "pubkey")?)),
        None => Ok(None),
    }
}

fn parse_pubkey_values(
    event: &Event,
    name: &str,
    description: &str,
) -> Result<Vec<PublicKeyHex>, String> {
    single_letter_values_for(event, name)?
        .into_iter()
        .map(|value| parse_pubkey_value(&value, description, "pubkey"))
        .collect()
}

fn parse_pubkey_value(value: &str, description: &str, field: &str) -> Result<PublicKeyHex, String> {
    PublicKeyHex::new(value).map_err(|source| format!("{description} {field} is invalid: {source}"))
}

fn normalized_optional_hint(
    value: Option<&String>,
    scope: &str,
    field: &str,
) -> Result<Option<String>, String> {
    match value {
        Some(value) if value.is_empty() => Err(format!(
            "comment {scope} target {field} hint must not be empty"
        )),
        Some(value) => Ok(Some(value.clone())),
        None => Ok(None),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReactionValue {
    Like,
    Dislike,
    Emoji(String),
    Text(String),
}

impl ReactionValue {
    pub fn canonical(&self) -> &str {
        match self {
            Self::Like => "like",
            Self::Dislike => "dislike",
            Self::Emoji(_) => "emoji",
            Self::Text(_) => "text",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionEvent {
    event_id: EventId,
    pubkey: PublicKeyHex,
    created_at: UnixTimestamp,
    content: String,
    value: ReactionValue,
    target_event_id: EventId,
    target_relay_hint: Option<String>,
    target_pubkey_hint: Option<PublicKeyHex>,
    target_pubkey: Option<PublicKeyHex>,
    target_address: Option<AddressCoordinate>,
    target_kind: Option<String>,
}

impl ReactionEvent {
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }

    pub fn pubkey(&self) -> &PublicKeyHex {
        &self.pubkey
    }

    pub fn created_at(&self) -> UnixTimestamp {
        self.created_at
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    pub fn value(&self) -> &ReactionValue {
        &self.value
    }

    pub fn target_event_id(&self) -> &EventId {
        &self.target_event_id
    }

    pub fn target_relay_hint(&self) -> Option<&str> {
        self.target_relay_hint.as_deref()
    }

    pub fn target_pubkey_hint(&self) -> Option<&PublicKeyHex> {
        self.target_pubkey_hint.as_ref()
    }

    pub fn target_pubkey(&self) -> Option<&PublicKeyHex> {
        self.target_pubkey.as_ref()
    }

    pub fn target_address(&self) -> Option<&AddressCoordinate> {
        self.target_address.as_ref()
    }

    pub fn target_kind(&self) -> Option<&str> {
        self.target_kind.as_deref()
    }
}

pub fn parse_reaction_event(event: &Event) -> Result<Option<ReactionEvent>, String> {
    if event.unsigned().kind().as_u32() != NIP25_REACTION_KIND {
        return Ok(None);
    }
    let target = last_matching_tag(event, "e")
        .ok_or_else(|| "reaction event must include an e target tag".to_owned())?;
    let target_event_id = target
        .first_value()
        .ok_or_else(|| "reaction e target tag must include an event id".to_owned())
        .and_then(EventId::new)?;
    let target_relay_hint = normalized_optional_hint(target.values().get(1), "reaction", "relay")?;
    let target_pubkey_hint = target
        .values()
        .get(2)
        .map(|value| parse_pubkey_value(value, "reaction target hint", "pubkey"))
        .transpose()?;
    let target_pubkey = last_matching_tag(event, "p")
        .and_then(|tag| tag.first_value().map(str::to_owned))
        .map(|value| parse_pubkey_value(&value, "reaction target", "pubkey"))
        .transpose()?;
    let target_address = last_matching_tag(event, "a")
        .and_then(|tag| tag.first_value().map(str::to_owned))
        .map(|value| AddressCoordinate::from_str(&value))
        .transpose()?;
    let target_kind = optional_tag_value(event, "k")?;
    if target_kind.as_ref().is_some_and(String::is_empty) {
        return Err("reaction k tag must not be empty".to_owned());
    }
    Ok(Some(ReactionEvent {
        event_id: event.id().clone(),
        pubkey: event.unsigned().pubkey().clone(),
        created_at: event.unsigned().created_at(),
        content: event.unsigned().content().to_owned(),
        value: reaction_value(event.unsigned().content()),
        target_event_id,
        target_relay_hint,
        target_pubkey_hint,
        target_pubkey,
        target_address,
        target_kind,
    }))
}

fn reaction_value(content: &str) -> ReactionValue {
    match content {
        "" | "+" => ReactionValue::Like,
        "-" => ReactionValue::Dislike,
        value if looks_like_single_emoji(value) => ReactionValue::Emoji(value.to_owned()),
        value => ReactionValue::Text(value.to_owned()),
    }
}

fn looks_like_single_emoji(value: &str) -> bool {
    let mut chars = value.chars();
    match (chars.next(), chars.next()) {
        (Some(character), None) => !character.is_ascii() && !character.is_alphanumeric(),
        _ => false,
    }
}

fn last_matching_tag(event: &Event, name: &str) -> Option<ParsedTag> {
    matching_tags(event, name).into_iter().last()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListingKind {
    Public,
    Draft,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingIdentity {
    event_id: EventId,
    listing_kind: ListingKind,
    address: AddressCoordinate,
}

impl ListingIdentity {
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }

    pub fn listing_kind(&self) -> ListingKind {
        self.listing_kind
    }

    pub fn address(&self) -> &AddressCoordinate {
        &self.address
    }

    pub fn seller_pubkey(&self) -> &PublicKeyHex {
        self.address.pubkey()
    }

    pub fn d(&self) -> &DTag {
        self.address.d()
    }
}

pub fn parse_listing_identity(event: &Event) -> Result<Option<ListingIdentity>, String> {
    let Some(listing_kind) = listing_kind_for_event(event) else {
        return Ok(None);
    };
    let d = required_tag_value(event, "d")?;
    if d.is_empty() {
        return Err("listing d tag must not be empty".to_owned());
    }
    let address = AddressCoordinate::new(
        event.unsigned().kind(),
        event.unsigned().pubkey().clone(),
        DTag::new(&d),
    )
    .expect("listing kind must be addressable");
    Ok(Some(ListingIdentity {
        event_id: event.id().clone(),
        listing_kind,
        address,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingText {
    title: String,
    summary: Option<String>,
    body: String,
}

impl ListingText {
    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn summary(&self) -> Option<&str> {
        self.summary.as_deref()
    }

    pub fn body(&self) -> &str {
        &self.body
    }
}

pub fn parse_listing_text(event: &Event) -> Result<Option<ListingText>, String> {
    if listing_kind_for_event(event).is_none() {
        return Ok(None);
    }
    let title = required_tag_value(event, "title")?;
    if title.is_empty() {
        return Err("listing title tag must not be empty".to_owned());
    }
    let summary = optional_tag_value(event, "summary")?;
    if summary.as_ref().is_some_and(String::is_empty) {
        return Err("listing summary tag must not be empty".to_owned());
    }
    Ok(Some(ListingText {
        title,
        summary,
        body: event.unsigned().content().to_owned(),
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceAmount {
    raw: String,
}

impl PriceAmount {
    pub fn raw(&self) -> &str {
        &self.raw
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingPrice {
    amount: PriceAmount,
    currency: String,
    display_currency: String,
    frequency: Option<String>,
}

impl ListingPrice {
    pub fn amount(&self) -> &PriceAmount {
        &self.amount
    }

    pub fn currency(&self) -> &str {
        &self.currency
    }

    pub fn display_currency(&self) -> &str {
        &self.display_currency
    }

    pub fn frequency(&self) -> Option<&str> {
        self.frequency.as_deref()
    }
}

pub fn parse_listing_price(event: &Event) -> Result<Option<ListingPrice>, String> {
    if listing_kind_for_event(event).is_none() {
        return Ok(None);
    }
    let values = required_tag_values(event, "price")?;
    match values.len() {
        0 | 1 => Err("price tag must include amount and currency".to_owned()),
        2 | 3 => {
            let amount = parse_price_amount(&values[0])?;
            let currency = values[1].clone();
            if currency.is_empty() {
                return Err("price currency must not be empty".to_owned());
            }
            let frequency = values.get(2).cloned();
            if frequency.as_ref().is_some_and(String::is_empty) {
                return Err("price frequency must not be empty".to_owned());
            }
            Ok(Some(ListingPrice {
                amount,
                display_currency: currency.to_ascii_uppercase(),
                currency,
                frequency,
            }))
        }
        _ => Err("price tag must not include more than amount currency and frequency".to_owned()),
    }
}

fn parse_price_amount(value: &str) -> Result<PriceAmount, String> {
    if is_exact_unsigned_decimal(value) {
        return Ok(PriceAmount {
            raw: value.to_owned(),
        });
    }
    Err("price amount must be an exact unsigned decimal".to_owned())
}

fn is_exact_unsigned_decimal(value: &str) -> bool {
    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    match fraction {
        Some(value) => !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        None => true,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListingUnit {
    Lb,
    Oz,
    Each,
    Bunch,
    Dozen,
    Kg,
    G,
    Share,
    Pint,
    Quart,
    Box,
    Crate,
    Flat,
}

impl ListingUnit {
    pub fn canonical(self) -> &'static str {
        match self {
            Self::Lb => "lb",
            Self::Oz => "oz",
            Self::Each => "each",
            Self::Bunch => "bunch",
            Self::Dozen => "dozen",
            Self::Kg => "kg",
            Self::G => "g",
            Self::Share => "share",
            Self::Pint => "pint",
            Self::Quart => "quart",
            Self::Box => "box",
            Self::Crate => "crate",
            Self::Flat => "flat",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingUnitTag {
    raw: String,
    unit: ListingUnit,
}

impl ListingUnitTag {
    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn unit(&self) -> ListingUnit {
        self.unit
    }

    pub fn canonical(&self) -> &'static str {
        self.unit.canonical()
    }
}

pub fn parse_listing_unit(event: &Event) -> Result<Option<ListingUnitTag>, String> {
    if listing_kind_for_event(event).is_none() {
        return Ok(None);
    }
    let raw = required_tag_value(event, "unit")?;
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err("listing unit tag must not be empty".to_owned());
    }
    let unit = parse_unit_value(&normalized)
        .ok_or_else(|| format!("listing unit `{raw}` is unsupported"))?;
    Ok(Some(ListingUnitTag { raw, unit }))
}

fn parse_unit_value(value: &str) -> Option<ListingUnit> {
    match value {
        "lb" | "lbs" | "pound" | "pounds" => Some(ListingUnit::Lb),
        "oz" | "ounce" | "ounces" => Some(ListingUnit::Oz),
        "each" | "ea" => Some(ListingUnit::Each),
        "bunch" | "bunches" => Some(ListingUnit::Bunch),
        "dozen" => Some(ListingUnit::Dozen),
        "kg" | "kilogram" | "kilograms" => Some(ListingUnit::Kg),
        "g" | "gram" | "grams" => Some(ListingUnit::G),
        "share" | "shares" => Some(ListingUnit::Share),
        "pint" | "pints" => Some(ListingUnit::Pint),
        "quart" | "quarts" => Some(ListingUnit::Quart),
        "box" | "boxes" => Some(ListingUnit::Box),
        "crate" | "crates" => Some(ListingUnit::Crate),
        "flat" | "flats" => Some(ListingUnit::Flat),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FulfillmentMethod {
    Pickup,
    Delivery,
    Shipping,
}

impl FulfillmentMethod {
    pub fn canonical(self) -> &'static str {
        match self {
            Self::Pickup => "pickup",
            Self::Delivery => "delivery",
            Self::Shipping => "shipping",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingFulfillment {
    methods: Vec<FulfillmentMethod>,
}

impl ListingFulfillment {
    pub fn methods(&self) -> &[FulfillmentMethod] {
        &self.methods
    }

    pub fn pickup_available(&self) -> bool {
        self.methods.contains(&FulfillmentMethod::Pickup)
    }

    pub fn delivery_available(&self) -> bool {
        self.methods.contains(&FulfillmentMethod::Delivery)
    }

    pub fn shipping_available(&self) -> bool {
        self.methods.contains(&FulfillmentMethod::Shipping)
    }

    pub fn delivery_only(&self) -> bool {
        self.delivery_available() && !self.pickup_available() && !self.shipping_available()
    }
}

pub fn parse_listing_fulfillment(event: &Event) -> Result<Option<ListingFulfillment>, String> {
    if listing_kind_for_event(event).is_none() {
        return Ok(None);
    }
    let tags = matching_tags(event, "fulfillment");
    if tags.is_empty() {
        return Err("tag `fulfillment` is required".to_owned());
    }
    let mut methods = Vec::new();
    for tag in tags {
        let values = tag.values();
        let raw = values
            .first()
            .ok_or_else(|| "tag `fulfillment` must include a value".to_owned())?;
        if values.len() > 1 {
            return Err("fulfillment tag must include exactly one method".to_owned());
        }
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return Err("fulfillment tag method must not be empty".to_owned());
        }
        let method = parse_fulfillment_method(&normalized)
            .ok_or_else(|| format!("fulfillment method `{raw}` is unsupported"))?;
        if !methods.contains(&method) {
            methods.push(method);
        }
    }
    methods.sort_unstable();
    Ok(Some(ListingFulfillment { methods }))
}

fn parse_fulfillment_method(value: &str) -> Option<FulfillmentMethod> {
    match value {
        "pickup" => Some(FulfillmentMethod::Pickup),
        "delivery" => Some(FulfillmentMethod::Delivery),
        "shipping" => Some(FulfillmentMethod::Shipping),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListingEffectiveStatus {
    Active,
    Sold,
    Draft,
}

impl ListingEffectiveStatus {
    pub fn canonical(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Sold => "sold",
            Self::Draft => "draft",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingStatus {
    raw_status: Option<String>,
    effective_status: ListingEffectiveStatus,
}

impl ListingStatus {
    pub fn raw_status(&self) -> Option<&str> {
        self.raw_status.as_deref()
    }

    pub fn effective_status(&self) -> ListingEffectiveStatus {
        self.effective_status
    }
}

pub fn parse_listing_status(event: &Event) -> Result<Option<ListingStatus>, String> {
    let Some(listing_kind) = listing_kind_for_event(event) else {
        return Ok(None);
    };
    let raw_status = optional_tag_value(event, "status")?;
    let parsed_status = match raw_status.as_deref() {
        Some("") => return Err("listing status tag must not be empty".to_owned()),
        Some("active") => Some(ListingEffectiveStatus::Active),
        Some("sold") => Some(ListingEffectiveStatus::Sold),
        Some(value) => return Err(format!("listing status `{value}` is unsupported")),
        None => None,
    };
    let effective_status = match listing_kind {
        ListingKind::Draft => ListingEffectiveStatus::Draft,
        ListingKind::Public => parsed_status.unwrap_or(ListingEffectiveStatus::Active),
    };
    Ok(Some(ListingStatus {
        raw_status,
        effective_status,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingLocation {
    location_text: Option<String>,
    geohash: Option<String>,
    geohash4: Option<String>,
    geohash5: Option<String>,
    geohash6: Option<String>,
    geohash7: Option<String>,
}

impl ListingLocation {
    pub fn location_text(&self) -> Option<&str> {
        self.location_text.as_deref()
    }

    pub fn geohash(&self) -> Option<&str> {
        self.geohash.as_deref()
    }

    pub fn geohash4(&self) -> Option<&str> {
        self.geohash4.as_deref()
    }

    pub fn geohash5(&self) -> Option<&str> {
        self.geohash5.as_deref()
    }

    pub fn geohash6(&self) -> Option<&str> {
        self.geohash6.as_deref()
    }

    pub fn geohash7(&self) -> Option<&str> {
        self.geohash7.as_deref()
    }

    pub fn location_precision(&self) -> Option<usize> {
        self.geohash.as_ref().map(String::len)
    }
}

pub fn parse_listing_location(event: &Event) -> Result<Option<ListingLocation>, String> {
    if listing_kind_for_event(event).is_none() {
        return Ok(None);
    }
    let location_text = optional_tag_value(event, "location")?;
    if location_text.as_ref().is_some_and(String::is_empty) {
        return Err("listing location tag must not be empty".to_owned());
    }
    let geohash = optional_exact_tag_value(event, "g")?
        .map(|value| parse_geohash(&value))
        .transpose()?;
    Ok(Some(ListingLocation {
        location_text,
        geohash4: geohash_prefix(&geohash, 4),
        geohash5: geohash_prefix(&geohash, 5),
        geohash6: geohash_prefix(&geohash, 6),
        geohash7: geohash_prefix(&geohash, 7),
        geohash,
    }))
}

fn optional_exact_tag_value(event: &Event, name: &str) -> Result<Option<String>, String> {
    let tags = matching_tags(event, name);
    match tags.as_slice() {
        [] => Ok(None),
        [tag] => match tag.values() {
            [] => Err(format!("tag `{name}` must include a value")),
            [value] => Ok(Some(value.clone())),
            _ => Err(format!("tag `{name}` must include exactly one value")),
        },
        _ => Err(format!("tag `{name}` must not be repeated")),
    }
}

fn parse_geohash(value: &str) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() < 4
        || normalized.len() > 12
        || !normalized
            .bytes()
            .all(|byte| b"0123456789bcdefghjkmnpqrstuvwxyz".contains(&byte))
    {
        return Err("geohash must be 4 to 12 geohash characters".to_owned());
    }
    Ok(normalized)
}

fn geohash_prefix(geohash: &Option<String>, length: usize) -> Option<String> {
    geohash
        .as_ref()
        .filter(|value| value.len() >= length)
        .map(|value| value[..length].to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingTaxonomy {
    categories: Vec<String>,
    topics: Vec<String>,
    practices: Vec<String>,
    certifications: Vec<String>,
}

impl ListingTaxonomy {
    pub fn categories(&self) -> &[String] {
        &self.categories
    }

    pub fn topics(&self) -> &[String] {
        &self.topics
    }

    pub fn practices(&self) -> &[String] {
        &self.practices
    }

    pub fn certifications(&self) -> &[String] {
        &self.certifications
    }
}

pub fn parse_listing_taxonomy(event: &Event) -> Result<Option<ListingTaxonomy>, String> {
    if listing_kind_for_event(event).is_none() {
        return Ok(None);
    }
    Ok(Some(ListingTaxonomy {
        categories: collect_taxonomy_values(event, "category")?,
        topics: collect_taxonomy_values(event, "t")?,
        practices: collect_taxonomy_values(event, "practice")?,
        certifications: collect_taxonomy_values(event, "certification")?,
    }))
}

fn collect_taxonomy_values(event: &Event, name: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    for tag in matching_tags(event, name) {
        match tag.values() {
            [] => return Err(format!("tag `{name}` must include a value")),
            [value] => {
                let normalized = normalize_taxonomy_value(name, value)?;
                values.push(normalized);
            }
            _ => return Err(format!("tag `{name}` must include exactly one value")),
        }
    }
    values.sort();
    values.dedup();
    Ok(values)
}

fn normalize_taxonomy_value(name: &str, value: &str) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(format!("listing taxonomy `{name}` value must not be empty"));
    }
    Ok(normalized)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingProjection {
    identity: ListingIdentity,
    text: ListingText,
    price: ListingPrice,
    unit: ListingUnitTag,
    fulfillment: ListingFulfillment,
    status: ListingStatus,
    location: ListingLocation,
    taxonomy: ListingTaxonomy,
}

impl ListingProjection {
    pub fn identity(&self) -> &ListingIdentity {
        &self.identity
    }

    pub fn text(&self) -> &ListingText {
        &self.text
    }

    pub fn price(&self) -> &ListingPrice {
        &self.price
    }

    pub fn unit(&self) -> &ListingUnitTag {
        &self.unit
    }

    pub fn fulfillment(&self) -> &ListingFulfillment {
        &self.fulfillment
    }

    pub fn status(&self) -> &ListingStatus {
        &self.status
    }

    pub fn location(&self) -> &ListingLocation {
        &self.location
    }

    pub fn taxonomy(&self) -> &ListingTaxonomy {
        &self.taxonomy
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingProjectionRejection {
    event_id: EventId,
    reasons: Vec<String>,
}

impl ListingProjectionRejection {
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }

    pub fn reasons(&self) -> &[String] {
        &self.reasons
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListingProjectionEvaluation {
    NotListing,
    Eligible(Box<ListingProjection>),
    Ineligible(ListingProjectionRejection),
}

impl ListingProjectionEvaluation {
    pub fn is_eligible(&self) -> bool {
        matches!(self, Self::Eligible(_))
    }

    pub fn projection(&self) -> Option<&ListingProjection> {
        match self {
            Self::Eligible(projection) => Some(projection),
            Self::NotListing | Self::Ineligible(_) => None,
        }
    }

    pub fn rejection(&self) -> Option<&ListingProjectionRejection> {
        match self {
            Self::Ineligible(rejection) => Some(rejection),
            Self::NotListing | Self::Eligible(_) => None,
        }
    }
}

pub fn evaluate_listing_projection(event: &Event) -> ListingProjectionEvaluation {
    if listing_kind_for_event(event).is_none() {
        return ListingProjectionEvaluation::NotListing;
    }
    let mut reasons = Vec::new();
    let identity = parse_listing_identity(event)
        .map_err(|reason| reasons.push(reason))
        .ok()
        .flatten();
    let text = parse_listing_text(event)
        .map_err(|reason| reasons.push(reason))
        .ok()
        .flatten();
    let price = parse_listing_price(event)
        .map_err(|reason| reasons.push(reason))
        .ok()
        .flatten();
    let unit = parse_listing_unit(event)
        .map_err(|reason| reasons.push(reason))
        .ok()
        .flatten();
    let fulfillment = parse_listing_fulfillment(event)
        .map_err(|reason| reasons.push(reason))
        .ok()
        .flatten();
    let status = parse_listing_status(event)
        .map_err(|reason| reasons.push(reason))
        .ok()
        .flatten();
    let location = parse_listing_location(event)
        .map_err(|reason| reasons.push(reason))
        .ok()
        .flatten();
    let taxonomy = parse_listing_taxonomy(event)
        .map_err(|reason| reasons.push(reason))
        .ok()
        .flatten();
    if identity
        .as_ref()
        .is_some_and(|identity| identity.listing_kind() == ListingKind::Draft)
    {
        reasons.push("draft listing is not public projection eligible".to_owned());
    }
    match (
        identity,
        text,
        price,
        unit,
        fulfillment,
        status,
        location,
        taxonomy,
    ) {
        (
            Some(identity),
            Some(text),
            Some(price),
            Some(unit),
            Some(fulfillment),
            Some(status),
            Some(location),
            Some(taxonomy),
        ) if reasons.is_empty() => {
            ListingProjectionEvaluation::Eligible(Box::new(ListingProjection {
                identity,
                text,
                price,
                unit,
                fulfillment,
                status,
                location,
                taxonomy,
            }))
        }
        _ => ListingProjectionEvaluation::Ineligible(ListingProjectionRejection {
            event_id: event.id().clone(),
            reasons,
        }),
    }
}

fn listing_kind_for_event(event: &Event) -> Option<ListingKind> {
    match event.unsigned().kind().as_u32() {
        NIP99_PUBLIC_LISTING_KIND => Some(ListingKind::Public),
        NIP99_DRAFT_LISTING_KIND => Some(ListingKind::Draft),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CommentTarget, DeletionTarget, FulfillmentMethod, ListingEffectiveStatus, ListingKind,
        ListingProjectionEvaluation, ListingUnit, NIP22_COMMENT_KIND, NIP25_REACTION_KIND,
        NIP99_PUBLIC_LISTING_KIND, ReactionValue, evaluate_listing_projection, matching_tags,
        optional_tag_value, optional_tag_values, parse_comment_event, parse_deletion_request,
        parse_listing_fulfillment, parse_listing_identity, parse_listing_location,
        parse_listing_price, parse_listing_status, parse_listing_taxonomy, parse_listing_text,
        parse_listing_unit, parse_nip50_filter_search, parse_nip50_search, parse_reaction_event,
        parse_relay_auth_event, parse_required_u64_tag, parse_u64_field,
        repeated_or_missing_policy_boundary, required_tag_value, required_tag_values,
        single_letter_tag_values, single_letter_values_for, tag_count,
    };
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
        filter_from_value,
    };

    #[test]
    fn shared_parser_utilities_extract_matching_tags() {
        let event = event_with_tags(vec![
            Tag::from_parts("d", &["listing-a"]).expect("d"),
            Tag::from_parts("title", &["Carrots"]).expect("title"),
            Tag::from_parts("price", &["12.50", "USD"]).expect("price"),
        ]);
        let price = matching_tags(&event, "price");

        assert_eq!(tag_count(&event, "d"), 1);
        assert_eq!(tag_count(&event, "missing"), 0);
        assert_eq!(price[0].name(), "price");
        assert_eq!(price[0].first_value(), Some("12.50"));
        assert_eq!(price[0].values(), &["12.50".to_owned(), "USD".to_owned()]);
        assert_eq!(
            optional_tag_value(&event, "d"),
            Ok(Some("listing-a".to_owned()))
        );
        assert_eq!(optional_tag_value(&event, "missing"), Ok(None));
        assert_eq!(
            required_tag_value(&event, "title"),
            Ok("Carrots".to_owned())
        );
        assert_eq!(
            optional_tag_values(&event, "price"),
            Ok(Some(vec!["12.50".to_owned(), "USD".to_owned()]))
        );
        assert_eq!(
            required_tag_values(&event, "price"),
            Ok(vec!["12.50".to_owned(), "USD".to_owned()])
        );
    }

    #[test]
    fn shared_parser_utilities_reject_missing_repeated_and_malformed_values() {
        let repeated = event_with_tags(vec![
            Tag::from_parts("d", &["one"]).expect("d"),
            Tag::from_parts("d", &["two"]).expect("d"),
        ]);
        let missing_value = event_with_tags(vec![Tag::from_parts("d", &[]).expect("d")]);
        let missing = event_with_tags(Vec::new());

        assert_eq!(
            optional_tag_value(&repeated, "d").expect_err("repeated"),
            "tag `d` must not be repeated"
        );
        assert_eq!(
            optional_tag_values(&repeated, "d").expect_err("repeated values"),
            "tag `d` must not be repeated"
        );
        assert_eq!(
            optional_tag_value(&missing_value, "d").expect_err("value"),
            "tag `d` must include a value"
        );
        assert_eq!(
            required_tag_value(&missing, "d").expect_err("missing"),
            "tag `d` is required"
        );
        assert_eq!(
            required_tag_values(&missing, "d").expect_err("missing values"),
            "tag `d` is required"
        );
        assert_eq!(
            parse_u64_field("published_at", "now").expect_err("number"),
            "field `published_at` must be an unsigned integer"
        );
    }

    #[test]
    fn shared_parser_utilities_parse_numeric_tags_and_policy_boundaries() {
        let event = event_with_tags(vec![Tag::from_parts("published_at", &["42"]).expect("tag")]);
        let missing = event_with_tags(Vec::new());

        assert_eq!(parse_u64_field("published_at", "42"), Ok(42));
        assert_eq!(parse_required_u64_tag(&event, "published_at"), Ok(42));
        assert_eq!(repeated_or_missing_policy_boundary(&missing, "d"), Ok(None));
    }

    #[test]
    fn single_letter_tag_extraction_indexes_first_values_only() {
        let event = event_with_tags(vec![
            Tag::from_parts("e", &["root", "relay"]).expect("e"),
            Tag::from_parts("p", &["peer"]).expect("p"),
            Tag::from_parts("E", &["uppercase-root"]).expect("E"),
            Tag::from_parts("t", &["carrots"]).expect("t"),
            Tag::from_parts("alt", &["not indexed"]).expect("alt"),
            Tag::from_parts("1", &["not indexed"]).expect("number"),
            Tag::from_parts("g", &[]).expect("missing value"),
        ]);
        let values = single_letter_tag_values(&event);

        assert_eq!(values.len(), 4);
        assert_eq!(values[0].name(), "e");
        assert_eq!(values[0].value(), "root");
        assert_eq!(values[2].name(), "E");
        assert_eq!(
            single_letter_values_for(&event, "e"),
            Ok(vec!["root".to_owned()])
        );
        assert_eq!(
            single_letter_values_for(&event, "E"),
            Ok(vec!["uppercase-root".to_owned()])
        );
        assert_eq!(single_letter_values_for(&event, "g"), Ok(Vec::new()));
    }

    #[test]
    fn single_letter_tag_extraction_handles_repeated_missing_and_malformed_names() {
        let repeated = event_with_tags(vec![
            Tag::from_parts("t", &["carrots"]).expect("t"),
            Tag::from_parts("t", &["greens"]).expect("t"),
        ]);
        let missing = event_with_tags(Vec::new());

        assert_eq!(
            single_letter_values_for(&repeated, "t"),
            Ok(vec!["carrots".to_owned(), "greens".to_owned()])
        );
        assert_eq!(
            super::first_single_letter_value(&repeated, "t"),
            Ok(Some("carrots".to_owned()))
        );
        assert_eq!(super::first_single_letter_value(&missing, "t"), Ok(None));
        assert_eq!(
            single_letter_values_for(&missing, "topic").expect_err("long"),
            "single-letter tag name `topic` must be one ASCII letter"
        );
        assert_eq!(
            single_letter_values_for(&missing, "é").expect_err("non ascii"),
            "single-letter tag name `é` must be one ASCII letter"
        );
    }

    #[test]
    fn comment_parser_extracts_root_parent_authors_and_references() {
        let root_pubkey = "2".repeat(PublicKeyHex::HEX_LENGTH);
        let parent_pubkey = "3".repeat(PublicKeyHex::HEX_LENGTH);
        let comment_event = "4".repeat(EventId::HEX_LENGTH);
        let mentioned_pubkey = "5".repeat(PublicKeyHex::HEX_LENGTH);
        let address = format!("30023:{root_pubkey}:article-a");
        let event = event_with_kind_tags_and_content(
            NIP22_COMMENT_KIND.into(),
            vec![
                Tag::from_parts("A", &[&address, "wss://relay.radroots.test"]).expect("A"),
                Tag::from_parts("K", &["30023"]).expect("K"),
                Tag::from_parts("P", &[&root_pubkey]).expect("P"),
                Tag::from_parts(
                    "e",
                    &[&comment_event, "wss://relay.radroots.test", &parent_pubkey],
                )
                .expect("e"),
                Tag::from_parts("k", &["1111"]).expect("k"),
                Tag::from_parts("p", &[&parent_pubkey]).expect("p"),
                Tag::from_parts("p", &[&mentioned_pubkey]).expect("mention"),
                Tag::from_parts("q", &[&comment_event]).expect("q"),
            ],
            "That harvest note helped.",
        );

        let comment = parse_comment_event(&event)
            .expect("parse")
            .expect("comment");

        assert_eq!(comment.event_id(), event.id());
        assert_eq!(comment.pubkey(), event.unsigned().pubkey());
        assert_eq!(comment.created_at(), event.unsigned().created_at());
        assert_eq!(comment.content(), "That harvest note helped.");
        assert_eq!(comment.root().kind(), "30023");
        assert_eq!(
            comment.root().author().expect("root author").as_str(),
            root_pubkey
        );
        assert_eq!(comment.parent().kind(), "1111");
        assert_eq!(
            comment.parent().author().expect("parent author").as_str(),
            parent_pubkey
        );
        assert_eq!(comment.cited_events(), &[comment_event.clone()]);
        assert_eq!(comment.mentioned_pubkeys()[0].as_str(), parent_pubkey);
        assert_eq!(comment.mentioned_pubkeys()[1].as_str(), mentioned_pubkey);
        match comment.root().target() {
            CommentTarget::Address {
                address: parsed,
                relay_hint,
            } => {
                assert_eq!(parsed.key().to_string(), address);
                assert_eq!(relay_hint.as_deref(), Some("wss://relay.radroots.test"));
            }
            other => panic!("unexpected target {other:?}"),
        }
        match comment.parent().target() {
            CommentTarget::Event {
                event_id,
                relay_hint,
                pubkey_hint,
            } => {
                assert_eq!(event_id.as_str(), comment_event);
                assert_eq!(relay_hint.as_deref(), Some("wss://relay.radroots.test"));
                assert_eq!(pubkey_hint.as_ref().expect("hint").as_str(), parent_pubkey);
            }
            other => panic!("unexpected target {other:?}"),
        }
    }

    #[test]
    fn comment_parser_extracts_external_scope_and_ignores_other_kinds() {
        let event = event_with_kind_and_tags(
            NIP22_COMMENT_KIND.into(),
            vec![
                Tag::from_parts("I", &["https://radroots.test/posts/harvest"]).expect("I"),
                Tag::from_parts("K", &["web"]).expect("K"),
                Tag::from_parts("i", &["https://radroots.test/posts/harvest"]).expect("i"),
                Tag::from_parts("k", &["web"]).expect("k"),
            ],
        );
        let note = event_with_kind_and_tags(1, Vec::new());

        let comment = parse_comment_event(&event)
            .expect("parse")
            .expect("comment");

        assert_eq!(parse_comment_event(&note), Ok(None));
        match comment.root().target() {
            CommentTarget::External { identity, .. } => {
                assert_eq!(identity, "https://radroots.test/posts/harvest");
            }
            other => panic!("unexpected target {other:?}"),
        }
    }

    #[test]
    fn comment_parser_rejects_missing_repeated_empty_and_kind_one_targets() {
        let target = "2".repeat(EventId::HEX_LENGTH);
        let valid = vec![
            Tag::from_parts("E", &[&target]).expect("E"),
            Tag::from_parts("K", &["30023"]).expect("K"),
            Tag::from_parts("e", &[&target]).expect("e"),
            Tag::from_parts("k", &["30023"]).expect("k"),
        ];
        let missing_root = event_with_kind_tags_and_content(
            NIP22_COMMENT_KIND.into(),
            valid
                .iter()
                .filter(|tag| tag.name().as_str() != "E")
                .cloned()
                .collect(),
            "",
        );
        let repeated_root = event_with_kind_tags_and_content(
            NIP22_COMMENT_KIND.into(),
            [valid.clone(), vec![Tag::from_parts("A", &["30023:1111111111111111111111111111111111111111111111111111111111111111:article"]).expect("A")]].concat(),
            "",
        );
        let empty_parent = event_with_kind_tags_and_content(
            NIP22_COMMENT_KIND.into(),
            vec![
                Tag::from_parts("E", &[&target]).expect("E"),
                Tag::from_parts("K", &["30023"]).expect("K"),
                Tag::from_parts("e", &[""]).expect("e"),
                Tag::from_parts("k", &["30023"]).expect("k"),
            ],
            "",
        );
        let kind_one = event_with_kind_tags_and_content(
            NIP22_COMMENT_KIND.into(),
            vec![
                Tag::from_parts("E", &[&target]).expect("E"),
                Tag::from_parts("K", &["1"]).expect("K"),
                Tag::from_parts("e", &[&target]).expect("e"),
                Tag::from_parts("k", &["30023"]).expect("k"),
            ],
            "",
        );

        assert_eq!(
            parse_comment_event(&missing_root).expect_err("missing"),
            "comment root target tag is required"
        );
        assert_eq!(
            parse_comment_event(&repeated_root).expect_err("repeated"),
            "comment root target tag must not be repeated"
        );
        assert_eq!(
            parse_comment_event(&empty_parent).expect_err("empty"),
            "comment parent target tag `e` must not be empty"
        );
        assert_eq!(
            parse_comment_event(&kind_one).expect_err("kind one"),
            "NIP-22 comments must not reply to kind 1 notes"
        );
    }

    #[test]
    fn reaction_parser_extracts_addressable_target_and_like_reaction() {
        let target_event = "2".repeat(EventId::HEX_LENGTH);
        let previous_event = "3".repeat(EventId::HEX_LENGTH);
        let target_pubkey = "4".repeat(PublicKeyHex::HEX_LENGTH);
        let address = format!("30023:{target_pubkey}:article-a");
        let event = event_with_kind_tags_and_content(
            NIP25_REACTION_KIND.into(),
            vec![
                Tag::from_parts("e", &[&previous_event]).expect("old e"),
                Tag::from_parts(
                    "e",
                    &[&target_event, "wss://relay.radroots.test", &target_pubkey],
                )
                .expect("e"),
                Tag::from_parts("p", &[&target_pubkey]).expect("p"),
                Tag::from_parts("a", &[&address]).expect("a"),
                Tag::from_parts("k", &["30023"]).expect("k"),
            ],
            "+",
        );

        let reaction = parse_reaction_event(&event)
            .expect("parse")
            .expect("reaction");

        assert_eq!(reaction.event_id(), event.id());
        assert_eq!(reaction.pubkey(), event.unsigned().pubkey());
        assert_eq!(reaction.created_at(), event.unsigned().created_at());
        assert_eq!(reaction.content(), "+");
        assert_eq!(reaction.value(), &ReactionValue::Like);
        assert_eq!(reaction.value().canonical(), "like");
        assert_eq!(reaction.target_event_id().as_str(), target_event);
        assert_eq!(
            reaction.target_relay_hint(),
            Some("wss://relay.radroots.test")
        );
        assert_eq!(
            reaction.target_pubkey_hint().expect("pubkey hint").as_str(),
            target_pubkey
        );
        assert_eq!(
            reaction.target_pubkey().expect("target pubkey").as_str(),
            target_pubkey
        );
        assert_eq!(
            reaction
                .target_address()
                .expect("target address")
                .key()
                .to_string(),
            address
        );
        assert_eq!(reaction.target_kind(), Some("30023"));
    }

    #[test]
    fn reaction_parser_classifies_empty_dislike_emoji_and_text_reactions() {
        let target_event = "2".repeat(EventId::HEX_LENGTH);
        let cases = [
            ("", ReactionValue::Like),
            ("-", ReactionValue::Dislike),
            ("⭐", ReactionValue::Emoji("⭐".to_owned())),
            ("agree", ReactionValue::Text("agree".to_owned())),
        ];
        for (content, expected) in cases {
            let event = event_with_kind_tags_and_content(
                NIP25_REACTION_KIND.into(),
                vec![Tag::from_parts("e", &[&target_event]).expect("e")],
                content,
            );
            let reaction = parse_reaction_event(&event)
                .expect("parse")
                .expect("reaction");

            assert_eq!(reaction.value(), &expected);
        }
        let note = event_with_kind_and_tags(1, Vec::new());
        assert_eq!(parse_reaction_event(&note), Ok(None));
    }

    #[test]
    fn reaction_parser_rejects_missing_and_malformed_targets() {
        let bad_event_id = event_with_kind_tags_and_content(
            NIP25_REACTION_KIND.into(),
            vec![Tag::from_parts("e", &["bad"]).expect("e")],
            "+",
        );
        let missing_event_id = event_with_kind_tags_and_content(
            NIP25_REACTION_KIND.into(),
            vec![Tag::from_parts("e", &[]).expect("e")],
            "+",
        );
        let missing_target = event_with_kind_and_tags(NIP25_REACTION_KIND.into(), Vec::new());
        let empty_kind = event_with_kind_tags_and_content(
            NIP25_REACTION_KIND.into(),
            vec![
                Tag::from_parts("e", &[&"2".repeat(EventId::HEX_LENGTH)]).expect("e"),
                Tag::from_parts("k", &[""]).expect("k"),
            ],
            "+",
        );

        assert_eq!(
            parse_reaction_event(&missing_target).expect_err("missing target"),
            "reaction event must include an e target tag"
        );
        assert!(
            parse_reaction_event(&bad_event_id)
                .expect_err("bad event id")
                .contains("event id")
        );
        assert_eq!(
            parse_reaction_event(&missing_event_id).expect_err("missing event id"),
            "reaction e target tag must include an event id"
        );
        assert_eq!(
            parse_reaction_event(&empty_kind).expect_err("empty kind"),
            "reaction k tag must not be empty"
        );
    }

    #[test]
    fn deletion_request_parser_extracts_event_and_address_targets() {
        let target_event_id = "2".repeat(EventId::HEX_LENGTH);
        let target_pubkey = "3".repeat(PublicKeyHex::HEX_LENGTH);
        let address = format!("30402:{target_pubkey}:listing-a");
        let event = event_with_kind_and_tags(
            5,
            vec![
                Tag::from_parts("e", &[&target_event_id]).expect("e"),
                Tag::from_parts("a", &[&address]).expect("a"),
            ],
        );

        let request = parse_deletion_request(&event)
            .expect("parse")
            .expect("request");

        assert_eq!(request.event_id(), event.id());
        assert_eq!(request.targets().len(), 2);
        assert_eq!(
            request.targets()[0],
            DeletionTarget::Event(EventId::new(&target_event_id).expect("event id"))
        );
        assert!(matches!(
            &request.targets()[1],
            DeletionTarget::Address(address) if address.to_string() == format!("30402:{target_pubkey}:listing-a")
        ));
    }

    #[test]
    fn deletion_request_parser_ignores_non_deletion_kinds() {
        let event = event_with_tags(vec![Tag::from_parts("e", &["ignored"]).expect("e")]);

        assert_eq!(parse_deletion_request(&event), Ok(None));
    }

    #[test]
    fn deletion_request_parser_rejects_missing_and_malformed_targets() {
        let missing = event_with_kind_and_tags(5, Vec::new());
        let malformed_event =
            event_with_kind_and_tags(5, vec![Tag::from_parts("e", &["not-hex"]).expect("e")]);
        let malformed_address = event_with_kind_and_tags(
            5,
            vec![Tag::from_parts("a", &["30402:not-a-pubkey:listing"]).expect("a")],
        );

        assert_eq!(
            parse_deletion_request(&missing).expect_err("missing"),
            "deletion event must target at least one e or a tag"
        );
        assert_eq!(
            parse_deletion_request(&malformed_event).expect_err("event"),
            "event id must be 64 characters, got 7"
        );
        assert_eq!(
            parse_deletion_request(&malformed_address).expect_err("address"),
            "public key must be 64 characters, got 12"
        );
    }

    #[test]
    fn deletion_request_parser_keeps_repeated_targets_in_order() {
        let first = "4".repeat(EventId::HEX_LENGTH);
        let second = "5".repeat(EventId::HEX_LENGTH);
        let event = event_with_kind_and_tags(
            5,
            vec![
                Tag::from_parts("e", &[&first]).expect("e"),
                Tag::from_parts("e", &[&second]).expect("e"),
            ],
        );
        let request = parse_deletion_request(&event)
            .expect("parse")
            .expect("request");

        assert_eq!(
            request.targets(),
            &[
                DeletionTarget::Event(EventId::new(&first).expect("first")),
                DeletionTarget::Event(EventId::new(&second).expect("second")),
            ]
        );
    }

    #[test]
    fn relay_auth_parser_extracts_mandatory_fields() {
        let event = event_with_kind_and_tags(
            22_242,
            vec![
                Tag::from_parts("relay", &["wss://relay.radroots.test"]).expect("relay"),
                Tag::from_parts("challenge", &["auth-challenge-001"]).expect("challenge"),
            ],
        );

        let auth = parse_relay_auth_event(&event)
            .expect("parse")
            .expect("auth");

        assert_eq!(auth.event_id(), event.id());
        assert_eq!(auth.pubkey(), event.unsigned().pubkey());
        assert_eq!(auth.created_at(), event.unsigned().created_at());
        assert_eq!(auth.relay(), "wss://relay.radroots.test");
        assert_eq!(auth.challenge(), "auth-challenge-001");
    }

    #[test]
    fn relay_auth_parser_ignores_non_auth_kinds() {
        let event = event_with_tags(vec![
            Tag::from_parts("relay", &["wss://relay.radroots.test"]).expect("relay"),
            Tag::from_parts("challenge", &["auth-challenge-001"]).expect("challenge"),
        ]);

        assert_eq!(parse_relay_auth_event(&event), Ok(None));
    }

    #[test]
    fn relay_auth_parser_rejects_missing_and_repeated_fields() {
        let missing_relay = event_with_kind_and_tags(
            22_242,
            vec![Tag::from_parts("challenge", &["challenge"]).expect("challenge")],
        );
        let missing_challenge = event_with_kind_and_tags(
            22_242,
            vec![Tag::from_parts("relay", &["wss://relay.radroots.test"]).expect("relay")],
        );
        let repeated_relay = event_with_kind_and_tags(
            22_242,
            vec![
                Tag::from_parts("relay", &["wss://relay-a.radroots.test"]).expect("relay"),
                Tag::from_parts("relay", &["wss://relay-b.radroots.test"]).expect("relay"),
                Tag::from_parts("challenge", &["challenge"]).expect("challenge"),
            ],
        );

        assert_eq!(
            parse_relay_auth_event(&missing_relay).expect_err("relay"),
            "tag `relay` is required"
        );
        assert_eq!(
            parse_relay_auth_event(&missing_challenge).expect_err("challenge"),
            "tag `challenge` is required"
        );
        assert_eq!(
            parse_relay_auth_event(&repeated_relay).expect_err("repeated"),
            "tag `relay` must not be repeated"
        );
    }

    #[test]
    fn relay_auth_parser_rejects_empty_fields() {
        let empty_relay = event_with_kind_and_tags(
            22_242,
            vec![
                Tag::from_parts("relay", &[""]).expect("relay"),
                Tag::from_parts("challenge", &["challenge"]).expect("challenge"),
            ],
        );
        let empty_challenge = event_with_kind_and_tags(
            22_242,
            vec![
                Tag::from_parts("relay", &["wss://relay.radroots.test"]).expect("relay"),
                Tag::from_parts("challenge", &[""]).expect("challenge"),
            ],
        );

        assert_eq!(
            parse_relay_auth_event(&empty_relay).expect_err("empty relay"),
            "relay auth relay tag must not be empty"
        );
        assert_eq!(
            parse_relay_auth_event(&empty_challenge).expect_err("empty challenge"),
            "relay auth challenge tag must not be empty"
        );
    }

    #[test]
    fn nip50_search_parser_extracts_plain_terms_and_ignores_extensions() {
        let query = parse_nip50_search("  fresh seller:ignored carrots status:ignored greens  ")
            .expect("parse")
            .expect("query");

        assert_eq!(query.text(), "fresh carrots greens");
        assert_eq!(
            query.terms(),
            &[
                "fresh".to_owned(),
                "carrots".to_owned(),
                "greens".to_owned()
            ]
        );
    }

    #[test]
    fn nip50_search_parser_treats_empty_and_extension_only_queries_as_absent() {
        assert_eq!(parse_nip50_search("   "), Ok(None));
        assert_eq!(
            parse_nip50_search("seller:ignored status:ignored"),
            Ok(None)
        );
    }

    #[test]
    fn nip50_search_parser_reads_filter_search_field() {
        let filter = filter_from_value(&serde_json::json!({
            "search": "farmstand tomatoes",
            "kinds": [1]
        }))
        .expect("filter");
        let missing = filter_from_value(&serde_json::json!({
            "kinds": [1]
        }))
        .expect("missing");

        assert_eq!(
            parse_nip50_filter_search(&filter)
                .expect("filter")
                .expect("query")
                .text(),
            "farmstand tomatoes"
        );
        assert_eq!(parse_nip50_filter_search(&missing), Ok(None));
    }

    #[test]
    fn listing_identity_parser_extracts_public_listing_address() {
        let event = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("d", &["listing-a"]).expect("d")],
        );

        let identity = parse_listing_identity(&event)
            .expect("parse")
            .expect("identity");

        assert_eq!(identity.event_id(), event.id());
        assert_eq!(identity.listing_kind(), ListingKind::Public);
        assert_eq!(identity.seller_pubkey(), event.unsigned().pubkey());
        assert_eq!(identity.d().as_str(), "listing-a");
        assert_eq!(
            identity.address().to_string(),
            format!("30402:{}:listing-a", event.unsigned().pubkey().as_str())
        );
    }

    #[test]
    fn listing_identity_parser_extracts_draft_listing_address() {
        let event =
            event_with_kind_and_tags(30_403, vec![Tag::from_parts("d", &["draft-a"]).expect("d")]);

        let identity = parse_listing_identity(&event)
            .expect("parse")
            .expect("identity");

        assert_eq!(identity.listing_kind(), ListingKind::Draft);
        assert_eq!(identity.address().kind().as_u32(), 30_403);
    }

    #[test]
    fn listing_identity_parser_ignores_non_listing_kinds() {
        let event = event_with_kind_and_tags(1, vec![Tag::from_parts("d", &["note"]).expect("d")]);

        assert_eq!(parse_listing_identity(&event), Ok(None));
    }

    #[test]
    fn listing_identity_parser_rejects_missing_repeated_and_empty_d_tags() {
        let missing = event_with_kind_and_tags(u64::from(NIP99_PUBLIC_LISTING_KIND), Vec::new());
        let repeated = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![
                Tag::from_parts("d", &["listing-a"]).expect("d"),
                Tag::from_parts("d", &["listing-b"]).expect("d"),
            ],
        );
        let empty = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("d", &[""]).expect("d")],
        );

        assert_eq!(
            parse_listing_identity(&missing).expect_err("missing"),
            "tag `d` is required"
        );
        assert_eq!(
            parse_listing_identity(&repeated).expect_err("repeated"),
            "tag `d` must not be repeated"
        );
        assert_eq!(
            parse_listing_identity(&empty).expect_err("empty"),
            "listing d tag must not be empty"
        );
    }

    #[test]
    fn listing_text_parser_extracts_title_summary_and_body() {
        let event = event_with_kind_tags_and_content(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![
                Tag::from_parts("title", &["Carrot bunches"]).expect("title"),
                Tag::from_parts("summary", &["Fresh field bunches"]).expect("summary"),
            ],
            "Harvested this morning.",
        );

        let text = parse_listing_text(&event).expect("parse").expect("text");

        assert_eq!(text.title(), "Carrot bunches");
        assert_eq!(text.summary(), Some("Fresh field bunches"));
        assert_eq!(text.body(), "Harvested this morning.");
    }

    #[test]
    fn listing_text_parser_parses_draft_text_and_ignores_non_listings() {
        let draft = event_with_kind_and_tags(
            30_403,
            vec![Tag::from_parts("title", &["Draft carrots"]).expect("title")],
        );
        let note = event_with_kind_and_tags(
            1,
            vec![Tag::from_parts("title", &["Note title"]).expect("title")],
        );

        assert_eq!(
            parse_listing_text(&draft)
                .expect("draft")
                .expect("text")
                .title(),
            "Draft carrots"
        );
        assert_eq!(parse_listing_text(&note), Ok(None));
    }

    #[test]
    fn listing_text_parser_rejects_missing_repeated_and_empty_titles() {
        let missing = event_with_kind_and_tags(u64::from(NIP99_PUBLIC_LISTING_KIND), Vec::new());
        let repeated = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![
                Tag::from_parts("title", &["Carrots"]).expect("title"),
                Tag::from_parts("title", &["Greens"]).expect("title"),
            ],
        );
        let missing_value = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("title", &[]).expect("title")],
        );
        let empty = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("title", &[""]).expect("title")],
        );

        assert_eq!(
            parse_listing_text(&missing).expect_err("missing"),
            "tag `title` is required"
        );
        assert_eq!(
            parse_listing_text(&repeated).expect_err("repeated"),
            "tag `title` must not be repeated"
        );
        assert_eq!(
            parse_listing_text(&missing_value).expect_err("value"),
            "tag `title` must include a value"
        );
        assert_eq!(
            parse_listing_text(&empty).expect_err("empty"),
            "listing title tag must not be empty"
        );
    }

    #[test]
    fn listing_text_parser_rejects_malformed_summary_tags() {
        let repeated = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![
                Tag::from_parts("title", &["Carrots"]).expect("title"),
                Tag::from_parts("summary", &["Fresh"]).expect("summary"),
                Tag::from_parts("summary", &["Sweet"]).expect("summary"),
            ],
        );
        let missing_value = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![
                Tag::from_parts("title", &["Carrots"]).expect("title"),
                Tag::from_parts("summary", &[]).expect("summary"),
            ],
        );
        let empty = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![
                Tag::from_parts("title", &["Carrots"]).expect("title"),
                Tag::from_parts("summary", &[""]).expect("summary"),
            ],
        );

        assert_eq!(
            parse_listing_text(&repeated).expect_err("repeated"),
            "tag `summary` must not be repeated"
        );
        assert_eq!(
            parse_listing_text(&missing_value).expect_err("value"),
            "tag `summary` must include a value"
        );
        assert_eq!(
            parse_listing_text(&empty).expect_err("empty"),
            "listing summary tag must not be empty"
        );
    }

    #[test]
    fn listing_price_parser_extracts_exact_decimal_currency_and_frequency() {
        let event = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("price", &["12.50", "usd", "weekly"]).expect("price")],
        );

        let price = parse_listing_price(&event).expect("parse").expect("price");

        assert_eq!(price.amount().raw(), "12.50");
        assert_eq!(price.currency(), "usd");
        assert_eq!(price.display_currency(), "USD");
        assert_eq!(price.frequency(), Some("weekly"));
    }

    #[test]
    fn listing_price_parser_accepts_integer_amount_without_frequency() {
        let event = event_with_kind_and_tags(
            30_403,
            vec![Tag::from_parts("price", &["7", "CAD"]).expect("price")],
        );

        let price = parse_listing_price(&event).expect("parse").expect("price");

        assert_eq!(price.amount().raw(), "7");
        assert_eq!(price.currency(), "CAD");
        assert_eq!(price.display_currency(), "CAD");
        assert_eq!(price.frequency(), None);
    }

    #[test]
    fn listing_price_parser_ignores_non_listing_kinds() {
        let event =
            event_with_kind_and_tags(1, vec![Tag::from_parts("price", &["3", "USD"]).expect("p")]);

        assert_eq!(parse_listing_price(&event), Ok(None));
    }

    #[test]
    fn listing_price_parser_rejects_missing_repeated_and_bad_shape() {
        let missing = event_with_kind_and_tags(u64::from(NIP99_PUBLIC_LISTING_KIND), Vec::new());
        let repeated = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![
                Tag::from_parts("price", &["3", "USD"]).expect("price"),
                Tag::from_parts("price", &["4", "USD"]).expect("price"),
            ],
        );
        let no_values = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("price", &[]).expect("price")],
        );
        let no_currency = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("price", &["3"]).expect("price")],
        );
        let extra = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("price", &["3", "USD", "weekly", "extra"]).expect("price")],
        );

        assert_eq!(
            parse_listing_price(&missing).expect_err("missing"),
            "tag `price` is required"
        );
        assert_eq!(
            parse_listing_price(&repeated).expect_err("repeated"),
            "tag `price` must not be repeated"
        );
        assert_eq!(
            parse_listing_price(&no_values).expect_err("values"),
            "price tag must include amount and currency"
        );
        assert_eq!(
            parse_listing_price(&no_currency).expect_err("currency"),
            "price tag must include amount and currency"
        );
        assert_eq!(
            parse_listing_price(&extra).expect_err("extra"),
            "price tag must not include more than amount currency and frequency"
        );
    }

    #[test]
    fn listing_price_parser_rejects_malformed_amount_currency_and_frequency() {
        let bad_amounts = ["", ".50", "12.", "12.5.0", "-12", "1e3", "12 usd"];
        for amount in bad_amounts {
            let event = event_with_kind_and_tags(
                u64::from(NIP99_PUBLIC_LISTING_KIND),
                vec![Tag::from_parts("price", &[amount, "USD"]).expect("price")],
            );
            assert_eq!(
                parse_listing_price(&event).expect_err("amount"),
                "price amount must be an exact unsigned decimal"
            );
        }
        let empty_currency = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("price", &["3", ""]).expect("price")],
        );
        let empty_frequency = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("price", &["3", "USD", ""]).expect("price")],
        );

        assert_eq!(
            parse_listing_price(&empty_currency).expect_err("currency"),
            "price currency must not be empty"
        );
        assert_eq!(
            parse_listing_price(&empty_frequency).expect_err("frequency"),
            "price frequency must not be empty"
        );
    }

    #[test]
    fn listing_unit_parser_normalizes_supported_units_and_aliases() {
        let cases = [
            ("LB", ListingUnit::Lb, "lb"),
            ("ounces", ListingUnit::Oz, "oz"),
            ("ea", ListingUnit::Each, "each"),
            ("bunches", ListingUnit::Bunch, "bunch"),
            ("dozen", ListingUnit::Dozen, "dozen"),
            ("kilograms", ListingUnit::Kg, "kg"),
            ("grams", ListingUnit::G, "g"),
            ("shares", ListingUnit::Share, "share"),
            ("pints", ListingUnit::Pint, "pint"),
            ("quarts", ListingUnit::Quart, "quart"),
            ("boxes", ListingUnit::Box, "box"),
            ("crates", ListingUnit::Crate, "crate"),
            ("flats", ListingUnit::Flat, "flat"),
        ];

        for (raw, unit, canonical) in cases {
            let event = event_with_kind_and_tags(
                u64::from(NIP99_PUBLIC_LISTING_KIND),
                vec![Tag::from_parts("unit", &[raw]).expect("unit")],
            );
            let parsed = parse_listing_unit(&event).expect("parse").expect("unit");

            assert_eq!(parsed.raw(), raw);
            assert_eq!(parsed.unit(), unit);
            assert_eq!(parsed.canonical(), canonical);
            assert_eq!(unit.canonical(), canonical);
        }
    }

    #[test]
    fn listing_unit_parser_trims_input_and_ignores_non_listing_kinds() {
        let listing = event_with_kind_and_tags(
            30_403,
            vec![Tag::from_parts("unit", &[" pound "]).expect("unit")],
        );
        let note =
            event_with_kind_and_tags(1, vec![Tag::from_parts("unit", &["lb"]).expect("unit")]);

        assert_eq!(
            parse_listing_unit(&listing)
                .expect("listing")
                .expect("unit")
                .canonical(),
            "lb"
        );
        assert_eq!(parse_listing_unit(&note), Ok(None));
    }

    #[test]
    fn listing_unit_parser_rejects_missing_repeated_and_empty_units() {
        let missing = event_with_kind_and_tags(u64::from(NIP99_PUBLIC_LISTING_KIND), Vec::new());
        let repeated = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![
                Tag::from_parts("unit", &["lb"]).expect("unit"),
                Tag::from_parts("unit", &["kg"]).expect("unit"),
            ],
        );
        let missing_value = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("unit", &[]).expect("unit")],
        );
        let empty = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("unit", &["  "]).expect("unit")],
        );

        assert_eq!(
            parse_listing_unit(&missing).expect_err("missing"),
            "tag `unit` is required"
        );
        assert_eq!(
            parse_listing_unit(&repeated).expect_err("repeated"),
            "tag `unit` must not be repeated"
        );
        assert_eq!(
            parse_listing_unit(&missing_value).expect_err("value"),
            "tag `unit` must include a value"
        );
        assert_eq!(
            parse_listing_unit(&empty).expect_err("empty"),
            "listing unit tag must not be empty"
        );
    }

    #[test]
    fn listing_unit_parser_rejects_unsupported_units() {
        let event = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("unit", &["bushel"]).expect("unit")],
        );

        assert_eq!(
            parse_listing_unit(&event).expect_err("unsupported"),
            "listing unit `bushel` is unsupported"
        );
    }

    #[test]
    fn listing_fulfillment_parser_extracts_methods_and_availability_flags() {
        let event = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![
                Tag::from_parts("fulfillment", &["shipping"]).expect("shipping"),
                Tag::from_parts("fulfillment", &["pickup"]).expect("pickup"),
                Tag::from_parts("fulfillment", &["delivery"]).expect("delivery"),
                Tag::from_parts("fulfillment", &["pickup"]).expect("pickup"),
            ],
        );

        let fulfillment = parse_listing_fulfillment(&event)
            .expect("parse")
            .expect("fulfillment");

        assert_eq!(
            fulfillment.methods(),
            &[
                FulfillmentMethod::Pickup,
                FulfillmentMethod::Delivery,
                FulfillmentMethod::Shipping
            ]
        );
        assert_eq!(FulfillmentMethod::Pickup.canonical(), "pickup");
        assert_eq!(FulfillmentMethod::Delivery.canonical(), "delivery");
        assert_eq!(FulfillmentMethod::Shipping.canonical(), "shipping");
        assert!(fulfillment.pickup_available());
        assert!(fulfillment.delivery_available());
        assert!(fulfillment.shipping_available());
        assert!(!fulfillment.delivery_only());
    }

    #[test]
    fn listing_fulfillment_parser_derives_delivery_only_and_ignores_non_listings() {
        let delivery = event_with_kind_and_tags(
            30_403,
            vec![Tag::from_parts("fulfillment", &[" delivery "]).expect("delivery")],
        );
        let note = event_with_kind_and_tags(
            1,
            vec![Tag::from_parts("fulfillment", &["pickup"]).expect("pickup")],
        );

        let fulfillment = parse_listing_fulfillment(&delivery)
            .expect("delivery")
            .expect("fulfillment");

        assert_eq!(fulfillment.methods(), &[FulfillmentMethod::Delivery]);
        assert!(fulfillment.delivery_only());
        assert_eq!(parse_listing_fulfillment(&note), Ok(None));
    }

    #[test]
    fn listing_fulfillment_parser_rejects_missing_and_malformed_tags() {
        let missing = event_with_kind_and_tags(u64::from(NIP99_PUBLIC_LISTING_KIND), Vec::new());
        let missing_value = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("fulfillment", &[]).expect("fulfillment")],
        );
        let extra_value = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("fulfillment", &["pickup", "delivery"]).expect("fulfillment")],
        );
        let empty = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("fulfillment", &["  "]).expect("fulfillment")],
        );

        assert_eq!(
            parse_listing_fulfillment(&missing).expect_err("missing"),
            "tag `fulfillment` is required"
        );
        assert_eq!(
            parse_listing_fulfillment(&missing_value).expect_err("value"),
            "tag `fulfillment` must include a value"
        );
        assert_eq!(
            parse_listing_fulfillment(&extra_value).expect_err("extra"),
            "fulfillment tag must include exactly one method"
        );
        assert_eq!(
            parse_listing_fulfillment(&empty).expect_err("empty"),
            "fulfillment tag method must not be empty"
        );
    }

    #[test]
    fn listing_fulfillment_parser_rejects_unsupported_methods() {
        let event = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("fulfillment", &["drone"]).expect("fulfillment")],
        );

        assert_eq!(
            parse_listing_fulfillment(&event).expect_err("unsupported"),
            "fulfillment method `drone` is unsupported"
        );
    }

    #[test]
    fn listing_status_parser_defaults_public_listings_to_active() {
        let event = event_with_kind_and_tags(u64::from(NIP99_PUBLIC_LISTING_KIND), Vec::new());

        let status = parse_listing_status(&event)
            .expect("parse")
            .expect("status");

        assert_eq!(status.raw_status(), None);
        assert_eq!(status.effective_status(), ListingEffectiveStatus::Active);
        assert_eq!(ListingEffectiveStatus::Active.canonical(), "active");
    }

    #[test]
    fn listing_status_parser_extracts_sold_and_active_status_tags() {
        let sold = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("status", &["sold"]).expect("status")],
        );
        let active = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("status", &["active"]).expect("status")],
        );

        let sold_status = parse_listing_status(&sold).expect("sold").expect("status");
        let active_status = parse_listing_status(&active)
            .expect("active")
            .expect("status");

        assert_eq!(sold_status.raw_status(), Some("sold"));
        assert_eq!(sold_status.effective_status(), ListingEffectiveStatus::Sold);
        assert_eq!(ListingEffectiveStatus::Sold.canonical(), "sold");
        assert_eq!(active_status.raw_status(), Some("active"));
        assert_eq!(
            active_status.effective_status(),
            ListingEffectiveStatus::Active
        );
    }

    #[test]
    fn listing_status_parser_derives_draft_from_kind_and_ignores_non_listings() {
        let draft = event_with_kind_and_tags(
            30_403,
            vec![Tag::from_parts("status", &["sold"]).expect("status")],
        );
        let note =
            event_with_kind_and_tags(1, vec![Tag::from_parts("status", &["active"]).expect("s")]);

        let status = parse_listing_status(&draft)
            .expect("draft")
            .expect("status");

        assert_eq!(status.raw_status(), Some("sold"));
        assert_eq!(status.effective_status(), ListingEffectiveStatus::Draft);
        assert_eq!(ListingEffectiveStatus::Draft.canonical(), "draft");
        assert_eq!(parse_listing_status(&note), Ok(None));
    }

    #[test]
    fn listing_status_parser_rejects_repeated_missing_empty_and_unsupported_tags() {
        let repeated = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![
                Tag::from_parts("status", &["active"]).expect("status"),
                Tag::from_parts("status", &["sold"]).expect("status"),
            ],
        );
        let missing_value = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("status", &[]).expect("status")],
        );
        let empty = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("status", &[""]).expect("status")],
        );
        let unsupported = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("status", &["inactive"]).expect("status")],
        );

        assert_eq!(
            parse_listing_status(&repeated).expect_err("repeated"),
            "tag `status` must not be repeated"
        );
        assert_eq!(
            parse_listing_status(&missing_value).expect_err("value"),
            "tag `status` must include a value"
        );
        assert_eq!(
            parse_listing_status(&empty).expect_err("empty"),
            "listing status tag must not be empty"
        );
        assert_eq!(
            parse_listing_status(&unsupported).expect_err("unsupported"),
            "listing status `inactive` is unsupported"
        );
    }

    #[test]
    fn listing_location_parser_extracts_text_geohash_and_prefixes() {
        let event = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![
                Tag::from_parts("location", &["Olympia Farmers Market"]).expect("location"),
                Tag::from_parts("g", &[" C22YZUG "]).expect("g"),
            ],
        );

        let location = parse_listing_location(&event)
            .expect("parse")
            .expect("location");

        assert_eq!(location.location_text(), Some("Olympia Farmers Market"));
        assert_eq!(location.geohash(), Some("c22yzug"));
        assert_eq!(location.geohash4(), Some("c22y"));
        assert_eq!(location.geohash5(), Some("c22yz"));
        assert_eq!(location.geohash6(), Some("c22yzu"));
        assert_eq!(location.geohash7(), Some("c22yzug"));
        assert_eq!(location.location_precision(), Some(7));
    }

    #[test]
    fn listing_location_parser_allows_missing_location_fields_and_ignores_non_listings() {
        let listing = event_with_kind_and_tags(u64::from(NIP99_PUBLIC_LISTING_KIND), Vec::new());
        let note = event_with_kind_and_tags(
            1,
            vec![Tag::from_parts("location", &["Somewhere"]).expect("location")],
        );

        let location = parse_listing_location(&listing)
            .expect("listing")
            .expect("location");

        assert_eq!(location.location_text(), None);
        assert_eq!(location.geohash(), None);
        assert_eq!(location.geohash4(), None);
        assert_eq!(location.location_precision(), None);
        assert_eq!(parse_listing_location(&note), Ok(None));
    }

    #[test]
    fn listing_location_parser_rejects_malformed_location_tags() {
        let repeated = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![
                Tag::from_parts("location", &["A"]).expect("location"),
                Tag::from_parts("location", &["B"]).expect("location"),
            ],
        );
        let missing_value = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("location", &[]).expect("location")],
        );
        let empty = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("location", &[""]).expect("location")],
        );

        assert_eq!(
            parse_listing_location(&repeated).expect_err("repeated"),
            "tag `location` must not be repeated"
        );
        assert_eq!(
            parse_listing_location(&missing_value).expect_err("value"),
            "tag `location` must include a value"
        );
        assert_eq!(
            parse_listing_location(&empty).expect_err("empty"),
            "listing location tag must not be empty"
        );
    }

    #[test]
    fn listing_location_parser_rejects_malformed_geohash_tags() {
        let repeated = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![
                Tag::from_parts("g", &["c22y"]).expect("g"),
                Tag::from_parts("g", &["c23n"]).expect("g"),
            ],
        );
        let missing_value = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("g", &[]).expect("g")],
        );
        let extra_value = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("g", &["c22y", "extra"]).expect("g")],
        );
        let invalid = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("g", &["c22a"]).expect("g")],
        );
        let too_short = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("g", &["c22"]).expect("g")],
        );

        assert_eq!(
            parse_listing_location(&repeated).expect_err("repeated"),
            "tag `g` must not be repeated"
        );
        assert_eq!(
            parse_listing_location(&missing_value).expect_err("value"),
            "tag `g` must include a value"
        );
        assert_eq!(
            parse_listing_location(&extra_value).expect_err("extra"),
            "tag `g` must include exactly one value"
        );
        assert_eq!(
            parse_listing_location(&invalid).expect_err("invalid"),
            "geohash must be 4 to 12 geohash characters"
        );
        assert_eq!(
            parse_listing_location(&too_short).expect_err("short"),
            "geohash must be 4 to 12 geohash characters"
        );
    }

    #[test]
    fn listing_taxonomy_parser_extracts_normalized_distinct_values() {
        let event = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![
                Tag::from_parts("category", &["Vegetables"]).expect("category"),
                Tag::from_parts("category", &[" vegetables "]).expect("category"),
                Tag::from_parts("t", &["Carrots"]).expect("topic"),
                Tag::from_parts("t", &["CSA"]).expect("topic"),
                Tag::from_parts("practice", &["No Spray"]).expect("practice"),
                Tag::from_parts("certification", &["Organic"]).expect("certification"),
            ],
        );

        let taxonomy = parse_listing_taxonomy(&event)
            .expect("parse")
            .expect("taxonomy");

        assert_eq!(taxonomy.categories(), &["vegetables".to_owned()]);
        assert_eq!(taxonomy.topics(), &["carrots".to_owned(), "csa".to_owned()]);
        assert_eq!(taxonomy.practices(), &["no spray".to_owned()]);
        assert_eq!(taxonomy.certifications(), &["organic".to_owned()]);
    }

    #[test]
    fn listing_taxonomy_parser_allows_missing_taxonomy_and_ignores_non_listings() {
        let listing = event_with_kind_and_tags(30_403, Vec::new());
        let note = event_with_kind_and_tags(
            1,
            vec![Tag::from_parts("category", &["vegetables"]).expect("category")],
        );

        let taxonomy = parse_listing_taxonomy(&listing)
            .expect("listing")
            .expect("taxonomy");

        assert_eq!(taxonomy.categories(), &[] as &[String]);
        assert_eq!(taxonomy.topics(), &[] as &[String]);
        assert_eq!(taxonomy.practices(), &[] as &[String]);
        assert_eq!(taxonomy.certifications(), &[] as &[String]);
        assert_eq!(parse_listing_taxonomy(&note), Ok(None));
    }

    #[test]
    fn listing_taxonomy_parser_rejects_malformed_category_and_topic_tags() {
        let category_missing_value = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("category", &[]).expect("category")],
        );
        let category_extra = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("category", &["vegetables", "extra"]).expect("category")],
        );
        let topic_empty = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("t", &["  "]).expect("topic")],
        );

        assert_eq!(
            parse_listing_taxonomy(&category_missing_value).expect_err("value"),
            "tag `category` must include a value"
        );
        assert_eq!(
            parse_listing_taxonomy(&category_extra).expect_err("extra"),
            "tag `category` must include exactly one value"
        );
        assert_eq!(
            parse_listing_taxonomy(&topic_empty).expect_err("empty"),
            "listing taxonomy `t` value must not be empty"
        );
    }

    #[test]
    fn listing_taxonomy_parser_rejects_malformed_practice_and_certification_tags() {
        let practice_empty = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("practice", &[""]).expect("practice")],
        );
        let certification_extra = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("certification", &["organic", "extra"]).expect("certification")],
        );

        assert_eq!(
            parse_listing_taxonomy(&practice_empty).expect_err("practice"),
            "listing taxonomy `practice` value must not be empty"
        );
        assert_eq!(
            parse_listing_taxonomy(&certification_extra).expect_err("certification"),
            "tag `certification` must include exactly one value"
        );
    }

    #[test]
    fn listing_projection_contract_accepts_complete_public_listing() {
        let event = event_with_kind_tags_and_content(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            complete_listing_tags(),
            "Sweet storage carrots.",
        );

        let evaluation = evaluate_listing_projection(&event);

        assert!(evaluation.is_eligible());
        assert_eq!(evaluation.rejection(), None);
        let projection = evaluation.projection().expect("projection");

        assert_eq!(projection.identity().d().as_str(), "listing-a");
        assert_eq!(projection.text().title(), "Carrot bunches");
        assert_eq!(projection.price().amount().raw(), "12.50");
        assert_eq!(projection.unit().unit(), ListingUnit::Lb);
        assert_eq!(projection.unit().canonical(), "lb");
        assert!(projection.fulfillment().pickup_available());
        assert_eq!(
            projection.status().effective_status(),
            ListingEffectiveStatus::Active
        );
        assert_eq!(projection.location().geohash4(), Some("c22y"));
        assert_eq!(
            projection.taxonomy().categories(),
            &["vegetables".to_owned()]
        );
    }

    #[test]
    fn listing_projection_contract_ignores_non_listing_events() {
        let event = event_with_kind_and_tags(1, complete_listing_tags());
        let evaluation = evaluate_listing_projection(&event);

        assert_eq!(evaluation, ListingProjectionEvaluation::NotListing);
        assert!(!evaluation.is_eligible());
        assert_eq!(evaluation.projection(), None);
        assert_eq!(evaluation.rejection(), None);
    }

    #[test]
    fn listing_projection_contract_rejects_draft_projection() {
        let event = event_with_kind_and_tags(30_403, complete_listing_tags());
        let evaluation = evaluate_listing_projection(&event);

        assert!(!evaluation.is_eligible());
        let rejection = evaluation.rejection().expect("rejection");

        assert_eq!(rejection.event_id(), event.id());
        assert_eq!(
            rejection.reasons(),
            &["draft listing is not public projection eligible".to_owned()]
        );
    }

    #[test]
    fn listing_projection_contract_accumulates_required_parser_failures() {
        let event = event_with_kind_and_tags(
            u64::from(NIP99_PUBLIC_LISTING_KIND),
            vec![Tag::from_parts("d", &["listing-a"]).expect("d")],
        );
        let evaluation = evaluate_listing_projection(&event);

        let rejection = evaluation.rejection().expect("rejection");

        assert_eq!(
            rejection.reasons(),
            &[
                "tag `title` is required".to_owned(),
                "tag `price` is required".to_owned(),
                "tag `unit` is required".to_owned(),
                "tag `fulfillment` is required".to_owned(),
            ]
        );
    }

    #[test]
    fn listing_projection_contract_accumulates_optional_parser_failures() {
        let mut tags = complete_listing_tags();
        tags.push(Tag::from_parts("location", &[""]).expect("location"));
        tags.push(Tag::from_parts("category", &["vegetables", "extra"]).expect("category"));
        let event = event_with_kind_and_tags(u64::from(NIP99_PUBLIC_LISTING_KIND), tags);
        let evaluation = evaluate_listing_projection(&event);

        let rejection = evaluation.rejection().expect("rejection");

        assert_eq!(
            rejection.reasons(),
            &[
                "listing location tag must not be empty".to_owned(),
                "tag `category` must include exactly one value".to_owned(),
            ]
        );
    }

    #[test]
    fn listing_projection_contract_accumulates_identity_and_status_failures() {
        let mut tags = complete_listing_tags();
        tags.retain(|tag| tag.name().as_str() != "d");
        tags.push(Tag::from_parts("status", &["inactive"]).expect("status"));
        let event = event_with_kind_and_tags(u64::from(NIP99_PUBLIC_LISTING_KIND), tags);
        let evaluation = evaluate_listing_projection(&event);

        let rejection = evaluation.rejection().expect("rejection");

        assert_eq!(
            rejection.reasons(),
            &[
                "tag `d` is required".to_owned(),
                "listing status `inactive` is unsupported".to_owned(),
            ]
        );
    }

    fn event_with_tags(tags: Vec<Tag>) -> Event {
        event_with_kind_and_tags(30_402, tags)
    }

    fn event_with_kind_and_tags(kind: u64, tags: Vec<Tag>) -> Event {
        event_with_kind_tags_and_content(kind, tags, "")
    }

    fn event_with_kind_tags_and_content(kind: u64, tags: Vec<Tag>, content: &str) -> Event {
        Event::new(
            EventId::new(&"a".repeat(EventId::HEX_LENGTH)).expect("id"),
            UnsignedEvent::new(
                PublicKeyHex::new(&"1".repeat(PublicKeyHex::HEX_LENGTH)).expect("pubkey"),
                UnixTimestamp::new(1_714_124_433),
                Kind::new(kind).expect("kind"),
                tags,
                content,
            ),
            SignatureHex::new(&"b".repeat(SignatureHex::HEX_LENGTH)).expect("sig"),
        )
    }

    fn complete_listing_tags() -> Vec<Tag> {
        vec![
            Tag::from_parts("d", &["listing-a"]).expect("d"),
            Tag::from_parts("title", &["Carrot bunches"]).expect("title"),
            Tag::from_parts("price", &["12.50", "USD"]).expect("price"),
            Tag::from_parts("unit", &["lb"]).expect("unit"),
            Tag::from_parts("fulfillment", &["pickup"]).expect("fulfillment"),
            Tag::from_parts("g", &["c22yzug"]).expect("g"),
            Tag::from_parts("category", &["vegetables"]).expect("category"),
            Tag::from_parts("t", &["carrots"]).expect("topic"),
            Tag::from_parts("practice", &["no spray"]).expect("practice"),
            Tag::from_parts("certification", &["organic"]).expect("certification"),
        ]
    }
}
