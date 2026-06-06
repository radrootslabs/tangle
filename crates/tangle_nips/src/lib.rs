#![forbid(unsafe_code)]

use core::str::FromStr;
use tangle_protocol::{
    AddressCoordinate, DTag, Event, EventId, Filter, PublicKeyHex, TagName, UnixTimestamp,
};

pub const NIP99_PUBLIC_LISTING_KIND: u32 = 30_402;
pub const NIP99_DRAFT_LISTING_KIND: u32 = 30_403;

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
        DeletionTarget, ListingKind, NIP99_PUBLIC_LISTING_KIND, matching_tags, optional_tag_value,
        optional_tag_values, parse_deletion_request, parse_listing_identity, parse_listing_price,
        parse_listing_text, parse_nip50_filter_search, parse_nip50_search, parse_relay_auth_event,
        parse_required_u64_tag, parse_u64_field, repeated_or_missing_policy_boundary,
        required_tag_value, required_tag_values, single_letter_tag_values,
        single_letter_values_for, tag_count,
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
}
