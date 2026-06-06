#![forbid(unsafe_code)]

use core::fmt;
use core::str::FromStr;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId(String);

impl EventId {
    pub const HEX_LENGTH: usize = 64;

    pub fn new(value: &str) -> Result<Self, String> {
        require_lowercase_hex("event id", value, Self::HEX_LENGTH)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for EventId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKeyHex(String);

impl PublicKeyHex {
    pub const HEX_LENGTH: usize = 64;

    pub fn new(value: &str) -> Result<Self, String> {
        require_lowercase_hex("public key", value, Self::HEX_LENGTH)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PublicKeyHex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for PublicKeyHex {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignatureHex(String);

impl SignatureHex {
    pub const HEX_LENGTH: usize = 128;

    pub fn new(value: &str) -> Result<Self, String> {
        require_lowercase_hex("signature", value, Self::HEX_LENGTH)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SignatureHex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SignatureHex {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionId(String);

impl SubscriptionId {
    pub const MAX_LENGTH: usize = 64;

    pub fn new(value: &str) -> Result<Self, String> {
        let actual = value.chars().count();
        if actual == 0 {
            return Err(empty_error("subscription id"));
        }
        if actual > Self::MAX_LENGTH {
            return Err(too_long_error("subscription id", Self::MAX_LENGTH, actual));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SubscriptionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SubscriptionId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTimestamp(u64);

impl UnixTimestamp {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for UnixTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl From<u64> for UnixTimestamp {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Kind(u32);

impl Kind {
    pub fn new(value: u64) -> Result<Self, String> {
        let value = u32::try_from(value).map_err(|_| kind_out_of_range_error(value))?;
        Ok(Self(value))
    }

    pub fn as_u32(self) -> u32 {
        self.0
    }

    pub fn class(self) -> KindClass {
        match self.0 {
            0 | 3 | 10_000..=19_999 => KindClass::Replaceable,
            20_000..=29_999 => KindClass::Ephemeral,
            30_000..=39_999 => KindClass::Addressable,
            _ => KindClass::Regular,
        }
    }

    pub fn is_regular(self) -> bool {
        self.class() == KindClass::Regular
    }

    pub fn is_replaceable(self) -> bool {
        self.class() == KindClass::Replaceable
    }

    pub fn is_ephemeral(self) -> bool {
        self.class() == KindClass::Ephemeral
    }

    pub fn is_addressable(self) -> bool {
        self.class() == KindClass::Addressable
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KindClass {
    Regular,
    Replaceable,
    Ephemeral,
    Addressable,
}

impl fmt::Display for Kind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl TryFrom<u64> for Kind {
    type Error = String;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tag {
    values: Vec<String>,
}

impl Tag {
    pub fn new(values: Vec<String>) -> Result<Self, String> {
        let Some(name) = values.first() else {
            return Err(empty_error("tag"));
        };
        TagName::new(name)?;
        Ok(Self { values })
    }

    pub fn from_parts(name: &str, values: &[&str]) -> Result<Self, String> {
        let values = core::iter::once(name)
            .chain(values.iter().copied())
            .map(str::to_owned)
            .collect();
        Self::new(values)
    }

    pub fn name(&self) -> TagName {
        TagName(self.values[0].clone())
    }

    pub fn value(&self) -> Option<TagValue> {
        self.values.get(1).map(|value| TagValue(value.clone()))
    }

    pub fn values(&self) -> &[String] {
        &self.values
    }

    pub fn indexed_pair(&self) -> Option<(&str, &str)> {
        let name = self.values[0].as_str();
        if !TagName::is_indexable_name(name) {
            return None;
        }
        self.values.get(1).map(|value| (name, value.as_str()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TagName(String);

impl TagName {
    pub fn new(value: &str) -> Result<Self, String> {
        if value.is_empty() {
            return Err(empty_error("tag name"));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_indexable(&self) -> bool {
        Self::is_indexable_name(self.as_str())
    }

    pub fn is_indexable_name(value: &str) -> bool {
        let mut bytes = value.bytes();
        let Some(byte) = bytes.next() else {
            return false;
        };
        bytes.next().is_none() && byte.is_ascii_alphabetic()
    }
}

impl fmt::Display for TagName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for TagName {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TagValue(String);

impl TagValue {
    pub fn new(value: &str) -> Self {
        Self(value.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TagValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedEvent {
    pubkey: PublicKeyHex,
    created_at: UnixTimestamp,
    kind: Kind,
    tags: Vec<Tag>,
    content: String,
}

impl UnsignedEvent {
    pub fn new(
        pubkey: PublicKeyHex,
        created_at: UnixTimestamp,
        kind: Kind,
        tags: Vec<Tag>,
        content: &str,
    ) -> Self {
        Self {
            pubkey,
            created_at,
            kind,
            tags,
            content: content.to_owned(),
        }
    }

    pub fn pubkey(&self) -> &PublicKeyHex {
        &self.pubkey
    }

    pub fn created_at(&self) -> UnixTimestamp {
        self.created_at
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn tags(&self) -> &[Tag] {
        &self.tags
    }

    pub fn content(&self) -> &str {
        &self.content
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    id: EventId,
    unsigned: UnsignedEvent,
    sig: SignatureHex,
}

impl Event {
    pub fn new(id: EventId, unsigned: UnsignedEvent, sig: SignatureHex) -> Self {
        Self { id, unsigned, sig }
    }

    pub fn id(&self) -> &EventId {
        &self.id
    }

    pub fn unsigned(&self) -> &UnsignedEvent {
        &self.unsigned
    }

    pub fn sig(&self) -> &SignatureHex {
        &self.sig
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEventJson(String);

impl RawEventJson {
    pub fn new(value: &str) -> Result<Self, EventShapeError> {
        if value.is_empty() {
            return Err(EventShapeError::empty_raw_json());
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

pub struct EventShapeError {
    message: String,
}

impl EventShapeError {
    pub fn missing_field(field: &'static str) -> Self {
        Self {
            message: format!("event field `{field}` is missing"),
        }
    }

    pub fn invalid_field(field: &'static str, reason: &str) -> Self {
        Self {
            message: format!("event field `{field}` is invalid: {reason}"),
        }
    }

    fn empty_raw_json() -> Self {
        Self {
            message: "raw event JSON must not be empty".to_owned(),
        }
    }
}

impl fmt::Display for EventShapeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl fmt::Debug for EventShapeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventShapeError")
            .field("message", &self.message)
            .finish()
    }
}

impl std::error::Error for EventShapeError {}

pub fn canonical_event_json(event: &UnsignedEvent) -> String {
    let tags: Vec<serde_json::Value> = event
        .tags()
        .iter()
        .map(|tag| {
            serde_json::Value::Array(
                tag.values()
                    .iter()
                    .map(|value| serde_json::Value::String(value.clone()))
                    .collect(),
            )
        })
        .collect();
    serde_json::json!([
        0,
        event.pubkey().as_str(),
        event.created_at().as_u64(),
        event.kind().as_u32(),
        tags,
        event.content()
    ])
    .to_string()
}

impl UnsignedEvent {
    pub fn canonical_json(&self) -> String {
        canonical_event_json(self)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClientMessage {
    Event(Event),
    Req {
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
    },
    Close(SubscriptionId),
    Auth(Event),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    ids: Vec<EventId>,
    authors: Vec<PublicKeyHex>,
    kinds: Vec<Kind>,
    tag_filters: BTreeMap<TagName, Vec<TagValue>>,
    since: Option<UnixTimestamp>,
    until: Option<UnixTimestamp>,
    limit: Option<u64>,
    search: Option<String>,
}

impl Filter {
    pub fn empty() -> Self {
        Self {
            ids: Vec::new(),
            authors: Vec::new(),
            kinds: Vec::new(),
            tag_filters: BTreeMap::new(),
            since: None,
            until: None,
            limit: None,
            search: None,
        }
    }

    pub fn ids(&self) -> &[EventId] {
        &self.ids
    }

    pub fn authors(&self) -> &[PublicKeyHex] {
        &self.authors
    }

    pub fn kinds(&self) -> &[Kind] {
        &self.kinds
    }

    pub fn tag_filters(&self) -> &BTreeMap<TagName, Vec<TagValue>> {
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

    pub fn search(&self) -> Option<&str> {
        self.search.as_deref()
    }

    pub fn matches(&self, event: &Event) -> bool {
        if !self.ids.is_empty() && !self.ids.iter().any(|id| id == event.id()) {
            return false;
        }
        if !self.authors.is_empty()
            && !self
                .authors
                .iter()
                .any(|author| author == event.unsigned().pubkey())
        {
            return false;
        }
        if !self.kinds.is_empty()
            && !self
                .kinds
                .iter()
                .any(|kind| *kind == event.unsigned().kind())
        {
            return false;
        }
        if let Some(since) = self.since
            && event.unsigned().created_at().as_u64() < since.as_u64()
        {
            return false;
        }
        if let Some(until) = self.until
            && event.unsigned().created_at().as_u64() > until.as_u64()
        {
            return false;
        }
        for (name, values) in &self.tag_filters {
            let matched = event.unsigned().tags().iter().any(|tag| {
                tag.indexed_pair().is_some_and(|(tag_name, tag_value)| {
                    tag_name == name.as_str()
                        && values.iter().any(|value| value.as_str() == tag_value)
                })
            });
            if !matched {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RelayMessage {
    Event {
        subscription_id: SubscriptionId,
        event: Event,
    },
    Ok {
        event_id: EventId,
        accepted: bool,
        message: String,
    },
    Eose(SubscriptionId),
    Closed {
        subscription_id: SubscriptionId,
        message: String,
    },
    Notice(String),
    Auth(String),
}

impl RelayMessage {
    pub fn encode(&self) -> String {
        encode_relay_message(self)
    }
}

pub fn encode_relay_message(message: &RelayMessage) -> String {
    relay_message_to_value(message).to_string()
}

pub fn relay_message_to_value(message: &RelayMessage) -> serde_json::Value {
    match message {
        RelayMessage::Event {
            subscription_id,
            event,
        } => serde_json::json!(["EVENT", subscription_id.as_str(), event_to_value(event)]),
        RelayMessage::Ok {
            event_id,
            accepted,
            message,
        } => serde_json::json!(["OK", event_id.as_str(), accepted, message]),
        RelayMessage::Eose(subscription_id) => {
            serde_json::json!(["EOSE", subscription_id.as_str()])
        }
        RelayMessage::Closed {
            subscription_id,
            message,
        } => serde_json::json!(["CLOSED", subscription_id.as_str(), message]),
        RelayMessage::Notice(message) => serde_json::json!(["NOTICE", message]),
        RelayMessage::Auth(challenge) => serde_json::json!(["AUTH", challenge]),
    }
}

pub fn event_to_value(event: &Event) -> serde_json::Value {
    let tags = event
        .unsigned()
        .tags()
        .iter()
        .map(|tag| {
            serde_json::Value::Array(
                tag.values()
                    .iter()
                    .map(|value| serde_json::Value::String(value.clone()))
                    .collect(),
            )
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "id": event.id().as_str(),
        "pubkey": event.unsigned().pubkey().as_str(),
        "created_at": event.unsigned().created_at().as_u64(),
        "kind": event.unsigned().kind().as_u32(),
        "tags": tags,
        "content": event.unsigned().content(),
        "sig": event.sig().as_str()
    })
}

pub fn filter_from_value(value: &serde_json::Value) -> Result<Filter, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "filter must be a JSON object".to_owned())?;
    let mut filter = Filter::empty();
    for (field, raw) in object {
        match field.as_str() {
            "ids" => filter.ids = parse_event_id_filter_array(field, raw)?,
            "authors" => filter.authors = parse_pubkey_filter_array(field, raw)?,
            "kinds" => filter.kinds = parse_kind_filter_array(field, raw)?,
            "since" => filter.since = Some(UnixTimestamp::new(parse_u64_filter_field(field, raw)?)),
            "until" => filter.until = Some(UnixTimestamp::new(parse_u64_filter_field(field, raw)?)),
            "limit" => filter.limit = Some(parse_u64_filter_field(field, raw)?),
            "search" => filter.search = Some(parse_string_filter_field(field, raw)?.to_owned()),
            tag_field if tag_field.starts_with('#') => {
                let (name, values) = parse_tag_filter_field(tag_field, raw)?;
                filter.tag_filters.insert(name, values);
            }
            unsupported => return Err(format!("filter field `{unsupported}` is unsupported")),
        }
    }
    Ok(filter)
}

pub fn parse_client_message(raw: &str) -> Result<ClientMessage, String> {
    let value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|source| format!("client message JSON is invalid: {source}"))?;
    let array = value
        .as_array()
        .ok_or_else(|| "client message must be an array".to_owned())?;
    let command_value = array
        .first()
        .ok_or_else(|| "client message command is missing".to_owned())?;
    let command = command_value
        .as_str()
        .ok_or_else(|| "client message command must be a string".to_owned())?;
    match command {
        "EVENT" => parse_event_client_message(array),
        "REQ" => parse_req_client_message(array),
        "CLOSE" => parse_close_client_message(array),
        "AUTH" => parse_auth_client_message(array),
        unsupported => Err(format!(
            "client message command `{unsupported}` is unsupported"
        )),
    }
}

pub fn parse_event_json(raw: &RawEventJson) -> Result<Event, EventShapeError> {
    let value = serde_json::from_str(raw.as_str()).map_err(|source| {
        EventShapeError::invalid_field("event", &format!("invalid JSON: {source}"))
    })?;
    event_from_value(&value)
}

pub fn event_from_value(value: &serde_json::Value) -> Result<Event, EventShapeError> {
    let object = value
        .as_object()
        .ok_or_else(|| EventShapeError::invalid_field("event", "must be an object"))?;
    let id = EventId::new(field_string(object, "id")?)
        .map_err(|reason| EventShapeError::invalid_field("id", &reason))?;
    let pubkey = PublicKeyHex::new(field_string(object, "pubkey")?)
        .map_err(|reason| EventShapeError::invalid_field("pubkey", &reason))?;
    let created_at = UnixTimestamp::new(field_u64(object, "created_at")?);
    let kind = Kind::new(field_u64(object, "kind")?)
        .map_err(|reason| EventShapeError::invalid_field("kind", &reason))?;
    let tags = tags_from_value(field_value(object, "tags")?)?;
    let content = field_string(object, "content")?;
    let sig = SignatureHex::new(field_string(object, "sig")?)
        .map_err(|reason| EventShapeError::invalid_field("sig", &reason))?;
    Ok(Event::new(
        id,
        UnsignedEvent::new(pubkey, created_at, kind, tags, content),
        sig,
    ))
}

fn parse_event_client_message(array: &[serde_json::Value]) -> Result<ClientMessage, String> {
    if array.len() != 2 {
        return Err("EVENT client message must contain exactly 2 elements".to_owned());
    }
    event_from_value(&array[1])
        .map(ClientMessage::Event)
        .map_err(|source| source.to_string())
}

fn parse_auth_client_message(array: &[serde_json::Value]) -> Result<ClientMessage, String> {
    if array.len() != 2 {
        return Err("AUTH client message must contain exactly 2 elements".to_owned());
    }
    event_from_value(&array[1])
        .map(ClientMessage::Auth)
        .map_err(|source| source.to_string())
}

fn parse_req_client_message(array: &[serde_json::Value]) -> Result<ClientMessage, String> {
    if array.len() < 3 {
        return Err("REQ client message must contain a subscription id and filters".to_owned());
    }
    let subscription_id = array[1]
        .as_str()
        .ok_or_else(|| "REQ subscription id must be a string".to_owned())
        .and_then(SubscriptionId::new)?;
    let filters = array[2..]
        .iter()
        .map(filter_from_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ClientMessage::Req {
        subscription_id,
        filters,
    })
}

fn parse_close_client_message(array: &[serde_json::Value]) -> Result<ClientMessage, String> {
    if array.len() != 2 {
        return Err("CLOSE client message must contain exactly 2 elements".to_owned());
    }
    array[1]
        .as_str()
        .ok_or_else(|| "CLOSE subscription id must be a string".to_owned())
        .and_then(SubscriptionId::new)
        .map(ClientMessage::Close)
}

fn field_value<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<&'a serde_json::Value, EventShapeError> {
    object
        .get(field)
        .ok_or_else(|| EventShapeError::missing_field(field))
}

fn field_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<&'a str, EventShapeError> {
    field_value(object, field)?
        .as_str()
        .ok_or_else(|| EventShapeError::invalid_field(field, "must be a string"))
}

fn field_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<u64, EventShapeError> {
    field_value(object, field)?
        .as_u64()
        .ok_or_else(|| EventShapeError::invalid_field(field, "must be an unsigned integer"))
}

fn tags_from_value(value: &serde_json::Value) -> Result<Vec<Tag>, EventShapeError> {
    let array = value
        .as_array()
        .ok_or_else(|| EventShapeError::invalid_field("tags", "must be an array"))?;
    array
        .iter()
        .map(|tag| {
            let values = tag
                .as_array()
                .ok_or_else(|| EventShapeError::invalid_field("tags", "tag must be an array"))?
                .iter()
                .map(|part| {
                    part.as_str().map(str::to_owned).ok_or_else(|| {
                        EventShapeError::invalid_field("tags", "tag elements must be strings")
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Tag::new(values).map_err(|reason| EventShapeError::invalid_field("tags", &reason))
        })
        .collect()
}

fn parse_event_id_filter_array(
    field: &str,
    value: &serde_json::Value,
) -> Result<Vec<EventId>, String> {
    parse_string_filter_array(field, value, |item| {
        EventId::new(item).map_err(|reason| format!("filter field `{field}` is invalid: {reason}"))
    })
}

fn parse_pubkey_filter_array(
    field: &str,
    value: &serde_json::Value,
) -> Result<Vec<PublicKeyHex>, String> {
    parse_string_filter_array(field, value, |item| {
        PublicKeyHex::new(item)
            .map_err(|reason| format!("filter field `{field}` is invalid: {reason}"))
    })
}

fn parse_kind_filter_array(field: &str, value: &serde_json::Value) -> Result<Vec<Kind>, String> {
    parse_u64_filter_array(field, value, |item| {
        Kind::new(item).map_err(|reason| format!("filter field `{field}` is invalid: {reason}"))
    })
}

fn parse_tag_filter_field(
    field: &str,
    value: &serde_json::Value,
) -> Result<(TagName, Vec<TagValue>), String> {
    let name = &field[1..];
    let tag_name = TagName::new(name)
        .map_err(|reason| format!("filter field `{field}` is invalid: {reason}"))?;
    if !tag_name.is_indexable() {
        return Err(format!(
            "filter field `{field}` is invalid: tag name must be a single ASCII letter"
        ));
    }
    let values = parse_string_filter_array(field, value, |item| {
        if name == "e" {
            EventId::new(item)
                .map(|_| TagValue::new(item))
                .map_err(|reason| format!("filter field `{field}` is invalid: {reason}"))
        } else if name == "p" {
            PublicKeyHex::new(item)
                .map(|_| TagValue::new(item))
                .map_err(|reason| format!("filter field `{field}` is invalid: {reason}"))
        } else {
            Ok(TagValue::new(item))
        }
    })?;
    Ok((tag_name, values))
}

fn parse_string_filter_array<T>(
    field: &str,
    value: &serde_json::Value,
    parse_item: impl Fn(&str) -> Result<T, String>,
) -> Result<Vec<T>, String> {
    let array = value.as_array().ok_or_else(|| filter_array_error(field))?;
    if array.is_empty() {
        return Err(filter_array_error(field));
    }
    array
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| format!("filter field `{field}` values must be strings"))
                .and_then(&parse_item)
        })
        .collect()
}

fn parse_u64_filter_array<T>(
    field: &str,
    value: &serde_json::Value,
    parse_item: impl Fn(u64) -> Result<T, String>,
) -> Result<Vec<T>, String> {
    let array = value.as_array().ok_or_else(|| filter_array_error(field))?;
    if array.is_empty() {
        return Err(filter_array_error(field));
    }
    array
        .iter()
        .map(|item| {
            item.as_u64()
                .ok_or_else(|| format!("filter field `{field}` values must be unsigned integers"))
                .and_then(&parse_item)
        })
        .collect()
}

fn parse_u64_filter_field(field: &str, value: &serde_json::Value) -> Result<u64, String> {
    value
        .as_u64()
        .ok_or_else(|| format!("filter field `{field}` must be an unsigned integer"))
}

fn parse_string_filter_field<'a>(
    field: &str,
    value: &'a serde_json::Value,
) -> Result<&'a str, String> {
    value
        .as_str()
        .ok_or_else(|| format!("filter field `{field}` must be a string"))
}

fn filter_array_error(field: &str) -> String {
    format!("filter field `{field}` must be a non-empty array")
}

fn require_lowercase_hex(scalar: &'static str, value: &str, expected: usize) -> Result<(), String> {
    let actual = value.chars().count();
    if actual != expected {
        return Err(invalid_length_error(scalar, expected, actual));
    }
    if value
        .bytes()
        .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(non_lowercase_hex_error(scalar));
    }
    Ok(())
}

fn empty_error(scalar: &'static str) -> String {
    format!("{scalar} must not be empty")
}

fn invalid_length_error(scalar: &'static str, expected: usize, actual: usize) -> String {
    format!("{scalar} must be {expected} characters, got {actual}")
}

fn too_long_error(scalar: &'static str, max: usize, actual: usize) -> String {
    format!("{scalar} must be at most {max} characters, got {actual}")
}

fn non_lowercase_hex_error(scalar: &'static str) -> String {
    format!("{scalar} must be lowercase hex")
}

fn kind_out_of_range_error(value: u64) -> String {
    format!("kind must fit in u32, got {value}")
}

#[cfg(test)]
mod tests {
    use super::{
        ClientMessage, Event, EventId, EventShapeError, Filter, Kind, KindClass, PublicKeyHex,
        RawEventJson, RelayMessage, SignatureHex, SubscriptionId, Tag, TagName, TagValue,
        UnixTimestamp, UnsignedEvent, canonical_event_json, empty_error, encode_relay_message,
        event_from_value, event_to_value, filter_from_value, invalid_length_error,
        kind_out_of_range_error, non_lowercase_hex_error, parse_client_message, parse_event_json,
        relay_message_to_value, too_long_error,
    };
    use core::str::FromStr;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    #[test]
    fn event_id_accepts_lowercase_hex() {
        let value = "0".repeat(EventId::HEX_LENGTH);
        let event_id = EventId::new(&value).expect("event id");

        assert_eq!(event_id.as_str(), value);
        assert_eq!(event_id.to_string(), value);
        let cloned = event_id.clone();
        let mut hasher = DefaultHasher::new();
        cloned.hash(&mut hasher);
        assert_ne!(hasher.finish(), 0);
        assert_eq!(format!("{cloned:?}"), format!("EventId(\"{value}\")"));
        assert!(cloned <= event_id);
        assert_eq!(EventId::from_str(&value), Ok(event_id));
    }

    #[test]
    fn fixed_hex_scalars_reject_bad_lengths_and_characters() {
        assert_eq!(
            EventId::new(&"0".repeat(EventId::HEX_LENGTH - 1)),
            Err(format!(
                "event id must be {} characters, got {}",
                EventId::HEX_LENGTH,
                EventId::HEX_LENGTH - 1
            ))
        );
        assert_eq!(
            EventId::new("bad"),
            Err("event id must be 64 characters, got 3".to_owned())
        );
        let invalid_public_key = format!("{}G", "0".repeat(PublicKeyHex::HEX_LENGTH - 1));
        assert_eq!(
            PublicKeyHex::new(&invalid_public_key),
            Err("public key must be lowercase hex".to_owned())
        );
        let invalid_signature = format!("{}A", "0".repeat(SignatureHex::HEX_LENGTH - 1));
        assert_eq!(
            SignatureHex::new(&invalid_signature),
            Err("signature must be lowercase hex".to_owned())
        );
    }

    #[test]
    fn public_key_and_signature_display_values() {
        let public_key_value = "1".repeat(PublicKeyHex::HEX_LENGTH);
        let signature_value = "2".repeat(SignatureHex::HEX_LENGTH);
        let public_key = PublicKeyHex::new(&public_key_value).expect("pubkey");
        let signature = SignatureHex::new(&signature_value).expect("sig");

        assert_eq!(public_key.as_str(), "1".repeat(PublicKeyHex::HEX_LENGTH));
        assert_eq!(signature.as_str(), "2".repeat(SignatureHex::HEX_LENGTH));
        assert_eq!(public_key.to_string(), public_key.as_str());
        assert_eq!(signature.to_string(), signature.as_str());
        assert_eq!(PublicKeyHex::from_str(public_key.as_str()), Ok(public_key));
        assert_eq!(SignatureHex::from_str(signature.as_str()), Ok(signature));
    }

    #[test]
    fn subscription_id_rejects_empty_and_overlong_values() {
        assert_eq!(
            SubscriptionId::new(""),
            Err("subscription id must not be empty".to_owned())
        );
        assert_eq!(
            SubscriptionId::new(&"x".repeat(SubscriptionId::MAX_LENGTH + 1)),
            Err(format!(
                "subscription id must be at most {} characters, got {}",
                SubscriptionId::MAX_LENGTH,
                SubscriptionId::MAX_LENGTH + 1
            ))
        );
        let subscription = SubscriptionId::new("radroots").expect("subscription");
        assert_eq!(subscription.as_str(), "radroots");
        assert_eq!(subscription.to_string(), "radroots");
        assert_eq!(SubscriptionId::from_str("radroots"), Ok(subscription));
    }

    #[test]
    fn timestamp_and_kind_expose_numeric_values() {
        let timestamp = UnixTimestamp::new(1_714_124_433);
        let kind = Kind::new(30_402).expect("kind");

        assert_eq!(timestamp.as_u64(), 1_714_124_433);
        assert_eq!(timestamp.to_string(), "1714124433");
        assert_eq!(UnixTimestamp::from(7).as_u64(), 7);
        assert_eq!(kind.as_u32(), 30_402);
        assert_eq!(kind.to_string(), "30402");
        assert_eq!(Kind::try_from(30_402), Ok(kind));
    }

    #[test]
    fn kind_rejects_values_outside_u32() {
        let value = u64::from(u32::MAX) + 1;

        assert_eq!(
            Kind::new(value),
            Err(format!("kind must fit in u32, got {value}"))
        );
        assert_eq!(
            kind_out_of_range_error(value),
            format!("kind must fit in u32, got {value}")
        );
    }

    #[test]
    fn event_kind_classification_matches_nip01_ranges() {
        for value in [1, 2, 4, 44, 1_000, 9_999, 45, 40_000] {
            let kind = Kind::new(value).expect("regular");
            assert_eq!(kind.class(), KindClass::Regular);
            assert!(kind.is_regular());
            assert!(!kind.is_replaceable());
            assert!(!kind.is_ephemeral());
            assert!(!kind.is_addressable());
        }

        for value in [0, 3, 10_000, 19_999] {
            let kind = Kind::new(value).expect("replaceable");
            assert_eq!(kind.class(), KindClass::Replaceable);
            assert!(kind.is_replaceable());
        }

        for value in [20_000, 29_999] {
            let kind = Kind::new(value).expect("ephemeral");
            assert_eq!(kind.class(), KindClass::Ephemeral);
            assert!(kind.is_ephemeral());
        }

        for value in [30_000, 39_999] {
            let kind = Kind::new(value).expect("addressable");
            assert_eq!(kind.class(), KindClass::Addressable);
            assert!(kind.is_addressable());
        }

        assert_eq!(format!("{:?}", KindClass::Regular), "Regular");
        assert_eq!(KindClass::Regular, KindClass::Regular);
    }

    #[test]
    fn scalar_errors_have_stable_messages() {
        assert_eq!(empty_error("id"), "id must not be empty");
        assert_eq!(
            invalid_length_error("id", 64, 63),
            "id must be 64 characters, got 63"
        );
        assert_eq!(
            too_long_error("id", 64, 65),
            "id must be at most 64 characters, got 65"
        );
        assert_eq!(non_lowercase_hex_error("id"), "id must be lowercase hex");
    }

    #[test]
    fn tag_model_preserves_tag_arrays_and_extracts_first_values() {
        let tag = Tag::from_parts("e", &["event-id", "wss://relay.example"]).expect("tag");

        assert_eq!(tag.name(), TagName::new("e").expect("name"));
        assert_eq!(tag.value(), Some(TagValue::new("event-id")));
        assert_eq!(
            tag.values(),
            &[
                "e".to_owned(),
                "event-id".to_owned(),
                "wss://relay.example".to_owned()
            ]
        );
        assert_eq!(tag.indexed_pair(), Some(("e", "event-id")));
        assert_eq!(tag.name().to_string(), "e");
        assert_eq!(tag.value().expect("value").to_string(), "event-id");
    }

    #[test]
    fn tag_model_rejects_empty_arrays_and_names() {
        assert_eq!(
            Tag::new(Vec::new()),
            Err("tag must not be empty".to_owned())
        );
        assert_eq!(
            Tag::new(vec![String::new()]),
            Err("tag name must not be empty".to_owned())
        );
        assert_eq!(
            TagName::new(""),
            Err("tag name must not be empty".to_owned())
        );
    }

    #[test]
    fn tag_indexing_is_limited_to_single_ascii_letters() {
        let uppercase = Tag::from_parts("E", &["root"]).expect("uppercase");
        let missing_value = Tag::from_parts("p", &[]).expect("missing value");
        let long_name = Tag::from_parts("alt", &["reply"]).expect("long name");
        let non_ascii = Tag::from_parts("é", &["value"]).expect("non ascii");

        assert!(TagName::from_str("A").expect("name").is_indexable());
        assert!(TagName::is_indexable_name("z"));
        assert_eq!(uppercase.indexed_pair(), Some(("E", "root")));
        assert_eq!(missing_value.indexed_pair(), None);
        assert_eq!(long_name.indexed_pair(), None);
        assert_eq!(non_ascii.indexed_pair(), None);
        assert!(!TagName::is_indexable_name(""));
        assert!(!TagName::is_indexable_name("aa"));
        assert!(!TagName::is_indexable_name("1"));
        assert_eq!(TagValue::new("").as_str(), "");
    }

    #[test]
    fn unsigned_event_exposes_nostr_event_shape() {
        let pubkey = PublicKeyHex::new(&"1".repeat(PublicKeyHex::HEX_LENGTH)).expect("pubkey");
        let tag = Tag::from_parts("p", &["peer"]).expect("tag");
        let event = UnsignedEvent::new(
            pubkey.clone(),
            UnixTimestamp::new(1_714_124_433),
            Kind::new(1).expect("kind"),
            vec![tag.clone()],
            "hello",
        );

        assert_eq!(event.pubkey(), &pubkey);
        assert_eq!(event.created_at().as_u64(), 1_714_124_433);
        assert_eq!(event.kind().as_u32(), 1);
        assert_eq!(event.tags(), &[tag]);
        assert_eq!(event.content(), "hello");
        assert!(format!("{event:?}").contains("UnsignedEvent"));
    }

    #[test]
    fn signed_event_wraps_id_unsigned_shape_and_signature() {
        let id = EventId::new(&"a".repeat(EventId::HEX_LENGTH)).expect("id");
        let sig = SignatureHex::new(&"b".repeat(SignatureHex::HEX_LENGTH)).expect("sig");
        let unsigned = UnsignedEvent::new(
            PublicKeyHex::new(&"c".repeat(PublicKeyHex::HEX_LENGTH)).expect("pubkey"),
            UnixTimestamp::new(1),
            Kind::new(1).expect("kind"),
            Vec::new(),
            "",
        );
        let event = Event::new(id.clone(), unsigned.clone(), sig.clone());

        assert_eq!(event.id(), &id);
        assert_eq!(event.unsigned(), &unsigned);
        assert_eq!(event.sig(), &sig);
        assert_eq!(event.clone(), Event::new(id, unsigned, sig));
        assert!(format!("{event:?}").contains("Event"));
    }

    #[test]
    fn raw_event_json_rejects_empty_input_and_preserves_bytes() {
        assert_eq!(
            RawEventJson::new("").expect_err("empty").to_string(),
            "raw event JSON must not be empty"
        );
        let raw = RawEventJson::new("{\"kind\":1}").expect("raw");

        assert_eq!(raw.as_str(), "{\"kind\":1}");
        assert_eq!(raw.clone().into_string(), "{\"kind\":1}");
        assert_eq!(format!("{raw:?}"), "RawEventJson(\"{\\\"kind\\\":1}\")");
    }

    #[test]
    fn event_shape_errors_have_stable_messages() {
        let missing = EventShapeError::missing_field("pubkey");
        let invalid = EventShapeError::invalid_field("kind", "must be unsigned integer");

        assert_eq!(missing.to_string(), "event field `pubkey` is missing");
        assert_eq!(
            invalid.to_string(),
            "event field `kind` is invalid: must be unsigned integer"
        );
        assert_eq!(
            format!("{missing:?}"),
            "EventShapeError { message: \"event field `pubkey` is missing\" }"
        );
    }

    #[test]
    fn parse_event_json_builds_typed_event_shape() {
        let raw = RawEventJson::new(&event_json("a", "b", 1, tags_json())).expect("raw");
        let event = parse_event_json(&raw).expect("event");

        assert_eq!(event.id().as_str(), "a".repeat(EventId::HEX_LENGTH));
        assert_eq!(
            event.unsigned().pubkey().as_str(),
            "1".repeat(PublicKeyHex::HEX_LENGTH)
        );
        assert_eq!(event.unsigned().created_at().as_u64(), 1_714_124_433);
        assert_eq!(event.unsigned().kind().as_u32(), 1);
        assert_eq!(event.unsigned().tags().len(), 2);
        assert_eq!(event.unsigned().content(), "hello");
        assert_eq!(event.sig().as_str(), "b".repeat(SignatureHex::HEX_LENGTH));
    }

    #[test]
    fn parse_client_message_accepts_event_auth_req_and_close() {
        let event_payload = event_json("a", "b", 1, tags_json());
        let auth_event_json = event_json("c", "d", 22242, "[]");
        let event_message = format!("[\"EVENT\",{event_payload}]");
        let auth_message = format!("[\"AUTH\",{auth_event_json}]");
        let req_message = "[\"REQ\",\"sub-a\",{\"ids\":[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]},{\"kinds\":[1]}]";
        let close_message = "[\"CLOSE\",\"sub-a\"]";
        let event =
            parse_event_json(&RawEventJson::new(&event_payload).expect("raw")).expect("event");
        let auth_event =
            parse_event_json(&RawEventJson::new(&auth_event_json).expect("raw")).expect("auth");

        assert_eq!(
            parse_client_message(&event_message),
            Ok(ClientMessage::Event(event))
        );
        assert_eq!(
            parse_client_message(&auth_message),
            Ok(ClientMessage::Auth(auth_event))
        );
        assert_eq!(
            parse_client_message(req_message),
            Ok(ClientMessage::Req {
                subscription_id: SubscriptionId::new("sub-a").expect("sub"),
                filters: vec![
                    filter_from_value(&serde_json::json!({"ids":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]})).expect("ids"),
                    filter_from_value(&serde_json::json!({"kinds":[1]})).expect("kinds")
                ]
            })
        );
        assert_eq!(
            parse_client_message(close_message).expect("close"),
            ClientMessage::Close(SubscriptionId::new("sub-a").expect("sub"))
        );
    }

    #[test]
    fn parse_client_message_rejects_malformed_envelopes() {
        assert!(
            parse_client_message("{")
                .expect_err("json")
                .starts_with("client message JSON is invalid")
        );
        assert_eq!(
            parse_client_message("{}").expect_err("object"),
            "client message must be an array"
        );
        assert_eq!(
            parse_client_message("[]").expect_err("empty"),
            "client message command is missing"
        );
        assert_eq!(
            parse_client_message("[1]").expect_err("command type"),
            "client message command must be a string"
        );
        assert_eq!(
            parse_client_message("[\"COUNT\"]").expect_err("unsupported"),
            "client message command `COUNT` is unsupported"
        );
        assert_eq!(
            parse_client_message("[\"EVENT\"]").expect_err("event length"),
            "EVENT client message must contain exactly 2 elements"
        );
        assert_eq!(
            parse_client_message("[\"EVENT\",{}]").expect_err("event shape"),
            "event field `id` is missing"
        );
        assert_eq!(
            parse_client_message("[\"AUTH\"]").expect_err("auth length"),
            "AUTH client message must contain exactly 2 elements"
        );
        assert_eq!(
            parse_client_message("[\"AUTH\",{}]").expect_err("auth shape"),
            "event field `id` is missing"
        );
        assert_eq!(
            parse_client_message("[\"REQ\",\"sub-a\"]").expect_err("req length"),
            "REQ client message must contain a subscription id and filters"
        );
        assert_eq!(
            parse_client_message("[\"REQ\",1,{}]").expect_err("req sub type"),
            "REQ subscription id must be a string"
        );
        assert_eq!(
            parse_client_message("[\"REQ\",\"\",{}]").expect_err("req sub empty"),
            "subscription id must not be empty"
        );
        assert_eq!(
            parse_client_message("[\"REQ\",\"sub-a\",1]").expect_err("req filter"),
            "filter must be a JSON object"
        );
        assert_eq!(
            parse_client_message("[\"CLOSE\"]").expect_err("close length"),
            "CLOSE client message must contain exactly 2 elements"
        );
        assert_eq!(
            parse_client_message("[\"CLOSE\",1]").expect_err("close sub type"),
            "CLOSE subscription id must be a string"
        );
    }

    #[test]
    fn parse_event_json_rejects_invalid_event_shapes() {
        assert_eq!(
            parse_event_json(&RawEventJson::new("{").expect("raw"))
                .expect_err("invalid json")
                .to_string(),
            "event field `event` is invalid: invalid JSON: EOF while parsing an object at line 1 column 1"
        );
        assert_eq!(
            event_from_value(&serde_json::json!(1))
                .expect_err("not object")
                .to_string(),
            "event field `event` is invalid: must be an object"
        );
        assert_eq!(
            event_from_value(&serde_json::json!({}))
                .expect_err("missing id")
                .to_string(),
            "event field `id` is missing"
        );
        assert_eq!(
            event_from_value(&event_value_without("created_at"))
                .expect_err("missing created_at")
                .to_string(),
            "event field `created_at` is missing"
        );
        assert_eq!(
            event_from_value(&event_value_with("id", serde_json::json!(1)))
                .expect_err("id type")
                .to_string(),
            "event field `id` is invalid: must be a string"
        );
        assert_eq!(
            event_from_value(&event_value_with("id", serde_json::json!("bad")))
                .expect_err("id scalar")
                .to_string(),
            "event field `id` is invalid: event id must be 64 characters, got 3"
        );
        assert_eq!(
            event_from_value(&event_value_with("pubkey", serde_json::json!("bad")))
                .expect_err("pubkey scalar")
                .to_string(),
            "event field `pubkey` is invalid: public key must be 64 characters, got 3"
        );
        assert_eq!(
            event_from_value(&event_value_with("created_at", serde_json::json!("now")))
                .expect_err("created type")
                .to_string(),
            "event field `created_at` is invalid: must be an unsigned integer"
        );
        assert_eq!(
            event_from_value(&event_value_with(
                "kind",
                serde_json::json!(u64::from(u32::MAX) + 1)
            ))
            .expect_err("kind range")
            .to_string(),
            format!(
                "event field `kind` is invalid: kind must fit in u32, got {}",
                u64::from(u32::MAX) + 1
            )
        );
        assert_eq!(
            event_from_value(&event_value_with("tags", serde_json::json!(1)))
                .expect_err("tags type")
                .to_string(),
            "event field `tags` is invalid: must be an array"
        );
        assert_eq!(
            event_from_value(&event_value_with("tags", serde_json::json!([1])))
                .expect_err("tag type")
                .to_string(),
            "event field `tags` is invalid: tag must be an array"
        );
        assert_eq!(
            event_from_value(&event_value_with("tags", serde_json::json!([[1]])))
                .expect_err("tag part type")
                .to_string(),
            "event field `tags` is invalid: tag elements must be strings"
        );
        assert_eq!(
            event_from_value(&event_value_with("tags", serde_json::json!([[]])))
                .expect_err("tag empty")
                .to_string(),
            "event field `tags` is invalid: tag must not be empty"
        );
        assert_eq!(
            event_from_value(&event_value_with("content", serde_json::json!(1)))
                .expect_err("content type")
                .to_string(),
            "event field `content` is invalid: must be a string"
        );
        assert_eq!(
            event_from_value(&event_value_with("sig", serde_json::json!("bad")))
                .expect_err("sig scalar")
                .to_string(),
            "event field `sig` is invalid: signature must be 128 characters, got 3"
        );
    }

    #[test]
    fn filter_model_parses_core_fields_and_matches_events() {
        let event_tag = "e".repeat(EventId::HEX_LENGTH);
        let event = event_for_filter(&event_tag, 50, 1);
        let filter = filter_from_value(&serde_json::json!({
            "ids": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "authors": ["1111111111111111111111111111111111111111111111111111111111111111"],
            "kinds": [1],
            "#e": [event_tag],
            "#p": ["1111111111111111111111111111111111111111111111111111111111111111"],
            "#t": ["radroots"],
            "since": 40,
            "until": 60,
            "limit": 5,
            "search": "fresh carrots"
        }))
        .expect("filter");

        assert_eq!(filter.ids()[0].as_str(), "a".repeat(EventId::HEX_LENGTH));
        assert_eq!(
            filter.authors()[0].as_str(),
            "1".repeat(PublicKeyHex::HEX_LENGTH)
        );
        assert_eq!(filter.kinds()[0].as_u32(), 1);
        assert_eq!(filter.since().expect("since").as_u64(), 40);
        assert_eq!(filter.until().expect("until").as_u64(), 60);
        assert_eq!(filter.limit(), Some(5));
        assert_eq!(filter.search(), Some("fresh carrots"));
        assert_eq!(
            filter
                .tag_filters()
                .get(&TagName::new("t").expect("tag"))
                .expect("tag")[0]
                .as_str(),
            "radroots"
        );
        assert!(filter.matches(&event));
        assert!(Filter::empty().matches(&event));
        assert_eq!(Filter::empty().limit(), None);
        assert_eq!(Filter::empty().search(), None);
    }

    #[test]
    fn filter_model_rejects_non_matching_events() {
        let event_tag = "e".repeat(EventId::HEX_LENGTH);
        let event = event_for_filter(&event_tag, 50, 1);

        assert!(
            !filter_from_value(&serde_json::json!({
                "ids": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
            }))
            .expect("id filter")
            .matches(&event)
        );
        assert!(
            !filter_from_value(&serde_json::json!({
                "authors": ["2222222222222222222222222222222222222222222222222222222222222222"]
            }))
            .expect("author filter")
            .matches(&event)
        );
        assert!(
            !filter_from_value(&serde_json::json!({"kinds": [2]}))
                .expect("kind filter")
                .matches(&event)
        );
        assert!(
            !filter_from_value(&serde_json::json!({"since": 51}))
                .expect("since filter")
                .matches(&event)
        );
        assert!(
            !filter_from_value(&serde_json::json!({"until": 49}))
                .expect("until filter")
                .matches(&event)
        );
        assert!(
            !filter_from_value(&serde_json::json!({"#e": [
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            ]}))
            .expect("tag filter")
            .matches(&event)
        );
    }

    #[test]
    fn filter_model_rejects_invalid_filter_shapes() {
        assert_eq!(
            filter_from_value(&serde_json::json!(1)).expect_err("object"),
            "filter must be a JSON object"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"ids": 1})).expect_err("ids array"),
            "filter field `ids` must be a non-empty array"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"ids": []})).expect_err("ids empty"),
            "filter field `ids` must be a non-empty array"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"ids": [1]})).expect_err("ids string"),
            "filter field `ids` values must be strings"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"ids": ["bad"]})).expect_err("ids hex"),
            "filter field `ids` is invalid: event id must be 64 characters, got 3"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"authors": ["bad"]})).expect_err("author hex"),
            "filter field `authors` is invalid: public key must be 64 characters, got 3"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"authors": 1})).expect_err("authors array"),
            "filter field `authors` must be a non-empty array"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"authors": []})).expect_err("authors empty"),
            "filter field `authors` must be a non-empty array"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"authors": [1]})).expect_err("authors string"),
            "filter field `authors` values must be strings"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"kinds": 1})).expect_err("kinds array"),
            "filter field `kinds` must be a non-empty array"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"kinds": []})).expect_err("kinds empty"),
            "filter field `kinds` must be a non-empty array"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"kinds": ["one"]})).expect_err("kind integer"),
            "filter field `kinds` values must be unsigned integers"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"kinds": [u64::from(u32::MAX) + 1]}))
                .expect_err("kind range"),
            format!(
                "filter field `kinds` is invalid: kind must fit in u32, got {}",
                u64::from(u32::MAX) + 1
            )
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"since": "now"})).expect_err("since"),
            "filter field `since` must be an unsigned integer"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"until": "then"})).expect_err("until"),
            "filter field `until` must be an unsigned integer"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"limit": "ten"})).expect_err("limit"),
            "filter field `limit` must be an unsigned integer"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"search": 1})).expect_err("search"),
            "filter field `search` must be a string"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"#": ["value"]})).expect_err("tag empty"),
            "filter field `#` is invalid: tag name must not be empty"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"#aa": ["value"]})).expect_err("tag long"),
            "filter field `#aa` is invalid: tag name must be a single ASCII letter"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"#t": 1})).expect_err("tag array"),
            "filter field `#t` must be a non-empty array"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"#t": []})).expect_err("tag empty array"),
            "filter field `#t` must be a non-empty array"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"#t": [1]})).expect_err("tag string"),
            "filter field `#t` values must be strings"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"#e": ["bad"]})).expect_err("tag event id"),
            "filter field `#e` is invalid: event id must be 64 characters, got 3"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"#p": ["bad"]})).expect_err("tag pubkey"),
            "filter field `#p` is invalid: public key must be 64 characters, got 3"
        );
        assert_eq!(
            filter_from_value(&serde_json::json!({"unknown": true})).expect_err("unknown"),
            "filter field `unknown` is unsupported"
        );
    }

    #[test]
    fn relay_message_encoder_emits_nip01_and_nip42_messages() {
        let event = parse_event_json(
            &RawEventJson::new(&event_json("a", "b", 1, tags_json())).expect("raw"),
        )
        .expect("event");
        let subscription_id = SubscriptionId::new("sub-a").expect("sub");
        let accepted_id = EventId::new(&"c".repeat(EventId::HEX_LENGTH)).expect("id");
        let rejected_id = EventId::new(&"d".repeat(EventId::HEX_LENGTH)).expect("id");

        assert_eq!(
            relay_message_to_value(&RelayMessage::Event {
                subscription_id: subscription_id.clone(),
                event: event.clone()
            }),
            serde_json::json!(["EVENT", "sub-a", event_to_value(&event)])
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&encode_relay_message(&RelayMessage::Ok {
                event_id: accepted_id,
                accepted: true,
                message: String::new()
            }))
            .expect("ok"),
            serde_json::json!([
                "OK",
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                true,
                ""
            ])
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                &RelayMessage::Ok {
                    event_id: rejected_id,
                    accepted: false,
                    message: "invalid: event id mismatch".to_owned()
                }
                .encode()
            )
            .expect("rejected"),
            serde_json::json!([
                "OK",
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                false,
                "invalid: event id mismatch"
            ])
        );
        assert_eq!(
            relay_message_to_value(&RelayMessage::Eose(subscription_id.clone())),
            serde_json::json!(["EOSE", "sub-a"])
        );
        assert_eq!(
            relay_message_to_value(&RelayMessage::Closed {
                subscription_id,
                message: "unsupported: filter contains unknown elements".to_owned()
            }),
            serde_json::json!([
                "CLOSED",
                "sub-a",
                "unsupported: filter contains unknown elements"
            ])
        );
        assert_eq!(
            relay_message_to_value(&RelayMessage::Notice("maintenance window".to_owned())),
            serde_json::json!(["NOTICE", "maintenance window"])
        );
        assert_eq!(
            relay_message_to_value(&RelayMessage::Auth("challenge-a".to_owned())),
            serde_json::json!(["AUTH", "challenge-a"])
        );
    }

    #[test]
    fn event_to_value_round_trips_with_event_parser() {
        let event = parse_event_json(
            &RawEventJson::new(&event_json("e", "f", 30402, tags_json())).expect("raw"),
        )
        .expect("event");

        assert_eq!(
            event_from_value(&event_to_value(&event)).expect("parsed"),
            event
        );
    }

    #[test]
    fn canonical_event_json_serializes_empty_content_and_tags() {
        let event = unsigned_event(Vec::new(), "");

        assert_eq!(
            event.canonical_json(),
            include_str!("../tests/fixtures/canonical_empty_event.json").trim_end()
        );
        assert_eq!(canonical_event_json(&event), event.canonical_json());
    }

    #[test]
    fn canonical_event_json_serializes_escaped_content() {
        let event = unsigned_event(
            vec![Tag::from_parts("alt", &["quote"]).expect("tag")],
            "quote \" slash \\ newline\n",
        );

        assert_eq!(
            event.canonical_json(),
            include_str!("../tests/fixtures/canonical_escaped_event.json").trim_end()
        );
    }

    #[test]
    fn canonical_event_json_serializes_unicode_content() {
        let event = unsigned_event(
            vec![Tag::from_parts("t", &["radroots"]).expect("tag")],
            "radroots 🌱 café",
        );

        assert_eq!(
            event.canonical_json(),
            include_str!("../tests/fixtures/canonical_unicode_event.json").trim_end()
        );
    }

    #[test]
    fn canonical_event_json_preserves_repeated_tags() {
        let event = unsigned_event(
            vec![
                Tag::from_parts("e", &["one"]).expect("first e"),
                Tag::from_parts("e", &["two"]).expect("second e"),
                Tag::from_parts("p", &["peer", "wss://relay.example"]).expect("p"),
            ],
            "with repeated tags",
        );

        assert_eq!(
            event.canonical_json(),
            include_str!("../tests/fixtures/canonical_repeated_tags_event.json").trim_end()
        );
    }

    fn unsigned_event(tags: Vec<Tag>, content: &str) -> UnsignedEvent {
        UnsignedEvent::new(
            PublicKeyHex::new(&"1".repeat(PublicKeyHex::HEX_LENGTH)).expect("pubkey"),
            UnixTimestamp::new(1_714_124_433),
            Kind::new(1).expect("kind"),
            tags,
            content,
        )
    }

    fn event_for_filter(event_tag: &str, created_at: u64, kind: u64) -> Event {
        Event::new(
            EventId::new(&"a".repeat(EventId::HEX_LENGTH)).expect("id"),
            UnsignedEvent::new(
                PublicKeyHex::new(&"1".repeat(PublicKeyHex::HEX_LENGTH)).expect("pubkey"),
                UnixTimestamp::new(created_at),
                Kind::new(kind).expect("kind"),
                vec![
                    Tag::from_parts("e", &[event_tag]).expect("event tag"),
                    Tag::from_parts(
                        "p",
                        &["1111111111111111111111111111111111111111111111111111111111111111"],
                    )
                    .expect("pubkey tag"),
                    Tag::from_parts("t", &["radroots"]).expect("topic tag"),
                ],
                "hello",
            ),
            SignatureHex::new(&"b".repeat(SignatureHex::HEX_LENGTH)).expect("sig"),
        )
    }

    fn tags_json() -> &'static str {
        "[[\"e\",\"root\"],[\"p\",\"peer\",\"wss://relay.example\"]]"
    }

    fn event_json(id_char: &str, sig_char: &str, kind: u64, tags: &str) -> String {
        format!(
            "{{\"id\":\"{}\",\"pubkey\":\"{}\",\"created_at\":1714124433,\"kind\":{},\"tags\":{},\"content\":\"hello\",\"sig\":\"{}\"}}",
            id_char.repeat(EventId::HEX_LENGTH),
            "1".repeat(PublicKeyHex::HEX_LENGTH),
            kind,
            tags,
            sig_char.repeat(SignatureHex::HEX_LENGTH)
        )
    }

    fn event_value_with(field: &'static str, value: serde_json::Value) -> serde_json::Value {
        let mut event =
            serde_json::from_str::<serde_json::Value>(&event_json("a", "b", 1, tags_json()))
                .expect("event value");
        event
            .as_object_mut()
            .expect("event object")
            .insert(field.to_owned(), value);
        event
    }

    fn event_value_without(field: &'static str) -> serde_json::Value {
        let mut event =
            serde_json::from_str::<serde_json::Value>(&event_json("a", "b", 1, tags_json()))
                .expect("event value");
        event.as_object_mut().expect("event object").remove(field);
        event
    }
}
