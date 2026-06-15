#![forbid(unsafe_code)]

use core::fmt;
use core::str::FromStr;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DTag(String);

impl DTag {
    pub fn new(value: &str) -> Self {
        Self(value.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for DTag {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AddressKey(String);

impl AddressKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AddressKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AddressCoordinate {
    kind: Kind,
    pubkey: PublicKeyHex,
    d: DTag,
}

impl AddressCoordinate {
    pub fn new(kind: Kind, pubkey: PublicKeyHex, d: DTag) -> Result<Self, String> {
        if !kind.is_addressable() {
            return Err(format!(
                "address coordinate kind must be addressable, got {}",
                kind.as_u32()
            ));
        }
        Ok(Self { kind, pubkey, d })
    }

    pub fn from_event(event: &Event) -> Result<Option<Self>, String> {
        let kind = event.unsigned().kind();
        if !kind.is_addressable() {
            return Ok(None);
        }
        let d = event
            .unsigned()
            .tags()
            .iter()
            .find_map(|tag| {
                tag.indexed_pair().and_then(|(name, value)| {
                    if name == "d" {
                        Some(DTag::new(value))
                    } else {
                        None
                    }
                })
            })
            .ok_or_else(|| "addressable event must include a d tag".to_owned())?;
        Self::new(kind, event.unsigned().pubkey().clone(), d).map(Some)
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn pubkey(&self) -> &PublicKeyHex {
        &self.pubkey
    }

    pub fn d(&self) -> &DTag {
        &self.d
    }

    pub fn key(&self) -> AddressKey {
        AddressKey(self.to_string())
    }
}

impl fmt::Display for AddressCoordinate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}:{}",
            self.kind.as_u32(),
            self.pubkey.as_str(),
            self.d.as_str()
        )
    }
}

impl FromStr for AddressCoordinate {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut parts = value.splitn(3, ':');
        let kind = parts
            .next()
            .unwrap_or_default()
            .parse::<u64>()
            .map_err(|_| "address coordinate kind must be an unsigned integer".to_owned())
            .and_then(Kind::new)?;
        let pubkey = parts
            .next()
            .ok_or_else(|| "address coordinate pubkey is missing".to_owned())
            .and_then(PublicKeyHex::new)?;
        let d = parts
            .next()
            .ok_or_else(|| "address coordinate d tag is missing".to_owned())
            .map(DTag::new)?;
        Self::new(kind, pubkey, d)
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
    Count {
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
    },
    Close(SubscriptionId),
    Auth(Event),
    NegOpen {
        subscription_id: SubscriptionId,
        filter: Filter,
        message: String,
    },
    NegMsg {
        subscription_id: SubscriptionId,
        message: String,
    },
    NegClose(SubscriptionId),
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

    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        ids: Vec<EventId>,
        authors: Vec<PublicKeyHex>,
        kinds: Vec<Kind>,
        tag_filters: BTreeMap<TagName, Vec<TagValue>>,
        since: Option<UnixTimestamp>,
        until: Option<UnixTimestamp>,
        limit: Option<u64>,
        search: Option<String>,
    ) -> Result<Self, String> {
        for (name, values) in &tag_filters {
            if !name.is_indexable() {
                return Err(format!(
                    "filter field `#{}` is invalid: tag name must be a single ASCII letter",
                    name.as_str()
                ));
            }
            if values.is_empty() {
                return Err(filter_array_error(&format!("#{}", name.as_str())));
            }
        }
        Ok(Self {
            ids,
            authors,
            kinds,
            tag_filters,
            since,
            until,
            limit,
            search,
        })
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

    pub fn without_limit(&self) -> Self {
        let mut filter = self.clone();
        filter.limit = None;
        filter
    }

    pub fn with_limit(&self, limit: u64) -> Self {
        let mut filter = self.clone();
        filter.limit = Some(limit);
        filter
    }

    pub fn search(&self) -> Option<&str> {
        self.search.as_deref()
    }

    pub fn is_complete(&self) -> bool {
        !self.ids.is_empty()
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
    Count {
        subscription_id: SubscriptionId,
        count: u64,
        hll: Option<String>,
    },
    Notice(String),
    Auth(String),
    NegErr {
        subscription_id: SubscriptionId,
        message: String,
    },
    NegMsg {
        subscription_id: SubscriptionId,
        message: String,
    },
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
        RelayMessage::Count {
            subscription_id,
            count,
            hll,
        } => {
            let mut payload = serde_json::Map::new();
            payload.insert(
                "count".to_owned(),
                serde_json::Value::Number((*count).into()),
            );
            if let Some(hll) = hll {
                payload.insert("hll".to_owned(), serde_json::Value::String(hll.clone()));
            }
            serde_json::json!(["COUNT", subscription_id.as_str(), payload])
        }
        RelayMessage::Notice(message) => serde_json::json!(["NOTICE", message]),
        RelayMessage::Auth(challenge) => serde_json::json!(["AUTH", challenge]),
        RelayMessage::NegErr {
            subscription_id,
            message,
        } => serde_json::json!(["NEG-ERR", subscription_id.as_str(), message]),
        RelayMessage::NegMsg {
            subscription_id,
            message,
        } => serde_json::json!(["NEG-MSG", subscription_id.as_str(), message]),
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

pub fn filter_to_value(filter: &Filter) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    if !filter.ids().is_empty() {
        object.insert(
            "ids".to_owned(),
            serde_json::Value::Array(
                filter
                    .ids()
                    .iter()
                    .map(|id| serde_json::Value::String(id.as_str().to_owned()))
                    .collect(),
            ),
        );
    }
    if !filter.authors().is_empty() {
        object.insert(
            "authors".to_owned(),
            serde_json::Value::Array(
                filter
                    .authors()
                    .iter()
                    .map(|author| serde_json::Value::String(author.as_str().to_owned()))
                    .collect(),
            ),
        );
    }
    if !filter.kinds().is_empty() {
        object.insert(
            "kinds".to_owned(),
            serde_json::Value::Array(
                filter
                    .kinds()
                    .iter()
                    .map(|kind| serde_json::Value::Number(kind.as_u32().into()))
                    .collect(),
            ),
        );
    }
    for (name, values) in filter.tag_filters() {
        object.insert(
            format!("#{}", name.as_str()),
            serde_json::Value::Array(
                values
                    .iter()
                    .map(|value| serde_json::Value::String(value.as_str().to_owned()))
                    .collect(),
            ),
        );
    }
    if let Some(since) = filter.since() {
        object.insert(
            "since".to_owned(),
            serde_json::Value::Number(since.as_u64().into()),
        );
    }
    if let Some(until) = filter.until() {
        object.insert(
            "until".to_owned(),
            serde_json::Value::Number(until.as_u64().into()),
        );
    }
    if let Some(limit) = filter.limit() {
        object.insert("limit".to_owned(), serde_json::Value::Number(limit.into()));
    }
    if let Some(search) = filter.search() {
        object.insert(
            "search".to_owned(),
            serde_json::Value::String(search.to_owned()),
        );
    }
    serde_json::Value::Object(object)
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
    let value = json_value_without_duplicate_fields(raw)
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
        "COUNT" => parse_count_client_message(array),
        "CLOSE" => parse_close_client_message(array),
        "AUTH" => parse_auth_client_message(array),
        unsupported => Err(format!(
            "client message command `{unsupported}` is unsupported"
        )),
    }
}

pub fn parse_event_json(raw: &RawEventJson) -> Result<Event, EventShapeError> {
    let value = json_value_without_duplicate_fields(raw.as_str()).map_err(|source| {
        EventShapeError::invalid_field("event", &format!("invalid JSON: {source}"))
    })?;
    event_from_value(&value)
}

fn json_value_without_duplicate_fields(raw: &str) -> Result<serde_json::Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_str(raw);
    let value = UniqueJsonValue::deserialize(&mut deserializer)?.0;
    deserializer.end()?;
    Ok(value)
}

struct UniqueJsonValue(serde_json::Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_any(UniqueJsonValueVisitor)
            .map(Self)
    }
}

struct UniqueJsonValueVisitor;

impl<'de> Visitor<'de> for UniqueJsonValueVisitor {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object fields")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("JSON number must be finite"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(value.to_owned()))
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJsonValue::deserialize(deserializer).map(|value| value.0)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJsonValue>()? {
            values.push(value.0);
        }
        Ok(serde_json::Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(field) = object.next_key::<String>()? {
            if values.contains_key(&field) {
                return Err(de::Error::custom(format!(
                    "duplicate object field `{field}`"
                )));
            }
            let value = object.next_value::<UniqueJsonValue>()?;
            values.insert(field, value.0);
        }
        Ok(serde_json::Value::Object(values))
    }
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

fn parse_count_client_message(array: &[serde_json::Value]) -> Result<ClientMessage, String> {
    if array.len() < 3 {
        return Err("COUNT client message must contain a subscription id and filters".to_owned());
    }
    let subscription_id = array[1]
        .as_str()
        .ok_or_else(|| "COUNT subscription id must be a string".to_owned())
        .and_then(SubscriptionId::new)?;
    let filters = array[2..]
        .iter()
        .map(filter_from_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ClientMessage::Count {
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
        AddressCoordinate, AddressKey, ClientMessage, DTag, Event, EventId, EventShapeError,
        Filter, Kind, KindClass, PublicKeyHex, RawEventJson, RelayMessage, SignatureHex,
        SubscriptionId, Tag, TagName, TagValue, UnixTimestamp, UnsignedEvent, canonical_event_json,
        empty_error, encode_relay_message, event_from_value, event_to_value, filter_from_value,
        filter_to_value, invalid_length_error, kind_out_of_range_error, non_lowercase_hex_error,
        parse_client_message, parse_event_json, relay_message_to_value, too_long_error,
    };
    use core::str::FromStr;
    use std::collections::{BTreeMap, hash_map::DefaultHasher};
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
    fn address_coordinate_parses_formats_and_extracts_from_events() {
        let pubkey = PublicKeyHex::new(&"1".repeat(PublicKeyHex::HEX_LENGTH)).expect("pubkey");
        let coordinate = AddressCoordinate::new(
            Kind::new(30_402).expect("kind"),
            pubkey.clone(),
            DTag::new("market-stall"),
        )
        .expect("coordinate");
        let key: AddressKey = coordinate.key();
        let parsed = AddressCoordinate::from_str(&coordinate.to_string()).expect("parsed");
        let empty_d =
            AddressCoordinate::from_str(&format!("30000:{}:", pubkey.as_str())).expect("empty d");
        let event = addressable_event("market-stall", 30_402);

        assert_eq!(coordinate.kind().as_u32(), 30_402);
        assert_eq!(coordinate.pubkey(), &pubkey);
        assert_eq!(coordinate.d().as_str(), "market-stall");
        assert_eq!(
            coordinate.to_string(),
            format!("30402:{}:market-stall", pubkey.as_str())
        );
        assert_eq!(key.as_str(), coordinate.to_string());
        assert_eq!(key.to_string(), coordinate.to_string());
        assert_eq!(parsed, coordinate);
        assert_eq!(empty_d.d().as_str(), "");
        assert_eq!(
            AddressCoordinate::from_event(&event).expect("event"),
            Some(coordinate)
        );
        assert_eq!(
            AddressCoordinate::from_event(&event_for_filter(
                &"e".repeat(EventId::HEX_LENGTH),
                50,
                1
            ))
            .expect("regular"),
            None
        );
        assert_eq!(format!("{:?}", DTag::new("d")), "DTag(\"d\")");
        assert_eq!(DTag::new("d").to_string(), "d");
        assert_eq!(DTag::from_str("d"), Ok(DTag::new("d")));
    }

    #[test]
    fn address_coordinate_rejects_invalid_coordinates() {
        let pubkey = "1".repeat(PublicKeyHex::HEX_LENGTH);

        assert_eq!(
            AddressCoordinate::new(
                Kind::new(1).expect("kind"),
                PublicKeyHex::new(&pubkey).expect("pubkey"),
                DTag::new("d")
            )
            .expect_err("regular kind"),
            "address coordinate kind must be addressable, got 1"
        );
        assert_eq!(
            AddressCoordinate::from_str("bad").expect_err("kind parse"),
            "address coordinate kind must be an unsigned integer"
        );
        assert_eq!(
            AddressCoordinate::from_str(&format!("{}:{pubkey}:d", u64::from(u32::MAX) + 1))
                .expect_err("kind range"),
            format!("kind must fit in u32, got {}", u64::from(u32::MAX) + 1)
        );
        assert_eq!(
            AddressCoordinate::from_str("1").expect_err("missing pubkey"),
            "address coordinate pubkey is missing"
        );
        assert_eq!(
            AddressCoordinate::from_str("30000:bad").expect_err("bad pubkey"),
            "public key must be 64 characters, got 3"
        );
        assert_eq!(
            AddressCoordinate::from_str(&format!("30000:{pubkey}")).expect_err("missing d"),
            "address coordinate d tag is missing"
        );
        assert_eq!(
            AddressCoordinate::from_str(&format!("1:{pubkey}:d")).expect_err("regular parse"),
            "address coordinate kind must be addressable, got 1"
        );
        assert_eq!(
            AddressCoordinate::from_event(&addressable_event_without_d())
                .expect_err("missing event d"),
            "addressable event must include a d tag"
        );
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
    fn parse_client_message_accepts_event_auth_req_count_and_close() {
        let event_payload = event_json("a", "b", 1, tags_json());
        let auth_event_json = event_json("c", "d", 22242, "[]");
        let event_message = format!("[\"EVENT\",{event_payload}]");
        let auth_message = format!("[\"AUTH\",{auth_event_json}]");
        let req_message = "[\"REQ\",\"sub-a\",{\"ids\":[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]},{\"kinds\":[1]}]";
        let count_message = "[\"COUNT\",\"sub-a\",{\"kinds\":[1]}]";
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
            parse_client_message(count_message),
            Ok(ClientMessage::Count {
                subscription_id: SubscriptionId::new("sub-a").expect("sub"),
                filters: vec![filter_from_value(&serde_json::json!({"kinds":[1]})).expect("kinds")]
            })
        );
        assert_eq!(
            parse_client_message(close_message).expect("close"),
            ClientMessage::Close(SubscriptionId::new("sub-a").expect("sub"))
        );
    }

    #[test]
    fn parser_rejects_duplicate_json_object_fields() {
        let duplicate_filter_field =
            parse_client_message(r#"["REQ","sub-a",{"limit":1,"limit":2,"kinds":[1]}]"#)
                .expect_err("duplicate filter field");
        let duplicate_event_field = parse_event_json(
            &RawEventJson::new(&format!(
                r#"{{"id":"{}","pubkey":"{}","created_at":1714124433,"kind":1,"tags":[],"content":"one","content":"two","sig":"{}"}}"#,
                "a".repeat(EventId::HEX_LENGTH),
                "1".repeat(PublicKeyHex::HEX_LENGTH),
                "b".repeat(SignatureHex::HEX_LENGTH)
            ))
            .expect("raw"),
        )
        .expect_err("duplicate event field")
        .to_string();

        assert!(
            duplicate_filter_field.contains("duplicate object field `limit`"),
            "{duplicate_filter_field}"
        );
        assert!(
            duplicate_event_field.contains("duplicate object field `content`"),
            "{duplicate_event_field}"
        );
    }

    #[test]
    fn nip01_client_and_relay_message_conformance_vectors_are_exact() {
        let event_payload = event_json("a", "b", 1, tags_json());
        let event =
            parse_event_json(&RawEventJson::new(&event_payload).expect("raw")).expect("event");
        let subscription_id = SubscriptionId::new("sub-vector").expect("sub");
        let event_id = EventId::new(&"c".repeat(EventId::HEX_LENGTH)).expect("id");
        let client_vectors = [
            (
                format!("[\"EVENT\",{event_payload}]"),
                ClientMessage::Event(event.clone()),
            ),
            (
                format!("[\"AUTH\",{event_payload}]"),
                ClientMessage::Auth(event.clone()),
            ),
            (
                "[\"REQ\",\"sub-vector\",{\"kinds\":[1]}]".to_owned(),
                ClientMessage::Req {
                    subscription_id: subscription_id.clone(),
                    filters: vec![
                        filter_from_value(&serde_json::json!({"kinds":[1]})).expect("filter"),
                    ],
                },
            ),
            (
                "[\"COUNT\",\"sub-vector\",{\"kinds\":[1]}]".to_owned(),
                ClientMessage::Count {
                    subscription_id: subscription_id.clone(),
                    filters: vec![
                        filter_from_value(&serde_json::json!({"kinds":[1]})).expect("filter"),
                    ],
                },
            ),
            (
                "[\"CLOSE\",\"sub-vector\"]".to_owned(),
                ClientMessage::Close(subscription_id.clone()),
            ),
        ];
        for (raw, expected) in client_vectors {
            assert_eq!(parse_client_message(&raw), Ok(expected));
        }
        let relay_vectors = [
            (
                RelayMessage::Event {
                    subscription_id: subscription_id.clone(),
                    event: event.clone(),
                },
                serde_json::json!(["EVENT", "sub-vector", event_to_value(&event)]),
            ),
            (
                RelayMessage::Ok {
                    event_id: event_id.clone(),
                    accepted: true,
                    message: String::new(),
                },
                serde_json::json!(["OK", event_id.as_str(), true, ""]),
            ),
            (
                RelayMessage::Eose(subscription_id.clone()),
                serde_json::json!(["EOSE", "sub-vector"]),
            ),
            (
                RelayMessage::Closed {
                    subscription_id: subscription_id.clone(),
                    message: "unsupported: search filters are not supported".to_owned(),
                },
                serde_json::json!([
                    "CLOSED",
                    "sub-vector",
                    "unsupported: search filters are not supported"
                ]),
            ),
            (
                RelayMessage::Count {
                    subscription_id: subscription_id.clone(),
                    count: 3,
                    hll: None,
                },
                serde_json::json!(["COUNT", "sub-vector", {"count": 3}]),
            ),
            (
                RelayMessage::Notice("invalid: bad envelope".to_owned()),
                serde_json::json!(["NOTICE", "invalid: bad envelope"]),
            ),
            (
                RelayMessage::Auth("challenge".to_owned()),
                serde_json::json!(["AUTH", "challenge"]),
            ),
        ];
        for (message, expected) in relay_vectors {
            assert_eq!(relay_message_to_value(&message), expected);
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&message.encode()).expect("encoded"),
                expected
            );
        }
    }

    #[test]
    fn protocol_conformance_fixtures_cover_dense_envelopes_and_parser_stress() {
        let event_payload = event_json(
            "a",
            "b",
            30_023,
            r#"[["e","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wss://relay.example","root"],["e","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],["p","2222222222222222222222222222222222222222222222222222222222222222"],["h","Farm"],["emoji","🌱"]]"#,
        );
        let parsed_event =
            parse_client_message(&format!("[\"EVENT\",{event_payload}]")).expect("event envelope");
        let ClientMessage::Event(event) = parsed_event else {
            panic!("expected event")
        };
        assert_eq!(event.unsigned().kind().as_u32(), 30_023);
        assert_eq!(event.unsigned().tags().len(), 5);

        let req = serde_json::json!([
            "REQ",
            "sub-dense",
            {
                "ids": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                "authors": ["1111111111111111111111111111111111111111111111111111111111111111"],
                "kinds": [1, 30023],
                "#e": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                "#p": ["2222222222222222222222222222222222222222222222222222222222222222"],
                "#h": ["Farm"],
                "since": 0,
                "until": 4102444800_u64,
                "limit": 500,
                "search": "radroots"
            },
            {
                "#t": ["radroots", "market", "farm"],
                "limit": 1
            }
        ])
        .to_string();
        let ClientMessage::Req {
            subscription_id,
            filters,
        } = parse_client_message(&req).expect("req")
        else {
            panic!("expected req")
        };
        assert_eq!(subscription_id.as_str(), "sub-dense");
        assert_eq!(filters.len(), 2);
        assert_eq!(filters[0].kinds().len(), 2);
        assert_eq!(filters[0].tag_filters().len(), 3);
        assert_eq!(filters[1].limit(), Some(1));

        let count = serde_json::json!([
            "COUNT",
            "sub-count",
            {"#h": ["Farm"], "kinds": [1], "limit": 1}
        ])
        .to_string();
        let ClientMessage::Count {
            subscription_id,
            filters,
        } = parse_client_message(&count).expect("count")
        else {
            panic!("expected count")
        };
        assert_eq!(subscription_id.as_str(), "sub-count");
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].limit(), Some(1));

        for raw in [
            "",
            "[",
            "[\"REQ\",\"sub\",{}",
            "[\"REQ\",\"sub\",{\"#h\":[{}]}]",
            "[\"REQ\",\"sub\",{\"ids\":[\"short\"]}]",
            "[\"COUNT\",\"sub\",{\"kinds\":[4294967296]}]",
            "[\"COUNT\",1,{}]",
            "[\"EVENT\",{\"tags\":[[1]]}]",
            "[\"AUTH\",{\"kind\":\"bad\"}]",
            "[\"CLOSE\",\"\"]",
        ] {
            std::panic::catch_unwind(|| {
                assert!(parse_client_message(raw).is_err());
            })
            .expect("parser must not panic");
        }
    }

    #[test]
    fn parser_preserves_addressable_events_and_weird_tag_shapes() {
        let p_tag = "2".repeat(PublicKeyHex::HEX_LENGTH);
        let event_payload = format!(
            r#"{{"id":"{}","pubkey":"{}","created_at":1714124433,"kind":30023,"tags":[["emoji","🌱","https://example.invalid/seed.png"],["d","market-stall"],["d","shadow"],["é","not-indexed"],["h","Farm","extra"],["p","{}","wss://relay.example","mention"]],"content":"addressable 🌱","sig":"{}"}}"#,
            "a".repeat(EventId::HEX_LENGTH),
            "1".repeat(PublicKeyHex::HEX_LENGTH),
            p_tag,
            "b".repeat(SignatureHex::HEX_LENGTH)
        );
        let event =
            parse_event_json(&RawEventJson::new(&event_payload).expect("raw")).expect("event");
        let coordinate = AddressCoordinate::from_event(&event)
            .expect("coordinate")
            .expect("addressable");
        let filter = filter_from_value(&serde_json::json!({
            "#d": ["market-stall"],
            "#h": ["Farm"],
            "#p": [p_tag],
            "limit": u64::MAX
        }))
        .expect("filter");

        assert_eq!(event.unsigned().tags().len(), 6);
        assert_eq!(
            event.unsigned().tags()[0].values(),
            &[
                "emoji".to_owned(),
                "🌱".to_owned(),
                "https://example.invalid/seed.png".to_owned()
            ]
        );
        assert_eq!(event.unsigned().tags()[3].indexed_pair(), None);
        assert_eq!(coordinate.d().as_str(), "market-stall");
        assert_eq!(filter.limit(), Some(u64::MAX));
        assert!(filter.matches(&event));
        assert_eq!(
            filter_from_value(&serde_json::json!({"#é": ["value"]}))
                .expect_err("non ascii tag filter"),
            "filter field `#é` is invalid: tag name must be a single ASCII letter"
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
            parse_client_message("[\"BOGUS\"]").expect_err("unsupported"),
            "client message command `BOGUS` is unsupported"
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
            parse_client_message("[\"COUNT\"]").expect_err("count length"),
            "COUNT client message must contain a subscription id and filters"
        );
        assert_eq!(
            parse_client_message("[\"COUNT\",1,{}]").expect_err("count sub type"),
            "COUNT subscription id must be a string"
        );
        assert_eq!(
            parse_client_message("[\"COUNT\",\"\",{}]").expect_err("count sub empty"),
            "subscription id must not be empty"
        );
        assert_eq!(
            parse_client_message("[\"COUNT\",\"sub-a\",1]").expect_err("count filter"),
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
    fn malformed_client_message_corpus_is_rejected_or_parsed_without_panic() {
        let valid_event = event_json("a", "b", 1, tags_json());
        let long_sub = "x".repeat(SubscriptionId::MAX_LENGTH + 1);
        let oversized_kind = u64::from(u32::MAX) + 1;
        let corpus = [
            String::new(),
            "[".to_owned(),
            "null".to_owned(),
            "[null]".to_owned(),
            "[\"EVENT\",null]".to_owned(),
            format!("[\"EVENT\",{valid_event},{}]", serde_json::json!({})),
            "[\"REQ\",{},{}]".to_owned(),
            "[\"REQ\",\"sub\",{\"ids\":[]}]".to_owned(),
            "[\"REQ\",\"sub\",{\"ids\":[1]}]".to_owned(),
            "[\"REQ\",\"sub\",{\"#aa\":[\"value\"]}]".to_owned(),
            format!("[\"REQ\",\"sub\",{{\"kinds\":[{oversized_kind}]}}]"),
            format!("[\"REQ\",\"{long_sub}\",{{}}]"),
            "[\"COUNT\",\"sub\",{\"authors\":[\"BAD\"]}]".to_owned(),
            "[\"COUNT\",\"sub\",{\"unknown\":true}]".to_owned(),
            "[\"CLOSE\",\"sub\",{}]".to_owned(),
            "[\"AUTH\",[]]".to_owned(),
            "[\"NOTICE\",\"not a client command\"]".to_owned(),
        ];
        for raw in corpus {
            std::panic::catch_unwind(|| {
                let _ = parse_client_message(&raw);
            })
            .expect("parser must not panic");
        }
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
        let without_limit = filter.without_limit();
        assert_eq!(without_limit.limit(), None);
        assert_eq!(without_limit.search(), filter.search());
        assert!(without_limit.matches(&event));
        let with_limit = without_limit.with_limit(2);
        assert_eq!(with_limit.limit(), Some(2));
        assert_eq!(with_limit.search(), filter.search());
        assert!(with_limit.matches(&event));
        assert_eq!(
            filter_from_value(&filter_to_value(&filter)).expect("encoded"),
            filter
        );
    }

    #[test]
    fn filter_from_parts_builds_validated_filter_components() {
        let name = TagName::new("t").expect("tag name");
        let value = TagValue::new("market");
        let filter = Filter::from_parts(
            vec![EventId::new(&"a".repeat(EventId::HEX_LENGTH)).expect("id")],
            vec![PublicKeyHex::new(&"b".repeat(PublicKeyHex::HEX_LENGTH)).expect("author")],
            vec![Kind::new(1).expect("kind")],
            BTreeMap::from([(name.clone(), vec![value.clone()])]),
            Some(UnixTimestamp::new(10)),
            Some(UnixTimestamp::new(20)),
            Some(30),
            Some("carrots".to_owned()),
        )
        .expect("filter");

        assert_eq!(filter.ids().len(), 1);
        assert_eq!(filter.authors().len(), 1);
        assert_eq!(filter.kinds(), &[Kind::new(1).expect("kind")]);
        assert_eq!(filter.tag_filters().get(&name), Some(&vec![value]));
        assert_eq!(filter.since(), Some(UnixTimestamp::new(10)));
        assert_eq!(filter.until(), Some(UnixTimestamp::new(20)));
        assert_eq!(filter.limit(), Some(30));
        assert_eq!(filter.search(), Some("carrots"));
        assert_eq!(
            Filter::from_parts(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                BTreeMap::from([(TagName::new("ab").expect("tag"), Vec::new())]),
                None,
                None,
                None,
                None
            )
            .expect_err("invalid tag"),
            "filter field `#ab` is invalid: tag name must be a single ASCII letter"
        );
    }

    #[test]
    fn filter_complete_semantics_are_exact_id_only() {
        assert!(
            filter_from_value(&serde_json::json!({
                "ids": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
            }))
            .expect("id filter")
            .is_complete()
        );
        assert!(
            !filter_from_value(&serde_json::json!({"kinds": [1]}))
                .expect("kind filter")
                .is_complete()
        );
        assert!(!Filter::empty().is_complete());
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
                subscription_id: subscription_id.clone(),
                message: "unsupported: filter contains unknown elements".to_owned()
            }),
            serde_json::json!([
                "CLOSED",
                "sub-a",
                "unsupported: filter contains unknown elements"
            ])
        );
        assert_eq!(
            relay_message_to_value(&RelayMessage::Count {
                subscription_id,
                count: 7,
                hll: None
            }),
            serde_json::json!(["COUNT", "sub-a", {"count": 7}])
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
    fn relay_message_encoder_emits_negentropy_messages() {
        let subscription_id = SubscriptionId::new("neg-sub").expect("sub");

        assert_eq!(
            relay_message_to_value(&RelayMessage::NegErr {
                subscription_id: subscription_id.clone(),
                message: "blocked: Negentropy sync is disabled".to_owned()
            }),
            serde_json::json!(["NEG-ERR", "neg-sub", "blocked: Negentropy sync is disabled"])
        );
        assert_eq!(
            relay_message_to_value(&RelayMessage::NegMsg {
                subscription_id,
                message: "00ff".to_owned()
            }),
            serde_json::json!(["NEG-MSG", "neg-sub", "00ff"])
        );
    }

    #[test]
    fn relay_message_encoder_emits_count_hll_when_present() {
        let subscription_id = SubscriptionId::new("count-hll").expect("sub");
        let hll = "0a".repeat(256);

        assert_eq!(
            relay_message_to_value(&RelayMessage::Count {
                subscription_id,
                count: 42,
                hll: Some(hll.clone())
            }),
            serde_json::json!(["COUNT", "count-hll", {"count": 42, "hll": hll}])
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

    #[test]
    fn canonical_event_json_preserves_large_tags_without_shape_drift() {
        let tags = (0..64)
            .map(|index| Tag::from_parts("t", &[&format!("topic-{index}")]).expect("tag"))
            .collect::<Vec<_>>();
        let event = unsigned_event(tags, "large tag set");
        let value =
            serde_json::from_str::<serde_json::Value>(&event.canonical_json()).expect("json");

        assert_eq!(value[0], 0);
        assert_eq!(value[4].as_array().expect("tags").len(), 64);
        assert_eq!(value[5], "large tag set");
    }

    #[test]
    fn parser_fuzz_style_scalar_corpus_is_total() {
        let ids = ["0", "a", "f", "g", "A", "00", "ff"];
        for id_seed in ids {
            let id = id_seed.repeat(EventId::HEX_LENGTH);
            let raw = serde_json::json!([
                "EVENT",
                {
                    "id": id,
                    "pubkey": "1".repeat(PublicKeyHex::HEX_LENGTH),
                    "created_at": 1_714_124_433_u64,
                    "kind": 1,
                    "tags": [["e", "a".repeat(EventId::HEX_LENGTH)]],
                    "content": "fuzz",
                    "sig": "2".repeat(SignatureHex::HEX_LENGTH)
                }
            ])
            .to_string();
            std::panic::catch_unwind(|| {
                let _ = parse_client_message(&raw);
            })
            .expect("event parser must not panic");
        }
        for size in [1_usize, 2, 4, 8, 16, 32, 64, 128] {
            let values = (0..size)
                .map(|index| serde_json::Value::String(format!("topic-{index}")))
                .collect::<Vec<_>>();
            let raw = serde_json::json!(["REQ", "fuzz", {"#t": values}]).to_string();
            assert!(parse_client_message(&raw).is_ok());
        }
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

    fn addressable_event(d: &str, kind: u64) -> Event {
        Event::new(
            EventId::new(&"a".repeat(EventId::HEX_LENGTH)).expect("id"),
            UnsignedEvent::new(
                PublicKeyHex::new(&"1".repeat(PublicKeyHex::HEX_LENGTH)).expect("pubkey"),
                UnixTimestamp::new(50),
                Kind::new(kind).expect("kind"),
                vec![
                    Tag::from_parts(
                        "p",
                        &["1111111111111111111111111111111111111111111111111111111111111111"],
                    )
                    .expect("pubkey tag"),
                    Tag::from_parts("d", &[d]).expect("d tag"),
                ],
                "hello",
            ),
            SignatureHex::new(&"b".repeat(SignatureHex::HEX_LENGTH)).expect("sig"),
        )
    }

    fn addressable_event_without_d() -> Event {
        Event::new(
            EventId::new(&"a".repeat(EventId::HEX_LENGTH)).expect("id"),
            UnsignedEvent::new(
                PublicKeyHex::new(&"1".repeat(PublicKeyHex::HEX_LENGTH)).expect("pubkey"),
                UnixTimestamp::new(50),
                Kind::new(30_402).expect("kind"),
                vec![
                    Tag::from_parts(
                        "p",
                        &["1111111111111111111111111111111111111111111111111111111111111111"],
                    )
                    .expect("pubkey tag"),
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
