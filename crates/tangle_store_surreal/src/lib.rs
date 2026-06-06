#![forbid(unsafe_code)]

use core::fmt;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use surrealdb::Surreal;
use surrealdb::engine::any::{Any, connect as connect_any};
use surrealdb::opt::auth::Root;
use tangle_nips::{
    CommentEvent, DeletionTarget, ForumThreadEvent, LabelEvent, ListingProjection,
    ListingProjectionEvaluation, LongFormEvent, LongFormKind, NIP99_DRAFT_LISTING_KIND,
    NIP99_PUBLIC_LISTING_KIND, ReactionEvent, ReactionValue, ReportEvent, ReportTarget,
    SellerProfileEvent, evaluate_listing_projection, parse_comment_event, parse_deletion_request,
    parse_forum_thread_event, parse_label_event, parse_long_form_event, parse_reaction_event,
    parse_report_event, parse_seller_profile_event,
};
use tangle_protocol::{AddressCoordinate, Event, EventId, Filter, UnixTimestamp, event_to_value};
use tangle_store::{StoreEventOutcome, StoredEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurrealConnectionMode {
    Memory,
    RocksDb { path: String },
    Http { endpoint: String },
    WebSocket { endpoint: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurrealConnectionConfig {
    mode: SurrealConnectionMode,
    namespace: String,
    database: String,
    root_credentials: Option<SurrealRootCredentials>,
}

impl SurrealConnectionConfig {
    pub fn memory(namespace: &str, database: &str) -> Result<Self, SurrealConfigError> {
        Self::new(SurrealConnectionMode::Memory, namespace, database)
    }

    pub fn rocksdb(
        path: &str,
        namespace: &str,
        database: &str,
    ) -> Result<Self, SurrealConfigError> {
        let path = normalized_endpoint(path, "rocksdb path")?;
        Self::new(SurrealConnectionMode::RocksDb { path }, namespace, database)
    }

    pub fn http(
        endpoint: &str,
        namespace: &str,
        database: &str,
    ) -> Result<Self, SurrealConfigError> {
        let endpoint = normalized_endpoint(endpoint, "http endpoint")?;
        Self::new(
            SurrealConnectionMode::Http { endpoint },
            namespace,
            database,
        )
    }

    pub fn websocket(
        endpoint: &str,
        namespace: &str,
        database: &str,
    ) -> Result<Self, SurrealConfigError> {
        let endpoint = normalized_endpoint(endpoint, "websocket endpoint")?;
        Self::new(
            SurrealConnectionMode::WebSocket { endpoint },
            namespace,
            database,
        )
    }

    pub fn mode(&self) -> &SurrealConnectionMode {
        &self.mode
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn database(&self) -> &str {
        &self.database
    }

    pub fn root_credentials(&self) -> Option<&SurrealRootCredentials> {
        self.root_credentials.as_ref()
    }

    pub fn with_root_credentials(
        mut self,
        username: &str,
        password: &str,
    ) -> Result<Self, SurrealConfigError> {
        self.root_credentials = Some(SurrealRootCredentials::new(username, password)?);
        Ok(self)
    }

    fn new(
        mode: SurrealConnectionMode,
        namespace: &str,
        database: &str,
    ) -> Result<Self, SurrealConfigError> {
        Ok(Self {
            mode,
            namespace: normalized_identifier(namespace, "namespace")?,
            database: normalized_identifier(database, "database")?,
            root_credentials: None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurrealRootCredentials {
    username: String,
    password: String,
}

impl SurrealRootCredentials {
    pub fn new(username: &str, password: &str) -> Result<Self, SurrealConfigError> {
        Ok(Self {
            username: normalized_secret(username, "username")?,
            password: normalized_secret(password, "password")?,
        })
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurrealConfigError {
    message: String,
}

impl SurrealConfigError {
    fn new(message: &str) -> Self {
        Self {
            message: message.to_owned(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for SurrealConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SurrealConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurrealMetricsSnapshot {
    stored_events: u64,
    visible_events: u64,
    hidden_events: u64,
    deleted_events: u64,
    current_listings: u64,
    active_listings: u64,
    seller_profiles: u64,
    visible_seller_profiles: u64,
    approved_sellers: u64,
    blocked_pubkeys: u64,
}

impl SurrealMetricsSnapshot {
    pub fn stored_events(self) -> u64 {
        self.stored_events
    }

    pub fn visible_events(self) -> u64 {
        self.visible_events
    }

    pub fn hidden_events(self) -> u64 {
        self.hidden_events
    }

    pub fn deleted_events(self) -> u64 {
        self.deleted_events
    }

    pub fn current_listings(self) -> u64 {
        self.current_listings
    }

    pub fn active_listings(self) -> u64 {
        self.active_listings
    }

    pub fn seller_profiles(self) -> u64 {
        self.seller_profiles
    }

    pub fn visible_seller_profiles(self) -> u64 {
        self.visible_seller_profiles
    }

    pub fn approved_sellers(self) -> u64 {
        self.approved_sellers
    }

    pub fn blocked_pubkeys(self) -> u64 {
        self.blocked_pubkeys
    }
}

fn normalized_identifier(value: &str, field: &str) -> Result<String, SurrealConfigError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SurrealConfigError::new(&format!(
            "surreal {field} must not be empty"
        )));
    }
    if !trimmed
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(SurrealConfigError::new(&format!(
            "surreal {field} must use ASCII letters, digits, or underscore"
        )));
    }
    Ok(trimmed.to_owned())
}

fn normalized_endpoint(value: &str, field: &str) -> Result<String, SurrealConfigError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SurrealConfigError::new(&format!(
            "surreal {field} must not be empty"
        )));
    }
    Ok(trimmed.to_owned())
}

fn normalized_secret(value: &str, field: &str) -> Result<String, SurrealConfigError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SurrealConfigError::new(&format!(
            "surreal root {field} must not be empty"
        )));
    }
    Ok(trimmed.to_owned())
}

fn rocksdb_endpoint(path: &str) -> String {
    format!("rocksdb://{path}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurrealMigration {
    name: String,
    surql: &'static str,
    checksum: String,
}

impl SurrealMigration {
    pub fn new(name: &str, surql: &'static str) -> Result<Self, SurrealMigrationError> {
        let name = normalized_migration_name(name)?;
        if surql.trim().is_empty() {
            return Err(SurrealMigrationError::new(
                "surreal migration body must not be empty",
            ));
        }
        Ok(Self {
            name,
            surql,
            checksum: checksum(surql),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn surql(&self) -> &'static str {
        self.surql
    }

    pub fn checksum(&self) -> &str {
        &self.checksum
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurrealMigrationPlan {
    migrations: Vec<SurrealMigration>,
}

impl SurrealMigrationPlan {
    pub fn new(migrations: Vec<SurrealMigration>) -> Result<Self, SurrealMigrationError> {
        for pair in migrations.windows(2) {
            if pair[0].name() >= pair[1].name() {
                return Err(SurrealMigrationError::new(
                    "surreal migrations must be strictly ordered by name",
                ));
            }
        }
        Ok(Self { migrations })
    }

    pub fn migrations(&self) -> &[SurrealMigration] {
        &self.migrations
    }

    pub fn names(&self) -> Vec<&str> {
        self.migrations.iter().map(SurrealMigration::name).collect()
    }

    pub fn find(&self, name: &str) -> Option<&SurrealMigration> {
        self.migrations
            .iter()
            .find(|migration| migration.name() == name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurrealMigrationError {
    message: String,
}

impl SurrealMigrationError {
    fn new(message: &str) -> Self {
        Self {
            message: message.to_owned(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for SurrealMigrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SurrealMigrationError {}

fn normalized_migration_name(name: &str) -> Result<String, SurrealMigrationError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(SurrealMigrationError::new(
            "surreal migration name must not be empty",
        ));
    }
    let mut parts = trimmed.splitn(2, '_');
    let version = parts.next().unwrap_or_default();
    let label = parts.next().unwrap_or_default();
    if version.len() != 4 || !version.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SurrealMigrationError::new(
            "surreal migration name must start with four digits",
        ));
    }
    if label.is_empty()
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(SurrealMigrationError::new(
            "surreal migration label must use lowercase ASCII, digits, or underscore",
        ));
    }
    Ok(trimmed.to_owned())
}

fn checksum(surql: &str) -> String {
    let digest = Sha256::digest(surql.as_bytes());
    lower_hex(&digest)
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub fn migration_tracking_schema() -> SurrealMigration {
    SurrealMigration::new(
        "0001_migration_tracking",
        r#"
DEFINE TABLE IF NOT EXISTS migration SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS name ON TABLE migration TYPE string;
DEFINE FIELD IF NOT EXISTS checksum ON TABLE migration TYPE string;
DEFINE FIELD IF NOT EXISTS applied_at ON TABLE migration TYPE datetime;
DEFINE INDEX IF NOT EXISTS migration_name_uid ON TABLE migration COLUMNS name UNIQUE;
"#,
    )
    .expect("migration tracking schema is valid")
}

pub fn base_migration_plan() -> SurrealMigrationPlan {
    SurrealMigrationPlan::new(vec![
        migration_tracking_schema(),
        raw_event_schema(),
        event_tag_index_schema(),
        current_event_schema(),
        deletion_marker_schema(),
        listing_revision_schema(),
        listing_current_schema(),
        listing_helper_schemas(),
        search_document_schema(),
        policy_schemas(),
        comment_projection_schema(),
        reaction_projection_schema(),
        long_form_projection_schema(),
        forum_thread_schema(),
        label_projection_schema(),
        report_projection_schema(),
        seller_profile_schema(),
    ])
    .expect("base migration plan is strictly ordered")
}

pub fn raw_event_schema() -> SurrealMigration {
    SurrealMigration::new(
        "0002_raw_event",
        r#"
DEFINE TABLE IF NOT EXISTS nostr_event SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE nostr_event TYPE string;
DEFINE FIELD IF NOT EXISTS pubkey ON TABLE nostr_event TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE nostr_event TYPE int;
DEFINE FIELD IF NOT EXISTS kind ON TABLE nostr_event TYPE int;
DEFINE FIELD IF NOT EXISTS tags ON TABLE nostr_event TYPE array;
DEFINE FIELD IF NOT EXISTS content ON TABLE nostr_event TYPE string;
DEFINE FIELD IF NOT EXISTS sig ON TABLE nostr_event TYPE string;
DEFINE FIELD IF NOT EXISTS raw_json ON TABLE nostr_event TYPE string;
DEFINE FIELD IF NOT EXISTS received_at ON TABLE nostr_event TYPE int;
DEFINE FIELD IF NOT EXISTS content_len ON TABLE nostr_event TYPE int;
DEFINE FIELD IF NOT EXISTS tag_count ON TABLE nostr_event TYPE int;
DEFINE FIELD IF NOT EXISTS d_tag ON TABLE nostr_event TYPE option<string>;
DEFINE FIELD IF NOT EXISTS address_key ON TABLE nostr_event TYPE option<string>;
DEFINE FIELD IF NOT EXISTS deleted ON TABLE nostr_event TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS hidden ON TABLE nostr_event TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS rejection_reason ON TABLE nostr_event TYPE option<string>;
DEFINE INDEX IF NOT EXISTS nostr_event_id_uid ON TABLE nostr_event COLUMNS event_id UNIQUE;
DEFINE INDEX IF NOT EXISTS nostr_event_author_created ON TABLE nostr_event COLUMNS pubkey, created_at, event_id;
DEFINE INDEX IF NOT EXISTS nostr_event_kind_created ON TABLE nostr_event COLUMNS kind, created_at, event_id;
DEFINE INDEX IF NOT EXISTS nostr_event_kind_author_created ON TABLE nostr_event COLUMNS kind, pubkey, created_at, event_id;
DEFINE INDEX IF NOT EXISTS nostr_event_address_created ON TABLE nostr_event COLUMNS address_key, created_at, event_id;
DEFINE INDEX IF NOT EXISTS nostr_event_created ON TABLE nostr_event COLUMNS created_at, event_id;
"#,
    )
    .expect("raw event schema is valid")
}

pub fn event_tag_index_schema() -> SurrealMigration {
    SurrealMigration::new(
        "0003_event_tag_index",
        r#"
DEFINE TABLE IF NOT EXISTS event_tag_index SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE event_tag_index TYPE string;
DEFINE FIELD IF NOT EXISTS kind ON TABLE event_tag_index TYPE int;
DEFINE FIELD IF NOT EXISTS pubkey ON TABLE event_tag_index TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE event_tag_index TYPE int;
DEFINE FIELD IF NOT EXISTS tag ON TABLE event_tag_index TYPE string;
DEFINE FIELD IF NOT EXISTS value ON TABLE event_tag_index TYPE string;
DEFINE FIELD IF NOT EXISTS ordinal ON TABLE event_tag_index TYPE int;
DEFINE INDEX IF NOT EXISTS event_tag_lookup ON TABLE event_tag_index COLUMNS tag, value, created_at, event_id;
DEFINE INDEX IF NOT EXISTS event_tag_kind_lookup ON TABLE event_tag_index COLUMNS tag, value, kind, created_at, event_id;
DEFINE INDEX IF NOT EXISTS event_tag_event ON TABLE event_tag_index COLUMNS event_id;
"#,
    )
    .expect("event tag index schema is valid")
}

pub fn current_event_schema() -> SurrealMigration {
    SurrealMigration::new(
        "0004_current_event",
        r#"
DEFINE TABLE IF NOT EXISTS event_current SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS address_key ON TABLE event_current TYPE string;
DEFINE FIELD IF NOT EXISTS kind ON TABLE event_current TYPE int;
DEFINE FIELD IF NOT EXISTS pubkey ON TABLE event_current TYPE string;
DEFINE FIELD IF NOT EXISTS d ON TABLE event_current TYPE option<string>;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE event_current TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE event_current TYPE int;
DEFINE FIELD IF NOT EXISTS tie_break_id ON TABLE event_current TYPE string;
DEFINE FIELD IF NOT EXISTS deleted ON TABLE event_current TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS hidden ON TABLE event_current TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE event_current TYPE int;
DEFINE INDEX IF NOT EXISTS event_current_address_uid ON TABLE event_current COLUMNS address_key UNIQUE;
DEFINE INDEX IF NOT EXISTS event_current_kind_pubkey ON TABLE event_current COLUMNS kind, pubkey;
DEFINE INDEX IF NOT EXISTS event_current_event ON TABLE event_current COLUMNS event_id;
"#,
    )
    .expect("current event schema is valid")
}

pub fn deletion_marker_schema() -> SurrealMigration {
    SurrealMigration::new(
        "0005_deletion_marker",
        r#"
DEFINE TABLE IF NOT EXISTS deletion_marker SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS deletion_event_id ON TABLE deletion_marker TYPE string;
DEFINE FIELD IF NOT EXISTS target_type ON TABLE deletion_marker TYPE string;
DEFINE FIELD IF NOT EXISTS target_ref ON TABLE deletion_marker TYPE string;
DEFINE FIELD IF NOT EXISTS author_pubkey ON TABLE deletion_marker TYPE string;
DEFINE FIELD IF NOT EXISTS deletion_created_at ON TABLE deletion_marker TYPE int;
DEFINE INDEX IF NOT EXISTS deletion_target ON TABLE deletion_marker COLUMNS target_type, target_ref, deletion_created_at;
DEFINE INDEX IF NOT EXISTS deletion_author_target ON TABLE deletion_marker COLUMNS author_pubkey, target_type, target_ref;
"#,
    )
    .expect("deletion marker schema is valid")
}

pub fn listing_revision_schema() -> SurrealMigration {
    SurrealMigration::new(
        "0006_listing_revision",
        r#"
DEFINE TABLE IF NOT EXISTS listing_revision SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS revision_key ON TABLE listing_revision TYPE string;
DEFINE FIELD IF NOT EXISTS listing_key ON TABLE listing_revision TYPE string;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE listing_revision TYPE string;
DEFINE FIELD IF NOT EXISTS seller_pubkey ON TABLE listing_revision TYPE string;
DEFINE FIELD IF NOT EXISTS d ON TABLE listing_revision TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE listing_revision TYPE int;
DEFINE FIELD IF NOT EXISTS parsed_ok ON TABLE listing_revision TYPE bool;
DEFINE FIELD IF NOT EXISTS parse_errors ON TABLE listing_revision TYPE array;
DEFINE FIELD IF NOT EXISTS title ON TABLE listing_revision TYPE option<string>;
DEFINE FIELD IF NOT EXISTS summary ON TABLE listing_revision TYPE option<string>;
DEFINE FIELD IF NOT EXISTS price_decimal ON TABLE listing_revision TYPE option<string>;
DEFINE FIELD IF NOT EXISTS price_minor ON TABLE listing_revision TYPE option<int>;
DEFINE FIELD IF NOT EXISTS currency_raw ON TABLE listing_revision TYPE option<string>;
DEFINE FIELD IF NOT EXISTS currency_norm ON TABLE listing_revision TYPE option<string>;
DEFINE FIELD IF NOT EXISTS unit ON TABLE listing_revision TYPE option<string>;
DEFINE FIELD IF NOT EXISTS status_tag ON TABLE listing_revision TYPE option<string>;
DEFINE FIELD IF NOT EXISTS projected_at ON TABLE listing_revision TYPE int;
DEFINE INDEX IF NOT EXISTS listing_revision_event_uid ON TABLE listing_revision COLUMNS event_id UNIQUE;
DEFINE INDEX IF NOT EXISTS listing_revision_listing_created ON TABLE listing_revision COLUMNS listing_key, created_at, event_id;
DEFINE INDEX IF NOT EXISTS listing_revision_seller_created ON TABLE listing_revision COLUMNS seller_pubkey, created_at, event_id;
"#,
    )
    .expect("listing revision schema is valid")
}

pub fn listing_current_schema() -> SurrealMigration {
    SurrealMigration::new(
        "0007_listing_current",
        r#"
DEFINE TABLE IF NOT EXISTS listing_current SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS listing_key ON TABLE listing_current TYPE string;
DEFINE FIELD IF NOT EXISTS listing_key_hash ON TABLE listing_current TYPE string;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE listing_current TYPE string;
DEFINE FIELD IF NOT EXISTS seller_pubkey ON TABLE listing_current TYPE string;
DEFINE FIELD IF NOT EXISTS d ON TABLE listing_current TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE listing_current TYPE int;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE listing_current TYPE int;
DEFINE FIELD IF NOT EXISTS published_at ON TABLE listing_current TYPE option<int>;
DEFINE FIELD IF NOT EXISTS title ON TABLE listing_current TYPE string;
DEFINE FIELD IF NOT EXISTS summary ON TABLE listing_current TYPE option<string>;
DEFINE FIELD IF NOT EXISTS content ON TABLE listing_current TYPE string;
DEFINE FIELD IF NOT EXISTS price_decimal ON TABLE listing_current TYPE string;
DEFINE FIELD IF NOT EXISTS price_minor ON TABLE listing_current TYPE int;
DEFINE FIELD IF NOT EXISTS currency_raw ON TABLE listing_current TYPE string;
DEFINE FIELD IF NOT EXISTS currency_norm ON TABLE listing_current TYPE string;
DEFINE FIELD IF NOT EXISTS price_frequency ON TABLE listing_current TYPE option<string>;
DEFINE FIELD IF NOT EXISTS unit ON TABLE listing_current TYPE string;
DEFINE FIELD IF NOT EXISTS unit_family ON TABLE listing_current TYPE string;
DEFINE FIELD IF NOT EXISTS location_text ON TABLE listing_current TYPE option<string>;
DEFINE FIELD IF NOT EXISTS geohash ON TABLE listing_current TYPE option<string>;
DEFINE FIELD IF NOT EXISTS geohash4 ON TABLE listing_current TYPE option<string>;
DEFINE FIELD IF NOT EXISTS geohash5 ON TABLE listing_current TYPE option<string>;
DEFINE FIELD IF NOT EXISTS geohash6 ON TABLE listing_current TYPE option<string>;
DEFINE FIELD IF NOT EXISTS geohash7 ON TABLE listing_current TYPE option<string>;
DEFINE FIELD IF NOT EXISTS point ON TABLE listing_current TYPE option<array>;
DEFINE FIELD IF NOT EXISTS status_tag ON TABLE listing_current TYPE option<string>;
DEFINE FIELD IF NOT EXISTS effective_status ON TABLE listing_current TYPE string;
DEFINE FIELD IF NOT EXISTS categories ON TABLE listing_current TYPE array;
DEFINE FIELD IF NOT EXISTS tags ON TABLE listing_current TYPE array;
DEFINE FIELD IF NOT EXISTS practices ON TABLE listing_current TYPE array;
DEFINE FIELD IF NOT EXISTS certifications ON TABLE listing_current TYPE array;
DEFINE FIELD IF NOT EXISTS image_urls ON TABLE listing_current TYPE array;
DEFINE FIELD IF NOT EXISTS pickup_available ON TABLE listing_current TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS delivery_available ON TABLE listing_current TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS shipping_available ON TABLE listing_current TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS delivery_only ON TABLE listing_current TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS seller_trust_score ON TABLE listing_current TYPE option<int>;
DEFINE FIELD IF NOT EXISTS hidden ON TABLE listing_current TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS deleted ON TABLE listing_current TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS projected_at ON TABLE listing_current TYPE int;
DEFINE INDEX IF NOT EXISTS listing_key_uid ON TABLE listing_current COLUMNS listing_key UNIQUE;
DEFINE INDEX IF NOT EXISTS listing_event_uid ON TABLE listing_current COLUMNS event_id UNIQUE;
DEFINE INDEX IF NOT EXISTS listing_status_updated ON TABLE listing_current COLUMNS effective_status, updated_at, event_id;
DEFINE INDEX IF NOT EXISTS listing_seller_status_updated ON TABLE listing_current COLUMNS seller_pubkey, effective_status, updated_at, event_id;
DEFINE INDEX IF NOT EXISTS listing_price_lookup ON TABLE listing_current COLUMNS effective_status, currency_norm, unit, price_minor, event_id;
DEFINE INDEX IF NOT EXISTS listing_geo4_status ON TABLE listing_current COLUMNS effective_status, geohash4, updated_at, event_id;
DEFINE INDEX IF NOT EXISTS listing_geo5_status ON TABLE listing_current COLUMNS effective_status, geohash5, updated_at, event_id;
DEFINE INDEX IF NOT EXISTS listing_geo6_status ON TABLE listing_current COLUMNS effective_status, geohash6, updated_at, event_id;
"#,
    )
    .expect("listing current schema is valid")
}

pub fn listing_helper_schemas() -> SurrealMigration {
    SurrealMigration::new(
        "0008_listing_helpers",
        r#"
DEFINE TABLE IF NOT EXISTS listing_category SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS listing_key ON TABLE listing_category TYPE string;
DEFINE FIELD IF NOT EXISTS category ON TABLE listing_category TYPE string;
DEFINE FIELD IF NOT EXISTS effective_status ON TABLE listing_category TYPE string;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE listing_category TYPE int;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE listing_category TYPE string;
DEFINE INDEX IF NOT EXISTS listing_category_lookup ON TABLE listing_category COLUMNS category, effective_status, updated_at, listing_key;
DEFINE INDEX IF NOT EXISTS listing_category_listing ON TABLE listing_category COLUMNS listing_key;

DEFINE TABLE IF NOT EXISTS listing_fulfillment SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS listing_key ON TABLE listing_fulfillment TYPE string;
DEFINE FIELD IF NOT EXISTS mode ON TABLE listing_fulfillment TYPE string;
DEFINE FIELD IF NOT EXISTS effective_status ON TABLE listing_fulfillment TYPE string;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE listing_fulfillment TYPE int;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE listing_fulfillment TYPE string;
DEFINE INDEX IF NOT EXISTS listing_fulfillment_lookup ON TABLE listing_fulfillment COLUMNS mode, effective_status, updated_at, listing_key;
DEFINE INDEX IF NOT EXISTS listing_fulfillment_listing ON TABLE listing_fulfillment COLUMNS listing_key;

DEFINE TABLE IF NOT EXISTS listing_tag SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS listing_key ON TABLE listing_tag TYPE string;
DEFINE FIELD IF NOT EXISTS tag_value ON TABLE listing_tag TYPE string;
DEFINE FIELD IF NOT EXISTS effective_status ON TABLE listing_tag TYPE string;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE listing_tag TYPE int;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE listing_tag TYPE string;
DEFINE INDEX IF NOT EXISTS listing_tag_lookup ON TABLE listing_tag COLUMNS tag_value, effective_status, updated_at, listing_key;
DEFINE INDEX IF NOT EXISTS listing_tag_listing ON TABLE listing_tag COLUMNS listing_key;

DEFINE TABLE IF NOT EXISTS listing_practice SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS listing_key ON TABLE listing_practice TYPE string;
DEFINE FIELD IF NOT EXISTS practice ON TABLE listing_practice TYPE string;
DEFINE FIELD IF NOT EXISTS effective_status ON TABLE listing_practice TYPE string;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE listing_practice TYPE int;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE listing_practice TYPE string;
DEFINE INDEX IF NOT EXISTS listing_practice_lookup ON TABLE listing_practice COLUMNS practice, effective_status, updated_at, listing_key;
DEFINE INDEX IF NOT EXISTS listing_practice_listing ON TABLE listing_practice COLUMNS listing_key;

DEFINE TABLE IF NOT EXISTS listing_certification SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS listing_key ON TABLE listing_certification TYPE string;
DEFINE FIELD IF NOT EXISTS certification ON TABLE listing_certification TYPE string;
DEFINE FIELD IF NOT EXISTS effective_status ON TABLE listing_certification TYPE string;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE listing_certification TYPE int;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE listing_certification TYPE string;
DEFINE INDEX IF NOT EXISTS listing_certification_lookup ON TABLE listing_certification COLUMNS certification, effective_status, updated_at, listing_key;
DEFINE INDEX IF NOT EXISTS listing_certification_listing ON TABLE listing_certification COLUMNS listing_key;
"#,
    )
    .expect("listing helper schemas are valid")
}

pub fn search_document_schema() -> SurrealMigration {
    SurrealMigration::new(
        "0009_search_document",
        r#"
DEFINE ANALYZER IF NOT EXISTS tangle_listing_search TOKENIZERS blank,class FILTERS lowercase,snowball(english);
DEFINE TABLE IF NOT EXISTS search_doc SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS doc_key ON TABLE search_doc TYPE string;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE search_doc TYPE string;
DEFINE FIELD IF NOT EXISTS current_event_id ON TABLE search_doc TYPE string;
DEFINE FIELD IF NOT EXISTS doc_type ON TABLE search_doc TYPE string;
DEFINE FIELD IF NOT EXISTS kind ON TABLE search_doc TYPE int;
DEFINE FIELD IF NOT EXISTS pubkey ON TABLE search_doc TYPE string;
DEFINE FIELD IF NOT EXISTS address_key ON TABLE search_doc TYPE option<string>;
DEFINE FIELD IF NOT EXISTS title ON TABLE search_doc TYPE string;
DEFINE FIELD IF NOT EXISTS summary ON TABLE search_doc TYPE option<string>;
DEFINE FIELD IF NOT EXISTS body ON TABLE search_doc TYPE string;
DEFINE FIELD IF NOT EXISTS category_text ON TABLE search_doc TYPE string;
DEFINE FIELD IF NOT EXISTS location_text ON TABLE search_doc TYPE option<string>;
DEFINE FIELD IF NOT EXISTS tags ON TABLE search_doc TYPE array;
DEFINE FIELD IF NOT EXISTS categories ON TABLE search_doc TYPE array;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE search_doc TYPE int;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE search_doc TYPE int;
DEFINE FIELD IF NOT EXISTS visible ON TABLE search_doc TYPE bool;
DEFINE FIELD IF NOT EXISTS status ON TABLE search_doc TYPE string;
DEFINE FIELD IF NOT EXISTS seller_trust_score ON TABLE search_doc TYPE option<int>;
DEFINE INDEX IF NOT EXISTS search_doc_key_uid ON TABLE search_doc COLUMNS doc_key UNIQUE;
DEFINE INDEX IF NOT EXISTS search_doc_type_visible_updated ON TABLE search_doc COLUMNS doc_type, visible, updated_at, event_id;
DEFINE INDEX IF NOT EXISTS search_doc_kind_visible_updated ON TABLE search_doc COLUMNS visible, kind, updated_at, event_id;
DEFINE INDEX IF NOT EXISTS search_doc_kind_pubkey_updated ON TABLE search_doc COLUMNS kind, pubkey, updated_at, event_id;
DEFINE INDEX IF NOT EXISTS search_doc_title_ft ON TABLE search_doc FIELDS title FULLTEXT ANALYZER tangle_listing_search BM25 HIGHLIGHTS;
DEFINE INDEX IF NOT EXISTS search_doc_summary_ft ON TABLE search_doc FIELDS summary FULLTEXT ANALYZER tangle_listing_search BM25 HIGHLIGHTS;
DEFINE INDEX IF NOT EXISTS search_doc_body_ft ON TABLE search_doc FIELDS body FULLTEXT ANALYZER tangle_listing_search BM25 HIGHLIGHTS;
"#,
    )
    .expect("search document schema is valid")
}

pub fn policy_schemas() -> SurrealMigration {
    SurrealMigration::new(
        "0010_policy",
        r#"
DEFINE TABLE IF NOT EXISTS relay_user SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS pubkey ON TABLE relay_user TYPE string;
DEFINE FIELD IF NOT EXISTS role ON TABLE relay_user TYPE string;
DEFINE FIELD IF NOT EXISTS seller_approved ON TABLE relay_user TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS blocked ON TABLE relay_user TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE relay_user TYPE int;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE relay_user TYPE int;
DEFINE INDEX IF NOT EXISTS relay_user_pubkey_uid ON TABLE relay_user COLUMNS pubkey UNIQUE;
DEFINE INDEX IF NOT EXISTS relay_user_role ON TABLE relay_user COLUMNS role;
DEFINE INDEX IF NOT EXISTS relay_user_seller_gate ON TABLE relay_user COLUMNS seller_approved, blocked;

DEFINE TABLE IF NOT EXISTS hidden_event SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE hidden_event TYPE string;
DEFINE FIELD IF NOT EXISTS reason ON TABLE hidden_event TYPE string;
DEFINE FIELD IF NOT EXISTS source ON TABLE hidden_event TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE hidden_event TYPE int;
DEFINE FIELD IF NOT EXISTS admin_pubkey ON TABLE hidden_event TYPE string;
DEFINE INDEX IF NOT EXISTS hidden_event_uid ON TABLE hidden_event COLUMNS event_id UNIQUE;
DEFINE INDEX IF NOT EXISTS hidden_event_created ON TABLE hidden_event COLUMNS created_at;

DEFINE TABLE IF NOT EXISTS moderation_action SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS action_id ON TABLE moderation_action TYPE string;
DEFINE FIELD IF NOT EXISTS admin_pubkey ON TABLE moderation_action TYPE string;
DEFINE FIELD IF NOT EXISTS target_type ON TABLE moderation_action TYPE string;
DEFINE FIELD IF NOT EXISTS target_ref ON TABLE moderation_action TYPE string;
DEFINE FIELD IF NOT EXISTS action ON TABLE moderation_action TYPE string;
DEFINE FIELD IF NOT EXISTS reason ON TABLE moderation_action TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE moderation_action TYPE int;
DEFINE INDEX IF NOT EXISTS moderation_action_target ON TABLE moderation_action COLUMNS target_type, target_ref, created_at;
DEFINE INDEX IF NOT EXISTS moderation_action_admin ON TABLE moderation_action COLUMNS admin_pubkey, created_at;

DEFINE TABLE IF NOT EXISTS rate_limit_state SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS key ON TABLE rate_limit_state TYPE string;
DEFINE FIELD IF NOT EXISTS state ON TABLE rate_limit_state TYPE string;
DEFINE FIELD IF NOT EXISTS expires_at ON TABLE rate_limit_state TYPE option<int>;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE rate_limit_state TYPE int;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE rate_limit_state TYPE int;
DEFINE INDEX IF NOT EXISTS rate_limit_state_key_uid ON TABLE rate_limit_state COLUMNS key UNIQUE;
DEFINE INDEX IF NOT EXISTS rate_limit_state_expires ON TABLE rate_limit_state COLUMNS expires_at;

DEFINE TABLE IF NOT EXISTS import_checkpoint SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS name ON TABLE import_checkpoint TYPE string;
DEFINE FIELD IF NOT EXISTS offset ON TABLE import_checkpoint TYPE int;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE import_checkpoint TYPE option<string>;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE import_checkpoint TYPE int;
DEFINE INDEX IF NOT EXISTS import_checkpoint_name_uid ON TABLE import_checkpoint COLUMNS name UNIQUE;

DEFINE TABLE IF NOT EXISTS projection_error SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE projection_error TYPE string;
DEFINE FIELD IF NOT EXISTS projector ON TABLE projection_error TYPE string;
DEFINE FIELD IF NOT EXISTS error ON TABLE projection_error TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE projection_error TYPE int;
DEFINE INDEX IF NOT EXISTS projection_error_event ON TABLE projection_error COLUMNS event_id;
DEFINE INDEX IF NOT EXISTS projection_error_projector_created ON TABLE projection_error COLUMNS projector, created_at;
"#,
    )
    .expect("policy schemas are valid")
}

pub fn comment_projection_schema() -> SurrealMigration {
    SurrealMigration::new(
        "0011_comment_projection",
        r#"
DEFINE TABLE IF NOT EXISTS comment_projection SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS comment_id ON TABLE comment_projection TYPE string;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE comment_projection TYPE string;
DEFINE FIELD IF NOT EXISTS pubkey ON TABLE comment_projection TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE comment_projection TYPE int;
DEFINE FIELD IF NOT EXISTS content ON TABLE comment_projection TYPE string;
DEFINE FIELD IF NOT EXISTS root_target_type ON TABLE comment_projection TYPE string;
DEFINE FIELD IF NOT EXISTS root_ref ON TABLE comment_projection TYPE string;
DEFINE FIELD IF NOT EXISTS root_kind ON TABLE comment_projection TYPE string;
DEFINE FIELD IF NOT EXISTS root_author ON TABLE comment_projection TYPE option<string>;
DEFINE FIELD IF NOT EXISTS parent_target_type ON TABLE comment_projection TYPE string;
DEFINE FIELD IF NOT EXISTS parent_ref ON TABLE comment_projection TYPE string;
DEFINE FIELD IF NOT EXISTS parent_kind ON TABLE comment_projection TYPE string;
DEFINE FIELD IF NOT EXISTS parent_author ON TABLE comment_projection TYPE option<string>;
DEFINE FIELD IF NOT EXISTS hidden ON TABLE comment_projection TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS deleted ON TABLE comment_projection TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS projected_at ON TABLE comment_projection TYPE int;
DEFINE INDEX IF NOT EXISTS comment_projection_event_uid ON TABLE comment_projection COLUMNS event_id UNIQUE;
DEFINE INDEX IF NOT EXISTS comment_projection_root_lookup ON TABLE comment_projection COLUMNS root_target_type, root_ref, created_at, event_id;
DEFINE INDEX IF NOT EXISTS comment_projection_parent_lookup ON TABLE comment_projection COLUMNS parent_target_type, parent_ref, created_at, event_id;
DEFINE INDEX IF NOT EXISTS comment_projection_author_created ON TABLE comment_projection COLUMNS pubkey, created_at, event_id;
"#,
    )
    .expect("comment projection schema is valid")
}

pub fn reaction_projection_schema() -> SurrealMigration {
    SurrealMigration::new(
        "0012_reaction_projection",
        r#"
DEFINE TABLE IF NOT EXISTS reaction_projection SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS reaction_id ON TABLE reaction_projection TYPE string;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE reaction_projection TYPE string;
DEFINE FIELD IF NOT EXISTS pubkey ON TABLE reaction_projection TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE reaction_projection TYPE int;
DEFINE FIELD IF NOT EXISTS content ON TABLE reaction_projection TYPE string;
DEFINE FIELD IF NOT EXISTS value_type ON TABLE reaction_projection TYPE string;
DEFINE FIELD IF NOT EXISTS value ON TABLE reaction_projection TYPE string;
DEFINE FIELD IF NOT EXISTS target_event_id ON TABLE reaction_projection TYPE string;
DEFINE FIELD IF NOT EXISTS target_pubkey ON TABLE reaction_projection TYPE option<string>;
DEFINE FIELD IF NOT EXISTS target_address ON TABLE reaction_projection TYPE option<string>;
DEFINE FIELD IF NOT EXISTS target_kind ON TABLE reaction_projection TYPE option<string>;
DEFINE FIELD IF NOT EXISTS hidden ON TABLE reaction_projection TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS deleted ON TABLE reaction_projection TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS projected_at ON TABLE reaction_projection TYPE int;
DEFINE INDEX IF NOT EXISTS reaction_projection_event_uid ON TABLE reaction_projection COLUMNS event_id UNIQUE;
DEFINE INDEX IF NOT EXISTS reaction_projection_target_created ON TABLE reaction_projection COLUMNS target_event_id, created_at, event_id;
DEFINE INDEX IF NOT EXISTS reaction_projection_author_created ON TABLE reaction_projection COLUMNS pubkey, created_at, event_id;
DEFINE INDEX IF NOT EXISTS reaction_projection_target_kind ON TABLE reaction_projection COLUMNS target_kind, target_event_id;

DEFINE TABLE IF NOT EXISTS reaction_count SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS target_event_id ON TABLE reaction_count TYPE string;
DEFINE FIELD IF NOT EXISTS target_kind ON TABLE reaction_count TYPE option<string>;
DEFINE FIELD IF NOT EXISTS like_count ON TABLE reaction_count TYPE int DEFAULT 0;
DEFINE FIELD IF NOT EXISTS dislike_count ON TABLE reaction_count TYPE int DEFAULT 0;
DEFINE FIELD IF NOT EXISTS emoji_count ON TABLE reaction_count TYPE int DEFAULT 0;
DEFINE FIELD IF NOT EXISTS text_count ON TABLE reaction_count TYPE int DEFAULT 0;
DEFINE FIELD IF NOT EXISTS total_count ON TABLE reaction_count TYPE int DEFAULT 0;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE reaction_count TYPE int;
DEFINE INDEX IF NOT EXISTS reaction_count_target_uid ON TABLE reaction_count COLUMNS target_event_id UNIQUE;
DEFINE INDEX IF NOT EXISTS reaction_count_kind_target ON TABLE reaction_count COLUMNS target_kind, target_event_id;
"#,
    )
    .expect("reaction projection schema is valid")
}

pub fn long_form_projection_schema() -> SurrealMigration {
    SurrealMigration::new(
        "0013_long_form_projection",
        r#"
DEFINE TABLE IF NOT EXISTS long_form_current SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS long_form_key ON TABLE long_form_current TYPE string;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE long_form_current TYPE string;
DEFINE FIELD IF NOT EXISTS author_pubkey ON TABLE long_form_current TYPE string;
DEFINE FIELD IF NOT EXISTS d ON TABLE long_form_current TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE long_form_current TYPE int;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE long_form_current TYPE int;
DEFINE FIELD IF NOT EXISTS published_at ON TABLE long_form_current TYPE option<int>;
DEFINE FIELD IF NOT EXISTS title ON TABLE long_form_current TYPE option<string>;
DEFINE FIELD IF NOT EXISTS image ON TABLE long_form_current TYPE option<string>;
DEFINE FIELD IF NOT EXISTS summary ON TABLE long_form_current TYPE option<string>;
DEFINE FIELD IF NOT EXISTS content ON TABLE long_form_current TYPE string;
DEFINE FIELD IF NOT EXISTS tags ON TABLE long_form_current TYPE array;
DEFINE FIELD IF NOT EXISTS referenced_events ON TABLE long_form_current TYPE array;
DEFINE FIELD IF NOT EXISTS referenced_addresses ON TABLE long_form_current TYPE array;
DEFINE FIELD IF NOT EXISTS referenced_pubkeys ON TABLE long_form_current TYPE array;
DEFINE FIELD IF NOT EXISTS hidden ON TABLE long_form_current TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS deleted ON TABLE long_form_current TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS projected_at ON TABLE long_form_current TYPE int;
DEFINE INDEX IF NOT EXISTS long_form_current_key_uid ON TABLE long_form_current COLUMNS long_form_key UNIQUE;
DEFINE INDEX IF NOT EXISTS long_form_current_event_uid ON TABLE long_form_current COLUMNS event_id UNIQUE;
DEFINE INDEX IF NOT EXISTS long_form_current_author_updated ON TABLE long_form_current COLUMNS author_pubkey, updated_at, event_id;
DEFINE INDEX IF NOT EXISTS long_form_current_published_updated ON TABLE long_form_current COLUMNS published_at, updated_at, event_id;
DEFINE INDEX IF NOT EXISTS long_form_current_visibility ON TABLE long_form_current COLUMNS hidden, deleted, updated_at, event_id;

DEFINE TABLE IF NOT EXISTS long_form_topic SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS long_form_key ON TABLE long_form_topic TYPE string;
DEFINE FIELD IF NOT EXISTS topic ON TABLE long_form_topic TYPE string;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE long_form_topic TYPE int;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE long_form_topic TYPE string;
DEFINE FIELD IF NOT EXISTS hidden ON TABLE long_form_topic TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS deleted ON TABLE long_form_topic TYPE bool DEFAULT false;
DEFINE INDEX IF NOT EXISTS long_form_topic_lookup ON TABLE long_form_topic COLUMNS topic, hidden, deleted, updated_at, long_form_key;
DEFINE INDEX IF NOT EXISTS long_form_topic_long_form ON TABLE long_form_topic COLUMNS long_form_key;
"#,
    )
    .expect("long-form projection schema is valid")
}

pub fn forum_thread_schema() -> SurrealMigration {
    SurrealMigration::new(
        "0014_forum_thread_projection",
        r#"
DEFINE TABLE IF NOT EXISTS forum_thread_projection SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS thread_id ON TABLE forum_thread_projection TYPE string;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE forum_thread_projection TYPE string;
DEFINE FIELD IF NOT EXISTS pubkey ON TABLE forum_thread_projection TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE forum_thread_projection TYPE int;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE forum_thread_projection TYPE int;
DEFINE FIELD IF NOT EXISTS title ON TABLE forum_thread_projection TYPE option<string>;
DEFINE FIELD IF NOT EXISTS content ON TABLE forum_thread_projection TYPE string;
DEFINE FIELD IF NOT EXISTS tags ON TABLE forum_thread_projection TYPE array;
DEFINE FIELD IF NOT EXISTS referenced_events ON TABLE forum_thread_projection TYPE array;
DEFINE FIELD IF NOT EXISTS referenced_pubkeys ON TABLE forum_thread_projection TYPE array;
DEFINE FIELD IF NOT EXISTS hidden ON TABLE forum_thread_projection TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS deleted ON TABLE forum_thread_projection TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS projected_at ON TABLE forum_thread_projection TYPE int;
DEFINE INDEX IF NOT EXISTS forum_thread_event_uid ON TABLE forum_thread_projection COLUMNS event_id UNIQUE;
DEFINE INDEX IF NOT EXISTS forum_thread_pubkey_updated ON TABLE forum_thread_projection COLUMNS pubkey, updated_at, event_id;
DEFINE INDEX IF NOT EXISTS forum_thread_visibility_updated ON TABLE forum_thread_projection COLUMNS hidden, deleted, updated_at, event_id;

DEFINE TABLE IF NOT EXISTS forum_thread_topic SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS thread_id ON TABLE forum_thread_topic TYPE string;
DEFINE FIELD IF NOT EXISTS topic ON TABLE forum_thread_topic TYPE string;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE forum_thread_topic TYPE int;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE forum_thread_topic TYPE string;
DEFINE FIELD IF NOT EXISTS hidden ON TABLE forum_thread_topic TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS deleted ON TABLE forum_thread_topic TYPE bool DEFAULT false;
DEFINE INDEX IF NOT EXISTS forum_thread_topic_lookup ON TABLE forum_thread_topic COLUMNS topic, hidden, deleted, updated_at, thread_id;
DEFINE INDEX IF NOT EXISTS forum_thread_topic_thread ON TABLE forum_thread_topic COLUMNS thread_id;
"#,
    )
    .expect("forum thread schema is valid")
}

pub fn label_projection_schema() -> SurrealMigration {
    SurrealMigration::new(
        "0015_label_projection",
        r#"
DEFINE TABLE IF NOT EXISTS label_projection SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS label_id ON TABLE label_projection TYPE string;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE label_projection TYPE string;
DEFINE FIELD IF NOT EXISTS pubkey ON TABLE label_projection TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE label_projection TYPE int;
DEFINE FIELD IF NOT EXISTS content ON TABLE label_projection TYPE string;
DEFINE FIELD IF NOT EXISTS namespace ON TABLE label_projection TYPE string;
DEFINE FIELD IF NOT EXISTS label ON TABLE label_projection TYPE string;
DEFINE FIELD IF NOT EXISTS target_type ON TABLE label_projection TYPE string;
DEFINE FIELD IF NOT EXISTS target_ref ON TABLE label_projection TYPE string;
DEFINE FIELD IF NOT EXISTS hidden ON TABLE label_projection TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS deleted ON TABLE label_projection TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS projected_at ON TABLE label_projection TYPE int;
DEFINE INDEX IF NOT EXISTS label_projection_label_uid ON TABLE label_projection COLUMNS label_id UNIQUE;
DEFINE INDEX IF NOT EXISTS label_projection_event ON TABLE label_projection COLUMNS event_id;
DEFINE INDEX IF NOT EXISTS label_projection_target_lookup ON TABLE label_projection COLUMNS target_type, target_ref, namespace, label, created_at, event_id;
DEFINE INDEX IF NOT EXISTS label_projection_namespace_lookup ON TABLE label_projection COLUMNS namespace, label, created_at, event_id;
DEFINE INDEX IF NOT EXISTS label_projection_author_created ON TABLE label_projection COLUMNS pubkey, created_at, event_id;
DEFINE INDEX IF NOT EXISTS label_projection_visibility ON TABLE label_projection COLUMNS hidden, deleted, created_at, event_id;
"#,
    )
    .expect("label projection schema is valid")
}

pub fn report_projection_schema() -> SurrealMigration {
    SurrealMigration::new(
        "0016_report_projection",
        r#"
DEFINE TABLE IF NOT EXISTS report_projection SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS report_id ON TABLE report_projection TYPE string;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE report_projection TYPE string;
DEFINE FIELD IF NOT EXISTS pubkey ON TABLE report_projection TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE report_projection TYPE int;
DEFINE FIELD IF NOT EXISTS content ON TABLE report_projection TYPE string;
DEFINE FIELD IF NOT EXISTS target_type ON TABLE report_projection TYPE string;
DEFINE FIELD IF NOT EXISTS target_ref ON TABLE report_projection TYPE string;
DEFINE FIELD IF NOT EXISTS report_type ON TABLE report_projection TYPE string;
DEFINE FIELD IF NOT EXISTS reported_pubkeys ON TABLE report_projection TYPE array;
DEFINE FIELD IF NOT EXISTS server_urls ON TABLE report_projection TYPE array;
DEFINE FIELD IF NOT EXISTS hidden ON TABLE report_projection TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS deleted ON TABLE report_projection TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS projected_at ON TABLE report_projection TYPE int;
DEFINE INDEX IF NOT EXISTS report_projection_report_uid ON TABLE report_projection COLUMNS report_id UNIQUE;
DEFINE INDEX IF NOT EXISTS report_projection_event ON TABLE report_projection COLUMNS event_id;
DEFINE INDEX IF NOT EXISTS report_projection_target_lookup ON TABLE report_projection COLUMNS target_type, target_ref, report_type, created_at, event_id;
DEFINE INDEX IF NOT EXISTS report_projection_type_created ON TABLE report_projection COLUMNS report_type, created_at, event_id;
DEFINE INDEX IF NOT EXISTS report_projection_author_created ON TABLE report_projection COLUMNS pubkey, created_at, event_id;
DEFINE INDEX IF NOT EXISTS report_projection_visibility ON TABLE report_projection COLUMNS hidden, deleted, created_at, event_id;
"#,
    )
    .expect("report projection schema is valid")
}

pub fn seller_profile_schema() -> SurrealMigration {
    SurrealMigration::new(
        "0017_seller_profile",
        r#"
DEFINE TABLE IF NOT EXISTS seller_profile SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS pubkey ON TABLE seller_profile TYPE string;
DEFINE FIELD IF NOT EXISTS event_id ON TABLE seller_profile TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE seller_profile TYPE int;
DEFINE FIELD IF NOT EXISTS updated_at ON TABLE seller_profile TYPE int;
DEFINE FIELD IF NOT EXISTS name ON TABLE seller_profile TYPE option<string>;
DEFINE FIELD IF NOT EXISTS display_name ON TABLE seller_profile TYPE option<string>;
DEFINE FIELD IF NOT EXISTS about ON TABLE seller_profile TYPE option<string>;
DEFINE FIELD IF NOT EXISTS picture ON TABLE seller_profile TYPE option<string>;
DEFINE FIELD IF NOT EXISTS website ON TABLE seller_profile TYPE option<string>;
DEFINE FIELD IF NOT EXISTS nip05 ON TABLE seller_profile TYPE option<string>;
DEFINE FIELD IF NOT EXISTS lud16 ON TABLE seller_profile TYPE option<string>;
DEFINE FIELD IF NOT EXISTS regions ON TABLE seller_profile TYPE array;
DEFINE FIELD IF NOT EXISTS categories ON TABLE seller_profile TYPE array;
DEFINE FIELD IF NOT EXISTS trust_markers ON TABLE seller_profile TYPE array;
DEFINE FIELD IF NOT EXISTS seller_approved ON TABLE seller_profile TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS blocked ON TABLE seller_profile TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS hidden ON TABLE seller_profile TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS deleted ON TABLE seller_profile TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS projected_at ON TABLE seller_profile TYPE int;
DEFINE INDEX IF NOT EXISTS seller_profile_pubkey_uid ON TABLE seller_profile COLUMNS pubkey UNIQUE;
DEFINE INDEX IF NOT EXISTS seller_profile_event_uid ON TABLE seller_profile COLUMNS event_id UNIQUE;
DEFINE INDEX IF NOT EXISTS seller_profile_updated ON TABLE seller_profile COLUMNS updated_at, pubkey;
DEFINE INDEX IF NOT EXISTS seller_profile_approved_blocked ON TABLE seller_profile COLUMNS seller_approved, blocked, updated_at, pubkey;
DEFINE INDEX IF NOT EXISTS seller_profile_visibility ON TABLE seller_profile COLUMNS hidden, deleted, updated_at, pubkey;
"#,
    )
    .expect("seller profile schema is valid")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedMigration {
    name: String,
    checksum: String,
}

impl AppliedMigration {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn checksum(&self) -> &str {
        &self.checksum
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationApplyOutcome {
    Applied,
    AlreadyApplied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrentEventOutcome {
    NotCurrent,
    Inserted,
    Replaced,
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeletionMarkerOutcome {
    NotDeletion,
    Applied { targets: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListingRevisionOutcome {
    NotListing,
    Stored { parsed_ok: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListingCurrentOutcome {
    NotListing,
    Ineligible,
    Projected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListingHelperOutcome {
    NotListing,
    Ineligible,
    Projected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchDocumentOutcome {
    NotListing,
    Ineligible,
    Indexed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentProjectionOutcome {
    NotComment,
    Ineligible,
    Projected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReactionProjectionOutcome {
    NotReaction,
    Ineligible,
    Projected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongFormProjectionOutcome {
    NotLongForm,
    Ineligible,
    Projected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForumThreadProjectionOutcome {
    NotForumThread,
    Ineligible,
    Projected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelProjectionOutcome {
    NotLabel,
    Ineligible,
    Projected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportProjectionOutcome {
    NotReport,
    Ineligible,
    Projected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SellerProfileProjectionOutcome {
    NotProfile,
    Ineligible,
    Projected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HiddenEventOutcome {
    NotFound,
    Hidden,
    Unhidden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableRateLimitDecision {
    Accepted {
        remaining: u64,
        reset_at: UnixTimestamp,
    },
    Rejected {
        retry_after_seconds: u64,
        reset_at: UnixTimestamp,
    },
}

impl DurableRateLimitDecision {
    pub fn allowed(self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    pub fn remaining(self) -> u64 {
        match self {
            Self::Accepted { remaining, .. } => remaining,
            Self::Rejected { .. } => 0,
        }
    }

    pub fn reset_at(self) -> UnixTimestamp {
        match self {
            Self::Accepted { reset_at, .. } | Self::Rejected { reset_at, .. } => reset_at,
        }
    }

    pub fn retry_after_seconds(self) -> Option<u64> {
        match self {
            Self::Accepted { .. } => None,
            Self::Rejected {
                retry_after_seconds,
                ..
            } => Some(retry_after_seconds),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListingProjectionQuery {
    effective_status: Option<String>,
    seller_pubkey: Option<String>,
    unit: Option<String>,
    currency_norm: Option<String>,
    min_price_minor: Option<i64>,
    max_price_minor: Option<i64>,
    limit: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchDocumentQuery {
    text: Option<String>,
    doc_type: Option<String>,
    kind: Option<u32>,
    pubkey: Option<String>,
    visible: Option<bool>,
    status: Option<String>,
    limit: Option<u64>,
}

impl ListingProjectionQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_effective_status(mut self, value: &str) -> Self {
        self.effective_status = Some(value.to_owned());
        self
    }

    pub fn with_seller_pubkey(mut self, value: &str) -> Self {
        self.seller_pubkey = Some(value.to_owned());
        self
    }

    pub fn with_unit(mut self, value: &str) -> Self {
        self.unit = Some(value.to_owned());
        self
    }

    pub fn with_currency_norm(mut self, value: &str) -> Self {
        self.currency_norm = Some(value.to_owned());
        self
    }

    pub fn with_min_price_minor(mut self, value: i64) -> Self {
        self.min_price_minor = Some(value);
        self
    }

    pub fn with_max_price_minor(mut self, value: i64) -> Self {
        self.max_price_minor = Some(value);
        self
    }

    pub fn with_limit(mut self, value: u64) -> Self {
        self.limit = Some(value);
        self
    }
}

impl SearchDocumentQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_text(mut self, value: &str) -> Self {
        self.text = Some(value.to_owned());
        self
    }

    pub fn with_doc_type(mut self, value: &str) -> Self {
        self.doc_type = Some(value.to_owned());
        self
    }

    pub fn with_kind(mut self, value: u32) -> Self {
        self.kind = Some(value);
        self
    }

    pub fn with_pubkey(mut self, value: &str) -> Self {
        self.pubkey = Some(value.to_owned());
        self
    }

    pub fn with_visible(mut self, value: bool) -> Self {
        self.visible = Some(value);
        self
    }

    pub fn with_status(mut self, value: &str) -> Self {
        self.status = Some(value.to_owned());
        self
    }

    pub fn with_limit(mut self, value: u64) -> Self {
        self.limit = Some(value);
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommentProjectionQuery {
    root_target_type: Option<String>,
    root_ref: Option<String>,
    parent_target_type: Option<String>,
    parent_ref: Option<String>,
    pubkey: Option<String>,
    limit: Option<u64>,
}

impl CommentProjectionQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_root(mut self, target_type: &str, target_ref: &str) -> Self {
        self.root_target_type = Some(target_type.to_owned());
        self.root_ref = Some(target_ref.to_owned());
        self
    }

    pub fn with_parent(mut self, target_type: &str, target_ref: &str) -> Self {
        self.parent_target_type = Some(target_type.to_owned());
        self.parent_ref = Some(target_ref.to_owned());
        self
    }

    pub fn with_pubkey(mut self, pubkey: &str) -> Self {
        self.pubkey = Some(pubkey.to_owned());
        self
    }

    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LongFormProjectionQuery {
    author_pubkey: Option<String>,
    topic: Option<String>,
    limit: Option<u64>,
}

impl LongFormProjectionQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_author_pubkey(mut self, pubkey: &str) -> Self {
        self.author_pubkey = Some(pubkey.to_owned());
        self
    }

    pub fn with_topic(mut self, topic: &str) -> Self {
        self.topic = Some(topic.to_owned());
        self
    }

    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ForumThreadProjectionQuery {
    pubkey: Option<String>,
    topic: Option<String>,
    limit: Option<u64>,
}

impl ForumThreadProjectionQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_pubkey(mut self, pubkey: &str) -> Self {
        self.pubkey = Some(pubkey.to_owned());
        self
    }

    pub fn with_topic(mut self, topic: &str) -> Self {
        self.topic = Some(topic.to_owned());
        self
    }

    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LabelProjectionQuery {
    target_type: Option<String>,
    target_ref: Option<String>,
    namespace: Option<String>,
    label: Option<String>,
    pubkey: Option<String>,
    limit: Option<u64>,
}

impl LabelProjectionQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_target(mut self, target_type: &str, target_ref: &str) -> Self {
        self.target_type = Some(target_type.to_owned());
        self.target_ref = Some(target_ref.to_owned());
        self
    }

    pub fn with_namespace(mut self, namespace: &str) -> Self {
        self.namespace = Some(namespace.to_owned());
        self
    }

    pub fn with_label(mut self, label: &str) -> Self {
        self.label = Some(label.to_owned());
        self
    }

    pub fn with_pubkey(mut self, pubkey: &str) -> Self {
        self.pubkey = Some(pubkey.to_owned());
        self
    }

    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReportProjectionQuery {
    target_type: Option<String>,
    target_ref: Option<String>,
    report_type: Option<String>,
    pubkey: Option<String>,
    limit: Option<u64>,
}

impl ReportProjectionQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_target(mut self, target_type: &str, target_ref: &str) -> Self {
        self.target_type = Some(target_type.to_owned());
        self.target_ref = Some(target_ref.to_owned());
        self
    }

    pub fn with_report_type(mut self, report_type: &str) -> Self {
        self.report_type = Some(report_type.to_owned());
        self
    }

    pub fn with_pubkey(mut self, pubkey: &str) -> Self {
        self.pubkey = Some(pubkey.to_owned());
        self
    }

    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SellerProfileQuery {
    pubkey: Option<String>,
    approved: Option<bool>,
    blocked: Option<bool>,
    limit: Option<u64>,
}

impl SellerProfileQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_pubkey(mut self, pubkey: &str) -> Self {
        self.pubkey = Some(pubkey.to_owned());
        self
    }

    pub fn with_approved(mut self, approved: bool) -> Self {
        self.approved = Some(approved);
        self
    }

    pub fn with_blocked(mut self, blocked: bool) -> Self {
        self.blocked = Some(blocked);
        self
    }

    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }
}

#[derive(Clone)]
pub struct SurrealStore {
    db: Surreal<Any>,
}

impl fmt::Debug for SurrealStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SurrealStore")
            .finish_non_exhaustive()
    }
}

impl SurrealStore {
    pub async fn connect(config: &SurrealConnectionConfig) -> Result<Self, SurrealStoreError> {
        match config.mode() {
            SurrealConnectionMode::Memory | SurrealConnectionMode::RocksDb { .. } => {
                Self::connect_local(config).await
            }
            SurrealConnectionMode::Http { endpoint }
            | SurrealConnectionMode::WebSocket { endpoint } => {
                Self::connect_remote(config, endpoint).await
            }
        }
    }

    pub async fn connect_local(
        config: &SurrealConnectionConfig,
    ) -> Result<Self, SurrealStoreError> {
        match config.mode() {
            SurrealConnectionMode::Memory => Self::connect_memory(config).await,
            SurrealConnectionMode::RocksDb { path } => {
                let db = connect_any(rocksdb_endpoint(path))
                    .await
                    .map_err(SurrealStoreError::from)?;
                db.use_ns(config.namespace())
                    .use_db(config.database())
                    .await
                    .map_err(SurrealStoreError::from)?;
                Ok(Self { db })
            }
            SurrealConnectionMode::Http { .. } | SurrealConnectionMode::WebSocket { .. } => {
                Err(SurrealStoreError::new(
                    "surreal local connection requires memory or rocksdb mode config",
                ))
            }
        }
    }

    pub async fn connect_memory(
        config: &SurrealConnectionConfig,
    ) -> Result<Self, SurrealStoreError> {
        if config.mode() != &SurrealConnectionMode::Memory {
            return Err(SurrealStoreError::new(
                "surreal memory connection requires memory mode config",
            ));
        }
        let db = connect_any("memory")
            .await
            .map_err(SurrealStoreError::from)?;
        db.use_ns(config.namespace())
            .use_db(config.database())
            .await
            .map_err(SurrealStoreError::from)?;
        Ok(Self { db })
    }

    async fn connect_remote(
        config: &SurrealConnectionConfig,
        endpoint: &str,
    ) -> Result<Self, SurrealStoreError> {
        let credentials = config.root_credentials().ok_or_else(|| {
            SurrealStoreError::new("surreal remote connection requires root credentials")
        })?;
        let db = connect_any(endpoint)
            .await
            .map_err(SurrealStoreError::from)?;
        db.signin(Root {
            username: credentials.username().to_owned(),
            password: credentials.password().to_owned(),
        })
        .await
        .map_err(SurrealStoreError::from)?;
        db.use_ns(config.namespace())
            .use_db(config.database())
            .await
            .map_err(SurrealStoreError::from)?;
        Ok(Self { db })
    }

    pub fn database(&self) -> &Surreal<Any> {
        &self.db
    }

    pub async fn ping(&self) -> Result<(), SurrealStoreError> {
        self.db
            .query("RETURN true;")
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        Ok(())
    }

    pub async fn apply_plan(
        &self,
        plan: &SurrealMigrationPlan,
    ) -> Result<Vec<MigrationApplyOutcome>, SurrealStoreError> {
        let mut outcomes = Vec::with_capacity(plan.migrations().len());
        for migration in plan.migrations() {
            outcomes.push(self.apply_migration(migration).await?);
        }
        Ok(outcomes)
    }

    pub async fn apply_migration(
        &self,
        migration: &SurrealMigration,
    ) -> Result<MigrationApplyOutcome, SurrealStoreError> {
        if self.has_migration_table().await?
            && let Some(applied) = self.applied_migration(migration.name()).await?
        {
            if applied.checksum() == migration.checksum() {
                return Ok(MigrationApplyOutcome::AlreadyApplied);
            }
            return Err(SurrealStoreError::new(&format!(
                "surreal migration `{}` checksum changed",
                migration.name()
            )));
        }
        self.db
            .query(migration.surql())
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        self.record_migration(migration).await?;
        Ok(MigrationApplyOutcome::Applied)
    }

    pub async fn applied_migrations(&self) -> Result<Vec<AppliedMigration>, SurrealStoreError> {
        if !self.has_migration_table().await? {
            return Ok(Vec::new());
        }
        let mut response = self
            .db
            .query("SELECT VALUE name FROM migration ORDER BY name ASC;")
            .query("SELECT VALUE checksum FROM migration ORDER BY name ASC;")
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        let names: Vec<String> = response.take(0).map_err(SurrealStoreError::from)?;
        let checksums: Vec<String> = response.take(1).map_err(SurrealStoreError::from)?;
        Ok(names
            .into_iter()
            .zip(checksums)
            .map(|(name, checksum)| AppliedMigration { name, checksum })
            .collect())
    }

    pub async fn table_info(&self, table: &str) -> Result<String, SurrealStoreError> {
        let table = normalized_identifier(table, "table").map_err(|error| {
            SurrealStoreError::new(&format!("surreal table info target is invalid: {error}"))
        })?;
        let mut response = self
            .db
            .query(format!("INFO FOR TABLE {table};"))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        let info: surrealdb::types::Value = response.take(0).map_err(SurrealStoreError::from)?;
        Ok(format!("{info:?}"))
    }

    pub async fn metrics_snapshot(&self) -> Result<SurrealMetricsSnapshot, SurrealStoreError> {
        Ok(SurrealMetricsSnapshot {
            stored_events: self
                .count_query("SELECT VALUE count() FROM nostr_event GROUP ALL;")
                .await?,
            visible_events: self
                .count_query(
                    "SELECT VALUE count() FROM nostr_event WHERE deleted = false AND hidden = false GROUP ALL;",
                )
                .await?,
            hidden_events: self
                .count_query("SELECT VALUE count() FROM nostr_event WHERE hidden = true GROUP ALL;")
                .await?,
            deleted_events: self
                .count_query(
                    "SELECT VALUE count() FROM nostr_event WHERE deleted = true GROUP ALL;",
                )
                .await?,
            current_listings: self
                .count_query("SELECT VALUE count() FROM listing_current GROUP ALL;")
                .await?,
            active_listings: self
                .count_query(
                    "SELECT VALUE count() FROM listing_current WHERE effective_status = 'active' AND hidden = false AND deleted = false GROUP ALL;",
                )
                .await?,
            seller_profiles: self
                .count_query("SELECT VALUE count() FROM seller_profile GROUP ALL;")
                .await?,
            visible_seller_profiles: self
                .count_query(
                    "SELECT VALUE count() FROM seller_profile WHERE hidden = false AND deleted = false GROUP ALL;",
                )
                .await?,
            approved_sellers: self
                .count_query(
                    "SELECT VALUE count() FROM relay_user WHERE seller_approved = true AND blocked = false GROUP ALL;",
                )
                .await?,
            blocked_pubkeys: self
                .count_query("SELECT VALUE count() FROM relay_user WHERE blocked = true GROUP ALL;")
                .await?,
        })
    }

    pub async fn store_raw_event(
        &self,
        stored: &StoredEvent,
    ) -> Result<StoreEventOutcome, SurrealStoreError> {
        if self.raw_event_row(stored.event().id()).await?.is_some() {
            return Ok(StoreEventOutcome::Duplicate);
        }
        let event = stored.event();
        self.db
            .query(
                r#"
CREATE type::record('nostr_event', $event_id) CONTENT {
    event_id: $event_id,
    pubkey: $pubkey,
    created_at: $created_at,
    kind: $kind,
    tags: $tags,
    content: $content,
    sig: $sig,
    raw_json: $raw_json,
    received_at: $received_at,
    content_len: $content_len,
    tag_count: $tag_count,
    d_tag: $d_tag,
    address_key: $address_key,
    deleted: false,
    hidden: false,
    rejection_reason: NONE
};
"#,
            )
            .bind(("event_id", event.id().as_str()))
            .bind(("pubkey", event.unsigned().pubkey().as_str()))
            .bind(("created_at", event.unsigned().created_at().as_u64()))
            .bind(("kind", event.unsigned().kind().as_u32()))
            .bind(("tags", event_tags_json(event)))
            .bind(("content", event.unsigned().content()))
            .bind(("sig", event.sig().as_str()))
            .bind(("raw_json", event_to_value(event).to_string()))
            .bind(("received_at", stored.received_at().as_u64()))
            .bind(("content_len", stored.content_len() as u64))
            .bind(("tag_count", stored.tag_count() as u64))
            .bind(("d_tag", d_tag_value(event)))
            .bind(("address_key", address_key_value(event)?))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        Ok(StoreEventOutcome::Inserted)
    }

    pub async fn raw_event_row(
        &self,
        event_id: &EventId,
    ) -> Result<Option<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query("SELECT * FROM ONLY type::record('nostr_event', $event_id);")
            .bind(("event_id", event_id.as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    async fn count_query(&self, statement: &str) -> Result<u64, SurrealStoreError> {
        let mut response = self
            .db
            .query(statement)
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        let rows: Vec<serde_json::Value> = response.take(0).map_err(SurrealStoreError::from)?;
        rows.into_iter().next().map(count_value).unwrap_or(Ok(0))
    }

    pub async fn query_raw_events(
        &self,
        filter: &Filter,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let mut statement =
            "SELECT * FROM nostr_event WHERE deleted = false AND hidden = false".to_owned();
        if !filter.ids().is_empty() {
            statement.push_str(" AND event_id IN $ids");
        }
        if !filter.authors().is_empty() {
            statement.push_str(" AND pubkey IN $authors");
        }
        if !filter.kinds().is_empty() {
            statement.push_str(" AND kind IN $kinds");
        }
        if filter.since().is_some() {
            statement.push_str(" AND created_at >= $since");
        }
        if filter.until().is_some() {
            statement.push_str(" AND created_at <= $until");
        }
        statement.push_str(" ORDER BY created_at DESC, event_id ASC");
        if filter.limit().is_some() {
            statement.push_str(" LIMIT $limit");
        }
        statement.push(';');
        let mut query = self.db.query(statement);
        if !filter.ids().is_empty() {
            query = query.bind((
                "ids",
                filter
                    .ids()
                    .iter()
                    .map(|id| id.as_str().to_owned())
                    .collect::<Vec<_>>(),
            ));
        }
        if !filter.authors().is_empty() {
            query = query.bind((
                "authors",
                filter
                    .authors()
                    .iter()
                    .map(|pubkey| pubkey.as_str().to_owned())
                    .collect::<Vec<_>>(),
            ));
        }
        if !filter.kinds().is_empty() {
            query = query.bind((
                "kinds",
                filter
                    .kinds()
                    .iter()
                    .map(|kind| kind.as_u32())
                    .collect::<Vec<_>>(),
            ));
        }
        if let Some(since) = filter.since() {
            query = query.bind(("since", since.as_u64()));
        }
        if let Some(until) = filter.until() {
            query = query.bind(("until", until.as_u64()));
        }
        if let Some(limit) = filter.limit() {
            query = query.bind(("limit", limit));
        }
        let mut response = query
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn backup_raw_events(&self) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query("SELECT * FROM nostr_event ORDER BY created_at ASC, event_id ASC;")
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn index_event_tags(&self, event: &Event) -> Result<(), SurrealStoreError> {
        self.db
            .query("DELETE event_tag_index WHERE event_id = $event_id;")
            .bind(("event_id", event.id().as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        for (ordinal, tag) in event.unsigned().tags().iter().enumerate() {
            let Some((name, value)) = tag.indexed_pair() else {
                continue;
            };
            self.db
                .query(
                    r#"
CREATE event_tag_index CONTENT {
    event_id: $event_id,
    kind: $kind,
    pubkey: $pubkey,
    created_at: $created_at,
    tag: $tag,
    value: $value,
    ordinal: $ordinal
};
"#,
                )
                .bind(("event_id", event.id().as_str()))
                .bind(("kind", event.unsigned().kind().as_u32()))
                .bind(("pubkey", event.unsigned().pubkey().as_str()))
                .bind(("created_at", event.unsigned().created_at().as_u64()))
                .bind(("tag", name))
                .bind(("value", value))
                .bind(("ordinal", ordinal as u64))
                .await
                .map_err(SurrealStoreError::from)?
                .check()
                .map_err(SurrealStoreError::from)?;
        }
        Ok(())
    }

    pub async fn tag_index_rows(
        &self,
        event_id: &EventId,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query("SELECT * FROM event_tag_index WHERE event_id = $event_id ORDER BY ordinal ASC;")
            .bind(("event_id", event_id.as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn query_indexed_tag_event_ids(
        &self,
        filter: &Filter,
    ) -> Result<Vec<String>, SurrealStoreError> {
        if filter.tag_filters().is_empty() {
            return Ok(Vec::new());
        }
        let mut first_order = Vec::new();
        let mut intersection = None::<BTreeSet<String>>;
        for (name, values) in filter.tag_filters() {
            let ids = self
                .query_single_indexed_tag_event_ids(
                    name.as_str(),
                    &values
                        .iter()
                        .map(|value| value.as_str().to_owned())
                        .collect::<Vec<_>>(),
                    filter,
                )
                .await?;
            let ids = unique_in_order(ids);
            if first_order.is_empty() {
                first_order = ids.clone();
            }
            let current = ids.into_iter().collect::<BTreeSet<_>>();
            intersection = Some(match intersection {
                Some(previous) => previous.intersection(&current).cloned().collect(),
                None => current,
            });
        }
        let intersection = intersection.unwrap_or_default();
        let mut result = first_order
            .into_iter()
            .filter(|event_id| intersection.contains(event_id))
            .collect::<Vec<_>>();
        if let Some(limit) = filter.limit() {
            result.truncate(limit as usize);
        }
        Ok(result)
    }

    pub async fn maintain_current_event(
        &self,
        event: &Event,
    ) -> Result<CurrentEventOutcome, SurrealStoreError> {
        let Some(current_key) = current_event_key(event)? else {
            return Ok(CurrentEventOutcome::NotCurrent);
        };
        let existing = self.current_event_row(&current_key.address_key).await?;
        let outcome = existing
            .as_ref()
            .map(|row| current_event_replacement_outcome(event, row))
            .unwrap_or(CurrentEventOutcome::Inserted);
        if outcome == CurrentEventOutcome::Unchanged {
            return Ok(outcome);
        }
        self.db
            .query(
                r#"
UPSERT type::record('event_current', $address_key) CONTENT {
    address_key: $address_key,
    kind: $kind,
    pubkey: $pubkey,
    d: $d,
    event_id: $event_id,
    created_at: $created_at,
    tie_break_id: $tie_break_id,
    deleted: false,
    hidden: false,
    updated_at: $updated_at
};
"#,
            )
            .bind(("address_key", current_key.address_key))
            .bind(("kind", event.unsigned().kind().as_u32()))
            .bind(("pubkey", event.unsigned().pubkey().as_str()))
            .bind(("d", current_key.d))
            .bind(("event_id", event.id().as_str()))
            .bind(("created_at", event.unsigned().created_at().as_u64()))
            .bind(("tie_break_id", event.id().as_str()))
            .bind(("updated_at", event.unsigned().created_at().as_u64()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        Ok(outcome)
    }

    pub async fn current_event_row(
        &self,
        address_key: &str,
    ) -> Result<Option<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query("SELECT * FROM ONLY type::record('event_current', $address_key);")
            .bind(("address_key", address_key))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn query_current_events(
        &self,
        filter: &Filter,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let mut statement =
            "SELECT * FROM event_current WHERE deleted = false AND hidden = false".to_owned();
        if !filter.ids().is_empty() {
            statement.push_str(" AND event_id IN $ids");
        }
        if !filter.authors().is_empty() {
            statement.push_str(" AND pubkey IN $authors");
        }
        if !filter.kinds().is_empty() {
            statement.push_str(" AND kind IN $kinds");
        }
        if filter.since().is_some() {
            statement.push_str(" AND created_at >= $since");
        }
        if filter.until().is_some() {
            statement.push_str(" AND created_at <= $until");
        }
        statement.push_str(" ORDER BY created_at DESC, event_id ASC");
        if filter.limit().is_some() {
            statement.push_str(" LIMIT $limit");
        }
        statement.push(';');
        let mut query = self.db.query(statement);
        if !filter.ids().is_empty() {
            query = query.bind((
                "ids",
                filter
                    .ids()
                    .iter()
                    .map(|id| id.as_str().to_owned())
                    .collect::<Vec<_>>(),
            ));
        }
        if !filter.authors().is_empty() {
            query = query.bind((
                "authors",
                filter
                    .authors()
                    .iter()
                    .map(|pubkey| pubkey.as_str().to_owned())
                    .collect::<Vec<_>>(),
            ));
        }
        if !filter.kinds().is_empty() {
            query = query.bind((
                "kinds",
                filter
                    .kinds()
                    .iter()
                    .map(|kind| kind.as_u32())
                    .collect::<Vec<_>>(),
            ));
        }
        if let Some(since) = filter.since() {
            query = query.bind(("since", since.as_u64()));
        }
        if let Some(until) = filter.until() {
            query = query.bind(("until", until.as_u64()));
        }
        if let Some(limit) = filter.limit() {
            query = query.bind(("limit", limit));
        }
        let mut response = query
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn apply_deletion_markers(
        &self,
        event: &Event,
    ) -> Result<DeletionMarkerOutcome, SurrealStoreError> {
        let Some(request) =
            parse_deletion_request(event).map_err(|message| SurrealStoreError::new(&message))?
        else {
            return Ok(DeletionMarkerOutcome::NotDeletion);
        };
        for target in request.targets() {
            let (target_type, target_ref) = deletion_target_parts(target);
            let marker_id = format!("{}:{}:{}", event.id().as_str(), target_type, target_ref);
            self.db
                .query(
                    r#"
UPSERT type::record('deletion_marker', $marker_id) CONTENT {
    deletion_event_id: $deletion_event_id,
    target_type: $target_type,
    target_ref: $target_ref,
    author_pubkey: $author_pubkey,
    deletion_created_at: $deletion_created_at
};
"#,
                )
                .bind(("marker_id", marker_id))
                .bind(("deletion_event_id", event.id().as_str()))
                .bind(("target_type", target_type))
                .bind(("target_ref", target_ref.as_str()))
                .bind(("author_pubkey", event.unsigned().pubkey().as_str()))
                .bind((
                    "deletion_created_at",
                    event.unsigned().created_at().as_u64(),
                ))
                .await
                .map_err(SurrealStoreError::from)?
                .check()
                .map_err(SurrealStoreError::from)?;
            if target_type == "event" {
                self.mark_raw_event_deleted(
                    &target_ref,
                    event.unsigned().pubkey().as_str(),
                    event.unsigned().created_at().as_u64(),
                )
                .await?;
            } else {
                self.mark_address_deleted(&target_ref, event.unsigned().pubkey().as_str())
                    .await?;
            }
        }
        Ok(DeletionMarkerOutcome::Applied {
            targets: request.targets().len(),
        })
    }

    pub async fn deletion_marker_rows(
        &self,
        deletion_event_id: &EventId,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query(
                "SELECT * FROM deletion_marker WHERE deletion_event_id = $deletion_event_id ORDER BY target_type ASC, target_ref ASC;",
            )
            .bind(("deletion_event_id", deletion_event_id.as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn store_listing_revision(
        &self,
        event: &Event,
        projected_at: UnixTimestamp,
    ) -> Result<ListingRevisionOutcome, SurrealStoreError> {
        if !is_listing_event(event) {
            return Ok(ListingRevisionOutcome::NotListing);
        }
        let evaluation = evaluate_listing_projection(event);
        let fields = listing_revision_fields(event, &evaluation)?;
        self.db
            .query(
                r#"
UPSERT type::record('listing_revision', $event_id) CONTENT {
    revision_key: $revision_key,
    listing_key: $listing_key,
    event_id: $event_id,
    seller_pubkey: $seller_pubkey,
    d: $d,
    created_at: $created_at,
    parsed_ok: $parsed_ok,
    parse_errors: $parse_errors,
    title: $title,
    summary: $summary,
    price_decimal: $price_decimal,
    price_minor: $price_minor,
    currency_raw: $currency_raw,
    currency_norm: $currency_norm,
    unit: $unit,
    status_tag: $status_tag,
    projected_at: $projected_at
};
"#,
            )
            .bind(("event_id", event.id().as_str()))
            .bind(("revision_key", fields.revision_key))
            .bind(("listing_key", fields.listing_key))
            .bind(("seller_pubkey", fields.seller_pubkey))
            .bind(("d", fields.d))
            .bind(("created_at", event.unsigned().created_at().as_u64()))
            .bind(("parsed_ok", fields.parsed_ok))
            .bind(("parse_errors", fields.parse_errors))
            .bind(("title", fields.title))
            .bind(("summary", fields.summary))
            .bind(("price_decimal", fields.price_decimal))
            .bind(("price_minor", fields.price_minor))
            .bind(("currency_raw", fields.currency_raw))
            .bind(("currency_norm", fields.currency_norm))
            .bind(("unit", fields.unit))
            .bind(("status_tag", fields.status_tag))
            .bind(("projected_at", projected_at.as_u64()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        Ok(ListingRevisionOutcome::Stored {
            parsed_ok: fields.parsed_ok,
        })
    }

    pub async fn listing_revision_row(
        &self,
        event_id: &EventId,
    ) -> Result<Option<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query("SELECT * FROM ONLY type::record('listing_revision', $event_id);")
            .bind(("event_id", event_id.as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn project_current_listing(
        &self,
        event: &Event,
        projected_at: UnixTimestamp,
    ) -> Result<ListingCurrentOutcome, SurrealStoreError> {
        let evaluation = evaluate_listing_projection(event);
        let ListingProjectionEvaluation::Eligible(projection) = evaluation else {
            return Ok(
                if matches!(evaluation, ListingProjectionEvaluation::NotListing) {
                    ListingCurrentOutcome::NotListing
                } else {
                    ListingCurrentOutcome::Ineligible
                },
            );
        };
        let fields = listing_current_fields(&projection, event, projected_at)?;
        self.db
            .query(
                r#"
UPSERT type::record('listing_current', $listing_key) CONTENT {
    listing_key: $listing_key,
    listing_key_hash: $listing_key_hash,
    event_id: $event_id,
    seller_pubkey: $seller_pubkey,
    d: $d,
    created_at: $created_at,
    updated_at: $updated_at,
    published_at: $published_at,
    title: $title,
    summary: $summary,
    content: $content,
    price_decimal: $price_decimal,
    price_minor: $price_minor,
    currency_raw: $currency_raw,
    currency_norm: $currency_norm,
    price_frequency: $price_frequency,
    unit: $unit,
    unit_family: $unit_family,
    location_text: $location_text,
    geohash: $geohash,
    geohash4: $geohash4,
    geohash5: $geohash5,
    geohash6: $geohash6,
    geohash7: $geohash7,
    point: $point,
    status_tag: $status_tag,
    effective_status: $effective_status,
    categories: $categories,
    tags: $tags,
    practices: $practices,
    certifications: $certifications,
    image_urls: $image_urls,
    pickup_available: $pickup_available,
    delivery_available: $delivery_available,
    shipping_available: $shipping_available,
    delivery_only: $delivery_only,
    seller_trust_score: $seller_trust_score,
    hidden: false,
    deleted: false,
    projected_at: $projected_at
};
"#,
            )
            .bind(("listing_key", fields.listing_key))
            .bind(("listing_key_hash", fields.listing_key_hash))
            .bind(("event_id", event.id().as_str()))
            .bind(("seller_pubkey", fields.seller_pubkey))
            .bind(("d", fields.d))
            .bind(("created_at", event.unsigned().created_at().as_u64()))
            .bind(("updated_at", event.unsigned().created_at().as_u64()))
            .bind(("published_at", fields.published_at))
            .bind(("title", fields.title))
            .bind(("summary", fields.summary))
            .bind(("content", fields.content))
            .bind(("price_decimal", fields.price_decimal))
            .bind(("price_minor", fields.price_minor))
            .bind(("currency_raw", fields.currency_raw))
            .bind(("currency_norm", fields.currency_norm))
            .bind(("price_frequency", fields.price_frequency))
            .bind(("unit", fields.unit.clone()))
            .bind(("unit_family", fields.unit))
            .bind(("location_text", fields.location_text))
            .bind(("geohash", fields.geohash))
            .bind(("geohash4", fields.geohash4))
            .bind(("geohash5", fields.geohash5))
            .bind(("geohash6", fields.geohash6))
            .bind(("geohash7", fields.geohash7))
            .bind(("point", Option::<Vec<serde_json::Value>>::None))
            .bind(("status_tag", fields.status_tag))
            .bind(("effective_status", fields.effective_status))
            .bind(("categories", fields.categories))
            .bind(("tags", fields.tags))
            .bind(("practices", fields.practices))
            .bind(("certifications", fields.certifications))
            .bind(("image_urls", fields.image_urls))
            .bind(("pickup_available", fields.pickup_available))
            .bind(("delivery_available", fields.delivery_available))
            .bind(("shipping_available", fields.shipping_available))
            .bind(("delivery_only", fields.delivery_only))
            .bind(("seller_trust_score", Option::<i64>::None))
            .bind(("projected_at", projected_at.as_u64()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        Ok(ListingCurrentOutcome::Projected)
    }

    pub async fn listing_current_row(
        &self,
        listing_key: &str,
    ) -> Result<Option<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query("SELECT * FROM ONLY type::record('listing_current', $listing_key);")
            .bind(("listing_key", listing_key))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn query_current_listings(
        &self,
        query: &ListingProjectionQuery,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let mut statement =
            "SELECT * FROM listing_current WHERE hidden = false AND deleted = false".to_owned();
        if query.effective_status.is_some() {
            statement.push_str(" AND effective_status = $effective_status");
        }
        if query.seller_pubkey.is_some() {
            statement.push_str(" AND seller_pubkey = $seller_pubkey");
        }
        if query.unit.is_some() {
            statement.push_str(" AND unit = $unit");
        }
        if query.currency_norm.is_some() {
            statement.push_str(" AND currency_norm = $currency_norm");
        }
        if query.min_price_minor.is_some() {
            statement.push_str(" AND price_minor >= $min_price_minor");
        }
        if query.max_price_minor.is_some() {
            statement.push_str(" AND price_minor <= $max_price_minor");
        }
        statement.push_str(" ORDER BY updated_at DESC, event_id ASC");
        if query.limit.is_some() {
            statement.push_str(" LIMIT $limit");
        }
        statement.push(';');
        let mut surreal_query = self.db.query(statement);
        if let Some(value) = &query.effective_status {
            surreal_query = surreal_query.bind(("effective_status", value.as_str()));
        }
        if let Some(value) = &query.seller_pubkey {
            surreal_query = surreal_query.bind(("seller_pubkey", value.as_str()));
        }
        if let Some(value) = &query.unit {
            surreal_query = surreal_query.bind(("unit", value.as_str()));
        }
        if let Some(value) = &query.currency_norm {
            surreal_query = surreal_query.bind(("currency_norm", value.as_str()));
        }
        if let Some(value) = query.min_price_minor {
            surreal_query = surreal_query.bind(("min_price_minor", value));
        }
        if let Some(value) = query.max_price_minor {
            surreal_query = surreal_query.bind(("max_price_minor", value));
        }
        if let Some(value) = query.limit {
            surreal_query = surreal_query.bind(("limit", value));
        }
        let mut response = surreal_query
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn project_comment(
        &self,
        event: &Event,
        projected_at: UnixTimestamp,
    ) -> Result<CommentProjectionOutcome, SurrealStoreError> {
        let comment = match parse_comment_event(event) {
            Ok(Some(comment)) => comment,
            Ok(None) => return Ok(CommentProjectionOutcome::NotComment),
            Err(_) => return Ok(CommentProjectionOutcome::Ineligible),
        };
        let fields = comment_projection_fields(&comment, projected_at);
        self.db
            .query(
                r#"
UPSERT type::record('comment_projection', $event_id) CONTENT {
    comment_id: $comment_id,
    event_id: $event_id,
    pubkey: $pubkey,
    created_at: $created_at,
    content: $content,
    root_target_type: $root_target_type,
    root_ref: $root_ref,
    root_kind: $root_kind,
    root_author: $root_author,
    parent_target_type: $parent_target_type,
    parent_ref: $parent_ref,
    parent_kind: $parent_kind,
    parent_author: $parent_author,
    hidden: false,
    deleted: false,
    projected_at: $projected_at
};
"#,
            )
            .bind(("event_id", event.id().as_str()))
            .bind(("comment_id", fields.comment_id))
            .bind(("pubkey", fields.pubkey))
            .bind(("created_at", fields.created_at))
            .bind(("content", fields.content))
            .bind(("root_target_type", fields.root_target_type))
            .bind(("root_ref", fields.root_ref))
            .bind(("root_kind", fields.root_kind))
            .bind(("root_author", fields.root_author))
            .bind(("parent_target_type", fields.parent_target_type))
            .bind(("parent_ref", fields.parent_ref))
            .bind(("parent_kind", fields.parent_kind))
            .bind(("parent_author", fields.parent_author))
            .bind(("projected_at", fields.projected_at))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        Ok(CommentProjectionOutcome::Projected)
    }

    pub async fn comment_projection_row(
        &self,
        event_id: &EventId,
    ) -> Result<Option<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query("SELECT * FROM ONLY type::record('comment_projection', $event_id);")
            .bind(("event_id", event_id.as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn query_comment_projections(
        &self,
        query: &CommentProjectionQuery,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let mut statement =
            "SELECT * FROM comment_projection WHERE hidden = false AND deleted = false".to_owned();
        if query.root_target_type.is_some() {
            statement.push_str(" AND root_target_type = $root_target_type");
        }
        if query.root_ref.is_some() {
            statement.push_str(" AND root_ref = $root_ref");
        }
        if query.parent_target_type.is_some() {
            statement.push_str(" AND parent_target_type = $parent_target_type");
        }
        if query.parent_ref.is_some() {
            statement.push_str(" AND parent_ref = $parent_ref");
        }
        if query.pubkey.is_some() {
            statement.push_str(" AND pubkey = $pubkey");
        }
        statement.push_str(" ORDER BY created_at ASC, event_id ASC");
        if query.limit.is_some() {
            statement.push_str(" LIMIT $limit");
        }
        statement.push(';');
        let mut surreal_query = self.db.query(statement);
        if let Some(value) = &query.root_target_type {
            surreal_query = surreal_query.bind(("root_target_type", value.as_str()));
        }
        if let Some(value) = &query.root_ref {
            surreal_query = surreal_query.bind(("root_ref", value.as_str()));
        }
        if let Some(value) = &query.parent_target_type {
            surreal_query = surreal_query.bind(("parent_target_type", value.as_str()));
        }
        if let Some(value) = &query.parent_ref {
            surreal_query = surreal_query.bind(("parent_ref", value.as_str()));
        }
        if let Some(value) = &query.pubkey {
            surreal_query = surreal_query.bind(("pubkey", value.as_str()));
        }
        if let Some(value) = query.limit {
            surreal_query = surreal_query.bind(("limit", value));
        }
        let mut response = surreal_query
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn project_reaction(
        &self,
        event: &Event,
        projected_at: UnixTimestamp,
    ) -> Result<ReactionProjectionOutcome, SurrealStoreError> {
        let reaction = match parse_reaction_event(event) {
            Ok(Some(reaction)) => reaction,
            Ok(None) => return Ok(ReactionProjectionOutcome::NotReaction),
            Err(_) => return Ok(ReactionProjectionOutcome::Ineligible),
        };
        let fields = reaction_projection_fields(&reaction, projected_at);
        self.db
            .query(
                r#"
UPSERT type::record('reaction_projection', $event_id) CONTENT {
    reaction_id: $reaction_id,
    event_id: $event_id,
    pubkey: $pubkey,
    created_at: $created_at,
    content: $content,
    value_type: $value_type,
    value: $value,
    target_event_id: $target_event_id,
    target_pubkey: $target_pubkey,
    target_address: $target_address,
    target_kind: $target_kind,
    hidden: false,
    deleted: false,
    projected_at: $projected_at
};
"#,
            )
            .bind(("event_id", event.id().as_str()))
            .bind(("reaction_id", fields.reaction_id))
            .bind(("pubkey", fields.pubkey))
            .bind(("created_at", fields.created_at))
            .bind(("content", fields.content))
            .bind(("value_type", fields.value_type))
            .bind(("value", fields.value))
            .bind(("target_event_id", fields.target_event_id.as_str()))
            .bind(("target_pubkey", fields.target_pubkey))
            .bind(("target_address", fields.target_address))
            .bind(("target_kind", fields.target_kind.as_deref()))
            .bind(("projected_at", fields.projected_at))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        self.recompute_reaction_count(
            &fields.target_event_id,
            fields.target_kind,
            projected_at.as_u64(),
        )
        .await?;
        Ok(ReactionProjectionOutcome::Projected)
    }

    pub async fn reaction_projection_row(
        &self,
        event_id: &EventId,
    ) -> Result<Option<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query("SELECT * FROM ONLY type::record('reaction_projection', $event_id);")
            .bind(("event_id", event_id.as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn reaction_count_row(
        &self,
        target_event_id: &EventId,
    ) -> Result<Option<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query("SELECT * FROM ONLY type::record('reaction_count', $target_event_id);")
            .bind(("target_event_id", target_event_id.as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn project_long_form(
        &self,
        event: &Event,
        projected_at: UnixTimestamp,
    ) -> Result<LongFormProjectionOutcome, SurrealStoreError> {
        let article = match parse_long_form_event(event) {
            Ok(Some(article)) => article,
            Ok(None) => return Ok(LongFormProjectionOutcome::NotLongForm),
            Err(_) => return Ok(LongFormProjectionOutcome::Ineligible),
        };
        if article.long_form_kind() != LongFormKind::Published {
            return Ok(LongFormProjectionOutcome::Ineligible);
        }
        let fields = long_form_projection_fields(&article, projected_at);
        if self
            .long_form_current_row(&fields.long_form_key)
            .await?
            .as_ref()
            .is_some_and(|row| !long_form_current_should_replace(&article, row))
        {
            return Ok(LongFormProjectionOutcome::Ineligible);
        }
        self.db
            .query(
                r#"
UPSERT type::record('long_form_current', $long_form_key) CONTENT {
    long_form_key: $long_form_key,
    event_id: $event_id,
    author_pubkey: $author_pubkey,
    d: $d,
    created_at: $created_at,
    updated_at: $updated_at,
    published_at: $published_at,
    title: $title,
    image: $image,
    summary: $summary,
    content: $content,
    tags: $tags,
    referenced_events: $referenced_events,
    referenced_addresses: $referenced_addresses,
    referenced_pubkeys: $referenced_pubkeys,
    hidden: false,
    deleted: false,
    projected_at: $projected_at
};
UPSERT type::record('search_doc', $long_form_key) CONTENT {
    doc_key: $long_form_key,
    event_id: $event_id,
    current_event_id: $event_id,
    doc_type: "long_form",
    kind: $kind,
    pubkey: $author_pubkey,
    address_key: $long_form_key,
    title: $search_title,
    summary: $summary,
    body: $content,
    category_text: $category_text,
    location_text: NONE,
    tags: $tags,
    categories: [],
    created_at: $created_at,
    updated_at: $updated_at,
    visible: true,
    status: "published",
    seller_trust_score: NONE
};
"#,
            )
            .bind(("long_form_key", fields.long_form_key.as_str()))
            .bind(("event_id", fields.event_id.as_str()))
            .bind(("author_pubkey", fields.author_pubkey.as_str()))
            .bind(("d", fields.d.as_str()))
            .bind(("created_at", fields.created_at))
            .bind(("updated_at", fields.updated_at))
            .bind(("published_at", fields.published_at))
            .bind(("title", fields.title.as_deref()))
            .bind(("image", fields.image.as_deref()))
            .bind(("summary", fields.summary.as_deref()))
            .bind(("content", fields.content.as_str()))
            .bind(("tags", fields.tags.clone()))
            .bind(("referenced_events", fields.referenced_events.clone()))
            .bind(("referenced_addresses", fields.referenced_addresses.clone()))
            .bind(("referenced_pubkeys", fields.referenced_pubkeys.clone()))
            .bind(("projected_at", fields.projected_at))
            .bind(("kind", fields.kind))
            .bind(("search_title", fields.search_title.as_str()))
            .bind(("category_text", fields.tags.join(" ")))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        self.replace_long_form_topic_rows(&fields).await?;
        Ok(LongFormProjectionOutcome::Projected)
    }

    pub async fn long_form_current_row(
        &self,
        long_form_key: &str,
    ) -> Result<Option<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query("SELECT * FROM ONLY type::record('long_form_current', $long_form_key);")
            .bind(("long_form_key", long_form_key))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn long_form_topic_rows(
        &self,
        long_form_key: &str,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query(
                "SELECT * FROM long_form_topic WHERE long_form_key = $long_form_key ORDER BY topic ASC;",
            )
            .bind(("long_form_key", long_form_key))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn query_long_form_projections(
        &self,
        query: &LongFormProjectionQuery,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let topic_keys = match query.topic.as_deref() {
            Some(topic) => {
                let normalized = topic.trim().to_ascii_lowercase();
                let mut response = self
                    .db
                    .query(
                        "SELECT VALUE long_form_key FROM long_form_topic WHERE topic = $topic AND hidden = false AND deleted = false ORDER BY updated_at DESC, event_id ASC;",
                    )
                    .bind(("topic", normalized.as_str()))
                    .await
                    .map_err(SurrealStoreError::from)?
                    .check()
                    .map_err(SurrealStoreError::from)?;
                let keys: Vec<String> = response.take(0).map_err(SurrealStoreError::from)?;
                if keys.is_empty() {
                    return Ok(Vec::new());
                }
                Some(keys)
            }
            None => None,
        };
        let mut statement =
            "SELECT * FROM long_form_current WHERE hidden = false AND deleted = false".to_owned();
        if query.author_pubkey.is_some() {
            statement.push_str(" AND author_pubkey = $author_pubkey");
        }
        if topic_keys.is_some() {
            statement.push_str(" AND long_form_key IN $topic_keys");
        }
        statement.push_str(" ORDER BY updated_at DESC, event_id ASC");
        if query.limit.is_some() {
            statement.push_str(" LIMIT $limit");
        }
        statement.push(';');
        let mut surreal_query = self.db.query(statement);
        if let Some(value) = &query.author_pubkey {
            surreal_query = surreal_query.bind(("author_pubkey", value.as_str()));
        }
        if let Some(keys) = topic_keys {
            surreal_query = surreal_query.bind(("topic_keys", keys));
        }
        if let Some(value) = query.limit {
            surreal_query = surreal_query.bind(("limit", value));
        }
        let mut response = surreal_query
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn project_forum_thread(
        &self,
        event: &Event,
        projected_at: UnixTimestamp,
    ) -> Result<ForumThreadProjectionOutcome, SurrealStoreError> {
        let thread = match parse_forum_thread_event(event) {
            Ok(Some(thread)) => thread,
            Ok(None) => return Ok(ForumThreadProjectionOutcome::NotForumThread),
            Err(_) => return Ok(ForumThreadProjectionOutcome::Ineligible),
        };
        let fields = forum_thread_projection_fields(&thread, projected_at);
        self.db
            .query(
                r#"
UPSERT type::record('forum_thread_projection', $thread_id) CONTENT {
    thread_id: $thread_id,
    event_id: $event_id,
    pubkey: $pubkey,
    created_at: $created_at,
    updated_at: $updated_at,
    title: $title,
    content: $content,
    tags: $tags,
    referenced_events: $referenced_events,
    referenced_pubkeys: $referenced_pubkeys,
    hidden: false,
    deleted: false,
    projected_at: $projected_at
};
UPSERT type::record('search_doc', $thread_id) CONTENT {
    doc_key: $thread_id,
    event_id: $event_id,
    current_event_id: $event_id,
    doc_type: "forum_thread",
    kind: $kind,
    pubkey: $pubkey,
    address_key: NONE,
    title: $search_title,
    summary: $title,
    body: $content,
    category_text: $category_text,
    location_text: NONE,
    tags: $tags,
    categories: [],
    created_at: $created_at,
    updated_at: $updated_at,
    visible: true,
    status: "open",
    seller_trust_score: NONE
};
"#,
            )
            .bind(("thread_id", fields.thread_id.as_str()))
            .bind(("event_id", fields.event_id.as_str()))
            .bind(("pubkey", fields.pubkey.as_str()))
            .bind(("created_at", fields.created_at))
            .bind(("updated_at", fields.updated_at))
            .bind(("title", fields.title.as_deref()))
            .bind(("content", fields.content.as_str()))
            .bind(("tags", fields.tags.clone()))
            .bind(("referenced_events", fields.referenced_events.clone()))
            .bind(("referenced_pubkeys", fields.referenced_pubkeys.clone()))
            .bind(("projected_at", fields.projected_at))
            .bind(("kind", fields.kind))
            .bind(("search_title", fields.search_title.as_str()))
            .bind(("category_text", fields.tags.join(" ")))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        self.replace_forum_thread_topic_rows(&fields).await?;
        Ok(ForumThreadProjectionOutcome::Projected)
    }

    pub async fn forum_thread_row(
        &self,
        thread_id: &EventId,
    ) -> Result<Option<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query("SELECT * FROM ONLY type::record('forum_thread_projection', $thread_id);")
            .bind(("thread_id", thread_id.as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn forum_thread_topic_rows(
        &self,
        thread_id: &EventId,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query(
                "SELECT * FROM forum_thread_topic WHERE thread_id = $thread_id ORDER BY topic ASC;",
            )
            .bind(("thread_id", thread_id.as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn query_forum_threads(
        &self,
        query: &ForumThreadProjectionQuery,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let topic_thread_ids = match query.topic.as_deref() {
            Some(topic) => {
                let normalized = topic.trim().to_ascii_lowercase();
                let mut response = self
                    .db
                    .query(
                        "SELECT VALUE thread_id FROM forum_thread_topic WHERE topic = $topic AND hidden = false AND deleted = false ORDER BY updated_at DESC, event_id ASC;",
                    )
                    .bind(("topic", normalized.as_str()))
                    .await
                    .map_err(SurrealStoreError::from)?
                    .check()
                    .map_err(SurrealStoreError::from)?;
                let ids: Vec<String> = response.take(0).map_err(SurrealStoreError::from)?;
                if ids.is_empty() {
                    return Ok(Vec::new());
                }
                Some(ids)
            }
            None => None,
        };
        let mut statement =
            "SELECT * FROM forum_thread_projection WHERE hidden = false AND deleted = false"
                .to_owned();
        if query.pubkey.is_some() {
            statement.push_str(" AND pubkey = $pubkey");
        }
        if topic_thread_ids.is_some() {
            statement.push_str(" AND thread_id IN $topic_thread_ids");
        }
        statement.push_str(" ORDER BY updated_at DESC, event_id ASC");
        if query.limit.is_some() {
            statement.push_str(" LIMIT $limit");
        }
        statement.push(';');
        let mut surreal_query = self.db.query(statement);
        if let Some(value) = &query.pubkey {
            surreal_query = surreal_query.bind(("pubkey", value.as_str()));
        }
        if let Some(ids) = topic_thread_ids {
            surreal_query = surreal_query.bind(("topic_thread_ids", ids));
        }
        if let Some(value) = query.limit {
            surreal_query = surreal_query.bind(("limit", value));
        }
        let mut response = surreal_query
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn project_label(
        &self,
        event: &Event,
        projected_at: UnixTimestamp,
    ) -> Result<LabelProjectionOutcome, SurrealStoreError> {
        let label = match parse_label_event(event) {
            Ok(Some(label)) => label,
            Ok(None) => return Ok(LabelProjectionOutcome::NotLabel),
            Err(_) => return Ok(LabelProjectionOutcome::Ineligible),
        };
        let fields = label_projection_fields(&label, projected_at);
        self.db
            .query("DELETE label_projection WHERE event_id = $event_id;")
            .bind(("event_id", label.event_id().as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        for field in fields {
            self.db
                .query(
                    r#"
UPSERT type::record('label_projection', $label_id) CONTENT {
    label_id: $label_id,
    event_id: $event_id,
    pubkey: $pubkey,
    created_at: $created_at,
    content: $content,
    namespace: $namespace,
    label: $label,
    target_type: $target_type,
    target_ref: $target_ref,
    hidden: false,
    deleted: false,
    projected_at: $projected_at
};
"#,
                )
                .bind(("label_id", field.label_id.as_str()))
                .bind(("event_id", field.event_id.as_str()))
                .bind(("pubkey", field.pubkey.as_str()))
                .bind(("created_at", field.created_at))
                .bind(("content", field.content.as_str()))
                .bind(("namespace", field.namespace.as_str()))
                .bind(("label", field.label.as_str()))
                .bind(("target_type", field.target_type.as_str()))
                .bind(("target_ref", field.target_ref.as_str()))
                .bind(("projected_at", field.projected_at))
                .await
                .map_err(SurrealStoreError::from)?
                .check()
                .map_err(SurrealStoreError::from)?;
        }
        Ok(LabelProjectionOutcome::Projected)
    }

    pub async fn label_projection_rows(
        &self,
        event_id: &EventId,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query(
                "SELECT * FROM label_projection WHERE event_id = $event_id ORDER BY target_type ASC, target_ref ASC, namespace ASC, label ASC, label_id ASC;",
            )
            .bind(("event_id", event_id.as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn query_label_projections(
        &self,
        query: &LabelProjectionQuery,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let mut statement =
            "SELECT * FROM label_projection WHERE hidden = false AND deleted = false".to_owned();
        if query.target_type.is_some() {
            statement.push_str(" AND target_type = $target_type");
        }
        if query.target_ref.is_some() {
            statement.push_str(" AND target_ref = $target_ref");
        }
        if query.namespace.is_some() {
            statement.push_str(" AND namespace = $namespace");
        }
        if query.label.is_some() {
            statement.push_str(" AND label = $label");
        }
        if query.pubkey.is_some() {
            statement.push_str(" AND pubkey = $pubkey");
        }
        statement.push_str(" ORDER BY created_at DESC, event_id ASC, label_id ASC");
        if query.limit.is_some() {
            statement.push_str(" LIMIT $limit");
        }
        statement.push(';');
        let mut surreal_query = self.db.query(statement);
        if let Some(value) = &query.target_type {
            surreal_query = surreal_query.bind(("target_type", value.as_str()));
        }
        if let Some(value) = &query.target_ref {
            surreal_query = surreal_query.bind(("target_ref", value.as_str()));
        }
        if let Some(value) = &query.namespace {
            surreal_query = surreal_query.bind(("namespace", value.as_str()));
        }
        if let Some(value) = &query.label {
            surreal_query = surreal_query.bind(("label", value.as_str()));
        }
        if let Some(value) = &query.pubkey {
            surreal_query = surreal_query.bind(("pubkey", value.as_str()));
        }
        if let Some(value) = query.limit {
            surreal_query = surreal_query.bind(("limit", value));
        }
        let mut response = surreal_query
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn project_report(
        &self,
        event: &Event,
        projected_at: UnixTimestamp,
    ) -> Result<ReportProjectionOutcome, SurrealStoreError> {
        let report = match parse_report_event(event) {
            Ok(Some(report)) => report,
            Ok(None) => return Ok(ReportProjectionOutcome::NotReport),
            Err(_) => return Ok(ReportProjectionOutcome::Ineligible),
        };
        let fields = report_projection_fields(&report, projected_at);
        self.db
            .query("DELETE report_projection WHERE event_id = $event_id;")
            .bind(("event_id", report.event_id().as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        for field in fields {
            self.db
                .query(
                    r#"
UPSERT type::record('report_projection', $report_id) CONTENT {
    report_id: $report_id,
    event_id: $event_id,
    pubkey: $pubkey,
    created_at: $created_at,
    content: $content,
    target_type: $target_type,
    target_ref: $target_ref,
    report_type: $report_type,
    reported_pubkeys: $reported_pubkeys,
    server_urls: $server_urls,
    hidden: false,
    deleted: false,
    projected_at: $projected_at
};
"#,
                )
                .bind(("report_id", field.report_id.as_str()))
                .bind(("event_id", field.event_id.as_str()))
                .bind(("pubkey", field.pubkey.as_str()))
                .bind(("created_at", field.created_at))
                .bind(("content", field.content.as_str()))
                .bind(("target_type", field.target_type.as_str()))
                .bind(("target_ref", field.target_ref.as_str()))
                .bind(("report_type", field.report_type.as_str()))
                .bind(("reported_pubkeys", field.reported_pubkeys))
                .bind(("server_urls", field.server_urls))
                .bind(("projected_at", field.projected_at))
                .await
                .map_err(SurrealStoreError::from)?
                .check()
                .map_err(SurrealStoreError::from)?;
        }
        Ok(ReportProjectionOutcome::Projected)
    }

    pub async fn report_projection_rows(
        &self,
        event_id: &EventId,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query(
                "SELECT * FROM report_projection WHERE event_id = $event_id ORDER BY target_type ASC, target_ref ASC, report_type ASC, report_id ASC;",
            )
            .bind(("event_id", event_id.as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn query_report_projections(
        &self,
        query: &ReportProjectionQuery,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let mut statement =
            "SELECT * FROM report_projection WHERE hidden = false AND deleted = false".to_owned();
        if query.target_type.is_some() {
            statement.push_str(" AND target_type = $target_type");
        }
        if query.target_ref.is_some() {
            statement.push_str(" AND target_ref = $target_ref");
        }
        if query.report_type.is_some() {
            statement.push_str(" AND report_type = $report_type");
        }
        if query.pubkey.is_some() {
            statement.push_str(" AND pubkey = $pubkey");
        }
        statement.push_str(" ORDER BY created_at DESC, event_id ASC, report_id ASC");
        if query.limit.is_some() {
            statement.push_str(" LIMIT $limit");
        }
        statement.push(';');
        let mut surreal_query = self.db.query(statement);
        if let Some(value) = &query.target_type {
            surreal_query = surreal_query.bind(("target_type", value.as_str()));
        }
        if let Some(value) = &query.target_ref {
            surreal_query = surreal_query.bind(("target_ref", value.as_str()));
        }
        if let Some(value) = &query.report_type {
            surreal_query = surreal_query.bind(("report_type", value.as_str()));
        }
        if let Some(value) = &query.pubkey {
            surreal_query = surreal_query.bind(("pubkey", value.as_str()));
        }
        if let Some(value) = query.limit {
            surreal_query = surreal_query.bind(("limit", value));
        }
        let mut response = surreal_query
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn project_seller_profile(
        &self,
        event: &Event,
        projected_at: UnixTimestamp,
    ) -> Result<SellerProfileProjectionOutcome, SurrealStoreError> {
        let profile = match parse_seller_profile_event(event) {
            Ok(Some(profile)) => profile,
            Ok(None) => return Ok(SellerProfileProjectionOutcome::NotProfile),
            Err(_) => return Ok(SellerProfileProjectionOutcome::Ineligible),
        };
        let pubkey = profile.pubkey().as_str().to_owned();
        let existing = self.seller_profile_row(&pubkey).await?;
        if existing
            .as_ref()
            .is_some_and(|row| !seller_profile_should_replace(&profile, row))
        {
            return Ok(SellerProfileProjectionOutcome::Ineligible);
        }
        let policy = self
            .seller_profile_policy_state(&pubkey, existing.as_ref())
            .await?;
        let fields = seller_profile_fields(
            &profile,
            policy.seller_approved,
            policy.blocked,
            projected_at,
        );
        self.db
            .query(
                r#"
UPSERT type::record('seller_profile', $pubkey) CONTENT {
    pubkey: $pubkey,
    event_id: $event_id,
    created_at: $created_at,
    updated_at: $updated_at,
    name: $name,
    display_name: $display_name,
    about: $about,
    picture: $picture,
    website: $website,
    nip05: $nip05,
    lud16: $lud16,
    regions: $regions,
    categories: $categories,
    trust_markers: $trust_markers,
    seller_approved: $seller_approved,
    blocked: $blocked,
    hidden: false,
    deleted: false,
    projected_at: $projected_at
};
"#,
            )
            .bind(("pubkey", fields.pubkey.as_str()))
            .bind(("event_id", fields.event_id.as_str()))
            .bind(("created_at", fields.created_at))
            .bind(("updated_at", fields.updated_at))
            .bind(("name", fields.name.as_deref()))
            .bind(("display_name", fields.display_name.as_deref()))
            .bind(("about", fields.about.as_deref()))
            .bind(("picture", fields.picture.as_deref()))
            .bind(("website", fields.website.as_deref()))
            .bind(("nip05", fields.nip05.as_deref()))
            .bind(("lud16", fields.lud16.as_deref()))
            .bind(("regions", fields.regions))
            .bind(("categories", fields.categories))
            .bind(("trust_markers", fields.trust_markers))
            .bind(("seller_approved", fields.seller_approved))
            .bind(("blocked", fields.blocked))
            .bind(("projected_at", fields.projected_at))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        Ok(SellerProfileProjectionOutcome::Projected)
    }

    pub async fn seller_profile_row(
        &self,
        pubkey: &str,
    ) -> Result<Option<serde_json::Value>, SurrealStoreError> {
        let pubkey = required_policy_text(pubkey, "seller profile pubkey")?;
        let mut response = self
            .db
            .query("SELECT * FROM ONLY type::record('seller_profile', $pubkey);")
            .bind(("pubkey", pubkey.as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn query_seller_profiles(
        &self,
        query: &SellerProfileQuery,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let mut statement =
            "SELECT * FROM seller_profile WHERE hidden = false AND deleted = false".to_owned();
        if query.pubkey.is_some() {
            statement.push_str(" AND pubkey = $pubkey");
        }
        if query.approved.is_some() {
            statement.push_str(" AND seller_approved = $approved");
        }
        if query.blocked.is_some() {
            statement.push_str(" AND blocked = $blocked");
        }
        statement.push_str(" ORDER BY updated_at DESC, pubkey ASC");
        if query.limit.is_some() {
            statement.push_str(" LIMIT $limit");
        }
        statement.push(';');
        let mut surreal_query = self.db.query(statement);
        if let Some(value) = &query.pubkey {
            surreal_query = surreal_query.bind(("pubkey", value.as_str()));
        }
        if let Some(value) = query.approved {
            surreal_query = surreal_query.bind(("approved", value));
        }
        if let Some(value) = query.blocked {
            surreal_query = surreal_query.bind(("blocked", value));
        }
        if let Some(value) = query.limit {
            surreal_query = surreal_query.bind(("limit", value));
        }
        let mut response = surreal_query
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn project_listing_helpers(
        &self,
        event: &Event,
    ) -> Result<ListingHelperOutcome, SurrealStoreError> {
        let evaluation = evaluate_listing_projection(event);
        let ListingProjectionEvaluation::Eligible(projection) = evaluation else {
            return Ok(
                if matches!(evaluation, ListingProjectionEvaluation::NotListing) {
                    ListingHelperOutcome::NotListing
                } else {
                    ListingHelperOutcome::Ineligible
                },
            );
        };
        let listing_key = projection.identity().address().key().to_string();
        let effective_status = projection
            .status()
            .effective_status()
            .canonical()
            .to_owned();
        let updated_at = event.unsigned().created_at().as_u64();
        let event_id = event.id().as_str();
        let helper_context = ListingHelperProjectionContext {
            listing_key: &listing_key,
            effective_status: &effective_status,
            updated_at,
            event_id,
        };
        self.replace_listing_helper_rows(
            "listing_category",
            "category",
            projection.taxonomy().categories(),
            &helper_context,
        )
        .await?;
        let fulfillment = projection
            .fulfillment()
            .methods()
            .iter()
            .map(|method| method.canonical().to_owned())
            .collect::<Vec<_>>();
        self.replace_listing_helper_rows(
            "listing_fulfillment",
            "mode",
            &fulfillment,
            &helper_context,
        )
        .await?;
        self.replace_listing_helper_rows(
            "listing_tag",
            "tag_value",
            projection.taxonomy().topics(),
            &helper_context,
        )
        .await?;
        self.replace_listing_helper_rows(
            "listing_practice",
            "practice",
            projection.taxonomy().practices(),
            &helper_context,
        )
        .await?;
        self.replace_listing_helper_rows(
            "listing_certification",
            "certification",
            projection.taxonomy().certifications(),
            &helper_context,
        )
        .await?;
        Ok(ListingHelperOutcome::Projected)
    }

    pub async fn listing_category_rows(
        &self,
        listing_key: &str,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        self.listing_helper_rows("listing_category", "category", listing_key)
            .await
    }

    pub async fn listing_fulfillment_rows(
        &self,
        listing_key: &str,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        self.listing_helper_rows("listing_fulfillment", "mode", listing_key)
            .await
    }

    pub async fn listing_topic_rows(
        &self,
        listing_key: &str,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        self.listing_helper_rows("listing_tag", "tag_value", listing_key)
            .await
    }

    pub async fn listing_practice_rows(
        &self,
        listing_key: &str,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        self.listing_helper_rows("listing_practice", "practice", listing_key)
            .await
    }

    pub async fn listing_certification_rows(
        &self,
        listing_key: &str,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        self.listing_helper_rows("listing_certification", "certification", listing_key)
            .await
    }

    pub async fn index_listing_search_document(
        &self,
        event: &Event,
    ) -> Result<SearchDocumentOutcome, SurrealStoreError> {
        let evaluation = evaluate_listing_projection(event);
        let ListingProjectionEvaluation::Eligible(projection) = evaluation else {
            return Ok(
                if matches!(evaluation, ListingProjectionEvaluation::NotListing) {
                    SearchDocumentOutcome::NotListing
                } else {
                    SearchDocumentOutcome::Ineligible
                },
            );
        };
        let fields = search_document_fields(&projection, event);
        self.db
            .query(
                r#"
UPSERT type::record('search_doc', $doc_key) CONTENT {
    doc_key: $doc_key,
    event_id: $event_id,
    current_event_id: $current_event_id,
    doc_type: "listing",
    kind: $kind,
    pubkey: $pubkey,
    address_key: $address_key,
    title: $title,
    summary: $summary,
    body: $body,
    category_text: $category_text,
    location_text: $location_text,
    tags: $tags,
    categories: $categories,
    created_at: $created_at,
    updated_at: $updated_at,
    visible: $visible,
    status: $status,
    seller_trust_score: $seller_trust_score
};
"#,
            )
            .bind(("doc_key", fields.doc_key))
            .bind(("event_id", event.id().as_str()))
            .bind(("current_event_id", event.id().as_str()))
            .bind(("kind", event.unsigned().kind().as_u32()))
            .bind(("pubkey", event.unsigned().pubkey().as_str()))
            .bind(("address_key", fields.address_key))
            .bind(("title", fields.title))
            .bind(("summary", fields.summary))
            .bind(("body", fields.body))
            .bind(("category_text", fields.category_text))
            .bind(("location_text", fields.location_text))
            .bind(("tags", fields.tags))
            .bind(("categories", fields.categories))
            .bind(("created_at", event.unsigned().created_at().as_u64()))
            .bind(("updated_at", event.unsigned().created_at().as_u64()))
            .bind(("visible", fields.visible))
            .bind(("status", fields.status))
            .bind(("seller_trust_score", Option::<i64>::None))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        Ok(SearchDocumentOutcome::Indexed)
    }

    pub async fn search_document_row(
        &self,
        doc_key: &str,
    ) -> Result<Option<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query("SELECT * FROM ONLY type::record('search_doc', $doc_key);")
            .bind(("doc_key", doc_key))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn query_search_documents(
        &self,
        query: &SearchDocumentQuery,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let mut statement = if query.text.is_some() {
            "SELECT *, search::score(0) AS score FROM search_doc WHERE true".to_owned()
        } else {
            "SELECT * FROM search_doc WHERE true".to_owned()
        };
        if query.text.is_some() {
            statement.push_str(" AND (title @0@ $text OR summary @1@ $text OR body @2@ $text)");
        }
        if query.doc_type.is_some() {
            statement.push_str(" AND doc_type = $doc_type");
        }
        if query.kind.is_some() {
            statement.push_str(" AND kind = $kind");
        }
        if query.pubkey.is_some() {
            statement.push_str(" AND pubkey = $pubkey");
        }
        if query.visible.is_some() {
            statement.push_str(" AND visible = $visible");
        }
        if query.status.is_some() {
            statement.push_str(" AND status = $status");
        }
        if query.text.is_some() {
            statement.push_str(" ORDER BY score DESC, updated_at DESC, event_id ASC");
        } else {
            statement.push_str(" ORDER BY updated_at DESC, event_id ASC");
        }
        if query.limit.is_some() {
            statement.push_str(" LIMIT $limit");
        }
        statement.push(';');
        let mut surreal_query = self.db.query(statement);
        if let Some(value) = &query.text {
            surreal_query = surreal_query.bind(("text", value.as_str()));
        }
        if let Some(value) = &query.doc_type {
            surreal_query = surreal_query.bind(("doc_type", value.as_str()));
        }
        if let Some(value) = query.kind {
            surreal_query = surreal_query.bind(("kind", value));
        }
        if let Some(value) = &query.pubkey {
            surreal_query = surreal_query.bind(("pubkey", value.as_str()));
        }
        if let Some(value) = query.visible {
            surreal_query = surreal_query.bind(("visible", value));
        }
        if let Some(value) = &query.status {
            surreal_query = surreal_query.bind(("status", value.as_str()));
        }
        if let Some(value) = query.limit {
            surreal_query = surreal_query.bind(("limit", value));
        }
        let mut response = surreal_query
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn hide_event(
        &self,
        event_id: &EventId,
        reason: &str,
        source: &str,
        admin_pubkey: &str,
        created_at: UnixTimestamp,
    ) -> Result<HiddenEventOutcome, SurrealStoreError> {
        if self.raw_event_row(event_id).await?.is_none() {
            return Ok(HiddenEventOutcome::NotFound);
        }
        let reason = required_policy_text(reason, "hidden event reason")?;
        let source = required_policy_text(source, "hidden event source")?;
        let admin_pubkey = required_policy_text(admin_pubkey, "admin pubkey")?;
        self.db
            .query(
                r#"
UPSERT type::record('hidden_event', $event_id) CONTENT {
    event_id: $event_id,
    reason: $reason,
    source: $source,
    created_at: $created_at,
    admin_pubkey: $admin_pubkey
};
CREATE moderation_action CONTENT {
    action_id: $action_id,
    admin_pubkey: $admin_pubkey,
    target_type: "event",
    target_ref: $event_id,
    action: "hide",
    reason: $reason,
    created_at: $created_at
};
UPDATE nostr_event SET hidden = true WHERE event_id = $event_id;
UPDATE event_current SET hidden = true WHERE event_id = $event_id;
UPDATE listing_current SET hidden = true WHERE event_id = $event_id;
UPDATE comment_projection SET hidden = true WHERE event_id = $event_id;
UPDATE reaction_projection SET hidden = true WHERE event_id = $event_id;
UPDATE long_form_current SET hidden = true WHERE event_id = $event_id;
UPDATE long_form_topic SET hidden = true WHERE event_id = $event_id;
UPDATE forum_thread_projection SET hidden = true WHERE event_id = $event_id;
UPDATE forum_thread_topic SET hidden = true WHERE event_id = $event_id;
UPDATE label_projection SET hidden = true WHERE event_id = $event_id;
UPDATE report_projection SET hidden = true WHERE event_id = $event_id;
UPDATE seller_profile SET hidden = true WHERE event_id = $event_id;
UPDATE search_doc SET visible = false WHERE event_id = $event_id OR current_event_id = $event_id;
"#,
            )
            .bind(("event_id", event_id.as_str()))
            .bind(("reason", reason.as_str()))
            .bind(("source", source.as_str()))
            .bind(("created_at", created_at.as_u64()))
            .bind(("admin_pubkey", admin_pubkey.as_str()))
            .bind((
                "action_id",
                moderation_action_id("hide", event_id.as_str(), admin_pubkey.as_str(), created_at),
            ))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        self.refresh_reaction_count_for_event(event_id.as_str(), created_at.as_u64())
            .await?;
        Ok(HiddenEventOutcome::Hidden)
    }

    pub async fn unhide_event(
        &self,
        event_id: &EventId,
        reason: &str,
        admin_pubkey: &str,
        created_at: UnixTimestamp,
    ) -> Result<HiddenEventOutcome, SurrealStoreError> {
        if self.raw_event_row(event_id).await?.is_none() {
            return Ok(HiddenEventOutcome::NotFound);
        }
        let reason = required_policy_text(reason, "hidden event reason")?;
        let admin_pubkey = required_policy_text(admin_pubkey, "admin pubkey")?;
        self.db
            .query(
                r#"
DELETE type::record('hidden_event', $event_id);
CREATE moderation_action CONTENT {
    action_id: $action_id,
    admin_pubkey: $admin_pubkey,
    target_type: "event",
    target_ref: $event_id,
    action: "unhide",
    reason: $reason,
    created_at: $created_at
};
UPDATE nostr_event SET hidden = false WHERE event_id = $event_id;
UPDATE event_current SET hidden = false WHERE event_id = $event_id;
UPDATE listing_current SET hidden = false WHERE event_id = $event_id;
UPDATE comment_projection SET hidden = false WHERE event_id = $event_id;
UPDATE reaction_projection SET hidden = false WHERE event_id = $event_id;
UPDATE long_form_current SET hidden = false WHERE event_id = $event_id;
UPDATE long_form_topic SET hidden = false WHERE event_id = $event_id;
UPDATE forum_thread_projection SET hidden = false WHERE event_id = $event_id;
UPDATE forum_thread_topic SET hidden = false WHERE event_id = $event_id;
UPDATE label_projection SET hidden = false WHERE event_id = $event_id;
UPDATE report_projection SET hidden = false WHERE event_id = $event_id;
UPDATE seller_profile SET hidden = false WHERE event_id = $event_id;
UPDATE search_doc SET visible = true WHERE (event_id = $event_id OR current_event_id = $event_id) AND (status = "active" OR status = "published" OR status = "open");
UPDATE search_doc SET visible = false WHERE (event_id = $event_id OR current_event_id = $event_id) AND status != "active" AND status != "published" AND status != "open";
"#,
            )
            .bind(("event_id", event_id.as_str()))
            .bind(("reason", reason.as_str()))
            .bind(("created_at", created_at.as_u64()))
            .bind(("admin_pubkey", admin_pubkey.as_str()))
            .bind((
                "action_id",
                moderation_action_id(
                    "unhide",
                    event_id.as_str(),
                    admin_pubkey.as_str(),
                    created_at,
                ),
            ))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        self.refresh_reaction_count_for_event(event_id.as_str(), created_at.as_u64())
            .await?;
        Ok(HiddenEventOutcome::Unhidden)
    }

    pub async fn hidden_event_row(
        &self,
        event_id: &EventId,
    ) -> Result<Option<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query("SELECT * FROM ONLY type::record('hidden_event', $event_id);")
            .bind(("event_id", event_id.as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn moderation_action_rows(
        &self,
        target_type: &str,
        target_ref: &str,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let mut response = self
            .db
            .query(
                "SELECT * FROM moderation_action WHERE target_type = $target_type AND target_ref = $target_ref ORDER BY created_at ASC, action_id ASC;",
            )
            .bind(("target_type", target_type))
            .bind(("target_ref", target_ref))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn relay_user_row(
        &self,
        pubkey: &str,
    ) -> Result<Option<serde_json::Value>, SurrealStoreError> {
        let pubkey = required_policy_text(pubkey, "relay user pubkey")?;
        let mut response = self
            .db
            .query("SELECT * FROM ONLY type::record('relay_user', $pubkey);")
            .bind(("pubkey", pubkey.as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn set_seller_approved(
        &self,
        pubkey: &str,
        approved: bool,
        updated_at: UnixTimestamp,
    ) -> Result<(), SurrealStoreError> {
        let pubkey = required_policy_text(pubkey, "relay user pubkey")?;
        let existing = self.relay_user_row(&pubkey).await?;
        let blocked = existing
            .as_ref()
            .and_then(|row| row.get("blocked"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let created_at = existing
            .as_ref()
            .and_then(|row| row.get("created_at"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| updated_at.as_u64());
        self.upsert_relay_user(&pubkey, "seller", approved, blocked, created_at, updated_at)
            .await
    }

    pub async fn set_pubkey_blocked(
        &self,
        pubkey: &str,
        blocked: bool,
        updated_at: UnixTimestamp,
    ) -> Result<(), SurrealStoreError> {
        let pubkey = required_policy_text(pubkey, "relay user pubkey")?;
        let existing = self.relay_user_row(&pubkey).await?;
        let approved = existing
            .as_ref()
            .and_then(|row| row.get("seller_approved"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let role = existing
            .as_ref()
            .and_then(|row| row.get("role"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("seller")
            .to_owned();
        let created_at = existing
            .as_ref()
            .and_then(|row| row.get("created_at"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| updated_at.as_u64());
        self.upsert_relay_user(&pubkey, &role, approved, blocked, created_at, updated_at)
            .await
    }

    pub async fn check_durable_rate_limit(
        &self,
        key: &str,
        limit: u64,
        window_seconds: u64,
        cost: u64,
        now: UnixTimestamp,
    ) -> Result<DurableRateLimitDecision, SurrealStoreError> {
        let key = required_policy_text(key, "rate limit key")?;
        if limit == 0 {
            return Err(SurrealStoreError::new(
                "rate limit must be greater than zero",
            ));
        }
        if window_seconds == 0 {
            return Err(SurrealStoreError::new(
                "rate limit window must be greater than zero seconds",
            ));
        }
        if cost == 0 {
            return Err(SurrealStoreError::new(
                "rate limit cost must be greater than zero",
            ));
        }
        if cost > limit {
            return Err(SurrealStoreError::new(&format!(
                "rate limit cost {cost} exceeds limit {limit}"
            )));
        }
        let row = self.rate_limit_state_row(&key).await?;
        let created_at = row
            .as_ref()
            .and_then(|row| row.get("created_at"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| now.as_u64());
        let mut state = row
            .as_ref()
            .map(rate_limit_window_state_from_row)
            .transpose()?
            .unwrap_or_else(|| DurableRateLimitWindowState::new(now));
        state.reset_if_elapsed(now, window_seconds);
        let reset_at = state.reset_at(window_seconds);
        if state.used.saturating_add(cost) > limit {
            return Ok(DurableRateLimitDecision::Rejected {
                retry_after_seconds: reset_at.as_u64().saturating_sub(now.as_u64()),
                reset_at,
            });
        }
        state.used += cost;
        self.upsert_rate_limit_state(&key, state, reset_at, created_at, now)
            .await?;
        Ok(DurableRateLimitDecision::Accepted {
            remaining: limit - state.used,
            reset_at,
        })
    }

    pub async fn rate_limit_state_row(
        &self,
        key: &str,
    ) -> Result<Option<serde_json::Value>, SurrealStoreError> {
        let key = required_policy_text(key, "rate limit key")?;
        let mut response = self
            .db
            .query("SELECT * FROM ONLY type::record('rate_limit_state', $key);")
            .bind(("key", key.as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    pub async fn prune_expired_rate_limit_state(
        &self,
        now: UnixTimestamp,
    ) -> Result<u64, SurrealStoreError> {
        let mut response = self
            .db
            .query(
                "DELETE rate_limit_state WHERE expires_at != NONE AND expires_at <= $now RETURN BEFORE;",
            )
            .bind(("now", now.as_u64()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        let rows = response
            .take::<Vec<serde_json::Value>>(0)
            .map_err(SurrealStoreError::from)?;
        Ok(rows.len() as u64)
    }

    async fn replace_listing_helper_rows(
        &self,
        table: &str,
        field: &str,
        values: &[String],
        context: &ListingHelperProjectionContext<'_>,
    ) -> Result<(), SurrealStoreError> {
        let delete_query = format!("DELETE {table} WHERE listing_key = $listing_key;");
        self.db
            .query(delete_query)
            .bind(("listing_key", context.listing_key))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        let create_query = format!(
            "CREATE {table} CONTENT {{ listing_key: $listing_key, {field}: $value, effective_status: $effective_status, updated_at: $updated_at, event_id: $event_id }};"
        );
        for value in values {
            self.db
                .query(create_query.as_str())
                .bind(("listing_key", context.listing_key))
                .bind(("value", value.as_str()))
                .bind(("effective_status", context.effective_status))
                .bind(("updated_at", context.updated_at))
                .bind(("event_id", context.event_id))
                .await
                .map_err(SurrealStoreError::from)?
                .check()
                .map_err(SurrealStoreError::from)?;
        }
        Ok(())
    }

    async fn listing_helper_rows(
        &self,
        table: &str,
        field: &str,
        listing_key: &str,
    ) -> Result<Vec<serde_json::Value>, SurrealStoreError> {
        let query =
            format!("SELECT * FROM {table} WHERE listing_key = $listing_key ORDER BY {field} ASC;");
        let mut response = self
            .db
            .query(query)
            .bind(("listing_key", listing_key))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    async fn replace_long_form_topic_rows(
        &self,
        fields: &LongFormProjectionFields,
    ) -> Result<(), SurrealStoreError> {
        self.db
            .query("DELETE long_form_topic WHERE long_form_key = $long_form_key;")
            .bind(("long_form_key", fields.long_form_key.as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        for topic in &fields.tags {
            self.db
                .query(
                    r#"
CREATE long_form_topic CONTENT {
    long_form_key: $long_form_key,
    topic: $topic,
    updated_at: $updated_at,
    event_id: $event_id,
    hidden: false,
    deleted: false
};
"#,
                )
                .bind(("long_form_key", fields.long_form_key.as_str()))
                .bind(("topic", topic.as_str()))
                .bind(("updated_at", fields.updated_at))
                .bind(("event_id", fields.event_id.as_str()))
                .await
                .map_err(SurrealStoreError::from)?
                .check()
                .map_err(SurrealStoreError::from)?;
        }
        Ok(())
    }

    async fn replace_forum_thread_topic_rows(
        &self,
        fields: &ForumThreadProjectionFields,
    ) -> Result<(), SurrealStoreError> {
        self.db
            .query("DELETE forum_thread_topic WHERE thread_id = $thread_id;")
            .bind(("thread_id", fields.thread_id.as_str()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        for topic in &fields.tags {
            self.db
                .query(
                    r#"
CREATE forum_thread_topic CONTENT {
    thread_id: $thread_id,
    topic: $topic,
    updated_at: $updated_at,
    event_id: $event_id,
    hidden: false,
    deleted: false
};
"#,
                )
                .bind(("thread_id", fields.thread_id.as_str()))
                .bind(("topic", topic.as_str()))
                .bind(("updated_at", fields.updated_at))
                .bind(("event_id", fields.event_id.as_str()))
                .await
                .map_err(SurrealStoreError::from)?
                .check()
                .map_err(SurrealStoreError::from)?;
        }
        Ok(())
    }

    async fn upsert_rate_limit_state(
        &self,
        key: &str,
        state: DurableRateLimitWindowState,
        expires_at: UnixTimestamp,
        created_at: u64,
        updated_at: UnixTimestamp,
    ) -> Result<(), SurrealStoreError> {
        self.db
            .query(
                r#"
UPSERT type::record('rate_limit_state', $key) CONTENT {
    key: $key,
    state: $state,
    expires_at: $expires_at,
    created_at: $created_at,
    updated_at: $updated_at
};
"#,
            )
            .bind(("key", key))
            .bind(("state", state.to_json_string()))
            .bind(("expires_at", expires_at.as_u64()))
            .bind(("created_at", created_at))
            .bind(("updated_at", updated_at.as_u64()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        Ok(())
    }

    async fn upsert_relay_user(
        &self,
        pubkey: &str,
        role: &str,
        seller_approved: bool,
        blocked: bool,
        created_at: u64,
        updated_at: UnixTimestamp,
    ) -> Result<(), SurrealStoreError> {
        self.db
            .query(
                r#"
UPSERT type::record('relay_user', $pubkey) CONTENT {
    pubkey: $pubkey,
    role: $role,
    seller_approved: $seller_approved,
    blocked: $blocked,
    created_at: $created_at,
    updated_at: $updated_at
};
UPDATE seller_profile SET seller_approved = $seller_approved, blocked = $blocked WHERE pubkey = $pubkey;
"#,
            )
            .bind(("pubkey", pubkey))
            .bind(("role", role))
            .bind(("seller_approved", seller_approved))
            .bind(("blocked", blocked))
            .bind(("created_at", created_at))
            .bind(("updated_at", updated_at.as_u64()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        Ok(())
    }

    async fn seller_profile_policy_state(
        &self,
        pubkey: &str,
        existing_profile: Option<&serde_json::Value>,
    ) -> Result<SellerProfilePolicyState, SurrealStoreError> {
        let relay_user = self.relay_user_row(pubkey).await?;
        Ok(SellerProfilePolicyState {
            seller_approved: relay_user
                .as_ref()
                .and_then(|row| row.get("seller_approved"))
                .and_then(serde_json::Value::as_bool)
                .or_else(|| {
                    existing_profile
                        .and_then(|row| row.get("seller_approved"))
                        .and_then(serde_json::Value::as_bool)
                })
                .unwrap_or(false),
            blocked: relay_user
                .as_ref()
                .and_then(|row| row.get("blocked"))
                .and_then(serde_json::Value::as_bool)
                .or_else(|| {
                    existing_profile
                        .and_then(|row| row.get("blocked"))
                        .and_then(serde_json::Value::as_bool)
                })
                .unwrap_or(false),
        })
    }

    async fn refresh_reaction_count_for_event(
        &self,
        event_id: &str,
        updated_at: u64,
    ) -> Result<(), SurrealStoreError> {
        let mut response = self
            .db
            .query("SELECT * FROM ONLY type::record('reaction_projection', $event_id);")
            .bind(("event_id", event_id))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        let row: Option<serde_json::Value> = response.take(0).map_err(SurrealStoreError::from)?;
        let Some(row) = row else {
            return Ok(());
        };
        let target_event_id = string_row_field(&row, "target_event_id")?;
        let target_kind = optional_string_row_field(&row, "target_kind")?;
        self.recompute_reaction_count(&target_event_id, target_kind, updated_at)
            .await
    }

    async fn recompute_reaction_count(
        &self,
        target_event_id: &str,
        target_kind: Option<String>,
        updated_at: u64,
    ) -> Result<(), SurrealStoreError> {
        let mut response = self
            .db
            .query(
                "SELECT value_type FROM reaction_projection WHERE target_event_id = $target_event_id AND hidden = false AND deleted = false;",
            )
            .bind(("target_event_id", target_event_id))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        let rows: Vec<serde_json::Value> = response.take(0).map_err(SurrealStoreError::from)?;
        let mut like_count = 0_i64;
        let mut dislike_count = 0_i64;
        let mut emoji_count = 0_i64;
        let mut text_count = 0_i64;
        for row in rows {
            match string_row_field(&row, "value_type")?.as_str() {
                "like" => like_count += 1,
                "dislike" => dislike_count += 1,
                "emoji" => emoji_count += 1,
                "text" => text_count += 1,
                _ => {}
            }
        }
        let total_count = like_count + dislike_count + emoji_count + text_count;
        self.db
            .query(
                r#"
UPSERT type::record('reaction_count', $target_event_id) CONTENT {
    target_event_id: $target_event_id,
    target_kind: $target_kind,
    like_count: $like_count,
    dislike_count: $dislike_count,
    emoji_count: $emoji_count,
    text_count: $text_count,
    total_count: $total_count,
    updated_at: $updated_at
};
"#,
            )
            .bind(("target_event_id", target_event_id))
            .bind(("target_kind", target_kind.as_deref()))
            .bind(("like_count", like_count))
            .bind(("dislike_count", dislike_count))
            .bind(("emoji_count", emoji_count))
            .bind(("text_count", text_count))
            .bind(("total_count", total_count))
            .bind(("updated_at", updated_at))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        Ok(())
    }

    async fn query_single_indexed_tag_event_ids(
        &self,
        tag: &str,
        values: &[String],
        filter: &Filter,
    ) -> Result<Vec<String>, SurrealStoreError> {
        let mut statement =
            "SELECT VALUE event_id FROM event_tag_index WHERE tag = $tag AND value IN $values"
                .to_owned();
        if !filter.authors().is_empty() {
            statement.push_str(" AND pubkey IN $authors");
        }
        if !filter.kinds().is_empty() {
            statement.push_str(" AND kind IN $kinds");
        }
        if filter.since().is_some() {
            statement.push_str(" AND created_at >= $since");
        }
        if filter.until().is_some() {
            statement.push_str(" AND created_at <= $until");
        }
        statement.push_str(" ORDER BY created_at DESC, event_id ASC;");
        let mut query = self
            .db
            .query(statement)
            .bind(("tag", tag))
            .bind(("values", values.to_vec()));
        if !filter.authors().is_empty() {
            query = query.bind((
                "authors",
                filter
                    .authors()
                    .iter()
                    .map(|pubkey| pubkey.as_str().to_owned())
                    .collect::<Vec<_>>(),
            ));
        }
        if !filter.kinds().is_empty() {
            query = query.bind((
                "kinds",
                filter
                    .kinds()
                    .iter()
                    .map(|kind| kind.as_u32())
                    .collect::<Vec<_>>(),
            ));
        }
        if let Some(since) = filter.since() {
            query = query.bind(("since", since.as_u64()));
        }
        if let Some(until) = filter.until() {
            query = query.bind(("until", until.as_u64()));
        }
        let mut response = query
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        response.take(0).map_err(SurrealStoreError::from)
    }

    async fn applied_migration(
        &self,
        name: &str,
    ) -> Result<Option<AppliedMigration>, SurrealStoreError> {
        Ok(self
            .applied_migrations()
            .await?
            .into_iter()
            .find(|migration| migration.name() == name))
    }

    async fn has_migration_table(&self) -> Result<bool, SurrealStoreError> {
        let mut response = self
            .db
            .query("INFO FOR DB;")
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        let info: Option<surrealdb::types::Value> =
            response.take(0).map_err(SurrealStoreError::from)?;
        Ok(info
            .map(|value| format!("{value:?}").contains("migration"))
            .unwrap_or(false))
    }

    async fn mark_raw_event_deleted(
        &self,
        event_id: &str,
        author_pubkey: &str,
        deleted_at: u64,
    ) -> Result<(), SurrealStoreError> {
        self.db
            .query(
                r#"
UPDATE nostr_event SET deleted = true WHERE event_id = $event_id AND pubkey = $author_pubkey;
UPDATE comment_projection SET deleted = true WHERE event_id = $event_id AND pubkey = $author_pubkey;
UPDATE reaction_projection SET deleted = true WHERE event_id = $event_id AND pubkey = $author_pubkey;
UPDATE long_form_current SET deleted = true WHERE event_id = $event_id AND author_pubkey = $author_pubkey;
UPDATE long_form_topic SET deleted = true WHERE event_id = $event_id;
UPDATE forum_thread_projection SET deleted = true WHERE event_id = $event_id AND pubkey = $author_pubkey;
UPDATE forum_thread_topic SET deleted = true WHERE event_id = $event_id;
UPDATE label_projection SET deleted = true WHERE event_id = $event_id AND pubkey = $author_pubkey;
UPDATE report_projection SET deleted = true WHERE event_id = $event_id AND pubkey = $author_pubkey;
UPDATE seller_profile SET deleted = true WHERE event_id = $event_id AND pubkey = $author_pubkey;
UPDATE search_doc SET visible = false WHERE event_id = $event_id OR current_event_id = $event_id;
"#,
            )
            .bind(("event_id", event_id))
            .bind(("author_pubkey", author_pubkey))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        self.refresh_reaction_count_for_event(event_id, deleted_at)
            .await?;
        Ok(())
    }

    async fn mark_address_deleted(
        &self,
        address_key: &str,
        author_pubkey: &str,
    ) -> Result<(), SurrealStoreError> {
        self.db
            .query(
                "UPDATE nostr_event SET deleted = true WHERE address_key = $address_key AND pubkey = $author_pubkey;",
            )
            .query(
                "UPDATE event_current SET deleted = true WHERE address_key = $address_key AND pubkey = $author_pubkey;",
            )
            .query(
                "UPDATE long_form_current SET deleted = true WHERE long_form_key = $address_key AND author_pubkey = $author_pubkey;",
            )
            .query("UPDATE long_form_topic SET deleted = true WHERE long_form_key = $address_key;")
            .query("UPDATE search_doc SET visible = false WHERE address_key = $address_key;")
            .bind(("address_key", address_key))
            .bind(("author_pubkey", author_pubkey))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        Ok(())
    }

    async fn record_migration(
        &self,
        migration: &SurrealMigration,
    ) -> Result<(), SurrealStoreError> {
        self.db
            .query(
                "CREATE migration CONTENT { name: $name, checksum: $checksum, applied_at: time::now() };",
            )
            .bind(("name", migration.name()))
            .bind(("checksum", migration.checksum()))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
        Ok(())
    }
}

fn event_tags_json(event: &Event) -> Vec<serde_json::Value> {
    event
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
        .collect()
}

fn count_value(value: serde_json::Value) -> Result<u64, SurrealStoreError> {
    if let Some(count) = value.as_u64() {
        return Ok(count);
    }
    if let Some(count) = value.get("count").and_then(serde_json::Value::as_u64) {
        return Ok(count);
    }
    Err(SurrealStoreError::new(
        "surreal count query returned a non-numeric count",
    ))
}

fn required_policy_text(value: &str, field: &str) -> Result<String, SurrealStoreError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(SurrealStoreError::new(&format!(
            "{field} must not be empty"
        )));
    }
    Ok(value.to_owned())
}

fn string_row_field(row: &serde_json::Value, field: &str) -> Result<String, SurrealStoreError> {
    row.get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| SurrealStoreError::new(&format!("{field} row field must be a string")))
}

fn optional_string_row_field(
    row: &serde_json::Value,
    field: &str,
) -> Result<Option<String>, SurrealStoreError> {
    match row.get(field) {
        Some(value) if value.is_null() => Ok(None),
        Some(value) => value
            .as_str()
            .map(|value| Some(value.to_owned()))
            .ok_or_else(|| SurrealStoreError::new(&format!("{field} row field must be a string"))),
        None => Ok(None),
    }
}

fn moderation_action_id(
    action: &str,
    target_ref: &str,
    admin_pubkey: &str,
    created_at: UnixTimestamp,
) -> String {
    checksum(&format!(
        "{action}:{target_ref}:{admin_pubkey}:{}",
        created_at.as_u64()
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DurableRateLimitWindowState {
    started_at: UnixTimestamp,
    used: u64,
}

impl DurableRateLimitWindowState {
    fn new(started_at: UnixTimestamp) -> Self {
        Self {
            started_at,
            used: 0,
        }
    }

    fn reset_at(self, window_seconds: u64) -> UnixTimestamp {
        UnixTimestamp::new(self.started_at.as_u64().saturating_add(window_seconds))
    }

    fn reset_if_elapsed(&mut self, now: UnixTimestamp, window_seconds: u64) {
        if now >= self.reset_at(window_seconds) || now < self.started_at {
            self.started_at = now;
            self.used = 0;
        }
    }

    fn to_json_string(self) -> String {
        serde_json::json!({
            "started_at": self.started_at.as_u64(),
            "used": self.used
        })
        .to_string()
    }
}

fn rate_limit_window_state_from_row(
    row: &serde_json::Value,
) -> Result<DurableRateLimitWindowState, SurrealStoreError> {
    let raw = row
        .get("state")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| SurrealStoreError::new("rate limit state is invalid"))?;
    let value = serde_json::from_str::<serde_json::Value>(raw)
        .map_err(|_| SurrealStoreError::new("rate limit state is invalid"))?;
    let started_at = value
        .get("started_at")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| SurrealStoreError::new("rate limit state is invalid"))?;
    let used = value
        .get("used")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| SurrealStoreError::new("rate limit state is invalid"))?;
    Ok(DurableRateLimitWindowState {
        started_at: UnixTimestamp::new(started_at),
        used,
    })
}

fn d_tag_value(event: &Event) -> Option<String> {
    event
        .unsigned()
        .tags()
        .iter()
        .find_map(|tag| tag.indexed_pair())
        .and_then(|(name, value)| (name == "d").then(|| value.to_owned()))
}

fn address_key_value(event: &Event) -> Result<Option<String>, SurrealStoreError> {
    AddressCoordinate::from_event(event)
        .map(|address| address.map(|address| address.key().to_string()))
        .map_err(|message| SurrealStoreError::new(&message))
}

struct CurrentEventKey {
    address_key: String,
    d: Option<String>,
}

fn current_event_key(event: &Event) -> Result<Option<CurrentEventKey>, SurrealStoreError> {
    let kind = event.unsigned().kind();
    if kind.is_addressable() {
        let coordinate = AddressCoordinate::from_event(event)
            .map_err(|message| SurrealStoreError::new(&message))?;
        return Ok(coordinate.map(|coordinate| CurrentEventKey {
            address_key: coordinate.key().to_string(),
            d: Some(coordinate.d().as_str().to_owned()),
        }));
    }
    if kind.is_replaceable() {
        return Ok(Some(CurrentEventKey {
            address_key: format!("{}:{}", kind.as_u32(), event.unsigned().pubkey().as_str()),
            d: None,
        }));
    }
    Ok(None)
}

fn current_event_replacement_outcome(
    event: &Event,
    row: &serde_json::Value,
) -> CurrentEventOutcome {
    let incoming_created_at = event.unsigned().created_at().as_u64();
    let existing_created_at = row["created_at"].as_u64().unwrap_or_default();
    let existing_event_id = row["event_id"].as_str().unwrap_or_default();
    if incoming_created_at > existing_created_at
        || (incoming_created_at == existing_created_at && event.id().as_str() > existing_event_id)
    {
        CurrentEventOutcome::Replaced
    } else {
        CurrentEventOutcome::Unchanged
    }
}

fn deletion_target_parts(target: &DeletionTarget) -> (&'static str, String) {
    match target {
        DeletionTarget::Event(event_id) => ("event", event_id.as_str().to_owned()),
        DeletionTarget::Address(address) => ("address", address.key().to_string()),
    }
}

struct ListingRevisionFields {
    revision_key: String,
    listing_key: String,
    seller_pubkey: String,
    d: String,
    parsed_ok: bool,
    parse_errors: Vec<String>,
    title: Option<String>,
    summary: Option<String>,
    price_decimal: Option<String>,
    price_minor: Option<i64>,
    currency_raw: Option<String>,
    currency_norm: Option<String>,
    unit: Option<String>,
    status_tag: Option<String>,
}

struct CommentProjectionFields {
    comment_id: String,
    pubkey: String,
    created_at: u64,
    content: String,
    root_target_type: String,
    root_ref: String,
    root_kind: String,
    root_author: Option<String>,
    parent_target_type: String,
    parent_ref: String,
    parent_kind: String,
    parent_author: Option<String>,
    projected_at: u64,
}

struct ReactionProjectionFields {
    reaction_id: String,
    pubkey: String,
    created_at: u64,
    content: String,
    value_type: String,
    value: String,
    target_event_id: String,
    target_pubkey: Option<String>,
    target_address: Option<String>,
    target_kind: Option<String>,
    projected_at: u64,
}

struct LongFormProjectionFields {
    long_form_key: String,
    event_id: String,
    author_pubkey: String,
    d: String,
    created_at: u64,
    updated_at: u64,
    published_at: Option<u64>,
    title: Option<String>,
    image: Option<String>,
    summary: Option<String>,
    content: String,
    tags: Vec<String>,
    referenced_events: Vec<String>,
    referenced_addresses: Vec<String>,
    referenced_pubkeys: Vec<String>,
    projected_at: u64,
    kind: u32,
    search_title: String,
}

struct ForumThreadProjectionFields {
    thread_id: String,
    event_id: String,
    pubkey: String,
    created_at: u64,
    updated_at: u64,
    title: Option<String>,
    content: String,
    tags: Vec<String>,
    referenced_events: Vec<String>,
    referenced_pubkeys: Vec<String>,
    projected_at: u64,
    kind: u32,
    search_title: String,
}

struct LabelProjectionFields {
    label_id: String,
    event_id: String,
    pubkey: String,
    created_at: u64,
    content: String,
    namespace: String,
    label: String,
    target_type: String,
    target_ref: String,
    projected_at: u64,
}

struct ReportProjectionFields {
    report_id: String,
    event_id: String,
    pubkey: String,
    created_at: u64,
    content: String,
    target_type: String,
    target_ref: String,
    report_type: String,
    reported_pubkeys: Vec<String>,
    server_urls: Vec<String>,
    projected_at: u64,
}

struct SellerProfilePolicyState {
    seller_approved: bool,
    blocked: bool,
}

struct SellerProfileFields {
    pubkey: String,
    event_id: String,
    created_at: u64,
    updated_at: u64,
    name: Option<String>,
    display_name: Option<String>,
    about: Option<String>,
    picture: Option<String>,
    website: Option<String>,
    nip05: Option<String>,
    lud16: Option<String>,
    regions: Vec<String>,
    categories: Vec<String>,
    trust_markers: Vec<String>,
    seller_approved: bool,
    blocked: bool,
    projected_at: u64,
}

struct ListingCurrentFields {
    listing_key: String,
    listing_key_hash: String,
    seller_pubkey: String,
    d: String,
    published_at: Option<u64>,
    title: String,
    summary: Option<String>,
    content: String,
    price_decimal: String,
    price_minor: i64,
    currency_raw: String,
    currency_norm: String,
    price_frequency: Option<String>,
    unit: String,
    location_text: Option<String>,
    geohash: Option<String>,
    geohash4: Option<String>,
    geohash5: Option<String>,
    geohash6: Option<String>,
    geohash7: Option<String>,
    status_tag: Option<String>,
    effective_status: String,
    categories: Vec<String>,
    tags: Vec<String>,
    practices: Vec<String>,
    certifications: Vec<String>,
    image_urls: Vec<String>,
    pickup_available: bool,
    delivery_available: bool,
    shipping_available: bool,
    delivery_only: bool,
}

struct ListingHelperProjectionContext<'a> {
    listing_key: &'a str,
    effective_status: &'a str,
    updated_at: u64,
    event_id: &'a str,
}

fn comment_projection_fields(
    comment: &CommentEvent,
    projected_at: UnixTimestamp,
) -> CommentProjectionFields {
    CommentProjectionFields {
        comment_id: comment.event_id().as_str().to_owned(),
        pubkey: comment.pubkey().as_str().to_owned(),
        created_at: comment.created_at().as_u64(),
        content: comment.content().to_owned(),
        root_target_type: comment.root().target().target_type().to_owned(),
        root_ref: comment.root().target().target_ref(),
        root_kind: comment.root().kind().to_owned(),
        root_author: comment
            .root()
            .author()
            .map(|pubkey| pubkey.as_str().to_owned()),
        parent_target_type: comment.parent().target().target_type().to_owned(),
        parent_ref: comment.parent().target().target_ref(),
        parent_kind: comment.parent().kind().to_owned(),
        parent_author: comment
            .parent()
            .author()
            .map(|pubkey| pubkey.as_str().to_owned()),
        projected_at: projected_at.as_u64(),
    }
}

fn reaction_projection_fields(
    reaction: &ReactionEvent,
    projected_at: UnixTimestamp,
) -> ReactionProjectionFields {
    ReactionProjectionFields {
        reaction_id: reaction.event_id().as_str().to_owned(),
        pubkey: reaction.pubkey().as_str().to_owned(),
        created_at: reaction.created_at().as_u64(),
        content: reaction.content().to_owned(),
        value_type: reaction.value().canonical().to_owned(),
        value: reaction_value_string(reaction.value()),
        target_event_id: reaction.target_event_id().as_str().to_owned(),
        target_pubkey: reaction
            .target_pubkey()
            .map(|pubkey| pubkey.as_str().to_owned()),
        target_address: reaction
            .target_address()
            .map(|address| address.key().to_string()),
        target_kind: reaction.target_kind().map(str::to_owned),
        projected_at: projected_at.as_u64(),
    }
}

fn reaction_value_string(value: &ReactionValue) -> String {
    match value {
        ReactionValue::Like => "like".to_owned(),
        ReactionValue::Dislike => "dislike".to_owned(),
        ReactionValue::Emoji(value) | ReactionValue::Text(value) => value.clone(),
    }
}

fn long_form_projection_fields(
    article: &LongFormEvent,
    projected_at: UnixTimestamp,
) -> LongFormProjectionFields {
    let d = article.d().as_str().to_owned();
    LongFormProjectionFields {
        long_form_key: article.address().key().to_string(),
        event_id: article.event_id().as_str().to_owned(),
        author_pubkey: article.pubkey().as_str().to_owned(),
        d: d.clone(),
        created_at: article.created_at().as_u64(),
        updated_at: article.created_at().as_u64(),
        published_at: article.published_at(),
        title: article.title().map(str::to_owned),
        image: article.image().map(str::to_owned),
        summary: article.summary().map(str::to_owned),
        content: article.content().to_owned(),
        tags: article.topics().to_vec(),
        referenced_events: article
            .referenced_events()
            .iter()
            .map(|event_id| event_id.as_str().to_owned())
            .collect(),
        referenced_addresses: article
            .referenced_addresses()
            .iter()
            .map(|address| address.key().to_string())
            .collect(),
        referenced_pubkeys: article
            .referenced_pubkeys()
            .iter()
            .map(|pubkey| pubkey.as_str().to_owned())
            .collect(),
        projected_at: projected_at.as_u64(),
        kind: article.address().kind().as_u32(),
        search_title: article.title().unwrap_or(&d).to_owned(),
    }
}

fn long_form_current_should_replace(article: &LongFormEvent, row: &serde_json::Value) -> bool {
    let incoming_created_at = article.created_at().as_u64();
    let existing_created_at = row["updated_at"].as_u64().unwrap_or_default();
    let existing_event_id = row["event_id"].as_str().unwrap_or_default();
    incoming_created_at > existing_created_at
        || (incoming_created_at == existing_created_at
            && article.event_id().as_str() > existing_event_id)
}

fn forum_thread_projection_fields(
    thread: &ForumThreadEvent,
    projected_at: UnixTimestamp,
) -> ForumThreadProjectionFields {
    ForumThreadProjectionFields {
        thread_id: thread.event_id().as_str().to_owned(),
        event_id: thread.event_id().as_str().to_owned(),
        pubkey: thread.pubkey().as_str().to_owned(),
        created_at: thread.created_at().as_u64(),
        updated_at: thread.created_at().as_u64(),
        title: thread.title().map(str::to_owned),
        content: thread.content().to_owned(),
        tags: thread.topics().to_vec(),
        referenced_events: thread
            .referenced_events()
            .iter()
            .map(|event_id| event_id.as_str().to_owned())
            .collect(),
        referenced_pubkeys: thread
            .referenced_pubkeys()
            .iter()
            .map(|pubkey| pubkey.as_str().to_owned())
            .collect(),
        projected_at: projected_at.as_u64(),
        kind: 11,
        search_title: thread
            .title()
            .map(str::to_owned)
            .unwrap_or_else(|| fallback_thread_title(thread)),
    }
}

fn fallback_thread_title(thread: &ForumThreadEvent) -> String {
    let fallback = thread.content().chars().take(80).collect::<String>();
    if fallback.is_empty() {
        return thread.event_id().as_str().to_owned();
    }
    fallback
}

fn label_projection_fields(
    label: &LabelEvent,
    projected_at: UnixTimestamp,
) -> Vec<LabelProjectionFields> {
    let mut pairs = BTreeSet::new();
    for target in label.targets() {
        let target_type = target.target_type().to_owned();
        let target_ref = target.target_ref();
        for value in label.labels() {
            pairs.insert((
                target_type.clone(),
                target_ref.clone(),
                value.namespace().to_owned(),
                value.value().to_owned(),
            ));
        }
    }
    pairs
        .into_iter()
        .map(|(target_type, target_ref, namespace, value)| {
            let event_id = label.event_id().as_str().to_owned();
            let pubkey = label.pubkey().as_str().to_owned();
            LabelProjectionFields {
                label_id: label_projection_id(
                    &event_id,
                    &target_type,
                    &target_ref,
                    &namespace,
                    &value,
                ),
                event_id,
                pubkey,
                created_at: label.created_at().as_u64(),
                content: label.content().to_owned(),
                namespace,
                label: value,
                target_type,
                target_ref,
                projected_at: projected_at.as_u64(),
            }
        })
        .collect()
}

fn label_projection_id(
    event_id: &str,
    target_type: &str,
    target_ref: &str,
    namespace: &str,
    label: &str,
) -> String {
    checksum(
        &serde_json::to_string(&[event_id, target_type, target_ref, namespace, label])
            .expect("label projection identity serializes"),
    )
}

fn report_projection_fields(
    report: &ReportEvent,
    projected_at: UnixTimestamp,
) -> Vec<ReportProjectionFields> {
    let reported_pubkeys = report
        .reported_pubkeys()
        .iter()
        .map(|pubkey| pubkey.as_str().to_owned())
        .collect::<Vec<_>>();
    let server_urls = report.server_urls().to_vec();
    let mut pairs = BTreeSet::new();
    for target in report.targets() {
        pairs.insert(report_target_parts(target));
    }
    pairs
        .into_iter()
        .map(|(target_type, target_ref, report_type)| {
            let event_id = report.event_id().as_str().to_owned();
            let pubkey = report.pubkey().as_str().to_owned();
            ReportProjectionFields {
                report_id: report_projection_id(&event_id, &target_type, &target_ref, &report_type),
                event_id,
                pubkey,
                created_at: report.created_at().as_u64(),
                content: report.content().to_owned(),
                target_type,
                target_ref,
                report_type,
                reported_pubkeys: reported_pubkeys.clone(),
                server_urls: server_urls.clone(),
                projected_at: projected_at.as_u64(),
            }
        })
        .collect()
}

fn report_target_parts(target: &ReportTarget) -> (String, String, String) {
    (
        target.target_type().to_owned(),
        target.target_ref().to_owned(),
        target.report_type().canonical().to_owned(),
    )
}

fn report_projection_id(
    event_id: &str,
    target_type: &str,
    target_ref: &str,
    report_type: &str,
) -> String {
    checksum(
        &serde_json::to_string(&[event_id, target_type, target_ref, report_type])
            .expect("report projection identity serializes"),
    )
}

fn seller_profile_fields(
    profile: &SellerProfileEvent,
    seller_approved: bool,
    blocked: bool,
    projected_at: UnixTimestamp,
) -> SellerProfileFields {
    let metadata = profile.metadata();
    SellerProfileFields {
        pubkey: profile.pubkey().as_str().to_owned(),
        event_id: profile.event_id().as_str().to_owned(),
        created_at: profile.created_at().as_u64(),
        updated_at: profile.created_at().as_u64(),
        name: metadata.name().map(str::to_owned),
        display_name: metadata.display_name().map(str::to_owned),
        about: metadata.about().map(str::to_owned),
        picture: metadata.picture().map(str::to_owned),
        website: metadata.website().map(str::to_owned),
        nip05: metadata.nip05().map(str::to_owned),
        lud16: metadata.lud16().map(str::to_owned),
        regions: profile.regions().to_vec(),
        categories: profile.categories().to_vec(),
        trust_markers: profile.trust_markers().to_vec(),
        seller_approved,
        blocked,
        projected_at: projected_at.as_u64(),
    }
}

fn seller_profile_should_replace(profile: &SellerProfileEvent, row: &serde_json::Value) -> bool {
    let incoming_created_at = profile.created_at().as_u64();
    let existing_created_at = row["updated_at"].as_u64().unwrap_or_default();
    let existing_event_id = row["event_id"].as_str().unwrap_or_default();
    incoming_created_at > existing_created_at
        || (incoming_created_at == existing_created_at
            && profile.event_id().as_str() > existing_event_id)
}

struct SearchDocumentFields {
    doc_key: String,
    address_key: Option<String>,
    title: String,
    summary: Option<String>,
    body: String,
    category_text: String,
    location_text: Option<String>,
    tags: Vec<String>,
    categories: Vec<String>,
    visible: bool,
    status: String,
}

fn search_document_fields(projection: &ListingProjection, _event: &Event) -> SearchDocumentFields {
    let doc_key = projection.identity().address().key().to_string();
    let status = projection
        .status()
        .effective_status()
        .canonical()
        .to_owned();
    let categories = projection.taxonomy().categories().to_vec();
    SearchDocumentFields {
        address_key: Some(doc_key.clone()),
        doc_key,
        title: projection.text().title().to_owned(),
        summary: projection.text().summary().map(str::to_owned),
        body: projection.text().body().to_owned(),
        category_text: categories.join(" "),
        location_text: projection.location().location_text().map(str::to_owned),
        tags: projection.taxonomy().topics().to_vec(),
        categories,
        visible: status == "active",
        status,
    }
}

fn listing_current_fields(
    projection: &ListingProjection,
    event: &Event,
    _projected_at: UnixTimestamp,
) -> Result<ListingCurrentFields, SurrealStoreError> {
    let listing_key = projection.identity().address().key().to_string();
    let price_decimal = projection.price().amount().raw().to_owned();
    let price_minor = price_minor(&price_decimal).ok_or_else(|| {
        SurrealStoreError::new("listing price amount must fit two decimal minor units")
    })?;
    Ok(ListingCurrentFields {
        listing_key_hash: checksum(&listing_key),
        listing_key,
        seller_pubkey: projection.identity().seller_pubkey().as_str().to_owned(),
        d: projection.identity().d().as_str().to_owned(),
        published_at: first_tag_value(event, "published_at").and_then(|value| value.parse().ok()),
        title: projection.text().title().to_owned(),
        summary: projection.text().summary().map(str::to_owned),
        content: projection.text().body().to_owned(),
        price_decimal,
        price_minor,
        currency_raw: projection.price().currency().to_owned(),
        currency_norm: projection.price().display_currency().to_owned(),
        price_frequency: projection.price().frequency().map(str::to_owned),
        unit: projection.unit().canonical().to_owned(),
        location_text: projection.location().location_text().map(str::to_owned),
        geohash: projection.location().geohash().map(str::to_owned),
        geohash4: projection.location().geohash4().map(str::to_owned),
        geohash5: projection.location().geohash5().map(str::to_owned),
        geohash6: projection.location().geohash6().map(str::to_owned),
        geohash7: projection.location().geohash7().map(str::to_owned),
        status_tag: projection.status().raw_status().map(str::to_owned),
        effective_status: projection
            .status()
            .effective_status()
            .canonical()
            .to_owned(),
        categories: projection.taxonomy().categories().to_vec(),
        tags: projection.taxonomy().topics().to_vec(),
        practices: projection.taxonomy().practices().to_vec(),
        certifications: projection.taxonomy().certifications().to_vec(),
        image_urls: tag_values(event, "image"),
        pickup_available: projection.fulfillment().pickup_available(),
        delivery_available: projection.fulfillment().delivery_available(),
        shipping_available: projection.fulfillment().shipping_available(),
        delivery_only: projection.fulfillment().delivery_only(),
    })
}

fn listing_revision_fields(
    event: &Event,
    evaluation: &ListingProjectionEvaluation,
) -> Result<ListingRevisionFields, SurrealStoreError> {
    let d = d_tag_value(event).unwrap_or_default();
    let fallback_listing_key = format!(
        "{}:{}:{}",
        event.unsigned().kind().as_u32(),
        event.unsigned().pubkey().as_str(),
        d
    );
    let listing_key = address_key_value(event)?.unwrap_or(fallback_listing_key);
    let base = ListingRevisionFields {
        revision_key: event.id().as_str().to_owned(),
        listing_key,
        seller_pubkey: event.unsigned().pubkey().as_str().to_owned(),
        d,
        parsed_ok: false,
        parse_errors: Vec::new(),
        title: first_tag_value(event, "title"),
        summary: first_tag_value(event, "summary"),
        price_decimal: None,
        price_minor: None,
        currency_raw: None,
        currency_norm: None,
        unit: None,
        status_tag: first_tag_value(event, "status"),
    };
    match evaluation {
        ListingProjectionEvaluation::Eligible(projection) => Ok(ListingRevisionFields {
            parsed_ok: true,
            title: Some(projection.text().title().to_owned()),
            summary: projection.text().summary().map(str::to_owned),
            price_decimal: Some(projection.price().amount().raw().to_owned()),
            price_minor: price_minor(projection.price().amount().raw()),
            currency_raw: Some(projection.price().currency().to_owned()),
            currency_norm: Some(projection.price().display_currency().to_owned()),
            unit: Some(projection.unit().canonical().to_owned()),
            status_tag: projection.status().raw_status().map(str::to_owned),
            ..base
        }),
        ListingProjectionEvaluation::Ineligible(rejection) => Ok(ListingRevisionFields {
            parse_errors: rejection.reasons().to_vec(),
            ..base
        }),
        ListingProjectionEvaluation::NotListing => Ok(base),
    }
}

fn is_listing_event(event: &Event) -> bool {
    matches!(
        event.unsigned().kind().as_u32(),
        NIP99_PUBLIC_LISTING_KIND | NIP99_DRAFT_LISTING_KIND
    )
}

fn first_tag_value(event: &Event, name: &str) -> Option<String> {
    event
        .unsigned()
        .tags()
        .iter()
        .find(|tag| tag.name().as_str() == name)
        .and_then(|tag| tag.value())
        .map(|value| value.as_str().to_owned())
}

fn tag_values(event: &Event, name: &str) -> Vec<String> {
    event
        .unsigned()
        .tags()
        .iter()
        .filter(|tag| tag.name().as_str() == name)
        .filter_map(|tag| tag.value())
        .map(|value| value.as_str().to_owned())
        .collect()
}

fn unique_in_order(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut unique = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            unique.push(value);
        }
    }
    unique
}

fn price_minor(raw: &str) -> Option<i64> {
    let mut parts = raw.split('.');
    let whole = parts.next()?.parse::<i64>().ok()?;
    let fraction = parts.next();
    if parts.next().is_some() {
        return None;
    }
    match fraction {
        Some(value) if value.len() <= 2 => {
            let padded = format!("{value:0<2}");
            Some(whole * 100 + padded.parse::<i64>().ok()?)
        }
        Some(_) => None,
        None => Some(whole * 100),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurrealStoreError {
    message: String,
}

impl SurrealStoreError {
    fn new(message: &str) -> Self {
        Self {
            message: message.to_owned(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for SurrealStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SurrealStoreError {}

impl From<surrealdb::Error> for SurrealStoreError {
    fn from(source: surrealdb::Error) -> Self {
        Self::new(&source.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CommentProjectionOutcome, CommentProjectionQuery, CurrentEventOutcome,
        DeletionMarkerOutcome, DurableRateLimitDecision, ForumThreadProjectionOutcome,
        ForumThreadProjectionQuery, HiddenEventOutcome, LabelProjectionOutcome,
        LabelProjectionQuery, ListingCurrentOutcome, ListingHelperOutcome, ListingProjectionQuery,
        ListingRevisionOutcome, LongFormProjectionOutcome, LongFormProjectionQuery,
        MigrationApplyOutcome, ReactionProjectionOutcome, ReportProjectionOutcome,
        ReportProjectionQuery, SearchDocumentOutcome, SearchDocumentQuery,
        SellerProfileProjectionOutcome, SellerProfileQuery, SurrealConfigError,
        SurrealConnectionConfig, SurrealConnectionMode, SurrealMigration, SurrealMigrationError,
        SurrealMigrationPlan, SurrealStore, SurrealStoreError, base_migration_plan,
        migration_tracking_schema,
    };
    use tangle_nips::{
        ListingProjectionEvaluation, NIP01_METADATA_KIND, NIP7D_THREAD_KIND,
        NIP23_LONG_FORM_DRAFT_KIND, NIP23_LONG_FORM_KIND, NIP32_LABEL_KIND, NIP56_REPORT_KIND,
    };
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
        filter_from_value,
    };
    use tangle_store::{StoreEventOutcome, StoredEvent};
    use tangle_test_support::{
        FixtureKey, build_fixture_event, build_fixture_event_from_parts, valid_public_listing_spec,
    };

    #[test]
    fn memory_config_normalizes_namespace_and_database() {
        let config =
            SurrealConnectionConfig::memory(" tangle_test ", " relay_one ").expect("memory config");

        assert_eq!(config.mode(), &SurrealConnectionMode::Memory);
        assert_eq!(config.namespace(), "tangle_test");
        assert_eq!(config.database(), "relay_one");
    }

    #[test]
    fn remote_config_preserves_trimmed_endpoints() {
        let rocksdb = SurrealConnectionConfig::rocksdb(" /tmp/tangle-rocksdb ", "ns", "db")
            .expect("rocksdb config");
        let http = SurrealConnectionConfig::http(" http://127.0.0.1:8000 ", "ns", "db")
            .expect("http config")
            .with_root_credentials(" root ", " root ")
            .expect("http credentials");
        let websocket = SurrealConnectionConfig::websocket(" ws://127.0.0.1:8000 ", "ns", "db")
            .expect("websocket config");

        assert_eq!(
            rocksdb.mode(),
            &SurrealConnectionMode::RocksDb {
                path: "/tmp/tangle-rocksdb".to_owned()
            }
        );
        assert_eq!(
            http.mode(),
            &SurrealConnectionMode::Http {
                endpoint: "http://127.0.0.1:8000".to_owned()
            }
        );
        let credentials = http.root_credentials().expect("http credentials");
        assert_eq!(credentials.username(), "root");
        assert_eq!(credentials.password(), "root");
        assert_eq!(
            websocket.mode(),
            &SurrealConnectionMode::WebSocket {
                endpoint: "ws://127.0.0.1:8000".to_owned()
            }
        );
    }

    #[test]
    fn config_rejects_empty_namespace_database_and_endpoint() {
        assert_eq!(
            SurrealConnectionConfig::memory(" ", "db")
                .expect_err("namespace error")
                .to_string(),
            "surreal namespace must not be empty"
        );
        assert_eq!(
            SurrealConnectionConfig::memory("ns", "")
                .expect_err("database error")
                .message(),
            "surreal database must not be empty"
        );
        assert_eq!(
            SurrealConnectionConfig::http("", "ns", "db").expect_err("endpoint error"),
            SurrealConfigError {
                message: "surreal http endpoint must not be empty".to_owned()
            }
        );
        assert_eq!(
            SurrealConnectionConfig::rocksdb("", "ns", "db").expect_err("path error"),
            SurrealConfigError {
                message: "surreal rocksdb path must not be empty".to_owned()
            }
        );
        assert_eq!(
            SurrealConnectionConfig::websocket(" ", "ns", "db")
                .expect_err("websocket endpoint error")
                .to_string(),
            "surreal websocket endpoint must not be empty"
        );
        assert_eq!(
            SurrealConnectionConfig::http("http://127.0.0.1:8000", "ns", "db")
                .expect("http config")
                .with_root_credentials("", "root")
                .expect_err("username error")
                .to_string(),
            "surreal root username must not be empty"
        );
        assert_eq!(
            SurrealConnectionConfig::http("http://127.0.0.1:8000", "ns", "db")
                .expect("http config")
                .with_root_credentials("root", " ")
                .expect_err("password error")
                .to_string(),
            "surreal root password must not be empty"
        );
    }

    #[test]
    fn config_rejects_non_portable_identifiers() {
        assert_eq!(
            SurrealConnectionConfig::memory("tangle-test", "db")
                .expect_err("namespace syntax")
                .to_string(),
            "surreal namespace must use ASCII letters, digits, or underscore"
        );
        assert_eq!(
            SurrealConnectionConfig::memory("ns", "relay.db")
                .expect_err("database syntax")
                .to_string(),
            "surreal database must use ASCII letters, digits, or underscore"
        );
    }

    #[test]
    fn migration_model_normalizes_names_and_hashes_surql() {
        let migration =
            SurrealMigration::new(" 0001_tracking ", "DEFINE TABLE migration SCHEMAFULL;")
                .expect("migration");

        assert_eq!(migration.name(), "0001_tracking");
        assert_eq!(migration.surql(), "DEFINE TABLE migration SCHEMAFULL;");
        assert_eq!(
            migration.checksum(),
            "ffedba540d84072a42d0e3f97bfdc054e688667e073b879e7409dd5253c8c896"
        );
    }

    #[test]
    fn migration_model_rejects_invalid_name_and_body() {
        assert_eq!(
            SurrealMigration::new("", "RETURN true;")
                .expect_err("missing name")
                .to_string(),
            "surreal migration name must not be empty"
        );
        assert_eq!(
            SurrealMigration::new("001_tracking", "RETURN true;")
                .expect_err("short version")
                .message(),
            "surreal migration name must start with four digits"
        );
        assert_eq!(
            SurrealMigration::new("0001_Tracking", "RETURN true;")
                .expect_err("bad label")
                .to_string(),
            "surreal migration label must use lowercase ASCII, digits, or underscore"
        );
        assert_eq!(
            SurrealMigration::new("0001_tracking", " ")
                .expect_err("empty body")
                .to_string(),
            "surreal migration body must not be empty"
        );
    }

    #[test]
    fn migration_plan_preserves_order_and_lookup() {
        let first = SurrealMigration::new("0001_tracking", "RETURN true;").expect("first");
        let second = SurrealMigration::new("0002_events", "RETURN false;").expect("second");
        let plan =
            SurrealMigrationPlan::new(vec![first.clone(), second.clone()]).expect("ordered plan");

        assert_eq!(plan.migrations(), &[first, second]);
        assert_eq!(plan.names(), vec!["0001_tracking", "0002_events"]);
        assert_eq!(
            plan.find("0002_events").expect("second migration").surql(),
            "RETURN false;"
        );
        assert_eq!(plan.find("9999_missing"), None);
    }

    #[test]
    fn migration_plan_rejects_duplicate_or_descending_names() {
        let first = SurrealMigration::new("0002_events", "RETURN true;").expect("first");
        let duplicate = SurrealMigration::new("0002_events", "RETURN false;").expect("duplicate");
        let descending = SurrealMigration::new("0001_tracking", "RETURN false;").expect("older");

        assert_eq!(
            SurrealMigrationPlan::new(vec![first.clone(), duplicate])
                .expect_err("duplicate")
                .to_string(),
            "surreal migrations must be strictly ordered by name"
        );
        assert_eq!(
            SurrealMigrationPlan::new(vec![first, descending]).expect_err("descending"),
            SurrealMigrationError {
                message: "surreal migrations must be strictly ordered by name".to_owned()
            }
        );
    }

    #[tokio::test]
    async fn memory_store_rejects_remote_config() {
        let config =
            SurrealConnectionConfig::websocket("ws://127.0.0.1:8000", "ns", "db").expect("config");
        let error = SurrealStore::connect_memory(&config)
            .await
            .expect_err("memory mismatch");

        assert_eq!(
            error.message(),
            "surreal memory connection requires memory mode config"
        );
        let local_error = SurrealStore::connect_local(&config)
            .await
            .expect_err("remote local mismatch");
        assert_eq!(
            local_error.message(),
            "surreal local connection requires memory or rocksdb mode config"
        );
    }

    #[tokio::test]
    async fn remote_connection_requires_root_credentials_before_network_use() {
        let config =
            SurrealConnectionConfig::http("http://127.0.0.1:8000", "ns", "db").expect("config");
        let error = SurrealStore::connect(&config)
            .await
            .expect_err("missing credentials");

        assert_eq!(
            error.message(),
            "surreal remote connection requires root credentials"
        );
    }

    #[tokio::test]
    async fn migration_tracking_schema_applies_idempotently() {
        let store = memory_store().await;
        let plan = base_migration_plan();

        assert_eq!(
            store.applied_migrations().await.expect("no table yet"),
            Vec::new()
        );
        assert_eq!(
            store.apply_plan(&plan).await.expect("apply"),
            vec![MigrationApplyOutcome::Applied; plan.migrations().len()]
        );
        assert_eq!(
            store.apply_plan(&plan).await.expect("reapply"),
            vec![MigrationApplyOutcome::AlreadyApplied; plan.migrations().len()]
        );

        let migrations = store.applied_migrations().await.expect("applied rows");
        assert_eq!(migrations.len(), plan.migrations().len());
        for (applied, expected) in migrations.iter().zip(plan.migrations()) {
            assert_eq!(applied.name(), expected.name());
            assert_eq!(applied.checksum(), expected.checksum());
        }
        assert!(format!("{:?}", store.database()).contains("Surreal"));
    }

    #[tokio::test]
    async fn store_ping_confirms_database_connectivity() {
        let store = memory_store().await;

        store.ping().await.expect("ping");
    }

    #[tokio::test]
    async fn migration_tracking_detects_checksum_changes() {
        let store = memory_store().await;
        let original = migration_tracking_schema();
        let changed = SurrealMigration::new(original.name(), "DEFINE TABLE migration SCHEMALESS;")
            .expect("changed");

        assert_eq!(
            store.apply_migration(&original).await.expect("apply"),
            MigrationApplyOutcome::Applied
        );
        assert_eq!(
            store
                .apply_migration(&changed)
                .await
                .expect_err("checksum changed")
                .to_string(),
            "surreal migration `0001_migration_tracking` checksum changed"
        );
    }

    async fn memory_store() -> SurrealStore {
        let config = SurrealConnectionConfig::memory("tangle_test", "relay").expect("config");
        SurrealStore::connect_memory(&config).await.expect("store")
    }

    #[tokio::test]
    async fn raw_event_schema_defines_canonical_event_table() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let info = store.table_info("nostr_event").await.expect("table info");

        for expected in [
            "event_id",
            "pubkey",
            "created_at",
            "kind",
            "tags",
            "content",
            "sig",
            "raw_json",
            "received_at",
            "content_len",
            "tag_count",
            "d_tag",
            "address_key",
            "deleted",
            "hidden",
            "rejection_reason",
            "nostr_event_id_uid",
            "nostr_event_kind_author_created",
        ] {
            assert!(info.contains(expected), "missing {expected} in {info}");
        }
        assert_eq!(
            store
                .table_info("nostr-event")
                .await
                .expect_err("invalid table")
                .to_string(),
            "surreal table info target is invalid: surreal table must use ASCII letters, digits, or underscore"
        );
    }

    #[tokio::test]
    async fn event_tag_index_schema_defines_single_letter_lookup_table() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let info = store
            .table_info("event_tag_index")
            .await
            .expect("table info");

        for expected in [
            "event_id",
            "kind",
            "pubkey",
            "created_at",
            "tag",
            "value",
            "ordinal",
            "event_tag_lookup",
            "event_tag_kind_lookup",
            "event_tag_event",
        ] {
            assert!(info.contains(expected), "missing {expected} in {info}");
        }
    }

    #[tokio::test]
    async fn current_event_schema_defines_replaceable_pointer_table() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let info = store.table_info("event_current").await.expect("table info");

        for expected in [
            "address_key",
            "kind",
            "pubkey",
            "d",
            "event_id",
            "created_at",
            "tie_break_id",
            "deleted",
            "hidden",
            "updated_at",
            "event_current_address_uid",
            "event_current_kind_pubkey",
            "event_current_event",
        ] {
            assert!(info.contains(expected), "missing {expected} in {info}");
        }
    }

    #[tokio::test]
    async fn deletion_marker_schema_defines_author_scoped_target_table() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let info = store
            .table_info("deletion_marker")
            .await
            .expect("table info");

        for expected in [
            "deletion_event_id",
            "target_type",
            "target_ref",
            "author_pubkey",
            "deletion_created_at",
            "deletion_target",
            "deletion_author_target",
        ] {
            assert!(info.contains(expected), "missing {expected} in {info}");
        }
    }

    #[tokio::test]
    async fn listing_revision_schema_defines_parse_audit_table() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let info = store
            .table_info("listing_revision")
            .await
            .expect("table info");

        for expected in [
            "revision_key",
            "listing_key",
            "event_id",
            "seller_pubkey",
            "d",
            "created_at",
            "parsed_ok",
            "parse_errors",
            "title",
            "summary",
            "price_decimal",
            "price_minor",
            "currency_raw",
            "currency_norm",
            "unit",
            "status_tag",
            "projected_at",
            "listing_revision_event_uid",
            "listing_revision_listing_created",
            "listing_revision_seller_created",
        ] {
            assert!(info.contains(expected), "missing {expected} in {info}");
        }
    }

    #[tokio::test]
    async fn comment_projection_schema_defines_threaded_comment_table() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let info = store
            .table_info("comment_projection")
            .await
            .expect("table info");

        for expected in [
            "comment_id",
            "event_id",
            "pubkey",
            "created_at",
            "content",
            "root_target_type",
            "root_ref",
            "root_kind",
            "root_author",
            "parent_target_type",
            "parent_ref",
            "parent_kind",
            "parent_author",
            "hidden",
            "deleted",
            "projected_at",
            "comment_projection_event_uid",
            "comment_projection_root_lookup",
            "comment_projection_parent_lookup",
            "comment_projection_author_created",
        ] {
            assert!(info.contains(expected), "missing {expected} in {info}");
        }
    }

    #[tokio::test]
    async fn reaction_projection_schema_defines_reaction_and_count_tables() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let projection = store
            .table_info("reaction_projection")
            .await
            .expect("projection info");
        let count = store
            .table_info("reaction_count")
            .await
            .expect("count info");

        for expected in [
            "reaction_id",
            "event_id",
            "pubkey",
            "created_at",
            "content",
            "value_type",
            "value",
            "target_event_id",
            "target_pubkey",
            "target_address",
            "target_kind",
            "hidden",
            "deleted",
            "projected_at",
            "reaction_projection_event_uid",
            "reaction_projection_target_created",
            "reaction_projection_author_created",
            "reaction_projection_target_kind",
        ] {
            assert!(
                projection.contains(expected),
                "missing {expected} in {projection}"
            );
        }
        for expected in [
            "target_event_id",
            "target_kind",
            "like_count",
            "dislike_count",
            "emoji_count",
            "text_count",
            "total_count",
            "updated_at",
            "reaction_count_target_uid",
            "reaction_count_kind_target",
        ] {
            assert!(count.contains(expected), "missing {expected} in {count}");
        }
    }

    #[tokio::test]
    async fn long_form_projection_schema_defines_current_and_topic_tables() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let current = store
            .table_info("long_form_current")
            .await
            .expect("current info");
        let topic = store
            .table_info("long_form_topic")
            .await
            .expect("topic info");

        for expected in [
            "long_form_key",
            "event_id",
            "author_pubkey",
            "d",
            "created_at",
            "updated_at",
            "published_at",
            "title",
            "image",
            "summary",
            "content",
            "tags",
            "referenced_events",
            "referenced_addresses",
            "referenced_pubkeys",
            "hidden",
            "deleted",
            "projected_at",
            "long_form_current_key_uid",
            "long_form_current_event_uid",
            "long_form_current_author_updated",
            "long_form_current_published_updated",
            "long_form_current_visibility",
        ] {
            assert!(
                current.contains(expected),
                "missing {expected} in {current}"
            );
        }
        for expected in [
            "long_form_key",
            "topic",
            "updated_at",
            "event_id",
            "hidden",
            "deleted",
            "long_form_topic_lookup",
            "long_form_topic_long_form",
        ] {
            assert!(topic.contains(expected), "missing {expected} in {topic}");
        }
    }

    #[tokio::test]
    async fn forum_thread_schema_defines_projection_and_topic_tables() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let projection = store
            .table_info("forum_thread_projection")
            .await
            .expect("projection info");
        let topic = store
            .table_info("forum_thread_topic")
            .await
            .expect("topic info");

        for expected in [
            "thread_id",
            "event_id",
            "pubkey",
            "created_at",
            "updated_at",
            "title",
            "content",
            "tags",
            "referenced_events",
            "referenced_pubkeys",
            "hidden",
            "deleted",
            "projected_at",
            "forum_thread_event_uid",
            "forum_thread_pubkey_updated",
            "forum_thread_visibility_updated",
        ] {
            assert!(
                projection.contains(expected),
                "missing {expected} in {projection}"
            );
        }
        for expected in [
            "thread_id",
            "topic",
            "updated_at",
            "event_id",
            "hidden",
            "deleted",
            "forum_thread_topic_lookup",
            "forum_thread_topic_thread",
        ] {
            assert!(topic.contains(expected), "missing {expected} in {topic}");
        }
    }

    #[tokio::test]
    async fn label_projection_schema_defines_reviewable_label_table() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let info = store
            .table_info("label_projection")
            .await
            .expect("label info");

        for expected in [
            "label_id",
            "event_id",
            "pubkey",
            "created_at",
            "content",
            "namespace",
            "label",
            "target_type",
            "target_ref",
            "hidden",
            "deleted",
            "projected_at",
            "label_projection_label_uid",
            "label_projection_event",
            "label_projection_target_lookup",
            "label_projection_namespace_lookup",
            "label_projection_author_created",
            "label_projection_visibility",
        ] {
            assert!(info.contains(expected), "missing {expected} in {info}");
        }
    }

    #[tokio::test]
    async fn report_projection_schema_defines_reviewable_report_table() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let info = store
            .table_info("report_projection")
            .await
            .expect("report info");

        for expected in [
            "report_id",
            "event_id",
            "pubkey",
            "created_at",
            "content",
            "target_type",
            "target_ref",
            "report_type",
            "reported_pubkeys",
            "server_urls",
            "hidden",
            "deleted",
            "projected_at",
            "report_projection_report_uid",
            "report_projection_event",
            "report_projection_target_lookup",
            "report_projection_type_created",
            "report_projection_author_created",
            "report_projection_visibility",
        ] {
            assert!(info.contains(expected), "missing {expected} in {info}");
        }
    }

    #[tokio::test]
    async fn seller_profile_schema_defines_current_seller_profile_table() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let info = store
            .table_info("seller_profile")
            .await
            .expect("seller profile info");

        for expected in [
            "pubkey",
            "event_id",
            "created_at",
            "updated_at",
            "name",
            "display_name",
            "about",
            "picture",
            "website",
            "nip05",
            "lud16",
            "regions",
            "categories",
            "trust_markers",
            "seller_approved",
            "blocked",
            "hidden",
            "deleted",
            "projected_at",
            "seller_profile_pubkey_uid",
            "seller_profile_event_uid",
            "seller_profile_updated",
            "seller_profile_approved_blocked",
            "seller_profile_visibility",
        ] {
            assert!(info.contains(expected), "missing {expected} in {info}");
        }
    }

    #[tokio::test]
    async fn listing_current_schema_defines_marketplace_projection_table() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let info = store
            .table_info("listing_current")
            .await
            .expect("table info");

        for expected in [
            "listing_key",
            "listing_key_hash",
            "event_id",
            "seller_pubkey",
            "d",
            "created_at",
            "updated_at",
            "published_at",
            "title",
            "summary",
            "content",
            "price_decimal",
            "price_minor",
            "currency_raw",
            "currency_norm",
            "price_frequency",
            "unit",
            "unit_family",
            "location_text",
            "geohash",
            "geohash4",
            "geohash5",
            "geohash6",
            "geohash7",
            "point",
            "status_tag",
            "effective_status",
            "categories",
            "tags",
            "practices",
            "certifications",
            "image_urls",
            "pickup_available",
            "delivery_available",
            "shipping_available",
            "delivery_only",
            "seller_trust_score",
            "hidden",
            "deleted",
            "projected_at",
            "listing_key_uid",
            "listing_event_uid",
            "listing_price_lookup",
            "listing_geo6_status",
        ] {
            assert!(info.contains(expected), "missing {expected} in {info}");
        }
    }

    #[tokio::test]
    async fn listing_helper_schemas_define_discovery_tables() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");

        for (table, value_field, lookup_index, listing_index) in [
            (
                "listing_category",
                "category",
                "listing_category_lookup",
                "listing_category_listing",
            ),
            (
                "listing_fulfillment",
                "mode",
                "listing_fulfillment_lookup",
                "listing_fulfillment_listing",
            ),
            (
                "listing_tag",
                "tag_value",
                "listing_tag_lookup",
                "listing_tag_listing",
            ),
            (
                "listing_practice",
                "practice",
                "listing_practice_lookup",
                "listing_practice_listing",
            ),
            (
                "listing_certification",
                "certification",
                "listing_certification_lookup",
                "listing_certification_listing",
            ),
        ] {
            let info = store.table_info(table).await.expect("table info");
            for expected in [
                "listing_key",
                value_field,
                "effective_status",
                "updated_at",
                "event_id",
                lookup_index,
                listing_index,
            ] {
                assert!(
                    info.contains(expected),
                    "missing {expected} in {table} info {info}"
                );
            }
        }
    }

    #[tokio::test]
    async fn search_document_schema_defines_listing_search_surface() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let info = store.table_info("search_doc").await.expect("table info");

        for expected in [
            "doc_key",
            "event_id",
            "current_event_id",
            "doc_type",
            "kind",
            "pubkey",
            "address_key",
            "title",
            "summary",
            "body",
            "category_text",
            "location_text",
            "tags",
            "categories",
            "created_at",
            "updated_at",
            "visible",
            "status",
            "seller_trust_score",
            "search_doc_key_uid",
            "search_doc_type_visible_updated",
            "search_doc_kind_visible_updated",
            "search_doc_title_ft",
            "tangle_listing_search",
            "FULLTEXT",
            "BM25",
        ] {
            assert!(info.contains(expected), "missing {expected} in {info}");
        }
    }

    #[tokio::test]
    async fn policy_schemas_define_user_moderation_and_rebuild_tables() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");

        for (table, expected) in [
            (
                "relay_user",
                vec![
                    "pubkey",
                    "role",
                    "seller_approved",
                    "blocked",
                    "created_at",
                    "updated_at",
                    "relay_user_pubkey_uid",
                    "relay_user_seller_gate",
                ],
            ),
            (
                "hidden_event",
                vec![
                    "event_id",
                    "reason",
                    "source",
                    "created_at",
                    "admin_pubkey",
                    "hidden_event_uid",
                    "hidden_event_created",
                ],
            ),
            (
                "moderation_action",
                vec![
                    "action_id",
                    "admin_pubkey",
                    "target_type",
                    "target_ref",
                    "action",
                    "reason",
                    "created_at",
                    "moderation_action_target",
                    "moderation_action_admin",
                ],
            ),
            (
                "rate_limit_state",
                vec![
                    "key",
                    "state",
                    "expires_at",
                    "created_at",
                    "updated_at",
                    "rate_limit_state_key_uid",
                    "rate_limit_state_expires",
                ],
            ),
            (
                "import_checkpoint",
                vec![
                    "name",
                    "offset",
                    "event_id",
                    "updated_at",
                    "import_checkpoint_name_uid",
                ],
            ),
            (
                "projection_error",
                vec![
                    "event_id",
                    "projector",
                    "error",
                    "created_at",
                    "projection_error_event",
                    "projection_error_projector_created",
                ],
            ),
        ] {
            let info = store.table_info(table).await.expect("table info");
            for field in expected {
                assert!(
                    info.contains(field),
                    "missing {field} in {table} info {info}"
                );
            }
        }
    }

    #[tokio::test]
    async fn store_raw_event_persists_canonical_nostr_event_row() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let event = build_fixture_event(&valid_public_listing_spec()).expect("event");
        let stored = StoredEvent::new(event.clone(), UnixTimestamp::new(1_714_124_500));

        assert_eq!(
            store.store_raw_event(&stored).await.expect("insert"),
            StoreEventOutcome::Inserted
        );
        assert_eq!(
            store.store_raw_event(&stored).await.expect("duplicate"),
            StoreEventOutcome::Duplicate
        );

        let row = store
            .raw_event_row(event.id())
            .await
            .expect("row query")
            .expect("row exists");
        assert_eq!(row["event_id"], event.id().as_str());
        assert_eq!(row["pubkey"], event.unsigned().pubkey().as_str());
        assert_eq!(row["created_at"], event.unsigned().created_at().as_u64());
        assert_eq!(row["kind"], event.unsigned().kind().as_u32());
        assert_eq!(row["content"], "Sweet storage carrots.");
        assert_eq!(row["sig"], event.sig().as_str());
        assert_eq!(row["received_at"], 1_714_124_500_u64);
        assert_eq!(row["content_len"], 22_u64);
        assert_eq!(row["tag_count"], 10_u64);
        assert_eq!(row["d_tag"], "listing-a");
        assert_eq!(
            row["address_key"],
            format!(
                "{}:{}:{}",
                event.unsigned().kind().as_u32(),
                event.unsigned().pubkey().as_str(),
                event.unsigned().tags()[0].values()[1]
            )
        );
        assert_eq!(row["deleted"], false);
        assert_eq!(row["hidden"], false);
        assert_eq!(
            row["raw_json"]
                .as_str()
                .expect("raw json string")
                .parse::<serde_json::Value>()
                .expect("raw json parses")["id"],
            event.id().as_str()
        );
        assert_eq!(row["tags"].as_array().expect("tags").len(), 10);
    }

    #[tokio::test]
    async fn query_raw_events_applies_core_filter_constraints() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let pubkey_a = "1".repeat(PublicKeyHex::HEX_LENGTH);
        let pubkey_b = "2".repeat(PublicKeyHex::HEX_LENGTH);
        let first = synthetic_event("1", "b", &pubkey_a, 100, 1, Vec::new(), "first");
        let second = synthetic_event("2", "c", &pubkey_a, 101, 1, Vec::new(), "second");
        let third = synthetic_event("3", "d", &pubkey_a, 102, 2, Vec::new(), "third");
        let fourth = synthetic_event("4", "e", &pubkey_b, 103, 1, Vec::new(), "fourth");
        for event in [&first, &second, &third, &fourth] {
            assert_eq!(
                store
                    .store_raw_event(&StoredEvent::new(event.clone(), UnixTimestamp::new(200)))
                    .await
                    .expect("insert"),
                StoreEventOutcome::Inserted
            );
        }

        let filtered = filter_from_value(&serde_json::json!({
            "authors": [pubkey_a],
            "kinds": [1],
            "since": 100,
            "until": 101,
            "limit": 1
        }))
        .expect("filter");
        let rows = store
            .query_raw_events(&filtered)
            .await
            .expect("filtered rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["event_id"], second.id().as_str());

        let id_filter = filter_from_value(&serde_json::json!({
            "ids": [first.id().as_str()]
        }))
        .expect("id filter");
        assert_eq!(
            store.query_raw_events(&id_filter).await.expect("id rows")[0]["event_id"],
            first.id().as_str()
        );

        store
            .database()
            .query("UPDATE nostr_event SET deleted = true WHERE event_id = $event_id;")
            .bind(("event_id", first.id().as_str()))
            .await
            .expect("delete marker")
            .check()
            .expect("delete check");
        assert!(
            store
                .query_raw_events(&id_filter)
                .await
                .expect("deleted rows")
                .is_empty()
        );
        let backup_rows = store.backup_raw_events().await.expect("backup rows");
        assert!(
            backup_rows
                .iter()
                .any(|row| row["event_id"] == first.id().as_str())
        );
    }

    #[tokio::test]
    async fn index_event_tags_persists_single_letter_tag_rows() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let event = Event::new(
            EventId::new(&"c".repeat(EventId::HEX_LENGTH)).expect("id"),
            UnsignedEvent::new(
                PublicKeyHex::new(&"d".repeat(PublicKeyHex::HEX_LENGTH)).expect("pubkey"),
                UnixTimestamp::new(1_714_124_600),
                Kind::new(1).expect("kind"),
                vec![
                    Tag::from_parts("e", &["target-event"]).expect("e"),
                    Tag::from_parts("A", &["upper-tag"]).expect("A"),
                    Tag::from_parts("topic", &["ignored"]).expect("topic"),
                    Tag::from_parts("p", &["target-pubkey"]).expect("p"),
                ],
                "tagged event",
            ),
            SignatureHex::new(&"e".repeat(SignatureHex::HEX_LENGTH)).expect("sig"),
        );

        store.index_event_tags(&event).await.expect("index");
        store.index_event_tags(&event).await.expect("reindex");

        let rows = store.tag_index_rows(event.id()).await.expect("rows");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["tag"], "e");
        assert_eq!(rows[0]["value"], "target-event");
        assert_eq!(rows[0]["ordinal"], 0_u64);
        assert_eq!(rows[1]["tag"], "A");
        assert_eq!(rows[1]["value"], "upper-tag");
        assert_eq!(rows[1]["ordinal"], 1_u64);
        assert_eq!(rows[2]["tag"], "p");
        assert_eq!(rows[2]["value"], "target-pubkey");
        assert_eq!(rows[2]["kind"], 1_u64);
        assert_eq!(rows[2]["pubkey"], event.unsigned().pubkey().as_str());
        assert_eq!(
            rows[2]["created_at"],
            event.unsigned().created_at().as_u64()
        );
    }

    #[tokio::test]
    async fn query_indexed_tags_intersects_filter_tag_constraints() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let target_event = "a".repeat(EventId::HEX_LENGTH);
        let other_event = "b".repeat(EventId::HEX_LENGTH);
        let pubkey_a = "1".repeat(PublicKeyHex::HEX_LENGTH);
        let pubkey_b = "2".repeat(PublicKeyHex::HEX_LENGTH);
        let first = synthetic_event(
            "1",
            "b",
            &pubkey_a,
            100,
            1,
            vec![
                Tag::from_parts("e", &[&target_event]).expect("e tag"),
                Tag::from_parts("p", &[&pubkey_a]).expect("p tag"),
            ],
            "first",
        );
        let second = synthetic_event(
            "2",
            "c",
            &pubkey_b,
            101,
            1,
            vec![
                Tag::from_parts("e", &[&target_event]).expect("e tag"),
                Tag::from_parts("p", &[&pubkey_b]).expect("p tag"),
            ],
            "second",
        );
        let third = synthetic_event(
            "3",
            "d",
            &pubkey_a,
            102,
            1,
            vec![
                Tag::from_parts("e", &[&other_event]).expect("e tag"),
                Tag::from_parts("p", &[&pubkey_a]).expect("p tag"),
            ],
            "third",
        );
        for event in [&first, &second, &third] {
            store.index_event_tags(event).await.expect("index");
        }

        let intersection = filter_from_value(&serde_json::json!({
            "#e": [target_event],
            "#p": [pubkey_a],
            "authors": [pubkey_a],
            "kinds": [1],
            "since": 100,
            "until": 102
        }))
        .expect("intersection filter");
        assert_eq!(
            store
                .query_indexed_tag_event_ids(&intersection)
                .await
                .expect("intersection"),
            vec![first.id().as_str().to_owned()]
        );

        let ordered = filter_from_value(&serde_json::json!({
            "#e": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "limit": 1
        }))
        .expect("ordered filter");
        assert_eq!(
            store
                .query_indexed_tag_event_ids(&ordered)
                .await
                .expect("ordered"),
            vec![second.id().as_str().to_owned()]
        );
        assert!(
            store
                .query_indexed_tag_event_ids(
                    &filter_from_value(&serde_json::json!({"kinds": [1]})).expect("no tag filter")
                )
                .await
                .expect("no tags")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn maintain_current_events_tracks_replaceable_and_addressable_winners() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let pubkey = "a".repeat(PublicKeyHex::HEX_LENGTH);
        let replaceable_key = format!("3:{pubkey}");
        let first = synthetic_event(
            "1",
            "b",
            &pubkey,
            1_714_124_700,
            3,
            Vec::new(),
            "profile one",
        );
        let older = synthetic_event(
            "2",
            "c",
            &pubkey,
            1_714_124_699,
            3,
            Vec::new(),
            "profile older",
        );
        let newer = synthetic_event(
            "3",
            "d",
            &pubkey,
            1_714_124_701,
            3,
            Vec::new(),
            "profile newer",
        );
        let tied_lower = synthetic_event(
            "2",
            "e",
            &pubkey,
            1_714_124_701,
            3,
            Vec::new(),
            "profile tied lower",
        );
        let tied_higher = synthetic_event(
            "4",
            "f",
            &pubkey,
            1_714_124_701,
            3,
            Vec::new(),
            "profile tied higher",
        );
        let regular = synthetic_event(
            "5",
            "1",
            &pubkey,
            1_714_124_702,
            1,
            Vec::new(),
            "regular note",
        );

        assert_eq!(
            store.maintain_current_event(&first).await.expect("first"),
            CurrentEventOutcome::Inserted
        );
        assert_eq!(
            store.maintain_current_event(&older).await.expect("older"),
            CurrentEventOutcome::Unchanged
        );
        assert_eq!(
            store.maintain_current_event(&newer).await.expect("newer"),
            CurrentEventOutcome::Replaced
        );
        assert_eq!(
            store
                .maintain_current_event(&tied_lower)
                .await
                .expect("tied lower"),
            CurrentEventOutcome::Unchanged
        );
        assert_eq!(
            store
                .maintain_current_event(&tied_higher)
                .await
                .expect("tied higher"),
            CurrentEventOutcome::Replaced
        );
        assert_eq!(
            store
                .maintain_current_event(&regular)
                .await
                .expect("regular"),
            CurrentEventOutcome::NotCurrent
        );

        let row = store
            .current_event_row(&replaceable_key)
            .await
            .expect("replaceable row")
            .expect("replaceable row exists");
        assert_eq!(row["address_key"], replaceable_key);
        assert_eq!(row["kind"], 3_u64);
        assert_eq!(row["pubkey"], pubkey);
        assert_eq!(row["event_id"], tied_higher.id().as_str());
        assert_eq!(row["tie_break_id"], tied_higher.id().as_str());
        assert_eq!(row["created_at"], 1_714_124_701_u64);
        assert!(row["d"].is_null());
        assert_eq!(row["deleted"], false);
        assert_eq!(row["hidden"], false);

        let addressable = synthetic_event(
            "6",
            "2",
            &pubkey,
            1_714_124_703,
            30_402,
            vec![Tag::from_parts("d", &["listing-a"]).expect("d tag")],
            "listing projection",
        );
        let addressable_key = format!("30402:{pubkey}:listing-a");

        assert_eq!(
            store
                .maintain_current_event(&addressable)
                .await
                .expect("addressable"),
            CurrentEventOutcome::Inserted
        );

        let addressable_row = store
            .current_event_row(&addressable_key)
            .await
            .expect("addressable row")
            .expect("addressable row exists");
        assert_eq!(addressable_row["address_key"], addressable_key);
        assert_eq!(addressable_row["kind"], 30_402_u64);
        assert_eq!(addressable_row["d"], "listing-a");
        assert_eq!(addressable_row["event_id"], addressable.id().as_str());
    }

    #[tokio::test]
    async fn query_current_events_returns_replaceable_winners() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let pubkey_a = "1".repeat(PublicKeyHex::HEX_LENGTH);
        let pubkey_b = "2".repeat(PublicKeyHex::HEX_LENGTH);
        let older = synthetic_event("1", "b", &pubkey_a, 100, 3, Vec::new(), "older");
        let newer = synthetic_event("2", "c", &pubkey_a, 101, 3, Vec::new(), "newer");
        let other = synthetic_event("3", "d", &pubkey_b, 102, 3, Vec::new(), "other");
        let addressable = synthetic_event(
            "4",
            "e",
            &pubkey_a,
            103,
            30_402,
            vec![Tag::from_parts("d", &["listing-current"]).expect("d tag")],
            "listing",
        );
        for event in [&older, &newer, &other, &addressable] {
            store.maintain_current_event(event).await.expect("current");
        }

        let replaceable_filter = filter_from_value(&serde_json::json!({
            "authors": [pubkey_a],
            "kinds": [3],
            "since": 100,
            "until": 101,
            "limit": 1
        }))
        .expect("replaceable filter");
        let rows = store
            .query_current_events(&replaceable_filter)
            .await
            .expect("current rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["event_id"], newer.id().as_str());

        let kind_filter = filter_from_value(&serde_json::json!({
            "kinds": [3]
        }))
        .expect("kind filter");
        let rows = store
            .query_current_events(&kind_filter)
            .await
            .expect("kind rows");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["event_id"], other.id().as_str());
        assert_eq!(rows[1]["event_id"], newer.id().as_str());

        store
            .database()
            .query("UPDATE event_current SET deleted = true WHERE event_id = $event_id;")
            .bind(("event_id", newer.id().as_str()))
            .await
            .expect("delete current")
            .check()
            .expect("delete check");
        let id_filter = filter_from_value(&serde_json::json!({
            "ids": [newer.id().as_str()]
        }))
        .expect("id filter");
        assert!(
            store
                .query_current_events(&id_filter)
                .await
                .expect("deleted current")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn apply_deletion_markers_persists_markers_and_author_scoped_deletes() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let pubkey = "a".repeat(PublicKeyHex::HEX_LENGTH);
        let other_pubkey = "b".repeat(PublicKeyHex::HEX_LENGTH);
        let raw = synthetic_event("7", "3", &pubkey, 1_714_124_800, 1, Vec::new(), "delete me");
        let foreign_target =
            synthetic_event("8", "4", &pubkey, 1_714_124_801, 1, Vec::new(), "keep me");
        let addressable_key = format!("30402:{pubkey}:listing-delete");
        let addressable = synthetic_event(
            "9",
            "5",
            &pubkey,
            1_714_124_802,
            30_402,
            vec![Tag::from_parts("d", &["listing-delete"]).expect("d tag")],
            "delete listing",
        );
        for event in [&raw, &foreign_target, &addressable] {
            assert_eq!(
                store
                    .store_raw_event(&StoredEvent::new(
                        event.clone(),
                        UnixTimestamp::new(1_714_124_900)
                    ))
                    .await
                    .expect("raw insert"),
                StoreEventOutcome::Inserted
            );
        }
        assert_eq!(
            store
                .maintain_current_event(&addressable)
                .await
                .expect("current"),
            CurrentEventOutcome::Inserted
        );

        let deletion = synthetic_event(
            "b",
            "6",
            &pubkey,
            1_714_124_903,
            5,
            vec![
                Tag::from_parts("e", &[raw.id().as_str()]).expect("e tag"),
                Tag::from_parts("a", &[&addressable_key]).expect("a tag"),
            ],
            "remove stale events",
        );
        let not_deletion = synthetic_event(
            "c",
            "7",
            &pubkey,
            1_714_124_904,
            1,
            Vec::new(),
            "plain note",
        );
        let unauthorized = synthetic_event(
            "d",
            "8",
            &other_pubkey,
            1_714_124_905,
            5,
            vec![Tag::from_parts("e", &[foreign_target.id().as_str()]).expect("foreign e")],
            "foreign delete",
        );

        assert_eq!(
            store
                .apply_deletion_markers(&not_deletion)
                .await
                .expect("not deletion"),
            DeletionMarkerOutcome::NotDeletion
        );
        assert_eq!(
            store
                .apply_deletion_markers(&deletion)
                .await
                .expect("delete"),
            DeletionMarkerOutcome::Applied { targets: 2 }
        );
        assert_eq!(
            store
                .apply_deletion_markers(&unauthorized)
                .await
                .expect("unauthorized"),
            DeletionMarkerOutcome::Applied { targets: 1 }
        );

        let markers = store
            .deletion_marker_rows(deletion.id())
            .await
            .expect("markers");
        assert_eq!(markers.len(), 2);
        assert_eq!(markers[0]["target_type"], "address");
        assert_eq!(markers[0]["target_ref"], addressable_key);
        assert_eq!(markers[0]["author_pubkey"], pubkey);
        assert_eq!(markers[1]["target_type"], "event");
        assert_eq!(markers[1]["target_ref"], raw.id().as_str());
        assert_eq!(markers[1]["deletion_created_at"], 1_714_124_903_u64);

        let unauthorized_markers = store
            .deletion_marker_rows(unauthorized.id())
            .await
            .expect("unauthorized markers");
        assert_eq!(unauthorized_markers.len(), 1);

        assert_eq!(
            store
                .raw_event_row(raw.id())
                .await
                .expect("raw row")
                .expect("raw exists")["deleted"],
            true
        );
        assert_eq!(
            store
                .raw_event_row(addressable.id())
                .await
                .expect("address row")
                .expect("address exists")["deleted"],
            true
        );
        assert_eq!(
            store
                .current_event_row(&addressable_key)
                .await
                .expect("current row")
                .expect("current exists")["deleted"],
            true
        );
        assert_eq!(
            store
                .raw_event_row(foreign_target.id())
                .await
                .expect("foreign row")
                .expect("foreign exists")["deleted"],
            false
        );
    }

    #[tokio::test]
    async fn store_listing_revisions_persists_projection_audit_rows() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let projected_at = UnixTimestamp::new(1_714_125_000);
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");

        assert_eq!(
            store
                .store_listing_revision(&listing, projected_at)
                .await
                .expect("valid revision"),
            ListingRevisionOutcome::Stored { parsed_ok: true }
        );

        let row = store
            .listing_revision_row(listing.id())
            .await
            .expect("valid row")
            .expect("valid row exists");
        assert_eq!(row["revision_key"], listing.id().as_str());
        assert_eq!(
            row["listing_key"],
            format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str())
        );
        assert_eq!(row["event_id"], listing.id().as_str());
        assert_eq!(row["seller_pubkey"], listing.unsigned().pubkey().as_str());
        assert_eq!(row["d"], "listing-a");
        assert_eq!(row["created_at"], 1_714_124_433_u64);
        assert_eq!(row["parsed_ok"], true);
        assert_eq!(row["parse_errors"].as_array().expect("errors").len(), 0);
        assert_eq!(row["title"], "Carrot bunches");
        assert!(row["summary"].is_null());
        assert_eq!(row["price_decimal"], "12.50");
        assert_eq!(row["price_minor"], 1_250_u64);
        assert_eq!(row["currency_raw"], "USD");
        assert_eq!(row["currency_norm"], "USD");
        assert_eq!(row["unit"], "lb");
        assert!(row["status_tag"].is_null());
        assert_eq!(row["projected_at"], projected_at.as_u64());

        let pubkey = "c".repeat(PublicKeyHex::HEX_LENGTH);
        let invalid = synthetic_event(
            "e",
            "9",
            &pubkey,
            1_714_125_010,
            30_402,
            vec![Tag::from_parts("d", &["listing-invalid"]).expect("d tag")],
            "",
        );
        let note = synthetic_event(
            "f",
            "a",
            &pubkey,
            1_714_125_011,
            1,
            Vec::new(),
            "not a listing",
        );

        assert_eq!(
            store
                .store_listing_revision(&invalid, projected_at)
                .await
                .expect("invalid revision"),
            ListingRevisionOutcome::Stored { parsed_ok: false }
        );
        assert_eq!(
            store
                .store_listing_revision(&note, projected_at)
                .await
                .expect("note revision"),
            ListingRevisionOutcome::NotListing
        );

        let invalid_row = store
            .listing_revision_row(invalid.id())
            .await
            .expect("invalid row")
            .expect("invalid row exists");
        let errors = invalid_row["parse_errors"].as_array().expect("errors");
        assert_eq!(
            invalid_row["listing_key"],
            format!("30402:{pubkey}:listing-invalid")
        );
        assert_eq!(invalid_row["parsed_ok"], false);
        assert!(errors.contains(&serde_json::Value::String(
            "tag `title` is required".to_owned()
        )));
        assert!(errors.contains(&serde_json::Value::String(
            "tag `price` is required".to_owned()
        )));
        assert!(invalid_row["price_decimal"].is_null());
        assert!(invalid_row["unit"].is_null());
        assert!(
            store
                .listing_revision_row(note.id())
                .await
                .expect("note row")
                .is_none()
        );
    }

    #[tokio::test]
    async fn project_current_listings_persists_normalized_marketplace_rows() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let projected_at = UnixTimestamp::new(1_714_125_100);
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());

        assert_eq!(
            store
                .project_current_listing(&listing, projected_at)
                .await
                .expect("current listing"),
            ListingCurrentOutcome::Projected
        );

        let row = store
            .listing_current_row(&listing_key)
            .await
            .expect("listing row")
            .expect("listing row exists");
        assert_eq!(row["listing_key"], listing_key);
        assert_eq!(row["listing_key_hash"].as_str().expect("hash").len(), 64);
        assert_eq!(row["event_id"], listing.id().as_str());
        assert_eq!(row["seller_pubkey"], listing.unsigned().pubkey().as_str());
        assert_eq!(row["d"], "listing-a");
        assert_eq!(row["created_at"], 1_714_124_433_u64);
        assert_eq!(row["updated_at"], 1_714_124_433_u64);
        assert!(row["published_at"].is_null());
        assert_eq!(row["title"], "Carrot bunches");
        assert!(row["summary"].is_null());
        assert_eq!(row["content"], "Sweet storage carrots.");
        assert_eq!(row["price_decimal"], "12.50");
        assert_eq!(row["price_minor"], 1_250_u64);
        assert_eq!(row["currency_raw"], "USD");
        assert_eq!(row["currency_norm"], "USD");
        assert!(row["price_frequency"].is_null());
        assert_eq!(row["unit"], "lb");
        assert_eq!(row["unit_family"], "lb");
        assert!(row["location_text"].is_null());
        assert_eq!(row["geohash"], "c22yzug");
        assert_eq!(row["geohash4"], "c22y");
        assert_eq!(row["geohash5"], "c22yz");
        assert_eq!(row["geohash6"], "c22yzu");
        assert_eq!(row["geohash7"], "c22yzug");
        assert!(row["point"].is_null());
        assert!(row["status_tag"].is_null());
        assert_eq!(row["effective_status"], "active");
        assert_eq!(row["categories"].as_array().expect("categories").len(), 1);
        assert_eq!(row["categories"][0], "vegetables");
        assert_eq!(row["tags"].as_array().expect("tags").len(), 1);
        assert_eq!(row["tags"][0], "carrots");
        assert_eq!(row["practices"].as_array().expect("practices").len(), 1);
        assert_eq!(row["practices"][0], "no spray");
        assert_eq!(
            row["certifications"]
                .as_array()
                .expect("certifications")
                .len(),
            1
        );
        assert_eq!(row["certifications"][0], "organic");
        assert_eq!(row["image_urls"].as_array().expect("images").len(), 0);
        assert_eq!(row["pickup_available"], true);
        assert_eq!(row["delivery_available"], false);
        assert_eq!(row["shipping_available"], false);
        assert_eq!(row["delivery_only"], false);
        assert!(row["seller_trust_score"].is_null());
        assert_eq!(row["hidden"], false);
        assert_eq!(row["deleted"], false);
        assert_eq!(row["projected_at"], projected_at.as_u64());

        let media_listing = synthetic_event(
            "6",
            "8",
            listing.unsigned().pubkey().as_str(),
            1_714_125_101,
            30_402,
            vec![
                Tag::from_parts("d", &["listing-media"]).expect("d tag"),
                Tag::from_parts("title", &["Media carrots"]).expect("title"),
                Tag::from_parts("price", &["7.25", "USD"]).expect("price"),
                Tag::from_parts("unit", &["lb"]).expect("unit"),
                Tag::from_parts("fulfillment", &["pickup"]).expect("fulfillment"),
                Tag::from_parts("published_at", &["1714125100"]).expect("published"),
                Tag::from_parts(
                    "image",
                    &["https://fixtures.radroots.test/listing-media.png"],
                )
                .expect("image"),
            ],
            "media listing",
        );
        assert_eq!(
            store
                .project_current_listing(&media_listing, projected_at)
                .await
                .expect("media current"),
            ListingCurrentOutcome::Projected
        );
        let media_row = store
            .listing_current_row(&format!(
                "30402:{}:listing-media",
                media_listing.unsigned().pubkey().as_str()
            ))
            .await
            .expect("media row")
            .expect("media row exists");
        assert_eq!(media_row["published_at"], 1_714_125_100_u64);
        assert_eq!(
            media_row["image_urls"][0],
            "https://fixtures.radroots.test/listing-media.png"
        );

        let pubkey = "d".repeat(PublicKeyHex::HEX_LENGTH);
        let invalid = synthetic_event(
            "e",
            "9",
            &pubkey,
            1_714_125_110,
            30_402,
            vec![Tag::from_parts("d", &["listing-invalid"]).expect("d tag")],
            "",
        );
        let note = synthetic_event(
            "f",
            "a",
            &pubkey,
            1_714_125_111,
            1,
            Vec::new(),
            "not a listing",
        );

        assert_eq!(
            store
                .project_current_listing(&invalid, projected_at)
                .await
                .expect("invalid current"),
            ListingCurrentOutcome::Ineligible
        );
        assert_eq!(
            store
                .project_current_listing(&note, projected_at)
                .await
                .expect("note current"),
            ListingCurrentOutcome::NotListing
        );
        assert!(
            store
                .listing_current_row(&format!("30402:{pubkey}:listing-invalid"))
                .await
                .expect("invalid row")
                .is_none()
        );
    }

    #[tokio::test]
    async fn query_current_listings_applies_projection_filters() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
        store
            .project_current_listing(&listing, UnixTimestamp::new(1_714_125_400))
            .await
            .expect("project listing");

        let query = ListingProjectionQuery::new()
            .with_effective_status("active")
            .with_seller_pubkey(listing.unsigned().pubkey().as_str())
            .with_unit("lb")
            .with_currency_norm("USD")
            .with_min_price_minor(1_000)
            .with_max_price_minor(2_000)
            .with_limit(5);
        let rows = store
            .query_current_listings(&query)
            .await
            .expect("listing query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["listing_key"], listing_key);

        let no_match = ListingProjectionQuery::new()
            .with_effective_status("active")
            .with_min_price_minor(2_000);
        assert!(
            store
                .query_current_listings(&no_match)
                .await
                .expect("no match")
                .is_empty()
        );

        store
            .database()
            .query("UPDATE listing_current SET hidden = true WHERE listing_key = $listing_key;")
            .bind(("listing_key", listing_key.as_str()))
            .await
            .expect("hide listing")
            .check()
            .expect("hide check");
        assert!(
            store
                .query_current_listings(
                    &ListingProjectionQuery::new().with_effective_status("active")
                )
                .await
                .expect("hidden query")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn project_listing_helpers_persists_discovery_tables() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());

        assert_eq!(
            store
                .project_listing_helpers(&listing)
                .await
                .expect("helpers"),
            ListingHelperOutcome::Projected
        );
        assert_eq!(
            store
                .project_listing_helpers(&listing)
                .await
                .expect("helpers again"),
            ListingHelperOutcome::Projected
        );

        let categories = store
            .listing_category_rows(&listing_key)
            .await
            .expect("categories");
        let fulfillment = store
            .listing_fulfillment_rows(&listing_key)
            .await
            .expect("fulfillment");
        let topics = store
            .listing_topic_rows(&listing_key)
            .await
            .expect("topics");
        let practices = store
            .listing_practice_rows(&listing_key)
            .await
            .expect("practices");
        let certifications = store
            .listing_certification_rows(&listing_key)
            .await
            .expect("certifications");

        assert_eq!(categories.len(), 1);
        assert_eq!(categories[0]["category"], "vegetables");
        assert_eq!(categories[0]["effective_status"], "active");
        assert_eq!(categories[0]["updated_at"], 1_714_124_433_u64);
        assert_eq!(categories[0]["event_id"], listing.id().as_str());
        assert_eq!(fulfillment.len(), 1);
        assert_eq!(fulfillment[0]["mode"], "pickup");
        assert_eq!(topics.len(), 1);
        assert_eq!(topics[0]["tag_value"], "carrots");
        assert_eq!(practices.len(), 1);
        assert_eq!(practices[0]["practice"], "no spray");
        assert_eq!(certifications.len(), 1);
        assert_eq!(certifications[0]["certification"], "organic");

        let pubkey = "e".repeat(PublicKeyHex::HEX_LENGTH);
        let invalid = synthetic_event(
            "e",
            "9",
            &pubkey,
            1_714_125_210,
            30_402,
            vec![Tag::from_parts("d", &["listing-invalid"]).expect("d tag")],
            "",
        );
        let note = synthetic_event(
            "f",
            "a",
            &pubkey,
            1_714_125_211,
            1,
            Vec::new(),
            "not a listing",
        );

        assert_eq!(
            store
                .project_listing_helpers(&invalid)
                .await
                .expect("invalid helpers"),
            ListingHelperOutcome::Ineligible
        );
        assert_eq!(
            store
                .project_listing_helpers(&note)
                .await
                .expect("note helpers"),
            ListingHelperOutcome::NotListing
        );
        assert!(
            store
                .listing_category_rows(&format!("30402:{pubkey}:listing-invalid"))
                .await
                .expect("invalid categories")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn index_listing_search_documents_persists_listing_search_rows() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let doc_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());

        assert_eq!(
            store
                .index_listing_search_document(&listing)
                .await
                .expect("search document"),
            SearchDocumentOutcome::Indexed
        );
        assert_eq!(
            store
                .index_listing_search_document(&listing)
                .await
                .expect("search document again"),
            SearchDocumentOutcome::Indexed
        );

        let row = store
            .search_document_row(&doc_key)
            .await
            .expect("search row")
            .expect("search row exists");
        assert_eq!(row["doc_key"], doc_key);
        assert_eq!(row["event_id"], listing.id().as_str());
        assert_eq!(row["current_event_id"], listing.id().as_str());
        assert_eq!(row["doc_type"], "listing");
        assert_eq!(row["kind"], 30_402_u64);
        assert_eq!(row["pubkey"], listing.unsigned().pubkey().as_str());
        assert_eq!(row["address_key"], doc_key);
        assert_eq!(row["title"], "Carrot bunches");
        assert!(row["summary"].is_null());
        assert_eq!(row["body"], "Sweet storage carrots.");
        assert_eq!(row["category_text"], "vegetables");
        assert!(row["location_text"].is_null());
        assert_eq!(row["tags"].as_array().expect("tags").len(), 1);
        assert_eq!(row["tags"][0], "carrots");
        assert_eq!(row["categories"].as_array().expect("categories").len(), 1);
        assert_eq!(row["categories"][0], "vegetables");
        assert_eq!(row["created_at"], 1_714_124_433_u64);
        assert_eq!(row["updated_at"], 1_714_124_433_u64);
        assert_eq!(row["visible"], true);
        assert_eq!(row["status"], "active");
        assert!(row["seller_trust_score"].is_null());

        let pubkey = "f".repeat(PublicKeyHex::HEX_LENGTH);
        let invalid = synthetic_event(
            "e",
            "9",
            &pubkey,
            1_714_125_310,
            30_402,
            vec![Tag::from_parts("d", &["listing-invalid"]).expect("d tag")],
            "",
        );
        let note = synthetic_event(
            "f",
            "a",
            &pubkey,
            1_714_125_311,
            1,
            Vec::new(),
            "not a listing",
        );

        assert_eq!(
            store
                .index_listing_search_document(&invalid)
                .await
                .expect("invalid search"),
            SearchDocumentOutcome::Ineligible
        );
        assert_eq!(
            store
                .index_listing_search_document(&note)
                .await
                .expect("note search"),
            SearchDocumentOutcome::NotListing
        );
        assert!(
            store
                .search_document_row(&format!("30402:{pubkey}:listing-invalid"))
                .await
                .expect("invalid row")
                .is_none()
        );
    }

    #[tokio::test]
    async fn query_search_documents_applies_full_text_and_structured_filters() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let doc_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
        store
            .index_listing_search_document(&listing)
            .await
            .expect("index search");

        let query = SearchDocumentQuery::new()
            .with_text("carrot")
            .with_doc_type("listing")
            .with_kind(30_402)
            .with_pubkey(listing.unsigned().pubkey().as_str())
            .with_visible(true)
            .with_status("active")
            .with_limit(5);
        let rows = store
            .query_search_documents(&query)
            .await
            .expect("search rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["doc_key"], doc_key);
        assert!(rows[0]["score"].is_number());

        let miss = SearchDocumentQuery::new()
            .with_text("turnip")
            .with_visible(true);
        assert!(
            store
                .query_search_documents(&miss)
                .await
                .expect("miss rows")
                .is_empty()
        );

        let structured = SearchDocumentQuery::new()
            .with_doc_type("listing")
            .with_visible(true)
            .with_status("active")
            .with_limit(1);
        assert_eq!(
            store
                .query_search_documents(&structured)
                .await
                .expect("structured rows")[0]["doc_key"],
            doc_key
        );

        store
            .database()
            .query("UPDATE search_doc SET visible = false WHERE doc_key = $doc_key;")
            .bind(("doc_key", doc_key.as_str()))
            .await
            .expect("hide search doc")
            .check()
            .expect("hide check");
        assert!(
            store
                .query_search_documents(
                    &SearchDocumentQuery::new()
                        .with_doc_type("listing")
                        .with_visible(true)
                )
                .await
                .expect("hidden rows")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn project_comments_persists_threaded_comment_rows() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
        let comment = listing_comment(&listing, 1_714_125_010, "Is pickup open Friday?");
        let invalid_comment = build_fixture_event_from_parts(
            FixtureKey::Buyer,
            1_714_125_009,
            1_111,
            vec![vec!["K".to_owned(), "30402".to_owned()]],
            "missing scoped targets",
        )
        .expect("invalid comment");

        assert_eq!(
            store
                .project_comment(&listing, UnixTimestamp::new(1_714_125_011))
                .await
                .expect("not comment"),
            CommentProjectionOutcome::NotComment
        );
        assert_eq!(
            store
                .project_comment(&invalid_comment, UnixTimestamp::new(1_714_125_011))
                .await
                .expect("invalid comment"),
            CommentProjectionOutcome::Ineligible
        );
        assert_eq!(
            store
                .project_comment(&comment, UnixTimestamp::new(1_714_125_011))
                .await
                .expect("project comment"),
            CommentProjectionOutcome::Projected
        );

        let row = store
            .comment_projection_row(comment.id())
            .await
            .expect("comment row")
            .expect("comment row exists");
        assert_eq!(row["comment_id"], comment.id().as_str());
        assert_eq!(row["event_id"], comment.id().as_str());
        assert_eq!(row["pubkey"], FixtureKey::Buyer.public_key().as_str());
        assert_eq!(row["content"], "Is pickup open Friday?");
        assert_eq!(row["root_target_type"], "address");
        assert_eq!(row["root_ref"], listing_key);
        assert_eq!(row["root_kind"], "30402");
        assert_eq!(row["root_author"], listing.unsigned().pubkey().as_str());
        assert_eq!(row["parent_target_type"], "address");
        assert_eq!(row["parent_ref"], listing_key);
        assert_eq!(row["parent_kind"], "30402");
        assert_eq!(row["parent_author"], listing.unsigned().pubkey().as_str());
        assert_eq!(row["hidden"], false);
        assert_eq!(row["deleted"], false);
        assert_eq!(row["projected_at"], 1_714_125_011_u64);

        let rows = store
            .query_comment_projections(
                &CommentProjectionQuery::new()
                    .with_root("address", &listing_key)
                    .with_parent("address", &listing_key)
                    .with_pubkey(FixtureKey::Buyer.public_key().as_str())
                    .with_limit(5),
            )
            .await
            .expect("comment query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["event_id"], comment.id().as_str());
    }

    #[tokio::test]
    async fn comment_projection_visibility_tracks_hidden_and_deleted_events() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
        let comment = listing_comment(&listing, 1_714_125_020, "Do you offer bunch pricing?");
        let admin_pubkey = "a".repeat(PublicKeyHex::HEX_LENGTH);
        store
            .store_raw_event(&StoredEvent::new(
                comment.clone(),
                UnixTimestamp::new(1_714_125_021),
            ))
            .await
            .expect("raw comment");
        store
            .project_comment(&comment, UnixTimestamp::new(1_714_125_022))
            .await
            .expect("project comment");

        assert_eq!(
            store
                .query_comment_projections(
                    &CommentProjectionQuery::new().with_root("address", &listing_key)
                )
                .await
                .expect("visible comments")
                .len(),
            1
        );
        assert_eq!(
            store
                .hide_event(
                    comment.id(),
                    "discussion moderation",
                    "admin_api",
                    &admin_pubkey,
                    UnixTimestamp::new(1_714_125_023),
                )
                .await
                .expect("hide comment"),
            HiddenEventOutcome::Hidden
        );
        assert!(
            store
                .query_comment_projections(
                    &CommentProjectionQuery::new().with_root("address", &listing_key)
                )
                .await
                .expect("hidden comments")
                .is_empty()
        );
        assert_eq!(
            store
                .comment_projection_row(comment.id())
                .await
                .expect("comment row")
                .expect("comment row exists")["hidden"],
            true
        );
        assert_eq!(
            store
                .unhide_event(
                    comment.id(),
                    "discussion restored",
                    &admin_pubkey,
                    UnixTimestamp::new(1_714_125_024),
                )
                .await
                .expect("unhide comment"),
            HiddenEventOutcome::Unhidden
        );
        assert_eq!(
            store
                .query_comment_projections(
                    &CommentProjectionQuery::new().with_root("address", &listing_key)
                )
                .await
                .expect("restored comments")
                .len(),
            1
        );

        let deletion = build_fixture_event_from_parts(
            FixtureKey::Buyer,
            1_714_125_025,
            5,
            vec![vec!["e".to_owned(), comment.id().as_str().to_owned()]],
            "",
        )
        .expect("deletion event");
        assert_eq!(
            store
                .apply_deletion_markers(&deletion)
                .await
                .expect("delete comment"),
            DeletionMarkerOutcome::Applied { targets: 1 }
        );
        assert!(
            store
                .query_comment_projections(
                    &CommentProjectionQuery::new().with_root("address", &listing_key)
                )
                .await
                .expect("deleted comments")
                .is_empty()
        );
        assert_eq!(
            store
                .comment_projection_row(comment.id())
                .await
                .expect("comment row")
                .expect("comment row exists")["deleted"],
            true
        );
    }

    #[tokio::test]
    async fn project_reactions_persists_rows_and_aggregate_counts() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let like = listing_reaction(&listing, 1_714_125_030, "+");
        let dislike = listing_reaction(&listing, 1_714_125_031, "-");
        let emoji = listing_reaction(&listing, 1_714_125_032, "⭐");
        let invalid =
            build_fixture_event_from_parts(FixtureKey::Buyer, 1_714_125_029, 7, Vec::new(), "+")
                .expect("invalid reaction");

        assert_eq!(
            store
                .project_reaction(&listing, UnixTimestamp::new(1_714_125_033))
                .await
                .expect("not reaction"),
            ReactionProjectionOutcome::NotReaction
        );
        assert_eq!(
            store
                .project_reaction(&invalid, UnixTimestamp::new(1_714_125_033))
                .await
                .expect("invalid reaction"),
            ReactionProjectionOutcome::Ineligible
        );
        for reaction in [&like, &dislike, &emoji] {
            assert_eq!(
                store
                    .project_reaction(reaction, UnixTimestamp::new(1_714_125_033))
                    .await
                    .expect("project reaction"),
                ReactionProjectionOutcome::Projected
            );
        }

        let row = store
            .reaction_projection_row(like.id())
            .await
            .expect("reaction row")
            .expect("reaction row exists");
        assert_eq!(row["reaction_id"], like.id().as_str());
        assert_eq!(row["event_id"], like.id().as_str());
        assert_eq!(row["pubkey"], FixtureKey::Buyer.public_key().as_str());
        assert_eq!(row["content"], "+");
        assert_eq!(row["value_type"], "like");
        assert_eq!(row["value"], "like");
        assert_eq!(row["target_event_id"], listing.id().as_str());
        assert_eq!(row["target_pubkey"], listing.unsigned().pubkey().as_str());
        assert_eq!(
            row["target_address"],
            format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str())
        );
        assert_eq!(row["target_kind"], "30402");
        assert_eq!(row["hidden"], false);
        assert_eq!(row["deleted"], false);

        let count = store
            .reaction_count_row(listing.id())
            .await
            .expect("count row")
            .expect("count row exists");
        assert_eq!(count["target_event_id"], listing.id().as_str());
        assert_eq!(count["target_kind"], "30402");
        assert_eq!(count["like_count"], 1_i64);
        assert_eq!(count["dislike_count"], 1_i64);
        assert_eq!(count["emoji_count"], 1_i64);
        assert_eq!(count["text_count"], 0_i64);
        assert_eq!(count["total_count"], 3_i64);
    }

    #[tokio::test]
    async fn reaction_counts_track_hidden_restored_and_deleted_reactions() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let reaction = listing_reaction(&listing, 1_714_125_040, "+");
        let admin_pubkey = "a".repeat(PublicKeyHex::HEX_LENGTH);
        store
            .store_raw_event(&StoredEvent::new(
                reaction.clone(),
                UnixTimestamp::new(1_714_125_041),
            ))
            .await
            .expect("raw reaction");
        store
            .project_reaction(&reaction, UnixTimestamp::new(1_714_125_042))
            .await
            .expect("project reaction");

        assert_eq!(
            store
                .reaction_count_row(listing.id())
                .await
                .expect("count")
                .expect("count row")["like_count"],
            1_i64
        );
        store
            .hide_event(
                reaction.id(),
                "reaction moderation",
                "admin_api",
                &admin_pubkey,
                UnixTimestamp::new(1_714_125_043),
            )
            .await
            .expect("hide reaction");
        assert_eq!(
            store
                .reaction_count_row(listing.id())
                .await
                .expect("count")
                .expect("count row")["total_count"],
            0_i64
        );
        store
            .unhide_event(
                reaction.id(),
                "reaction restored",
                &admin_pubkey,
                UnixTimestamp::new(1_714_125_044),
            )
            .await
            .expect("unhide reaction");
        assert_eq!(
            store
                .reaction_count_row(listing.id())
                .await
                .expect("count")
                .expect("count row")["total_count"],
            1_i64
        );
        let deletion = build_fixture_event_from_parts(
            FixtureKey::Buyer,
            1_714_125_045,
            5,
            vec![vec!["e".to_owned(), reaction.id().as_str().to_owned()]],
            "",
        )
        .expect("deletion event");
        store
            .apply_deletion_markers(&deletion)
            .await
            .expect("delete reaction");
        let row = store
            .reaction_projection_row(reaction.id())
            .await
            .expect("reaction row")
            .expect("reaction row exists");
        assert_eq!(row["deleted"], true);
        assert_eq!(
            store
                .reaction_count_row(listing.id())
                .await
                .expect("count")
                .expect("count row")["total_count"],
            0_i64
        );
    }

    #[tokio::test]
    async fn project_long_form_posts_persists_current_topic_and_search_rows() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let article = long_form_article(
            1_714_125_060,
            "harvest-notes",
            "Harvest notes",
            "The storage carrots held well.",
            &["Carrots", "CSA"],
        );
        let draft = build_fixture_event_from_parts(
            FixtureKey::Seller,
            1_714_125_061,
            u64::from(NIP23_LONG_FORM_DRAFT_KIND),
            vec![vec!["d".to_owned(), "draft-a".to_owned()]],
            "Draft body.",
        )
        .expect("draft");
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let long_form_key = format!(
            "30023:{}:harvest-notes",
            article.unsigned().pubkey().as_str()
        );

        assert_eq!(
            store
                .project_long_form(&listing, UnixTimestamp::new(1_714_125_062))
                .await
                .expect("not long form"),
            LongFormProjectionOutcome::NotLongForm
        );
        assert_eq!(
            store
                .project_long_form(&draft, UnixTimestamp::new(1_714_125_062))
                .await
                .expect("draft long form"),
            LongFormProjectionOutcome::Ineligible
        );
        assert_eq!(
            store
                .project_long_form(&article, UnixTimestamp::new(1_714_125_063))
                .await
                .expect("project article"),
            LongFormProjectionOutcome::Projected
        );

        let row = store
            .long_form_current_row(&long_form_key)
            .await
            .expect("long-form row")
            .expect("long-form row exists");
        assert_eq!(row["long_form_key"], long_form_key);
        assert_eq!(row["event_id"], article.id().as_str());
        assert_eq!(
            row["author_pubkey"],
            FixtureKey::Seller.public_key().as_str()
        );
        assert_eq!(row["d"], "harvest-notes");
        assert_eq!(row["created_at"], 1_714_125_060_u64);
        assert_eq!(row["updated_at"], 1_714_125_060_u64);
        assert_eq!(row["published_at"], 1_714_125_000_u64);
        assert_eq!(row["title"], "Harvest notes");
        assert_eq!(row["image"], "https://radroots.test/harvest.jpg");
        assert_eq!(row["summary"], "Long-form harvest field notes.");
        assert_eq!(row["content"], "The storage carrots held well.");
        assert_eq!(row["tags"][0], "carrots");
        assert_eq!(row["tags"][1], "csa");
        assert_eq!(row["referenced_events"][0], "4".repeat(EventId::HEX_LENGTH));
        assert_eq!(
            row["referenced_pubkeys"][0],
            FixtureKey::Buyer.public_key().as_str()
        );
        assert_eq!(row["hidden"], false);
        assert_eq!(row["deleted"], false);

        let topics = store
            .long_form_topic_rows(&long_form_key)
            .await
            .expect("topic rows");
        assert_eq!(topics.len(), 2);
        assert_eq!(topics[0]["topic"], "carrots");
        assert_eq!(topics[1]["topic"], "csa");
        assert_eq!(
            store
                .query_long_form_projections(
                    &LongFormProjectionQuery::new()
                        .with_author_pubkey(FixtureKey::Seller.public_key().as_str())
                        .with_topic("CSA")
                        .with_limit(5),
                )
                .await
                .expect("long-form query")
                .len(),
            1
        );

        let search = store
            .search_document_row(&long_form_key)
            .await
            .expect("search row")
            .expect("search row exists");
        assert_eq!(search["doc_type"], "long_form");
        assert_eq!(search["kind"], u64::from(NIP23_LONG_FORM_KIND));
        assert_eq!(search["title"], "Harvest notes");
        assert_eq!(search["body"], "The storage carrots held well.");
        assert_eq!(search["status"], "published");
        assert_eq!(search["visible"], true);
        assert_eq!(
            store
                .query_search_documents(
                    &SearchDocumentQuery::new()
                        .with_text("carrots")
                        .with_doc_type("long_form")
                        .with_visible(true),
                )
                .await
                .expect("search query")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn long_form_projection_tracks_replacement_moderation_and_deletion() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let first = long_form_article(
            1_714_125_070,
            "harvest-notes",
            "First harvest notes",
            "First body.",
            &["carrots"],
        );
        let second = long_form_article(
            1_714_125_071,
            "harvest-notes",
            "Updated harvest notes",
            "Updated body.",
            &["storage"],
        );
        let long_form_key = format!(
            "30023:{}:harvest-notes",
            second.unsigned().pubkey().as_str()
        );
        let admin_pubkey = "a".repeat(PublicKeyHex::HEX_LENGTH);
        store
            .store_raw_event(&StoredEvent::new(
                second.clone(),
                UnixTimestamp::new(1_714_125_072),
            ))
            .await
            .expect("raw article");

        assert_eq!(
            store
                .project_long_form(&first, UnixTimestamp::new(1_714_125_073))
                .await
                .expect("project first"),
            LongFormProjectionOutcome::Projected
        );
        assert_eq!(
            store
                .project_long_form(&second, UnixTimestamp::new(1_714_125_074))
                .await
                .expect("project second"),
            LongFormProjectionOutcome::Projected
        );
        assert_eq!(
            store
                .project_long_form(&first, UnixTimestamp::new(1_714_125_075))
                .await
                .expect("stale first"),
            LongFormProjectionOutcome::Ineligible
        );
        assert_eq!(
            store
                .long_form_current_row(&long_form_key)
                .await
                .expect("row")
                .expect("row exists")["event_id"],
            second.id().as_str()
        );
        assert_eq!(
            store
                .long_form_topic_rows(&long_form_key)
                .await
                .expect("topics")[0]["topic"],
            "storage"
        );

        assert_eq!(
            store
                .hide_event(
                    second.id(),
                    "long-form moderation",
                    "admin_api",
                    &admin_pubkey,
                    UnixTimestamp::new(1_714_125_076),
                )
                .await
                .expect("hide article"),
            HiddenEventOutcome::Hidden
        );
        assert!(
            store
                .query_long_form_projections(&LongFormProjectionQuery::new())
                .await
                .expect("hidden query")
                .is_empty()
        );
        assert_eq!(
            store
                .long_form_current_row(&long_form_key)
                .await
                .expect("row")
                .expect("row exists")["hidden"],
            true
        );
        assert_eq!(
            store
                .long_form_topic_rows(&long_form_key)
                .await
                .expect("topics")[0]["hidden"],
            true
        );
        assert_eq!(
            store
                .search_document_row(&long_form_key)
                .await
                .expect("search row")
                .expect("search exists")["visible"],
            false
        );

        assert_eq!(
            store
                .unhide_event(
                    second.id(),
                    "long-form restored",
                    &admin_pubkey,
                    UnixTimestamp::new(1_714_125_077),
                )
                .await
                .expect("unhide article"),
            HiddenEventOutcome::Unhidden
        );
        assert_eq!(
            store
                .query_long_form_projections(&LongFormProjectionQuery::new())
                .await
                .expect("visible query")
                .len(),
            1
        );
        assert_eq!(
            store
                .search_document_row(&long_form_key)
                .await
                .expect("search row")
                .expect("search exists")["visible"],
            true
        );

        let deletion = build_fixture_event_from_parts(
            FixtureKey::Seller,
            1_714_125_078,
            5,
            vec![vec!["e".to_owned(), second.id().as_str().to_owned()]],
            "",
        )
        .expect("deletion event");
        assert_eq!(
            store
                .apply_deletion_markers(&deletion)
                .await
                .expect("delete article"),
            DeletionMarkerOutcome::Applied { targets: 1 }
        );
        assert!(
            store
                .query_long_form_projections(&LongFormProjectionQuery::new())
                .await
                .expect("deleted query")
                .is_empty()
        );
        assert_eq!(
            store
                .long_form_current_row(&long_form_key)
                .await
                .expect("row")
                .expect("row exists")["deleted"],
            true
        );
        assert_eq!(
            store
                .long_form_topic_rows(&long_form_key)
                .await
                .expect("topics")[0]["deleted"],
            true
        );
        assert_eq!(
            store
                .search_document_row(&long_form_key)
                .await
                .expect("search row")
                .expect("search exists")["visible"],
            false
        );
    }

    #[tokio::test]
    async fn project_forum_threads_persists_projection_topic_and_search_rows() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let thread = forum_thread(1_714_125_080, Some("Market day thread"), &["market", "CSA"]);
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let invalid = build_fixture_event_from_parts(
            FixtureKey::Buyer,
            1_714_125_079,
            u64::from(NIP7D_THREAD_KIND),
            vec![vec!["p".to_owned(), "bad".to_owned()]],
            "Invalid thread.",
        )
        .expect("invalid thread");

        assert_eq!(
            store
                .project_forum_thread(&listing, UnixTimestamp::new(1_714_125_081))
                .await
                .expect("not forum"),
            ForumThreadProjectionOutcome::NotForumThread
        );
        assert_eq!(
            store
                .project_forum_thread(&invalid, UnixTimestamp::new(1_714_125_081))
                .await
                .expect("invalid forum"),
            ForumThreadProjectionOutcome::Ineligible
        );
        assert_eq!(
            store
                .project_forum_thread(&thread, UnixTimestamp::new(1_714_125_082))
                .await
                .expect("project thread"),
            ForumThreadProjectionOutcome::Projected
        );

        let row = store
            .forum_thread_row(thread.id())
            .await
            .expect("thread row")
            .expect("thread row exists");
        assert_eq!(row["thread_id"], thread.id().as_str());
        assert_eq!(row["event_id"], thread.id().as_str());
        assert_eq!(row["pubkey"], FixtureKey::Buyer.public_key().as_str());
        assert_eq!(row["created_at"], 1_714_125_080_u64);
        assert_eq!(row["updated_at"], 1_714_125_080_u64);
        assert_eq!(row["title"], "Market day thread");
        assert_eq!(row["content"], "What is everyone bringing this weekend?");
        assert_eq!(row["tags"][0], "csa");
        assert_eq!(row["tags"][1], "market");
        assert_eq!(row["referenced_events"][0], "5".repeat(EventId::HEX_LENGTH));
        assert_eq!(
            row["referenced_pubkeys"][0],
            FixtureKey::Seller.public_key().as_str()
        );
        assert_eq!(row["hidden"], false);
        assert_eq!(row["deleted"], false);

        let topics = store
            .forum_thread_topic_rows(thread.id())
            .await
            .expect("topic rows");
        assert_eq!(topics.len(), 2);
        assert_eq!(topics[0]["topic"], "csa");
        assert_eq!(topics[1]["topic"], "market");
        assert_eq!(
            store
                .query_forum_threads(
                    &ForumThreadProjectionQuery::new()
                        .with_pubkey(FixtureKey::Buyer.public_key().as_str())
                        .with_topic("Market")
                        .with_limit(5),
                )
                .await
                .expect("forum query")
                .len(),
            1
        );

        let search = store
            .search_document_row(thread.id().as_str())
            .await
            .expect("search row")
            .expect("search row exists");
        assert_eq!(search["doc_type"], "forum_thread");
        assert_eq!(search["kind"], u64::from(NIP7D_THREAD_KIND));
        assert_eq!(search["title"], "Market day thread");
        assert_eq!(search["body"], "What is everyone bringing this weekend?");
        assert_eq!(search["status"], "open");
        assert_eq!(search["visible"], true);
        assert_eq!(
            store
                .query_search_documents(
                    &SearchDocumentQuery::new()
                        .with_text("bringing")
                        .with_doc_type("forum_thread")
                        .with_visible(true),
                )
                .await
                .expect("search query")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn forum_thread_projection_tracks_moderation_and_deletion() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let thread = forum_thread(1_714_125_090, None, &["market"]);
        let admin_pubkey = "a".repeat(PublicKeyHex::HEX_LENGTH);
        store
            .store_raw_event(&StoredEvent::new(
                thread.clone(),
                UnixTimestamp::new(1_714_125_091),
            ))
            .await
            .expect("raw thread");
        store
            .project_forum_thread(&thread, UnixTimestamp::new(1_714_125_092))
            .await
            .expect("project thread");

        assert_eq!(
            store
                .search_document_row(thread.id().as_str())
                .await
                .expect("search")
                .expect("search row")["title"],
            "What is everyone bringing this weekend?"
        );
        assert_eq!(
            store
                .hide_event(
                    thread.id(),
                    "forum moderation",
                    "admin_api",
                    &admin_pubkey,
                    UnixTimestamp::new(1_714_125_093),
                )
                .await
                .expect("hide thread"),
            HiddenEventOutcome::Hidden
        );
        assert!(
            store
                .query_forum_threads(&ForumThreadProjectionQuery::new())
                .await
                .expect("hidden query")
                .is_empty()
        );
        assert_eq!(
            store
                .forum_thread_row(thread.id())
                .await
                .expect("row")
                .expect("row exists")["hidden"],
            true
        );
        assert_eq!(
            store
                .forum_thread_topic_rows(thread.id())
                .await
                .expect("topics")[0]["hidden"],
            true
        );
        assert_eq!(
            store
                .search_document_row(thread.id().as_str())
                .await
                .expect("search")
                .expect("search row")["visible"],
            false
        );

        assert_eq!(
            store
                .unhide_event(
                    thread.id(),
                    "forum restored",
                    &admin_pubkey,
                    UnixTimestamp::new(1_714_125_094),
                )
                .await
                .expect("unhide thread"),
            HiddenEventOutcome::Unhidden
        );
        assert_eq!(
            store
                .query_forum_threads(&ForumThreadProjectionQuery::new())
                .await
                .expect("visible query")
                .len(),
            1
        );
        assert_eq!(
            store
                .search_document_row(thread.id().as_str())
                .await
                .expect("search")
                .expect("search row")["visible"],
            true
        );

        let deletion = build_fixture_event_from_parts(
            FixtureKey::Buyer,
            1_714_125_095,
            5,
            vec![vec!["e".to_owned(), thread.id().as_str().to_owned()]],
            "",
        )
        .expect("deletion event");
        assert_eq!(
            store
                .apply_deletion_markers(&deletion)
                .await
                .expect("delete thread"),
            DeletionMarkerOutcome::Applied { targets: 1 }
        );
        assert!(
            store
                .query_forum_threads(&ForumThreadProjectionQuery::new())
                .await
                .expect("deleted query")
                .is_empty()
        );
        assert_eq!(
            store
                .forum_thread_row(thread.id())
                .await
                .expect("row")
                .expect("row exists")["deleted"],
            true
        );
        assert_eq!(
            store
                .forum_thread_topic_rows(thread.id())
                .await
                .expect("topics")[0]["deleted"],
            true
        );
        assert_eq!(
            store
                .search_document_row(thread.id().as_str())
                .await
                .expect("search")
                .expect("search row")["visible"],
            false
        );
    }

    #[tokio::test]
    async fn project_labels_persists_deterministic_target_label_rows() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
        let label = listing_label(
            &listing,
            1_714_125_100,
            &["reviewed", "market"],
            "moderator labels listing",
        );
        let invalid_label = build_fixture_event_from_parts(
            FixtureKey::Buyer,
            1_714_125_099,
            u64::from(NIP32_LABEL_KIND),
            vec![vec!["l".to_owned(), "reviewed".to_owned()]],
            "missing target",
        )
        .expect("invalid label");

        assert_eq!(
            store
                .project_label(&listing, UnixTimestamp::new(1_714_125_101))
                .await
                .expect("not label"),
            LabelProjectionOutcome::NotLabel
        );
        assert_eq!(
            store
                .project_label(&invalid_label, UnixTimestamp::new(1_714_125_101))
                .await
                .expect("invalid label"),
            LabelProjectionOutcome::Ineligible
        );
        assert_eq!(
            store
                .project_label(&label, UnixTimestamp::new(1_714_125_102))
                .await
                .expect("project label"),
            LabelProjectionOutcome::Projected
        );
        assert_eq!(
            store
                .project_label(&label, UnixTimestamp::new(1_714_125_103))
                .await
                .expect("reproject label"),
            LabelProjectionOutcome::Projected
        );

        let rows = store
            .label_projection_rows(label.id())
            .await
            .expect("label rows");
        assert_eq!(rows.len(), 4);
        assert!(
            rows.iter()
                .all(|row| row["label_id"].as_str().expect("label id").len() == 64)
        );
        assert!(
            rows.iter()
                .all(|row| row["event_id"] == label.id().as_str())
        );
        assert!(
            rows.iter()
                .all(|row| row["pubkey"] == FixtureKey::Buyer.public_key().as_str())
        );
        assert!(
            rows.iter()
                .all(|row| row["created_at"] == 1_714_125_100_u64)
        );
        assert!(
            rows.iter()
                .all(|row| row["content"] == "moderator labels listing")
        );
        assert!(
            rows.iter()
                .all(|row| row["namespace"] == "com.radroots.moderation")
        );
        assert!(
            rows.iter()
                .all(|row| row["projected_at"] == 1_714_125_103_u64)
        );

        let address_rows = store
            .query_label_projections(
                &LabelProjectionQuery::new()
                    .with_target("address", &listing_key)
                    .with_namespace("com.radroots.moderation")
                    .with_label("reviewed")
                    .with_pubkey(FixtureKey::Buyer.public_key().as_str())
                    .with_limit(5),
            )
            .await
            .expect("label query");
        assert_eq!(address_rows.len(), 1);
        assert_eq!(address_rows[0]["target_type"], "address");
        assert_eq!(address_rows[0]["target_ref"], listing_key);
        assert_eq!(address_rows[0]["label"], "reviewed");
        assert_eq!(address_rows[0]["hidden"], false);
        assert_eq!(address_rows[0]["deleted"], false);

        let event_rows = store
            .query_label_projections(
                &LabelProjectionQuery::new()
                    .with_target("event", listing.id().as_str())
                    .with_namespace("com.radroots.moderation")
                    .with_limit(5),
            )
            .await
            .expect("event label query");
        assert_eq!(event_rows.len(), 2);
    }

    #[tokio::test]
    async fn label_projection_visibility_tracks_hidden_and_deleted_events() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
        let label = listing_label(&listing, 1_714_125_110, &["reviewed"], "label under review");
        let admin_pubkey = "a".repeat(PublicKeyHex::HEX_LENGTH);
        store
            .store_raw_event(&StoredEvent::new(
                label.clone(),
                UnixTimestamp::new(1_714_125_111),
            ))
            .await
            .expect("raw label");
        store
            .project_label(&label, UnixTimestamp::new(1_714_125_112))
            .await
            .expect("project label");

        let query = LabelProjectionQuery::new()
            .with_target("address", &listing_key)
            .with_namespace("com.radroots.moderation")
            .with_label("reviewed");
        assert_eq!(
            store
                .query_label_projections(&query)
                .await
                .expect("visible labels")
                .len(),
            1
        );
        assert_eq!(
            store
                .hide_event(
                    label.id(),
                    "label moderation",
                    "admin_api",
                    &admin_pubkey,
                    UnixTimestamp::new(1_714_125_113),
                )
                .await
                .expect("hide label"),
            HiddenEventOutcome::Hidden
        );
        assert!(
            store
                .query_label_projections(&query)
                .await
                .expect("hidden labels")
                .is_empty()
        );
        assert!(
            store
                .label_projection_rows(label.id())
                .await
                .expect("label rows")
                .iter()
                .all(|row| row["hidden"] == true)
        );
        assert_eq!(
            store
                .unhide_event(
                    label.id(),
                    "label restored",
                    &admin_pubkey,
                    UnixTimestamp::new(1_714_125_114),
                )
                .await
                .expect("unhide label"),
            HiddenEventOutcome::Unhidden
        );
        assert_eq!(
            store
                .query_label_projections(&query)
                .await
                .expect("restored labels")
                .len(),
            1
        );

        let deletion = build_fixture_event_from_parts(
            FixtureKey::Buyer,
            1_714_125_115,
            5,
            vec![vec!["e".to_owned(), label.id().as_str().to_owned()]],
            "",
        )
        .expect("deletion event");
        assert_eq!(
            store
                .apply_deletion_markers(&deletion)
                .await
                .expect("delete label"),
            DeletionMarkerOutcome::Applied { targets: 1 }
        );
        assert!(
            store
                .query_label_projections(&query)
                .await
                .expect("deleted labels")
                .is_empty()
        );
        assert!(
            store
                .label_projection_rows(label.id())
                .await
                .expect("label rows")
                .iter()
                .all(|row| row["deleted"] == true)
        );
    }

    #[tokio::test]
    async fn project_reports_persists_deterministic_target_report_rows() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let report = listing_report(
            &listing,
            1_714_125_120,
            Some("impersonation"),
            "spam",
            "moderator report",
        );
        let invalid_report = build_fixture_event_from_parts(
            FixtureKey::Buyer,
            1_714_125_119,
            u64::from(NIP56_REPORT_KIND),
            vec![vec![
                "p".to_owned(),
                listing.unsigned().pubkey().as_str().to_owned(),
            ]],
            "missing report type",
        )
        .expect("invalid report");

        assert_eq!(
            store
                .project_report(&listing, UnixTimestamp::new(1_714_125_121))
                .await
                .expect("not report"),
            ReportProjectionOutcome::NotReport
        );
        assert_eq!(
            store
                .project_report(&invalid_report, UnixTimestamp::new(1_714_125_121))
                .await
                .expect("invalid report"),
            ReportProjectionOutcome::Ineligible
        );
        assert_eq!(
            store
                .project_report(&report, UnixTimestamp::new(1_714_125_122))
                .await
                .expect("project report"),
            ReportProjectionOutcome::Projected
        );
        assert_eq!(
            store
                .project_report(&report, UnixTimestamp::new(1_714_125_123))
                .await
                .expect("reproject report"),
            ReportProjectionOutcome::Projected
        );

        let rows = store
            .report_projection_rows(report.id())
            .await
            .expect("report rows");
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .all(|row| row["report_id"].as_str().expect("report id").len() == 64)
        );
        assert!(
            rows.iter()
                .all(|row| row["event_id"] == report.id().as_str())
        );
        assert!(
            rows.iter()
                .all(|row| row["pubkey"] == FixtureKey::Buyer.public_key().as_str())
        );
        assert!(
            rows.iter()
                .all(|row| row["created_at"] == 1_714_125_120_u64)
        );
        assert!(rows.iter().all(|row| row["content"] == "moderator report"));
        assert!(
            rows.iter()
                .all(|row| row["reported_pubkeys"][0] == listing.unsigned().pubkey().as_str())
        );
        assert!(
            rows.iter()
                .all(|row| row["server_urls"][0] == "https://media.radroots.test/report.jpg")
        );
        assert!(
            rows.iter()
                .all(|row| row["projected_at"] == 1_714_125_123_u64)
        );

        let event_rows = store
            .query_report_projections(
                &ReportProjectionQuery::new()
                    .with_target("event", listing.id().as_str())
                    .with_report_type("spam")
                    .with_pubkey(FixtureKey::Buyer.public_key().as_str())
                    .with_limit(5),
            )
            .await
            .expect("report query");
        assert_eq!(event_rows.len(), 1);
        assert_eq!(event_rows[0]["target_type"], "event");
        assert_eq!(event_rows[0]["target_ref"], listing.id().as_str());
        assert_eq!(event_rows[0]["report_type"], "spam");
        assert_eq!(event_rows[0]["hidden"], false);
        assert_eq!(event_rows[0]["deleted"], false);

        let pubkey_rows = store
            .query_report_projections(
                &ReportProjectionQuery::new()
                    .with_target("pubkey", listing.unsigned().pubkey().as_str())
                    .with_report_type("impersonation")
                    .with_limit(5),
            )
            .await
            .expect("profile report query");
        assert_eq!(pubkey_rows.len(), 1);
    }

    #[tokio::test]
    async fn report_projection_visibility_tracks_hidden_and_deleted_events() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let report = listing_report(
            &listing,
            1_714_125_130,
            None,
            "spam",
            "listing should be reviewed",
        );
        let admin_pubkey = "a".repeat(PublicKeyHex::HEX_LENGTH);
        store
            .store_raw_event(&StoredEvent::new(
                report.clone(),
                UnixTimestamp::new(1_714_125_131),
            ))
            .await
            .expect("raw report");
        store
            .project_report(&report, UnixTimestamp::new(1_714_125_132))
            .await
            .expect("project report");

        let query = ReportProjectionQuery::new()
            .with_target("event", listing.id().as_str())
            .with_report_type("spam");
        assert_eq!(
            store
                .query_report_projections(&query)
                .await
                .expect("visible reports")
                .len(),
            1
        );
        assert_eq!(
            store
                .hide_event(
                    report.id(),
                    "report moderation",
                    "admin_api",
                    &admin_pubkey,
                    UnixTimestamp::new(1_714_125_133),
                )
                .await
                .expect("hide report"),
            HiddenEventOutcome::Hidden
        );
        assert!(
            store
                .query_report_projections(&query)
                .await
                .expect("hidden reports")
                .is_empty()
        );
        assert!(
            store
                .report_projection_rows(report.id())
                .await
                .expect("report rows")
                .iter()
                .all(|row| row["hidden"] == true)
        );
        assert_eq!(
            store
                .unhide_event(
                    report.id(),
                    "report restored",
                    &admin_pubkey,
                    UnixTimestamp::new(1_714_125_134),
                )
                .await
                .expect("unhide report"),
            HiddenEventOutcome::Unhidden
        );
        assert_eq!(
            store
                .query_report_projections(&query)
                .await
                .expect("restored reports")
                .len(),
            1
        );

        let deletion = build_fixture_event_from_parts(
            FixtureKey::Buyer,
            1_714_125_135,
            5,
            vec![vec!["e".to_owned(), report.id().as_str().to_owned()]],
            "",
        )
        .expect("deletion event");
        assert_eq!(
            store
                .apply_deletion_markers(&deletion)
                .await
                .expect("delete report"),
            DeletionMarkerOutcome::Applied { targets: 1 }
        );
        assert!(
            store
                .query_report_projections(&query)
                .await
                .expect("deleted reports")
                .is_empty()
        );
        assert!(
            store
                .report_projection_rows(report.id())
                .await
                .expect("report rows")
                .iter()
                .all(|row| row["deleted"] == true)
        );
    }

    #[tokio::test]
    async fn project_seller_profiles_persists_current_metadata_and_trust_state() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let profile = seller_profile(
            1_714_125_140,
            "radroots-market",
            Some("Radroots Market"),
            &["PNW", "pnw", " Cascadia "],
            &["Produce", "produce"],
            &["CSA", "regenerative"],
        );
        let invalid_profile = build_fixture_event_from_parts(
            FixtureKey::Seller,
            1_714_125_139,
            u64::from(NIP01_METADATA_KIND),
            Vec::new(),
            "{\"name\":7}",
        )
        .expect("invalid profile");

        store
            .set_seller_approved(
                FixtureKey::Seller.public_key().as_str(),
                true,
                UnixTimestamp::new(1_714_125_138),
            )
            .await
            .expect("approve seller");
        assert_eq!(
            store
                .project_seller_profile(&listing, UnixTimestamp::new(1_714_125_141))
                .await
                .expect("not profile"),
            SellerProfileProjectionOutcome::NotProfile
        );
        assert_eq!(
            store
                .project_seller_profile(&invalid_profile, UnixTimestamp::new(1_714_125_141))
                .await
                .expect("invalid profile"),
            SellerProfileProjectionOutcome::Ineligible
        );
        assert_eq!(
            store
                .project_seller_profile(&profile, UnixTimestamp::new(1_714_125_142))
                .await
                .expect("project profile"),
            SellerProfileProjectionOutcome::Projected
        );

        let row = store
            .seller_profile_row(FixtureKey::Seller.public_key().as_str())
            .await
            .expect("profile row")
            .expect("profile exists");
        assert_eq!(row["pubkey"], FixtureKey::Seller.public_key().as_str());
        assert_eq!(row["event_id"], profile.id().as_str());
        assert_eq!(row["created_at"], 1_714_125_140_u64);
        assert_eq!(row["updated_at"], 1_714_125_140_u64);
        assert_eq!(row["name"], "radroots-market");
        assert_eq!(row["display_name"], "Radroots Market");
        assert_eq!(row["about"], "Local food seller profile");
        assert_eq!(row["picture"], "https://fixtures.radroots.test/seller.png");
        assert_eq!(row["website"], "https://seller.radroots.test");
        assert_eq!(row["nip05"], "seller@radroots.test");
        assert_eq!(row["lud16"], "seller@pay.radroots.test");
        assert_eq!(row["regions"], serde_json::json!(["cascadia", "pnw"]));
        assert_eq!(row["categories"], serde_json::json!(["produce"]));
        assert_eq!(
            row["trust_markers"],
            serde_json::json!(["csa", "regenerative"])
        );
        assert_eq!(row["seller_approved"], true);
        assert_eq!(row["blocked"], false);
        assert_eq!(row["hidden"], false);
        assert_eq!(row["deleted"], false);
        assert_eq!(row["projected_at"], 1_714_125_142_u64);

        let rows = store
            .query_seller_profiles(
                &SellerProfileQuery::new()
                    .with_pubkey(FixtureKey::Seller.public_key().as_str())
                    .with_approved(true)
                    .with_blocked(false)
                    .with_limit(5),
            )
            .await
            .expect("seller query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["event_id"], profile.id().as_str());
    }

    #[tokio::test]
    async fn metrics_snapshot_counts_projected_store_state() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let profile = seller_profile(
            1_714_125_145,
            "radroots-market",
            Some("Radroots Market"),
            &["PNW"],
            &["Produce"],
            &["CSA"],
        );
        let blocked_pubkey = "b".repeat(PublicKeyHex::HEX_LENGTH);

        store
            .store_raw_event(&StoredEvent::new(
                listing.clone(),
                UnixTimestamp::new(1_714_125_146),
            ))
            .await
            .expect("store listing");
        store
            .store_raw_event(&StoredEvent::new(
                profile.clone(),
                UnixTimestamp::new(1_714_125_147),
            ))
            .await
            .expect("store profile");
        store
            .project_current_listing(&listing, UnixTimestamp::new(1_714_125_148))
            .await
            .expect("project listing");
        store
            .project_seller_profile(&profile, UnixTimestamp::new(1_714_125_149))
            .await
            .expect("project profile");
        store
            .set_seller_approved(
                FixtureKey::Seller.public_key().as_str(),
                true,
                UnixTimestamp::new(1_714_125_150),
            )
            .await
            .expect("approve seller");
        store
            .set_pubkey_blocked(&blocked_pubkey, true, UnixTimestamp::new(1_714_125_151))
            .await
            .expect("block pubkey");

        let snapshot = store.metrics_snapshot().await.expect("snapshot");
        assert_eq!(snapshot.stored_events(), 2);
        assert_eq!(snapshot.visible_events(), 2);
        assert_eq!(snapshot.hidden_events(), 0);
        assert_eq!(snapshot.deleted_events(), 0);
        assert_eq!(snapshot.current_listings(), 1);
        assert_eq!(snapshot.active_listings(), 1);
        assert_eq!(snapshot.seller_profiles(), 1);
        assert_eq!(snapshot.visible_seller_profiles(), 1);
        assert_eq!(snapshot.approved_sellers(), 1);
        assert_eq!(snapshot.blocked_pubkeys(), 1);
    }

    #[tokio::test]
    async fn seller_profile_projection_tracks_replacement_moderation_and_deletion() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let older = seller_profile(
            1_714_125_150,
            "older-market",
            None,
            &["pnw"],
            &["produce"],
            &["csa"],
        );
        let newer = seller_profile(
            1_714_125_151,
            "newer-market",
            Some("Newer Market"),
            &["cascadia"],
            &["fruit"],
            &["inspected"],
        );
        let admin_pubkey = "a".repeat(PublicKeyHex::HEX_LENGTH);

        assert_eq!(
            store
                .project_seller_profile(&older, UnixTimestamp::new(1_714_125_152))
                .await
                .expect("older profile"),
            SellerProfileProjectionOutcome::Projected
        );
        assert_eq!(
            store
                .project_seller_profile(&newer, UnixTimestamp::new(1_714_125_153))
                .await
                .expect("newer profile"),
            SellerProfileProjectionOutcome::Projected
        );
        assert_eq!(
            store
                .project_seller_profile(&older, UnixTimestamp::new(1_714_125_154))
                .await
                .expect("stale profile"),
            SellerProfileProjectionOutcome::Ineligible
        );
        let current = store
            .seller_profile_row(FixtureKey::Seller.public_key().as_str())
            .await
            .expect("profile row")
            .expect("profile exists");
        assert_eq!(current["event_id"], newer.id().as_str());
        assert_eq!(current["name"], "newer-market");
        assert_eq!(current["categories"], serde_json::json!(["fruit"]));

        store
            .store_raw_event(&StoredEvent::new(
                newer.clone(),
                UnixTimestamp::new(1_714_125_155),
            ))
            .await
            .expect("raw profile");
        assert_eq!(
            store
                .hide_event(
                    newer.id(),
                    "profile moderation",
                    "admin_api",
                    &admin_pubkey,
                    UnixTimestamp::new(1_714_125_156),
                )
                .await
                .expect("hide profile"),
            HiddenEventOutcome::Hidden
        );
        assert!(
            store
                .query_seller_profiles(&SellerProfileQuery::new())
                .await
                .expect("hidden profiles")
                .is_empty()
        );
        assert_eq!(
            store
                .seller_profile_row(FixtureKey::Seller.public_key().as_str())
                .await
                .expect("profile row")
                .expect("profile exists")["hidden"],
            true
        );
        assert_eq!(
            store
                .unhide_event(
                    newer.id(),
                    "profile restored",
                    &admin_pubkey,
                    UnixTimestamp::new(1_714_125_157),
                )
                .await
                .expect("unhide profile"),
            HiddenEventOutcome::Unhidden
        );
        assert_eq!(
            store
                .query_seller_profiles(&SellerProfileQuery::new())
                .await
                .expect("visible profiles")
                .len(),
            1
        );

        store
            .set_pubkey_blocked(
                FixtureKey::Seller.public_key().as_str(),
                true,
                UnixTimestamp::new(1_714_125_158),
            )
            .await
            .expect("block seller");
        assert_eq!(
            store
                .seller_profile_row(FixtureKey::Seller.public_key().as_str())
                .await
                .expect("profile row")
                .expect("profile exists")["blocked"],
            true
        );

        let deletion = build_fixture_event_from_parts(
            FixtureKey::Seller,
            1_714_125_159,
            5,
            vec![vec!["e".to_owned(), newer.id().as_str().to_owned()]],
            "",
        )
        .expect("deletion event");
        assert_eq!(
            store
                .apply_deletion_markers(&deletion)
                .await
                .expect("delete profile"),
            DeletionMarkerOutcome::Applied { targets: 1 }
        );
        assert!(
            store
                .query_seller_profiles(&SellerProfileQuery::new())
                .await
                .expect("deleted profiles")
                .is_empty()
        );
        assert_eq!(
            store
                .seller_profile_row(FixtureKey::Seller.public_key().as_str())
                .await
                .expect("profile row")
                .expect("profile exists")["deleted"],
            true
        );
    }

    #[tokio::test]
    async fn hidden_event_overlay_excludes_events_from_public_read_models() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
        let admin_pubkey = "a".repeat(PublicKeyHex::HEX_LENGTH);
        let id_filter = filter_from_value(&serde_json::json!({
            "ids": [listing.id().as_str()]
        }))
        .expect("id filter");

        store
            .store_raw_event(&StoredEvent::new(
                listing.clone(),
                UnixTimestamp::new(1_714_125_500),
            ))
            .await
            .expect("raw event");
        store
            .maintain_current_event(&listing)
            .await
            .expect("current event");
        store
            .project_current_listing(&listing, UnixTimestamp::new(1_714_125_501))
            .await
            .expect("listing projection");
        store
            .index_listing_search_document(&listing)
            .await
            .expect("search document");

        assert_eq!(
            store
                .query_raw_events(&id_filter)
                .await
                .expect("raw query")
                .len(),
            1
        );
        assert_eq!(
            store
                .query_current_events(&id_filter)
                .await
                .expect("current query")
                .len(),
            1
        );
        assert_eq!(
            store
                .query_current_listings(
                    &ListingProjectionQuery::new().with_effective_status("active")
                )
                .await
                .expect("listing query")
                .len(),
            1
        );
        assert_eq!(
            store
                .query_search_documents(
                    &SearchDocumentQuery::new()
                        .with_text("carrot")
                        .with_doc_type("listing")
                        .with_visible(true)
                )
                .await
                .expect("search query")
                .len(),
            1
        );

        assert_eq!(
            store
                .hide_event(
                    listing.id(),
                    "policy proof",
                    "admin_api",
                    &admin_pubkey,
                    UnixTimestamp::new(1_714_125_600),
                )
                .await
                .expect("hide"),
            HiddenEventOutcome::Hidden
        );

        let hidden = store
            .hidden_event_row(listing.id())
            .await
            .expect("hidden row")
            .expect("hidden row exists");
        assert_eq!(hidden["event_id"], listing.id().as_str());
        assert_eq!(hidden["reason"], "policy proof");
        assert_eq!(hidden["source"], "admin_api");
        assert_eq!(hidden["created_at"], 1_714_125_600_u64);
        assert_eq!(hidden["admin_pubkey"], admin_pubkey);
        assert_eq!(
            store
                .raw_event_row(listing.id())
                .await
                .expect("raw row")
                .expect("raw row exists")["hidden"],
            true
        );
        assert_eq!(
            store
                .current_event_row(&listing_key)
                .await
                .expect("current row")
                .expect("current row exists")["hidden"],
            true
        );
        assert_eq!(
            store
                .listing_current_row(&listing_key)
                .await
                .expect("listing row")
                .expect("listing row exists")["hidden"],
            true
        );
        assert_eq!(
            store
                .search_document_row(&listing_key)
                .await
                .expect("search row")
                .expect("search row exists")["visible"],
            false
        );
        assert!(
            store
                .query_raw_events(&id_filter)
                .await
                .expect("hidden raw query")
                .is_empty()
        );
        assert!(
            store
                .query_current_events(&id_filter)
                .await
                .expect("hidden current query")
                .is_empty()
        );
        assert!(
            store
                .query_current_listings(
                    &ListingProjectionQuery::new().with_effective_status("active")
                )
                .await
                .expect("hidden listing query")
                .is_empty()
        );
        assert!(
            store
                .query_search_documents(
                    &SearchDocumentQuery::new()
                        .with_text("carrot")
                        .with_doc_type("listing")
                        .with_visible(true)
                )
                .await
                .expect("hidden search query")
                .is_empty()
        );
        let actions = store
            .moderation_action_rows("event", listing.id().as_str())
            .await
            .expect("actions");
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0]["action"], "hide");
        assert_eq!(actions[0]["target_ref"], listing.id().as_str());

        assert_eq!(
            store
                .unhide_event(
                    listing.id(),
                    "policy proof complete",
                    &admin_pubkey,
                    UnixTimestamp::new(1_714_125_700),
                )
                .await
                .expect("unhide"),
            HiddenEventOutcome::Unhidden
        );
        assert!(
            store
                .hidden_event_row(listing.id())
                .await
                .expect("hidden row removed")
                .is_none()
        );
        assert_eq!(
            store
                .raw_event_row(listing.id())
                .await
                .expect("raw row")
                .expect("raw row exists")["hidden"],
            false
        );
        assert_eq!(
            store
                .search_document_row(&listing_key)
                .await
                .expect("search row")
                .expect("search row exists")["visible"],
            true
        );
        assert_eq!(
            store
                .query_search_documents(
                    &SearchDocumentQuery::new()
                        .with_text("carrot")
                        .with_doc_type("listing")
                        .with_visible(true)
                )
                .await
                .expect("visible search query")
                .len(),
            1
        );
        let actions = store
            .moderation_action_rows("event", listing.id().as_str())
            .await
            .expect("actions");
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[1]["action"], "unhide");
        assert_eq!(
            store
                .hide_event(
                    &EventId::new(&"b".repeat(EventId::HEX_LENGTH)).expect("missing id"),
                    "missing",
                    "admin_api",
                    &admin_pubkey,
                    UnixTimestamp::new(1_714_125_800),
                )
                .await
                .expect("missing hide"),
            HiddenEventOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn durable_rate_limit_state_persists_fixed_windows() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let key = "event_write:".to_owned() + &"1".repeat(PublicKeyHex::HEX_LENGTH);

        let first = store
            .check_durable_rate_limit(&key, 3, 60, 1, UnixTimestamp::new(100))
            .await
            .expect("first");
        let second = store
            .check_durable_rate_limit(&key, 3, 60, 2, UnixTimestamp::new(110))
            .await
            .expect("second");
        let rejected = store
            .check_durable_rate_limit(&key, 3, 60, 1, UnixTimestamp::new(120))
            .await
            .expect("rejected");

        assert_eq!(
            first,
            DurableRateLimitDecision::Accepted {
                remaining: 2,
                reset_at: UnixTimestamp::new(160)
            }
        );
        assert!(first.allowed());
        assert_eq!(first.remaining(), 2);
        assert_eq!(first.reset_at(), UnixTimestamp::new(160));
        assert_eq!(first.retry_after_seconds(), None);
        assert_eq!(
            second,
            DurableRateLimitDecision::Accepted {
                remaining: 0,
                reset_at: UnixTimestamp::new(160)
            }
        );
        assert_eq!(
            rejected,
            DurableRateLimitDecision::Rejected {
                retry_after_seconds: 40,
                reset_at: UnixTimestamp::new(160)
            }
        );
        assert!(!rejected.allowed());
        assert_eq!(rejected.remaining(), 0);
        assert_eq!(rejected.retry_after_seconds(), Some(40));
        let row = store
            .rate_limit_state_row(&key)
            .await
            .expect("rate row")
            .expect("rate row exists");
        assert_eq!(row["key"], key);
        assert_eq!(row["expires_at"], 160_u64);
        assert_eq!(row["created_at"], 100_u64);
        assert_eq!(row["updated_at"], 110_u64);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(row["state"].as_str().expect("state"))
                .expect("state json"),
            serde_json::json!({
                "started_at": 100,
                "used": 3
            })
        );

        let reset = store
            .check_durable_rate_limit(&key, 3, 60, 1, UnixTimestamp::new(160))
            .await
            .expect("reset");
        assert_eq!(
            reset,
            DurableRateLimitDecision::Accepted {
                remaining: 2,
                reset_at: UnixTimestamp::new(220)
            }
        );
        let row = store
            .rate_limit_state_row(&key)
            .await
            .expect("rate row")
            .expect("rate row exists");
        assert_eq!(row["expires_at"], 220_u64);
        assert_eq!(row["created_at"], 100_u64);
        assert_eq!(row["updated_at"], 160_u64);
        assert_eq!(
            store
                .prune_expired_rate_limit_state(UnixTimestamp::new(221))
                .await
                .expect("prune"),
            1
        );
        assert!(
            store
                .rate_limit_state_row(&key)
                .await
                .expect("pruned row")
                .is_none()
        );
    }

    #[tokio::test]
    async fn relay_user_policy_rows_persist_approval_and_block_state() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let seller = "2".repeat(PublicKeyHex::HEX_LENGTH);

        store
            .set_seller_approved(&seller, true, UnixTimestamp::new(1_714_125_900))
            .await
            .expect("approve seller");
        let approved = store
            .relay_user_row(&seller)
            .await
            .expect("relay user")
            .expect("relay user exists");
        assert_eq!(approved["pubkey"], seller);
        assert_eq!(approved["role"], "seller");
        assert_eq!(approved["seller_approved"], true);
        assert_eq!(approved["blocked"], false);
        assert_eq!(approved["created_at"], 1_714_125_900_u64);
        assert_eq!(approved["updated_at"], 1_714_125_900_u64);

        store
            .set_pubkey_blocked(&seller, true, UnixTimestamp::new(1_714_126_000))
            .await
            .expect("block seller");
        let blocked = store
            .relay_user_row(&seller)
            .await
            .expect("relay user")
            .expect("relay user exists");
        assert_eq!(blocked["seller_approved"], true);
        assert_eq!(blocked["blocked"], true);
        assert_eq!(blocked["created_at"], 1_714_125_900_u64);
        assert_eq!(blocked["updated_at"], 1_714_126_000_u64);

        store
            .set_seller_approved(&seller, false, UnixTimestamp::new(1_714_126_100))
            .await
            .expect("unapprove seller");
        let unapproved = store
            .relay_user_row(&seller)
            .await
            .expect("relay user")
            .expect("relay user exists");
        assert_eq!(unapproved["seller_approved"], false);
        assert_eq!(unapproved["blocked"], true);
        assert_eq!(unapproved["created_at"], 1_714_125_900_u64);
        assert_eq!(unapproved["updated_at"], 1_714_126_100_u64);
    }

    #[tokio::test]
    async fn private_helpers_cover_debug_errors_and_decimal_edges() {
        let store = memory_store().await;
        assert!(format!("{store:?}").contains("SurrealStore"));
        let source = store
            .database()
            .query("THIS IS NOT VALID SURQL")
            .await
            .expect_err("surreal error");
        assert!(!SurrealStoreError::from(source).message().is_empty());
        let note = synthetic_event(
            "1",
            "b",
            &"1".repeat(PublicKeyHex::HEX_LENGTH),
            1,
            1,
            Vec::new(),
            "note",
        );
        let fields =
            super::listing_revision_fields(&note, &ListingProjectionEvaluation::NotListing)
                .expect("not listing fields");
        assert_eq!(fields.revision_key, note.id().as_str());
        assert!(!fields.parsed_ok);
        let pubkey = "2".repeat(PublicKeyHex::HEX_LENGTH);
        let addressable_without_d =
            synthetic_event("2", "c", &pubkey, 2, 30_402, Vec::new(), "addressless");
        assert_eq!(
            super::address_key_value(&addressable_without_d)
                .expect_err("address key error")
                .message(),
            "addressable event must include a d tag"
        );
        assert_eq!(
            store
                .maintain_current_event(&addressable_without_d)
                .await
                .expect_err("current key error")
                .message(),
            "addressable event must include a d tag"
        );
        let malformed_deletion = synthetic_event(
            "3",
            "d",
            &pubkey,
            3,
            5,
            vec![Tag::from_parts("e", &["not-hex"]).expect("e tag")],
            "bad deletion",
        );
        assert_eq!(
            store
                .apply_deletion_markers(&malformed_deletion)
                .await
                .expect_err("malformed deletion")
                .message(),
            "event id must be 64 characters, got 7"
        );
        assert_eq!(
            super::tag_values(
                &synthetic_event(
                    "4",
                    "e",
                    &pubkey,
                    4,
                    1,
                    vec![
                        Tag::from_parts("image", &["https://fixtures.radroots.test/helper.png"])
                            .expect("image tag")
                    ],
                    "image helper",
                ),
                "image"
            ),
            vec!["https://fixtures.radroots.test/helper.png".to_owned()]
        );
        assert_eq!(
            super::unique_in_order(vec![
                "first".to_owned(),
                "first".to_owned(),
                "second".to_owned()
            ]),
            vec!["first".to_owned(), "second".to_owned()]
        );
        assert_eq!(super::price_minor("12"), Some(1_200));
        assert_eq!(super::price_minor("1.2.3"), None);
        assert_eq!(super::price_minor("1.234"), None);
    }

    #[tokio::test]
    async fn project_current_listing_rejects_prices_without_minor_unit_representation() {
        let store = memory_store().await;
        store
            .apply_plan(&base_migration_plan())
            .await
            .expect("apply plan");
        let pubkey = "1".repeat(PublicKeyHex::HEX_LENGTH);
        let listing = synthetic_event(
            "2",
            "c",
            &pubkey,
            1_714_125_500,
            30_402,
            vec![
                Tag::from_parts("d", &["listing-fractional"]).expect("d tag"),
                Tag::from_parts("title", &["Fractional carrots"]).expect("title"),
                Tag::from_parts("price", &["1.234", "USD"]).expect("price"),
                Tag::from_parts("unit", &["lb"]).expect("unit"),
                Tag::from_parts("fulfillment", &["pickup"]).expect("fulfillment"),
            ],
            "fractional listing",
        );

        assert_eq!(
            store
                .store_listing_revision(&listing, UnixTimestamp::new(1_714_125_501))
                .await
                .expect("revision"),
            ListingRevisionOutcome::Stored { parsed_ok: true }
        );
        assert_eq!(
            store
                .listing_revision_row(listing.id())
                .await
                .expect("revision row")
                .expect("revision exists")["price_minor"],
            serde_json::Value::Null
        );
        let error = store
            .project_current_listing(&listing, UnixTimestamp::new(1_714_125_501))
            .await
            .expect_err("minor unit error");
        assert_eq!(
            error.message(),
            "listing price amount must fit two decimal minor units"
        );
    }

    fn seller_profile(
        created_at: u64,
        name: &str,
        display_name: Option<&str>,
        regions: &[&str],
        categories: &[&str],
        trust_markers: &[&str],
    ) -> Event {
        let mut tags = Vec::new();
        tags.extend(
            regions
                .iter()
                .map(|region| vec!["region".to_owned(), (*region).to_owned()]),
        );
        tags.extend(
            categories
                .iter()
                .map(|category| vec!["category".to_owned(), (*category).to_owned()]),
        );
        tags.extend(
            trust_markers
                .iter()
                .map(|trust| vec!["trust".to_owned(), (*trust).to_owned()]),
        );
        let mut content = serde_json::json!({
            "name": name,
            "about": "Local food seller profile",
            "picture": "https://fixtures.radroots.test/seller.png",
            "website": "https://seller.radroots.test",
            "nip05": "seller@radroots.test",
            "lud16": "seller@pay.radroots.test"
        });
        if let Some(display_name) = display_name {
            content["display_name"] = serde_json::Value::String(display_name.to_owned());
        }
        build_fixture_event_from_parts(
            FixtureKey::Seller,
            created_at,
            u64::from(NIP01_METADATA_KIND),
            tags,
            &content.to_string(),
        )
        .expect("seller profile")
    }

    fn listing_comment(listing: &Event, created_at: u64, content: &str) -> Event {
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
        build_fixture_event_from_parts(
            FixtureKey::Buyer,
            created_at,
            1_111,
            vec![
                vec!["A".to_owned(), listing_key.clone()],
                vec!["K".to_owned(), "30402".to_owned()],
                vec![
                    "P".to_owned(),
                    listing.unsigned().pubkey().as_str().to_owned(),
                ],
                vec!["a".to_owned(), listing_key],
                vec!["k".to_owned(), "30402".to_owned()],
                vec![
                    "p".to_owned(),
                    listing.unsigned().pubkey().as_str().to_owned(),
                ],
            ],
            content,
        )
        .expect("comment event")
    }

    fn listing_reaction(listing: &Event, created_at: u64, content: &str) -> Event {
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
        build_fixture_event_from_parts(
            FixtureKey::Buyer,
            created_at,
            7,
            vec![
                vec![
                    "e".to_owned(),
                    listing.id().as_str().to_owned(),
                    "wss://relay.radroots.test".to_owned(),
                    listing.unsigned().pubkey().as_str().to_owned(),
                ],
                vec![
                    "p".to_owned(),
                    listing.unsigned().pubkey().as_str().to_owned(),
                ],
                vec!["a".to_owned(), listing_key],
                vec!["k".to_owned(), "30402".to_owned()],
            ],
            content,
        )
        .expect("reaction event")
    }

    fn listing_label(listing: &Event, created_at: u64, labels: &[&str], content: &str) -> Event {
        let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
        let namespace = "com.radroots.moderation";
        let mut tags = vec![
            vec!["L".to_owned(), namespace.to_owned()],
            vec!["e".to_owned(), listing.id().as_str().to_owned()],
            vec!["a".to_owned(), listing_key],
        ];
        tags.extend(
            labels
                .iter()
                .map(|label| vec!["l".to_owned(), (*label).to_owned(), namespace.to_owned()]),
        );
        build_fixture_event_from_parts(
            FixtureKey::Buyer,
            created_at,
            u64::from(NIP32_LABEL_KIND),
            tags,
            content,
        )
        .expect("label event")
    }

    fn listing_report(
        listing: &Event,
        created_at: u64,
        profile_report_type: Option<&str>,
        event_report_type: &str,
        content: &str,
    ) -> Event {
        let mut pubkey_tag = vec![
            "p".to_owned(),
            listing.unsigned().pubkey().as_str().to_owned(),
        ];
        if let Some(report_type) = profile_report_type {
            pubkey_tag.push(report_type.to_owned());
        }
        build_fixture_event_from_parts(
            FixtureKey::Buyer,
            created_at,
            u64::from(NIP56_REPORT_KIND),
            vec![
                pubkey_tag,
                vec![
                    "e".to_owned(),
                    listing.id().as_str().to_owned(),
                    event_report_type.to_owned(),
                ],
                vec![
                    "server".to_owned(),
                    "https://media.radroots.test/report.jpg".to_owned(),
                ],
            ],
            content,
        )
        .expect("report event")
    }

    fn long_form_article(
        created_at: u64,
        d: &str,
        title: &str,
        content: &str,
        topics: &[&str],
    ) -> Event {
        let buyer_pubkey = FixtureKey::Buyer.public_key().as_str().to_owned();
        let referenced_address = format!("30023:{buyer_pubkey}:soil-notes");
        let mut tags = vec![
            vec!["d".to_owned(), d.to_owned()],
            vec!["title".to_owned(), title.to_owned()],
            vec![
                "summary".to_owned(),
                "Long-form harvest field notes.".to_owned(),
            ],
            vec![
                "image".to_owned(),
                "https://radroots.test/harvest.jpg".to_owned(),
            ],
            vec!["published_at".to_owned(), "1714125000".to_owned()],
            vec!["e".to_owned(), "4".repeat(EventId::HEX_LENGTH)],
            vec!["a".to_owned(), referenced_address],
            vec!["p".to_owned(), buyer_pubkey],
        ];
        tags.extend(
            topics
                .iter()
                .map(|topic| vec!["t".to_owned(), (*topic).to_owned()]),
        );
        build_fixture_event_from_parts(
            FixtureKey::Seller,
            created_at,
            u64::from(NIP23_LONG_FORM_KIND),
            tags,
            content,
        )
        .expect("long-form article")
    }

    fn forum_thread(created_at: u64, title: Option<&str>, topics: &[&str]) -> Event {
        let mut tags = vec![
            vec!["e".to_owned(), "5".repeat(EventId::HEX_LENGTH)],
            vec![
                "p".to_owned(),
                FixtureKey::Seller.public_key().as_str().to_owned(),
            ],
        ];
        if let Some(title) = title {
            tags.push(vec!["title".to_owned(), title.to_owned()]);
        }
        tags.extend(
            topics
                .iter()
                .map(|topic| vec!["t".to_owned(), (*topic).to_owned()]),
        );
        build_fixture_event_from_parts(
            FixtureKey::Buyer,
            created_at,
            u64::from(NIP7D_THREAD_KIND),
            tags,
            "What is everyone bringing this weekend?",
        )
        .expect("forum thread")
    }

    fn synthetic_event(
        id_digit: &str,
        sig_digit: &str,
        pubkey: &str,
        created_at: u64,
        kind: u64,
        tags: Vec<Tag>,
        content: &str,
    ) -> Event {
        Event::new(
            EventId::new(&id_digit.repeat(EventId::HEX_LENGTH)).expect("id"),
            UnsignedEvent::new(
                PublicKeyHex::new(pubkey).expect("pubkey"),
                UnixTimestamp::new(created_at),
                Kind::new(kind).expect("kind"),
                tags,
                content,
            ),
            SignatureHex::new(&sig_digit.repeat(SignatureHex::HEX_LENGTH)).expect("sig"),
        )
    }
}
