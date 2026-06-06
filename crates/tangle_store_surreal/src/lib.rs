#![forbid(unsafe_code)]

use core::fmt;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use tangle_nips::{
    DeletionTarget, ListingProjection, ListingProjectionEvaluation, NIP99_DRAFT_LISTING_KIND,
    NIP99_PUBLIC_LISTING_KIND, evaluate_listing_projection, parse_deletion_request,
};
use tangle_protocol::{AddressCoordinate, Event, EventId, Filter, UnixTimestamp, event_to_value};
use tangle_store::{StoreEventOutcome, StoredEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurrealConnectionMode {
    Memory,
    Http { endpoint: String },
    WebSocket { endpoint: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurrealConnectionConfig {
    mode: SurrealConnectionMode,
    namespace: String,
    database: String,
}

impl SurrealConnectionConfig {
    pub fn memory(namespace: &str, database: &str) -> Result<Self, SurrealConfigError> {
        Self::new(SurrealConnectionMode::Memory, namespace, database)
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

    fn new(
        mode: SurrealConnectionMode,
        namespace: &str,
        database: &str,
    ) -> Result<Self, SurrealConfigError> {
        Ok(Self {
            mode,
            namespace: normalized_identifier(namespace, "namespace")?,
            database: normalized_identifier(database, "database")?,
        })
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

#[derive(Clone)]
pub struct SurrealStore {
    db: Surreal<Db>,
}

impl fmt::Debug for SurrealStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SurrealStore")
            .finish_non_exhaustive()
    }
}

impl SurrealStore {
    pub async fn connect_memory(
        config: &SurrealConnectionConfig,
    ) -> Result<Self, SurrealStoreError> {
        if config.mode() != &SurrealConnectionMode::Memory {
            return Err(SurrealStoreError::new(
                "surreal memory connection requires memory mode config",
            ));
        }
        let db = Surreal::new::<Mem>(())
            .await
            .map_err(SurrealStoreError::from)?;
        db.use_ns(config.namespace())
            .use_db(config.database())
            .await
            .map_err(SurrealStoreError::from)?;
        Ok(Self { db })
    }

    pub fn database(&self) -> &Surreal<Db> {
        &self.db
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
        let info: Option<surrealdb::types::Value> =
            response.take(0).map_err(SurrealStoreError::from)?;
        Ok(info
            .map(|value| format!("{value:?}"))
            .unwrap_or_else(|| "None".to_owned()))
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
        let Some(intersection) = intersection else {
            return Ok(Vec::new());
        };
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
            match target_type {
                "event" => {
                    self.mark_raw_event_deleted(&target_ref, event.unsigned().pubkey().as_str())
                        .await?;
                }
                "address" => {
                    self.mark_address_deleted(&target_ref, event.unsigned().pubkey().as_str())
                        .await?;
                }
                _ => {}
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
    ) -> Result<(), SurrealStoreError> {
        self.db
            .query(
                "UPDATE nostr_event SET deleted = true WHERE event_id = $event_id AND pubkey = $author_pubkey;",
            )
            .bind(("event_id", event_id))
            .bind(("author_pubkey", author_pubkey))
            .await
            .map_err(SurrealStoreError::from)?
            .check()
            .map_err(SurrealStoreError::from)?;
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
        CurrentEventOutcome, DeletionMarkerOutcome, ListingCurrentOutcome, ListingHelperOutcome,
        ListingProjectionQuery, ListingRevisionOutcome, MigrationApplyOutcome,
        SearchDocumentOutcome, SearchDocumentQuery, SurrealConfigError, SurrealConnectionConfig,
        SurrealConnectionMode, SurrealMigration, SurrealMigrationError, SurrealMigrationPlan,
        SurrealStore, base_migration_plan, migration_tracking_schema,
    };
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
        filter_from_value,
    };
    use tangle_store::{StoreEventOutcome, StoredEvent};
    use tangle_test_support::{build_fixture_event, valid_public_listing_spec};

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
        let http = SurrealConnectionConfig::http(" http://127.0.0.1:8000 ", "ns", "db")
            .expect("http config");
        let websocket = SurrealConnectionConfig::websocket(" ws://127.0.0.1:8000 ", "ns", "db")
            .expect("websocket config");

        assert_eq!(
            http.mode(),
            &SurrealConnectionMode::Http {
                endpoint: "http://127.0.0.1:8000".to_owned()
            }
        );
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
            SurrealConnectionConfig::websocket(" ", "ns", "db")
                .expect_err("websocket endpoint error")
                .to_string(),
            "surreal websocket endpoint must not be empty"
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
