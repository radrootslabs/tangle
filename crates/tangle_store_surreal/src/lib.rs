#![forbid(unsafe_code)]

use core::fmt;
use sha2::{Digest, Sha256};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use tangle_protocol::{AddressCoordinate, Event, EventId, event_to_value};
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
        if self.has_migration_table().await? {
            if let Some(applied) = self.applied_migration(migration.name()).await? {
                if applied.checksum() == migration.checksum() {
                    return Ok(MigrationApplyOutcome::AlreadyApplied);
                }
                return Err(SurrealStoreError::new(&format!(
                    "surreal migration `{}` checksum changed",
                    migration.name()
                )));
            }
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
            .zip(checksums.into_iter())
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
        MigrationApplyOutcome, SurrealConfigError, SurrealConnectionConfig, SurrealConnectionMode,
        SurrealMigration, SurrealMigrationError, SurrealMigrationPlan, SurrealStore,
        base_migration_plan, migration_tracking_schema,
    };
    use tangle_protocol::{
        Event, EventId, Kind, PublicKeyHex, SignatureHex, Tag, UnixTimestamp, UnsignedEvent,
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
}
