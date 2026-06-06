#![forbid(unsafe_code)]

use core::fmt;
use sha2::{Digest, Sha256};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};

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
DEFINE FIELD IF NOT EXISTS raw_json ON TABLE nostr_event TYPE object;
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
}
