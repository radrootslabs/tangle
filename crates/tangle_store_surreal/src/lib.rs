#![forbid(unsafe_code)]

use core::fmt;
use sha2::{Digest, Sha256};

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

#[cfg(test)]
mod tests {
    use super::{
        SurrealConfigError, SurrealConnectionConfig, SurrealConnectionMode, SurrealMigration,
        SurrealMigrationError, SurrealMigrationPlan,
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
}
