#![forbid(unsafe_code)]

use core::fmt;

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

#[cfg(test)]
mod tests {
    use super::{SurrealConfigError, SurrealConnectionConfig, SurrealConnectionMode};

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
}
