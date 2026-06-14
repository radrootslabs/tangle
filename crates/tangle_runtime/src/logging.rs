#![forbid(unsafe_code)]

use crate::{
    config::{BaseRelayRuntimeConfig, BaseRelayTracingConfig, BaseRelayTracingFormat},
    errors::BaseRelayError,
};
use std::{fmt, net::IpAddr, net::SocketAddr};
use tangle_protocol::{EventId, SubscriptionId, UnixTimestamp};
use tracing_subscriber::EnvFilter;

pub const TANGLE_LOG_REDACTED: &str = "<redacted>";
pub const TANGLE_LOG_SECRET_ABSENT: &str = "absent";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TangleTracingInit {
    Disabled,
    Installed,
    AlreadyInstalled,
}

#[derive(Clone, PartialEq, Eq)]
pub struct TangleLogRedactor {
    secrets: Vec<String>,
}

impl TangleLogRedactor {
    pub fn new<I, S>(secrets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut secrets = secrets
            .into_iter()
            .map(Into::into)
            .filter(|secret| !secret.is_empty())
            .collect::<Vec<_>>();
        secrets.sort();
        secrets.dedup();
        Self { secrets }
    }

    pub fn from_runtime_config(config: &BaseRelayRuntimeConfig) -> Self {
        Self::new(
            config
                .groups()
                .relay_secret()
                .map(|secret| secret.expose_for_signing().to_owned()),
        )
    }

    pub fn redact(&self, value: impl AsRef<str>) -> String {
        let mut redacted = value.as_ref().to_owned();
        for secret in &self.secrets {
            redacted = redacted.replace(secret, TANGLE_LOG_REDACTED);
        }
        redacted
    }

    pub fn contains_secret(&self, value: impl AsRef<str>) -> bool {
        let value = value.as_ref();
        self.secrets.iter().any(|secret| value.contains(secret))
    }

    pub fn secret_count(&self) -> usize {
        self.secrets.len()
    }
}

impl fmt::Debug for TangleLogRedactor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TangleLogRedactor")
            .field("secret_count", &self.secret_count())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TangleRuntimeLogSummary {
    listen_addr: SocketAddr,
    relay_url: String,
    groups_enabled: bool,
    relay_secret: &'static str,
}

impl TangleRuntimeLogSummary {
    pub fn from_config(config: &BaseRelayRuntimeConfig) -> Self {
        Self {
            listen_addr: config.listen_addr(),
            relay_url: config.relay_url().to_owned(),
            groups_enabled: config.groups().enabled(),
            relay_secret: relay_secret_log_value(config),
        }
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    pub fn groups_enabled(&self) -> bool {
        self.groups_enabled
    }

    pub fn relay_secret(&self) -> &'static str {
        self.relay_secret
    }
}

pub fn init_tangle_tracing(
    config: &BaseRelayTracingConfig,
) -> Result<TangleTracingInit, BaseRelayError> {
    if !config.enabled() {
        return Ok(TangleTracingInit::Disabled);
    }
    let filter = EnvFilter::try_new(config.filter()).map_err(|error| {
        BaseRelayError::invalid(format!("observability.tracing.filter is invalid: {error}"))
    })?;
    let result = match config.format() {
        BaseRelayTracingFormat::Compact => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .compact()
            .try_init(),
        BaseRelayTracingFormat::Json => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .json()
            .try_init(),
    };
    match result {
        Ok(()) => Ok(TangleTracingInit::Installed),
        Err(_) => Ok(TangleTracingInit::AlreadyInstalled),
    }
}

pub fn log_runtime_config_loaded(config: &BaseRelayRuntimeConfig) {
    let summary = TangleRuntimeLogSummary::from_config(config);
    tracing::info!(
        event = "runtime_config_loaded",
        listen_addr = %summary.listen_addr(),
        relay_url = summary.relay_url(),
        groups_enabled = summary.groups_enabled(),
        relay_secret = summary.relay_secret(),
        "tangle runtime config loaded"
    );
}

pub fn log_runtime_opened(config: &BaseRelayRuntimeConfig) {
    let summary = TangleRuntimeLogSummary::from_config(config);
    tracing::info!(
        event = "runtime_opened",
        listen_addr = %summary.listen_addr(),
        relay_url = summary.relay_url(),
        groups_enabled = summary.groups_enabled(),
        relay_secret = summary.relay_secret(),
        "tangle runtime opened"
    );
}

pub fn log_server_listening(listen_addr: SocketAddr, relay_url: &str) {
    tracing::info!(
        event = "server_listening",
        listen_addr = %listen_addr,
        relay_url,
        "tangle server listening"
    );
}

pub fn log_server_shutdown(listen_addr: SocketAddr, closed_subscriptions: usize) {
    tracing::info!(
        event = "server_shutdown",
        listen_addr = %listen_addr,
        closed_subscriptions,
        "tangle server shut down"
    );
}

pub fn log_websocket_session_opened(connection_id: u64, peer_ip: Option<IpAddr>) {
    tracing::info!(
        event = "websocket_session_opened",
        connection_id,
        peer_ip = optional_ip(peer_ip),
        "tangle websocket session opened"
    );
}

pub fn log_websocket_session_closed(
    connection_id: u64,
    peer_ip: Option<IpAddr>,
    closed_subscriptions: usize,
) {
    tracing::info!(
        event = "websocket_session_closed",
        connection_id,
        peer_ip = optional_ip(peer_ip),
        closed_subscriptions,
        "tangle websocket session closed"
    );
}

pub fn log_subscription_opened(connection_id: u64, subscription_id: &SubscriptionId) {
    tracing::info!(
        event = "subscription_opened",
        connection_id,
        subscription_id = subscription_id.as_str(),
        "tangle subscription opened"
    );
}

pub fn log_rate_limit_rejected(
    scope: &'static str,
    dimension: &'static str,
    reset_at: UnixTimestamp,
) {
    tracing::warn!(
        event = "rate_limit_rejected",
        scope,
        dimension,
        reset_at = reset_at.as_u64(),
        "tangle rate limit rejected client message"
    );
}

pub fn log_event_stored(event_id: &EventId, stored_offsets: usize, total_stored_offsets: u64) {
    tracing::info!(
        event = "event_stored",
        event_id = event_id.as_str(),
        stored_offsets,
        total_stored_offsets,
        "tangle event stored"
    );
}

pub fn sanitize_error_message(config: &BaseRelayRuntimeConfig, message: impl AsRef<str>) -> String {
    TangleLogRedactor::from_runtime_config(config).redact(message)
}

fn relay_secret_log_value(config: &BaseRelayRuntimeConfig) -> &'static str {
    if config.groups().relay_secret().is_some() {
        TANGLE_LOG_REDACTED
    } else {
        TANGLE_LOG_SECRET_ABSENT
    }
}

fn optional_ip(peer_ip: Option<IpAddr>) -> String {
    peer_ip
        .map(|address| address.to_string())
        .unwrap_or_else(|| "unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        TANGLE_LOG_REDACTED, TangleLogRedactor, TangleRuntimeLogSummary, log_runtime_config_loaded,
        sanitize_error_message,
    };
    use crate::config::parse_base_relay_runtime_config_json;
    use std::{
        io,
        sync::{Arc, Mutex},
    };

    #[test]
    fn log_redactor_removes_configured_relay_secret() {
        let secret = "7".repeat(64);
        let redactor = TangleLogRedactor::new([secret.clone()]);

        assert_eq!(
            redactor.redact(format!("relay secret {secret} loaded")),
            "relay secret <redacted> loaded"
        );
        assert!(redactor.contains_secret(format!("raw={secret}")));
        assert!(!format!("{redactor:?}").contains(&secret));
    }

    #[test]
    fn runtime_log_summary_never_contains_relay_secret() {
        let raw = include_str!("../../../ops/production/tangle-v2.example.json");
        let config = parse_base_relay_runtime_config_json(raw).expect("config");
        let secret = "7".repeat(64);
        let summary = TangleRuntimeLogSummary::from_config(&config);

        assert_eq!(summary.relay_secret(), TANGLE_LOG_REDACTED);
        assert!(!format!("{summary:?}").contains(&secret));
        assert_eq!(
            sanitize_error_message(&config, format!("failed with relay secret {secret}")),
            "failed with relay secret <redacted>"
        );
    }

    #[test]
    fn structured_runtime_config_log_redacts_relay_secret() {
        let raw = include_str!("../../../ops/production/tangle-v2.example.json");
        let config = parse_base_relay_runtime_config_json(raw).expect("config");
        let secret = "7".repeat(64);
        let writer = CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(writer.clone())
            .with_max_level(tracing::Level::INFO)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            log_runtime_config_loaded(&config);
        });

        let output = writer.output();
        assert!(output.contains(r#""event":"runtime_config_loaded""#));
        assert!(output.contains(r#""relay_secret":"<redacted>""#));
        assert!(!output.contains(&secret));
    }

    #[derive(Clone, Default)]
    struct CapturedWriter {
        inner: Arc<Mutex<Vec<u8>>>,
    }

    impl CapturedWriter {
        fn output(&self) -> String {
            let bytes = self.inner.lock().expect("writer").clone();
            String::from_utf8(bytes).expect("utf8")
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedWriter {
        type Writer = CapturedWriterGuard;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedWriterGuard {
                inner: Arc::clone(&self.inner),
            }
        }
    }

    struct CapturedWriterGuard {
        inner: Arc<Mutex<Vec<u8>>>,
    }

    impl io::Write for CapturedWriterGuard {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.inner.lock().expect("writer").extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
