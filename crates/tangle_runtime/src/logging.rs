#![forbid(unsafe_code)]

use crate::{
    config::{BaseRelayRuntimeConfig, BaseRelayTracingConfig, BaseRelayTracingFormat},
    errors::BaseRelayError,
};
use std::{fmt, net::IpAddr, net::SocketAddr};
use tangle_groups::{
    GroupEventClass, GroupEventView, KIND_GROUP_ADMINS, KIND_GROUP_CREATE_GROUP,
    KIND_GROUP_DELETE_EVENT, KIND_GROUP_DELETE_GROUP, KIND_GROUP_EDIT_METADATA,
    KIND_GROUP_JOIN_REQUEST, KIND_GROUP_LEAVE_REQUEST, KIND_GROUP_MEMBERS, KIND_GROUP_METADATA,
    KIND_GROUP_PUT_USER, KIND_GROUP_REMOVE_USER,
};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TangleModerationAuditResult {
    Accepted,
    Rejected,
}

impl TangleModerationAuditResult {
    fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TangleModerationAuditEntry {
    action_family: &'static str,
    result: &'static str,
    event_id: String,
    actor_pubkey: String,
    event_kind: u32,
    target_count: usize,
    generated_state_rejection: bool,
}

impl TangleModerationAuditEntry {
    pub(crate) fn new(
        event: &(impl GroupEventView + ?Sized),
        class: &GroupEventClass,
        result: TangleModerationAuditResult,
    ) -> Option<Self> {
        let action_family = moderation_audit_action_family(event, class)?;
        let event_id = event.id().ok()?;
        let actor_pubkey = event.pubkey().ok()?;
        let generated_state_rejection = matches!(
            (class, result),
            (
                GroupEventClass::RelayGeneratedSnapshot { .. },
                TangleModerationAuditResult::Rejected
            )
        );
        Some(Self {
            action_family,
            result: result.as_str(),
            event_id: event_id.as_str().to_owned(),
            actor_pubkey: actor_pubkey.as_str().to_owned(),
            event_kind: event.kind_u32(),
            target_count: moderation_target_count(event, action_family),
            generated_state_rejection,
        })
    }
}

pub(crate) fn log_group_moderation_audit(
    event: &(impl GroupEventView + ?Sized),
    class: &GroupEventClass,
    result: TangleModerationAuditResult,
) {
    let Some(entry) = TangleModerationAuditEntry::new(event, class, result) else {
        return;
    };
    tracing::info!(
        event = "group_moderation_audit",
        action_family = entry.action_family,
        result = entry.result,
        event_id = entry.event_id,
        actor_pubkey = entry.actor_pubkey,
        event_kind = entry.event_kind,
        target_count = entry.target_count,
        group_id = TANGLE_LOG_REDACTED,
        group_id_redacted = true,
        generated_state_rejection = entry.generated_state_rejection,
        "tangle group moderation audit"
    );
}

pub fn sanitize_error_message(config: &BaseRelayRuntimeConfig, message: impl AsRef<str>) -> String {
    TangleLogRedactor::from_runtime_config(config).redact(message)
}

fn moderation_audit_action_family(
    event: &(impl GroupEventView + ?Sized),
    class: &GroupEventClass,
) -> Option<&'static str> {
    match class {
        GroupEventClass::Moderation { kind, .. } => match kind.as_u32() {
            KIND_GROUP_CREATE_GROUP => Some("group_create"),
            KIND_GROUP_EDIT_METADATA => Some("metadata"),
            KIND_GROUP_DELETE_GROUP => Some("delete_group"),
            KIND_GROUP_DELETE_EVENT => Some("delete_event"),
            KIND_GROUP_PUT_USER => Some("put_user"),
            KIND_GROUP_REMOVE_USER => Some("remove_user"),
            _ => None,
        },
        GroupEventClass::Normal { .. } => match event.kind_u32() {
            KIND_GROUP_JOIN_REQUEST => Some("join"),
            KIND_GROUP_LEAVE_REQUEST => Some("leave"),
            _ => None,
        },
        GroupEventClass::RelayGeneratedSnapshot { kind, .. } => match kind.as_u32() {
            KIND_GROUP_METADATA => Some("metadata"),
            KIND_GROUP_ADMINS => Some("admins"),
            KIND_GROUP_MEMBERS => Some("members"),
            _ => None,
        },
        GroupEventClass::NonGroup => None,
    }
}

fn moderation_target_count(event: &(impl GroupEventView + ?Sized), action_family: &str) -> usize {
    let target_tag = match action_family {
        "put_user" | "remove_user" | "members" => Some("p"),
        "delete_event" => Some("e"),
        _ => None,
    };
    let Some(target_tag) = target_tag else {
        return 0;
    };
    let mut count = 0;
    if event
        .visit_tags(|tag| {
            if tag
                .indexed_pair()
                .is_some_and(|(name, _)| name == target_tag)
            {
                count += 1;
            }
            Ok(())
        })
        .is_err()
    {
        return 0;
    }
    count
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
        TANGLE_LOG_REDACTED, TangleLogRedactor, TangleModerationAuditEntry,
        TangleModerationAuditResult, TangleRuntimeLogSummary, log_group_moderation_audit,
        log_runtime_config_loaded, sanitize_error_message,
    };
    use crate::config::parse_base_relay_runtime_config_json;
    use crate::pocket_conversion::tangle_event_to_pocket;
    use std::{
        io,
        sync::{Arc, Mutex},
    };
    use tangle_groups::{
        GroupEventClass, GroupLimitsConfig, KIND_GROUP_ADMINS, KIND_GROUP_JOIN_REQUEST,
        KIND_GROUP_MEMBERS, KIND_GROUP_METADATA, classify_group_event,
    };
    use tangle_test_support::{
        FixtureKey, tangle_v2_address_group_tag, tangle_v2_delete_event_event,
        tangle_v2_delete_group_event, tangle_v2_event, tangle_v2_group_create_event,
        tangle_v2_group_event, tangle_v2_group_metadata_event, tangle_v2_group_tag,
        tangle_v2_join_event, tangle_v2_leave_event, tangle_v2_put_user_event,
        tangle_v2_remove_user_event, tangle_v2_tag,
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
        let raw = include_str!("../../../config/tangle.example.json");
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
        let raw = include_str!("../../../config/tangle.example.json");
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

    #[test]
    fn group_moderation_audit_entries_cover_required_action_families_and_target_counts() {
        let target = tangle_v2_group_event(FixtureKey::Member, "AuditFarm", 10, 1, "target")
            .expect("target");
        let cases = [
            (
                tangle_v2_group_create_event(FixtureKey::Owner, "AuditFarm", 11, &[])
                    .expect("create"),
                "group_create",
                0,
                false,
            ),
            (
                tangle_v2_group_metadata_event(
                    FixtureKey::Owner,
                    "AuditFarm",
                    "Audit Farm",
                    12,
                    &[],
                )
                .expect("metadata"),
                "metadata",
                0,
                false,
            ),
            (
                tangle_v2_put_user_event(FixtureKey::Owner, "AuditFarm", FixtureKey::Member, 13)
                    .expect("put"),
                "put_user",
                1,
                false,
            ),
            (
                tangle_v2_remove_user_event(FixtureKey::Owner, "AuditFarm", FixtureKey::Member, 14)
                    .expect("remove"),
                "remove_user",
                1,
                false,
            ),
            (
                tangle_v2_delete_event_event(FixtureKey::Owner, "AuditFarm", &target, 15)
                    .expect("delete event"),
                "delete_event",
                1,
                false,
            ),
            (
                tangle_v2_delete_group_event(FixtureKey::Owner, "AuditFarm", 16)
                    .expect("delete group"),
                "delete_group",
                0,
                false,
            ),
            (
                tangle_v2_join_event(FixtureKey::Member, "AuditFarm", 17).expect("join"),
                "join",
                0,
                false,
            ),
            (
                tangle_v2_leave_event(FixtureKey::Member, "AuditFarm", 18).expect("leave"),
                "leave",
                0,
                false,
            ),
            (
                tangle_v2_event(
                    FixtureKey::Owner,
                    19,
                    KIND_GROUP_METADATA.into(),
                    vec![tangle_v2_address_group_tag("AuditFarm").expect("d")],
                    "",
                )
                .expect("generated metadata"),
                "metadata",
                0,
                true,
            ),
            (
                tangle_v2_event(
                    FixtureKey::Owner,
                    20,
                    KIND_GROUP_ADMINS.into(),
                    vec![tangle_v2_address_group_tag("AuditFarm").expect("d")],
                    "",
                )
                .expect("generated admins"),
                "admins",
                0,
                true,
            ),
            (
                tangle_v2_event(
                    FixtureKey::Owner,
                    21,
                    KIND_GROUP_MEMBERS.into(),
                    vec![
                        tangle_v2_address_group_tag("AuditFarm").expect("d"),
                        tangle_v2_tag("p", &[FixtureKey::Member.public_key().as_str()]).expect("p"),
                    ],
                    "",
                )
                .expect("generated members"),
                "members",
                1,
                true,
            ),
        ];

        for (event, action_family, target_count, generated_state_rejection) in cases {
            let pocket = tangle_event_to_pocket(&event).expect("pocket");
            let class = classify_group_event(&pocket, GroupLimitsConfig::default()).expect("class");
            let result = if matches!(class, GroupEventClass::RelayGeneratedSnapshot { .. }) {
                TangleModerationAuditResult::Rejected
            } else {
                TangleModerationAuditResult::Accepted
            };
            let entry =
                TangleModerationAuditEntry::new(&pocket, &class, result).expect("audit entry");

            assert_eq!(entry.action_family, action_family);
            assert_eq!(entry.target_count, target_count);
            assert_eq!(entry.generated_state_rejection, generated_state_rejection);
            assert_eq!(entry.result, result.as_str());
        }
    }

    #[test]
    fn group_moderation_audit_log_redacts_group_content_invite_and_secret_values() {
        let secret = "7".repeat(64);
        let event = tangle_v2_event(
            FixtureKey::Member,
            31,
            KIND_GROUP_JOIN_REQUEST.into(),
            vec![
                tangle_v2_group_tag("SecretFarm").expect("h"),
                tangle_v2_tag("code", &["invite-super-secret"]).expect("code"),
            ],
            "secret-content",
        )
        .expect("join");
        let pocket = tangle_event_to_pocket(&event).expect("pocket");
        let class = classify_group_event(&pocket, GroupLimitsConfig::default()).expect("class");
        let writer = CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(writer.clone())
            .with_max_level(tracing::Level::INFO)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            log_group_moderation_audit(&pocket, &class, TangleModerationAuditResult::Rejected);
        });

        let output = writer.output();
        assert!(output.contains(r#""event":"group_moderation_audit""#));
        assert!(output.contains(r#""action_family":"join""#));
        assert!(output.contains(r#""result":"rejected""#));
        assert!(output.contains(r#""event_id":"#));
        assert!(output.contains(event.id().as_str()));
        assert!(output.contains(r#""actor_pubkey":"#));
        assert!(output.contains(event.unsigned().pubkey().as_str()));
        assert!(output.contains(r#""event_kind":9021"#));
        assert!(output.contains(r#""target_count":0"#));
        assert!(output.contains(r#""group_id":"<redacted>""#));
        assert!(output.contains(r#""group_id_redacted":true"#));
        assert!(output.contains(r#""generated_state_rejection":false"#));
        assert!(!output.contains("SecretFarm"));
        assert!(!output.contains("secret-content"));
        assert!(!output.contains("invite-super-secret"));
        assert!(!output.contains(&secret));
    }

    #[test]
    fn group_moderation_audit_ignores_non_requested_group_event_kinds() {
        let event =
            tangle_v2_group_event(FixtureKey::Member, "AuditFarm", 41, 1, "normal").expect("event");
        let pocket = tangle_event_to_pocket(&event).expect("pocket");
        let class = classify_group_event(&pocket, GroupLimitsConfig::default()).expect("class");

        assert!(
            TangleModerationAuditEntry::new(&pocket, &class, TangleModerationAuditResult::Accepted)
                .is_none()
        );
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
