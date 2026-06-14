#![forbid(unsafe_code)]

use crate::errors::BaseRelayError;
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};
use tangle_groups::GroupId;
use tangle_protocol::{Kind, PublicKeyHex, UnixTimestamp};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TangleRateLimitScope {
    Auth,
    Event,
    GroupWrite,
    Req,
    Count,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TangleRateLimitKey {
    Ip {
        scope: TangleRateLimitScope,
        ip: IpAddr,
    },
    Pubkey {
        scope: TangleRateLimitScope,
        pubkey: PublicKeyHex,
    },
    Group {
        scope: TangleRateLimitScope,
        group_id: GroupId,
    },
    Kind {
        scope: TangleRateLimitScope,
        kind: Kind,
    },
    AuthFailure {
        ip: Option<IpAddr>,
        pubkey: Option<PublicKeyHex>,
    },
    JoinFlowIp {
        group_id: GroupId,
        ip: IpAddr,
    },
    JoinFlow {
        group_id: GroupId,
        pubkey: PublicKeyHex,
    },
    Connection {
        scope: TangleRateLimitScope,
        connection_id: u64,
    },
    QueryClass {
        scope: TangleRateLimitScope,
        class: TangleRateLimitQueryClass,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TangleRateLimitQueryClass {
    Broad,
}

impl TangleRateLimitKey {
    pub fn ip(scope: TangleRateLimitScope, ip: IpAddr) -> Self {
        Self::Ip { scope, ip }
    }

    pub fn pubkey(scope: TangleRateLimitScope, pubkey: PublicKeyHex) -> Self {
        Self::Pubkey { scope, pubkey }
    }

    pub fn group(scope: TangleRateLimitScope, group_id: GroupId) -> Self {
        Self::Group { scope, group_id }
    }

    pub fn kind(scope: TangleRateLimitScope, kind: Kind) -> Self {
        Self::Kind { scope, kind }
    }

    pub fn auth_failure(ip: Option<IpAddr>, pubkey: Option<PublicKeyHex>) -> Self {
        Self::AuthFailure { ip, pubkey }
    }

    pub fn join_flow(group_id: GroupId, pubkey: PublicKeyHex) -> Self {
        Self::JoinFlow { group_id, pubkey }
    }

    pub fn join_flow_ip(group_id: GroupId, ip: IpAddr) -> Self {
        Self::JoinFlowIp { group_id, ip }
    }

    pub fn connection(scope: TangleRateLimitScope, connection_id: u64) -> Self {
        Self::Connection {
            scope,
            connection_id,
        }
    }

    pub fn query_class(scope: TangleRateLimitScope, class: TangleRateLimitQueryClass) -> Self {
        Self::QueryClass { scope, class }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TangleRateLimitConfig {
    auth: TangleAuthRateLimitConfig,
    event: TangleEventRateLimitConfig,
    group: TangleGroupRateLimitConfig,
    req: TangleQueryRateLimitConfig,
    count: TangleQueryRateLimitConfig,
}

impl TangleRateLimitConfig {
    pub fn new(
        auth: TangleAuthRateLimitConfig,
        event: TangleEventRateLimitConfig,
        group: TangleGroupRateLimitConfig,
        req: TangleQueryRateLimitConfig,
        count: TangleQueryRateLimitConfig,
    ) -> Self {
        Self {
            auth,
            event,
            group,
            req,
            count,
        }
    }

    pub fn auth(self) -> TangleAuthRateLimitConfig {
        self.auth
    }

    pub fn event(self) -> TangleEventRateLimitConfig {
        self.event
    }

    pub fn group(self) -> TangleGroupRateLimitConfig {
        self.group
    }

    pub fn req(self) -> TangleQueryRateLimitConfig {
        self.req
    }

    pub fn count(self) -> TangleQueryRateLimitConfig {
        self.count
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TangleAuthRateLimitConfig {
    per_ip: TangleRateLimitRule,
    per_pubkey: TangleRateLimitRule,
    failures: TangleRateLimitRule,
    failures_per_ip: TangleRateLimitRule,
}

impl TangleAuthRateLimitConfig {
    pub fn new(
        per_ip: TangleRateLimitRule,
        per_pubkey: TangleRateLimitRule,
        failures: TangleRateLimitRule,
        failures_per_ip: TangleRateLimitRule,
    ) -> Self {
        Self {
            per_ip,
            per_pubkey,
            failures,
            failures_per_ip,
        }
    }

    pub fn per_ip(self) -> TangleRateLimitRule {
        self.per_ip
    }

    pub fn per_pubkey(self) -> TangleRateLimitRule {
        self.per_pubkey
    }

    pub fn failures(self) -> TangleRateLimitRule {
        self.failures
    }

    pub fn failures_per_ip(self) -> TangleRateLimitRule {
        self.failures_per_ip
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TangleEventRateLimitConfig {
    per_ip: TangleRateLimitRule,
    per_pubkey: TangleRateLimitRule,
    per_kind: TangleRateLimitRule,
}

impl TangleEventRateLimitConfig {
    pub fn new(
        per_ip: TangleRateLimitRule,
        per_pubkey: TangleRateLimitRule,
        per_kind: TangleRateLimitRule,
    ) -> Self {
        Self {
            per_ip,
            per_pubkey,
            per_kind,
        }
    }

    pub fn per_ip(self) -> TangleRateLimitRule {
        self.per_ip
    }

    pub fn per_pubkey(self) -> TangleRateLimitRule {
        self.per_pubkey
    }

    pub fn per_kind(self) -> TangleRateLimitRule {
        self.per_kind
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TangleGroupRateLimitConfig {
    write_per_ip: TangleRateLimitRule,
    write_per_pubkey: TangleRateLimitRule,
    write_per_group: TangleRateLimitRule,
    write_per_kind: TangleRateLimitRule,
    join_flow: TangleRateLimitRule,
    join_flow_per_ip: TangleRateLimitRule,
}

impl TangleGroupRateLimitConfig {
    pub fn new(
        write_per_ip: TangleRateLimitRule,
        write_per_pubkey: TangleRateLimitRule,
        write_per_group: TangleRateLimitRule,
        write_per_kind: TangleRateLimitRule,
        join_flow: TangleRateLimitRule,
        join_flow_per_ip: TangleRateLimitRule,
    ) -> Self {
        Self {
            write_per_ip,
            write_per_pubkey,
            write_per_group,
            write_per_kind,
            join_flow,
            join_flow_per_ip,
        }
    }

    pub fn write_per_ip(self) -> TangleRateLimitRule {
        self.write_per_ip
    }

    pub fn write_per_pubkey(self) -> TangleRateLimitRule {
        self.write_per_pubkey
    }

    pub fn write_per_group(self) -> TangleRateLimitRule {
        self.write_per_group
    }

    pub fn write_per_kind(self) -> TangleRateLimitRule {
        self.write_per_kind
    }

    pub fn join_flow(self) -> TangleRateLimitRule {
        self.join_flow
    }

    pub fn join_flow_per_ip(self) -> TangleRateLimitRule {
        self.join_flow_per_ip
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TangleQueryRateLimitConfig {
    per_ip: TangleRateLimitRule,
    per_connection: TangleRateLimitRule,
    per_pubkey: TangleRateLimitRule,
    per_group: TangleRateLimitRule,
    per_kind: TangleRateLimitRule,
    broad: TangleRateLimitRule,
}

impl TangleQueryRateLimitConfig {
    pub fn new(
        per_ip: TangleRateLimitRule,
        per_connection: TangleRateLimitRule,
        per_pubkey: TangleRateLimitRule,
        per_group: TangleRateLimitRule,
        per_kind: TangleRateLimitRule,
        broad: TangleRateLimitRule,
    ) -> Self {
        Self {
            per_ip,
            per_connection,
            per_pubkey,
            per_group,
            per_kind,
            broad,
        }
    }

    pub fn per_ip(self) -> TangleRateLimitRule {
        self.per_ip
    }

    pub fn per_connection(self) -> TangleRateLimitRule {
        self.per_connection
    }

    pub fn per_pubkey(self) -> TangleRateLimitRule {
        self.per_pubkey
    }

    pub fn per_group(self) -> TangleRateLimitRule {
        self.per_group
    }

    pub fn per_kind(self) -> TangleRateLimitRule {
        self.per_kind
    }

    pub fn broad(self) -> TangleRateLimitRule {
        self.broad
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TangleRateLimitRule {
    window_seconds: u64,
    max_hits: u64,
}

impl TangleRateLimitRule {
    pub fn new(window_seconds: u64, max_hits: u64) -> Result<Self, BaseRelayError> {
        if window_seconds == 0 {
            return Err(BaseRelayError::invalid(
                "rate limit window seconds must be greater than zero",
            ));
        }
        if max_hits == 0 {
            return Err(BaseRelayError::invalid(
                "rate limit max hits must be greater than zero",
            ));
        }
        Ok(Self {
            window_seconds,
            max_hits,
        })
    }

    pub fn window_seconds(self) -> u64 {
        self.window_seconds
    }

    pub fn max_hits(self) -> u64 {
        self.max_hits
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TangleRateLimitDecision {
    Allowed {
        remaining: u64,
        reset_at: UnixTimestamp,
    },
    Rejected {
        reset_at: UnixTimestamp,
    },
}

impl TangleRateLimitDecision {
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    pub fn reset_at(self) -> UnixTimestamp {
        match self {
            Self::Allowed { reset_at, .. } | Self::Rejected { reset_at } => reset_at,
        }
    }

    pub fn remaining(self) -> u64 {
        match self {
            Self::Allowed { remaining, .. } => remaining,
            Self::Rejected { .. } => 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TangleRateLimiter {
    entries: Arc<Mutex<BTreeMap<TangleRateLimitKey, TangleRateLimitEntry>>>,
}

impl TangleRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(
        &self,
        key: TangleRateLimitKey,
        rule: TangleRateLimitRule,
        now: UnixTimestamp,
    ) -> TangleRateLimitDecision {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let entry = entries
            .entry(key)
            .and_modify(|entry| entry.reset_if_expired(rule, now))
            .or_insert_with(|| TangleRateLimitEntry::new(rule, now));
        if entry.hits >= rule.max_hits() {
            return TangleRateLimitDecision::Rejected {
                reset_at: entry.reset_at,
            };
        }
        entry.hits = entry.hits.saturating_add(1);
        TangleRateLimitDecision::Allowed {
            remaining: rule.max_hits().saturating_sub(entry.hits),
            reset_at: entry.reset_at,
        }
    }

    pub fn hits(&self, key: &TangleRateLimitKey) -> u64 {
        self.entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(key)
            .map(|entry| entry.hits)
            .unwrap_or(0)
    }

    pub fn retain_active(&self, now: UnixTimestamp) {
        self.entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .retain(|_, entry| now.as_u64() < entry.reset_at.as_u64());
    }

    pub fn tracked_key_count(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TangleRateLimitEntry {
    reset_at: UnixTimestamp,
    hits: u64,
}

impl TangleRateLimitEntry {
    fn new(rule: TangleRateLimitRule, now: UnixTimestamp) -> Self {
        Self {
            reset_at: reset_at(rule, now),
            hits: 0,
        }
    }

    fn reset_if_expired(&mut self, rule: TangleRateLimitRule, now: UnixTimestamp) {
        if now.as_u64() >= self.reset_at.as_u64() {
            *self = Self::new(rule, now);
        }
    }
}

fn reset_at(rule: TangleRateLimitRule, now: UnixTimestamp) -> UnixTimestamp {
    UnixTimestamp::from(now.as_u64().saturating_add(rule.window_seconds()))
}

#[cfg(test)]
mod tests {
    use super::{
        TangleAuthRateLimitConfig, TangleEventRateLimitConfig, TangleGroupRateLimitConfig,
        TangleQueryRateLimitConfig, TangleRateLimitConfig, TangleRateLimitDecision,
        TangleRateLimitKey, TangleRateLimitQueryClass, TangleRateLimitRule, TangleRateLimitScope,
        TangleRateLimiter,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use tangle_groups::GroupId;
    use tangle_protocol::{Kind, PublicKeyHex, UnixTimestamp};

    #[test]
    fn rate_limit_rules_reject_zero_values() {
        assert_eq!(
            TangleRateLimitRule::new(0, 1)
                .expect_err("window")
                .prefixed_message(),
            "invalid: rate limit window seconds must be greater than zero"
        );
        assert_eq!(
            TangleRateLimitRule::new(1, 0)
                .expect_err("max hits")
                .prefixed_message(),
            "invalid: rate limit max hits must be greater than zero"
        );
    }

    #[test]
    fn rate_limiter_tracks_required_key_dimensions() {
        let limiter = TangleRateLimiter::new();
        let rule = TangleRateLimitRule::new(60, 1).expect("rule");
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let pubkey = PublicKeyHex::new(&"1".repeat(64)).expect("pubkey");
        let group_id = GroupId::new("farm").expect("group");
        let kind = Kind::new(1).expect("kind");
        let keys = [
            TangleRateLimitKey::ip(TangleRateLimitScope::Event, ip),
            TangleRateLimitKey::pubkey(TangleRateLimitScope::Event, pubkey.clone()),
            TangleRateLimitKey::group(TangleRateLimitScope::GroupWrite, group_id.clone()),
            TangleRateLimitKey::kind(TangleRateLimitScope::Event, kind),
            TangleRateLimitKey::auth_failure(Some(ip), Some(pubkey.clone())),
            TangleRateLimitKey::join_flow_ip(group_id.clone(), ip),
            TangleRateLimitKey::join_flow(group_id, pubkey),
            TangleRateLimitKey::connection(TangleRateLimitScope::Req, 42),
            TangleRateLimitKey::query_class(
                TangleRateLimitScope::Count,
                TangleRateLimitQueryClass::Broad,
            ),
        ];

        for key in keys {
            assert!(
                limiter
                    .record(key.clone(), rule, UnixTimestamp::from(1))
                    .is_allowed()
            );
            assert_eq!(
                limiter.record(key.clone(), rule, UnixTimestamp::from(2)),
                TangleRateLimitDecision::Rejected {
                    reset_at: UnixTimestamp::from(61)
                }
            );
            assert_eq!(limiter.hits(&key), 1);
        }
        assert_eq!(limiter.tracked_key_count(), 9);
    }

    #[test]
    fn rate_limiter_counts_per_key_and_resets_after_window() {
        let limiter = TangleRateLimiter::new();
        let rule = TangleRateLimitRule::new(10, 2).expect("rule");
        let key = TangleRateLimitKey::ip(
            TangleRateLimitScope::Event,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        );

        let first = limiter.record(key.clone(), rule, UnixTimestamp::from(100));
        let second = limiter.record(key.clone(), rule, UnixTimestamp::from(101));
        let third = limiter.record(key.clone(), rule, UnixTimestamp::from(102));
        let after_window = limiter.record(key, rule, UnixTimestamp::from(110));

        assert_eq!(
            first,
            TangleRateLimitDecision::Allowed {
                remaining: 1,
                reset_at: UnixTimestamp::from(110)
            }
        );
        assert_eq!(
            second,
            TangleRateLimitDecision::Allowed {
                remaining: 0,
                reset_at: UnixTimestamp::from(110)
            }
        );
        assert_eq!(
            third,
            TangleRateLimitDecision::Rejected {
                reset_at: UnixTimestamp::from(110)
            }
        );
        assert_eq!(
            after_window,
            TangleRateLimitDecision::Allowed {
                remaining: 1,
                reset_at: UnixTimestamp::from(120)
            }
        );
    }

    #[test]
    fn rate_limiter_drops_expired_key_state() {
        let limiter = TangleRateLimiter::new();
        let rule = TangleRateLimitRule::new(5, 1).expect("rule");
        limiter.record(
            TangleRateLimitKey::ip(
                TangleRateLimitScope::Event,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            ),
            rule,
            UnixTimestamp::from(1),
        );
        limiter.record(
            TangleRateLimitKey::ip(
                TangleRateLimitScope::Event,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            ),
            rule,
            UnixTimestamp::from(5),
        );

        limiter.retain_active(UnixTimestamp::from(6));

        assert_eq!(limiter.tracked_key_count(), 1);
    }

    #[test]
    fn scoped_pubkey_keys_do_not_share_buckets() {
        let limiter = TangleRateLimiter::new();
        let rule = TangleRateLimitRule::new(60, 1).expect("rule");
        let pubkey = PublicKeyHex::new(&"1".repeat(64)).expect("pubkey");
        let auth_key = TangleRateLimitKey::pubkey(TangleRateLimitScope::Auth, pubkey.clone());
        let event_key = TangleRateLimitKey::pubkey(TangleRateLimitScope::Event, pubkey);

        assert!(
            limiter
                .record(auth_key.clone(), rule, UnixTimestamp::from(1))
                .is_allowed()
        );
        assert!(
            limiter
                .record(event_key.clone(), rule, UnixTimestamp::from(1))
                .is_allowed()
        );
        assert!(
            !limiter
                .record(auth_key, rule, UnixTimestamp::from(2))
                .is_allowed()
        );
        assert!(
            !limiter
                .record(event_key, rule, UnixTimestamp::from(2))
                .is_allowed()
        );
    }

    #[test]
    fn rate_limit_config_exposes_auth_and_event_rules() {
        let auth_pubkey = TangleRateLimitRule::new(60, 2).expect("auth pubkey");
        let auth_failures = TangleRateLimitRule::new(300, 3).expect("auth failures");
        let auth_ip = TangleRateLimitRule::new(60, 4).expect("auth ip");
        let auth_failures_ip = TangleRateLimitRule::new(300, 5).expect("auth failures ip");
        let event_ip = TangleRateLimitRule::new(60, 6).expect("event ip");
        let event_pubkey = TangleRateLimitRule::new(60, 7).expect("event pubkey");
        let event_kind = TangleRateLimitRule::new(60, 8).expect("event kind");
        let group_ip = TangleRateLimitRule::new(60, 9).expect("group ip");
        let group_pubkey = TangleRateLimitRule::new(60, 10).expect("group pubkey");
        let group_write = TangleRateLimitRule::new(60, 11).expect("group write");
        let group_kind = TangleRateLimitRule::new(60, 12).expect("group kind");
        let group_join = TangleRateLimitRule::new(300, 13).expect("group join");
        let group_join_ip = TangleRateLimitRule::new(300, 14).expect("group join ip");
        let req_ip = TangleRateLimitRule::new(60, 15).expect("req ip");
        let req_connection = TangleRateLimitRule::new(60, 16).expect("req connection");
        let req_pubkey = TangleRateLimitRule::new(60, 17).expect("req pubkey");
        let req_group = TangleRateLimitRule::new(60, 18).expect("req group");
        let req_kind = TangleRateLimitRule::new(60, 19).expect("req kind");
        let req_broad = TangleRateLimitRule::new(60, 20).expect("req broad");
        let count_ip = TangleRateLimitRule::new(60, 21).expect("count ip");
        let count_connection = TangleRateLimitRule::new(60, 22).expect("count connection");
        let count_pubkey = TangleRateLimitRule::new(60, 23).expect("count pubkey");
        let count_group = TangleRateLimitRule::new(60, 24).expect("count group");
        let count_kind = TangleRateLimitRule::new(60, 25).expect("count kind");
        let count_broad = TangleRateLimitRule::new(60, 26).expect("count broad");
        let config = TangleRateLimitConfig::new(
            TangleAuthRateLimitConfig::new(auth_ip, auth_pubkey, auth_failures, auth_failures_ip),
            TangleEventRateLimitConfig::new(event_ip, event_pubkey, event_kind),
            TangleGroupRateLimitConfig::new(
                group_ip,
                group_pubkey,
                group_write,
                group_kind,
                group_join,
                group_join_ip,
            ),
            TangleQueryRateLimitConfig::new(
                req_ip,
                req_connection,
                req_pubkey,
                req_group,
                req_kind,
                req_broad,
            ),
            TangleQueryRateLimitConfig::new(
                count_ip,
                count_connection,
                count_pubkey,
                count_group,
                count_kind,
                count_broad,
            ),
        );

        assert_eq!(config.auth().per_ip(), auth_ip);
        assert_eq!(config.auth().per_pubkey(), auth_pubkey);
        assert_eq!(config.auth().failures(), auth_failures);
        assert_eq!(config.auth().failures_per_ip(), auth_failures_ip);
        assert_eq!(config.event().per_ip(), event_ip);
        assert_eq!(config.event().per_pubkey(), event_pubkey);
        assert_eq!(config.event().per_kind(), event_kind);
        assert_eq!(config.group().write_per_ip(), group_ip);
        assert_eq!(config.group().write_per_pubkey(), group_pubkey);
        assert_eq!(config.group().write_per_group(), group_write);
        assert_eq!(config.group().write_per_kind(), group_kind);
        assert_eq!(config.group().join_flow(), group_join);
        assert_eq!(config.group().join_flow_per_ip(), group_join_ip);
        assert_eq!(config.req().per_ip(), req_ip);
        assert_eq!(config.req().per_connection(), req_connection);
        assert_eq!(config.req().per_pubkey(), req_pubkey);
        assert_eq!(config.req().per_group(), req_group);
        assert_eq!(config.req().per_kind(), req_kind);
        assert_eq!(config.req().broad(), req_broad);
        assert_eq!(config.count().per_ip(), count_ip);
        assert_eq!(config.count().per_connection(), count_connection);
        assert_eq!(config.count().per_pubkey(), count_pubkey);
        assert_eq!(config.count().per_group(), count_group);
        assert_eq!(config.count().per_kind(), count_kind);
        assert_eq!(config.count().broad(), count_broad);
    }
}
