#![forbid(unsafe_code)]

use crate::errors::BaseRelayError;
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};
use tangle_groups::GroupId;
use tangle_protocol::{Kind, PublicKeyHex, UnixTimestamp};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TangleRateLimitKey {
    Ip(IpAddr),
    Pubkey(PublicKeyHex),
    Group(GroupId),
    Kind(Kind),
    AuthFailure {
        ip: Option<IpAddr>,
        pubkey: Option<PublicKeyHex>,
    },
    JoinFlow {
        group_id: GroupId,
        pubkey: PublicKeyHex,
    },
}

impl TangleRateLimitKey {
    pub fn ip(ip: IpAddr) -> Self {
        Self::Ip(ip)
    }

    pub fn pubkey(pubkey: PublicKeyHex) -> Self {
        Self::Pubkey(pubkey)
    }

    pub fn group(group_id: GroupId) -> Self {
        Self::Group(group_id)
    }

    pub fn kind(kind: Kind) -> Self {
        Self::Kind(kind)
    }

    pub fn auth_failure(ip: Option<IpAddr>, pubkey: Option<PublicKeyHex>) -> Self {
        Self::AuthFailure { ip, pubkey }
    }

    pub fn join_flow(group_id: GroupId, pubkey: PublicKeyHex) -> Self {
        Self::JoinFlow { group_id, pubkey }
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
        TangleRateLimitDecision, TangleRateLimitKey, TangleRateLimitRule, TangleRateLimiter,
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
            TangleRateLimitKey::ip(ip),
            TangleRateLimitKey::pubkey(pubkey.clone()),
            TangleRateLimitKey::group(group_id.clone()),
            TangleRateLimitKey::kind(kind),
            TangleRateLimitKey::auth_failure(Some(ip), Some(pubkey.clone())),
            TangleRateLimitKey::join_flow(group_id, pubkey),
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
        assert_eq!(limiter.tracked_key_count(), 6);
    }

    #[test]
    fn rate_limiter_counts_per_key_and_resets_after_window() {
        let limiter = TangleRateLimiter::new();
        let rule = TangleRateLimitRule::new(10, 2).expect("rule");
        let key = TangleRateLimitKey::ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

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
            TangleRateLimitKey::ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            rule,
            UnixTimestamp::from(1),
        );
        limiter.record(
            TangleRateLimitKey::ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            rule,
            UnixTimestamp::from(5),
        );

        limiter.retain_active(UnixTimestamp::from(6));

        assert_eq!(limiter.tracked_key_count(), 1);
    }
}
