#![forbid(unsafe_code)]

use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tangle_groups::{KIND_GROUP_ADMINS, KIND_GROUP_MEMBERS, KIND_GROUP_METADATA, MemberStatus};
use tangle_protocol::{
    Event, Filter, RelayMessage, SubscriptionId, UnixTimestamp, event_to_value, filter_from_value,
    filter_to_value,
};
use tangle_runtime::{
    config::{BaseRelayRuntimeConfig, parse_base_relay_runtime_config_json},
    relay::{
        auth::BaseAuthState,
        core::{BaseRelay, BaseRelayLimitSettings, BaseRelayLimits},
    },
    runtime::{TangleRuntime, TangleRuntimeHandle},
};
use tangle_store_pocket::{
    PocketOwnedFilter, PocketQueryConfig, PocketStoreConfig, PocketSyncPolicy,
    parse_pocket_event_json, parse_pocket_filter_json,
};
use tangle_test_support::{
    FixtureKey, TANGLE_V2_RELAY_URL, tangle_v2_auth_event, tangle_v2_event, tangle_v2_group_config,
    tangle_v2_group_create_event, tangle_v2_group_event, tangle_v2_put_user_event, tangle_v2_tag,
};

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

pub const SCENARIO_POCKET_QUERY_VISIBLE_EVENTS: &str = "pocket_query_visible_events";
pub const SCENARIO_GROUP_READ_GATE_OVERHEAD: &str = "group_read_gate_overhead";
pub const SCENARIO_COUNT_RESOURCE_CONTROLS: &str = "count_resource_controls";
pub const SCENARIO_PROJECTION_REBUILD: &str = "projection_rebuild";
pub const SCENARIO_OUTBOX_REPLAY: &str = "outbox_replay";
pub const SCENARIO_BROADCAST_LAG: &str = "broadcast_lag";
pub const SCENARIO_MEMORY_PROFILE: &str = "memory_profile";
pub const POCKET_SOURCE_REPOSITORY: &str = "https://github.com/triesap/pocket";
pub const POCKET_SOURCE_REVISION: &str = "329334f20948c796c6016b673b92551ac4855ad7";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BenchDatasetConfig {
    pub group_count: usize,
    pub public_events_per_group: usize,
    pub private_events_per_group: usize,
    pub public_note_count: usize,
    pub member_count: usize,
}

impl BenchDatasetConfig {
    pub fn new(
        group_count: usize,
        public_events_per_group: usize,
        private_events_per_group: usize,
        public_note_count: usize,
        member_count: usize,
    ) -> Self {
        Self {
            group_count,
            public_events_per_group,
            private_events_per_group,
            public_note_count,
            member_count,
        }
    }

    pub fn smoke() -> Self {
        Self::new(6, 4, 3, 6, 3)
    }

    pub fn medium() -> Self {
        Self::new(24, 8, 6, 24, 5)
    }

    pub fn large_smoke() -> Self {
        Self::new(120, 24, 16, 120, 12)
    }

    pub fn proof_10m() -> Self {
        Self::new(30_000, 100, 100, 6_670_000, 10)
    }

    pub fn proof_large_group() -> Self {
        Self::new(3, 50, 50, 10_000, 100_000)
    }

    pub fn proof_join_storm() -> Self {
        Self::new(25_000, 1, 1, 25_000, 40)
    }

    pub fn proof_slow_client() -> Self {
        Self::new(50_000, 2, 1, 50_000, 2)
    }

    pub fn validate(self) -> Result<Self, String> {
        if self.group_count < 3 {
            return Err("group-count must be at least 3".to_owned());
        }
        if self.public_events_per_group == 0 {
            return Err("public-events-per-group must be greater than zero".to_owned());
        }
        if self.private_events_per_group == 0 {
            return Err("private-events-per-group must be greater than zero".to_owned());
        }
        if self.member_count == 0 {
            return Err("member-count must be greater than zero".to_owned());
        }
        Ok(self)
    }

    pub fn estimated_source_event_count(self) -> u64 {
        let public_groups = self.group_count.div_ceil(3);
        let private_and_hidden_groups = self.group_count - public_groups;
        let total = self.group_count
            + self.group_count * self.member_count
            + public_groups * self.public_events_per_group
            + private_and_hidden_groups * self.private_events_per_group
            + self.public_note_count;
        total.try_into().expect("estimated event count fits in u64")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchmarkProfileName {
    Smoke,
    Medium,
    LargeSmoke,
    Proof10m,
    ProofLargeGroup,
    ProofJoinStorm,
    ProofSlowClient,
}

impl BenchmarkProfileName {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "smoke" => Ok(Self::Smoke),
            "medium" => Ok(Self::Medium),
            "large-smoke" => Ok(Self::LargeSmoke),
            "proof-10m" => Ok(Self::Proof10m),
            "proof-large-group" => Ok(Self::ProofLargeGroup),
            "proof-join-storm" => Ok(Self::ProofJoinStorm),
            "proof-slow-client" => Ok(Self::ProofSlowClient),
            _ => Err(format!(
                "unknown benchmark profile `{value}`; expected smoke, medium, large-smoke, proof-10m, proof-large-group, proof-join-storm, or proof-slow-client"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Medium => "medium",
            Self::LargeSmoke => "large-smoke",
            Self::Proof10m => "proof-10m",
            Self::ProofLargeGroup => "proof-large-group",
            Self::ProofJoinStorm => "proof-join-storm",
            Self::ProofSlowClient => "proof-slow-client",
        }
    }

    pub fn all() -> [Self; 7] {
        [
            Self::Smoke,
            Self::Medium,
            Self::LargeSmoke,
            Self::Proof10m,
            Self::ProofLargeGroup,
            Self::ProofJoinStorm,
            Self::ProofSlowClient,
        ]
    }

    pub fn is_proof(self) -> bool {
        matches!(
            self,
            Self::Proof10m | Self::ProofLargeGroup | Self::ProofJoinStorm | Self::ProofSlowClient
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchmarkProfile {
    name: BenchmarkProfileName,
    dataset_config: BenchDatasetConfig,
    thresholds: BenchmarkThresholds,
    threshold_source: String,
    target_hardware_evidence: Option<String>,
}

impl BenchmarkProfile {
    pub fn from_name(name: BenchmarkProfileName) -> Self {
        match name {
            BenchmarkProfileName::Smoke => Self::smoke(),
            BenchmarkProfileName::Medium => Self::medium(),
            BenchmarkProfileName::LargeSmoke => Self::large_smoke(),
            BenchmarkProfileName::Proof10m => Self::proof_10m(),
            BenchmarkProfileName::ProofLargeGroup => Self::proof_large_group(),
            BenchmarkProfileName::ProofJoinStorm => Self::proof_join_storm(),
            BenchmarkProfileName::ProofSlowClient => Self::proof_slow_client(),
        }
    }

    pub fn smoke() -> Self {
        Self::new(
            BenchmarkProfileName::Smoke,
            BenchDatasetConfig::smoke(),
            BenchmarkThresholds::smoke(),
        )
    }

    pub fn medium() -> Self {
        Self::new(
            BenchmarkProfileName::Medium,
            BenchDatasetConfig::medium(),
            BenchmarkThresholds::medium(),
        )
    }

    pub fn large_smoke() -> Self {
        Self::new(
            BenchmarkProfileName::LargeSmoke,
            BenchDatasetConfig::large_smoke(),
            BenchmarkThresholds::large_smoke(),
        )
    }

    pub fn proof_10m() -> Self {
        Self::new(
            BenchmarkProfileName::Proof10m,
            BenchDatasetConfig::proof_10m(),
            BenchmarkThresholds::proof_10m(),
        )
    }

    pub fn proof_large_group() -> Self {
        Self::new(
            BenchmarkProfileName::ProofLargeGroup,
            BenchDatasetConfig::proof_large_group(),
            BenchmarkThresholds::proof_large_group(),
        )
    }

    pub fn proof_join_storm() -> Self {
        Self::new(
            BenchmarkProfileName::ProofJoinStorm,
            BenchDatasetConfig::proof_join_storm(),
            BenchmarkThresholds::proof_join_storm(),
        )
    }

    pub fn proof_slow_client() -> Self {
        Self::new(
            BenchmarkProfileName::ProofSlowClient,
            BenchDatasetConfig::proof_slow_client(),
            BenchmarkThresholds::proof_slow_client(),
        )
    }

    fn new(
        name: BenchmarkProfileName,
        dataset_config: BenchDatasetConfig,
        thresholds: BenchmarkThresholds,
    ) -> Self {
        Self {
            name,
            dataset_config,
            thresholds,
            threshold_source: format!("builtin:{}", name.as_str()),
            target_hardware_evidence: None,
        }
    }

    pub fn name(&self) -> BenchmarkProfileName {
        self.name
    }

    pub fn dataset_config(&self) -> BenchDatasetConfig {
        self.dataset_config
    }

    pub fn thresholds(&self) -> BenchmarkThresholds {
        self.thresholds
    }

    pub fn threshold_source(&self) -> &str {
        &self.threshold_source
    }

    pub fn target_hardware_evidence(&self) -> Option<&str> {
        self.target_hardware_evidence.as_deref()
    }

    pub fn requires_target_hardware_evidence(&self) -> bool {
        self.name.is_proof()
    }

    pub fn validate_for_run(&self) -> Result<(), String> {
        if self.requires_target_hardware_evidence() && self.target_hardware_evidence.is_none() {
            return Err(format!(
                "target hardware evidence is required for `{}` benchmark profile",
                self.name.as_str()
            ));
        }
        Ok(())
    }

    pub fn with_dataset_config(mut self, config: BenchDatasetConfig) -> Result<Self, String> {
        self.dataset_config = config.validate()?;
        Ok(self)
    }

    pub fn with_thresholds(
        mut self,
        thresholds: BenchmarkThresholds,
        source: impl Into<String>,
    ) -> Result<Self, String> {
        let source = source.into();
        if source.is_empty() {
            return Err("benchmark threshold source must not be empty".to_owned());
        }
        self.thresholds = thresholds;
        self.threshold_source = source;
        Ok(self)
    }

    pub fn with_target_hardware_evidence(
        mut self,
        evidence: impl Into<String>,
    ) -> Result<Self, String> {
        let evidence = evidence.into();
        if evidence.is_empty() {
            return Err("target hardware evidence must not be empty".to_owned());
        }
        self.target_hardware_evidence = Some(evidence);
        Ok(self)
    }

    pub fn proof_claim_eligible(&self) -> bool {
        self.name.is_proof() && self.target_hardware_evidence.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchGroupVisibility {
    Public,
    Private,
    Hidden,
}

impl BenchGroupVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Hidden => "hidden",
        }
    }

    fn flags(self) -> &'static [&'static str] {
        match self {
            Self::Public => &[],
            Self::Private => &["private"],
            Self::Hidden => &["hidden"],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchGroup {
    id: String,
    visibility: BenchGroupVisibility,
}

impl BenchGroup {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn visibility(&self) -> BenchGroupVisibility {
        self.visibility
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchEventAuth {
    None,
    Owner,
    Admin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchSourceEvent {
    event: Event,
    auth: BenchEventAuth,
}

impl BenchSourceEvent {
    pub fn event(&self) -> &Event {
        &self.event
    }

    pub fn auth(&self) -> BenchEventAuth {
        self.auth
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchDataset {
    config: BenchDatasetConfig,
    groups: Vec<BenchGroup>,
    group_create_events: Vec<BenchSourceEvent>,
    membership_events: Vec<BenchSourceEvent>,
    group_timeline_events: Vec<BenchSourceEvent>,
    public_note_events: Vec<BenchSourceEvent>,
}

impl BenchDataset {
    pub fn generate(config: BenchDatasetConfig) -> Result<Self, String> {
        let config = config.validate()?;
        let groups = (0..config.group_count)
            .map(|index| BenchGroup {
                id: format!("BenchFarm{index:04}"),
                visibility: group_visibility(index),
            })
            .collect::<Vec<_>>();
        let mut group_create_events = Vec::with_capacity(groups.len());
        let mut membership_events = Vec::with_capacity(groups.len() * config.member_count);
        let mut group_timeline_events = Vec::new();
        let mut public_note_events = Vec::with_capacity(config.public_note_count);

        for (group_index, group) in groups.iter().enumerate() {
            group_create_events.push(BenchSourceEvent {
                event: tangle_v2_group_create_event(
                    FixtureKey::Owner,
                    &group.id,
                    1_714_200_000 + u64::try_from(group_index).expect("group index fits in u64"),
                    group.visibility.flags(),
                )?,
                auth: BenchEventAuth::Owner,
            });
            for member_index in 0..config.member_count {
                membership_events.push(BenchSourceEvent {
                    event: bench_member_event(&group.id, group_index, member_index, 1_714_300_000)?,
                    auth: BenchEventAuth::Admin,
                });
            }
            let per_group = match group.visibility {
                BenchGroupVisibility::Public => config.public_events_per_group,
                BenchGroupVisibility::Private | BenchGroupVisibility::Hidden => {
                    config.private_events_per_group
                }
            };
            for event_index in 0..per_group {
                let created_at = 1_714_400_000
                    + u64::try_from(group_index * 10_000 + event_index)
                        .expect("event index fits in u64");
                group_timeline_events.push(BenchSourceEvent {
                    event: tangle_v2_group_event(
                        FixtureKey::Owner,
                        &group.id,
                        created_at,
                        1,
                        &format!(
                            "bench {} group event {group_index:04}-{event_index:04}",
                            group.visibility.as_str()
                        ),
                    )?,
                    auth: BenchEventAuth::Owner,
                });
            }
        }

        for index in 0..config.public_note_count {
            public_note_events.push(BenchSourceEvent {
                event: tangle_v2_event(
                    FixtureKey::Outsider,
                    1_714_500_000 + u64::try_from(index).expect("note index fits in u64"),
                    1,
                    vec![tangle_v2_tag("t", &["tangle-bench"])?],
                    &format!("bench public note {index:04}"),
                )?,
                auth: BenchEventAuth::None,
            });
        }

        Ok(Self {
            config,
            groups,
            group_create_events,
            membership_events,
            group_timeline_events,
            public_note_events,
        })
    }

    pub fn config(&self) -> BenchDatasetConfig {
        self.config
    }

    pub fn groups(&self) -> &[BenchGroup] {
        &self.groups
    }

    pub fn source_events(&self) -> Vec<&BenchSourceEvent> {
        self.group_create_events
            .iter()
            .chain(self.membership_events.iter())
            .chain(self.group_timeline_events.iter())
            .chain(self.public_note_events.iter())
            .collect()
    }

    pub fn source_event_count(&self) -> u64 {
        self.source_events()
            .len()
            .try_into()
            .expect("source event count fits in u64")
    }

    pub fn group_event_count(&self) -> u64 {
        (self.group_create_events.len()
            + self.membership_events.len()
            + self.group_timeline_events.len())
        .try_into()
        .expect("group event count fits in u64")
    }

    pub fn membership_event_count(&self) -> u64 {
        self.membership_events
            .len()
            .try_into()
            .expect("membership event count fits in u64")
    }

    pub fn largest_group_members(&self) -> u64 {
        self.config
            .member_count
            .try_into()
            .expect("member count fits in u64")
    }

    pub fn dataset_digest(&self) -> Result<String, String> {
        let mut hasher = Sha256::new();
        for event in self.source_events() {
            let raw = serde_json::to_string(&event_to_value(event.event()))
                .map_err(|error| error.to_string())?;
            hasher.update(raw.as_bytes());
            hasher.update(b"\n");
        }
        Ok(lower_hex(&hasher.finalize()))
    }

    pub fn source_events_jsonl(&self) -> Result<String, String> {
        let mut output = String::new();
        for source in self.source_events() {
            let raw = serde_json::to_string(&event_to_value(source.event()))
                .map_err(|error| error.to_string())?;
            output.push_str(&raw);
            output.push('\n');
        }
        Ok(output)
    }

    fn first_group(&self, visibility: BenchGroupVisibility) -> Result<&BenchGroup, String> {
        self.groups
            .iter()
            .find(|group| group.visibility == visibility)
            .ok_or_else(|| format!("dataset does not include {} group", visibility.as_str()))
    }

    fn first_timeline_event(&self, visibility: BenchGroupVisibility) -> Result<&Event, String> {
        let group = self.first_group(visibility)?;
        self.group_timeline_events
            .iter()
            .find(|source| event_has_group(source.event(), group.id()))
            .map(BenchSourceEvent::event)
            .ok_or_else(|| {
                format!(
                    "dataset does not include {} timeline event",
                    visibility.as_str()
                )
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetProfile {
    pub total_events: u64,
    pub group_events: u64,
    pub groups: u64,
    pub memberships: u64,
    pub largest_group_members: u64,
    pub dataset_digest: String,
    pub fixture_family: String,
}

impl DatasetProfile {
    fn from_dataset(dataset: &BenchDataset) -> Result<Self, String> {
        Ok(Self {
            total_events: dataset.source_event_count(),
            group_events: dataset.group_event_count(),
            groups: dataset
                .groups()
                .len()
                .try_into()
                .expect("group count fits in u64"),
            memberships: dataset.membership_event_count(),
            largest_group_members: dataset.largest_group_members(),
            dataset_digest: dataset.dataset_digest()?,
            fixture_family: "synthetic repo-owned fixtures".to_owned(),
        })
    }

    fn to_json(&self) -> serde_json::Value {
        json!({
            "total_events": self.total_events,
            "group_events": self.group_events,
            "groups": self.groups,
            "memberships": self.memberships,
            "largest_group_members": self.largest_group_members,
            "dataset_digest": self.dataset_digest,
            "fixture_family": self.fixture_family
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScenarioReport {
    pub scenario: String,
    pub attempted: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub elapsed_micros: u64,
    pub events_per_second: f64,
    pub p50_micros: u64,
    pub p95_micros: u64,
    pub p99_micros: u64,
    pub max_rss_bytes: u64,
}

impl ScenarioReport {
    fn new(
        scenario: &str,
        attempted: u64,
        accepted: u64,
        rejected: u64,
        elapsed_micros: u64,
        mut samples: Vec<u64>,
        max_rss_bytes: u64,
    ) -> Self {
        samples.sort_unstable();
        let events_per_second = if elapsed_micros == 0 {
            0.0
        } else {
            attempted as f64 * 1_000_000.0 / elapsed_micros as f64
        };
        Self {
            scenario: scenario.to_owned(),
            attempted,
            accepted,
            rejected,
            elapsed_micros,
            events_per_second,
            p50_micros: percentile(&samples, 50),
            p95_micros: percentile(&samples, 95),
            p99_micros: percentile(&samples, 99),
            max_rss_bytes,
        }
    }

    fn pass_latency_gate(&self, p95_threshold_micros: u64) -> bool {
        self.rejected == 0
            && self.accepted == self.attempted
            && self.p95_micros <= p95_threshold_micros
    }

    fn pass_elapsed_gate(&self, elapsed_threshold_micros: u64) -> bool {
        self.rejected == 0
            && self.accepted == self.attempted
            && self.elapsed_micros <= elapsed_threshold_micros
    }

    fn pass_memory_gate(&self, max_bytes: u64) -> bool {
        self.rejected == 0 && self.accepted == self.attempted && self.max_rss_bytes <= max_bytes
    }

    fn to_json(&self) -> serde_json::Value {
        json!({
            "scenario": self.scenario,
            "status": status(self.accepted == self.attempted && self.rejected == 0),
            "attempted": self.attempted,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "elapsed_micros": self.elapsed_micros,
            "events_per_second": self.events_per_second,
            "p50_micros": self.p50_micros,
            "p95_micros": self.p95_micros,
            "p99_micros": self.p99_micros,
            "max_rss_bytes": self.max_rss_bytes,
            "query_metrics": {
                "candidates_scanned": self.attempted,
                "events_returned": self.accepted,
                "events_rejected": self.rejected
            },
            "memory": {
                "max_rss_bytes": self.max_rss_bytes
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BenchmarkThresholds {
    pub pocket_query_p95_micros: u64,
    pub read_gate_p95_micros: u64,
    pub count_resource_controls_p95_micros: u64,
    pub projection_rebuild_elapsed_micros: u64,
    pub outbox_replay_elapsed_micros: u64,
    pub broadcast_lag_p95_micros: u64,
    pub memory_profile_max_bytes: u64,
}

impl BenchmarkThresholds {
    pub fn smoke() -> Self {
        Self {
            pocket_query_p95_micros: 1_000_000,
            read_gate_p95_micros: 1_000_000,
            count_resource_controls_p95_micros: 1_000_000,
            projection_rebuild_elapsed_micros: 5_000_000,
            outbox_replay_elapsed_micros: 5_000_000,
            broadcast_lag_p95_micros: 1_000_000,
            memory_profile_max_bytes: 512 * 1024 * 1024,
        }
    }

    pub fn medium() -> Self {
        Self {
            pocket_query_p95_micros: 2_500_000,
            read_gate_p95_micros: 2_500_000,
            count_resource_controls_p95_micros: 2_500_000,
            projection_rebuild_elapsed_micros: 15_000_000,
            outbox_replay_elapsed_micros: 15_000_000,
            broadcast_lag_p95_micros: 2_500_000,
            memory_profile_max_bytes: 768 * 1024 * 1024,
        }
    }

    pub fn large_smoke() -> Self {
        Self {
            pocket_query_p95_micros: 5_000_000,
            read_gate_p95_micros: 5_000_000,
            count_resource_controls_p95_micros: 5_000_000,
            projection_rebuild_elapsed_micros: 60_000_000,
            outbox_replay_elapsed_micros: 60_000_000,
            broadcast_lag_p95_micros: 5_000_000,
            memory_profile_max_bytes: 1024 * 1024 * 1024,
        }
    }

    pub fn proof_10m() -> Self {
        Self {
            pocket_query_p95_micros: 10_000_000,
            read_gate_p95_micros: 10_000_000,
            count_resource_controls_p95_micros: 10_000_000,
            projection_rebuild_elapsed_micros: 300_000_000,
            outbox_replay_elapsed_micros: 300_000_000,
            broadcast_lag_p95_micros: 10_000_000,
            memory_profile_max_bytes: 16 * 1024 * 1024 * 1024,
        }
    }

    pub fn proof_large_group() -> Self {
        Self {
            pocket_query_p95_micros: 10_000_000,
            read_gate_p95_micros: 10_000_000,
            count_resource_controls_p95_micros: 10_000_000,
            projection_rebuild_elapsed_micros: 300_000_000,
            outbox_replay_elapsed_micros: 300_000_000,
            broadcast_lag_p95_micros: 10_000_000,
            memory_profile_max_bytes: 16 * 1024 * 1024 * 1024,
        }
    }

    pub fn proof_join_storm() -> Self {
        Self {
            pocket_query_p95_micros: 10_000_000,
            read_gate_p95_micros: 10_000_000,
            count_resource_controls_p95_micros: 10_000_000,
            projection_rebuild_elapsed_micros: 300_000_000,
            outbox_replay_elapsed_micros: 300_000_000,
            broadcast_lag_p95_micros: 10_000_000,
            memory_profile_max_bytes: 16 * 1024 * 1024 * 1024,
        }
    }

    pub fn proof_slow_client() -> Self {
        Self {
            pocket_query_p95_micros: 10_000_000,
            read_gate_p95_micros: 10_000_000,
            count_resource_controls_p95_micros: 10_000_000,
            projection_rebuild_elapsed_micros: 300_000_000,
            outbox_replay_elapsed_micros: 300_000_000,
            broadcast_lag_p95_micros: 10_000_000,
            memory_profile_max_bytes: 16 * 1024 * 1024 * 1024,
        }
    }

    pub fn from_json_str(raw: &str) -> Result<Self, String> {
        let value = serde_json::from_str::<serde_json::Value>(raw)
            .map_err(|error| format!("benchmark thresholds JSON is invalid: {error}"))?;
        Self::from_json_value(&value)
    }

    pub fn from_json_value(value: &serde_json::Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "benchmark thresholds JSON must be an object".to_owned())?;
        for key in object.keys() {
            if !benchmark_threshold_fields().contains(&key.as_str()) {
                return Err(format!("unknown benchmark threshold field `{key}`"));
            }
        }
        Ok(Self {
            pocket_query_p95_micros: threshold_u64(value, "pocket_query_p95_micros")?,
            read_gate_p95_micros: threshold_u64(value, "read_gate_p95_micros")?,
            count_resource_controls_p95_micros: threshold_u64(
                value,
                "count_resource_controls_p95_micros",
            )?,
            projection_rebuild_elapsed_micros: threshold_u64(
                value,
                "projection_rebuild_elapsed_micros",
            )?,
            outbox_replay_elapsed_micros: threshold_u64(value, "outbox_replay_elapsed_micros")?,
            broadcast_lag_p95_micros: threshold_u64(value, "broadcast_lag_p95_micros")?,
            memory_profile_max_bytes: threshold_u64(value, "memory_profile_max_bytes")?,
        })
    }

    pub fn to_json(self) -> serde_json::Value {
        json!({
            "pocket_query_p95_micros": self.pocket_query_p95_micros,
            "read_gate_p95_micros": self.read_gate_p95_micros,
            "count_resource_controls_p95_micros": self.count_resource_controls_p95_micros,
            "projection_rebuild_elapsed_micros": self.projection_rebuild_elapsed_micros,
            "outbox_replay_elapsed_micros": self.outbox_replay_elapsed_micros,
            "broadcast_lag_p95_micros": self.broadcast_lag_p95_micros,
            "memory_profile_max_bytes": self.memory_profile_max_bytes
        })
    }
}

fn benchmark_threshold_fields() -> [&'static str; 7] {
    [
        "pocket_query_p95_micros",
        "read_gate_p95_micros",
        "count_resource_controls_p95_micros",
        "projection_rebuild_elapsed_micros",
        "outbox_replay_elapsed_micros",
        "broadcast_lag_p95_micros",
        "memory_profile_max_bytes",
    ]
}

fn threshold_u64(value: &serde_json::Value, field: &str) -> Result<u64, String> {
    let value = value
        .get(field)
        .ok_or_else(|| format!("missing benchmark threshold field `{field}`"))?;
    let Some(value) = value.as_u64() else {
        return Err(format!(
            "benchmark threshold field `{field}` must be an unsigned integer"
        ));
    };
    if value == 0 {
        return Err(format!(
            "benchmark threshold field `{field}` must be greater than zero"
        ));
    }
    Ok(value)
}

#[derive(Debug, Clone, PartialEq)]
pub struct BenchmarkRunReport {
    dataset: BenchDataset,
    dataset_profile: DatasetProfile,
    profile: BenchmarkProfile,
    scenarios: Vec<ScenarioReport>,
    validation_summary: BTreeMap<String, String>,
}

impl BenchmarkRunReport {
    pub fn run(profile: BenchmarkProfile) -> Result<Self, String> {
        profile.validate_for_run()?;
        let dataset = BenchDataset::generate(profile.dataset_config())?;
        let thresholds = profile.thresholds();
        let pocket_query = run_pocket_query_benchmark(&dataset)?;
        let read_gate = run_read_gate_benchmark(&dataset)?;
        let count_resource_controls = run_count_resource_control_benchmark(&dataset)?;
        let projection_rebuild = run_projection_rebuild_benchmark(&dataset)?;
        let outbox_replay = run_outbox_replay_benchmark(&dataset)?;
        let broadcast_lag = run_broadcast_lag_benchmark(&dataset)?;
        let memory_profile = run_memory_profile_benchmark(&dataset)?;
        let scenarios = vec![
            pocket_query,
            read_gate,
            count_resource_controls,
            projection_rebuild,
            outbox_replay,
            broadcast_lag,
            memory_profile,
        ];
        let validation_summary = validation_summary(&scenarios, thresholds)?;
        let dataset_profile = DatasetProfile::from_dataset(&dataset)?;
        Ok(Self {
            dataset,
            dataset_profile,
            profile,
            scenarios,
            validation_summary,
        })
    }

    pub fn dataset(&self) -> &BenchDataset {
        &self.dataset
    }

    pub fn dataset_profile(&self) -> &DatasetProfile {
        &self.dataset_profile
    }

    pub fn profile(&self) -> &BenchmarkProfile {
        &self.profile
    }

    pub fn scenarios(&self) -> &[ScenarioReport] {
        &self.scenarios
    }

    pub fn scenario(&self, name: &str) -> Option<&ScenarioReport> {
        self.scenarios
            .iter()
            .find(|scenario| scenario.scenario == name)
    }

    pub fn validation_summary(&self) -> &BTreeMap<String, String> {
        &self.validation_summary
    }

    pub fn summary_json(&self, run_id: &str, artifact_directory: &Path) -> serde_json::Value {
        json!({
            "schema": 2,
            "run_id": run_id,
            "artifact_directory": artifact_directory.to_string_lossy(),
            "profile": self.profile.name().as_str(),
            "dataset": self.dataset_profile.to_json(),
            "dataset_profile": self.dataset_profile.to_json(),
            "scenarios": self.scenarios.iter().map(ScenarioReport::to_json).collect::<Vec<_>>(),
            "pocket_source": pocket_source_json(),
            "threshold_source": self.profile.threshold_source(),
            "thresholds": self.profile.thresholds().to_json(),
            "validation_summary": self.validation_summary,
            "pass_fail_summary": {
                "overall_status": validation_overall_status(&self.validation_summary),
                "passed_scenarios": self
                    .validation_summary
                    .values()
                    .filter(|value| value.as_str() == "pass")
                    .count(),
                "failed_scenarios": self
                    .validation_summary
                    .values()
                    .filter(|value| value.as_str() == "fail")
                    .count()
            },
            "proof_claim": {
                "eligible": self.profile.proof_claim_eligible(),
                "profile_required": "proof-*",
                "target_hardware_evidence": self
                    .profile
                    .target_hardware_evidence()
                    .unwrap_or("absent")
            },
            "artifacts": {
                "summary_json": "summary.json",
                "dataset_events_jsonl": "dataset-events.jsonl"
            }
        })
    }
}

fn pocket_source_json() -> serde_json::Value {
    json!({
        "repository": POCKET_SOURCE_REPOSITORY,
        "revision": POCKET_SOURCE_REVISION,
        "crates": ["pocket-db", "pocket-types"]
    })
}

fn validation_overall_status(summary: &BTreeMap<String, String>) -> &'static str {
    if summary.values().all(|value| value == "pass") {
        "pass"
    } else {
        "fail"
    }
}

struct MaterializedBenchRelay {
    relay: BaseRelay,
    store_config: PocketStoreConfig,
    ingest_report: ScenarioReport,
}

fn run_pocket_query_benchmark(dataset: &BenchDataset) -> Result<ScenarioReport, String> {
    let mut materialized = materialize_dataset(dataset, "pocket-query", 128)?;
    let public_group = dataset.first_group(BenchGroupVisibility::Public)?;
    let public_event = dataset.first_timeline_event(BenchGroupVisibility::Public)?;
    let owner_auth = authenticated(FixtureKey::Owner)?;
    let owner = FixtureKey::Owner.public_key();
    let created_at = public_event.unsigned().created_at().as_u64();
    let operations = vec![
        QueryOperation::new(
            "pocket-h",
            filter_from_value(&json!({"kinds": [1], "#h": [public_group.id()], "limit": 50}))?,
            QueryAuth::None,
            QueryExpectation::AtLeast(1),
        ),
        QueryOperation::new(
            "pocket-d",
            filter_from_value(&json!({
                "kinds": [KIND_GROUP_METADATA],
                "#d": [public_group.id()],
                "limit": 10
            }))?,
            QueryAuth::None,
            QueryExpectation::AtLeast(1),
        ),
        QueryOperation::new(
            "pocket-kind-author-window-limit",
            filter_from_value(&json!({
                "kinds": [1],
                "authors": [owner.as_str()],
                "since": created_at.saturating_sub(1),
                "until": created_at.saturating_add(100_000),
                "limit": 25
            }))?,
            QueryAuth::Owner,
            QueryExpectation::AtLeast(1),
        ),
        QueryOperation::new(
            "pocket-count",
            filter_from_value(&json!({"kinds": [1], "#h": [public_group.id()]}))?,
            QueryAuth::None,
            QueryExpectation::AtLeast(1),
        ),
    ];
    let started = Instant::now();
    let mut samples = Vec::with_capacity(operations.len());
    let mut accepted = 0;
    let mut rejected = 0;
    for operation in operations {
        let sample = Instant::now();
        let observed = match operation.name {
            "pocket-count" => count_for_operation(&materialized.relay, &operation, &owner_auth)?,
            _ => query_for_operation(&mut materialized.relay, &operation, &owner_auth)?,
        };
        samples.push(elapsed_micros(sample));
        if operation.expectation.matches(observed) {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    Ok(ScenarioReport::new(
        SCENARIO_POCKET_QUERY_VISIBLE_EVENTS,
        accepted + rejected,
        accepted,
        rejected,
        elapsed_micros(started),
        samples,
        materialized.ingest_report.max_rss_bytes,
    ))
}

fn run_read_gate_benchmark(dataset: &BenchDataset) -> Result<ScenarioReport, String> {
    let mut materialized = materialize_dataset(dataset, "read-gate", 128)?;
    let public_group = dataset.first_group(BenchGroupVisibility::Public)?;
    let private_group = dataset.first_group(BenchGroupVisibility::Private)?;
    let hidden_group = dataset.first_group(BenchGroupVisibility::Hidden)?;
    let owner_auth = authenticated(FixtureKey::Owner)?;
    let operations = vec![
        QueryOperation::new(
            "public-unauth",
            filter_from_value(&json!({"kinds": [1], "#h": [public_group.id()]}))?,
            QueryAuth::None,
            QueryExpectation::AtLeast(1),
        ),
        QueryOperation::new(
            "private-unauth",
            filter_from_value(&json!({"kinds": [1], "#h": [private_group.id()]}))?,
            QueryAuth::None,
            QueryExpectation::Exactly(0),
        ),
        QueryOperation::new(
            "private-owner",
            filter_from_value(&json!({"kinds": [1], "#h": [private_group.id()]}))?,
            QueryAuth::Owner,
            QueryExpectation::AtLeast(1),
        ),
        QueryOperation::new(
            "hidden-metadata-unauth",
            filter_from_value(&json!({"kinds": [KIND_GROUP_METADATA], "#d": [hidden_group.id()]}))?,
            QueryAuth::None,
            QueryExpectation::Exactly(0),
        ),
        QueryOperation::new(
            "hidden-metadata-owner",
            filter_from_value(&json!({"kinds": [KIND_GROUP_METADATA], "#d": [hidden_group.id()]}))?,
            QueryAuth::Owner,
            QueryExpectation::AtLeast(1),
        ),
        QueryOperation::new(
            "private-count-unauth",
            filter_from_value(&json!({"kinds": [1], "#h": [private_group.id()]}))?,
            QueryAuth::None,
            QueryExpectation::Exactly(0),
        ),
        QueryOperation::new(
            "private-count-owner",
            filter_from_value(&json!({"kinds": [1], "#h": [private_group.id()]}))?,
            QueryAuth::Owner,
            QueryExpectation::AtLeast(1),
        ),
    ];
    let started = Instant::now();
    let mut samples = Vec::with_capacity(operations.len());
    let mut accepted = 0;
    let mut rejected = 0;
    for operation in operations {
        let sample = Instant::now();
        let observed = if operation.name.contains("count") {
            count_for_operation(&materialized.relay, &operation, &owner_auth)?
        } else {
            query_for_operation(&mut materialized.relay, &operation, &owner_auth)?
        };
        samples.push(elapsed_micros(sample));
        if operation.expectation.matches(observed) {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    Ok(ScenarioReport::new(
        SCENARIO_GROUP_READ_GATE_OVERHEAD,
        accepted + rejected,
        accepted,
        rejected,
        elapsed_micros(started),
        samples,
        materialized.ingest_report.max_rss_bytes,
    ))
}

fn run_count_resource_control_benchmark(dataset: &BenchDataset) -> Result<ScenarioReport, String> {
    let materialized = materialize_dataset(dataset, "count-resource-controls", 128)?;
    let public_group = dataset.first_group(BenchGroupVisibility::Public)?;
    let private_group = dataset.first_group(BenchGroupVisibility::Private)?;
    let owner_auth = authenticated(FixtureKey::Owner)?;
    let operations = vec![
        QueryOperation::new(
            "bounded-public-count",
            filter_from_value(&json!({"kinds": [1], "#h": [public_group.id()]}))?,
            QueryAuth::None,
            QueryExpectation::Exactly(
                dataset
                    .config
                    .public_events_per_group
                    .try_into()
                    .expect("public event count fits in u64"),
            ),
        ),
        QueryOperation::new(
            "bounded-private-owner-count",
            filter_from_value(&json!({"kinds": [1], "#h": [private_group.id()]}))?,
            QueryAuth::Owner,
            QueryExpectation::Exactly(
                dataset
                    .config
                    .private_events_per_group
                    .try_into()
                    .expect("private event count fits in u64"),
            ),
        ),
    ];
    let started = Instant::now();
    let mut samples = Vec::with_capacity(operations.len() + 3);
    let mut accepted = 0;
    let mut rejected = 0;
    for operation in operations {
        let sample = Instant::now();
        let observed = count_for_operation(&materialized.relay, &operation, &owner_auth)?;
        samples.push(elapsed_micros(sample));
        if operation.expectation.matches(observed) {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|error| format!("failed to build count resource benchmark runtime: {error}"))?;
    let probe = runtime.block_on(runtime_count_resource_control_probe())?;
    samples.extend(probe.samples);
    accepted += probe.accepted;
    rejected += probe.rejected;
    Ok(ScenarioReport::new(
        SCENARIO_COUNT_RESOURCE_CONTROLS,
        accepted + rejected,
        accepted,
        rejected,
        elapsed_micros(started),
        samples,
        materialized.ingest_report.max_rss_bytes,
    ))
}

fn run_projection_rebuild_benchmark(dataset: &BenchDataset) -> Result<ScenarioReport, String> {
    let mut materialized = materialize_dataset(dataset, "projection-rebuild", 128)?;
    materialized
        .relay
        .shutdown()
        .map_err(|error| error.to_string())?;
    let started = Instant::now();
    let reopened = BaseRelay::open_with_groups(
        &materialized.store_config,
        relay_limits(128),
        &group_config()?,
        PocketQueryConfig::default(),
    )
    .map_err(|error| error.to_string())?;
    let elapsed = elapsed_micros(started);
    let projection = reopened
        .group_projection()
        .ok_or_else(|| "group projection is unavailable".to_owned())?;
    let groups_match = projection.groups().len() == dataset.groups().len();
    let members_match = projection
        .members()
        .values()
        .filter(|member| member.status() == MemberStatus::Member)
        .count()
        == usize::try_from(dataset.membership_event_count())
            .expect("membership count fits in usize");
    let accepted = u64::from(groups_match && members_match);
    Ok(ScenarioReport::new(
        SCENARIO_PROJECTION_REBUILD,
        1,
        accepted,
        1 - accepted,
        elapsed,
        vec![elapsed],
        estimate_memory_bytes(dataset),
    ))
}

fn run_outbox_replay_benchmark(dataset: &BenchDataset) -> Result<ScenarioReport, String> {
    let mut materialized = materialize_dataset(dataset, "outbox-replay", 128)?;
    let before = generated_state_counts(&materialized.relay)?;
    materialized
        .relay
        .shutdown()
        .map_err(|error| error.to_string())?;
    let started = Instant::now();
    let mut reopened = BaseRelay::open_with_groups(
        &materialized.store_config,
        relay_limits(128),
        &group_config()?,
        PocketQueryConfig::default(),
    )
    .map_err(|error| error.to_string())?;
    let after_first = generated_state_counts(&reopened)?;
    reopened.shutdown().map_err(|error| error.to_string())?;
    let reopened = BaseRelay::open_with_groups(
        &materialized.store_config,
        relay_limits(128),
        &group_config()?,
        PocketQueryConfig::default(),
    )
    .map_err(|error| error.to_string())?;
    let after_second = generated_state_counts(&reopened)?;
    let elapsed = elapsed_micros(started);
    let accepted = u64::from(before == after_first && before == after_second);
    Ok(ScenarioReport::new(
        SCENARIO_OUTBOX_REPLAY,
        1,
        accepted,
        1 - accepted,
        elapsed,
        vec![elapsed],
        estimate_memory_bytes(dataset),
    ))
}

fn run_broadcast_lag_benchmark(dataset: &BenchDataset) -> Result<ScenarioReport, String> {
    let mut materialized = materialize_dataset(dataset, "broadcast-lag", 1)?;
    let public_group = dataset.first_group(BenchGroupVisibility::Public)?;
    let subscriber_count = dataset.config.group_count.max(4);
    let filter = filter_from_value(&json!({"kinds": [1], "#h": [public_group.id()]}))?;
    for index in 0..subscriber_count {
        materialized
            .relay
            .handle_req(
                subscription(&format!("lag-{index:04}"))?,
                vec![filter.clone()],
            )
            .map_err(|error| error.to_string())?;
    }
    let first = tangle_v2_group_event(
        FixtureKey::Owner,
        public_group.id(),
        1_714_600_000,
        1,
        "broadcast lag first",
    )?;
    let second = tangle_v2_group_event(
        FixtureKey::Owner,
        public_group.id(),
        1_714_600_001,
        1,
        "broadcast lag second",
    )?;
    let started = Instant::now();
    let first_messages = materialized.relay.fanout(&first);
    let second_messages = materialized.relay.fanout(&second);
    let elapsed = elapsed_micros(started);
    let first_events = first_messages
        .iter()
        .filter(|message| matches!(message, RelayMessage::Event { .. }))
        .count();
    let second_events = second_messages
        .iter()
        .filter(|message| matches!(message, RelayMessage::Event { .. }))
        .count();
    let accepted = if first_events == subscriber_count
        && second_events == subscriber_count
        && materialized.relay.active_subscription_count() == subscriber_count
    {
        subscriber_count
    } else {
        0
    };
    let attempted = subscriber_count
        .try_into()
        .expect("subscriber count fits in u64");
    let accepted = accepted.try_into().expect("accepted fits in u64");
    Ok(ScenarioReport::new(
        SCENARIO_BROADCAST_LAG,
        attempted,
        accepted,
        attempted - accepted,
        elapsed,
        vec![elapsed],
        materialized.ingest_report.max_rss_bytes,
    ))
}

fn run_memory_profile_benchmark(dataset: &BenchDataset) -> Result<ScenarioReport, String> {
    let started = Instant::now();
    let estimated = estimate_memory_bytes(dataset);
    let elapsed = elapsed_micros(started);
    Ok(ScenarioReport::new(
        SCENARIO_MEMORY_PROFILE,
        1,
        1,
        0,
        elapsed,
        vec![elapsed],
        estimated,
    ))
}

struct CountResourceControlProbe {
    accepted: u64,
    rejected: u64,
    samples: Vec<u64>,
}

async fn runtime_count_resource_control_probe() -> Result<CountResourceControlProbe, String> {
    let root = bench_temp_root("count-resource-controls-runtime");
    let _ = fs::remove_dir_all(&root);
    let handle = TangleRuntimeHandle::new(
        TangleRuntime::open(bench_runtime_config(&root)?).map_err(|error| error.to_string())?,
    );
    let mut auth = handle
        .auth_state()
        .await
        .map_err(|error| error.to_string())?;
    let cases = [
        ("broad-empty-selector-count", json!({"limit": 1})),
        ("broad-kind-only-count", json!({"kinds": [1], "limit": 1})),
        (
            "broad-high-limit-count",
            json!({"kinds": [1], "#h": ["BenchFarm0000"], "limit": 500}),
        ),
    ];
    let mut samples = Vec::with_capacity(cases.len());
    let mut accepted = 0;
    let mut rejected = 0;
    for (name, filter) in cases {
        let sample = Instant::now();
        let subscription_id = subscription(name)?;
        let pocket_filter = parse_pocket_filter_json(filter.to_string().as_bytes())
            .map_err(|error| error.to_string())?;
        let replies = handle
            .handle_count_pocket(
                subscription_id.clone(),
                vec![pocket_filter],
                &mut auth,
                UnixTimestamp::new(1_714_700_000),
            )
            .await
            .map_err(|error| error.to_string())?;
        samples.push(elapsed_micros(sample));
        if replies
            == vec![RelayMessage::Closed {
                subscription_id,
                message: "restricted: count filters are too broad or expensive".to_owned(),
            }]
        {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    let metrics = handle.metrics();
    if metrics.count_refusals() != accepted || metrics.broad_query_rejections() != accepted {
        rejected += 1;
    }
    let _ = fs::remove_dir_all(root);
    Ok(CountResourceControlProbe {
        accepted,
        rejected,
        samples,
    })
}

fn materialize_dataset(
    dataset: &BenchDataset,
    run_name: &str,
    max_pending_events: usize,
) -> Result<MaterializedBenchRelay, String> {
    let store_config = bench_store_config(run_name)?;
    let relay = BaseRelay::open_with_groups(
        &store_config,
        relay_limits(max_pending_events),
        &group_config()?,
        PocketQueryConfig::default(),
    )
    .map_err(|error| error.to_string())?;
    let owner_auth = authenticated(FixtureKey::Owner)?;
    let admin_auth = authenticated(FixtureKey::Admin)?;
    let started = Instant::now();
    let mut samples = Vec::with_capacity(dataset.source_events().len());
    let mut accepted = 0;
    let mut rejected = 0;
    for source in dataset.source_events() {
        let sample = Instant::now();
        let pocket_event =
            parse_pocket_event_json(event_to_value(source.event()).to_string().as_bytes())
                .map_err(|error| error.to_string())?;
        let message = match source.auth() {
            BenchEventAuth::None => relay
                .handle_pocket_event(&pocket_event)
                .map_err(|error| error.to_string())?,
            BenchEventAuth::Owner => relay
                .handle_pocket_event_with_auth(&pocket_event, &owner_auth)
                .map_err(|error| error.to_string())?,
            BenchEventAuth::Admin => relay
                .handle_pocket_event_with_auth(&pocket_event, &admin_auth)
                .map_err(|error| error.to_string())?,
        };
        samples.push(elapsed_micros(sample));
        if ok_accepted(&message) {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    let attempted = accepted + rejected;
    let ingest_report = ScenarioReport::new(
        "dataset_ingest",
        attempted,
        accepted,
        rejected,
        elapsed_micros(started),
        samples,
        estimate_memory_bytes(dataset),
    );
    Ok(MaterializedBenchRelay {
        relay,
        store_config,
        ingest_report,
    })
}

fn relay_limits(max_pending_events: usize) -> BaseRelayLimits {
    BaseRelayLimits::new(BaseRelayLimitSettings {
        max_pending_events,
        max_subscription_id_length: 64,
        max_subscriptions: 512,
        max_filters_per_request: 10,
        max_tag_values_per_filter: 100,
        max_query_complexity: 610,
        max_event_tags: 200,
        max_content_length: 65_536,
        max_limit: 500,
        default_limit: 100,
    })
    .expect("benchmark relay limits")
}

#[derive(Clone)]
struct QueryOperation {
    name: &'static str,
    filter: Filter,
    auth: QueryAuth,
    expectation: QueryExpectation,
}

impl QueryOperation {
    fn new(
        name: &'static str,
        filter: Filter,
        auth: QueryAuth,
        expectation: QueryExpectation,
    ) -> Self {
        Self {
            name,
            filter,
            auth,
            expectation,
        }
    }
}

#[derive(Clone, Copy)]
enum QueryAuth {
    None,
    Owner,
}

#[derive(Clone, Copy)]
enum QueryExpectation {
    Exactly(u64),
    AtLeast(u64),
}

impl QueryExpectation {
    fn matches(self, observed: u64) -> bool {
        match self {
            Self::Exactly(expected) => observed == expected,
            Self::AtLeast(expected) => observed >= expected,
        }
    }
}

fn query_for_operation(
    relay: &mut BaseRelay,
    operation: &QueryOperation,
    owner_auth: &BaseAuthState,
) -> Result<u64, String> {
    let subscription_id = subscription(operation.name)?;
    let messages = match operation.auth {
        QueryAuth::None => relay
            .handle_req(subscription_id.clone(), vec![operation.filter.clone()])
            .map_err(|error| error.to_string())?,
        QueryAuth::Owner => relay
            .handle_req_with_auth(
                subscription_id.clone(),
                vec![operation.filter.clone()],
                owner_auth,
            )
            .map_err(|error| error.to_string())?,
    };
    relay.handle_close(&subscription_id);
    Ok(messages
        .iter()
        .filter(|message| matches!(message, RelayMessage::Event { .. }))
        .count()
        .try_into()
        .expect("message count fits in u64"))
}

fn count_for_operation(
    relay: &BaseRelay,
    operation: &QueryOperation,
    owner_auth: &BaseAuthState,
) -> Result<u64, String> {
    let subscription_id = subscription(operation.name)?;
    let filter = pocket_filter(&operation.filter)?;
    let message = match operation.auth {
        QueryAuth::None => relay
            .handle_count(subscription_id, vec![filter])
            .map_err(|error| error.to_string())?,
        QueryAuth::Owner => relay
            .handle_count_with_auth(subscription_id, vec![filter], owner_auth)
            .map_err(|error| error.to_string())?,
    };
    match message {
        RelayMessage::Count { count, .. } => Ok(count),
        value => Err(format!("expected COUNT message, got {value:?}")),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GeneratedStateCounts {
    metadata: u64,
    admins: u64,
    members: u64,
}

fn generated_state_counts(relay: &BaseRelay) -> Result<GeneratedStateCounts, String> {
    Ok(GeneratedStateCounts {
        metadata: count_kind(relay, KIND_GROUP_METADATA)?,
        admins: count_kind(relay, KIND_GROUP_ADMINS)?,
        members: count_kind(relay, KIND_GROUP_MEMBERS)?,
    })
}

fn count_kind(relay: &BaseRelay, kind: u32) -> Result<u64, String> {
    let owner_auth = authenticated(FixtureKey::Owner)?;
    let message = relay
        .handle_count_with_auth(
            subscription(&format!("count-{kind}"))?,
            vec![pocket_filter_from_value(&json!({"kinds": [kind]}))?],
            &owner_auth,
        )
        .map_err(|error| error.to_string())?;
    match message {
        RelayMessage::Count { count, .. } => Ok(count),
        value => Err(format!("expected COUNT message, got {value:?}")),
    }
}

fn pocket_filter(filter: &Filter) -> Result<PocketOwnedFilter, String> {
    let raw = serde_json::to_vec(&filter_to_value(filter)).map_err(|error| error.to_string())?;
    parse_pocket_filter_json(&raw).map_err(|error| error.to_string())
}

fn pocket_filter_from_value(value: &serde_json::Value) -> Result<PocketOwnedFilter, String> {
    let filter = filter_from_value(value)?;
    pocket_filter(&filter)
}

fn validation_summary(
    scenarios: &[ScenarioReport],
    thresholds: BenchmarkThresholds,
) -> Result<BTreeMap<String, String>, String> {
    let mut summary = BTreeMap::new();
    let mut failures = Vec::new();
    if let Some(failure) = record_threshold_status(
        &mut summary,
        SCENARIO_POCKET_QUERY_VISIBLE_EVENTS,
        scenario(scenarios, SCENARIO_POCKET_QUERY_VISIBLE_EVENTS)?
            .pass_latency_gate(thresholds.pocket_query_p95_micros),
    ) {
        failures.push(failure);
    }
    if let Some(failure) = record_threshold_status(
        &mut summary,
        SCENARIO_GROUP_READ_GATE_OVERHEAD,
        scenario(scenarios, SCENARIO_GROUP_READ_GATE_OVERHEAD)?
            .pass_latency_gate(thresholds.read_gate_p95_micros),
    ) {
        failures.push(failure);
    }
    if let Some(failure) = record_threshold_status(
        &mut summary,
        SCENARIO_COUNT_RESOURCE_CONTROLS,
        scenario(scenarios, SCENARIO_COUNT_RESOURCE_CONTROLS)?
            .pass_latency_gate(thresholds.count_resource_controls_p95_micros),
    ) {
        failures.push(failure);
    }
    if let Some(failure) = record_threshold_status(
        &mut summary,
        SCENARIO_PROJECTION_REBUILD,
        scenario(scenarios, SCENARIO_PROJECTION_REBUILD)?
            .pass_elapsed_gate(thresholds.projection_rebuild_elapsed_micros),
    ) {
        failures.push(failure);
    }
    if let Some(failure) = record_threshold_status(
        &mut summary,
        SCENARIO_OUTBOX_REPLAY,
        scenario(scenarios, SCENARIO_OUTBOX_REPLAY)?
            .pass_elapsed_gate(thresholds.outbox_replay_elapsed_micros),
    ) {
        failures.push(failure);
    }
    if let Some(failure) = record_threshold_status(
        &mut summary,
        SCENARIO_BROADCAST_LAG,
        scenario(scenarios, SCENARIO_BROADCAST_LAG)?
            .pass_latency_gate(thresholds.broadcast_lag_p95_micros),
    ) {
        failures.push(failure);
    }
    if let Some(failure) = record_threshold_status(
        &mut summary,
        SCENARIO_MEMORY_PROFILE,
        scenario(scenarios, SCENARIO_MEMORY_PROFILE)?
            .pass_memory_gate(thresholds.memory_profile_max_bytes),
    ) {
        failures.push(failure);
    }
    if failures.is_empty() {
        Ok(summary)
    } else {
        Err(failures.join("; "))
    }
}

fn record_threshold_status(
    summary: &mut BTreeMap<String, String>,
    name: &str,
    passed: bool,
) -> Option<String> {
    summary.insert(name.to_owned(), status(passed));
    if passed {
        None
    } else {
        Some(format!("scenario `{name}` failed benchmark threshold"))
    }
}

fn scenario<'a>(scenarios: &'a [ScenarioReport], name: &str) -> Result<&'a ScenarioReport, String> {
    scenarios
        .iter()
        .find(|scenario| scenario.scenario == name)
        .ok_or_else(|| format!("scenario `{name}` was not run"))
}

fn status(value: bool) -> String {
    if value { "pass" } else { "fail" }.to_owned()
}

fn bench_member_event(
    group_id: &str,
    group_index: usize,
    member_index: usize,
    base_created_at: u64,
) -> Result<Event, String> {
    if member_index == 0 {
        return tangle_v2_put_user_event(
            FixtureKey::Admin,
            group_id,
            FixtureKey::Member,
            base_created_at + u64::try_from(group_index * 10_000).expect("group index fits in u64"),
        );
    }
    let pubkey = synthetic_member_pubkey(group_index, member_index);
    tangle_v2_event(
        FixtureKey::Admin,
        base_created_at
            + u64::try_from(group_index * 10_000 + member_index).expect("member index fits in u64"),
        9_000,
        vec![
            tangle_v2_tag("h", &[group_id])?,
            tangle_v2_tag("p", &[pubkey.as_str()])?,
        ],
        "",
    )
}

fn synthetic_member_pubkey(group_index: usize, member_index: usize) -> String {
    format!(
        "{:064x}",
        0x100000_u128 + (group_index as u128 * 10_000) + member_index as u128
    )
}

fn group_visibility(index: usize) -> BenchGroupVisibility {
    match index % 3 {
        0 => BenchGroupVisibility::Public,
        1 => BenchGroupVisibility::Private,
        _ => BenchGroupVisibility::Hidden,
    }
}

fn event_has_group(event: &Event, group_id: &str) -> bool {
    event.unsigned().tags().iter().any(|tag| {
        tag.indexed_pair()
            .is_some_and(|(name, value)| name == "h" && value == group_id)
    })
}

fn group_config() -> Result<tangle_groups::GroupRuntimeConfig, String> {
    tangle_v2_group_config(FixtureKey::Owner, &[FixtureKey::Admin])
}

fn authenticated(key: FixtureKey) -> Result<BaseAuthState, String> {
    let mut auth =
        BaseAuthState::new(TANGLE_V2_RELAY_URL, 60, 600).map_err(|error| error.to_string())?;
    auth.issue_challenge("challenge-a", tangle_protocol::UnixTimestamp::new(100))
        .map_err(|error| error.to_string())?;
    let event = tangle_v2_auth_event(key, "challenge-a", 120)?;
    auth.authenticate(&event, tangle_protocol::UnixTimestamp::new(120))
        .map_err(|error| error.to_string())?;
    Ok(auth)
}

fn bench_store_config(run_name: &str) -> Result<PocketStoreConfig, String> {
    let root = bench_temp_root(run_name);
    let _ = fs::remove_dir_all(&root);
    PocketStoreConfig::new(root.join("pocket"), PocketSyncPolicy::FlushOnShutdown)
        .map_err(|error| error.to_string())
}

fn bench_runtime_config(root: &Path) -> Result<BaseRelayRuntimeConfig, String> {
    let raw = json!({
        "server": {
            "listen_addr": "127.0.0.1:0",
            "relay_url": TANGLE_V2_RELAY_URL
        },
        "pocket": {
            "data_directory": root.join("pocket"),
            "sync_policy": "flush_on_shutdown",
            "query": {
                "allow_scraping": false,
                "allow_scrape_if_limited_to": 100,
                "allow_scrape_if_max_seconds": 3600
            }
        },
        "groups": {
            "enabled": true,
            "canonical_relay_url": TANGLE_V2_RELAY_URL,
            "relay_secret": "7777777777777777777777777777777777777777777777777777777777777777",
            "owner_pubkeys": [FixtureKey::Owner.public_key().as_str()]
        },
        "auth": {
            "challenge_ttl_seconds": 300,
            "created_at_skew_seconds": 600
        },
        "limits": {
            "max_message_length": 1048576,
            "max_subid_length": 64,
            "max_subscriptions_per_connection": 64,
            "max_filters_per_request": 10,
            "max_tag_values_per_filter": 100,
            "max_query_complexity": 2048,
            "max_limit": 500,
            "default_limit": 100,
            "max_event_tags": 200,
            "max_content_length": 65536,
            "broadcast_channel_capacity": 16,
            "per_connection_outbound_queue": 8
        },
        "rate_limits": {
            "auth": {
                "per_ip": {"window_seconds": 60, "max_hits": 120},
                "per_pubkey": {"window_seconds": 60, "max_hits": 30},
                "failures": {"window_seconds": 300, "max_hits": 5},
                "failures_per_ip": {"window_seconds": 300, "max_hits": 20}
            },
            "event": {
                "per_ip": {"window_seconds": 60, "max_hits": 600},
                "per_pubkey": {"window_seconds": 60, "max_hits": 120},
                "per_kind": {"window_seconds": 60, "max_hits": 1000}
            },
            "group": {
                "write_per_ip": {"window_seconds": 60, "max_hits": 300},
                "write_per_pubkey": {"window_seconds": 60, "max_hits": 60},
                "write_per_group": {"window_seconds": 60, "max_hits": 90},
                "write_per_kind": {"window_seconds": 60, "max_hits": 300},
                "join_flow": {"window_seconds": 300, "max_hits": 10},
                "join_flow_per_ip": {"window_seconds": 300, "max_hits": 30}
            },
            "req": {
                "per_ip": {"window_seconds": 60, "max_hits": 600},
                "per_connection": {"window_seconds": 60, "max_hits": 120},
                "per_pubkey": {"window_seconds": 60, "max_hits": 240},
                "per_group": {"window_seconds": 60, "max_hits": 240},
                "per_kind": {"window_seconds": 60, "max_hits": 500},
                "broad": {"window_seconds": 60, "max_hits": 30}
            },
            "count": {
                "per_ip": {"window_seconds": 60, "max_hits": 300},
                "per_connection": {"window_seconds": 60, "max_hits": 60},
                "per_pubkey": {"window_seconds": 60, "max_hits": 120},
                "per_group": {"window_seconds": 60, "max_hits": 120},
                "per_kind": {"window_seconds": 60, "max_hits": 240},
                "broad": {"window_seconds": 60, "max_hits": 20}
            }
        }
    })
    .to_string();
    parse_base_relay_runtime_config_json(&raw).map_err(|error| error.to_string())
}

fn bench_temp_root(run_name: &str) -> PathBuf {
    let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "tangle-bench-{run_name}-{}-{id}",
        std::process::id()
    ))
}

fn subscription(value: &str) -> Result<SubscriptionId, String> {
    SubscriptionId::new(value).map_err(|error| error.to_string())
}

fn ok_accepted(message: &RelayMessage) -> bool {
    matches!(message, RelayMessage::Ok { accepted: true, .. })
}

fn estimate_memory_bytes(dataset: &BenchDataset) -> u64 {
    let event_bytes = dataset
        .source_events()
        .iter()
        .map(|source| {
            serde_json::to_string(&event_to_value(source.event()))
                .unwrap_or_default()
                .len()
        })
        .sum::<usize>();
    let projection_bytes = dataset.groups().len() * 512
        + usize::try_from(dataset.membership_event_count()).expect("member count fits in usize")
            * 192;
    (event_bytes + projection_bytes)
        .try_into()
        .expect("estimated memory fits in u64")
}

fn percentile(samples: &[u64], percentile: u64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let last = samples.len() - 1;
    let index = (last as u64 * percentile).div_ceil(100);
    samples[usize::try_from(index).expect("percentile index fits in usize")]
}

fn elapsed_micros(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros())
        .unwrap_or(u64::MAX)
        .max(1)
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
        BenchDataset, BenchDatasetConfig, BenchGroupVisibility, BenchmarkProfile,
        BenchmarkProfileName, BenchmarkRunReport, BenchmarkThresholds, POCKET_SOURCE_REPOSITORY,
        POCKET_SOURCE_REVISION, SCENARIO_BROADCAST_LAG, SCENARIO_COUNT_RESOURCE_CONTROLS,
        SCENARIO_GROUP_READ_GATE_OVERHEAD, SCENARIO_MEMORY_PROFILE, SCENARIO_OUTBOX_REPLAY,
        SCENARIO_POCKET_QUERY_VISIBLE_EVENTS, SCENARIO_PROJECTION_REBUILD, ScenarioReport,
        generated_state_counts, materialize_dataset,
    };
    use std::collections::BTreeSet;
    use tangle_groups::{GroupId, KIND_GROUP_ADMINS, KIND_GROUP_MEMBERS, KIND_GROUP_METADATA};

    #[test]
    fn deterministic_dataset_generator_produces_stable_group_events() {
        let first =
            BenchDataset::generate(BenchDatasetConfig::new(3, 2, 2, 2, 2)).expect("first dataset");
        let second =
            BenchDataset::generate(BenchDatasetConfig::new(3, 2, 2, 2, 2)).expect("second dataset");
        let first_ids = first
            .source_events()
            .into_iter()
            .map(|source| source.event().id().as_str().to_owned())
            .collect::<Vec<_>>();
        let second_ids = second
            .source_events()
            .into_iter()
            .map(|source| source.event().id().as_str().to_owned())
            .collect::<Vec<_>>();
        let unique_ids = first_ids.iter().cloned().collect::<BTreeSet<_>>();

        assert_eq!(first_ids, second_ids);
        assert_eq!(first.groups().len(), 3);
        assert_eq!(first.source_event_count(), 17);
        assert_eq!(first.group_event_count(), 15);
        assert_eq!(first.membership_event_count(), 6);
        assert_eq!(unique_ids.len(), first_ids.len());
        assert_eq!(
            first
                .groups()
                .iter()
                .map(|group| group.visibility())
                .collect::<Vec<_>>(),
            vec![
                BenchGroupVisibility::Public,
                BenchGroupVisibility::Private,
                BenchGroupVisibility::Hidden
            ]
        );
        assert_eq!(
            first.dataset_digest().expect("first digest"),
            second.dataset_digest().expect("second digest")
        );
        assert_eq!(
            first.source_events_jsonl().expect("jsonl").lines().count(),
            usize::try_from(first.source_event_count()).expect("count fits")
        );
    }

    #[test]
    fn dataset_config_rejects_benchmark_shapes_without_privacy_coverage() {
        assert!(BenchDataset::generate(BenchDatasetConfig::new(2, 1, 1, 0, 1)).is_err());
        assert!(BenchDataset::generate(BenchDatasetConfig::new(3, 0, 1, 0, 1)).is_err());
        assert!(BenchDataset::generate(BenchDatasetConfig::new(3, 1, 0, 0, 1)).is_err());
        assert!(BenchDataset::generate(BenchDatasetConfig::new(3, 1, 1, 0, 0)).is_err());
    }

    #[test]
    fn materialized_dataset_populates_generated_group_state() {
        let dataset =
            BenchDataset::generate(BenchDatasetConfig::new(3, 1, 1, 1, 1)).expect("dataset");
        let materialized = materialize_dataset(&dataset, "test-generated-state", 16)
            .expect("materialized dataset");
        let counts = generated_state_counts(&materialized.relay).expect("state counts");

        assert_eq!(counts.metadata, 3);
        assert_eq!(counts.admins, 3);
        assert_eq!(counts.members, 3);
        assert_eq!(
            super::count_kind(&materialized.relay, KIND_GROUP_METADATA).expect("metadata"),
            3
        );
        assert_eq!(
            super::count_kind(&materialized.relay, KIND_GROUP_ADMINS).expect("admins"),
            3
        );
        assert_eq!(
            super::count_kind(&materialized.relay, KIND_GROUP_MEMBERS).expect("members"),
            3
        );
    }

    #[test]
    fn benchmark_suite_runs_all_required_v2_scenarios() {
        let report = BenchmarkRunReport::run(smoke_profile(BenchDatasetConfig::new(3, 1, 1, 2, 1)))
            .expect("report");

        for name in [
            SCENARIO_POCKET_QUERY_VISIBLE_EVENTS,
            SCENARIO_GROUP_READ_GATE_OVERHEAD,
            SCENARIO_COUNT_RESOURCE_CONTROLS,
            SCENARIO_PROJECTION_REBUILD,
            SCENARIO_OUTBOX_REPLAY,
            SCENARIO_BROADCAST_LAG,
            SCENARIO_MEMORY_PROFILE,
        ] {
            let scenario = report.scenario(name).expect("scenario");
            assert_eq!(scenario.rejected, 0, "{name} rejected operations");
            assert_eq!(scenario.accepted, scenario.attempted, "{name} acceptance");
            assert!(scenario.elapsed_micros > 0, "{name} elapsed");
        }
        assert_eq!(report.dataset_profile().groups, 3);
        assert_eq!(report.validation_summary().len(), 7);
        assert!(
            report
                .validation_summary()
                .values()
                .all(|status| status == "pass")
        );
    }

    #[test]
    fn local_smoke_profiles_run_without_hardware_evidence() {
        for profile in [BenchmarkProfile::smoke(), BenchmarkProfile::large_smoke()] {
            assert!(!profile.requires_target_hardware_evidence());
            let report = BenchmarkRunReport::run(profile).expect("local profile report");
            assert!(
                report
                    .validation_summary()
                    .values()
                    .all(|status| status == "pass")
            );
        }
    }

    #[test]
    fn protocol_conversion_for_supported_profile_sizes_is_bounded() {
        let dataset =
            BenchDataset::generate(BenchDatasetConfig::new(4, 3, 3, 4, 3)).expect("dataset");
        let mut total_event_json_bytes = 0_usize;
        for source in dataset.source_events() {
            let event_json = tangle_protocol::event_to_value(source.event()).to_string();
            total_event_json_bytes += event_json.len();
            assert!(
                tangle_protocol::parse_client_message(&format!("[\"EVENT\",{event_json}]")).is_ok()
            );
        }

        assert!(total_event_json_bytes < 1_000_000);
    }

    #[test]
    fn benchmark_profiles_are_explicit_and_unknown_profiles_fail_closed() {
        assert_eq!(
            BenchmarkProfileName::all()
                .iter()
                .map(|profile| profile.as_str())
                .collect::<Vec<_>>(),
            vec![
                "smoke",
                "medium",
                "large-smoke",
                "proof-10m",
                "proof-large-group",
                "proof-join-storm",
                "proof-slow-client"
            ]
        );
        assert_eq!(
            BenchmarkProfileName::parse("smoke")
                .expect("smoke")
                .as_str(),
            "smoke"
        );
        assert_eq!(
            BenchmarkProfileName::parse("medium")
                .expect("medium")
                .as_str(),
            "medium"
        );
        assert_eq!(
            BenchmarkProfileName::parse("large-smoke")
                .expect("large-smoke")
                .as_str(),
            "large-smoke"
        );
        assert!(BenchmarkProfileName::parse("production").is_err());
        assert!(
            BenchmarkProfileName::parse("local")
                .expect_err("unknown")
                .contains("unknown benchmark profile")
        );
        assert_eq!(
            BenchmarkProfile::smoke().dataset_config(),
            BenchDatasetConfig::smoke()
        );
        assert_eq!(
            BenchmarkProfile::medium().dataset_config(),
            BenchDatasetConfig::medium()
        );
        assert_eq!(
            BenchmarkProfile::large_smoke().dataset_config(),
            BenchDatasetConfig::large_smoke()
        );
        assert_eq!(
            BenchmarkProfile::proof_10m().dataset_config(),
            BenchDatasetConfig::proof_10m()
        );
        assert_eq!(
            BenchmarkProfile::proof_large_group().dataset_config(),
            BenchDatasetConfig::proof_large_group()
        );
        assert_eq!(
            BenchmarkProfile::proof_join_storm().dataset_config(),
            BenchDatasetConfig::proof_join_storm()
        );
        assert_eq!(
            BenchmarkProfile::proof_slow_client().dataset_config(),
            BenchDatasetConfig::proof_slow_client()
        );
    }

    #[test]
    fn proof_profile_dataset_definitions_are_hardware_scale_without_materialization() {
        assert_eq!(
            BenchDatasetConfig::proof_10m().estimated_source_event_count(),
            10_000_000
        );
        assert_eq!(
            BenchDatasetConfig::proof_large_group().member_count,
            100_000
        );
        assert_eq!(
            BenchDatasetConfig::proof_join_storm().group_count
                * BenchDatasetConfig::proof_join_storm().member_count,
            1_000_000
        );
        assert_eq!(BenchDatasetConfig::proof_slow_client().group_count, 50_000);
        for profile in [
            BenchmarkProfile::proof_10m(),
            BenchmarkProfile::proof_large_group(),
            BenchmarkProfile::proof_join_storm(),
            BenchmarkProfile::proof_slow_client(),
        ] {
            assert!(profile.requires_target_hardware_evidence());
            assert!(profile.validate_for_run().is_err());
            assert!(!profile.proof_claim_eligible());
            assert!(profile.dataset_config().validate().is_ok());
        }
    }

    #[test]
    fn benchmark_threshold_json_rejects_missing_unknown_or_zero_fields() {
        let valid = BenchmarkThresholds::from_json_value(&BenchmarkThresholds::smoke().to_json())
            .expect("valid thresholds");
        assert_eq!(valid, BenchmarkThresholds::smoke());

        let missing = serde_json::json!({
            "pocket_query_p95_micros": 1,
            "read_gate_p95_micros": 1,
            "count_resource_controls_p95_micros": 1,
            "projection_rebuild_elapsed_micros": 1,
            "outbox_replay_elapsed_micros": 1,
            "broadcast_lag_p95_micros": 1
        });
        assert!(
            BenchmarkThresholds::from_json_value(&missing)
                .expect_err("missing")
                .contains("memory_profile_max_bytes")
        );

        let unknown = serde_json::json!({
            "pocket_query_p95_micros": 1,
            "read_gate_p95_micros": 1,
            "count_resource_controls_p95_micros": 1,
            "projection_rebuild_elapsed_micros": 1,
            "outbox_replay_elapsed_micros": 1,
            "broadcast_lag_p95_micros": 1,
            "memory_profile_max_bytes": 1,
            "extra": 1
        });
        assert!(
            BenchmarkThresholds::from_json_value(&unknown)
                .expect_err("unknown")
                .contains("unknown benchmark threshold field")
        );

        let zero = serde_json::json!({
            "pocket_query_p95_micros": 0,
            "read_gate_p95_micros": 1,
            "count_resource_controls_p95_micros": 1,
            "projection_rebuild_elapsed_micros": 1,
            "outbox_replay_elapsed_micros": 1,
            "broadcast_lag_p95_micros": 1,
            "memory_profile_max_bytes": 1
        });
        assert!(
            BenchmarkThresholds::from_json_value(&zero)
                .expect_err("zero")
                .contains("greater than zero")
        );
    }

    #[test]
    fn proof_claim_eligibility_requires_manual_proof_profile() {
        assert!(!BenchmarkProfile::smoke().proof_claim_eligible());
        assert!(
            !BenchmarkProfile::smoke()
                .with_target_hardware_evidence("target-hardware:ci")
                .expect("evidence")
                .proof_claim_eligible()
        );
        assert!(!BenchmarkProfile::large_smoke().proof_claim_eligible());
        assert!(
            !BenchmarkProfile::large_smoke()
                .with_target_hardware_evidence("target-hardware:bench-node-001")
                .expect("evidence")
                .proof_claim_eligible()
        );
        assert!(!BenchmarkProfile::proof_10m().proof_claim_eligible());
        assert!(
            BenchmarkProfile::proof_10m()
                .with_target_hardware_evidence("target-hardware:proof-node-001")
                .expect("evidence")
                .proof_claim_eligible()
        );
    }

    #[test]
    fn proof_profile_runs_fail_closed_without_hardware_evidence() {
        for profile in [
            BenchmarkProfile::proof_10m(),
            BenchmarkProfile::proof_large_group(),
            BenchmarkProfile::proof_join_storm(),
            BenchmarkProfile::proof_slow_client(),
        ] {
            let error =
                BenchmarkRunReport::run(profile).expect_err("proof profile requires evidence");

            assert!(error.contains("target hardware evidence is required"));
        }
    }

    #[test]
    fn benchmark_threshold_validation_rejects_missing_or_failed_scenarios() {
        let scenarios = vec![
            passing_scenario(SCENARIO_POCKET_QUERY_VISIBLE_EVENTS),
            ScenarioReport::new(
                SCENARIO_GROUP_READ_GATE_OVERHEAD,
                1,
                1,
                0,
                10,
                vec![BenchmarkThresholds::smoke().read_gate_p95_micros + 1],
                128,
            ),
            passing_scenario(SCENARIO_COUNT_RESOURCE_CONTROLS),
            passing_scenario(SCENARIO_PROJECTION_REBUILD),
            passing_scenario(SCENARIO_OUTBOX_REPLAY),
            passing_scenario(SCENARIO_BROADCAST_LAG),
            passing_scenario(SCENARIO_MEMORY_PROFILE),
        ];
        let failed =
            super::validation_summary(&scenarios, BenchmarkThresholds::smoke()).expect_err("fail");
        assert!(failed.contains(SCENARIO_GROUP_READ_GATE_OVERHEAD));

        let missing = super::validation_summary(
            &scenarios[..scenarios.len() - 1],
            BenchmarkThresholds::smoke(),
        )
        .expect_err("missing");
        assert!(missing.contains(SCENARIO_MEMORY_PROFILE));
    }

    #[test]
    fn benchmark_summary_json_matches_report_template_surface() {
        let report = BenchmarkRunReport::run(smoke_profile(BenchDatasetConfig::new(3, 1, 1, 1, 1)))
            .expect("report");
        let summary = report.summary_json("unit-run", std::path::Path::new(".local/unit"));

        assert_eq!(summary["schema"], 2);
        assert_eq!(summary["run_id"], "unit-run");
        assert_eq!(summary["profile"], "smoke");
        assert_eq!(summary["threshold_source"], "builtin:smoke");
        assert_eq!(
            summary["pocket_source"]["repository"],
            POCKET_SOURCE_REPOSITORY
        );
        assert_eq!(summary["pocket_source"]["revision"], POCKET_SOURCE_REVISION);
        assert_eq!(summary["proof_claim"]["eligible"], false);
        assert_eq!(summary["proof_claim"]["target_hardware_evidence"], "absent");
        assert_eq!(
            summary["dataset"]["fixture_family"],
            "synthetic repo-owned fixtures"
        );
        assert_eq!(
            summary["dataset_profile"]["fixture_family"],
            "synthetic repo-owned fixtures"
        );
        assert_eq!(summary["scenarios"].as_array().expect("scenarios").len(), 7);
        let first_scenario = &summary["scenarios"]
            .as_array()
            .expect("scenarios")
            .first()
            .expect("first scenario");
        assert_eq!(first_scenario["status"], "pass");
        assert!(first_scenario["p50_micros"].as_u64().expect("p50") > 0);
        assert!(first_scenario["p95_micros"].as_u64().expect("p95") > 0);
        assert!(first_scenario["p99_micros"].as_u64().expect("p99") > 0);
        assert!(
            first_scenario["query_metrics"]["candidates_scanned"]
                .as_u64()
                .expect("candidates")
                > 0
        );
        assert!(
            first_scenario["query_metrics"]["events_returned"]
                .as_u64()
                .expect("returned")
                > 0
        );
        assert!(
            first_scenario["memory"]["max_rss_bytes"]
                .as_u64()
                .expect("memory")
                > 0
        );
        assert_eq!(
            summary["validation_summary"][SCENARIO_POCKET_QUERY_VISIBLE_EVENTS],
            "pass"
        );
        assert_eq!(summary["pass_fail_summary"]["overall_status"], "pass");
        assert!(
            summary["thresholds"]["read_gate_p95_micros"]
                .as_u64()
                .expect("threshold")
                > 0
        );
        assert_eq!(
            summary["artifacts"]["dataset_events_jsonl"],
            "dataset-events.jsonl"
        );
    }

    #[test]
    fn count_resource_controls_scenario_accepts_bounded_counts_and_refuses_broad_counts() {
        let dataset =
            BenchDataset::generate(BenchDatasetConfig::new(3, 101, 101, 0, 1)).expect("dataset");
        let scenario =
            super::run_count_resource_control_benchmark(&dataset).expect("count controls");

        assert_eq!(scenario.scenario, SCENARIO_COUNT_RESOURCE_CONTROLS);
        assert_eq!(scenario.attempted, 5);
        assert_eq!(scenario.accepted, scenario.attempted);
        assert_eq!(scenario.rejected, 0);
    }

    #[test]
    fn benchmark_pocket_source_matches_store_boundary() {
        assert_eq!(
            POCKET_SOURCE_REPOSITORY,
            tangle_store_pocket::POCKET_SOURCE_REPOSITORY
        );
        assert_eq!(
            POCKET_SOURCE_REVISION,
            tangle_store_pocket::POCKET_SOURCE_REVISION
        );
    }

    #[test]
    fn projection_rebuild_scenario_recreates_groups_and_members() {
        let dataset =
            BenchDataset::generate(BenchDatasetConfig::new(3, 1, 1, 0, 2)).expect("dataset");
        let scenario = super::run_projection_rebuild_benchmark(&dataset).expect("rebuild");

        assert_eq!(scenario.scenario, SCENARIO_PROJECTION_REBUILD);
        assert_eq!(scenario.accepted, 1);
        assert_eq!(scenario.rejected, 0);
    }

    #[test]
    fn outbox_replay_scenario_keeps_generated_state_idempotent() {
        let dataset =
            BenchDataset::generate(BenchDatasetConfig::new(3, 1, 1, 0, 1)).expect("dataset");
        let scenario = super::run_outbox_replay_benchmark(&dataset).expect("outbox");

        assert_eq!(scenario.scenario, SCENARIO_OUTBOX_REPLAY);
        assert_eq!(scenario.accepted, 1);
        assert_eq!(scenario.rejected, 0);
    }

    #[test]
    fn broadcast_lag_scenario_keeps_healthy_subscriptions_open() {
        let dataset =
            BenchDataset::generate(BenchDatasetConfig::new(3, 1, 1, 0, 1)).expect("dataset");
        let scenario = super::run_broadcast_lag_benchmark(&dataset).expect("lag");

        assert_eq!(scenario.scenario, SCENARIO_BROADCAST_LAG);
        assert_eq!(scenario.accepted, scenario.attempted);
        assert_eq!(scenario.rejected, 0);
    }

    #[test]
    fn percentile_helper_handles_empty_and_sorted_samples() {
        assert_eq!(super::percentile(&[], 95), 0);
        assert_eq!(super::percentile(&[1, 2, 3, 4, 5], 50), 3);
        assert_eq!(super::percentile(&[1, 2, 3, 4, 5], 95), 5);
        assert_eq!(super::lower_hex(&[0, 15, 16, 255]), "000f10ff");
    }

    #[test]
    fn group_id_helper_accepts_dataset_group_names() {
        let dataset =
            BenchDataset::generate(BenchDatasetConfig::new(3, 1, 1, 0, 1)).expect("dataset");

        for group in dataset.groups() {
            GroupId::new(group.id()).expect("group id");
        }
    }

    fn passing_scenario(name: &str) -> ScenarioReport {
        ScenarioReport::new(name, 1, 1, 0, 10, vec![1], 128)
    }

    fn smoke_profile(config: BenchDatasetConfig) -> BenchmarkProfile {
        BenchmarkProfile::smoke()
            .with_dataset_config(config)
            .expect("smoke profile")
    }
}
