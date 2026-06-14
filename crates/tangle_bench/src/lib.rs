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
    Event, Filter, RelayMessage, SubscriptionId, event_to_value, filter_from_value,
};
use tangle_runtime::relay::{
    auth::BaseAuthState,
    core::{BaseRelay, BaseRelayLimitSettings, BaseRelayLimits},
};
use tangle_store_pocket::{PocketStoreConfig, PocketSyncPolicy};
use tangle_test_support::{
    FixtureKey, TANGLE_V2_RELAY_URL, tangle_v2_auth_event, tangle_v2_event, tangle_v2_group_config,
    tangle_v2_group_create_event, tangle_v2_group_event, tangle_v2_put_user_event, tangle_v2_tag,
};

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

pub const SCENARIO_POCKET_QUERY_VISIBLE_EVENTS: &str = "pocket_query_visible_events";
pub const SCENARIO_GROUP_READ_GATE_OVERHEAD: &str = "group_read_gate_overhead";
pub const SCENARIO_PROJECTION_REBUILD: &str = "projection_rebuild";
pub const SCENARIO_OUTBOX_REPLAY: &str = "outbox_replay";
pub const SCENARIO_BROADCAST_LAG: &str = "broadcast_lag";
pub const SCENARIO_MEMORY_PROFILE: &str = "memory_profile";

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
            "attempted": self.attempted,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "elapsed_micros": self.elapsed_micros,
            "events_per_second": self.events_per_second,
            "p50_micros": self.p50_micros,
            "p95_micros": self.p95_micros,
            "p99_micros": self.p99_micros,
            "max_rss_bytes": self.max_rss_bytes
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BenchmarkThresholds {
    pub pocket_query_p95_micros: u64,
    pub read_gate_p95_micros: u64,
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
            projection_rebuild_elapsed_micros: 5_000_000,
            outbox_replay_elapsed_micros: 5_000_000,
            broadcast_lag_p95_micros: 1_000_000,
            memory_profile_max_bytes: 512 * 1024 * 1024,
        }
    }

    fn to_json(self) -> serde_json::Value {
        json!({
            "pocket_query_p95_micros": self.pocket_query_p95_micros,
            "read_gate_p95_micros": self.read_gate_p95_micros,
            "projection_rebuild_elapsed_micros": self.projection_rebuild_elapsed_micros,
            "outbox_replay_elapsed_micros": self.outbox_replay_elapsed_micros,
            "broadcast_lag_p95_micros": self.broadcast_lag_p95_micros,
            "memory_profile_max_bytes": self.memory_profile_max_bytes
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BenchmarkRunReport {
    dataset: BenchDataset,
    dataset_profile: DatasetProfile,
    scenarios: Vec<ScenarioReport>,
    thresholds: BenchmarkThresholds,
    validation_summary: BTreeMap<String, String>,
}

impl BenchmarkRunReport {
    pub fn run(config: BenchDatasetConfig) -> Result<Self, String> {
        let dataset = BenchDataset::generate(config)?;
        let thresholds = BenchmarkThresholds::smoke();
        let pocket_query = run_pocket_query_benchmark(&dataset)?;
        let read_gate = run_read_gate_benchmark(&dataset)?;
        let projection_rebuild = run_projection_rebuild_benchmark(&dataset)?;
        let outbox_replay = run_outbox_replay_benchmark(&dataset)?;
        let broadcast_lag = run_broadcast_lag_benchmark(&dataset)?;
        let memory_profile = run_memory_profile_benchmark(&dataset)?;
        let scenarios = vec![
            pocket_query,
            read_gate,
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
            scenarios,
            thresholds,
            validation_summary,
        })
    }

    pub fn dataset(&self) -> &BenchDataset {
        &self.dataset
    }

    pub fn dataset_profile(&self) -> &DatasetProfile {
        &self.dataset_profile
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
            "schema": 1,
            "run_id": run_id,
            "artifact_directory": artifact_directory.to_string_lossy(),
            "dataset": self.dataset_profile.to_json(),
            "scenarios": self.scenarios.iter().map(ScenarioReport::to_json).collect::<Vec<_>>(),
            "thresholds": self.thresholds.to_json(),
            "validation_summary": self.validation_summary,
            "artifacts": {
                "summary_json": "summary.json",
                "dataset_events_jsonl": "dataset-events.jsonl"
            }
        })
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
    )
    .map_err(|error| error.to_string())?;
    let after_first = generated_state_counts(&reopened)?;
    reopened.shutdown().map_err(|error| error.to_string())?;
    let reopened = BaseRelay::open_with_groups(
        &materialized.store_config,
        relay_limits(128),
        &group_config()?,
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
    let closed = second_messages
        .iter()
        .filter(|message| matches!(message, RelayMessage::Closed { .. }))
        .count();
    let accepted = if first_events == subscriber_count
        && closed == subscriber_count
        && materialized.relay.active_subscription_count() == 0
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

fn materialize_dataset(
    dataset: &BenchDataset,
    run_name: &str,
    max_pending_events: usize,
) -> Result<MaterializedBenchRelay, String> {
    let store_config = bench_store_config(run_name)?;
    let mut relay = BaseRelay::open_with_groups(
        &store_config,
        relay_limits(max_pending_events),
        &group_config()?,
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
        let message = match source.auth() {
            BenchEventAuth::None => relay
                .handle_event(source.event().clone())
                .map_err(|error| error.to_string())?,
            BenchEventAuth::Owner => relay
                .handle_event_with_auth(source.event().clone(), &owner_auth)
                .map_err(|error| error.to_string())?,
            BenchEventAuth::Admin => relay
                .handle_event_with_auth(source.event().clone(), &admin_auth)
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
    let message = match operation.auth {
        QueryAuth::None => relay
            .handle_count(subscription_id, vec![operation.filter.clone()])
            .map_err(|error| error.to_string())?,
        QueryAuth::Owner => relay
            .handle_count_with_auth(subscription_id, vec![operation.filter.clone()], owner_auth)
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
            vec![filter_from_value(&json!({"kinds": [kind]}))?],
            &owner_auth,
        )
        .map_err(|error| error.to_string())?;
    match message {
        RelayMessage::Count { count, .. } => Ok(count),
        value => Err(format!("expected COUNT message, got {value:?}")),
    }
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
    PocketStoreConfig::new(
        root.join("pocket"),
        1024 * 1024 * 1024,
        128,
        PocketSyncPolicy::FlushOnShutdown,
    )
    .map_err(|error| error.to_string())
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
        BenchDataset, BenchDatasetConfig, BenchGroupVisibility, BenchmarkRunReport,
        BenchmarkThresholds, SCENARIO_BROADCAST_LAG, SCENARIO_GROUP_READ_GATE_OVERHEAD,
        SCENARIO_MEMORY_PROFILE, SCENARIO_OUTBOX_REPLAY, SCENARIO_POCKET_QUERY_VISIBLE_EVENTS,
        SCENARIO_PROJECTION_REBUILD, ScenarioReport, generated_state_counts, materialize_dataset,
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
        let report =
            BenchmarkRunReport::run(BenchDatasetConfig::new(3, 1, 1, 2, 1)).expect("report");

        for name in [
            SCENARIO_POCKET_QUERY_VISIBLE_EVENTS,
            SCENARIO_GROUP_READ_GATE_OVERHEAD,
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
        assert_eq!(report.validation_summary().len(), 6);
        assert!(
            report
                .validation_summary()
                .values()
                .all(|status| status == "pass")
        );
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
        let report =
            BenchmarkRunReport::run(BenchDatasetConfig::new(3, 1, 1, 1, 1)).expect("report");
        let summary = report.summary_json("unit-run", std::path::Path::new(".local/unit"));

        assert_eq!(summary["schema"], 1);
        assert_eq!(summary["run_id"], "unit-run");
        assert_eq!(
            summary["dataset"]["fixture_family"],
            "synthetic repo-owned fixtures"
        );
        assert_eq!(summary["scenarios"].as_array().expect("scenarios").len(), 6);
        assert_eq!(
            summary["validation_summary"][SCENARIO_POCKET_QUERY_VISIBLE_EVENTS],
            "pass"
        );
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
    fn broadcast_lag_scenario_closes_slow_subscriptions() {
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
}
