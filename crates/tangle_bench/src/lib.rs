#![forbid(unsafe_code)]

use tangle_protocol::Event;
use tangle_store::{StoreEventOutcome, StoredEvent};
use tangle_store_surreal::{
    ListingCurrentOutcome, ListingProjectionQuery, SurrealConnectionConfig, SurrealStore,
    base_migration_plan,
};
use tangle_test_support::{FixtureKey, build_fixture_event_from_parts};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BenchDatasetConfig {
    pub listing_count: usize,
    pub note_count: usize,
}

impl BenchDatasetConfig {
    pub fn new(listing_count: usize, note_count: usize) -> Self {
        Self {
            listing_count,
            note_count,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchDataset {
    listings: Vec<Event>,
    notes: Vec<Event>,
}

impl BenchDataset {
    pub fn generate(config: BenchDatasetConfig) -> Result<Self, String> {
        let mut listings = Vec::with_capacity(config.listing_count);
        for index in 0..config.listing_count {
            listings.push(bench_listing(index)?);
        }
        let mut notes = Vec::with_capacity(config.note_count);
        for index in 0..config.note_count {
            notes.push(bench_note(index)?);
        }
        Ok(Self { listings, notes })
    }

    pub fn listings(&self) -> &[Event] {
        &self.listings
    }

    pub fn notes(&self) -> &[Event] {
        &self.notes
    }

    pub fn events(&self) -> Vec<Event> {
        self.listings
            .iter()
            .chain(self.notes.iter())
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListingWorkloadReport {
    pub attempted: u64,
    pub inserted: u64,
    pub projected: u64,
    pub listing_rows: u64,
}

#[derive(Debug, Clone)]
pub struct MaterializedListingWorkload {
    store: SurrealStore,
    report: ListingWorkloadReport,
}

impl MaterializedListingWorkload {
    pub fn store(&self) -> &SurrealStore {
        &self.store
    }

    pub fn report(&self) -> ListingWorkloadReport {
        self.report
    }
}

pub async fn materialize_listing_workload(
    dataset: &BenchDataset,
) -> Result<MaterializedListingWorkload, String> {
    let store = bench_memory_store("listing_workload").await?;
    let mut inserted = 0;
    let mut projected = 0;
    for event in dataset.listings() {
        let now = event.unsigned().created_at();
        if store
            .store_raw_event(&StoredEvent::new(event.clone(), now))
            .await
            .map_err(|error| error.to_string())?
            == StoreEventOutcome::Inserted
        {
            inserted += 1;
        }
        store
            .index_event_tags(event)
            .await
            .map_err(|error| error.to_string())?;
        store
            .maintain_current_event(event)
            .await
            .map_err(|error| error.to_string())?;
        store
            .store_listing_revision(event, now)
            .await
            .map_err(|error| error.to_string())?;
        if store
            .project_current_listing(event, now)
            .await
            .map_err(|error| error.to_string())?
            == ListingCurrentOutcome::Projected
        {
            projected += 1;
        }
        store
            .project_listing_helpers(event)
            .await
            .map_err(|error| error.to_string())?;
    }
    let listing_rows = store
        .query_current_listings(&ListingProjectionQuery::new().with_effective_status("active"))
        .await
        .map_err(|error| error.to_string())?
        .len() as u64;
    Ok(MaterializedListingWorkload {
        store,
        report: ListingWorkloadReport {
            attempted: dataset.listings().len() as u64,
            inserted,
            projected,
            listing_rows,
        },
    })
}

async fn bench_memory_store(database: &str) -> Result<SurrealStore, String> {
    let config = SurrealConnectionConfig::memory("tangle_bench", database)
        .map_err(|error| error.to_string())?;
    let store = SurrealStore::connect_memory(&config)
        .await
        .map_err(|error| error.to_string())?;
    store
        .apply_plan(&base_migration_plan())
        .await
        .map_err(|error| error.to_string())?;
    Ok(store)
}

fn bench_listing(index: usize) -> Result<Event, String> {
    let created_at = 1_714_200_000 + index as u64;
    let price_major = 10 + (index % 50);
    let price_minor = (index * 7) % 100;
    let d = format!("bench-listing-{index:04}");
    let title = format!("Bench carrots {index:04}");
    let content = format!("Deterministic bench listing body {index:04}");
    build_fixture_event_from_parts(
        FixtureKey::Seller,
        created_at,
        30_402,
        vec![
            vec!["d".to_owned(), d],
            vec!["title".to_owned(), title],
            vec![
                "price".to_owned(),
                format!("{price_major}.{price_minor:02}"),
                "USD".to_owned(),
            ],
            vec!["unit".to_owned(), "lb".to_owned()],
            vec!["fulfillment".to_owned(), "pickup".to_owned()],
            vec!["g".to_owned(), format!("c22yzu{}", index % 10)],
            vec!["category".to_owned(), bench_category(index).to_owned()],
            vec!["t".to_owned(), bench_topic(index).to_owned()],
            vec!["practice".to_owned(), "no spray".to_owned()],
            vec!["certification".to_owned(), "organic".to_owned()],
        ],
        &content,
    )
}

fn bench_note(index: usize) -> Result<Event, String> {
    build_fixture_event_from_parts(
        FixtureKey::Buyer,
        1_714_300_000 + index as u64,
        1,
        vec![vec!["t".to_owned(), "bench".to_owned()]],
        &format!("Deterministic generic relay note {index:04}"),
    )
}

fn bench_category(index: usize) -> &'static str {
    match index % 3 {
        0 => "vegetables",
        1 => "fruit",
        _ => "herbs",
    }
}

fn bench_topic(index: usize) -> &'static str {
    match index % 4 {
        0 => "carrots",
        1 => "greens",
        2 => "apples",
        _ => "basil",
    }
}

#[cfg(test)]
mod tests {
    use super::{BenchDataset, BenchDatasetConfig};
    use std::collections::BTreeSet;
    use tangle_nips::{ListingProjectionEvaluation, evaluate_listing_projection};

    #[test]
    fn deterministic_dataset_generator_produces_stable_signed_events() {
        let first = BenchDataset::generate(BenchDatasetConfig::new(4, 2)).expect("first");
        let second = BenchDataset::generate(BenchDatasetConfig::new(4, 2)).expect("second");
        let listing_ids = first
            .listings()
            .iter()
            .map(|event| event.id().as_str())
            .collect::<BTreeSet<_>>();
        let note_ids = first
            .notes()
            .iter()
            .map(|event| event.id().as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            first
                .events()
                .iter()
                .map(|event| event.id().as_str().to_owned())
                .collect::<Vec<_>>(),
            second
                .events()
                .iter()
                .map(|event| event.id().as_str().to_owned())
                .collect::<Vec<_>>()
        );
        assert_eq!(first.listings().len(), 4);
        assert_eq!(first.notes().len(), 2);
        assert_eq!(listing_ids.len(), 4);
        assert_eq!(note_ids.len(), 2);
        assert!(first.listings().iter().all(|event| matches!(
            evaluate_listing_projection(event),
            ListingProjectionEvaluation::Eligible(_)
        )));
        assert!(
            first
                .notes()
                .iter()
                .all(|event| event.unsigned().kind().as_u32() == 1)
        );
    }

    #[tokio::test]
    async fn listing_workload_materializes_projected_listing_rows() {
        let dataset = BenchDataset::generate(BenchDatasetConfig::new(8, 3)).expect("dataset");
        let materialized = super::materialize_listing_workload(&dataset)
            .await
            .expect("listing workload");
        let report = materialized.report();

        assert_eq!(
            report,
            super::ListingWorkloadReport {
                attempted: 8,
                inserted: 8,
                projected: 8,
                listing_rows: 8
            }
        );
        assert_eq!(
            materialized
                .store()
                .query_current_listings(
                    &tangle_store_surreal::ListingProjectionQuery::new()
                        .with_effective_status("active")
                        .with_limit(3)
                )
                .await
                .expect("listing rows")
                .len(),
            3
        );
    }
}
