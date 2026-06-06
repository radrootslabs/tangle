#![forbid(unsafe_code)]

use std::time::Instant;
use tangle_protocol::{Event, filter_from_value};
use tangle_store::{StoreEventOutcome, StoredEvent};
use tangle_store_surreal::{
    ListingCurrentOutcome, ListingProjectionQuery, SearchDocumentOutcome, SearchDocumentQuery,
    SurrealConnectionConfig, SurrealStore, base_migration_plan,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchWorkloadReport {
    pub indexed: u64,
    pub carrot_results: u64,
    pub browse_results: u64,
}

pub async fn run_search_workload(dataset: &BenchDataset) -> Result<SearchWorkloadReport, String> {
    let materialized = materialize_listing_workload(dataset).await?;
    let store = materialized.store();
    let mut indexed = 0;
    for event in dataset.listings() {
        if store
            .index_listing_search_document(event)
            .await
            .map_err(|error| error.to_string())?
            == SearchDocumentOutcome::Indexed
        {
            indexed += 1;
        }
    }
    let carrot_results = store
        .query_search_documents(
            &SearchDocumentQuery::new()
                .with_text("carrots")
                .with_doc_type("listing")
                .with_visible(true),
        )
        .await
        .map_err(|error| error.to_string())?
        .len() as u64;
    let browse_results = store
        .query_search_documents(
            &SearchDocumentQuery::new()
                .with_doc_type("listing")
                .with_visible(true)
                .with_limit(5),
        )
        .await
        .map_err(|error| error.to_string())?
        .len() as u64;
    Ok(SearchWorkloadReport {
        indexed,
        carrot_results,
        browse_results,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenericRelayWorkloadReport {
    pub attempted: u64,
    pub inserted: u64,
    pub note_results: u64,
    pub all_results: u64,
}

pub async fn run_generic_relay_workload(
    dataset: &BenchDataset,
) -> Result<GenericRelayWorkloadReport, String> {
    let store = bench_memory_store("generic_relay_workload").await?;
    let events = dataset.events();
    let mut inserted = 0;
    for event in &events {
        if store
            .store_raw_event(&StoredEvent::new(
                event.clone(),
                event.unsigned().created_at(),
            ))
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
    }
    let note_filter = filter_from_value(&serde_json::json!({
        "kinds": [1],
        "limit": dataset.notes().len()
    }))?;
    let note_results = store
        .query_raw_events(&note_filter)
        .await
        .map_err(|error| error.to_string())?
        .len() as u64;
    let all_results = store
        .query_raw_events(&tangle_protocol::Filter::empty())
        .await
        .map_err(|error| error.to_string())?
        .len() as u64;
    Ok(GenericRelayWorkloadReport {
        attempted: events.len() as u64,
        inserted,
        note_results,
        all_results,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestBenchmarkReport {
    pub attempted: u64,
    pub inserted: u64,
    pub elapsed_micros: u128,
}

pub async fn run_ingest_benchmark(
    config: BenchDatasetConfig,
) -> Result<IngestBenchmarkReport, String> {
    let dataset = BenchDataset::generate(config)?;
    let started = Instant::now();
    let report = run_generic_relay_workload(&dataset).await?;
    Ok(IngestBenchmarkReport {
        attempted: report.attempted,
        inserted: report.inserted,
        elapsed_micros: started.elapsed().as_micros(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListingQueryBenchmarkReport {
    pub listing_rows: u64,
    pub limited_rows: u64,
    pub elapsed_micros: u128,
}

pub async fn run_listing_query_benchmark(
    config: BenchDatasetConfig,
) -> Result<ListingQueryBenchmarkReport, String> {
    let dataset = BenchDataset::generate(config)?;
    let materialized = materialize_listing_workload(&dataset).await?;
    let started = Instant::now();
    let listing_rows = materialized
        .store()
        .query_current_listings(&ListingProjectionQuery::new().with_effective_status("active"))
        .await
        .map_err(|error| error.to_string())?
        .len() as u64;
    let limited_rows = materialized
        .store()
        .query_current_listings(
            &ListingProjectionQuery::new()
                .with_effective_status("active")
                .with_limit(7),
        )
        .await
        .map_err(|error| error.to_string())?
        .len() as u64;
    Ok(ListingQueryBenchmarkReport {
        listing_rows,
        limited_rows,
        elapsed_micros: started.elapsed().as_micros(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchBenchmarkReport {
    pub indexed: u64,
    pub text_results: u64,
    pub browse_results: u64,
    pub elapsed_micros: u128,
}

pub async fn run_search_benchmark(
    config: BenchDatasetConfig,
) -> Result<SearchBenchmarkReport, String> {
    let dataset = BenchDataset::generate(config)?;
    let materialized = materialize_listing_workload(&dataset).await?;
    let store = materialized.store();
    let mut indexed = 0;
    for event in dataset.listings() {
        if store
            .index_listing_search_document(event)
            .await
            .map_err(|error| error.to_string())?
            == SearchDocumentOutcome::Indexed
        {
            indexed += 1;
        }
    }
    let started = Instant::now();
    let text_results = store
        .query_search_documents(
            &SearchDocumentQuery::new()
                .with_text("carrots")
                .with_doc_type("listing")
                .with_visible(true),
        )
        .await
        .map_err(|error| error.to_string())?
        .len() as u64;
    let browse_results = store
        .query_search_documents(
            &SearchDocumentQuery::new()
                .with_doc_type("listing")
                .with_visible(true)
                .with_limit(9),
        )
        .await
        .map_err(|error| error.to_string())?
        .len() as u64;
    Ok(SearchBenchmarkReport {
        indexed,
        text_results,
        browse_results,
        elapsed_micros: started.elapsed().as_micros(),
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

    #[tokio::test]
    async fn search_workload_indexes_and_queries_listing_documents() {
        let dataset = BenchDataset::generate(BenchDatasetConfig::new(12, 2)).expect("dataset");
        let report = super::run_search_workload(&dataset)
            .await
            .expect("search workload");

        assert_eq!(
            report,
            super::SearchWorkloadReport {
                indexed: 12,
                carrot_results: 12,
                browse_results: 5
            }
        );
    }

    #[tokio::test]
    async fn generic_relay_workload_stores_and_queries_non_marketplace_events() {
        let dataset = BenchDataset::generate(BenchDatasetConfig::new(5, 7)).expect("dataset");
        let report = super::run_generic_relay_workload(&dataset)
            .await
            .expect("generic workload");

        assert_eq!(
            report,
            super::GenericRelayWorkloadReport {
                attempted: 12,
                inserted: 12,
                note_results: 7,
                all_results: 12
            }
        );
    }

    #[tokio::test]
    async fn ingest_benchmark_reports_deterministic_event_counts() {
        let report = super::run_ingest_benchmark(BenchDatasetConfig::new(6, 4))
            .await
            .expect("ingest benchmark");

        assert_eq!(report.attempted, 10);
        assert_eq!(report.inserted, 10);
        assert!(report.elapsed_micros > 0);
    }

    #[tokio::test]
    async fn listing_query_benchmark_reports_deterministic_row_counts() {
        let report = super::run_listing_query_benchmark(BenchDatasetConfig::new(18, 0))
            .await
            .expect("listing query benchmark");

        assert_eq!(report.listing_rows, 18);
        assert_eq!(report.limited_rows, 7);
        assert!(report.elapsed_micros > 0);
    }

    #[tokio::test]
    async fn search_benchmark_reports_deterministic_query_counts() {
        let report = super::run_search_benchmark(BenchDatasetConfig::new(16, 0))
            .await
            .expect("search benchmark");

        assert_eq!(report.indexed, 16);
        assert_eq!(report.text_results, 16);
        assert_eq!(report.browse_results, 9);
        assert!(report.elapsed_micros > 0);
    }
}
