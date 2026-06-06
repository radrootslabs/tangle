#![forbid(unsafe_code)]

mod support;

use std::fs;
use support::{
    RelayHarness, assert_ok, connect_client, http_get, http_get_admin, next_label, reopen_store,
    request_event_by_id, send_auth, send_event,
};
use tangle_protocol::Event;
use tangle_test_support::{
    FixtureKey, auth_event_spec, build_fixture_event, build_fixture_event_from_parts,
    valid_public_listing_spec,
};

#[tokio::test]
async fn moderation_conformance_projects_labels_reports_and_admin_queries() {
    let seller = FixtureKey::Seller.public_key();
    let admin = FixtureKey::Relay.public_key();
    let harness = RelayHarness::start(
        "moderation_conformance",
        serde_json::json!({
            "admin_pubkeys": [admin.as_str()],
            "approved_sellers": [seller.as_str()]
        }),
    );
    let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
    let label = listing_label(&listing, 1_714_124_440, "reviewed");
    let report = listing_report(&listing, 1_714_124_441, "spam");
    let auth = build_fixture_event(&auth_event_spec()).expect("auth");

    let mut client = connect_client(harness.port).await;
    assert_ok(&send_auth(&mut client, &auth).await, true);
    for event in [&listing, &label, &report] {
        assert_ok(&send_event(&mut client, event).await, true);
    }
    let fetched_label = request_event_by_id(&mut client, "moderation-label", &label).await;
    assert_eq!(fetched_label[0], "EVENT");
    assert_eq!(fetched_label[1], "moderation-label");
    assert_eq!(fetched_label[2]["id"], label.id().as_str());
    assert_eq!(next_label(&mut client).await, "EOSE");
    let fetched_report = request_event_by_id(&mut client, "moderation-report", &report).await;
    assert_eq!(fetched_report[0], "EVENT");
    assert_eq!(fetched_report[1], "moderation-report");
    assert_eq!(fetched_report[2]["id"], report.id().as_str());
    assert_eq!(next_label(&mut client).await, "EOSE");

    let unauthenticated_labels = http_get(
        harness.port,
        &format!(
            "/api/admin/moderation/labels?target_type=event&target_ref={}&namespace=com.radroots.moderation&label=reviewed&limit=5",
            listing.id().as_str()
        ),
    );
    assert!(unauthenticated_labels.contains("401 Unauthorized"));
    let labels = http_get_admin(
        harness.port,
        &format!(
            "/api/admin/moderation/labels?target_type=event&target_ref={}&namespace=com.radroots.moderation&label=reviewed&limit=5",
            listing.id().as_str()
        ),
        admin.as_str(),
    );
    assert!(labels.contains("200 OK"));
    assert!(labels.contains(label.id().as_str()));
    assert!(labels.contains("\"label\":\"reviewed\""));
    let reports = http_get_admin(
        harness.port,
        &format!(
            "/api/admin/moderation/reports?target_type=event&target_ref={}&report_type=spam&limit=5",
            listing.id().as_str()
        ),
        admin.as_str(),
    );
    assert!(reports.contains("200 OK"));
    assert!(reports.contains(report.id().as_str()));
    assert!(reports.contains("\"report_type\":\"spam\""));

    let store_config = harness.store_config();
    let root = harness.root.clone();
    drop(client);
    harness.stop();
    let store = reopen_store(&store_config).await;
    for event in [&listing, &label, &report] {
        assert!(
            store
                .raw_event_row(event.id())
                .await
                .expect("raw row")
                .is_some()
        );
    }
    let label_rows = store
        .label_projection_rows(label.id())
        .await
        .expect("label rows");
    assert_eq!(label_rows.len(), 2);
    let event_label = label_rows
        .iter()
        .find(|row| row["target_type"] == "event")
        .expect("event label");
    assert_eq!(event_label["event_id"], label.id().as_str());
    assert_eq!(event_label["target_ref"], listing.id().as_str());
    assert_eq!(event_label["namespace"], "com.radroots.moderation");
    assert_eq!(event_label["label"], "reviewed");
    let address_label = label_rows
        .iter()
        .find(|row| row["target_type"] == "address")
        .expect("address label");
    assert_eq!(
        address_label["target_ref"],
        format!("30402:{}:listing-a", seller.as_str())
    );
    let report_rows = store
        .report_projection_rows(report.id())
        .await
        .expect("report rows");
    let event_report = report_rows
        .iter()
        .find(|row| {
            row["target_type"] == "event"
                && row["target_ref"] == listing.id().as_str()
                && row["report_type"] == "spam"
        })
        .expect("event report");
    assert_eq!(event_report["reported_pubkeys"][0], seller.as_str());
    drop(store);
    fs::remove_dir_all(root).expect("remove runtime root");
}

fn listing_label(listing: &Event, created_at: u64, label: &str) -> Event {
    let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
    let namespace = "com.radroots.moderation";
    build_fixture_event_from_parts(
        FixtureKey::Seller,
        created_at,
        1_985,
        vec![
            vec!["L".to_owned(), namespace.to_owned()],
            vec!["l".to_owned(), label.to_owned(), namespace.to_owned()],
            vec!["e".to_owned(), listing.id().as_str().to_owned()],
            vec!["a".to_owned(), listing_key],
        ],
        "moderator label",
    )
    .expect("label event")
}

fn listing_report(listing: &Event, created_at: u64, report_type: &str) -> Event {
    build_fixture_event_from_parts(
        FixtureKey::Seller,
        created_at,
        1_984,
        vec![
            vec![
                "p".to_owned(),
                listing.unsigned().pubkey().as_str().to_owned(),
            ],
            vec![
                "e".to_owned(),
                listing.id().as_str().to_owned(),
                report_type.to_owned(),
            ],
        ],
        "moderator report",
    )
    .expect("report event")
}
