#![forbid(unsafe_code)]

mod support;

use std::fs;
use support::{
    RelayHarness, assert_ok, connect_client, http_get, next_label, reopen_store,
    request_event_by_id, send_auth, send_event,
};
use tangle_protocol::Event;
use tangle_test_support::{
    FixtureKey, auth_event_spec, build_fixture_event, build_fixture_event_from_parts,
    valid_public_listing_spec,
};

const PRIVATE_VALUES: &[&str] = &[
    "fixture-order-001",
    "buyer.contact@privacy.test",
    "100 Privacy Fixture Way",
    "fixture-payment-token",
    "fixture-refund-token",
    "fixture-dispute-evidence",
    "private order note fixture",
    "5550100",
];

#[tokio::test]
async fn commerce_privacy_conformance_rejects_private_order_plaintext() {
    let seller = FixtureKey::Seller.public_key();
    let harness = RelayHarness::start(
        "commerce_privacy_conformance",
        serde_json::json!({
            "approved_sellers": [seller.as_str()]
        }),
    );
    let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
    let auth = build_fixture_event(&auth_event_spec()).expect("auth");
    let private_events = private_commerce_events();
    let mut client = connect_client(harness.port).await;

    assert_ok(&send_auth(&mut client, &auth).await, true);
    for event in &private_events {
        let rejection = send_event(&mut client, event).await;
        assert_ok(&rejection, false);
        assert_eq!(rejection[1], event.id().as_str());
        assert!(
            rejection[3]
                .as_str()
                .expect("privacy rejection")
                .contains("privacy: private commerce plaintext field")
        );
    }
    assert_ok(&send_event(&mut client, &listing).await, true);

    let rejected_lookup =
        request_event_by_id(&mut client, "private-order-rejected", &private_events[0]).await;
    assert_eq!(rejected_lookup[0], "EOSE");
    assert_eq!(rejected_lookup[1], "private-order-rejected");
    let accepted_lookup =
        request_event_by_id(&mut client, "public-listing-accepted", &listing).await;
    assert_eq!(accepted_lookup[0], "EVENT");
    assert_eq!(accepted_lookup[1], "public-listing-accepted");
    assert_eq!(accepted_lookup[2]["id"], listing.id().as_str());
    assert_eq!(next_label(&mut client).await, "EOSE");

    let listings = http_get(harness.port, "/api/listings?limit=5");
    assert!(listings.contains("200 OK"));
    assert!(listings.contains(listing.id().as_str()));
    for value in PRIVATE_VALUES {
        assert!(!listings.contains(value));
    }
    let detail = http_get(
        harness.port,
        &format!("/api/listings/{}/listing-a", seller.as_str()),
    );
    assert!(detail.contains("200 OK"));
    assert!(detail.contains(listing.id().as_str()));
    for value in PRIVATE_VALUES {
        assert!(!detail.contains(value));
    }

    let store_config = harness.store_config();
    let root = harness.root.clone();
    drop(client);
    harness.stop();
    let store = reopen_store(&store_config).await;
    for event in &private_events {
        assert!(
            store
                .raw_event_row(event.id())
                .await
                .expect("private raw row")
                .is_none()
        );
    }
    assert!(
        store
            .raw_event_row(listing.id())
            .await
            .expect("listing raw row")
            .is_some()
    );
    let listing_key = format!("30402:{}:listing-a", seller.as_str());
    assert!(
        store
            .listing_current_row(&listing_key)
            .await
            .expect("listing row")
            .is_some()
    );
    assert!(
        store
            .search_document_row(&listing_key)
            .await
            .expect("search row")
            .is_some()
    );
    drop(store);
    fs::remove_dir_all(root).expect("remove runtime root");
}

fn private_commerce_events() -> Vec<Event> {
    let mut events = PRIVATE_FIELDS
        .iter()
        .enumerate()
        .map(|(index, (field, value))| {
            let mut private = serde_json::Map::new();
            private.insert(
                (*field).to_owned(),
                serde_json::Value::String((*value).to_owned()),
            );
            let mut root = serde_json::Map::new();
            root.insert(
                "private_commerce".to_owned(),
                serde_json::Value::Object(private),
            );
            build_fixture_event_from_parts(
                FixtureKey::Seller,
                1_714_124_450 + index as u64,
                1,
                vec![vec!["t".to_owned(), "commerce-privacy".to_owned()]],
                &serde_json::Value::Object(root).to_string(),
            )
            .expect("private commerce event")
        })
        .collect::<Vec<_>>();
    events.push(
        build_fixture_event_from_parts(
            FixtureKey::Seller,
            1_714_124_470,
            1,
            vec![vec!["phone".to_owned(), "5550100".to_owned()]],
            "private phone detail",
        )
        .expect("phone tag event"),
    );
    events
}

const PRIVATE_FIELDS: &[(&str, &str)] = &[
    ("order_id", "fixture-order-001"),
    ("buyer_contact", "buyer.contact@privacy.test"),
    ("delivery_address", "100 Privacy Fixture Way"),
    ("payment_details", "fixture-payment-token"),
    ("refund_details", "fixture-refund-token"),
    ("dispute_evidence", "fixture-dispute-evidence"),
    ("private_note", "private order note fixture"),
];
