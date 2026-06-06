#![forbid(unsafe_code)]

mod support;

use std::fs;
use support::{
    RelayHarness, assert_ok, connect_client, next_label, reopen_store, send_auth, send_event,
    send_req,
};
use tangle_test_support::{
    FixtureKey, auth_event_spec, build_fixture_event, valid_public_listing_spec,
};

#[tokio::test]
async fn nip50_conformance_searches_persisted_listing_documents() {
    let seller = FixtureKey::Seller.public_key();
    let harness = RelayHarness::start(
        "nip50_conformance",
        serde_json::json!({
            "approved_sellers": [seller.as_str()]
        }),
    );
    let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
    let auth = build_fixture_event(&auth_event_spec()).expect("auth");

    let mut client = connect_client(harness.port).await;
    assert_ok(&send_auth(&mut client, &auth).await, true);
    assert_ok(&send_event(&mut client, &listing).await, true);

    let found = send_req(
        &mut client,
        "nip50-search",
        serde_json::json!({
            "search": "carrot",
            "kinds": [30402],
            "authors": [seller.as_str()],
            "limit": 5
        }),
    )
    .await;
    assert_eq!(found[0], "EVENT");
    assert_eq!(found[1], "nip50-search");
    assert_eq!(found[2]["id"], listing.id().as_str());
    assert_eq!(next_label(&mut client).await, "EOSE");

    let miss = send_req(
        &mut client,
        "nip50-miss",
        serde_json::json!({
            "search": "rutabaga",
            "kinds": [30402],
            "authors": [seller.as_str()],
            "limit": 5
        }),
    )
    .await;
    assert_eq!(miss[0], "EOSE");
    assert_eq!(miss[1], "nip50-miss");

    let store_config = harness.store_config();
    let root = harness.root.clone();
    drop(client);
    harness.stop();
    let store = reopen_store(&store_config).await;
    let listing_key = format!("30402:{}:listing-a", seller.as_str());
    let search_row = store
        .search_document_row(&listing_key)
        .await
        .expect("search row")
        .expect("search row exists");
    assert_eq!(search_row["event_id"], listing.id().as_str());
    assert_eq!(search_row["doc_type"], "listing");
    assert_eq!(search_row["title"], "Carrot bunches");
    assert_eq!(search_row["visible"], true);
    drop(store);
    fs::remove_dir_all(root).expect("remove runtime root");
}
