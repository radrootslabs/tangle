#![forbid(unsafe_code)]

mod support;

use std::fs;
use support::{
    RelayHarness, assert_ok, connect_client, reopen_store, request_event_by_id, send_auth,
    send_event,
};
use tangle_test_support::{
    FixtureKey, auth_event_spec, build_fixture_event, build_fixture_event_from_parts,
    valid_public_listing_spec,
};

#[tokio::test]
async fn nip09_conformance_deletes_event_and_hides_it_from_req_results() {
    let seller = FixtureKey::Seller.public_key();
    let harness = RelayHarness::start(
        "nip09_conformance",
        serde_json::json!({
            "approved_sellers": [seller.as_str()]
        }),
    );
    let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
    let deletion = build_fixture_event_from_parts(
        FixtureKey::Seller,
        1_714_124_460,
        5,
        vec![vec!["e".to_owned(), listing.id().as_str().to_owned()]],
        "delete listing",
    )
    .expect("deletion");
    let auth = build_fixture_event(&auth_event_spec()).expect("auth");

    let mut client = connect_client(harness.port).await;
    assert_ok(&send_auth(&mut client, &auth).await, true);
    assert_ok(&send_event(&mut client, &listing).await, true);
    assert_ok(&send_event(&mut client, &deletion).await, true);
    let deleted_lookup = request_event_by_id(&mut client, "nip09-deleted", &listing).await;
    assert_eq!(deleted_lookup[0], "EOSE");
    assert_eq!(deleted_lookup[1], "nip09-deleted");

    let store_config = harness.store_config();
    let root = harness.root.clone();
    drop(client);
    harness.stop();
    let store = reopen_store(&store_config).await;
    let raw_listing = store
        .raw_event_row(listing.id())
        .await
        .expect("listing row")
        .expect("listing exists");
    assert_eq!(raw_listing["deleted"], true);
    assert!(
        store
            .raw_event_row(deletion.id())
            .await
            .expect("deletion row")
            .is_some()
    );
    let markers = store
        .deletion_marker_rows(deletion.id())
        .await
        .expect("markers");
    assert_eq!(markers.len(), 1);
    assert_eq!(markers[0]["target_type"], "event");
    assert_eq!(markers[0]["target_ref"], listing.id().as_str());
    drop(store);
    fs::remove_dir_all(root).expect("remove runtime root");
}
