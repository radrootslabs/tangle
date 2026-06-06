#![forbid(unsafe_code)]

mod support;

use std::fs;
use support::{
    RelayHarness, assert_ok, close_subscription, connect_client, http_get, next_label,
    reopen_store, request_event_by_id, send_auth, send_event, send_text,
};
use tangle_test_support::{
    FixtureKey, auth_event_spec, build_fixture_event, valid_public_listing_spec,
};

#[tokio::test]
async fn nip01_conformance_event_req_eose_and_close_round_trip() {
    let seller = FixtureKey::Seller.public_key();
    let harness = RelayHarness::start(
        "nip01_conformance",
        serde_json::json!({
            "approved_sellers": [seller.as_str()]
        }),
    );
    let readiness = http_get(harness.port, "/readyz");
    assert!(readiness.contains("200 OK"));
    assert!(readiness.contains("\"status\":\"ready\""));

    let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
    let auth = build_fixture_event(&auth_event_spec()).expect("auth");
    let mut client = connect_client(harness.port).await;
    let notice = send_text(&mut client, "not json").await;
    assert_eq!(notice[0], "NOTICE");
    assert!(
        notice[1]
            .as_str()
            .expect("notice")
            .starts_with("invalid: client message JSON is invalid:")
    );

    assert_ok(&send_auth(&mut client, &auth).await, true);
    assert_ok(&send_event(&mut client, &listing).await, true);
    let fetched = request_event_by_id(&mut client, "nip01-fetch", &listing).await;
    assert_eq!(fetched[0], "EVENT");
    assert_eq!(fetched[1], "nip01-fetch");
    assert_eq!(fetched[2]["id"], listing.id().as_str());
    assert_eq!(next_label(&mut client).await, "EOSE");
    close_subscription(&mut client, "nip01-fetch").await;

    let store_config = harness.store_config();
    let root = harness.root.clone();
    drop(client);
    harness.stop();
    let store = reopen_store(&store_config).await;
    assert!(
        store
            .raw_event_row(listing.id())
            .await
            .expect("raw row")
            .is_some()
    );
    drop(store);
    fs::remove_dir_all(root).expect("remove runtime root");
}
