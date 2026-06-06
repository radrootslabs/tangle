#![forbid(unsafe_code)]

mod support;

use std::fs;
use support::{
    RelayHarness, assert_ok, connect_client_with_challenge, reopen_store, send_auth, send_event,
};
use tangle_test_support::{
    FixtureKey, auth_event_spec, build_fixture_event, valid_public_listing_spec,
};

#[tokio::test]
async fn nip42_conformance_challenges_authenticates_and_gates_writes() {
    let seller = FixtureKey::Seller.public_key();
    let harness = RelayHarness::start(
        "nip42_conformance",
        serde_json::json!({
            "require_write_auth": true,
            "approved_sellers": [seller.as_str()]
        }),
    );
    let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
    let auth = build_fixture_event(&auth_event_spec()).expect("auth");

    let (mut client, challenge) = connect_client_with_challenge(harness.port).await;
    assert_eq!(challenge[0], "AUTH");
    assert_eq!(challenge[1], "challenge-001");

    let auth_as_event = send_event(&mut client, &auth).await;
    assert_ok(&auth_as_event, false);
    assert!(
        auth_as_event[3]
            .as_str()
            .expect("auth rejection")
            .contains("auth events must use AUTH")
    );
    let unauthenticated_write = send_event(&mut client, &listing).await;
    assert_ok(&unauthenticated_write, false);
    assert!(
        unauthenticated_write[3]
            .as_str()
            .expect("write rejection")
            .contains("write authentication required")
    );

    assert_ok(&send_auth(&mut client, &auth).await, true);
    assert_ok(&send_event(&mut client, &listing).await, true);

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
    assert!(
        store
            .raw_event_row(auth.id())
            .await
            .expect("auth raw row")
            .is_none()
    );
    drop(store);
    fs::remove_dir_all(root).expect("remove runtime root");
}
