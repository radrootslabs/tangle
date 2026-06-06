#![forbid(unsafe_code)]

mod support;

use std::fs;
use support::{
    RelayHarness, assert_ok, connect_client, http_get, http_post_json, reopen_store, send_auth,
    send_event, send_req, send_text,
};
use tangle_protocol::{Event, event_to_value};
use tangle_test_support::{
    FixtureKey, auth_event_spec, build_fixture_event, build_fixture_event_from_parts,
    valid_public_listing_spec,
};

#[tokio::test]
async fn abuse_conformance_rejects_malformed_invalid_and_replayed_messages() {
    let seller = FixtureKey::Seller.public_key();
    let harness = RelayHarness::start(
        "abuse_invalid_messages",
        serde_json::json!({
            "approved_sellers": [seller.as_str()]
        }),
    );
    let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
    let auth = build_fixture_event(&auth_event_spec()).expect("auth");
    let mut client = connect_client(harness.port).await;

    let malformed = send_text(&mut client, "not json").await;
    assert_eq!(malformed[0], "NOTICE");
    assert!(
        malformed[1]
            .as_str()
            .expect("notice")
            .contains("client message JSON is invalid")
    );
    let bad_id = send_text(&mut client, r#"["REQ","bad-id",{"ids":["bad"]}]"#).await;
    assert_eq!(bad_id[0], "NOTICE");
    assert!(bad_id[1].as_str().expect("notice").contains("event id"));

    assert_ok(&send_auth(&mut client, &auth).await, true);
    let replay = send_auth(&mut client, &auth).await;
    assert_ok(&replay, false);
    assert!(
        replay[3]
            .as_str()
            .expect("replay rejection")
            .contains("auth challenge is missing")
    );

    let mut bad_sig = event_to_value(&listing);
    bad_sig["sig"] = serde_json::Value::String("f".repeat(128));
    let rejected_sig = send_text(
        &mut client,
        &serde_json::json!(["EVENT", bad_sig]).to_string(),
    )
    .await;
    assert_ok(&rejected_sig, false);
    assert!(
        rejected_sig[3]
            .as_str()
            .expect("signature rejection")
            .contains("crypto")
    );
    let mut bad_event_id = event_to_value(&listing);
    bad_event_id["id"] = serde_json::Value::String("f".repeat(64));
    let rejected_id = send_text(
        &mut client,
        &serde_json::json!(["EVENT", bad_event_id]).to_string(),
    )
    .await;
    assert_ok(&rejected_id, false);

    let store_config = harness.store_config();
    let root = harness.root.clone();
    drop(client);
    harness.stop();
    let store = reopen_store(&store_config).await;
    assert!(
        store
            .raw_event_row(listing.id())
            .await
            .expect("raw listing")
            .is_none()
    );
    drop(store);
    fs::remove_dir_all(root).expect("remove runtime root");
}

#[tokio::test]
async fn abuse_conformance_enforces_runtime_limits_for_events_subscriptions_and_search() {
    let seller = FixtureKey::Seller.public_key();
    let harness = RelayHarness::start_with_runtime_limits(
        "abuse_runtime_limits",
        serde_json::json!({
            "approved_sellers": [seller.as_str()]
        }),
        serde_json::json!({
            "max_tags_per_event": 1,
            "max_filters_per_subscription": 1,
            "max_subscriptions_per_connection": 1,
            "max_search_tokens": 1
        }),
    );
    let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
    let auth = build_fixture_event(&auth_event_spec()).expect("auth");

    let mut writer = connect_client(harness.port).await;
    assert_ok(&send_auth(&mut writer, &auth).await, true);
    let too_many_tags = send_event(&mut writer, &listing).await;
    assert_ok(&too_many_tags, false);
    assert!(
        too_many_tags[3]
            .as_str()
            .expect("tag rejection")
            .contains("tags per event")
    );
    drop(writer);

    let mut reader = connect_client(harness.port).await;
    let too_many_filters = send_text(
        &mut reader,
        r#"["REQ","too-many-filters",{"ids":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]},{"ids":["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}]"#,
    )
    .await;
    assert_eq!(too_many_filters[0], "CLOSED");
    assert!(
        too_many_filters[2]
            .as_str()
            .expect("filter rejection")
            .contains("filters per subscription")
    );
    let first_subscription = send_req(
        &mut reader,
        "sub-one",
        serde_json::json!({
            "ids": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        }),
    )
    .await;
    assert_eq!(first_subscription[0], "EOSE");
    let too_many_subscriptions = send_req(
        &mut reader,
        "sub-two",
        serde_json::json!({
            "ids": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
        }),
    )
    .await;
    assert_eq!(too_many_subscriptions[0], "CLOSED");
    assert!(
        too_many_subscriptions[2]
            .as_str()
            .expect("subscription rejection")
            .contains("subscriptions per connection")
    );
    drop(reader);

    let mut searcher = connect_client(harness.port).await;
    let abusive_search = send_req(
        &mut searcher,
        "search-abuse",
        serde_json::json!({
            "search": "fresh carrots",
            "limit": 5
        }),
    )
    .await;
    assert_eq!(abusive_search[0], "CLOSED");
    assert!(
        abusive_search[2]
            .as_str()
            .expect("search rejection")
            .contains("search tokens")
    );

    let store_config = harness.store_config();
    let root = harness.root.clone();
    drop(searcher);
    harness.stop();
    let store = reopen_store(&store_config).await;
    assert!(
        store
            .raw_event_row(listing.id())
            .await
            .expect("raw listing")
            .is_none()
    );
    drop(store);
    fs::remove_dir_all(root).expect("remove runtime root");
}

#[tokio::test]
async fn abuse_conformance_excludes_blocked_pubkey_writes_from_public_surfaces() {
    let seller = FixtureKey::Seller.public_key();
    let harness = RelayHarness::start(
        "abuse_blocked_pubkey",
        serde_json::json!({
            "approved_sellers": [seller.as_str()],
            "blocked_pubkeys": [seller.as_str()]
        }),
    );
    let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
    let auth = build_fixture_event(&auth_event_spec()).expect("auth");
    let mut client = connect_client(harness.port).await;

    assert_ok(&send_auth(&mut client, &auth).await, true);
    assert_ok(&send_event(&mut client, &listing).await, true);
    assert!(!http_get(harness.port, "/api/listings?limit=5").contains(listing.id().as_str()));

    let store_config = harness.store_config();
    let root = harness.root.clone();
    drop(client);
    harness.stop();
    let store = reopen_store(&store_config).await;
    assert!(
        store
            .raw_event_row(listing.id())
            .await
            .expect("raw listing")
            .is_some()
    );
    let listing_key = format!("30402:{}:listing-a", seller.as_str());
    assert!(
        store
            .listing_current_row(&listing_key)
            .await
            .expect("listing row")
            .is_none()
    );
    assert!(
        store
            .search_document_row(&listing_key)
            .await
            .expect("search row")
            .is_none()
    );
    drop(store);
    fs::remove_dir_all(root).expect("remove runtime root");
}

#[tokio::test]
async fn abuse_conformance_excludes_hidden_and_deleted_listings_from_public_surfaces() {
    let hidden = publish_listing_for_visibility("abuse_hidden_listing").await;
    let hide = http_post_json(
        hidden.harness.port,
        &format!("/api/admin/events/{}/hide", hidden.listing.id().as_str()),
        Some(hidden.admin.as_str()),
        serde_json::json!({
            "reason": "abuse visibility test"
        }),
    );
    assert!(hide.contains("200 OK"));
    assert!(hide.contains("\"status\":\"hidden\""));
    assert!(
        !http_get(hidden.harness.port, "/api/listings?limit=5")
            .contains(hidden.listing.id().as_str())
    );
    let hidden_store_config = hidden.harness.store_config();
    let hidden_root = hidden.harness.root.clone();
    drop(hidden.client);
    hidden.harness.stop();
    let store = reopen_store(&hidden_store_config).await;
    let listing_key = format!("30402:{}:listing-a", hidden.seller.as_str());
    assert_eq!(
        store
            .raw_event_row(hidden.listing.id())
            .await
            .expect("raw row")
            .expect("raw row exists")["hidden"],
        true
    );
    assert_eq!(
        store
            .listing_current_row(&listing_key)
            .await
            .expect("listing row")
            .expect("listing row exists")["hidden"],
        true
    );
    assert_eq!(
        store
            .search_document_row(&listing_key)
            .await
            .expect("search row")
            .expect("search row exists")["visible"],
        false
    );
    drop(store);
    fs::remove_dir_all(hidden_root).expect("remove hidden runtime root");

    let mut deleted = publish_listing_for_visibility("abuse_deleted_listing").await;
    let listing_key = format!("30402:{}:listing-a", deleted.seller.as_str());
    let deletion = build_fixture_event_from_parts(
        FixtureKey::Seller,
        1_714_124_460,
        5,
        vec![vec!["a".to_owned(), listing_key.clone()]],
        "delete listing",
    )
    .expect("deletion");
    assert_ok(&send_event(&mut deleted.client, &deletion).await, true);
    let deleted_lookup = send_req(
        &mut deleted.client,
        "deleted-listing",
        serde_json::json!({
            "ids": [deleted.listing.id().as_str()]
        }),
    )
    .await;
    assert_eq!(deleted_lookup[0], "EOSE");
    assert!(
        !http_get(deleted.harness.port, "/api/listings?limit=5")
            .contains(deleted.listing.id().as_str())
    );
    let deleted_store_config = deleted.harness.store_config();
    let deleted_root = deleted.harness.root.clone();
    drop(deleted.client);
    deleted.harness.stop();
    let store = reopen_store(&deleted_store_config).await;
    assert_eq!(
        store
            .raw_event_row(deleted.listing.id())
            .await
            .expect("raw row")
            .expect("raw row exists")["deleted"],
        true
    );
    assert_eq!(
        store
            .search_document_row(&listing_key)
            .await
            .expect("search row")
            .expect("search row exists")["visible"],
        false
    );
    assert_eq!(
        store
            .deletion_marker_rows(deletion.id())
            .await
            .expect("markers")[0]["target_type"],
        "address"
    );
    drop(store);
    fs::remove_dir_all(deleted_root).expect("remove deleted runtime root");
}

struct VisibilityHarness {
    harness: RelayHarness,
    client: support::RelayClient,
    listing: Event,
    seller: tangle_protocol::PublicKeyHex,
    admin: tangle_protocol::PublicKeyHex,
}

async fn publish_listing_for_visibility(namespace: &str) -> VisibilityHarness {
    let seller = FixtureKey::Seller.public_key();
    let admin = FixtureKey::Relay.public_key();
    let harness = RelayHarness::start(
        namespace,
        serde_json::json!({
            "admin_pubkeys": [admin.as_str()],
            "approved_sellers": [seller.as_str()]
        }),
    );
    let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
    let auth = build_fixture_event(&auth_event_spec()).expect("auth");
    let mut client = connect_client(harness.port).await;
    assert_ok(&send_auth(&mut client, &auth).await, true);
    assert_ok(&send_event(&mut client, &listing).await, true);
    assert!(http_get(harness.port, "/api/listings?limit=5").contains(listing.id().as_str()));
    VisibilityHarness {
        harness,
        client,
        listing,
        seller,
        admin,
    }
}
