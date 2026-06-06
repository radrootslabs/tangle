#![forbid(unsafe_code)]

mod support;

use std::fs;
use support::{
    RelayHarness, assert_ok, connect_client, http_get, next_label, reopen_store, send_auth,
    send_event, send_req,
};
use tangle_test_support::{
    FixtureKey, auth_event_spec, build_fixture_event, valid_public_listing_spec,
};

#[tokio::test]
async fn nip99_conformance_projects_and_serves_public_listings() {
    let seller = FixtureKey::Seller.public_key();
    let harness = RelayHarness::start(
        "nip99_conformance",
        serde_json::json!({
            "approved_sellers": [seller.as_str()]
        }),
    );
    let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
    let auth = build_fixture_event(&auth_event_spec()).expect("auth");

    let mut client = connect_client(harness.port).await;
    assert_ok(&send_auth(&mut client, &auth).await, true);
    assert_ok(&send_event(&mut client, &listing).await, true);
    let by_address = send_req(
        &mut client,
        "nip99-address",
        serde_json::json!({
            "kinds": [30402],
            "authors": [seller.as_str()],
            "#d": ["listing-a"],
            "limit": 5
        }),
    )
    .await;
    assert_eq!(by_address[0], "EVENT");
    assert_eq!(by_address[1], "nip99-address");
    assert_eq!(by_address[2]["id"], listing.id().as_str());
    assert_eq!(by_address[2]["kind"], 30402);
    assert_eq!(next_label(&mut client).await, "EOSE");

    let list_response = http_get(
        harness.port,
        &format!(
            "/api/listings?status=active&seller={}&unit=lb&currency=usd&limit=5",
            seller.as_str()
        ),
    );
    assert!(list_response.contains("200 OK"));
    assert!(list_response.contains(listing.id().as_str()));
    assert!(list_response.contains("\"title\":\"Carrot bunches\""));
    assert!(list_response.contains("\"unit\":\"lb\""));
    let detail_response = http_get(
        harness.port,
        &format!("/api/listings/{}/listing-a", seller.as_str()),
    );
    assert!(detail_response.contains("200 OK"));
    assert!(detail_response.contains(listing.id().as_str()));
    assert!(detail_response.contains("\"content\":\"Sweet storage carrots.\""));

    let store_config = harness.store_config();
    let root = harness.root.clone();
    drop(client);
    harness.stop();
    let store = reopen_store(&store_config).await;
    let listing_key = format!("30402:{}:listing-a", seller.as_str());
    assert!(
        store
            .raw_event_row(listing.id())
            .await
            .expect("raw row")
            .is_some()
    );
    let row = store
        .listing_current_row(&listing_key)
        .await
        .expect("listing row")
        .expect("listing row exists");
    assert_eq!(row["listing_key"], listing_key);
    assert_eq!(row["event_id"], listing.id().as_str());
    assert_eq!(row["seller_pubkey"], seller.as_str());
    assert_eq!(row["d"], "listing-a");
    assert_eq!(row["title"], "Carrot bunches");
    assert_eq!(row["content"], "Sweet storage carrots.");
    assert_eq!(row["price_decimal"], "12.50");
    assert_eq!(row["price_minor"], 1_250_u64);
    assert_eq!(row["currency_norm"], "USD");
    assert_eq!(row["unit"], "lb");
    assert_eq!(row["effective_status"], "active");
    assert_eq!(row["hidden"], false);
    drop(store);
    fs::remove_dir_all(root).expect("remove runtime root");
}
