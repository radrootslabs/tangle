#![forbid(unsafe_code)]

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tangle_protocol::{EventId, event_to_value};
use tangle_store_surreal::{SurrealConnectionConfig, SurrealStore};
use tangle_test_support::{
    FixtureKey, auth_event_spec, build_fixture_event, build_fixture_event_from_parts,
    valid_public_listing_spec,
};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn tangle_run_serves_relay_clients_and_persists_surreal_state() {
    let port = free_port();
    let root = std::env::temp_dir().join(format!(
        "tangle-run-integration-{}-{port}",
        std::process::id()
    ));
    let db_path = root.join("surrealdb");
    let config_path = root.join("runtime.json");
    fs::create_dir_all(&root).expect("runtime root");
    let admin = FixtureKey::Relay.public_key();
    write_runtime_config(
        &config_path,
        &db_path,
        port,
        "tangle_it",
        serde_json::json!({
            "admin_pubkeys": [admin.as_str()],
            "approved_sellers": [FixtureKey::Seller.public_key().as_str()],
            "write_rate_limit": {
                "limit": 10,
                "window_seconds": 60
            }
        }),
    );

    let mut relay = Command::new(env!("CARGO_BIN_EXE_tangle"))
        .args(["run", "--config"])
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tangle run");

    wait_for_http(port, &mut relay);
    let nip11 = http_get(port, "/");
    assert!(nip11.contains("200 OK"));
    assert!(nip11.contains("application/nostr+json"));
    assert!(nip11.contains("\"supported_nips\""));

    let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
    let comment = listing_comment(&listing, 1_714_124_436, "Can I pickup Saturday?");
    let reaction = listing_reaction(&listing, 1_714_124_437, "+");
    let thread = forum_thread(1_714_124_438, Some("Market day thread"), &["market", "csa"]);
    let thread_comment = forum_thread_comment(&thread, 1_714_124_439, "I can bring greens.");
    let label = listing_label(&listing, 1_714_124_440, "reviewed");
    let report = listing_report(&listing, 1_714_124_441, "spam");
    let profile = seller_profile(1_714_124_442);
    let auth = build_fixture_event(&auth_event_spec()).expect("auth");
    let seller = FixtureKey::Seller.public_key();

    let (mut subscriber, _) = connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("subscriber connect");
    assert_eq!(next_label(&mut subscriber).await, "AUTH");
    subscriber
        .send(Message::Text(
            serde_json::json!([
                "REQ",
                "sub-live",
                {
                    "kinds": [30402],
                    "authors": [seller.as_str()]
                }
            ])
            .to_string()
            .into(),
        ))
        .await
        .expect("subscribe");
    assert_eq!(next_label(&mut subscriber).await, "EOSE");

    let (mut unauthenticated, _) = connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("unauthenticated connect");
    assert_eq!(next_label(&mut unauthenticated).await, "AUTH");
    unauthenticated
        .send(Message::Text(
            serde_json::json!(["EVENT", event_to_value(&listing)])
                .to_string()
                .into(),
        ))
        .await
        .expect("unauthenticated event send");
    let unauthenticated_rejection = next_json(&mut unauthenticated).await;
    assert_ok(&unauthenticated_rejection, false);
    assert!(
        unauthenticated_rejection[3]
            .as_str()
            .expect("rejection message")
            .contains("write authentication required")
    );

    let (mut publisher, _) = connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("publisher connect");
    assert_eq!(next_label(&mut publisher).await, "AUTH");
    publisher
        .send(Message::Text(
            serde_json::json!(["AUTH", event_to_value(&auth)])
                .to_string()
                .into(),
        ))
        .await
        .expect("auth send");
    assert_ok(&next_json(&mut publisher).await, true);

    publisher
        .send(Message::Text(
            serde_json::json!(["EVENT", event_to_value(&profile)])
                .to_string()
                .into(),
        ))
        .await
        .expect("profile send");
    assert_ok(&next_json(&mut publisher).await, true);
    publisher
        .send(Message::Text(
            serde_json::json!(["REQ", "sub-profile", { "ids": [profile.id().as_str()] }])
                .to_string()
                .into(),
        ))
        .await
        .expect("profile fetch send");
    let fetched_profile = next_json(&mut publisher).await;
    assert_eq!(fetched_profile[0], "EVENT");
    assert_eq!(fetched_profile[1], "sub-profile");
    assert_eq!(fetched_profile[2]["id"], profile.id().as_str());
    assert_eq!(next_label(&mut publisher).await, "EOSE");

    publisher
        .send(Message::Text(
            serde_json::json!(["EVENT", event_to_value(&listing)])
                .to_string()
                .into(),
        ))
        .await
        .expect("event send");
    assert_ok(&next_json(&mut publisher).await, true);
    let live = next_json(&mut subscriber).await;
    assert_eq!(live[0], "EVENT");
    assert_eq!(live[1], "sub-live");
    assert_eq!(live[2]["id"], listing.id().as_str());

    publisher
        .send(Message::Text(
            serde_json::json!(["REQ", "sub-fetch", { "ids": [listing.id().as_str()] }])
                .to_string()
                .into(),
        ))
        .await
        .expect("fetch send");
    let fetched = next_json(&mut publisher).await;
    assert_eq!(fetched[0], "EVENT");
    assert_eq!(fetched[1], "sub-fetch");
    assert_eq!(fetched[2]["id"], listing.id().as_str());
    assert_eq!(next_label(&mut publisher).await, "EOSE");

    publisher
        .send(Message::Text(
            serde_json::json!(["EVENT", event_to_value(&comment)])
                .to_string()
                .into(),
        ))
        .await
        .expect("comment send");
    assert_ok(&next_json(&mut publisher).await, true);
    publisher
        .send(Message::Text(
            serde_json::json!(["REQ", "sub-comment", { "ids": [comment.id().as_str()] }])
                .to_string()
                .into(),
        ))
        .await
        .expect("comment fetch send");
    let fetched_comment = next_json(&mut publisher).await;
    assert_eq!(fetched_comment[0], "EVENT");
    assert_eq!(fetched_comment[1], "sub-comment");
    assert_eq!(fetched_comment[2]["id"], comment.id().as_str());
    assert_eq!(next_label(&mut publisher).await, "EOSE");

    publisher
        .send(Message::Text(
            serde_json::json!(["EVENT", event_to_value(&reaction)])
                .to_string()
                .into(),
        ))
        .await
        .expect("reaction send");
    assert_ok(&next_json(&mut publisher).await, true);
    publisher
        .send(Message::Text(
            serde_json::json!(["REQ", "sub-reaction", { "ids": [reaction.id().as_str()] }])
                .to_string()
                .into(),
        ))
        .await
        .expect("reaction fetch send");
    let fetched_reaction = next_json(&mut publisher).await;
    assert_eq!(fetched_reaction[0], "EVENT");
    assert_eq!(fetched_reaction[1], "sub-reaction");
    assert_eq!(fetched_reaction[2]["id"], reaction.id().as_str());
    assert_eq!(next_label(&mut publisher).await, "EOSE");

    publisher
        .send(Message::Text(
            serde_json::json!(["EVENT", event_to_value(&thread)])
                .to_string()
                .into(),
        ))
        .await
        .expect("thread send");
    assert_ok(&next_json(&mut publisher).await, true);
    publisher
        .send(Message::Text(
            serde_json::json!(["REQ", "sub-thread", { "ids": [thread.id().as_str()] }])
                .to_string()
                .into(),
        ))
        .await
        .expect("thread fetch send");
    let fetched_thread = next_json(&mut publisher).await;
    assert_eq!(fetched_thread[0], "EVENT");
    assert_eq!(fetched_thread[1], "sub-thread");
    assert_eq!(fetched_thread[2]["id"], thread.id().as_str());
    assert_eq!(next_label(&mut publisher).await, "EOSE");

    publisher
        .send(Message::Text(
            serde_json::json!(["EVENT", event_to_value(&thread_comment)])
                .to_string()
                .into(),
        ))
        .await
        .expect("thread comment send");
    assert_ok(&next_json(&mut publisher).await, true);
    publisher
        .send(Message::Text(
            serde_json::json!(["REQ", "sub-thread-comment", { "ids": [thread_comment.id().as_str()] }])
                .to_string()
                .into(),
        ))
        .await
        .expect("thread comment fetch send");
    let fetched_thread_comment = next_json(&mut publisher).await;
    assert_eq!(fetched_thread_comment[0], "EVENT");
    assert_eq!(fetched_thread_comment[1], "sub-thread-comment");
    assert_eq!(
        fetched_thread_comment[2]["id"],
        thread_comment.id().as_str()
    );
    assert_eq!(next_label(&mut publisher).await, "EOSE");

    publisher
        .send(Message::Text(
            serde_json::json!(["EVENT", event_to_value(&label)])
                .to_string()
                .into(),
        ))
        .await
        .expect("label send");
    assert_ok(&next_json(&mut publisher).await, true);
    publisher
        .send(Message::Text(
            serde_json::json!(["REQ", "sub-label", { "ids": [label.id().as_str()] }])
                .to_string()
                .into(),
        ))
        .await
        .expect("label fetch send");
    let fetched_label = next_json(&mut publisher).await;
    assert_eq!(fetched_label[0], "EVENT");
    assert_eq!(fetched_label[1], "sub-label");
    assert_eq!(fetched_label[2]["id"], label.id().as_str());
    assert_eq!(next_label(&mut publisher).await, "EOSE");

    publisher
        .send(Message::Text(
            serde_json::json!(["EVENT", event_to_value(&report)])
                .to_string()
                .into(),
        ))
        .await
        .expect("report send");
    assert_ok(&next_json(&mut publisher).await, true);
    publisher
        .send(Message::Text(
            serde_json::json!(["REQ", "sub-report", { "ids": [report.id().as_str()] }])
                .to_string()
                .into(),
        ))
        .await
        .expect("report fetch send");
    let fetched_report = next_json(&mut publisher).await;
    assert_eq!(fetched_report[0], "EVENT");
    assert_eq!(fetched_report[1], "sub-report");
    assert_eq!(fetched_report[2]["id"], report.id().as_str());
    assert_eq!(next_label(&mut publisher).await, "EOSE");

    subscriber
        .send(Message::Text(
            serde_json::json!(["CLOSE", "sub-live"]).to_string().into(),
        ))
        .await
        .expect("close send");

    let listings = http_get(port, "/api/listings?limit=5");
    assert!(listings.contains("200 OK"));
    assert!(listings.contains("Carrot bunches"));
    assert!(listings.contains(listing.id().as_str()));
    let detail = http_get(
        port,
        &format!("/api/listings/{}/listing-a", seller.as_str()),
    );
    assert!(detail.contains("200 OK"));
    assert!(detail.contains("listing-a"));
    assert!(detail.contains("Carrot bunches"));
    let comments = http_get(
        port,
        &format!(
            "/api/listings/{}/listing-a/comments?limit=5",
            seller.as_str()
        ),
    );
    assert!(comments.contains("200 OK"));
    assert!(comments.contains(comment.id().as_str()));
    assert!(comments.contains("Can I pickup Saturday?"));
    let reactions = http_get(
        port,
        &format!("/api/listings/{}/listing-a/reactions", seller.as_str()),
    );
    assert!(reactions.contains("200 OK"));
    assert!(reactions.contains("\"like_count\":1"));
    assert!(reactions.contains("\"total_count\":1"));
    let forum_threads = http_get(port, "/api/forum/threads?topic=market&limit=5");
    assert!(forum_threads.contains("200 OK"));
    assert!(forum_threads.contains(thread.id().as_str()));
    assert!(forum_threads.contains("Market day thread"));
    let forum_detail = http_get(
        port,
        &format!("/api/forum/threads/{}", thread.id().as_str()),
    );
    assert!(forum_detail.contains("200 OK"));
    assert!(forum_detail.contains(thread.id().as_str()));
    assert!(forum_detail.contains("Market day thread"));
    let forum_comments = http_get(
        port,
        &format!(
            "/api/forum/threads/{}/comments?limit=5",
            thread.id().as_str()
        ),
    );
    assert!(forum_comments.contains("200 OK"));
    assert!(forum_comments.contains(thread_comment.id().as_str()));
    assert!(forum_comments.contains("I can bring greens."));
    let moderation_labels = http_get_admin(
        port,
        &format!(
            "/api/admin/moderation/labels?target_type=event&target_ref={}&namespace=com.radroots.moderation&label=reviewed&limit=5",
            listing.id().as_str()
        ),
        Some(admin.as_str()),
    );
    assert!(moderation_labels.contains("200 OK"));
    assert!(moderation_labels.contains(label.id().as_str()));
    assert!(moderation_labels.contains("\"label\":\"reviewed\""));
    let moderation_reports = http_get_admin(
        port,
        &format!(
            "/api/admin/moderation/reports?target_type=event&target_ref={}&report_type=spam&limit=5",
            listing.id().as_str()
        ),
        Some(admin.as_str()),
    );
    assert!(moderation_reports.contains("200 OK"));
    assert!(moderation_reports.contains(report.id().as_str()));
    assert!(moderation_reports.contains("\"report_type\":\"spam\""));
    let search = http_get(port, "/api/search?q=carrots&limit=5");
    assert!(search.contains("200 OK"));
    assert!(search.contains(listing.id().as_str()));
    let seller_detail = http_get(port, &format!("/api/sellers/{}", seller.as_str()));
    assert!(seller_detail.contains("200 OK"));
    assert!(seller_detail.contains(seller.as_str()));
    assert!(seller_detail.contains(profile.id().as_str()));
    assert!(seller_detail.contains("\"display_name\":\"Radroots Market\""));
    assert!(seller_detail.contains("\"regions\":[\"cascadia\",\"pnw\"]"));

    stop_relay(relay);

    let store_config =
        SurrealConnectionConfig::rocksdb(db_path.to_str().expect("db path"), "tangle_it", "relay")
            .expect("store config");
    let store = reopen_store(&store_config).await;
    let listing_key = format!("30402:{}:listing-a", seller.as_str());
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
    assert!(
        store
            .raw_event_row(profile.id())
            .await
            .expect("profile raw row")
            .is_some()
    );
    let profile_row = store
        .seller_profile_row(seller.as_str())
        .await
        .expect("profile row")
        .expect("profile row exists");
    assert_eq!(profile_row["event_id"], profile.id().as_str());
    assert_eq!(profile_row["name"], "radroots-market");
    assert_eq!(profile_row["display_name"], "Radroots Market");
    assert_eq!(
        profile_row["regions"],
        serde_json::json!(["cascadia", "pnw"])
    );
    assert_eq!(profile_row["categories"], serde_json::json!(["produce"]));
    assert_eq!(
        profile_row["trust_markers"],
        serde_json::json!(["csa", "regenerative"])
    );
    assert!(
        store
            .listing_current_row(&listing_key)
            .await
            .expect("listing row")
            .is_some()
    );
    let comment_row = store
        .comment_projection_row(comment.id())
        .await
        .expect("comment row")
        .expect("comment row exists");
    assert_eq!(comment_row["event_id"], comment.id().as_str());
    assert_eq!(comment_row["root_ref"], listing_key);
    assert_eq!(comment_row["content"], "Can I pickup Saturday?");
    let reaction_count = store
        .reaction_count_row(listing.id())
        .await
        .expect("reaction count")
        .expect("reaction count exists");
    assert_eq!(reaction_count["target_event_id"], listing.id().as_str());
    assert_eq!(reaction_count["like_count"], 1_i64);
    assert_eq!(reaction_count["total_count"], 1_i64);
    let thread_row = store
        .forum_thread_row(thread.id())
        .await
        .expect("thread row")
        .expect("thread row exists");
    assert_eq!(thread_row["event_id"], thread.id().as_str());
    assert_eq!(thread_row["title"], "Market day thread");
    let thread_comment_row = store
        .comment_projection_row(thread_comment.id())
        .await
        .expect("thread comment row")
        .expect("thread comment row exists");
    assert_eq!(thread_comment_row["root_ref"], thread.id().as_str());
    assert_eq!(thread_comment_row["content"], "I can bring greens.");
    assert!(
        store
            .search_document_row(thread.id().as_str())
            .await
            .expect("thread search row")
            .is_some()
    );
    let label_rows = store
        .label_projection_rows(label.id())
        .await
        .expect("label rows");
    assert_eq!(label_rows.len(), 2);
    let event_label = label_rows
        .iter()
        .find(|row| row["target_type"] == "event")
        .expect("event label row");
    assert_eq!(event_label["event_id"], label.id().as_str());
    assert_eq!(event_label["target_ref"], listing.id().as_str());
    assert_eq!(event_label["namespace"], "com.radroots.moderation");
    assert_eq!(event_label["label"], "reviewed");
    let report_rows = store
        .report_projection_rows(report.id())
        .await
        .expect("report rows");
    assert_eq!(report_rows.len(), 1);
    assert_eq!(report_rows[0]["event_id"], report.id().as_str());
    assert_eq!(report_rows[0]["target_type"], "event");
    assert_eq!(report_rows[0]["target_ref"], listing.id().as_str());
    assert_eq!(report_rows[0]["report_type"], "spam");
    assert_eq!(report_rows[0]["reported_pubkeys"][0], seller.as_str());
    assert!(
        store
            .search_document_row(&listing_key)
            .await
            .expect("search row")
            .is_some()
    );

    drop(store);
    fs::remove_dir_all(&root).expect("remove runtime root");
}

#[tokio::test]
async fn tangle_run_enforces_seller_projection_policy() {
    let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
    let auth = build_fixture_event(&auth_event_spec()).expect("auth");
    let seller = FixtureKey::Seller.public_key();
    let listing_key = format!("30402:{}:listing-a", seller.as_str());

    let raw_only = run_policy_write_scenario(
        "raw-only",
        "tangle_policy_raw_only",
        serde_json::json!({}),
        &listing,
        &auth,
    )
    .await;
    assert_ok(&raw_only.event_response, true);
    assert!(raw_only.listing_response.contains("200 OK"));
    assert!(!raw_only.listing_response.contains(listing.id().as_str()));
    let raw_only_store = reopen_store(&raw_only.store_config).await;
    assert!(
        raw_only_store
            .raw_event_row(listing.id())
            .await
            .expect("raw row")
            .is_some()
    );
    assert!(
        raw_only_store
            .listing_current_row(&listing_key)
            .await
            .expect("listing row")
            .is_none()
    );
    assert!(
        raw_only_store
            .search_document_row(&listing_key)
            .await
            .expect("search row")
            .is_none()
    );
    drop(raw_only_store);
    fs::remove_dir_all(&raw_only.root).expect("remove raw-only root");

    let reject_write = run_policy_write_scenario(
        "reject-write",
        "tangle_policy_reject_write",
        serde_json::json!({
            "unapproved_seller_action": "reject_write"
        }),
        &listing,
        &auth,
    )
    .await;
    assert_ok(&reject_write.event_response, false);
    assert!(
        reject_write.event_response[3]
            .as_str()
            .expect("rejection message")
            .contains("seller is not approved")
    );
    assert!(reject_write.listing_response.contains("200 OK"));
    assert!(
        !reject_write
            .listing_response
            .contains(listing.id().as_str())
    );
    let reject_store = reopen_store(&reject_write.store_config).await;
    assert!(
        reject_store
            .raw_event_row(listing.id())
            .await
            .expect("raw row")
            .is_none()
    );
    assert!(
        reject_store
            .listing_current_row(&listing_key)
            .await
            .expect("listing row")
            .is_none()
    );
    drop(reject_store);
    fs::remove_dir_all(&reject_write.root).expect("remove reject root");
}

#[tokio::test]
async fn tangle_run_persists_durable_write_rate_limits() {
    let port = free_port();
    let root = std::env::temp_dir().join(format!(
        "tangle-rate-limit-integration-{}-{port}",
        std::process::id()
    ));
    let db_path = root.join("surrealdb");
    let config_path = root.join("runtime.json");
    fs::create_dir_all(&root).expect("runtime root");
    let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
    let auth = build_fixture_event(&auth_event_spec()).expect("auth");
    let seller = FixtureKey::Seller.public_key();
    write_runtime_config(
        &config_path,
        &db_path,
        port,
        "tangle_rate_limit",
        serde_json::json!({
            "approved_sellers": [seller.as_str()],
            "write_rate_limit": {
                "limit": 1,
                "window_seconds": 60
            }
        }),
    );
    let mut relay = spawn_relay(&config_path);
    wait_for_http(port, &mut relay);
    let (mut client, _) = connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("client connect");
    assert_eq!(next_label(&mut client).await, "AUTH");
    client
        .send(Message::Text(
            serde_json::json!(["AUTH", event_to_value(&auth)])
                .to_string()
                .into(),
        ))
        .await
        .expect("auth send");
    assert_ok(&next_json(&mut client).await, true);

    client
        .send(Message::Text(
            serde_json::json!(["EVENT", event_to_value(&listing)])
                .to_string()
                .into(),
        ))
        .await
        .expect("first event send");
    assert_ok(&next_json(&mut client).await, true);
    client
        .send(Message::Text(
            serde_json::json!(["EVENT", event_to_value(&listing)])
                .to_string()
                .into(),
        ))
        .await
        .expect("second event send");
    let rejected = next_json(&mut client).await;
    assert_ok(&rejected, false);
    assert!(
        rejected[3]
            .as_str()
            .expect("rate rejection")
            .contains("rate-limited: retry after")
    );
    stop_relay(relay);

    let store_config = SurrealConnectionConfig::rocksdb(
        db_path.to_str().expect("db path"),
        "tangle_rate_limit",
        "relay",
    )
    .expect("store config");
    let store = reopen_store(&store_config).await;
    let key = format!("event_write:{}", seller.as_str());
    let row = store
        .rate_limit_state_row(&key)
        .await
        .expect("rate row")
        .expect("rate row exists");
    assert_eq!(row["key"], key);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(row["state"].as_str().expect("state"))
            .expect("state json")["used"],
        1_u64
    );
    assert!(
        store
            .raw_event_row(listing.id())
            .await
            .expect("raw row")
            .is_some()
    );
    drop(store);
    fs::remove_dir_all(&root).expect("remove runtime root");
}

#[tokio::test]
async fn tangle_run_serves_admin_policy_api() {
    let port = free_port();
    let root = std::env::temp_dir().join(format!(
        "tangle-admin-policy-integration-{}-{port}",
        std::process::id()
    ));
    let db_path = root.join("surrealdb");
    let config_path = root.join("runtime.json");
    fs::create_dir_all(&root).expect("runtime root");
    let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
    let auth = build_fixture_event(&auth_event_spec()).expect("auth");
    let seller = FixtureKey::Seller.public_key();
    let admin = FixtureKey::Relay.public_key();
    let listing_key = format!("30402:{}:listing-a", seller.as_str());
    write_runtime_config(
        &config_path,
        &db_path,
        port,
        "tangle_admin_policy",
        serde_json::json!({
            "admin_pubkeys": [admin.as_str()]
        }),
    );
    let mut relay = spawn_relay(&config_path);
    wait_for_http(port, &mut relay);

    let unauthorized = http_post_json(
        port,
        &format!("/api/admin/sellers/{}/approve", seller.as_str()),
        None,
        serde_json::json!({}),
    );
    assert!(unauthorized.contains("401 Unauthorized"));
    let approve = http_post_json(
        port,
        &format!("/api/admin/sellers/{}/approve", seller.as_str()),
        Some(admin.as_str()),
        serde_json::json!({}),
    );
    assert!(approve.contains("200 OK"));
    assert!(approve.contains("\"status\":\"approved\""));
    let seller_detail = http_get(port, &format!("/api/sellers/{}", seller.as_str()));
    assert!(seller_detail.contains("\"approved\":true"));

    let (mut client, _) = connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("client connect");
    assert_eq!(next_label(&mut client).await, "AUTH");
    client
        .send(Message::Text(
            serde_json::json!(["AUTH", event_to_value(&auth)])
                .to_string()
                .into(),
        ))
        .await
        .expect("auth send");
    assert_ok(&next_json(&mut client).await, true);
    client
        .send(Message::Text(
            serde_json::json!(["EVENT", event_to_value(&listing)])
                .to_string()
                .into(),
        ))
        .await
        .expect("event send");
    assert_ok(&next_json(&mut client).await, true);
    assert!(http_get(port, "/api/listings?limit=5").contains(listing.id().as_str()));

    let hide = http_post_json(
        port,
        &format!("/api/admin/events/{}/hide", listing.id().as_str()),
        Some(admin.as_str()),
        serde_json::json!({
            "reason": "admin policy integration"
        }),
    );
    assert!(hide.contains("200 OK"));
    assert!(hide.contains("\"status\":\"hidden\""));
    assert!(!http_get(port, "/api/listings?limit=5").contains(listing.id().as_str()));
    let unhide = http_post_json(
        port,
        &format!("/api/admin/events/{}/unhide", listing.id().as_str()),
        Some(admin.as_str()),
        serde_json::json!({
            "reason": "admin policy integration complete"
        }),
    );
    assert!(unhide.contains("200 OK"));
    assert!(unhide.contains("\"status\":\"unhidden\""));
    assert!(http_get(port, "/api/listings?limit=5").contains(listing.id().as_str()));
    let block = http_post_json(
        port,
        &format!("/api/admin/pubkeys/{}/block", seller.as_str()),
        Some(admin.as_str()),
        serde_json::json!({}),
    );
    assert!(block.contains("200 OK"));
    assert!(block.contains("\"status\":\"blocked\""));
    stop_relay(relay);

    let store_config = SurrealConnectionConfig::rocksdb(
        db_path.to_str().expect("db path"),
        "tangle_admin_policy",
        "relay",
    )
    .expect("store config");
    let store = reopen_store(&store_config).await;
    let user = store
        .relay_user_row(seller.as_str())
        .await
        .expect("relay user")
        .expect("relay user exists");
    assert_eq!(user["seller_approved"], true);
    assert_eq!(user["blocked"], true);
    assert!(
        store
            .hidden_event_row(listing.id())
            .await
            .expect("hidden row")
            .is_none()
    );
    assert_eq!(
        store
            .raw_event_row(listing.id())
            .await
            .expect("raw row")
            .expect("raw row exists")["hidden"],
        false
    );
    assert_eq!(
        store
            .listing_current_row(&listing_key)
            .await
            .expect("listing row")
            .expect("listing row exists")["hidden"],
        false
    );
    let actions = store
        .moderation_action_rows("event", listing.id().as_str())
        .await
        .expect("moderation actions");
    assert_eq!(actions.len(), 2);
    let action_labels = actions
        .iter()
        .map(|action| action["action"].as_str().expect("action label"))
        .collect::<std::collections::BTreeSet<_>>();
    assert!(action_labels.contains("hide"));
    assert!(action_labels.contains("unhide"));
    drop(store);
    fs::remove_dir_all(&root).expect("remove runtime root");
}

struct PolicyWriteScenario {
    root: std::path::PathBuf,
    store_config: SurrealConnectionConfig,
    event_response: Value,
    listing_response: String,
}

async fn run_policy_write_scenario(
    name: &str,
    namespace: &str,
    policy: Value,
    listing: &tangle_protocol::Event,
    auth: &tangle_protocol::Event,
) -> PolicyWriteScenario {
    let port = free_port();
    let root = std::env::temp_dir().join(format!(
        "tangle-policy-{name}-{}-{port}",
        std::process::id()
    ));
    let db_path = root.join("surrealdb");
    let config_path = root.join("runtime.json");
    fs::create_dir_all(&root).expect("runtime root");
    write_runtime_config(&config_path, &db_path, port, namespace, policy);
    let mut relay = spawn_relay(&config_path);
    wait_for_http(port, &mut relay);
    let (mut client, _) = connect_async(format!("ws://127.0.0.1:{port}/ws"))
        .await
        .expect("client connect");
    assert_eq!(next_label(&mut client).await, "AUTH");
    client
        .send(Message::Text(
            serde_json::json!(["AUTH", event_to_value(auth)])
                .to_string()
                .into(),
        ))
        .await
        .expect("auth send");
    assert_ok(&next_json(&mut client).await, true);
    client
        .send(Message::Text(
            serde_json::json!(["EVENT", event_to_value(listing)])
                .to_string()
                .into(),
        ))
        .await
        .expect("event send");
    let event_response = next_json(&mut client).await;
    let listing_response = http_get(port, "/api/listings?limit=5");
    stop_relay(relay);
    let store_config =
        SurrealConnectionConfig::rocksdb(db_path.to_str().expect("db path"), namespace, "relay")
            .expect("store config");
    PolicyWriteScenario {
        root,
        store_config,
        event_response,
        listing_response,
    }
}

fn spawn_relay(config_path: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_tangle"))
        .args(["run", "--config"])
        .arg(config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tangle run")
}

fn write_runtime_config(path: &Path, db_path: &Path, port: u16, namespace: &str, policy: Value) {
    let config = serde_json::json!({
        "server": {
            "listen_addr": format!("127.0.0.1:{port}"),
            "relay_url": "wss://relay.radroots.test"
        },
        "database": {
            "mode": "rocks_db",
            "path": db_path.to_str().expect("db path"),
            "namespace": namespace,
            "database": "relay"
        },
        "auth": {
            "challenge_ttl_seconds": 300
        },
        "limits": {
            "message_rate_limit": {
                "limit": 120,
                "window_seconds": 60
            }
        },
        "policy": policy
    });
    fs::write(
        path,
        serde_json::to_string_pretty(&config).expect("config JSON"),
    )
    .expect("write config");
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn wait_for_http(port: u16, child: &mut Child) {
    let started = Instant::now();
    loop {
        if let Ok(response) = try_http_get(port, "/healthz")
            && response.contains("200 OK")
        {
            return;
        }
        if let Some(status) = child.try_wait().expect("child status") {
            panic!("relay exited before readiness: {status}");
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "relay did not open port {port}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn http_get(port: u16, path: &str) -> String {
    try_http_get(port, path).expect("http get")
}

fn http_get_admin(port: u16, path: &str, admin_pubkey: Option<&str>) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("http connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("write timeout");
    let admin_header = admin_pubkey
        .map(|pubkey| format!("x-tangle-admin-pubkey: {pubkey}\r\n"))
        .unwrap_or_default();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: application/json\r\n{admin_header}Connection: close\r\n\r\n"
    )
    .expect("http get");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("http read");
    response
}

fn http_post_json(port: u16, path: &str, admin_pubkey: Option<&str>, body: Value) -> String {
    let body = body.to_string();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("http connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("write timeout");
    let admin_header = admin_pubkey
        .map(|pubkey| format!("x-tangle-admin-pubkey: {pubkey}\r\n"))
        .unwrap_or_default();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{admin_header}Connection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("http post");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("http read");
    response
}

fn try_http_get(port: u16, path: &str) -> Result<String, std::io::Error> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

async fn reopen_store(config: &SurrealConnectionConfig) -> SurrealStore {
    let started = Instant::now();
    loop {
        match SurrealStore::connect_local(config).await {
            Ok(store) => return store,
            Err(error) if started.elapsed() < Duration::from_secs(5) => {
                let _ = error;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("store reopen failed: {error}"),
        }
    }
}

async fn next_json(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Value {
    let message = socket
        .next()
        .await
        .expect("websocket message")
        .expect("websocket frame");
    let text = message.into_text().expect("text frame");
    serde_json::from_str(&text).expect("relay JSON")
}

async fn next_label(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> String {
    next_json(socket).await[0]
        .as_str()
        .expect("label")
        .to_owned()
}

fn assert_ok(message: &Value, accepted: bool) {
    assert_eq!(message[0], "OK");
    assert_eq!(message[2], accepted, "relay OK frame: {message}");
}

fn seller_profile(created_at: u64) -> tangle_protocol::Event {
    let content = serde_json::json!({
        "name": "radroots-market",
        "display_name": "Radroots Market",
        "about": "Local food seller profile",
        "picture": "https://fixtures.radroots.test/seller.png",
        "website": "https://seller.radroots.test",
        "nip05": "seller@radroots.test",
        "lud16": "seller@pay.radroots.test"
    });
    build_fixture_event_from_parts(
        FixtureKey::Seller,
        created_at,
        0,
        vec![
            vec!["region".to_owned(), "PNW".to_owned()],
            vec!["region".to_owned(), "Cascadia".to_owned()],
            vec!["category".to_owned(), "Produce".to_owned()],
            vec!["trust".to_owned(), "CSA".to_owned()],
            vec!["trust".to_owned(), "regenerative".to_owned()],
        ],
        &content.to_string(),
    )
    .expect("seller profile")
}

fn listing_comment(
    listing: &tangle_protocol::Event,
    created_at: u64,
    content: &str,
) -> tangle_protocol::Event {
    let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
    build_fixture_event_from_parts(
        FixtureKey::Seller,
        created_at,
        1_111,
        vec![
            vec!["A".to_owned(), listing_key.clone()],
            vec!["K".to_owned(), "30402".to_owned()],
            vec![
                "P".to_owned(),
                listing.unsigned().pubkey().as_str().to_owned(),
            ],
            vec!["a".to_owned(), listing_key],
            vec!["k".to_owned(), "30402".to_owned()],
            vec![
                "p".to_owned(),
                listing.unsigned().pubkey().as_str().to_owned(),
            ],
        ],
        content,
    )
    .expect("comment event")
}

fn listing_reaction(
    listing: &tangle_protocol::Event,
    created_at: u64,
    content: &str,
) -> tangle_protocol::Event {
    let listing_key = format!("30402:{}:listing-a", listing.unsigned().pubkey().as_str());
    build_fixture_event_from_parts(
        FixtureKey::Seller,
        created_at,
        7,
        vec![
            vec![
                "e".to_owned(),
                listing.id().as_str().to_owned(),
                "wss://relay.radroots.test".to_owned(),
                listing.unsigned().pubkey().as_str().to_owned(),
            ],
            vec![
                "p".to_owned(),
                listing.unsigned().pubkey().as_str().to_owned(),
            ],
            vec!["a".to_owned(), listing_key],
            vec!["k".to_owned(), "30402".to_owned()],
        ],
        content,
    )
    .expect("reaction event")
}

fn listing_label(
    listing: &tangle_protocol::Event,
    created_at: u64,
    label: &str,
) -> tangle_protocol::Event {
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

fn listing_report(
    listing: &tangle_protocol::Event,
    created_at: u64,
    report_type: &str,
) -> tangle_protocol::Event {
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

fn forum_thread(created_at: u64, title: Option<&str>, topics: &[&str]) -> tangle_protocol::Event {
    let mut tags = vec![
        vec!["e".to_owned(), "5".repeat(EventId::HEX_LENGTH)],
        vec![
            "p".to_owned(),
            FixtureKey::Buyer.public_key().as_str().to_owned(),
        ],
    ];
    if let Some(title) = title {
        tags.push(vec!["title".to_owned(), title.to_owned()]);
    }
    tags.extend(
        topics
            .iter()
            .map(|topic| vec!["t".to_owned(), (*topic).to_owned()]),
    );
    build_fixture_event_from_parts(
        FixtureKey::Seller,
        created_at,
        11,
        tags,
        "What is everyone bringing this weekend?",
    )
    .expect("forum thread")
}

fn forum_thread_comment(
    thread: &tangle_protocol::Event,
    created_at: u64,
    content: &str,
) -> tangle_protocol::Event {
    build_fixture_event_from_parts(
        FixtureKey::Seller,
        created_at,
        1_111,
        vec![
            vec![
                "E".to_owned(),
                thread.id().as_str().to_owned(),
                "wss://relay.radroots.test".to_owned(),
                thread.unsigned().pubkey().as_str().to_owned(),
            ],
            vec!["K".to_owned(), "11".to_owned()],
            vec![
                "P".to_owned(),
                thread.unsigned().pubkey().as_str().to_owned(),
            ],
            vec![
                "e".to_owned(),
                thread.id().as_str().to_owned(),
                "wss://relay.radroots.test".to_owned(),
                thread.unsigned().pubkey().as_str().to_owned(),
            ],
            vec!["k".to_owned(), "11".to_owned()],
            vec![
                "p".to_owned(),
                thread.unsigned().pubkey().as_str().to_owned(),
            ],
        ],
        content,
    )
    .expect("forum comment event")
}

fn stop_relay(mut relay: Child) {
    stop_child(&mut relay);
    let status = relay.wait().expect("relay exit");
    assert!(status.success());
}

#[cfg(unix)]
fn stop_child(relay: &mut Child) {
    let status = Command::new("kill")
        .args(["-INT", &relay.id().to_string()])
        .status()
        .expect("send interrupt");
    assert!(status.success());
}

#[cfg(not(unix))]
fn stop_child(relay: &mut Child) {
    relay.kill().expect("kill relay");
}
