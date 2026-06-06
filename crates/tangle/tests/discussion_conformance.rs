#![forbid(unsafe_code)]

mod support;

use std::fs;
use support::{
    RelayHarness, assert_ok, connect_client, http_get, next_label, reopen_store,
    request_event_by_id, send_auth, send_event,
};
use tangle_protocol::{Event, EventId};
use tangle_test_support::{
    FixtureKey, auth_event_spec, build_fixture_event, build_fixture_event_from_parts,
    valid_public_listing_spec,
};

#[tokio::test]
async fn discussion_conformance_projects_listing_comments_and_forum_threads() {
    let seller = FixtureKey::Seller.public_key();
    let harness = RelayHarness::start(
        "discussion_conformance",
        serde_json::json!({
            "approved_sellers": [seller.as_str()]
        }),
    );
    let listing = build_fixture_event(&valid_public_listing_spec()).expect("listing");
    let listing_comment = listing_comment(&listing, 1_714_124_436, "Can I pickup Saturday?");
    let thread = forum_thread(1_714_124_438, Some("Market day thread"), &["market", "csa"]);
    let thread_comment = forum_thread_comment(&thread, 1_714_124_439, "I can bring greens.");
    let auth = build_fixture_event(&auth_event_spec()).expect("auth");

    let mut client = connect_client(harness.port).await;
    assert_ok(&send_auth(&mut client, &auth).await, true);
    for event in [&listing, &listing_comment, &thread, &thread_comment] {
        assert_ok(&send_event(&mut client, event).await, true);
    }

    let fetched_comment =
        request_event_by_id(&mut client, "discussion-comment", &listing_comment).await;
    assert_eq!(fetched_comment[0], "EVENT");
    assert_eq!(fetched_comment[1], "discussion-comment");
    assert_eq!(fetched_comment[2]["id"], listing_comment.id().as_str());
    assert_eq!(next_label(&mut client).await, "EOSE");
    let fetched_thread = request_event_by_id(&mut client, "discussion-thread", &thread).await;
    assert_eq!(fetched_thread[0], "EVENT");
    assert_eq!(fetched_thread[1], "discussion-thread");
    assert_eq!(fetched_thread[2]["id"], thread.id().as_str());
    assert_eq!(next_label(&mut client).await, "EOSE");

    let listing_comments = http_get(
        harness.port,
        &format!(
            "/api/listings/{}/listing-a/comments?limit=5",
            seller.as_str()
        ),
    );
    assert!(listing_comments.contains("200 OK"));
    assert!(listing_comments.contains(listing_comment.id().as_str()));
    assert!(listing_comments.contains("Can I pickup Saturday?"));
    let forum_threads = http_get(harness.port, "/api/forum/threads?topic=market&limit=5");
    assert!(forum_threads.contains("200 OK"));
    assert!(forum_threads.contains(thread.id().as_str()));
    assert!(forum_threads.contains("Market day thread"));
    let forum_detail = http_get(
        harness.port,
        &format!("/api/forum/threads/{}", thread.id().as_str()),
    );
    assert!(forum_detail.contains("200 OK"));
    assert!(forum_detail.contains(thread.id().as_str()));
    assert!(forum_detail.contains("Market day thread"));
    let forum_comments = http_get(
        harness.port,
        &format!(
            "/api/forum/threads/{}/comments?limit=5",
            thread.id().as_str()
        ),
    );
    assert!(forum_comments.contains("200 OK"));
    assert!(forum_comments.contains(thread_comment.id().as_str()));
    assert!(forum_comments.contains("I can bring greens."));

    let store_config = harness.store_config();
    let root = harness.root.clone();
    drop(client);
    harness.stop();
    let store = reopen_store(&store_config).await;
    for event in [&listing, &listing_comment, &thread, &thread_comment] {
        assert!(
            store
                .raw_event_row(event.id())
                .await
                .expect("raw row")
                .is_some()
        );
    }
    let listing_key = format!("30402:{}:listing-a", seller.as_str());
    let listing_comment_row = store
        .comment_projection_row(listing_comment.id())
        .await
        .expect("listing comment row")
        .expect("listing comment row exists");
    assert_eq!(
        listing_comment_row["event_id"],
        listing_comment.id().as_str()
    );
    assert_eq!(listing_comment_row["root_target_type"], "address");
    assert_eq!(listing_comment_row["root_ref"], listing_key);
    assert_eq!(listing_comment_row["root_kind"], "30402");
    assert_eq!(listing_comment_row["content"], "Can I pickup Saturday?");
    let thread_row = store
        .forum_thread_row(thread.id())
        .await
        .expect("thread row")
        .expect("thread row exists");
    assert_eq!(thread_row["event_id"], thread.id().as_str());
    assert_eq!(thread_row["title"], "Market day thread");
    assert_eq!(
        thread_row["content"],
        "What is everyone bringing this weekend?"
    );
    let topics = store
        .forum_thread_topic_rows(thread.id())
        .await
        .expect("topic rows");
    assert_eq!(topics.len(), 2);
    assert_eq!(topics[0]["topic"], "csa");
    assert_eq!(topics[1]["topic"], "market");
    let thread_comment_row = store
        .comment_projection_row(thread_comment.id())
        .await
        .expect("thread comment row")
        .expect("thread comment row exists");
    assert_eq!(thread_comment_row["event_id"], thread_comment.id().as_str());
    assert_eq!(thread_comment_row["root_target_type"], "event");
    assert_eq!(thread_comment_row["root_ref"], thread.id().as_str());
    assert_eq!(thread_comment_row["root_kind"], "11");
    assert_eq!(thread_comment_row["content"], "I can bring greens.");
    assert!(
        store
            .search_document_row(thread.id().as_str())
            .await
            .expect("thread search row")
            .is_some()
    );
    drop(store);
    fs::remove_dir_all(root).expect("remove runtime root");
}

fn listing_comment(listing: &Event, created_at: u64, content: &str) -> Event {
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

fn forum_thread(created_at: u64, title: Option<&str>, topics: &[&str]) -> Event {
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

fn forum_thread_comment(thread: &Event, created_at: u64, content: &str) -> Event {
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
