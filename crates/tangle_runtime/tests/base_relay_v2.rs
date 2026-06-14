#![forbid(unsafe_code)]

use std::{fs, panic, path::PathBuf};
use tangle_crypto::{event_id_matches, verify_event_signature};
use tangle_groups::{
    GroupId, GroupRuntimeConfig, KIND_GROUP_ADMINS, KIND_GROUP_DELETE_GROUP,
    KIND_GROUP_JOIN_REQUEST, KIND_GROUP_LEAVE_REQUEST, KIND_GROUP_MEMBERS, KIND_GROUP_METADATA,
    KIND_GROUP_PUT_USER, MemberStatus, NIP29_RELAY_GENERATED_KIND_VALUES,
    parse_group_runtime_config_json,
};
use tangle_protocol::{
    Event, Filter, RawEventJson, RelayMessage, SubscriptionId, Tag, UnixTimestamp,
    filter_from_value, parse_client_message, parse_event_json,
};
use tangle_runtime::{
    nip11::{BASE_RELAY_SUPPORTED_NIPS, BaseRelayInfoConfig},
    relay::{auth::BaseAuthState, core::BaseRelay, live::CloseResult},
};
use tangle_store_pocket::{PocketStoreConfig, PocketSyncPolicy};
use tangle_test_support::{
    FixtureKey, TANGLE_V2_RELAY_SECRET_HEX, TANGLE_V2_RELAY_URL, tangle_v2_auth_event,
    tangle_v2_delete_group_event, tangle_v2_event, tangle_v2_group_config,
    tangle_v2_group_create_event, tangle_v2_group_event, tangle_v2_group_metadata_event,
    tangle_v2_join_event, tangle_v2_leave_event, tangle_v2_put_user_event,
    tangle_v2_remove_user_event,
};

#[test]
fn public_relay_smoke_stores_queries_counts_and_fans_out() {
    let config = test_store_config("public-smoke");
    let mut relay = BaseRelay::open(&config, 4).expect("relay");
    let first =
        tangle_v2_event(FixtureKey::Member, 1_714_124_433, 1, Vec::new(), "hello").expect("first");
    let query_id = subscription("public-query");

    assert_accepted(relay.handle_event(first.clone()).expect("event"), &first);
    assert_event_query(
        relay
            .handle_req(query_id.clone(), vec![filter_kind(1)])
            .expect("query"),
        &query_id,
        &[&first],
    );
    assert_count(
        relay.handle_count(subscription("public-count"), vec![filter_kind(1)]),
        1,
    );
    assert_eq!(relay.handle_close(&query_id), CloseResult::Closed);

    let live_id = subscription("public-live");
    relay
        .handle_req(live_id.clone(), vec![filter_kind(1)])
        .expect("live");
    let second =
        tangle_v2_event(FixtureKey::Member, 1_714_124_434, 1, Vec::new(), "again").expect("second");
    assert_accepted(relay.handle_event(second.clone()).expect("event"), &second);

    assert!(matches!(
        relay.fanout(&second).as_slice(),
        [RelayMessage::Event { subscription_id, event }]
            if subscription_id == &live_id && event.id() == second.id()
    ));
}

#[test]
fn nip11_integration_reports_group_contracts() {
    let groups = group_config();
    let document = BaseRelayInfoConfig::new("tangle", groups)
        .expect("config")
        .build_document()
        .expect("document");
    let disabled = BaseRelayInfoConfig::new("tangle", GroupRuntimeConfig::disabled())
        .expect("config")
        .build_document()
        .expect("disabled");

    assert!(BASE_RELAY_SUPPORTED_NIPS.contains(&1));
    assert!(document.supported_nips.contains(&29));
    assert!(document.supported_nips.contains(&42));
    assert!(document.supported_nips.contains(&45));
    assert!(document.supported_nips.contains(&70));
    assert!(!document.supported_nips.contains(&50));
    assert!(!document.supported_nips.contains(&77));
    assert!(!document.supported_nips.contains(&99));
    assert!(document.relay_self().is_some());
    assert!(!disabled.supported_nips.contains(&29));
    assert!(disabled.relay_self().is_none());
}

#[test]
fn auth_integration_covers_challenge_edges() {
    let mut auth = BaseAuthState::new(TANGLE_V2_RELAY_URL, 20, 600).expect("auth");

    assert_eq!(
        auth.issue_challenge("challenge-a", UnixTimestamp::new(100))
            .expect("challenge"),
        RelayMessage::Auth("challenge-a".to_owned())
    );

    let owner_event = tangle_v2_auth_event(FixtureKey::Owner, "challenge-a", 105).expect("owner");
    let admin_event = tangle_v2_auth_event(FixtureKey::Admin, "challenge-a", 110).expect("admin");

    let owner = auth
        .authenticate(&owner_event, UnixTimestamp::new(105))
        .expect("owner");
    let admin = auth
        .authenticate(&admin_event, UnixTimestamp::new(110))
        .expect("admin");

    assert_ne!(owner, admin);
    assert!(auth.authenticated_pubkeys().contains(&owner));
    assert!(auth.authenticated_pubkeys().contains(&admin));
    assert_eq!(
        auth.authenticate(
            &tangle_v2_auth_event(FixtureKey::Member, "wrong", 111).expect("wrong"),
            UnixTimestamp::new(111),
        )
        .expect_err("wrong")
        .prefixed_message(),
        "auth-required: auth challenge does not match"
    );

    let expired = BaseAuthState::new(TANGLE_V2_RELAY_URL, 1, 600).expect("expired");
    let mut expired = issue_challenge(expired, "challenge-b", 100);
    assert_eq!(
        expired
            .authenticate(
                &tangle_v2_auth_event(FixtureKey::Owner, "challenge-b", 101).expect("expired"),
                UnixTimestamp::new(102),
            )
            .expect_err("expired")
            .prefixed_message(),
        "auth-required: auth challenge expired"
    );

    let mut wrong_relay = BaseAuthState::new("wss://other.radroots.test", 20, 600).expect("relay");
    wrong_relay
        .issue_challenge("challenge-a", UnixTimestamp::new(100))
        .expect("challenge");
    assert_eq!(
        wrong_relay
            .authenticate(&owner_event, UnixTimestamp::new(105))
            .expect_err("relay")
            .prefixed_message(),
        "auth-required: auth relay does not match canonical relay URL"
    );
}

#[test]
fn group_auth_lifecycle_membership_and_flag_flows_pass_in_process() {
    let config = test_store_config("group-flows");
    let groups = group_config_with_public_join();
    let mut relay = BaseRelay::open_with_groups(&config, 8, &groups).expect("relay");
    let owner_auth = authenticated(FixtureKey::Owner);
    let admin_auth = authenticated(FixtureKey::Admin);
    let member_auth = authenticated(FixtureKey::Member);
    let outsider_auth = authenticated(FixtureKey::Outsider);
    let create = tangle_v2_group_create_event(FixtureKey::Owner, "Farm", 1, &[]).expect("create");

    assert_eq!(
        rejected_message(relay.handle_event(create.clone()).expect("no auth")),
        "auth-required: group event author must authenticate with AUTH"
    );
    assert_eq!(
        rejected_message(
            relay
                .handle_event_with_auth(create.clone(), &outsider_auth)
                .expect("wrong auth")
        ),
        "auth-required: group event author must authenticate with AUTH"
    );
    assert_accepted(
        relay
            .handle_event_with_auth(create.clone(), &owner_auth)
            .expect("create"),
        &create,
    );

    let metadata = tangle_v2_group_metadata_event(FixtureKey::Admin, "Farm", "Market", 2, &[])
        .expect("metadata");
    assert_accepted(
        relay
            .handle_event_with_auth(metadata.clone(), &admin_auth)
            .expect("metadata"),
        &metadata,
    );

    let put =
        tangle_v2_put_user_event(FixtureKey::Admin, "Farm", FixtureKey::Member, 3).expect("put");
    assert_accepted(
        relay
            .handle_event_with_auth(put.clone(), &admin_auth)
            .expect("put"),
        &put,
    );
    assert_eq!(
        relay
            .group_projection()
            .expect("projection")
            .member(&group("Farm"), &FixtureKey::Member.public_key())
            .expect("member")
            .status(),
        MemberStatus::Member
    );

    let join = tangle_v2_join_event(FixtureKey::Outsider, "Farm", 4).expect("join");
    assert_accepted(
        relay
            .handle_event_with_auth(join.clone(), &outsider_auth)
            .expect("join"),
        &join,
    );
    assert_eq!(
        rejected_message(
            relay
                .handle_event_with_auth(
                    tangle_v2_join_event(FixtureKey::Outsider, "Farm", 5).expect("duplicate"),
                    &outsider_auth,
                )
                .expect("duplicate")
        ),
        "duplicate: group member already exists"
    );

    let leave = tangle_v2_leave_event(FixtureKey::Outsider, "Farm", 6).expect("leave");
    assert_accepted(
        relay
            .handle_event_with_auth(leave.clone(), &outsider_auth)
            .expect("leave"),
        &leave,
    );
    assert_eq!(
        rejected_message(
            relay
                .handle_event_with_auth(
                    tangle_v2_leave_event(FixtureKey::Admin, "Farm", 7).expect("admin leave"),
                    &admin_auth,
                )
                .expect("admin leave")
        ),
        "duplicate: group member does not exist"
    );

    let protected_remove =
        tangle_v2_remove_user_event(FixtureKey::Admin, "Farm", FixtureKey::Admin, 8)
            .expect("remove admin");
    assert_eq!(
        rejected_message(
            relay
                .handle_event_with_auth(protected_remove, &admin_auth)
                .expect("remove admin")
        ),
        "restricted: permanent group admins cannot be removed"
    );

    let remove = tangle_v2_remove_user_event(FixtureKey::Admin, "Farm", FixtureKey::Member, 9)
        .expect("remove member");
    assert_accepted(
        relay
            .handle_event_with_auth(remove.clone(), &admin_auth)
            .expect("remove member"),
        &remove,
    );
    assert_count(
        relay.handle_count(
            subscription("members"),
            vec![filter_kind(KIND_GROUP_MEMBERS)],
        ),
        1,
    );
    assert_eq!(member_auth.authenticated_pubkeys().len(), 1);
}

#[test]
fn group_join_requests_are_denied_by_default() {
    let config = test_store_config("group-public-join-default");
    let mut relay = BaseRelay::open_with_groups(&config, 8, &group_config()).expect("relay");
    let owner_auth = authenticated(FixtureKey::Owner);
    let outsider_auth = authenticated(FixtureKey::Outsider);
    let create = tangle_v2_group_create_event(FixtureKey::Owner, "Farm", 1, &[]).expect("create");
    assert_accepted(
        relay
            .handle_event_with_auth(create.clone(), &owner_auth)
            .expect("create"),
        &create,
    );
    let join = tangle_v2_join_event(FixtureKey::Outsider, "Farm", 2).expect("join");

    assert_eq!(
        rejected_message(
            relay
                .handle_event_with_auth(join, &outsider_auth)
                .expect("join")
        ),
        "restricted: group is unavailable"
    );
    assert!(
        relay
            .group_projection()
            .expect("projection")
            .member(&group("Farm"), &FixtureKey::Outsider.public_key())
            .is_none()
    );
    assert_eq!(count_kind(&relay, KIND_GROUP_PUT_USER), 0);
}

#[test]
fn metadata_flags_and_read_privacy_cover_req_count_and_fanout() {
    let config = test_store_config("privacy-flags");
    let mut relay = BaseRelay::open_with_groups(&config, 8, &group_config()).expect("relay");
    let owner_auth = authenticated(FixtureKey::Owner);
    let outsider_auth = authenticated(FixtureKey::Outsider);

    accept_group_create(&mut relay, "PrivateFarm", &["private"], 1, &owner_auth);
    let private_event =
        tangle_v2_group_event(FixtureKey::Owner, "PrivateFarm", 2, 1, "private harvest")
            .expect("private");
    assert_accepted(
        relay
            .handle_event_with_auth(private_event.clone(), &owner_auth)
            .expect("private"),
        &private_event,
    );

    let unauth_id = subscription("private-unauth");
    assert_eq!(
        relay
            .handle_req(
                unauth_id.clone(),
                vec![filter_group_tag(1, "h", "PrivateFarm")]
            )
            .expect("unauth"),
        vec![RelayMessage::Eose(unauth_id)]
    );
    assert_count(
        relay.handle_count(
            subscription("private-count-unauth"),
            vec![filter_group_tag(1, "h", "PrivateFarm")],
        ),
        0,
    );
    assert_count(
        relay.handle_count(
            subscription("private-metadata-unauth"),
            vec![filter_group_tag(KIND_GROUP_METADATA, "d", "PrivateFarm")],
        ),
        1,
    );
    assert_count(
        relay.handle_count(
            subscription("private-admins-unauth"),
            vec![filter_group_tag(KIND_GROUP_ADMINS, "d", "PrivateFarm")],
        ),
        1,
    );
    assert_count(
        relay.handle_count(
            subscription("private-members-unauth"),
            vec![filter_kind(KIND_GROUP_MEMBERS)],
        ),
        0,
    );
    let owner_query_id = subscription("private-owner");
    assert_event_query(
        relay
            .handle_req_with_auth(
                owner_query_id.clone(),
                vec![filter_group_tag(1, "h", "PrivateFarm")],
                &owner_auth,
            )
            .expect("owner"),
        &owner_query_id,
        &[&private_event],
    );
    assert_eq!(relay.handle_close(&owner_query_id), CloseResult::Closed);
    assert_count(
        relay.handle_count_with_auth(
            subscription("private-count-owner"),
            vec![filter_group_tag(1, "h", "PrivateFarm")],
            &owner_auth,
        ),
        1,
    );

    let live_unauth = subscription("live-private-unauth");
    let live_owner = subscription("live-private-owner");
    relay
        .handle_req(live_unauth, vec![filter_group_tag(1, "h", "PrivateFarm")])
        .expect("live unauth");
    relay
        .handle_req_with_auth(
            live_owner.clone(),
            vec![filter_group_tag(1, "h", "PrivateFarm")],
            &owner_auth,
        )
        .expect("live owner");
    let second_private =
        tangle_v2_group_event(FixtureKey::Owner, "PrivateFarm", 3, 1, "second").expect("second");
    assert_accepted(
        relay
            .handle_event_with_auth(second_private.clone(), &owner_auth)
            .expect("second"),
        &second_private,
    );
    assert!(matches!(
        relay.fanout(&second_private).as_slice(),
        [RelayMessage::Event { subscription_id, event }]
            if subscription_id == &live_owner && event.id() == second_private.id()
    ));

    accept_group_create(&mut relay, "HiddenFarm", &["hidden"], 10, &owner_auth);
    assert_count(
        relay.handle_count(
            subscription("hidden-unauth"),
            vec![filter_group_tag(KIND_GROUP_METADATA, "d", "HiddenFarm")],
        ),
        0,
    );
    assert_count(
        relay.handle_count_with_auth(
            subscription("hidden-owner"),
            vec![filter_group_tag(KIND_GROUP_METADATA, "d", "HiddenFarm")],
            &owner_auth,
        ),
        1,
    );

    accept_group_create(
        &mut relay,
        "RestrictedFarm",
        &["restricted"],
        20,
        &owner_auth,
    );
    assert_eq!(
        rejected_message(
            relay
                .handle_event_with_auth(
                    tangle_v2_group_event(FixtureKey::Outsider, "RestrictedFarm", 21, 1, "no")
                        .expect("restricted"),
                    &outsider_auth,
                )
                .expect("restricted")
        ),
        "restricted: group is unavailable"
    );

    accept_group_create(&mut relay, "ClosedFarm", &["closed"], 30, &owner_auth);
    assert_eq!(
        rejected_message(
            relay
                .handle_event_with_auth(
                    tangle_v2_join_event(FixtureKey::Outsider, "ClosedFarm", 31)
                        .expect("closed join"),
                    &outsider_auth,
                )
                .expect("closed join")
        ),
        "restricted: group is unavailable"
    );
    let closed_normal = tangle_v2_group_event(FixtureKey::Outsider, "ClosedFarm", 32, 1, "visible")
        .expect("closed normal");
    assert_accepted(
        relay
            .handle_event_with_auth(closed_normal.clone(), &outsider_auth)
            .expect("closed normal"),
        &closed_normal,
    );
}

#[test]
fn nip29_privacy_leak_suite_covers_relay_exposure_and_rejection_paths() {
    let config = test_store_config("nip29-leak-suite");
    let mut relay = BaseRelay::open_with_groups(&config, 16, &group_config()).expect("relay");
    let owner_auth = authenticated(FixtureKey::Owner);
    let admin_auth = authenticated(FixtureKey::Admin);
    let member_auth = authenticated(FixtureKey::Member);
    let outsider_auth = authenticated(FixtureKey::Outsider);

    let unauthorized_create =
        tangle_v2_group_create_event(FixtureKey::Owner, "UnauthorizedFarm", 1, &[])
            .expect("unauthorized");
    assert_eq!(
        rejected_message(
            relay
                .handle_event(unauthorized_create.clone())
                .expect("no auth")
        ),
        "auth-required: group event author must authenticate with AUTH"
    );
    assert_eq!(
        rejected_message(
            relay
                .handle_event_with_auth(unauthorized_create, &outsider_auth)
                .expect("wrong auth")
        ),
        "auth-required: group event author must authenticate with AUTH"
    );
    assert_count(
        relay.handle_count(
            subscription("unauthorized-generated"),
            vec![filter_group_tag(
                KIND_GROUP_METADATA,
                "d",
                "UnauthorizedFarm",
            )],
        ),
        0,
    );

    accept_group_create(&mut relay, "LeakPrivate", &["private"], 10, &owner_auth);
    let put_member =
        tangle_v2_put_user_event(FixtureKey::Admin, "LeakPrivate", FixtureKey::Member, 11)
            .expect("put member");
    assert_accepted(
        relay
            .handle_event_with_auth(put_member.clone(), &admin_auth)
            .expect("put member"),
        &put_member,
    );
    let private_event = tangle_v2_group_event(FixtureKey::Member, "LeakPrivate", 12, 1, "private")
        .expect("private");
    assert_accepted(
        relay
            .handle_event_with_auth(private_event.clone(), &member_auth)
            .expect("private"),
        &private_event,
    );

    let private_unauth = subscription("private-leak-unauth");
    assert_event_query(
        relay
            .handle_req(
                private_unauth.clone(),
                vec![filter_group_tag(1, "h", "LeakPrivate")],
            )
            .expect("private unauth"),
        &private_unauth,
        &[],
    );
    assert_count(
        relay.handle_count(
            subscription("private-count-unauth"),
            vec![filter_group_tag(1, "h", "LeakPrivate")],
        ),
        0,
    );
    let private_member = subscription("private-leak-member");
    assert_event_query(
        relay
            .handle_req_with_auth(
                private_member.clone(),
                vec![filter_group_tag(1, "h", "LeakPrivate")],
                &member_auth,
            )
            .expect("private member"),
        &private_member,
        &[&private_event],
    );
    assert_eq!(relay.handle_close(&private_member), CloseResult::Closed);

    let live_unauth = subscription("private-live-unauth");
    let live_member = subscription("private-live-member");
    relay
        .handle_req(live_unauth, vec![filter_group_tag(1, "h", "LeakPrivate")])
        .expect("private live unauth");
    relay
        .handle_req_with_auth(
            live_member.clone(),
            vec![filter_group_tag(1, "h", "LeakPrivate")],
            &member_auth,
        )
        .expect("private live member");
    let live_private = tangle_v2_group_event(FixtureKey::Member, "LeakPrivate", 13, 1, "live")
        .expect("live private");
    assert_accepted(
        relay
            .handle_event_with_auth(live_private.clone(), &member_auth)
            .expect("live private"),
        &live_private,
    );
    assert!(matches!(
        relay.fanout(&live_private).as_slice(),
        [RelayMessage::Event { subscription_id, event }]
            if subscription_id == &live_member && event.id() == live_private.id()
    ));

    assert_count(
        relay.handle_count(
            subscription("private-metadata-public"),
            vec![filter_group_tag(KIND_GROUP_METADATA, "d", "LeakPrivate")],
        ),
        1,
    );
    assert_count(
        relay.handle_count(
            subscription("private-members-public"),
            vec![filter_group_tag(KIND_GROUP_MEMBERS, "d", "LeakPrivate")],
        ),
        0,
    );

    accept_group_create(&mut relay, "LeakHidden", &["hidden"], 20, &owner_auth);
    assert_count(
        relay.handle_count(
            subscription("hidden-metadata-public"),
            vec![filter_group_tag(KIND_GROUP_METADATA, "d", "LeakHidden")],
        ),
        0,
    );
    assert_count(
        relay.handle_count_with_auth(
            subscription("hidden-metadata-owner"),
            vec![filter_group_tag(KIND_GROUP_METADATA, "d", "LeakHidden")],
            &owner_auth,
        ),
        1,
    );

    accept_group_create(
        &mut relay,
        "LeakRestricted",
        &["restricted"],
        30,
        &owner_auth,
    );
    let restricted_event =
        tangle_v2_group_event(FixtureKey::Outsider, "LeakRestricted", 31, 1, "restricted")
            .expect("restricted");
    assert_eq!(
        rejected_message(
            relay
                .handle_event_with_auth(restricted_event, &outsider_auth)
                .expect("restricted")
        ),
        "restricted: group is unavailable"
    );
    assert_count(
        relay.handle_count(
            subscription("restricted-count"),
            vec![filter_group_tag(1, "h", "LeakRestricted")],
        ),
        0,
    );

    accept_group_create(&mut relay, "LeakClosed", &["closed"], 40, &owner_auth);
    let closed_join =
        tangle_v2_join_event(FixtureKey::Outsider, "LeakClosed", 41).expect("closed join");
    assert_eq!(
        rejected_message(
            relay
                .handle_event_with_auth(closed_join, &outsider_auth)
                .expect("closed join")
        ),
        "restricted: group is unavailable"
    );
    assert_count(
        relay.handle_count(
            subscription("closed-join-count"),
            vec![filter_group_tag(KIND_GROUP_JOIN_REQUEST, "h", "LeakClosed")],
        ),
        0,
    );
    let closed_normal =
        tangle_v2_group_event(FixtureKey::Outsider, "LeakClosed", 42, 1, "closed normal")
            .expect("closed normal");
    assert_accepted(
        relay
            .handle_event_with_auth(closed_normal.clone(), &outsider_auth)
            .expect("closed normal"),
        &closed_normal,
    );
    assert_count(
        relay.handle_count(
            subscription("closed-normal-count"),
            vec![filter_group_tag(1, "h", "LeakClosed")],
        ),
        1,
    );

    let duplicate_join =
        tangle_v2_join_event(FixtureKey::Member, "LeakPrivate", 50).expect("duplicate join");
    assert_eq!(
        rejected_message(
            relay
                .handle_event_with_auth(duplicate_join, &member_auth)
                .expect("duplicate join")
        ),
        "duplicate: group member already exists"
    );
    assert_count(
        relay.handle_count(
            subscription("duplicate-join-count"),
            vec![filter_group_tag(
                KIND_GROUP_JOIN_REQUEST,
                "h",
                "LeakPrivate",
            )],
        ),
        0,
    );
    let duplicate_leave =
        tangle_v2_leave_event(FixtureKey::Outsider, "LeakPrivate", 51).expect("duplicate leave");
    assert_eq!(
        rejected_message(
            relay
                .handle_event_with_auth(duplicate_leave, &outsider_auth)
                .expect("duplicate leave")
        ),
        "duplicate: group member does not exist"
    );
    assert_count(
        relay.handle_count(
            subscription("duplicate-leave-count"),
            vec![filter_group_tag(
                KIND_GROUP_LEAVE_REQUEST,
                "h",
                "LeakPrivate",
            )],
        ),
        0,
    );

    for (index, kind) in NIP29_RELAY_GENERATED_KIND_VALUES
        .iter()
        .copied()
        .enumerate()
    {
        let generated = tangle_v2_event(
            FixtureKey::Owner,
            60 + u64::try_from(index).expect("index"),
            u64::from(kind),
            vec![Tag::from_parts("d", &["ClientGenerated"]).expect("d")],
            "",
        )
        .expect("generated");
        assert_eq!(
            rejected_message(
                relay
                    .handle_event_with_auth(generated, &owner_auth)
                    .expect("generated")
            ),
            "blocked: relay-generated group state events cannot be submitted by clients"
        );
        assert_count(
            relay.handle_count(
                subscription("client-generated-count"),
                vec![filter_group_tag(kind, "d", "ClientGenerated")],
            ),
            0,
        );
    }

    accept_group_create(&mut relay, "LeakDeleted", &[], 70, &owner_auth);
    let deleted_target = tangle_v2_group_event(FixtureKey::Owner, "LeakDeleted", 71, 1, "deleted")
        .expect("deleted target");
    assert_accepted(
        relay
            .handle_event_with_auth(deleted_target.clone(), &owner_auth)
            .expect("deleted target"),
        &deleted_target,
    );
    let delete_target = tangle_test_support::tangle_v2_delete_event_event(
        FixtureKey::Owner,
        "LeakDeleted",
        &deleted_target,
        72,
    )
    .expect("delete target");
    assert_accepted(
        relay
            .handle_event_with_auth(delete_target.clone(), &owner_auth)
            .expect("delete target"),
        &delete_target,
    );
    assert_count(
        relay.handle_count(
            subscription("deleted-target-count"),
            vec![filter_group_tag(1, "h", "LeakDeleted")],
        ),
        0,
    );
    let deleted_query = subscription("deleted-target-query");
    assert_event_query(
        relay
            .handle_req(
                deleted_query.clone(),
                vec![filter_group_tag(1, "h", "LeakDeleted")],
            )
            .expect("deleted query"),
        &deleted_query,
        &[],
    );
    let delete_group =
        tangle_v2_delete_group_event(FixtureKey::Owner, "LeakDeleted", 73).expect("delete group");
    assert_accepted(
        relay
            .handle_event_with_auth(delete_group.clone(), &owner_auth)
            .expect("delete group"),
        &delete_group,
    );
    assert_eq!(
        rejected_message(
            relay
                .handle_event_with_auth(
                    tangle_v2_group_event(FixtureKey::Owner, "LeakDeleted", 74, 1, "late")
                        .expect("late deleted"),
                    &owner_auth,
                )
                .expect("late deleted")
        ),
        "blocked: group is deleted"
    );

    accept_group_create(
        &mut relay,
        "LeakUnauthorizedCapability",
        &[],
        80,
        &owner_auth,
    );
    let unauthorized_put = tangle_v2_put_user_event(
        FixtureKey::Outsider,
        "LeakUnauthorizedCapability",
        FixtureKey::Member,
        81,
    )
    .expect("unauthorized put");
    assert_eq!(
        rejected_message(
            relay
                .handle_event_with_auth(unauthorized_put, &outsider_auth)
                .expect("unauthorized put")
        ),
        "restricted: missing group capability manage_members"
    );
    assert_count(
        relay.handle_count(
            subscription("unauthorized-put-count"),
            vec![filter_group_tag(
                KIND_GROUP_PUT_USER,
                "h",
                "LeakUnauthorizedCapability",
            )],
        ),
        0,
    );
}

#[test]
fn delete_and_secondary_privacy_surfaces_are_read_gated_or_absent() {
    let config = test_store_config("delete-privacy");
    let mut relay = BaseRelay::open_with_groups(&config, 8, &group_config()).expect("relay");
    let owner_auth = authenticated(FixtureKey::Owner);

    accept_group_create(&mut relay, "DeleteFarm", &[], 1, &owner_auth);
    let target =
        tangle_v2_group_event(FixtureKey::Owner, "DeleteFarm", 2, 1, "target").expect("target");
    assert_accepted(
        relay
            .handle_event_with_auth(target.clone(), &owner_auth)
            .expect("target"),
        &target,
    );
    let delete = tangle_test_support::tangle_v2_delete_event_event(
        FixtureKey::Owner,
        "DeleteFarm",
        &target,
        3,
    )
    .expect("delete");
    assert_accepted(
        relay
            .handle_event_with_auth(delete.clone(), &owner_auth)
            .expect("delete"),
        &delete,
    );

    assert_count(
        relay.handle_count(
            subscription("deleted-target"),
            vec![filter_group_tag(1, "h", "DeleteFarm")],
        ),
        0,
    );
    assert_count(
        relay.handle_count(
            subscription("delete-marker"),
            vec![filter_group_tag(KIND_GROUP_DELETE_GROUP, "h", "DeleteFarm")],
        ),
        0,
    );
    let delete_group =
        tangle_v2_delete_group_event(FixtureKey::Owner, "DeleteFarm", 4).expect("delete group");
    assert_accepted(
        relay
            .handle_event_with_auth(delete_group.clone(), &owner_auth)
            .expect("delete group"),
        &delete_group,
    );
    assert_eq!(
        rejected_message(
            relay
                .handle_event_with_auth(
                    tangle_v2_group_event(FixtureKey::Owner, "DeleteFarm", 5, 1, "late")
                        .expect("late"),
                    &owner_auth,
                )
                .expect("late")
        ),
        "blocked: group is deleted"
    );
    assert_count(
        relay.handle_count(
            subscription("group-marker"),
            vec![filter_group_tag(KIND_GROUP_DELETE_GROUP, "h", "DeleteFarm")],
        ),
        1,
    );

    let document = BaseRelayInfoConfig::new("tangle", group_config())
        .expect("config")
        .build_document()
        .expect("document");
    assert!(!document.supported_nips.contains(&77));
    assert!(!document.supported_nips.contains(&86));
    assert!(!document.supported_nips.contains(&98));
}

#[test]
fn projection_rebuild_after_restart_matches_live_state_and_outbox_is_idempotent() {
    let config = test_store_config("projection-restart");
    let owner_auth = authenticated(FixtureKey::Owner);
    {
        let mut relay = BaseRelay::open_with_groups(&config, 8, &group_config()).expect("relay");
        accept_group_create(&mut relay, "RestartFarm", &[], 1, &owner_auth);
        let put = tangle_v2_put_user_event(FixtureKey::Admin, "RestartFarm", FixtureKey::Member, 2)
            .expect("put");
        let admin_auth = authenticated(FixtureKey::Admin);
        assert_accepted(
            relay
                .handle_event_with_auth(put.clone(), &admin_auth)
                .expect("put"),
            &put,
        );
        assert_eq!(count_kind(&relay, KIND_GROUP_METADATA), 1);
        assert_eq!(count_kind(&relay, KIND_GROUP_ADMINS), 1);
        assert_eq!(count_kind(&relay, KIND_GROUP_MEMBERS), 1);
        relay.shutdown().expect("shutdown");
    }

    let relay = BaseRelay::open_with_groups(&config, 8, &group_config()).expect("reopen");
    assert!(
        relay
            .group_projection()
            .expect("projection")
            .group(&group("RestartFarm"))
            .is_some()
    );
    assert_eq!(
        relay
            .group_projection()
            .expect("projection")
            .member(&group("RestartFarm"), &FixtureKey::Member.public_key())
            .expect("member")
            .status(),
        MemberStatus::Member
    );
    assert_eq!(count_kind(&relay, KIND_GROUP_METADATA), 1);
    assert_eq!(count_kind(&relay, KIND_GROUP_ADMINS), 1);
    assert_eq!(count_kind(&relay, KIND_GROUP_MEMBERS), 1);

    let relay = BaseRelay::open_with_groups(&config, 8, &group_config()).expect("second reopen");
    assert_eq!(count_kind(&relay, KIND_GROUP_METADATA), 1);
    assert_eq!(count_kind(&relay, KIND_GROUP_ADMINS), 1);
    assert_eq!(count_kind(&relay, KIND_GROUP_MEMBERS), 1);
}

#[test]
fn same_timestamp_conflicts_are_deterministic_across_ingest_order() {
    let first = tangle_v2_group_metadata_event(FixtureKey::Owner, "ClockFarm", "Alpha", 100, &[])
        .expect("first");
    let second = tangle_v2_group_metadata_event(FixtureKey::Owner, "ClockFarm", "Beta", 100, &[])
        .expect("second");
    let expected = if first.id() > second.id() {
        "Alpha"
    } else {
        "Beta"
    };

    assert_eq!(
        final_group_name_for_order("conflict-a", [&first, &second]),
        expected
    );
    assert_eq!(
        final_group_name_for_order("conflict-b", [&second, &first]),
        expected
    );
}

#[test]
fn malformed_input_fuzz_smoke_rejects_without_panic() {
    for raw in [
        "",
        "[]",
        "[\"EVENT\"]",
        "[\"REQ\",\"sub\",{\"#h\":[1]}]",
        "[\"AUTH\",{}]",
        "[\"COUNT\",\"sub\",{\"kinds\":[4294967296]}]",
    ] {
        panic::catch_unwind(|| {
            let _ = parse_client_message(raw);
        })
        .expect("client parser must not panic");
    }

    for raw in [
        "{}",
        "{\"id\":\"bad\"}",
        "{\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"pubkey\":\"bad\",\"created_at\":0,\"kind\":1,\"tags\":[],\"content\":\"\",\"sig\":\"bad\"}",
    ] {
        panic::catch_unwind(|| {
            if let Ok(raw) = RawEventJson::new(raw) {
                let _ = parse_event_json(&raw);
            }
        })
        .expect("event parser must not panic");
    }

    for value in [
        serde_json::json!({"#h":[1]}),
        serde_json::json!({"ids":[1]}),
        serde_json::json!({"authors":[false]}),
        serde_json::json!({"kinds":["bad"]}),
        serde_json::json!({"limit":-1}),
    ] {
        panic::catch_unwind(|| {
            let _ = filter_from_value(&value);
        })
        .expect("filter parser must not panic");
    }

    for values in [vec![], vec!["".to_owned()], vec!["h".to_owned()]] {
        panic::catch_unwind(|| {
            let _ = Tag::new(values);
        })
        .expect("tag parser must not panic");
    }
}

fn accept_group_create(
    relay: &mut BaseRelay,
    group_id: &str,
    flags: &[&str],
    created_at: u64,
    auth: &BaseAuthState,
) {
    let event = tangle_v2_group_create_event(FixtureKey::Owner, group_id, created_at, flags)
        .expect("event");
    assert_accepted(
        relay
            .handle_event_with_auth(event.clone(), auth)
            .expect("create"),
        &event,
    );
}

fn final_group_name_for_order(name: &str, edits: [&Event; 2]) -> String {
    let config = test_store_config(name);
    let mut relay = BaseRelay::open_with_groups(&config, 8, &group_config()).expect("relay");
    let auth = authenticated(FixtureKey::Owner);
    accept_group_create(&mut relay, "ClockFarm", &[], 1, &auth);
    for edit in edits {
        assert_accepted(
            relay
                .handle_event_with_auth(edit.clone(), &auth)
                .expect("edit"),
            edit,
        );
    }
    relay
        .group_projection()
        .expect("projection")
        .group(&group("ClockFarm"))
        .expect("group")
        .metadata()
        .name()
        .expect("name")
        .to_owned()
}

fn test_store_config(name: &str) -> PocketStoreConfig {
    let root = temp_root(name);
    let _ = fs::remove_dir_all(&root);
    PocketStoreConfig::new(
        root.join("pocket"),
        1024 * 1024 * 1024,
        128,
        PocketSyncPolicy::FlushOnShutdown,
    )
    .expect("config")
}

fn temp_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("tangle-rcld12-{name}-{}", std::process::id()))
}

fn group_config() -> GroupRuntimeConfig {
    tangle_v2_group_config(FixtureKey::Owner, &[FixtureKey::Admin]).expect("groups")
}

fn group_config_with_public_join() -> GroupRuntimeConfig {
    parse_group_runtime_config_json(&format!(
        r#"{{
            "enabled": true,
            "canonical_relay_url": "{TANGLE_V2_RELAY_URL}",
            "relay_secret": "{TANGLE_V2_RELAY_SECRET_HEX}",
            "owner_pubkeys": ["{}"],
            "admin_pubkeys": ["{}"],
            "policy": {{"public_join": true, "invites_enabled": false}}
        }}"#,
        FixtureKey::Owner.public_key().as_str(),
        FixtureKey::Admin.public_key().as_str()
    ))
    .expect("groups")
}

fn authenticated(key: FixtureKey) -> BaseAuthState {
    let auth = BaseAuthState::new(TANGLE_V2_RELAY_URL, 60, 600).expect("auth");
    let mut auth = issue_challenge(auth, "challenge-a", 100);
    let event = tangle_v2_auth_event(key, "challenge-a", 120).expect("auth event");
    auth.authenticate(&event, UnixTimestamp::new(120))
        .expect("authenticate");
    auth
}

fn issue_challenge(mut auth: BaseAuthState, challenge: &str, created_at: u64) -> BaseAuthState {
    auth.issue_challenge(challenge, UnixTimestamp::new(created_at))
        .expect("challenge");
    auth
}

fn assert_accepted(message: RelayMessage, event: &Event) {
    assert_eq!(
        message,
        RelayMessage::Ok {
            event_id: event.id().clone(),
            accepted: true,
            message: String::new()
        }
    );
    assert!(event_id_matches(event));
    assert_eq!(verify_event_signature(event), Ok(()));
}

fn rejected_message(message: RelayMessage) -> String {
    match message {
        RelayMessage::Ok {
            accepted: false,
            message,
            ..
        } => message,
        value => panic!("expected rejected OK, got {value:?}"),
    }
}

fn assert_event_query(
    messages: Vec<RelayMessage>,
    subscription_id: &SubscriptionId,
    events: &[&Event],
) {
    assert_eq!(messages.len(), events.len() + 1);
    for (message, expected) in messages.iter().zip(events.iter()) {
        match message {
            RelayMessage::Event {
                subscription_id: actual_subscription,
                event,
            } => {
                assert_eq!(actual_subscription, subscription_id);
                assert_eq!(event.id(), expected.id());
            }
            value => panic!("expected event, got {value:?}"),
        }
    }
    assert_eq!(
        messages.last(),
        Some(&RelayMessage::Eose(subscription_id.clone()))
    );
}

fn assert_count(
    message: Result<RelayMessage, tangle_runtime::errors::BaseRelayError>,
    expected: u64,
) {
    let RelayMessage::Count { count, .. } = message.expect("count") else {
        panic!("expected count")
    };
    assert_eq!(count, expected);
}

fn count_kind(relay: &BaseRelay, kind: u32) -> u64 {
    let RelayMessage::Count { count, .. } = relay
        .handle_count(subscription("count-kind"), vec![filter_kind(kind)])
        .expect("count")
    else {
        panic!("expected count")
    };
    count
}

fn filter_kind(kind: u32) -> Filter {
    filter_from_value(&serde_json::json!({"kinds":[kind]})).expect("filter")
}

fn filter_group_tag(kind: u32, tag_name: &str, tag_value: &str) -> Filter {
    let mut value = serde_json::Map::new();
    value.insert("kinds".to_owned(), serde_json::json!([kind]));
    value.insert(format!("#{tag_name}"), serde_json::json!([tag_value]));
    filter_from_value(&serde_json::Value::Object(value)).expect("filter")
}

fn group(value: &str) -> GroupId {
    GroupId::new(value).expect("group")
}

fn subscription(value: &str) -> SubscriptionId {
    SubscriptionId::new(value).expect("subscription")
}
