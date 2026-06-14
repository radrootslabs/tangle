#![forbid(unsafe_code)]

use std::{fs, panic, path::PathBuf};
use tangle_crypto::{event_id_matches, verify_event_signature};
use tangle_groups::{
    GroupAuthority, GroupGeneratedEventBuilder, GroupId, GroupLimitsConfig, GroupOutboxEffect,
    GroupOutboxKey, GroupOutboxRecord, GroupOutboxStatus, GroupProjection, GroupRuntimeConfig,
    KIND_GROUP_ADMINS, KIND_GROUP_DELETE_GROUP, KIND_GROUP_JOIN_REQUEST, KIND_GROUP_LEAVE_REQUEST,
    KIND_GROUP_MEMBERS, KIND_GROUP_METADATA, KIND_GROUP_PUT_USER, MemberStatus,
    NIP29_RELAY_GENERATED_KIND_VALUES, PERMANENT_RELAY_OVERRIDE_ROLE, ProjectionCheckpoint,
    StoreOffset, member_current_key, parse_group_runtime_config_json, projection_checkpoint_key,
};
use tangle_protocol::{
    Event, Filter, RawEventJson, RelayMessage, SubscriptionId, Tag, UnixTimestamp, event_to_value,
    filter_from_value, parse_client_message, parse_event_json,
};
use tangle_runtime::{
    config::{BaseRelayRuntimeConfig, parse_base_relay_runtime_config_json},
    groups::{GroupCheckpointStatus, validate_group_extra_tables},
    nip11::BaseRelayInfoConfig,
    relay::{
        auth::BaseAuthState,
        core::{BaseRelay, BaseRelayLimitSettings, BaseRelayLimits},
        live::CloseResult,
    },
};
use tangle_store_pocket::{
    PocketQueryConfig, PocketStoreConfig, PocketStoreHandle, PocketSyncPolicy,
    TANGLE_GROUP_CHECKPOINT_TABLE, TANGLE_GROUP_OUTBOX_TABLE, TANGLE_GROUP_PROJECTION_TABLE,
    parse_pocket_event_json,
};
use tangle_test_support::{
    FixtureKey, TANGLE_V2_RELAY_SECRET_HEX, TANGLE_V2_RELAY_URL, tangle_v2_auth_event,
    tangle_v2_delete_event_event, tangle_v2_delete_group_event, tangle_v2_event,
    tangle_v2_group_config, tangle_v2_group_create_event, tangle_v2_group_event,
    tangle_v2_group_metadata_event, tangle_v2_group_tag, tangle_v2_join_event,
    tangle_v2_leave_event, tangle_v2_pubkey_tag, tangle_v2_put_user_event,
    tangle_v2_remove_user_event, tangle_v2_tag,
};

#[test]
fn public_relay_smoke_stores_queries_counts_and_fans_out() {
    let config = test_store_config("public-smoke");
    let mut relay =
        BaseRelay::open(&config, relay_limits(4), PocketQueryConfig::default()).expect("relay");
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
    let config = runtime_config(true);
    let disabled_config = runtime_config(false);
    let document = BaseRelayInfoConfig::new("tangle", &config)
        .expect("config")
        .build_document()
        .expect("document");
    let disabled = BaseRelayInfoConfig::new("tangle", &disabled_config)
        .expect("config")
        .build_document()
        .expect("disabled");

    assert_eq!(document.supported_nips, vec![1, 11, 29, 42, 45, 70]);
    assert!(!document.supported_nips.contains(&50));
    assert!(!document.supported_nips.contains(&77));
    assert!(!document.supported_nips.contains(&99));
    assert!(document.relay_self().is_some());
    assert_eq!(document.limitation.max_message_length, 1_048_576);
    assert_eq!(document.limitation.max_subscriptions, 64);
    assert_eq!(document.limitation.max_filters, 10);
    assert_eq!(document.limitation.max_limit, 500);
    assert_eq!(document.limitation.max_query_complexity, 2_048);
    assert_eq!(document.limitation.max_subid_length, 64);
    assert_eq!(document.limitation.max_event_tags, 200);
    assert_eq!(document.limitation.max_content_length, 65_536);
    assert!(!document.limitation.auth_required);
    assert!(!document.limitation.payment_required);
    assert!(document.limitation.restricted_writes);
    assert_eq!(document.limitation.default_limit, 100);
    assert!(!document.retention.physical_erasure);
    assert!(!document.retention.compaction_guarantee);
    assert_eq!(
        document.retention.group_visibility,
        "private and hidden group policy gates visibility without implying physical deletion"
    );
    assert_eq!(disabled.supported_nips, vec![1, 11, 42, 45, 70]);
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
    let relay = BaseRelay::open_with_groups(
        &config,
        relay_limits(8),
        &groups,
        PocketQueryConfig::default(),
    )
    .expect("relay");
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
fn relay_override_role_changes_generate_admin_snapshots() {
    let config = test_store_config("role-admin-snapshots");
    let mut relay = BaseRelay::open_with_groups(
        &config,
        relay_limits(8),
        &group_config(),
        PocketQueryConfig::default(),
    )
    .expect("relay");
    let owner_auth = authenticated(FixtureKey::Owner);
    let admin_auth = authenticated(FixtureKey::Admin);
    let member = FixtureKey::Member.public_key().as_str().to_owned();
    let owner = FixtureKey::Owner.public_key().as_str().to_owned();
    let admin = FixtureKey::Admin.public_key().as_str().to_owned();

    accept_group_create(&mut relay, "RoleFarm", &[], 1, &owner_auth);
    assert_eq!(
        stored_event_ids_for_kind(&config, KIND_GROUP_ADMINS).len(),
        1
    );

    let promote = tangle_v2_put_user_event_with_roles(
        FixtureKey::Admin,
        "RoleFarm",
        FixtureKey::Member,
        2,
        &[PERMANENT_RELAY_OVERRIDE_ROLE],
    );
    assert_accepted(
        relay
            .handle_event_with_auth(promote.clone(), &admin_auth)
            .expect("promote"),
        &promote,
    );
    assert!(
        relay
            .group_projection()
            .expect("projection")
            .member(&group("RoleFarm"), &FixtureKey::Member.public_key())
            .expect("member")
            .roles()
            .iter()
            .any(|role| role.as_str() == PERMANENT_RELAY_OVERRIDE_ROLE)
    );
    assert_eq!(outbox_status_counts(&config).stored, 4);
    assert_eq!(
        stored_event_ids_for_kind(&config, KIND_GROUP_ADMINS).len(),
        2
    );
    assert_eq!(
        latest_admin_snapshot_pubkeys(&mut relay, "RoleFarm"),
        sorted_strings([owner.clone(), admin.clone(), member.clone()])
    );

    let demote = tangle_v2_put_user_event_with_roles(
        FixtureKey::Admin,
        "RoleFarm",
        FixtureKey::Member,
        3,
        &[],
    );
    assert_accepted(
        relay
            .handle_event_with_auth(demote.clone(), &admin_auth)
            .expect("demote"),
        &demote,
    );
    assert_eq!(
        stored_event_ids_for_kind(&config, KIND_GROUP_ADMINS).len(),
        3
    );
    assert_eq!(
        latest_admin_snapshot_pubkeys(&mut relay, "RoleFarm"),
        sorted_strings([owner, admin])
    );
}

#[test]
fn group_join_requests_are_denied_by_default() {
    let config = test_store_config("group-public-join-default");
    let relay = BaseRelay::open_with_groups(
        &config,
        relay_limits(8),
        &group_config(),
        PocketQueryConfig::default(),
    )
    .expect("relay");
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
    let mut relay = BaseRelay::open_with_groups(
        &config,
        relay_limits(8),
        &group_config(),
        PocketQueryConfig::default(),
    )
    .expect("relay");
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
    let mut relay = BaseRelay::open_with_groups(
        &config,
        relay_limits(16),
        &group_config(),
        PocketQueryConfig::default(),
    )
    .expect("relay");
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
    let mut relay = BaseRelay::open_with_groups(
        &config,
        relay_limits(8),
        &group_config(),
        PocketQueryConfig::default(),
    )
    .expect("relay");
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

    let config = runtime_config(true);
    let document = BaseRelayInfoConfig::new("tangle", &config)
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
        let mut relay = BaseRelay::open_with_groups(
            &config,
            relay_limits(8),
            &group_config(),
            PocketQueryConfig::default(),
        )
        .expect("relay");
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
    delete_group_extra_records(&config);

    let relay = BaseRelay::open_with_groups(
        &config,
        relay_limits(8),
        &group_config(),
        PocketQueryConfig::default(),
    )
    .expect("reopen");
    assert_eq!(
        relay
            .readiness_state()
            .response()
            .checks
            .group_outbox_replay,
        "ready"
    );
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
    assert!(
        relay
            .group_projection()
            .expect("projection")
            .checkpoint()
            .is_some()
    );
    assert_eq!(count_kind(&relay, KIND_GROUP_METADATA), 1);
    assert_eq!(count_kind(&relay, KIND_GROUP_ADMINS), 1);
    assert_eq!(count_kind(&relay, KIND_GROUP_MEMBERS), 1);
    let validation = group_extra_table_validation(&config);
    assert!(validation.projection_records() > 0);
    assert_eq!(validation.outbox_records(), 3);
    assert!(matches!(
        validation.checkpoint_status(),
        &GroupCheckpointStatus::Current { .. }
    ));

    let relay = BaseRelay::open_with_groups(
        &config,
        relay_limits(8),
        &group_config(),
        PocketQueryConfig::default(),
    )
    .expect("second reopen");
    assert_eq!(count_kind(&relay, KIND_GROUP_METADATA), 1);
    assert_eq!(count_kind(&relay, KIND_GROUP_ADMINS), 1);
    assert_eq!(count_kind(&relay, KIND_GROUP_MEMBERS), 1);
}

#[test]
fn projection_applies_canonical_events_after_checkpoint_on_restart() {
    let config = test_store_config("projection-incremental");
    let owner_auth = authenticated(FixtureKey::Owner);
    let admin_auth = authenticated(FixtureKey::Admin);
    let create =
        tangle_v2_group_create_event(FixtureKey::Owner, "IncrementalFarm", 1, &[]).expect("create");
    let put = tangle_v2_put_user_event(FixtureKey::Admin, "IncrementalFarm", FixtureKey::Member, 2)
        .expect("put");
    {
        let mut relay = BaseRelay::open_with_groups(
            &config,
            relay_limits(8),
            &group_config(),
            PocketQueryConfig::default(),
        )
        .expect("relay");
        assert_accepted(
            relay
                .handle_event_with_auth(create.clone(), &owner_auth)
                .expect("create"),
            &create,
        );
        assert_accepted(
            relay
                .handle_event_with_auth(put.clone(), &admin_auth)
                .expect("put"),
            &put,
        );
        relay.shutdown().expect("shutdown");
    }
    let create_offset = stored_event_offset(&config, &create);
    regress_member_projection_to_checkpoint(&config, create_offset, "IncrementalFarm");

    let relay = BaseRelay::open_with_groups(
        &config,
        relay_limits(8),
        &group_config(),
        PocketQueryConfig::default(),
    )
    .expect("reopen");
    assert_eq!(
        relay
            .group_projection()
            .expect("projection")
            .member(&group("IncrementalFarm"), &FixtureKey::Member.public_key())
            .expect("member")
            .status(),
        MemberStatus::Member
    );
    let validation = group_extra_table_validation(&config);
    match validation.checkpoint_status() {
        GroupCheckpointStatus::Current { checkpoint } => assert!(
            checkpoint
                .last_offset()
                .is_some_and(|offset| offset.as_u64() > create_offset)
        ),
        status => panic!("expected current checkpoint, got {status:?}"),
    }
}

#[test]
fn source_store_crash_recovery_rebuilds_projection_outbox_and_generated_events() {
    let config = test_store_config("source-store-crash-recovery");
    let create =
        tangle_v2_group_create_event(FixtureKey::Owner, "CrashFarm", 1, &[]).expect("create");
    let put = tangle_v2_put_user_event(FixtureKey::Admin, "CrashFarm", FixtureKey::Member, 2)
        .expect("put");

    store_source_events(&config, &[create, put]);

    let relay = BaseRelay::open_with_groups(
        &config,
        relay_limits(8),
        &group_config(),
        PocketQueryConfig::default(),
    )
    .expect("reopen");
    assert_eq!(
        relay
            .readiness_state()
            .response()
            .checks
            .group_outbox_replay,
        "ready"
    );
    assert!(
        relay
            .group_projection()
            .expect("projection")
            .group(&group("CrashFarm"))
            .is_some()
    );
    assert_eq!(
        relay
            .group_projection()
            .expect("projection")
            .member(&group("CrashFarm"), &FixtureKey::Member.public_key())
            .expect("member")
            .status(),
        MemberStatus::Member
    );
    assert_eq!(
        stored_event_ids_for_kind(&config, KIND_GROUP_METADATA).len(),
        1
    );
    assert_eq!(
        stored_event_ids_for_kind(&config, KIND_GROUP_ADMINS).len(),
        1
    );
    assert_eq!(
        stored_event_ids_for_kind(&config, KIND_GROUP_MEMBERS).len(),
        1
    );
    let counts = outbox_status_counts(&config);
    assert_eq!(counts.pending, 0);
    assert_eq!(counts.retryable, 0);
    assert_eq!(counts.stored, 3);
}

#[test]
fn rebuilt_projection_matches_live_projection_for_moderation_stream() {
    let config = test_store_config("projection-equivalence");
    let owner_auth = authenticated(FixtureKey::Owner);
    let admin_auth = authenticated(FixtureKey::Admin);
    let member_auth = authenticated(FixtureKey::Member);
    let live_projection;
    let metadata_before;
    let admins_before;
    let members_before;

    {
        let mut relay = BaseRelay::open_with_groups(
            &config,
            relay_limits(16),
            &group_config(),
            PocketQueryConfig::default(),
        )
        .expect("relay");
        accept_group_create(&mut relay, "EquivFarm", &[], 1, &owner_auth);
        let metadata =
            tangle_v2_group_metadata_event(FixtureKey::Admin, "EquivFarm", "Market", 2, &[])
                .expect("metadata");
        assert_accepted(
            relay
                .handle_event_with_auth(metadata.clone(), &admin_auth)
                .expect("metadata"),
            &metadata,
        );
        let promote = tangle_v2_put_user_event_with_roles(
            FixtureKey::Admin,
            "EquivFarm",
            FixtureKey::Member,
            3,
            &[PERMANENT_RELAY_OVERRIDE_ROLE],
        );
        assert_accepted(
            relay
                .handle_event_with_auth(promote.clone(), &admin_auth)
                .expect("promote"),
            &promote,
        );
        let normal = tangle_v2_group_event(FixtureKey::Member, "EquivFarm", 4, 1, "harvest")
            .expect("normal");
        assert_accepted(
            relay
                .handle_event_with_auth(normal.clone(), &member_auth)
                .expect("normal"),
            &normal,
        );
        let delete_event = tangle_v2_delete_event_event(FixtureKey::Admin, "EquivFarm", &normal, 5)
            .expect("delete event");
        assert_accepted(
            relay
                .handle_event_with_auth(delete_event.clone(), &admin_auth)
                .expect("delete event"),
            &delete_event,
        );
        let demote = tangle_v2_put_user_event_with_roles(
            FixtureKey::Admin,
            "EquivFarm",
            FixtureKey::Member,
            6,
            &[],
        );
        assert_accepted(
            relay
                .handle_event_with_auth(demote.clone(), &admin_auth)
                .expect("demote"),
            &demote,
        );
        let remove =
            tangle_v2_remove_user_event(FixtureKey::Admin, "EquivFarm", FixtureKey::Member, 7)
                .expect("remove");
        assert_accepted(
            relay
                .handle_event_with_auth(remove.clone(), &admin_auth)
                .expect("remove"),
            &remove,
        );
        let delete_group =
            tangle_v2_delete_group_event(FixtureKey::Owner, "EquivFarm", 8).expect("delete group");
        assert_accepted(
            relay
                .handle_event_with_auth(delete_group.clone(), &owner_auth)
                .expect("delete group"),
            &delete_group,
        );
        live_projection = relay.group_projection().expect("projection").clone();
        metadata_before = stored_event_ids_for_kind(&config, KIND_GROUP_METADATA);
        admins_before = stored_event_ids_for_kind(&config, KIND_GROUP_ADMINS);
        members_before = stored_event_ids_for_kind(&config, KIND_GROUP_MEMBERS);
        relay.shutdown().expect("shutdown");
    }

    delete_group_extra_records(&config);

    let relay = BaseRelay::open_with_groups(
        &config,
        relay_limits(16),
        &group_config(),
        PocketQueryConfig::default(),
    )
    .expect("reopen");
    let recovered_projection = relay.group_projection().expect("projection");
    assert_projection_without_checkpoint_eq(&live_projection, &recovered_projection);
    assert_eq!(
        stored_event_ids_for_kind(&config, KIND_GROUP_METADATA),
        metadata_before
    );
    assert_eq!(
        stored_event_ids_for_kind(&config, KIND_GROUP_ADMINS),
        admins_before
    );
    assert_eq!(
        stored_event_ids_for_kind(&config, KIND_GROUP_MEMBERS),
        members_before
    );
}

#[test]
fn pending_and_retryable_group_outbox_records_materialize_on_restart() {
    let config = test_store_config("outbox-retryable-restart");
    let owner_auth = authenticated(FixtureKey::Owner);
    {
        let mut relay = BaseRelay::open_with_groups(
            &config,
            relay_limits(8),
            &group_config(),
            PocketQueryConfig::default(),
        )
        .expect("relay");
        accept_group_create(&mut relay, "OutboxFarm", &[], 1, &owner_auth);
        relay.shutdown().expect("shutdown");
    }
    regress_outbox_records_to_retryable(&config);
    assert_eq!(outbox_status_counts(&config).pending, 1);
    assert_eq!(outbox_status_counts(&config).retryable, 1);

    let relay = BaseRelay::open_with_groups(
        &config,
        relay_limits(8),
        &group_config(),
        PocketQueryConfig::default(),
    )
    .expect("reopen");
    assert_eq!(
        relay
            .readiness_state()
            .response()
            .checks
            .group_outbox_replay,
        "ready"
    );
    assert_eq!(count_kind(&relay, KIND_GROUP_METADATA), 1);
    assert_eq!(count_kind(&relay, KIND_GROUP_ADMINS), 1);
    let counts = outbox_status_counts(&config);
    assert_eq!(counts.pending, 0);
    assert_eq!(counts.retryable, 0);
    assert!(counts.stored >= 2);
}

#[test]
fn max_outbox_replay_batch_one_drains_all_pending_generated_records() {
    let config = test_store_config("outbox-batch-one");
    let owner_auth = authenticated(FixtureKey::Owner);
    let mut relay = BaseRelay::open_with_groups(
        &config,
        relay_limits(8),
        &group_config_with_outbox_batch(1),
        PocketQueryConfig::default(),
    )
    .expect("relay");

    accept_group_create(&mut relay, "BatchFarm", &[], 1, &owner_auth);

    assert_eq!(count_kind(&relay, KIND_GROUP_METADATA), 1);
    assert_eq!(count_kind(&relay, KIND_GROUP_ADMINS), 1);
    let counts = outbox_status_counts(&config);
    assert_eq!(counts.pending, 0);
    assert_eq!(counts.retryable, 0);
    assert_eq!(counts.stored, 2);
}

#[test]
fn already_stored_generated_events_mark_outbox_stored_without_duplication_on_restart() {
    let config = test_store_config("outbox-generated-already-stored");
    let owner_auth = authenticated(FixtureKey::Owner);
    {
        let mut relay = BaseRelay::open_with_groups(
            &config,
            relay_limits(8),
            &group_config(),
            PocketQueryConfig::default(),
        )
        .expect("relay");
        accept_group_create(&mut relay, "StoredGeneratedFarm", &[], 1, &owner_auth);
        relay.shutdown().expect("shutdown");
    }
    let metadata_before = stored_event_ids_for_kind(&config, KIND_GROUP_METADATA);
    let admins_before = stored_event_ids_for_kind(&config, KIND_GROUP_ADMINS);
    assert_eq!(metadata_before.len(), 1);
    assert_eq!(admins_before.len(), 1);

    regress_outbox_records_to_pending(&config);
    assert_eq!(outbox_status_counts(&config).pending, 2);

    let relay = BaseRelay::open_with_groups(
        &config,
        relay_limits(8),
        &group_config(),
        PocketQueryConfig::default(),
    )
    .expect("reopen");
    assert_eq!(count_kind(&relay, KIND_GROUP_METADATA), 1);
    assert_eq!(count_kind(&relay, KIND_GROUP_ADMINS), 1);
    assert_eq!(
        stored_event_ids_for_kind(&config, KIND_GROUP_METADATA),
        metadata_before
    );
    assert_eq!(
        stored_event_ids_for_kind(&config, KIND_GROUP_ADMINS),
        admins_before
    );
    let counts = outbox_status_counts(&config);
    assert_eq!(counts.pending, 0);
    assert_eq!(counts.stored, 2);
}

#[test]
fn crash_point_recovery_states_match_live_projection_and_generated_events() {
    let live_config = test_store_config("crash-equivalence-live");
    let source_only_config = test_store_config("crash-equivalence-source-only");
    let pending_outbox_config = test_store_config("crash-equivalence-pending-outbox");
    let events = recovery_equivalence_events();
    let expected = {
        let mut relay = BaseRelay::open_with_groups(
            &live_config,
            relay_limits(8),
            &group_config(),
            PocketQueryConfig::default(),
        )
        .expect("live");
        let owner_auth = authenticated(FixtureKey::Owner);
        let admin_auth = authenticated(FixtureKey::Admin);
        assert_accepted(
            relay
                .handle_event_with_auth(events[0].clone(), &owner_auth)
                .expect("create"),
            &events[0],
        );
        for event in events.iter().skip(1) {
            assert_accepted(
                relay
                    .handle_event_with_auth(event.clone(), &admin_auth)
                    .expect("event"),
                event,
            );
        }
        recovery_summary(&mut relay, "CrashFarm")
    };

    store_source_events(&source_only_config, &events);
    let mut source_only = BaseRelay::open_with_groups(
        &source_only_config,
        relay_limits(8),
        &group_config(),
        PocketQueryConfig::default(),
    )
    .expect("source only");
    assert_eq!(recovery_summary(&mut source_only, "CrashFarm"), expected);
    assert_eq!(outbox_status_counts(&source_only_config).stored, 5);

    let offsets = store_source_events(&pending_outbox_config, &events);
    seed_pending_create_outbox_records(&pending_outbox_config, &events[0], offsets[0]);
    let mut pending_outbox = BaseRelay::open_with_groups(
        &pending_outbox_config,
        relay_limits(8),
        &group_config(),
        PocketQueryConfig::default(),
    )
    .expect("pending outbox");
    assert_eq!(recovery_summary(&mut pending_outbox, "CrashFarm"), expected);
    let counts = outbox_status_counts(&pending_outbox_config);
    assert_eq!(counts.pending, 0);
    assert_eq!(counts.retryable, 0);
    assert_eq!(counts.stored, 5);
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecoverySummary {
    group_name: Option<String>,
    member_status: Option<MemberStatus>,
    member_roles: Vec<String>,
    metadata_event_ids: Vec<String>,
    admin_event_ids: Vec<String>,
    member_event_ids: Vec<String>,
    latest_admin_pubkeys: Vec<String>,
}

fn recovery_equivalence_events() -> Vec<Event> {
    vec![
        tangle_v2_group_create_event(FixtureKey::Owner, "CrashFarm", 1, &[]).expect("create"),
        tangle_v2_put_user_event_with_roles(
            FixtureKey::Admin,
            "CrashFarm",
            FixtureKey::Member,
            2,
            &[PERMANENT_RELAY_OVERRIDE_ROLE],
        ),
        tangle_v2_group_metadata_event(FixtureKey::Admin, "CrashFarm", "Crash Market", 3, &[])
            .expect("metadata"),
    ]
}

fn recovery_summary(relay: &mut BaseRelay, group_id: &str) -> RecoverySummary {
    let group_id_model = group(group_id);
    let (group_name, member_status, member_roles) = {
        let projection = relay.group_projection().expect("projection");
        let group_state = projection.group(&group_id_model).expect("group");
        let member = projection.member(&group_id_model, &FixtureKey::Member.public_key());
        let mut roles = member
            .map(|member| {
                member
                    .roles()
                    .iter()
                    .map(|role| role.as_str().to_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        roles.sort();
        (
            group_state.metadata().name().map(str::to_owned),
            member.map(|member| member.status()),
            roles,
        )
    };
    RecoverySummary {
        group_name,
        member_status,
        member_roles,
        metadata_event_ids: event_ids_for_group_kind(relay, group_id, KIND_GROUP_METADATA),
        admin_event_ids: event_ids_for_group_kind(relay, group_id, KIND_GROUP_ADMINS),
        member_event_ids: event_ids_for_group_kind(relay, group_id, KIND_GROUP_MEMBERS),
        latest_admin_pubkeys: latest_admin_snapshot_pubkeys(relay, group_id),
    }
}

fn assert_projection_without_checkpoint_eq(left: &GroupProjection, right: &GroupProjection) {
    assert_eq!(left.groups(), right.groups());
    assert_eq!(left.members(), right.members());
    assert_eq!(left.roles(), right.roles());
    assert_eq!(left.tombstones(), right.tombstones());
    assert_eq!(left.event_deletions(), right.event_deletions());
}

fn event_ids_for_group_kind(relay: &mut BaseRelay, group_id: &str, kind: u32) -> Vec<String> {
    let mut ids = query_events(
        relay,
        &format!("summary-{group_id}-{kind}"),
        vec![filter_group_tag(kind, "d", group_id)],
    )
    .into_iter()
    .map(|event| event.id().as_str().to_owned())
    .collect::<Vec<_>>();
    ids.sort();
    ids
}

fn store_source_events(config: &PocketStoreConfig, events: &[Event]) -> Vec<StoreOffset> {
    let store = PocketStoreHandle::open(config).expect("store");
    let mut offsets = Vec::new();
    for event in events {
        let raw = serde_json::to_vec(&event_to_value(event)).expect("event JSON");
        let pocket = parse_pocket_event_json(&raw).expect("pocket event");
        offsets.push(StoreOffset::new(store.store_event(&pocket).expect("store")));
    }
    store.sync().expect("sync");
    offsets
}

fn seed_pending_create_outbox_records(
    config: &PocketStoreConfig,
    create: &Event,
    create_offset: StoreOffset,
) {
    let store = PocketStoreHandle::open(config).expect("store");
    let group_id = group("CrashFarm");
    let mut projection = GroupProjection::new();
    projection
        .apply_canonical_event(create, create_offset, GroupLimitsConfig::default())
        .expect("projection");
    let authority = GroupAuthority::new(
        [FixtureKey::Owner.public_key()],
        [FixtureKey::Admin.public_key()],
    );
    let group_state = projection.group(&group_id).expect("group");
    let records = [
        GroupOutboxRecord::pending(
            GroupOutboxKey::new(
                create.id().clone(),
                GroupOutboxEffect::MetadataSnapshot,
                group_id.clone(),
                None,
            ),
            GroupGeneratedEventBuilder::metadata_snapshot_payload(
                group_state,
                create.unsigned().created_at(),
            )
            .expect("metadata payload"),
        ),
        GroupOutboxRecord::pending(
            GroupOutboxKey::new(
                create.id().clone(),
                GroupOutboxEffect::AdminListSnapshot,
                group_id.clone(),
                None,
            ),
            GroupGeneratedEventBuilder::admin_list_snapshot_payload(
                &group_id,
                &projection,
                &authority,
                create.unsigned().created_at(),
            )
            .expect("admin payload"),
        ),
    ];
    for record in records {
        store
            .put_extra_record(
                TANGLE_GROUP_OUTBOX_TABLE,
                &record.key().storage_key(),
                &record.to_json_bytes().expect("record bytes"),
            )
            .expect("outbox");
    }
    store.sync().expect("sync");
}

fn tangle_v2_put_user_event_with_roles(
    actor: FixtureKey,
    group_id: &str,
    target: FixtureKey,
    created_at: u64,
    roles: &[&str],
) -> Event {
    let mut tags = vec![
        tangle_v2_group_tag(group_id).expect("group tag"),
        tangle_v2_pubkey_tag(target).expect("pubkey tag"),
    ];
    for role in roles {
        tags.push(tangle_v2_tag("role", &[*role]).expect("role tag"));
    }
    tangle_v2_event(actor, created_at, KIND_GROUP_PUT_USER.into(), tags, "").expect("put user")
}

fn latest_admin_snapshot_pubkeys(relay: &mut BaseRelay, group_id: &str) -> Vec<String> {
    let mut events = query_events(
        relay,
        "admin-snapshots",
        vec![filter_group_tag(KIND_GROUP_ADMINS, "d", group_id)],
    );
    events.sort_by_key(|event| (event.unsigned().created_at(), event.id().clone()));
    let latest = events.last().expect("admin snapshot");
    let mut pubkeys = latest
        .unsigned()
        .tags()
        .iter()
        .filter_map(|tag| match tag.values() {
            [name, pubkey, ..] if name == "p" => Some(pubkey.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    pubkeys.sort();
    pubkeys
}

fn query_events(relay: &mut BaseRelay, subscription_id: &str, filters: Vec<Filter>) -> Vec<Event> {
    let subscription_id = subscription(subscription_id);
    let messages = relay
        .handle_req(subscription_id.clone(), filters)
        .expect("query");
    let mut events = Vec::new();
    for message in messages {
        match message {
            RelayMessage::Event {
                subscription_id: actual,
                event,
            } => {
                assert_eq!(actual, subscription_id);
                events.push(event);
            }
            RelayMessage::Eose(actual) => assert_eq!(actual, subscription_id),
            value => panic!("expected event or EOSE, got {value:?}"),
        }
    }
    events
}

fn sorted_strings(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort();
    values
}

fn final_group_name_for_order(name: &str, edits: [&Event; 2]) -> String {
    let config = test_store_config(name);
    let mut relay = BaseRelay::open_with_groups(
        &config,
        relay_limits(8),
        &group_config(),
        PocketQueryConfig::default(),
    )
    .expect("relay");
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
    PocketStoreConfig::new(root.join("pocket"), PocketSyncPolicy::FlushOnShutdown).expect("config")
}

fn relay_limits(max_pending_events: usize) -> BaseRelayLimits {
    BaseRelayLimits::new(BaseRelayLimitSettings {
        max_pending_events,
        max_subscription_id_length: 64,
        max_subscriptions: 64,
        max_filters_per_request: 10,
        max_tag_values_per_filter: 100,
        max_query_complexity: 610,
        max_event_tags: 200,
        max_content_length: 65_536,
        max_limit: 500,
        default_limit: 100,
    })
    .expect("limits")
}

fn delete_group_extra_records(config: &PocketStoreConfig) {
    let store = PocketStoreHandle::open(config).expect("store");
    for table in [
        TANGLE_GROUP_PROJECTION_TABLE,
        TANGLE_GROUP_OUTBOX_TABLE,
        TANGLE_GROUP_CHECKPOINT_TABLE,
    ] {
        for (key, _) in store.scan_extra_records(table).expect("scan") {
            store.delete_extra_record(table, &key).expect("delete");
        }
    }
    store.sync().expect("sync");
}

fn group_extra_table_validation(
    config: &PocketStoreConfig,
) -> tangle_runtime::groups::GroupExtraTableValidation {
    let store = PocketStoreHandle::open(config).expect("store");
    validate_group_extra_tables(&store).expect("validation")
}

fn stored_event_offset(config: &PocketStoreConfig, event: &Event) -> u64 {
    let store = PocketStoreHandle::open(config).expect("store");
    store
        .scan_events()
        .expect("events")
        .into_iter()
        .find(|stored| stored.event().id().as_hex_string() == event.id().as_str())
        .expect("stored event")
        .store_offset()
}

fn regress_member_projection_to_checkpoint(
    config: &PocketStoreConfig,
    checkpoint_offset: u64,
    group_id: &str,
) {
    let store = PocketStoreHandle::open(config).expect("store");
    let group_id = GroupId::new(group_id).expect("group");
    let checkpoint = ProjectionCheckpoint::current(
        Some(StoreOffset::new(checkpoint_offset)),
        UnixTimestamp::new(1_714_999_999),
    );
    store
        .put_extra_record(
            TANGLE_GROUP_CHECKPOINT_TABLE,
            &projection_checkpoint_key(),
            &checkpoint.to_json_bytes().expect("checkpoint"),
        )
        .expect("checkpoint");
    store
        .delete_extra_record(
            TANGLE_GROUP_PROJECTION_TABLE,
            &member_current_key(&group_id, &FixtureKey::Member.public_key()),
        )
        .expect("delete member");
    store.sync().expect("sync");
}

fn regress_outbox_records_to_retryable(config: &PocketStoreConfig) {
    let store = PocketStoreHandle::open(config).expect("store");
    let records = store
        .scan_extra_records(TANGLE_GROUP_OUTBOX_TABLE)
        .expect("outbox records");
    assert!(records.len() >= 2);
    let mut first = GroupOutboxRecord::from_json_bytes(&records[0].1).expect("first outbox record");
    let second = GroupOutboxRecord::from_json_bytes(&records[1].1).expect("second outbox record");
    first.mark_failed(true, "retry on restart");
    let pending = GroupOutboxRecord::pending(second.key().clone(), second.payload().clone());
    store
        .put_extra_record(
            TANGLE_GROUP_OUTBOX_TABLE,
            &first.key().storage_key(),
            &first.to_json_bytes().expect("failed bytes"),
        )
        .expect("put failed");
    store
        .put_extra_record(
            TANGLE_GROUP_OUTBOX_TABLE,
            &pending.key().storage_key(),
            &pending.to_json_bytes().expect("pending bytes"),
        )
        .expect("put pending");
    store.sync().expect("sync");
}

fn regress_outbox_records_to_pending(config: &PocketStoreConfig) {
    let store = PocketStoreHandle::open(config).expect("store");
    for (_, value) in store
        .scan_extra_records(TANGLE_GROUP_OUTBOX_TABLE)
        .expect("outbox records")
    {
        let record = GroupOutboxRecord::from_json_bytes(&value).expect("outbox record");
        let pending = GroupOutboxRecord::pending(record.key().clone(), record.payload().clone());
        store
            .put_extra_record(
                TANGLE_GROUP_OUTBOX_TABLE,
                &pending.key().storage_key(),
                &pending.to_json_bytes().expect("pending bytes"),
            )
            .expect("put pending");
    }
    store.sync().expect("sync");
}

fn stored_event_ids_for_kind(config: &PocketStoreConfig, kind: u32) -> Vec<String> {
    let store = PocketStoreHandle::open(config).expect("store");
    let mut ids = store
        .scan_events()
        .expect("events")
        .into_iter()
        .filter(|stored| u32::from(stored.event().kind().as_u16()) == kind)
        .map(|stored| stored.event().id().as_hex_string())
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct OutboxStatusCounts {
    pending: usize,
    retryable: usize,
    stored: usize,
}

fn outbox_status_counts(config: &PocketStoreConfig) -> OutboxStatusCounts {
    let store = PocketStoreHandle::open(config).expect("store");
    let mut counts = OutboxStatusCounts::default();
    for (_, value) in store
        .scan_extra_records(TANGLE_GROUP_OUTBOX_TABLE)
        .expect("outbox records")
    {
        match GroupOutboxRecord::from_json_bytes(&value)
            .expect("outbox record")
            .status()
        {
            GroupOutboxStatus::Pending => counts.pending += 1,
            GroupOutboxStatus::Failed { retryable: true } => counts.retryable += 1,
            GroupOutboxStatus::Stored { .. } => counts.stored += 1,
            GroupOutboxStatus::Skipped { .. } | GroupOutboxStatus::Failed { retryable: false } => {}
        }
    }
    counts
}

fn temp_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("tangle-rcld12-{name}-{}", std::process::id()))
}

fn group_config() -> GroupRuntimeConfig {
    tangle_v2_group_config(FixtureKey::Owner, &[FixtureKey::Admin]).expect("groups")
}

fn runtime_config(groups_enabled: bool) -> BaseRelayRuntimeConfig {
    let groups = if groups_enabled {
        serde_json::json!({
            "enabled": true,
            "canonical_relay_url": TANGLE_V2_RELAY_URL,
            "relay_secret": TANGLE_V2_RELAY_SECRET_HEX,
            "owner_pubkeys": [FixtureKey::Owner.public_key().as_str()],
            "admin_pubkeys": [FixtureKey::Admin.public_key().as_str()]
        })
    } else {
        serde_json::json!({"enabled": false})
    };
    parse_base_relay_runtime_config_json(
        &serde_json::json!({
            "server": {
                "listen_addr": "127.0.0.1:0",
                "relay_url": TANGLE_V2_RELAY_URL
            },
            "pocket": {
                "data_directory": "runtime/pocket",
                "sync_policy": "flush_on_shutdown",
                "query": {
                  "allow_scraping": false,
                  "allow_scrape_if_limited_to": 100,
                  "allow_scrape_if_max_seconds": 3600
                }
            },
            "groups": groups,
            "auth": {
                "challenge_ttl_seconds": 300,
                "created_at_skew_seconds": 600
            },
            "limits": {
                "max_message_length": 1048576,
                "max_subid_length": 64,
                "max_subscriptions_per_connection": 64,
                "max_filters_per_request": 10,
                "max_tag_values_per_filter": 100,
                "max_query_complexity": 2048,
                "max_limit": 500,
                "default_limit": 100,
                "max_event_tags": 200,
                "max_content_length": 65536,
                "broadcast_channel_capacity": 4096,
                "per_connection_outbound_queue": 256
            },
            "rate_limits": {
                "auth": {
                    "per_ip": {"window_seconds": 60, "max_hits": 120},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 30},
                    "failures": {"window_seconds": 300, "max_hits": 5},
                    "failures_per_ip": {"window_seconds": 300, "max_hits": 20}
                },
                "event": {
                    "per_ip": {"window_seconds": 60, "max_hits": 600},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 120},
                    "per_kind": {"window_seconds": 60, "max_hits": 1000}
                },
                "group": {
                    "write_per_ip": {"window_seconds": 60, "max_hits": 300},
                    "write_per_pubkey": {"window_seconds": 60, "max_hits": 60},
                    "write_per_group": {"window_seconds": 60, "max_hits": 90},
                    "write_per_kind": {"window_seconds": 60, "max_hits": 300},
                    "join_flow": {"window_seconds": 300, "max_hits": 10},
                    "join_flow_per_ip": {"window_seconds": 300, "max_hits": 30}
                },
                "req": {
                    "per_ip": {"window_seconds": 60, "max_hits": 600},
                    "per_connection": {"window_seconds": 60, "max_hits": 120},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 240},
                    "per_group": {"window_seconds": 60, "max_hits": 240},
                    "per_kind": {"window_seconds": 60, "max_hits": 500},
                    "broad": {"window_seconds": 60, "max_hits": 30}
                },
                "count": {
                    "per_ip": {"window_seconds": 60, "max_hits": 300},
                    "per_connection": {"window_seconds": 60, "max_hits": 60},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 120},
                    "per_group": {"window_seconds": 60, "max_hits": 120},
                    "per_kind": {"window_seconds": 60, "max_hits": 240},
                    "broad": {"window_seconds": 60, "max_hits": 20}
                }
            }
        })
        .to_string(),
    )
    .expect("runtime config")
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

fn group_config_with_outbox_batch(batch: u32) -> GroupRuntimeConfig {
    parse_group_runtime_config_json(&format!(
        r#"{{
            "enabled": true,
            "canonical_relay_url": "{TANGLE_V2_RELAY_URL}",
            "relay_secret": "{TANGLE_V2_RELAY_SECRET_HEX}",
            "owner_pubkeys": ["{}"],
            "admin_pubkeys": ["{}"],
            "limits": {{"max_outbox_replay_batch": {batch}}}
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
