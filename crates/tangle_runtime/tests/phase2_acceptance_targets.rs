#![forbid(unsafe_code)]

#[test]
#[ignore = "phase2 target: long-lived server runtime"]
fn tangle_run_serves_until_shutdown() {
    pending("tangle run --config PATH must bind a server and run until shutdown");
}

#[test]
#[ignore = "phase2 target: websocket protocol runtime"]
fn websocket_clients_use_nip01_nip42_and_nip45_flows() {
    pending("real websocket sessions must handle EVENT REQ COUNT CLOSE and AUTH");
}

#[test]
#[ignore = "phase2 target: nip11 truthfulness"]
fn nip11_includes_cors_headers_and_truthful_supported_nips() {
    pending("NIP-11 must include CORS headers and advertise only enforced NIPs");
}

#[test]
#[ignore = "phase2 target: auth skew"]
fn auth_rejects_events_outside_created_at_skew() {
    pending("AUTH must validate created_at against configured skew");
}

#[test]
#[ignore = "phase2 target: nip70 enforcement"]
fn protected_events_require_author_auth_before_nip70_is_advertised() {
    pending("events with a dash tag require AUTH as event author before NIP-70 advertisement");
}

#[test]
#[ignore = "phase2 target: private hidden semantics"]
fn private_but_not_hidden_group_metadata_remains_visible() {
    pending("private-but-not-hidden group metadata and admins must remain visible to non-members");
}

#[test]
#[ignore = "phase2 target: public join policy"]
fn public_join_defaults_false() {
    pending(
        "group join requests must be denied by default unless public join or invite flow allows them",
    );
}

#[test]
#[ignore = "phase2 target: duplicate membership prefixes"]
fn duplicate_join_and_leave_use_duplicate_prefix() {
    pending("duplicate join and leave responses must use the duplicate prefix");
}

#[test]
#[ignore = "phase2 target: central read gate"]
fn req_count_and_live_fanout_share_one_group_read_gate() {
    pending("REQ COUNT and live fanout must use one central group read gate");
}

#[test]
#[ignore = "phase2 target: hot path representation"]
fn runtime_hot_path_does_not_stringify_and_reparse_events() {
    pending("runtime hot paths must use Pocket event and filter types or EventView");
}

#[test]
#[ignore = "phase2 target: canonical recovery"]
fn projection_and_outbox_recover_from_canonical_pocket_events() {
    pending("projection and outbox recovery must rebuild from canonical Pocket events");
}

#[test]
#[ignore = "phase2 target: generated broadcast"]
fn relay_generated_events_are_stored_projected_recovered_and_broadcast() {
    pending(
        "relay-generated group events must be stored projected recovered and broadcast by offset",
    );
}

fn pending(target: &str) {
    panic!("{target}");
}
