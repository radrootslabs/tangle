use tangle_protocol::Kind;

pub const KIND_GROUP_PUT_USER: u32 = 9_000;
pub const KIND_GROUP_REMOVE_USER: u32 = 9_001;
pub const KIND_GROUP_EDIT_METADATA: u32 = 9_002;
pub const KIND_GROUP_DELETE_EVENT: u32 = 9_005;
pub const KIND_GROUP_CREATE_GROUP: u32 = 9_007;
pub const KIND_GROUP_DELETE_GROUP: u32 = 9_008;
pub const KIND_GROUP_CREATE_INVITE: u32 = 9_009;
pub const KIND_GROUP_JOIN_REQUEST: u32 = 9_021;
pub const KIND_GROUP_LEAVE_REQUEST: u32 = 9_022;
pub const KIND_GROUP_METADATA: u32 = 39_000;
pub const KIND_GROUP_ADMINS: u32 = 39_001;
pub const KIND_GROUP_MEMBERS: u32 = 39_002;
pub const KIND_GROUP_ROLES: u32 = 39_003;
pub const KIND_GROUP_STATE_39004: u32 = 39_004;

pub const NIP29_MODERATION_KIND_VALUES: [u32; 7] = [
    KIND_GROUP_PUT_USER,
    KIND_GROUP_REMOVE_USER,
    KIND_GROUP_EDIT_METADATA,
    KIND_GROUP_DELETE_EVENT,
    KIND_GROUP_CREATE_GROUP,
    KIND_GROUP_DELETE_GROUP,
    KIND_GROUP_CREATE_INVITE,
];

pub const NIP29_USER_REQUEST_KIND_VALUES: [u32; 2] =
    [KIND_GROUP_JOIN_REQUEST, KIND_GROUP_LEAVE_REQUEST];

pub const NIP29_RELAY_GENERATED_KIND_VALUES: [u32; 5] = [
    KIND_GROUP_METADATA,
    KIND_GROUP_ADMINS,
    KIND_GROUP_MEMBERS,
    KIND_GROUP_ROLES,
    KIND_GROUP_STATE_39004,
];

pub const NIP29_GROUP_KIND_VALUES: [u32; 14] = [
    KIND_GROUP_PUT_USER,
    KIND_GROUP_REMOVE_USER,
    KIND_GROUP_EDIT_METADATA,
    KIND_GROUP_DELETE_EVENT,
    KIND_GROUP_CREATE_GROUP,
    KIND_GROUP_DELETE_GROUP,
    KIND_GROUP_CREATE_INVITE,
    KIND_GROUP_JOIN_REQUEST,
    KIND_GROUP_LEAVE_REQUEST,
    KIND_GROUP_METADATA,
    KIND_GROUP_ADMINS,
    KIND_GROUP_MEMBERS,
    KIND_GROUP_ROLES,
    KIND_GROUP_STATE_39004,
];

pub fn is_moderation_kind(kind: Kind) -> bool {
    NIP29_MODERATION_KIND_VALUES.contains(&kind.as_u32())
}

pub fn is_user_request_kind(kind: Kind) -> bool {
    NIP29_USER_REQUEST_KIND_VALUES.contains(&kind.as_u32())
}

pub fn is_relay_generated_kind(kind: Kind) -> bool {
    NIP29_RELAY_GENERATED_KIND_VALUES.contains(&kind.as_u32())
}

pub fn is_group_specific_kind(kind: Kind) -> bool {
    NIP29_GROUP_KIND_VALUES.contains(&kind.as_u32())
}

#[cfg(test)]
mod tests {
    use super::{
        KIND_GROUP_ADMINS, KIND_GROUP_CREATE_GROUP, KIND_GROUP_CREATE_INVITE,
        KIND_GROUP_DELETE_EVENT, KIND_GROUP_DELETE_GROUP, KIND_GROUP_EDIT_METADATA,
        KIND_GROUP_JOIN_REQUEST, KIND_GROUP_LEAVE_REQUEST, KIND_GROUP_MEMBERS, KIND_GROUP_METADATA,
        KIND_GROUP_PUT_USER, KIND_GROUP_REMOVE_USER, KIND_GROUP_ROLES, KIND_GROUP_STATE_39004,
        NIP29_GROUP_KIND_VALUES, is_group_specific_kind, is_moderation_kind,
        is_relay_generated_kind, is_user_request_kind,
    };
    use tangle_protocol::Kind;

    #[test]
    fn nip29_kind_constants_cover_moderation_and_relay_generated_ranges() {
        assert_eq!(
            NIP29_GROUP_KIND_VALUES,
            [
                9_000, 9_001, 9_002, 9_005, 9_007, 9_008, 9_009, 9_021, 9_022, 39_000, 39_001,
                39_002, 39_003, 39_004
            ]
        );
        for value in [
            KIND_GROUP_PUT_USER,
            KIND_GROUP_REMOVE_USER,
            KIND_GROUP_EDIT_METADATA,
            KIND_GROUP_DELETE_EVENT,
            KIND_GROUP_CREATE_GROUP,
            KIND_GROUP_DELETE_GROUP,
            KIND_GROUP_CREATE_INVITE,
        ] {
            let kind = Kind::new(value.into()).expect("kind");
            assert!(is_moderation_kind(kind));
            assert!(is_group_specific_kind(kind));
            assert!(!is_relay_generated_kind(kind));
            assert!(!is_user_request_kind(kind));
        }
        for value in [KIND_GROUP_JOIN_REQUEST, KIND_GROUP_LEAVE_REQUEST] {
            let kind = Kind::new(value.into()).expect("kind");
            assert!(is_user_request_kind(kind));
            assert!(is_group_specific_kind(kind));
            assert!(!is_moderation_kind(kind));
            assert!(!is_relay_generated_kind(kind));
        }
        for value in [
            KIND_GROUP_METADATA,
            KIND_GROUP_ADMINS,
            KIND_GROUP_MEMBERS,
            KIND_GROUP_ROLES,
            KIND_GROUP_STATE_39004,
        ] {
            let kind = Kind::new(value.into()).expect("kind");
            assert!(is_relay_generated_kind(kind));
            assert!(is_group_specific_kind(kind));
            assert!(!is_moderation_kind(kind));
        }
        assert!(!is_group_specific_kind(Kind::new(1).expect("kind")));
    }
}
