use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupReplyPrefix {
    Duplicate,
    Blocked,
    RateLimited,
    Invalid,
    Restricted,
    AuthRequired,
    Error,
}

impl GroupReplyPrefix {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Duplicate => "duplicate",
            Self::Blocked => "blocked",
            Self::RateLimited => "rate-limited",
            Self::Invalid => "invalid",
            Self::Restricted => "restricted",
            Self::AuthRequired => "auth-required",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for GroupReplyPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupErrorKind {
    InvalidGroupId,
    MalformedGroupTag,
    MissingGroupTag,
    ConflictingGroupTag,
    TooManyGroupTags,
    UnsupportedGroupKind,
    DirectRelayGeneratedSubmission,
    MissingTargetTag,
    MalformedTargetTag,
    MetadataTooLarge,
    TooManySupportedKinds,
    InvalidRole,
    MissingCapability,
    AuthenticationRequired,
    GroupUnavailable,
    GroupDeleted,
    GroupAlreadyExists,
    DuplicateMember,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupError {
    kind: GroupErrorKind,
    prefix: GroupReplyPrefix,
    message: String,
}

impl GroupError {
    pub fn new(kind: GroupErrorKind, prefix: GroupReplyPrefix, message: impl Into<String>) -> Self {
        Self {
            kind,
            prefix,
            message: message.into(),
        }
    }

    pub fn invalid(kind: GroupErrorKind, message: impl Into<String>) -> Self {
        Self::new(kind, GroupReplyPrefix::Invalid, message)
    }

    pub fn duplicate(kind: GroupErrorKind, message: impl Into<String>) -> Self {
        Self::new(kind, GroupReplyPrefix::Duplicate, message)
    }

    pub fn blocked(kind: GroupErrorKind, message: impl Into<String>) -> Self {
        Self::new(kind, GroupReplyPrefix::Blocked, message)
    }

    pub fn restricted(kind: GroupErrorKind, message: impl Into<String>) -> Self {
        Self::new(kind, GroupReplyPrefix::Restricted, message)
    }

    pub fn auth_required(message: impl Into<String>) -> Self {
        Self::new(
            GroupErrorKind::AuthenticationRequired,
            GroupReplyPrefix::AuthRequired,
            message,
        )
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(GroupErrorKind::Internal, GroupReplyPrefix::Error, message)
    }

    pub fn kind(&self) -> GroupErrorKind {
        self.kind
    }

    pub fn reply_prefix(&self) -> GroupReplyPrefix {
        self.prefix
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn prefixed_message(&self) -> String {
        format!("{}: {}", self.prefix.as_str(), self.message)
    }
}

impl fmt::Display for GroupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.prefixed_message())
    }
}

impl std::error::Error for GroupError {}

#[cfg(test)]
mod tests {
    use super::{GroupError, GroupErrorKind, GroupReplyPrefix};

    #[test]
    fn group_errors_map_to_nostr_reply_prefixes() {
        let cases = [
            (GroupReplyPrefix::Duplicate, "duplicate"),
            (GroupReplyPrefix::Blocked, "blocked"),
            (GroupReplyPrefix::RateLimited, "rate-limited"),
            (GroupReplyPrefix::Invalid, "invalid"),
            (GroupReplyPrefix::Restricted, "restricted"),
            (GroupReplyPrefix::AuthRequired, "auth-required"),
            (GroupReplyPrefix::Error, "error"),
        ];

        for (prefix, value) in cases {
            assert_eq!(prefix.as_str(), value);
            assert_eq!(prefix.to_string(), value);
        }

        let error = GroupError::restricted(
            GroupErrorKind::MissingCapability,
            "missing group capability manage_members",
        );

        assert_eq!(error.reply_prefix(), GroupReplyPrefix::Restricted);
        assert_eq!(
            error.prefixed_message(),
            "restricted: missing group capability manage_members"
        );

        let duplicate = GroupError::duplicate(
            GroupErrorKind::DuplicateMember,
            "group member already exists",
        );

        assert_eq!(duplicate.reply_prefix(), GroupReplyPrefix::Duplicate);
        assert_eq!(
            duplicate.prefixed_message(),
            "duplicate: group member already exists"
        );
    }
}
