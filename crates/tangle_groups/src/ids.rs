use core::fmt;

use crate::errors::{GroupError, GroupErrorKind};

pub const MIN_GROUP_ID_BYTES: usize = 1;
pub const MAX_GROUP_ID_BYTES: usize = 128;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId(String);

impl GroupId {
    pub fn new(value: &str) -> Result<Self, GroupError> {
        Self::new_with_max_bytes(value, MAX_GROUP_ID_BYTES)
    }

    pub fn new_with_max_bytes(value: &str, max_bytes: usize) -> Result<Self, GroupError> {
        validate_group_id(value, max_bytes)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GroupId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("GroupId").field(&self.0).finish()
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

pub fn validate_group_id(value: &str, max_bytes: usize) -> Result<(), GroupError> {
    let byte_len = value.len();
    if byte_len < MIN_GROUP_ID_BYTES {
        return Err(invalid_group_id("group id must not be empty"));
    }
    if byte_len > max_bytes {
        return Err(invalid_group_id(format!(
            "group id must be at most {max_bytes} bytes"
        )));
    }
    if value.trim() != value {
        return Err(invalid_group_id(
            "group id must not contain leading or trailing whitespace",
        ));
    }
    for character in value.chars() {
        if character == '\0' {
            return Err(invalid_group_id("group id must not contain NUL"));
        }
        if character.is_control() {
            return Err(invalid_group_id(
                "group id must not contain control characters",
            ));
        }
        if matches!(character, '/' | '\\' | '?' | '#' | ':' | '&' | '=') {
            return Err(invalid_group_id(
                "group id must not contain slashes or URL separators",
            ));
        }
    }
    Ok(())
}

fn invalid_group_id(message: impl Into<String>) -> GroupError {
    GroupError::invalid(GroupErrorKind::InvalidGroupId, message)
}

#[cfg(test)]
mod tests {
    use super::GroupId;

    #[test]
    fn group_id_validation_rejects_forbidden_forms() {
        assert_eq!(
            GroupId::new("").expect_err("empty").message(),
            "group id must not be empty"
        );
        assert_eq!(
            GroupId::new(&"a".repeat(129))
                .expect_err("too long")
                .message(),
            "group id must be at most 128 bytes"
        );
        assert_eq!(
            GroupId::new(" group").expect_err("trim").message(),
            "group id must not contain leading or trailing whitespace"
        );
        assert_eq!(
            GroupId::new("group\u{0}id").expect_err("nul").message(),
            "group id must not contain NUL"
        );
        assert_eq!(
            GroupId::new("group\nid").expect_err("control").message(),
            "group id must not contain control characters"
        );
        assert_eq!(
            GroupId::new("group/id").expect_err("slash").message(),
            "group id must not contain slashes or URL separators"
        );
        assert_eq!(
            GroupId::new("group?id").expect_err("url").message(),
            "group id must not contain slashes or URL separators"
        );
    }

    #[test]
    fn group_id_is_case_sensitive() {
        let lower = GroupId::new("farm").expect("lower");
        let upper = GroupId::new("Farm").expect("upper");

        assert_ne!(lower, upper);
        assert_eq!(lower.as_str(), "farm");
        assert_eq!(upper.as_str(), "Farm");
    }
}
