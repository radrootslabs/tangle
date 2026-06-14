use std::collections::{BTreeMap, BTreeSet};

use crate::errors::{GroupError, GroupErrorKind};

pub const MAX_ROLE_NAME_BYTES: usize = 64;
pub const PERMANENT_RELAY_OVERRIDE_ROLE: &str = "relay_owner";

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoleName(String);

impl RoleName {
    pub fn new(value: &str) -> Result<Self, GroupError> {
        if value.is_empty() {
            return Err(invalid_role("role name must not be empty"));
        }
        if value.len() > MAX_ROLE_NAME_BYTES {
            return Err(invalid_role(format!(
                "role name must be at most {MAX_ROLE_NAME_BYTES} bytes"
            )));
        }
        if value.trim() != value {
            return Err(invalid_role(
                "role name must not contain leading or trailing whitespace",
            ));
        }
        if value.chars().any(char::is_control) {
            return Err(invalid_role(
                "role name must not contain control characters",
            ));
        }
        if value.chars().any(char::is_whitespace) {
            return Err(invalid_role("role name must not contain whitespace"));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn permanent_relay_override() -> Self {
        Self(PERMANENT_RELAY_OVERRIDE_ROLE.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_permanent_relay_override(&self) -> bool {
        self.as_str() == PERMANENT_RELAY_OVERRIDE_ROLE
    }
}

impl core::fmt::Debug for RoleName {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_tuple("RoleName").field(&self.0).finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    ManageMembers,
    ManageRoles,
    ManageMetadata,
    DeleteEvents,
    DeleteGroup,
    CreateInvites,
    ManageInvites,
    RelayOverride,
}

impl Capability {
    pub fn all() -> [Self; 8] {
        [
            Self::ManageMembers,
            Self::ManageRoles,
            Self::ManageMetadata,
            Self::DeleteEvents,
            Self::DeleteGroup,
            Self::CreateInvites,
            Self::ManageInvites,
            Self::RelayOverride,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ManageMembers => "manage_members",
            Self::ManageRoles => "manage_roles",
            Self::ManageMetadata => "manage_metadata",
            Self::DeleteEvents => "delete_events",
            Self::DeleteGroup => "delete_group",
            Self::CreateInvites => "create_invites",
            Self::ManageInvites => "manage_invites",
            Self::RelayOverride => "relay_override",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CapabilitySet {
    capabilities: BTreeSet<Capability>,
}

impl CapabilitySet {
    pub fn new(capabilities: impl IntoIterator<Item = Capability>) -> Self {
        Self {
            capabilities: capabilities.into_iter().collect(),
        }
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn permanent_relay_override() -> Self {
        Self::new(Capability::all())
    }

    pub fn insert(&mut self, capability: Capability) {
        self.capabilities.insert(capability);
    }

    pub fn contains(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = Capability> + '_ {
        self.capabilities.iter().copied()
    }

    fn extend_from(&mut self, other: &CapabilitySet) {
        self.capabilities.extend(other.iter());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleDefinition {
    name: RoleName,
    capabilities: CapabilitySet,
    description: Option<String>,
}

impl RoleDefinition {
    pub fn new(name: RoleName, capabilities: CapabilitySet, description: Option<String>) -> Self {
        Self {
            name,
            capabilities,
            description,
        }
    }

    pub fn name(&self) -> &RoleName {
        &self.name
    }

    pub fn capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

pub fn resolve_capabilities<'a>(
    definitions: impl IntoIterator<Item = &'a RoleDefinition>,
    roles: impl IntoIterator<Item = &'a RoleName>,
) -> Result<CapabilitySet, GroupError> {
    let definitions = definitions
        .into_iter()
        .map(|definition| (definition.name().clone(), definition))
        .collect::<BTreeMap<_, _>>();
    let mut resolved = CapabilitySet::empty();
    for role in roles {
        if role.is_permanent_relay_override() {
            resolved.extend_from(&CapabilitySet::permanent_relay_override());
            continue;
        }
        let Some(definition) = definitions.get(role) else {
            return Err(GroupError::restricted(
                GroupErrorKind::MissingCapability,
                format!("unknown group role {}", role.as_str()),
            ));
        };
        resolved.extend_from(definition.capabilities());
    }
    Ok(resolved)
}

fn invalid_role(message: impl Into<String>) -> GroupError {
    GroupError::invalid(GroupErrorKind::InvalidRole, message)
}

#[cfg(test)]
mod tests {
    use super::{Capability, CapabilitySet, RoleDefinition, RoleName, resolve_capabilities};
    use crate::GroupErrorKind;

    #[test]
    fn role_name_validation_is_strict() {
        assert_eq!(
            RoleName::new("").expect_err("empty").message(),
            "role name must not be empty"
        );
        assert_eq!(
            RoleName::new("a role").expect_err("space").message(),
            "role name must not contain whitespace"
        );
        assert_eq!(
            RoleName::new(" role").expect_err("trim").message(),
            "role name must not contain leading or trailing whitespace"
        );
        assert_eq!(
            RoleName::new("role\nname").expect_err("control").message(),
            "role name must not contain control characters"
        );
    }

    #[test]
    fn resolves_role_capabilities_and_rejects_unknown_roles() {
        let moderator = RoleName::new("moderator").expect("role");
        let definition = RoleDefinition::new(
            moderator.clone(),
            CapabilitySet::new([Capability::ManageMembers, Capability::DeleteEvents]),
            Some("Moderates group members".to_owned()),
        );
        let resolved = resolve_capabilities([&definition], [&moderator]).expect("capabilities");

        assert!(resolved.contains(Capability::ManageMembers));
        assert!(resolved.contains(Capability::DeleteEvents));
        assert!(!resolved.contains(Capability::DeleteGroup));
        assert_eq!(definition.description(), Some("Moderates group members"));

        let unknown = RoleName::new("unknown").expect("unknown");
        let error = resolve_capabilities([&definition], [&unknown]).expect_err("unknown");
        assert_eq!(error.kind(), GroupErrorKind::MissingCapability);
        assert_eq!(error.message(), "unknown group role unknown");
    }

    #[test]
    fn permanent_relay_override_grants_every_capability() {
        let role = RoleName::permanent_relay_override();
        let resolved = resolve_capabilities([], [&role]).expect("capabilities");

        assert!(role.is_permanent_relay_override());
        for capability in Capability::all() {
            assert!(resolved.contains(capability), "{}", capability.as_str());
        }
    }
}
