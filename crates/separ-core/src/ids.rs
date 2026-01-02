//! Strongly-typed identifiers for domain entities

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Macro to generate strongly-typed ID wrappers
macro_rules! define_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            pub fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            pub fn into_uuid(self) -> Uuid {
                self.0
            }

            /// Returns the SpiceDB-compatible object ID with prefix
            pub fn to_spicedb_id(&self) -> String {
                format!("{}_{}", $prefix, self.0)
            }

            /// Parse from a SpiceDB object ID
            pub fn from_spicedb_id(s: &str) -> Option<Self> {
                let prefix = concat!($prefix, "_");
                if let Some(stripped) = s.strip_prefix(prefix) {
                    Uuid::parse_str(stripped).ok().map(Self)
                } else {
                    Uuid::parse_str(s).ok().map(Self)
                }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                // Try parsing with prefix first
                if let Some(id) = Self::from_spicedb_id(s) {
                    return Ok(id);
                }
                // Fall back to plain UUID
                Uuid::parse_str(s).map(Self)
            }
        }
    };
}

// Platform-level IDs
define_id!(PlatformId, "plat");
define_id!(TenantId, "tn");
define_id!(WorkspaceId, "ws");
define_id!(ApplicationId, "app");
define_id!(ResourceId, "res");

// User and identity IDs
define_id!(UserId, "usr");
define_id!(ServiceAccountId, "sa");
define_id!(GroupId, "grp");
define_id!(RoleId, "role");

// OAuth and sync IDs
define_id!(OAuthProviderId, "oauth");
define_id!(SyncConfigId, "sync");
define_id!(WebhookId, "wh");
define_id!(ApiKeyId, "key");

// Audit and events
define_id!(AuditEventId, "audit");
define_id!(SessionId, "sess");

// Identity provider IDs
define_id!(IdentityProviderId, "idp");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_generation() {
        let id1 = TenantId::new();
        let id2 = TenantId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_spicedb_id_roundtrip() {
        let id = TenantId::new();
        let spicedb_id = id.to_spicedb_id();
        assert!(spicedb_id.starts_with("tn_"));

        let parsed = TenantId::from_spicedb_id(&spicedb_id).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_id_parsing() {
        let id = UserId::new();
        let s = id.to_string();
        let parsed: UserId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }
}

