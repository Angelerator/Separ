//! Unit tests for separ-core

use super::*;
use chrono::Utc;
use std::collections::HashMap;

// =============================================================================
// ID Type Tests
// =============================================================================

#[cfg(test)]
mod id_tests {
    use super::*;

    #[test]
    fn test_tenant_id_creation() {
        let id = TenantId::new();
        assert!(!id.to_string().is_empty());
    }

    #[test]
    fn test_user_id_creation() {
        let id = UserId::new();
        assert!(!id.to_string().is_empty());
    }

    #[test]
    fn test_workspace_id_creation() {
        let id = WorkspaceId::new();
        assert!(!id.to_string().is_empty());
    }

    #[test]
    fn test_application_id_creation() {
        let id = ApplicationId::new();
        assert!(!id.to_string().is_empty());
    }

    #[test]
    fn test_group_id_creation() {
        let id = GroupId::new();
        assert!(!id.to_string().is_empty());
    }

    #[test]
    fn test_identity_provider_id_creation() {
        let id = IdentityProviderId::new();
        assert!(!id.to_string().is_empty());
    }

    #[test]
    fn test_id_equality() {
        let id1 = TenantId::new();
        let id2 = TenantId::new();
        assert_ne!(id1, id2);
        assert_eq!(id1, id1.clone());
    }

    #[test]
    fn test_id_serialization() {
        let id = TenantId::new();
        let json = serde_json::to_string(&id).unwrap();
        let deserialized: TenantId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, deserialized);
    }
}

// =============================================================================
// Model Tests
// =============================================================================

#[cfg(test)]
mod model_tests {
    use super::*;

    #[test]
    fn test_tenant_status_serialization() {
        let status = TenantStatus::Active;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"active\"");

        let deserialized: TenantStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, TenantStatus::Active);
    }

    #[test]
    fn test_tenant_settings_default() {
        let settings = TenantSettings::default();
        assert!(!settings.allow_external_oauth);
        assert!(!settings.scim_enabled);
        assert!(settings.max_users.is_none());
    }

    #[test]
    fn test_user_status_variants() {
        let statuses = vec![
            UserStatus::Active,
            UserStatus::Inactive,
            UserStatus::Suspended,
            UserStatus::PendingVerification,
        ];
        
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: UserStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, status);
        }
    }

    #[test]
    fn test_subject_creation() {
        let subject = Subject {
            subject_type: SubjectType::User,
            id: "user123".to_string(),
            relation: None,
        };
        
        assert_eq!(subject.subject_type, SubjectType::User);
        assert_eq!(subject.id, "user123");
        assert!(subject.relation.is_none());
    }

    #[test]
    fn test_subject_with_relation() {
        let subject = Subject {
            subject_type: SubjectType::Group,
            id: "group456".to_string(),
            relation: Some("member".to_string()),
        };
        
        assert_eq!(subject.subject_type, SubjectType::Group);
        assert_eq!(subject.relation, Some("member".to_string()));
    }

    #[test]
    fn test_resource_creation() {
        let resource = Resource {
            resource_type: "document".to_string(),
            id: "doc123".to_string(),
        };
        
        assert_eq!(resource.resource_type, "document");
        assert_eq!(resource.id, "doc123");
    }

    #[test]
    fn test_relationship_creation() {
        let relationship = Relationship {
            resource: Resource {
                resource_type: "document".to_string(),
                id: "doc123".to_string(),
            },
            relation: "viewer".to_string(),
            subject: Subject {
                subject_type: SubjectType::User,
                id: "user456".to_string(),
                relation: None,
            },
            caveat: None,
        };
        
        assert_eq!(relationship.relation, "viewer");
        assert!(relationship.caveat.is_none());
    }

    #[test]
    fn test_relationship_with_caveat() {
        let mut context = HashMap::new();
        context.insert("ip_range".to_string(), serde_json::json!("192.168.1.0/24"));
        
        let relationship = Relationship {
            resource: Resource {
                resource_type: "document".to_string(),
                id: "doc123".to_string(),
            },
            relation: "editor".to_string(),
            subject: Subject {
                subject_type: SubjectType::User,
                id: "user789".to_string(),
                relation: None,
            },
            caveat: Some(Caveat {
                name: "ip_whitelist".to_string(),
                context,
            }),
        };
        
        assert!(relationship.caveat.is_some());
        let caveat = relationship.caveat.unwrap();
        assert_eq!(caveat.name, "ip_whitelist");
    }

    #[test]
    fn test_check_result_allowed() {
        let result = CheckResult {
            allowed: true,
            checked_at: Utc::now(),
            debug_trace: None,
        };
        
        assert!(result.allowed);
        assert!(result.debug_trace.is_none());
    }

    #[test]
    fn test_check_result_denied_with_trace() {
        let result = CheckResult {
            allowed: false,
            checked_at: Utc::now(),
            debug_trace: Some("Permission denied: user lacks 'viewer' relation".to_string()),
        };
        
        assert!(!result.allowed);
        assert!(result.debug_trace.is_some());
    }

    #[test]
    fn test_application_type_serialization() {
        let types = vec![
            ApplicationType::Web,
            ApplicationType::Mobile,
            ApplicationType::Spa,
            ApplicationType::Backend,
            ApplicationType::MachineToMachine,
        ];
        
        for app_type in types {
            let json = serde_json::to_string(&app_type).unwrap();
            let deserialized: ApplicationType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, app_type);
        }
    }

    #[test]
    fn test_oauth_provider_type_variants() {
        let types = vec![
            OAuthProviderType::Microsoft,
            OAuthProviderType::Google,
            OAuthProviderType::Okta,
            OAuthProviderType::Auth0,
            OAuthProviderType::Custom,
            OAuthProviderType::Saml,
        ];
        
        for provider_type in types {
            let json = serde_json::to_string(&provider_type).unwrap();
            let deserialized: OAuthProviderType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, provider_type);
        }
    }

    #[test]
    fn test_audit_event_type_serialization() {
        let event_type = AuditEventType::PermissionCheck;
        let json = serde_json::to_string(&event_type).unwrap();
        assert_eq!(json, "\"permission_check\"");
    }

    #[test]
    fn test_audit_result_variants() {
        let results = vec![
            AuditResult::Success,
            AuditResult::Denied,
            AuditResult::Error,
        ];
        
        for result in results {
            let json = serde_json::to_string(&result).unwrap();
            let deserialized: AuditResult = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, result);
        }
    }

    #[test]
    fn test_sync_type_serialization() {
        let types = vec![
            models::SyncType::Scim,
            models::SyncType::Webhook,
            models::SyncType::LdapPull,
            models::SyncType::ApiPull,
        ];
        
        for sync_type in types {
            let json = serde_json::to_string(&sync_type).unwrap();
            let deserialized: models::SyncType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, sync_type);
        }
    }
}

// =============================================================================
// Error Tests
// =============================================================================

#[cfg(test)]
mod error_tests {
    use super::*;

    #[test]
    fn test_not_found_error() {
        let error = SeparError::NotFound {
            entity_type: "tenant".to_string(),
            id: "tenant_123".to_string(),
        };
        
        let message = error.to_string();
        assert!(message.contains("tenant"));
        assert!(message.contains("tenant_123"));
    }

    #[test]
    fn test_permission_denied_error() {
        let error = SeparError::PermissionDenied {
            action: "view".to_string(),
            resource: "document:123".to_string(),
        };
        
        let message = error.to_string();
        assert!(message.contains("view"));
        assert!(message.contains("document:123"));
    }

    #[test]
    fn test_invalid_input_error() {
        let error = SeparError::InvalidInput {
            message: "Invalid email format".to_string(),
        };
        
        let message = error.to_string();
        assert!(message.contains("Invalid email format"));
    }

    #[test]
    fn test_internal_error() {
        let error = SeparError::Internal {
            message: "Database connection failed".to_string(),
        };
        
        let message = error.to_string();
        assert!(message.contains("Database connection failed"));
    }

    #[test]
    fn test_spicedb_error() {
        let error = SeparError::spicedb_error("Connection timeout");
        let message = error.to_string();
        assert!(message.contains("Connection timeout"));
    }

    #[test]
    fn test_database_error() {
        let error = SeparError::database_error("Unique constraint violation");
        let message = error.to_string();
        assert!(message.contains("Unique constraint violation"));
    }

    #[test]
    fn test_auth_error() {
        let error = SeparError::auth_error("Invalid token");
        let message = error.to_string();
        assert!(message.contains("Invalid token"));
    }

    #[test]
    fn test_error_helper_methods() {
        let not_found = SeparError::not_found("user", "user_123");
        assert!(matches!(not_found, SeparError::NotFound { .. }));

        let permission_denied = SeparError::permission_denied("write", "doc_456");
        assert!(matches!(permission_denied, SeparError::PermissionDenied { .. }));

        let invalid_input = SeparError::invalid_input("Missing field");
        assert!(matches!(invalid_input, SeparError::InvalidInput { .. }));
    }
}

// =============================================================================
// Identity Provider Tests
// =============================================================================

#[cfg(test)]
mod identity_tests {
    use super::*;
    use crate::identity::*;

    #[test]
    fn test_provider_type_serialization() {
        let types = vec![
            ProviderType::AzureAd,
            ProviderType::Okta,
            ProviderType::Google,
            ProviderType::GenericOidc,
            ProviderType::Direct,
        ];
        
        for provider_type in types {
            let json = serde_json::to_string(&provider_type).unwrap();
            let deserialized: ProviderType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, provider_type);
        }
    }

    #[test]
    fn test_provider_type_display() {
        assert_eq!(ProviderType::AzureAd.to_string(), "azure_ad");
        assert_eq!(ProviderType::Okta.to_string(), "okta");
        assert_eq!(ProviderType::Google.to_string(), "google");
        assert_eq!(ProviderType::Direct.to_string(), "direct");
    }

    #[test]
    fn test_synced_user_creation() {
        let user = identity::SyncedUser {
            external_id: "ext_user_123".to_string(),
            email: "john.doe@example.com".to_string(),
            display_name: "John Doe".to_string(),
            given_name: Some("John".to_string()),
            family_name: Some("Doe".to_string()),
            picture_url: None,
            active: true,
            email_verified: true,
            groups: vec![],
            roles: vec![],
            attributes: HashMap::new(),
            synced_at: Utc::now(),
        };
        
        assert_eq!(user.display_name, "John Doe");
        assert_eq!(user.email, "john.doe@example.com");
        assert!(user.active);
    }

    #[test]
    fn test_synced_group_creation() {
        let group = identity::SyncedGroup {
            external_id: "ext_group_456".to_string(),
            name: "Engineering".to_string(),
            description: Some("Engineering team".to_string()),
            group_type: None,
            members: vec!["user1".to_string(), "user2".to_string()],
            parent_groups: vec![],
            child_groups: vec![],
            attributes: HashMap::new(),
            synced_at: Utc::now(),
        };
        
        assert_eq!(group.name, "Engineering");
        assert_eq!(group.members.len(), 2);
    }

    #[test]
    fn test_synced_app_creation() {
        let app = identity::SyncedApp {
            external_id: "ext_app_789".to_string(),
            name: "My Service".to_string(),
            app_type: identity::SyncedAppType::ServicePrincipal,
            description: Some("A service principal".to_string()),
            enabled: true,
            assigned_permissions: vec!["read".to_string()],
            attributes: HashMap::new(),
            synced_at: Utc::now(),
        };
        
        assert_eq!(app.name, "My Service");
        assert!(app.enabled);
    }

    #[test]
    fn test_provider_features_default() {
        let features = ProviderFeatures::default();
        
        // Default should have all features disabled
        assert!(!features.sync_users);
        assert!(!features.sync_groups);
        assert!(!features.authentication);
    }

    #[test]
    fn test_sync_settings_default() {
        let settings = SyncSettings::default();
        
        // Default should have reasonable values
        assert!(settings.interval_secs.is_some());
        assert!(settings.full_sync_enabled);
        assert_eq!(settings.batch_size, 100);
    }

    #[test]
    fn test_sync_result_status_variants() {
        let statuses = vec![
            identity::SyncResultStatus::Success,
            identity::SyncResultStatus::PartialSuccess,
            identity::SyncResultStatus::Failed,
        ];
        
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: identity::SyncResultStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, status);
        }
    }

    #[test]
    fn test_principal_type_variants() {
        let types = vec![
            PrincipalType::User,
            PrincipalType::Service,
            PrincipalType::Application,
            PrincipalType::ManagedIdentity,
        ];
        
        for principal_type in types {
            let json = serde_json::to_string(&principal_type).unwrap();
            let deserialized: PrincipalType = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, principal_type);
        }
    }
}

// =============================================================================
// Relationship Filter Tests
// =============================================================================

#[cfg(test)]
mod filter_tests {
    use super::*;

    #[test]
    fn test_relationship_filter_default() {
        let filter = RelationshipFilter::default();
        
        assert!(filter.resource_type.is_none());
        assert!(filter.resource_id.is_none());
        assert!(filter.relation.is_none());
        assert!(filter.subject_type.is_none());
        assert!(filter.subject_id.is_none());
    }

    #[test]
    fn test_relationship_filter_with_resource_type() {
        let filter = RelationshipFilter {
            resource_type: Some("tenant".to_string()),
            ..Default::default()
        };
        
        assert_eq!(filter.resource_type, Some("tenant".to_string()));
        assert!(filter.resource_id.is_none());
    }

    #[test]
    fn test_relationship_filter_with_all_fields() {
        let filter = RelationshipFilter {
            resource_type: Some("document".to_string()),
            resource_id: Some("doc123".to_string()),
            relation: Some("viewer".to_string()),
            subject_type: Some("user".to_string()),
            subject_id: Some("user456".to_string()),
            subject_relation: None,
        };
        
        assert_eq!(filter.resource_type, Some("document".to_string()));
        assert_eq!(filter.resource_id, Some("doc123".to_string()));
        assert_eq!(filter.relation, Some("viewer".to_string()));
        assert_eq!(filter.subject_type, Some("user".to_string()));
        assert_eq!(filter.subject_id, Some("user456".to_string()));
    }
}
