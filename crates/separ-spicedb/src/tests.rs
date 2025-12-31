//! Unit and integration tests for separ-spicedb

use super::*;
use separ_core::{Resource, Subject, SubjectType, Relationship, RelationshipFilter};

// =============================================================================
// Schema Tests
// =============================================================================

#[cfg(test)]
mod schema_tests {
    use super::*;
    use crate::schema::YEKTA_SCHEMA;

    #[test]
    fn test_schema_contains_required_definitions() {
        assert!(YEKTA_SCHEMA.contains("definition platform"));
        assert!(YEKTA_SCHEMA.contains("definition tenant"));
        assert!(YEKTA_SCHEMA.contains("definition workspace"));
        assert!(YEKTA_SCHEMA.contains("definition application"));
        assert!(YEKTA_SCHEMA.contains("definition resource"));
        assert!(YEKTA_SCHEMA.contains("definition user"));
        assert!(YEKTA_SCHEMA.contains("definition group"));
        assert!(YEKTA_SCHEMA.contains("definition service_account"));
        assert!(YEKTA_SCHEMA.contains("definition api_key"));
        assert!(YEKTA_SCHEMA.contains("definition role"));
        assert!(YEKTA_SCHEMA.contains("definition oauth_provider"));
        assert!(YEKTA_SCHEMA.contains("definition sync_config"));
    }

    #[test]
    fn test_tenant_has_required_relations() {
        // Check that tenant has the expected relations
        assert!(YEKTA_SCHEMA.contains("relation owner: user | service_account"));
        assert!(YEKTA_SCHEMA.contains("relation admin: user | service_account | group#member"));
        assert!(YEKTA_SCHEMA.contains("relation member: user | service_account | group#member"));
    }

    #[test]
    fn test_tenant_has_required_permissions() {
        // Check that tenant has the expected permissions
        assert!(YEKTA_SCHEMA.contains("permission manage"));
        assert!(YEKTA_SCHEMA.contains("permission view"));
        assert!(YEKTA_SCHEMA.contains("permission create_workspace"));
        assert!(YEKTA_SCHEMA.contains("permission manage_users"));
        assert!(YEKTA_SCHEMA.contains("permission manage_groups"));
    }

    #[test]
    fn test_workspace_inherits_from_tenant() {
        // Check that workspace has tenant relation for hierarchy
        assert!(YEKTA_SCHEMA.contains("relation tenant: tenant"));
    }

    #[test]
    fn test_application_inherits_from_workspace() {
        // Check that application has workspace relation
        assert!(YEKTA_SCHEMA.contains("relation workspace: workspace"));
    }

    #[test]
    fn test_resource_inherits_from_application() {
        // Check that resource has application relation
        assert!(YEKTA_SCHEMA.contains("relation application: application"));
    }

    #[test]
    fn test_group_membership_relation() {
        // Check that groups support nested membership
        assert!(YEKTA_SCHEMA.contains("relation member: user | service_account | group#member"));
    }

    #[test]
    fn test_permission_inheritance() {
        // Check permission inheritance patterns
        // Workspace permissions should inherit from tenant
        assert!(YEKTA_SCHEMA.contains("tenant->manage"));
        // Application permissions should inherit from workspace
        assert!(YEKTA_SCHEMA.contains("workspace->manage"));
        assert!(YEKTA_SCHEMA.contains("workspace->view"));
    }

    #[test]
    fn test_schema_is_valid_spicedb_format() {
        // Basic format validation
        let lines: Vec<&str> = YEKTA_SCHEMA.lines().collect();
        
        // Check that definitions are properly formatted
        let definition_count = lines.iter()
            .filter(|line| line.trim().starts_with("definition "))
            .count();
        
        assert!(definition_count >= 10, "Should have at least 10 definitions");
        
        // Check that we have permission declarations
        let permission_count = lines.iter()
            .filter(|line| line.trim().starts_with("permission "))
            .count();
        
        assert!(permission_count >= 15, "Should have at least 15 permission declarations");
    }
}

// =============================================================================
// Client Tests (Unit - Mocked)
// =============================================================================

#[cfg(test)]
mod client_tests {
    use super::*;

    #[test]
    fn test_relationship_filter_default() {
        let filter = RelationshipFilter::default();
        assert!(filter.resource_type.is_none());
        assert!(filter.resource_id.is_none());
        assert!(filter.relation.is_none());
        assert!(filter.subject_type.is_none());
        assert!(filter.subject_id.is_none());
        assert!(filter.subject_relation.is_none());
    }

    #[test]
    fn test_relationship_filter_with_resource_type() {
        let filter = RelationshipFilter {
            resource_type: Some("tenant".to_string()),
            ..Default::default()
        };
        
        assert_eq!(filter.resource_type, Some("tenant".to_string()));
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

    #[test]
    fn test_subject_creation_for_user() {
        let subject = Subject {
            subject_type: SubjectType::User,
            id: "user_123".to_string(),
            relation: None,
        };
        
        assert_eq!(subject.subject_type, SubjectType::User);
        assert_eq!(subject.id, "user_123");
    }

    #[test]
    fn test_subject_creation_for_group_member() {
        let subject = Subject {
            subject_type: SubjectType::Group,
            id: "engineers".to_string(),
            relation: Some("member".to_string()),
        };
        
        assert_eq!(subject.subject_type, SubjectType::Group);
        assert_eq!(subject.id, "engineers");
        assert_eq!(subject.relation, Some("member".to_string()));
    }

    #[test]
    fn test_resource_creation() {
        let resource = Resource {
            resource_type: "workspace".to_string(),
            id: "ws_123".to_string(),
        };
        
        assert_eq!(resource.resource_type, "workspace");
        assert_eq!(resource.id, "ws_123");
    }

    #[test]
    fn test_relationship_creation() {
        let relationship = Relationship {
            resource: Resource {
                resource_type: "tenant".to_string(),
                id: "tenant_456".to_string(),
            },
            relation: "admin".to_string(),
            subject: Subject {
                subject_type: SubjectType::User,
                id: "user_789".to_string(),
                relation: None,
            },
            caveat: None,
        };
        
        assert_eq!(relationship.resource.resource_type, "tenant");
        assert_eq!(relationship.resource.id, "tenant_456");
        assert_eq!(relationship.relation, "admin");
        assert_eq!(relationship.subject.id, "user_789");
    }
}

// =============================================================================
// Authorization Service Tests (Unit - Mocked)
// =============================================================================

#[cfg(test)]
mod service_tests {
    use super::*;
    use chrono::Utc;
    use separ_core::CheckResult;

    #[test]
    fn test_check_result_creation_allowed() {
        let result = CheckResult {
            allowed: true,
            checked_at: Utc::now(),
            debug_trace: None,
        };
        
        assert!(result.allowed);
        assert!(result.debug_trace.is_none());
    }

    #[test]
    fn test_check_result_creation_denied() {
        let result = CheckResult {
            allowed: false,
            checked_at: Utc::now(),
            debug_trace: Some("No matching relation found".to_string()),
        };
        
        assert!(!result.allowed);
        assert!(result.debug_trace.is_some());
    }

    #[test]
    fn test_check_result_serialization() {
        let result = CheckResult {
            allowed: true,
            checked_at: Utc::now(),
            debug_trace: None,
        };
        
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: CheckResult = serde_json::from_str(&json).unwrap();
        
        assert_eq!(result.allowed, deserialized.allowed);
    }
}

// =============================================================================
// Integration Tests (Require SpiceDB)
// =============================================================================

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// Helper to check if SpiceDB is available
    fn spicedb_available() -> bool {
        std::env::var("SPICEDB_ENDPOINT").is_ok()
    }

    #[tokio::test]
    #[ignore = "Requires running SpiceDB instance"]
    async fn test_spicedb_connection() {
        if !spicedb_available() {
            eprintln!("Skipping: SpiceDB not available");
            return;
        }
        
        let endpoint = std::env::var("SPICEDB_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:50051".to_string());
        let token = std::env::var("SPICEDB_TOKEN")
            .unwrap_or_else(|_| "supersecretkey".to_string());
        
        let config = crate::SpiceDbConfig {
            endpoint,
            token,
            use_tls: false,
            connect_timeout_ms: 5000,
            request_timeout_ms: 30000,
        };
        
        let client = SpiceDbClient::new(config).await;
        assert!(client.is_ok(), "Should connect to SpiceDB");
    }

    #[tokio::test]
    #[ignore = "Requires running SpiceDB instance"]
    async fn test_write_and_check_permission() {
        if !spicedb_available() {
            return;
        }
        
        // This test would:
        // 1. Write a relationship (user:alice -> tenant:test_tenant#owner)
        // 2. Check permission (can user:alice manage tenant:test_tenant?)
        // 3. Assert the permission is granted
        // 4. Clean up the relationship
    }

    #[tokio::test]
    #[ignore = "Requires running SpiceDB instance"]
    async fn test_permission_inheritance() {
        if !spicedb_available() {
            return;
        }
        
        // This test would:
        // 1. Create a tenant with an owner
        // 2. Create a workspace under the tenant
        // 3. Check that the tenant owner can manage the workspace
    }

    #[tokio::test]
    #[ignore = "Requires running SpiceDB instance"]
    async fn test_group_membership_permissions() {
        if !spicedb_available() {
            return;
        }
        
        // This test would:
        // 1. Create a group with members
        // 2. Assign the group#member to a tenant as admin
        // 3. Check that group members have admin permissions
    }

    #[tokio::test]
    #[ignore = "Requires running SpiceDB instance"]
    async fn test_lookup_resources() {
        if !spicedb_available() {
            return;
        }
        
        // This test would:
        // 1. Create multiple resources with a user as viewer
        // 2. Lookup all resources the user can view
        // 3. Assert all expected resources are returned
    }

    #[tokio::test]
    #[ignore = "Requires running SpiceDB instance"]
    async fn test_lookup_subjects() {
        if !spicedb_available() {
            return;
        }
        
        // This test would:
        // 1. Create a resource with multiple viewers
        // 2. Lookup all subjects that can view the resource
        // 3. Assert all expected subjects are returned
    }
}

// =============================================================================
// SpiceDB Schema Assertion Tests (Following SpiceDB Best Practices)
// =============================================================================

#[cfg(test)]
mod schema_assertion_tests {
    use super::*;
    
    /// These tests validate the authorization model semantics
    /// They should be run with `zed validate` or similar tooling
    
    #[test]
    fn test_tenant_owner_has_all_permissions() {
        // Assertion: tenant#owner should have:
        // - manage permission
        // - view permission
        // - create_workspace permission
        // - manage_users permission
        // - manage_groups permission
        // - manage_oauth permission
        // - view_audit permission
        
        let schema = crate::schema::YEKTA_SCHEMA;
        
        // Verify owner is included in manage
        assert!(schema.contains("permission manage = owner"));
        // Verify owner is included in view (via manage)
        assert!(schema.contains("permission view = owner + admin"));
    }

    #[test]
    fn test_platform_admin_inherits_to_tenant() {
        let schema = crate::schema::YEKTA_SCHEMA;
        
        // Platform admin should be able to manage tenants
        assert!(schema.contains("platform->admin"));
    }

    #[test]
    fn test_resource_permissions_flow_through_application() {
        let schema = crate::schema::YEKTA_SCHEMA;
        
        // Resources should inherit from application
        assert!(schema.contains("application->manage"));
        assert!(schema.contains("application->view"));
    }

    #[test]
    fn test_group_member_relation_is_usable() {
        let schema = crate::schema::YEKTA_SCHEMA;
        
        // Groups should allow their members to be used in other relations
        assert!(schema.contains("group#member"));
    }

    #[test]
    fn test_service_account_can_act_like_user() {
        let schema = crate::schema::YEKTA_SCHEMA;
        
        // Service accounts should be able to hold the same relations as users
        assert!(schema.contains("user | service_account"));
    }
}

