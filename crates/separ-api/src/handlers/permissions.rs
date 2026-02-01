//! Permission registry handlers
//!
//! Exposes the permission registry based on SpiceDB schema.
//! This is the single source of truth for all available permissions.

use axum::{http::StatusCode, Json};
use serde::Serialize;

// ============================================================================
// DTOs
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct PermissionDefinition {
    /// Resource type from SpiceDB schema
    pub resource_type: String,
    /// Relation/role that can be assigned
    pub relation: String,
    /// Human-readable name
    pub name: String,
    /// Description of what this permission allows
    pub description: String,
    /// Category for grouping in UI
    pub category: String,
    /// Whether this permission requires a specific resource ID
    pub requires_resource_id: bool,
    /// Display order within category
    pub order: u32,
}

#[derive(Debug, Serialize)]
pub struct PermissionRegistryResponse {
    pub permissions: Vec<PermissionDefinition>,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

// ============================================================================
// Permission Registry - Based on schema.zed
// ============================================================================

/// Build the complete permission registry based on SpiceDB schema.
/// This is the single source of truth for all permission types.
fn build_permission_registry() -> Vec<PermissionDefinition> {
    vec![
        // =====================================================================
        // Platform-level permissions (no resource ID needed)
        // =====================================================================
        PermissionDefinition {
            resource_type: "platform".to_string(),
            relation: "admin".to_string(),
            name: "Platform Administrator".to_string(),
            description: "Full administrative access to the entire platform, all organizations, and all resources.".to_string(),
            category: "platform".to_string(),
            requires_resource_id: false,
            order: 1,
        },
        PermissionDefinition {
            resource_type: "platform".to_string(),
            relation: "member".to_string(),
            name: "Platform Member".to_string(),
            description: "Basic platform access. Can view platform-wide resources.".to_string(),
            category: "platform".to_string(),
            requires_resource_id: false,
            order: 2,
        },

        // =====================================================================
        // Tenant/Organization permissions
        // =====================================================================
        PermissionDefinition {
            resource_type: "tenant".to_string(),
            relation: "owner".to_string(),
            name: "Organization Owner".to_string(),
            description: "Full ownership of an organization. Can manage all settings, users, and data.".to_string(),
            category: "organization".to_string(),
            requires_resource_id: true,
            order: 1,
        },
        PermissionDefinition {
            resource_type: "tenant".to_string(),
            relation: "admin".to_string(),
            name: "Organization Administrator".to_string(),
            description: "Administrative access to an organization. Can manage users, groups, and settings.".to_string(),
            category: "organization".to_string(),
            requires_resource_id: true,
            order: 2,
        },
        PermissionDefinition {
            resource_type: "tenant".to_string(),
            relation: "member".to_string(),
            name: "Organization Member".to_string(),
            description: "Member of an organization. Can view organization resources and use assigned apps.".to_string(),
            category: "organization".to_string(),
            requires_resource_id: true,
            order: 3,
        },

        // =====================================================================
        // Workspace permissions
        // =====================================================================
        PermissionDefinition {
            resource_type: "workspace".to_string(),
            relation: "owner".to_string(),
            name: "Workspace Owner".to_string(),
            description: "Full ownership of a workspace. Can manage all settings and invite members.".to_string(),
            category: "workspace".to_string(),
            requires_resource_id: true,
            order: 1,
        },
        PermissionDefinition {
            resource_type: "workspace".to_string(),
            relation: "admin".to_string(),
            name: "Workspace Administrator".to_string(),
            description: "Administrative access to a workspace. Can manage applications and members.".to_string(),
            category: "workspace".to_string(),
            requires_resource_id: true,
            order: 2,
        },
        PermissionDefinition {
            resource_type: "workspace".to_string(),
            relation: "member".to_string(),
            name: "Workspace Member".to_string(),
            description: "Member of a workspace. Can view and edit workspace resources.".to_string(),
            category: "workspace".to_string(),
            requires_resource_id: true,
            order: 3,
        },
        PermissionDefinition {
            resource_type: "workspace".to_string(),
            relation: "viewer".to_string(),
            name: "Workspace Viewer".to_string(),
            description: "Read-only access to a workspace. Can view but not modify resources.".to_string(),
            category: "workspace".to_string(),
            requires_resource_id: true,
            order: 4,
        },

        // =====================================================================
        // Application permissions
        // =====================================================================
        PermissionDefinition {
            resource_type: "application".to_string(),
            relation: "owner".to_string(),
            name: "Application Owner".to_string(),
            description: "Full ownership of an application. Can manage all settings and deployments.".to_string(),
            category: "application".to_string(),
            requires_resource_id: true,
            order: 1,
        },
        PermissionDefinition {
            resource_type: "application".to_string(),
            relation: "admin".to_string(),
            name: "Application Administrator".to_string(),
            description: "Administrative access to an application. Can manage resources and permissions.".to_string(),
            category: "application".to_string(),
            requires_resource_id: true,
            order: 2,
        },
        PermissionDefinition {
            resource_type: "application".to_string(),
            relation: "developer".to_string(),
            name: "Application Developer".to_string(),
            description: "Developer access to an application. Can deploy and manage resources.".to_string(),
            category: "application".to_string(),
            requires_resource_id: true,
            order: 3,
        },
        PermissionDefinition {
            resource_type: "application".to_string(),
            relation: "viewer".to_string(),
            name: "Application Viewer".to_string(),
            description: "Read-only access to an application. Can view resources and deployments.".to_string(),
            category: "application".to_string(),
            requires_resource_id: true,
            order: 4,
        },

        // =====================================================================
        // Resource permissions (generic resources within applications)
        // =====================================================================
        PermissionDefinition {
            resource_type: "resource".to_string(),
            relation: "owner".to_string(),
            name: "Resource Owner".to_string(),
            description: "Full ownership of a resource. Can manage access and delete.".to_string(),
            category: "data".to_string(),
            requires_resource_id: true,
            order: 1,
        },
        PermissionDefinition {
            resource_type: "resource".to_string(),
            relation: "editor".to_string(),
            name: "Resource Editor".to_string(),
            description: "Editor access to a resource. Can view and modify data.".to_string(),
            category: "data".to_string(),
            requires_resource_id: true,
            order: 2,
        },
        PermissionDefinition {
            resource_type: "resource".to_string(),
            relation: "viewer".to_string(),
            name: "Resource Viewer".to_string(),
            description: "Read-only access to a resource.".to_string(),
            category: "data".to_string(),
            requires_resource_id: true,
            order: 3,
        },

        // =====================================================================
        // Yekta data catalog permissions
        // =====================================================================
        PermissionDefinition {
            resource_type: "yekta_resource".to_string(),
            relation: "owner".to_string(),
            name: "Data Resource Owner".to_string(),
            description: "Full ownership of a data resource in the catalog. Can manage access and metadata.".to_string(),
            category: "data".to_string(),
            requires_resource_id: true,
            order: 4,
        },
        PermissionDefinition {
            resource_type: "yekta_resource".to_string(),
            relation: "editor".to_string(),
            name: "Data Resource Editor".to_string(),
            description: "Editor access to a data resource. Can modify data and metadata.".to_string(),
            category: "data".to_string(),
            requires_resource_id: true,
            order: 5,
        },
        PermissionDefinition {
            resource_type: "yekta_resource".to_string(),
            relation: "viewer".to_string(),
            name: "Data Resource Viewer".to_string(),
            description: "Read-only access to a data resource. Can view data and metadata.".to_string(),
            category: "data".to_string(),
            requires_resource_id: true,
            order: 6,
        },

        // =====================================================================
        // Group permissions
        // =====================================================================
        PermissionDefinition {
            resource_type: "group".to_string(),
            relation: "owner".to_string(),
            name: "Group Owner".to_string(),
            description: "Owner of a security group. Can manage group settings and membership.".to_string(),
            category: "security".to_string(),
            requires_resource_id: true,
            order: 1,
        },
        PermissionDefinition {
            resource_type: "group".to_string(),
            relation: "admin".to_string(),
            name: "Group Administrator".to_string(),
            description: "Administrator of a security group. Can add/remove members.".to_string(),
            category: "security".to_string(),
            requires_resource_id: true,
            order: 2,
        },
        PermissionDefinition {
            resource_type: "group".to_string(),
            relation: "member".to_string(),
            name: "Group Member".to_string(),
            description: "Member of a security group. Inherits group permissions.".to_string(),
            category: "security".to_string(),
            requires_resource_id: true,
            order: 3,
        },

        // =====================================================================
        // Service Account permissions
        // =====================================================================
        PermissionDefinition {
            resource_type: "service_account".to_string(),
            relation: "owner".to_string(),
            name: "Service Account Owner".to_string(),
            description: "Owner of a service account. Can manage credentials and access.".to_string(),
            category: "security".to_string(),
            requires_resource_id: true,
            order: 4,
        },
        PermissionDefinition {
            resource_type: "service_account".to_string(),
            relation: "admin".to_string(),
            name: "Service Account Administrator".to_string(),
            description: "Administrator of a service account. Can rotate credentials.".to_string(),
            category: "security".to_string(),
            requires_resource_id: true,
            order: 5,
        },

        // =====================================================================
        // API Key permissions
        // =====================================================================
        PermissionDefinition {
            resource_type: "api_key".to_string(),
            relation: "creator".to_string(),
            name: "API Key Creator".to_string(),
            description: "Creator of an API key. Can manage and revoke the key.".to_string(),
            category: "security".to_string(),
            requires_resource_id: true,
            order: 6,
        },

        // =====================================================================
        // Role permissions
        // =====================================================================
        PermissionDefinition {
            resource_type: "role".to_string(),
            relation: "creator".to_string(),
            name: "Role Creator".to_string(),
            description: "Creator of a custom role. Can manage role definition.".to_string(),
            category: "security".to_string(),
            requires_resource_id: true,
            order: 7,
        },
        PermissionDefinition {
            resource_type: "role".to_string(),
            relation: "assignee".to_string(),
            name: "Role Assignee".to_string(),
            description: "User assigned to a role. Inherits role permissions.".to_string(),
            category: "security".to_string(),
            requires_resource_id: true,
            order: 8,
        },

        // =====================================================================
        // OAuth Provider permissions
        // =====================================================================
        PermissionDefinition {
            resource_type: "oauth_provider".to_string(),
            relation: "admin".to_string(),
            name: "OAuth Provider Administrator".to_string(),
            description: "Administrator of an OAuth provider. Can configure SSO settings.".to_string(),
            category: "security".to_string(),
            requires_resource_id: true,
            order: 9,
        },

        // =====================================================================
        // Sync Config permissions
        // =====================================================================
        PermissionDefinition {
            resource_type: "sync_config".to_string(),
            relation: "admin".to_string(),
            name: "Sync Configuration Administrator".to_string(),
            description: "Administrator of sync configuration. Can manage directory sync.".to_string(),
            category: "security".to_string(),
            requires_resource_id: true,
            order: 10,
        },
    ]
}

// ============================================================================
// Handlers
// ============================================================================

/// Get the complete permission registry
///
/// GET /api/v1/admin/permissions/registry
///
/// Returns all possible permission types based on SpiceDB schema.
/// This is used by the frontend to dynamically build permission UIs.
pub async fn get_permission_registry() -> Result<Json<ApiResponse<PermissionRegistryResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let permissions = build_permission_registry();
    
    tracing::info!("Returning permission registry with {} permission types", permissions.len());
    
    Ok(Json(ApiResponse {
        success: true,
        data: Some(PermissionRegistryResponse { permissions }),
        error: None,
    }))
}

/// Get available categories
///
/// GET /api/v1/admin/permissions/categories
pub async fn get_permission_categories() -> Json<ApiResponse<Vec<String>>> {
    let categories = vec![
        "platform".to_string(),
        "organization".to_string(),
        "workspace".to_string(),
        "application".to_string(),
        "data".to_string(),
        "security".to_string(),
    ];
    
    Json(ApiResponse {
        success: true,
        data: Some(categories),
        error: None,
    })
}
