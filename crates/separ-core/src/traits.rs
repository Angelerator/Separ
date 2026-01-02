//! Core traits for the Separ authorization platform

use crate::{error::Result, ids::*, models::*};
use async_trait::async_trait;

// =============================================================================
// Authorization Traits
// =============================================================================

/// Core authorization operations using SpiceDB
#[async_trait]
pub trait AuthorizationService: Send + Sync {
    /// Check if a subject has a permission on a resource
    async fn check_permission(
        &self,
        subject: &Subject,
        resource: &Resource,
        permission: &str,
    ) -> Result<CheckResult>;

    /// Check multiple permissions at once
    async fn check_permissions_bulk(
        &self,
        checks: Vec<(Subject, Resource, String)>,
    ) -> Result<Vec<CheckResult>>;

    /// Write a relationship
    async fn write_relationship(&self, relationship: &Relationship) -> Result<String>;

    /// Write multiple relationships atomically
    async fn write_relationships(&self, relationships: &[Relationship]) -> Result<String>;

    /// Delete a relationship
    async fn delete_relationship(&self, relationship: &Relationship) -> Result<String>;

    /// Delete multiple relationships matching a filter
    async fn delete_relationships(&self, filter: &RelationshipFilter) -> Result<u64>;

    /// Lookup all subjects that have a permission on a resource
    async fn lookup_subjects(
        &self,
        resource: &Resource,
        permission: &str,
        subject_type: &str,
    ) -> Result<Vec<Subject>>;

    /// Lookup all resources a subject has a permission on
    async fn lookup_resources(
        &self,
        subject: &Subject,
        permission: &str,
        resource_type: &str,
    ) -> Result<Vec<Resource>>;

    /// Read relationships matching a filter
    async fn read_relationships(&self, filter: &RelationshipFilter) -> Result<Vec<Relationship>>;
}

/// Filter for querying relationships
#[derive(Debug, Clone, Default)]
pub struct RelationshipFilter {
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub relation: Option<String>,
    pub subject_type: Option<String>,
    pub subject_id: Option<String>,
    pub subject_relation: Option<String>,
}

// =============================================================================
// Tenant Management Traits
// =============================================================================

/// Tenant management operations
#[async_trait]
pub trait TenantRepository: Send + Sync {
    async fn create(&self, tenant: &Tenant) -> Result<Tenant>;
    async fn get_by_id(&self, id: TenantId) -> Result<Option<Tenant>>;
    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>>;
    async fn list(&self, offset: u32, limit: u32) -> Result<Vec<Tenant>>;
    async fn update(&self, tenant: &Tenant) -> Result<Tenant>;
    async fn delete(&self, id: TenantId) -> Result<()>;
}

/// Workspace management operations
#[async_trait]
pub trait WorkspaceRepository: Send + Sync {
    async fn create(&self, workspace: &Workspace) -> Result<Workspace>;
    async fn get_by_id(&self, id: WorkspaceId) -> Result<Option<Workspace>>;
    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<Workspace>>;
    async fn update(&self, workspace: &Workspace) -> Result<Workspace>;
    async fn delete(&self, id: WorkspaceId) -> Result<()>;
}

/// Application management operations
#[async_trait]
pub trait ApplicationRepository: Send + Sync {
    async fn create(&self, application: &Application) -> Result<Application>;
    async fn get_by_id(&self, id: ApplicationId) -> Result<Option<Application>>;
    async fn get_by_slug(
        &self,
        workspace_id: WorkspaceId,
        slug: &str,
    ) -> Result<Option<Application>>;
    async fn list_by_workspace(
        &self,
        workspace_id: WorkspaceId,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<Application>>;
    async fn update(&self, application: &Application) -> Result<Application>;
    async fn delete(&self, id: ApplicationId) -> Result<()>;
}

// =============================================================================
// User Management Traits
// =============================================================================

/// User management operations
#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create(&self, user: &User) -> Result<User>;
    async fn get_by_id(&self, id: UserId) -> Result<Option<User>>;
    async fn get_by_email(&self, tenant_id: TenantId, email: &str) -> Result<Option<User>>;
    async fn get_by_external_id(
        &self,
        tenant_id: TenantId,
        external_id: &str,
    ) -> Result<Option<User>>;
    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<User>>;
    async fn update(&self, user: &User) -> Result<User>;
    async fn delete(&self, id: UserId) -> Result<()>;
    async fn count_by_tenant(&self, tenant_id: TenantId) -> Result<u64>;
}

/// Group management operations
#[async_trait]
pub trait GroupRepository: Send + Sync {
    async fn create(&self, group: &Group) -> Result<Group>;
    async fn get_by_id(&self, id: GroupId) -> Result<Option<Group>>;
    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<Group>>;
    async fn update(&self, group: &Group) -> Result<Group>;
    async fn delete(&self, id: GroupId) -> Result<()>;
    async fn add_member(&self, group_id: GroupId, user_id: UserId) -> Result<()>;
    async fn remove_member(&self, group_id: GroupId, user_id: UserId) -> Result<()>;
    async fn list_members(&self, group_id: GroupId, offset: u32, limit: u32) -> Result<Vec<User>>;
}

// =============================================================================
// OAuth & SSO Traits
// =============================================================================

/// OAuth provider management
#[async_trait]
pub trait OAuthProviderRepository: Send + Sync {
    async fn create(&self, provider: &OAuthProvider) -> Result<OAuthProvider>;
    async fn get_by_id(&self, id: OAuthProviderId) -> Result<Option<OAuthProvider>>;
    async fn list_by_tenant(&self, tenant_id: TenantId) -> Result<Vec<OAuthProvider>>;
    async fn update(&self, provider: &OAuthProvider) -> Result<OAuthProvider>;
    async fn delete(&self, id: OAuthProviderId) -> Result<()>;
}

/// OAuth authentication flow handler
#[async_trait]
pub trait OAuthHandler: Send + Sync {
    /// Generate authorization URL for a provider
    async fn get_authorization_url(
        &self,
        provider: &OAuthProvider,
        state: &str,
        nonce: Option<&str>,
    ) -> Result<String>;

    /// Exchange authorization code for tokens
    async fn exchange_code(&self, provider: &OAuthProvider, code: &str) -> Result<TokenResponse>;

    /// Validate and decode an ID token
    async fn validate_id_token(
        &self,
        provider: &OAuthProvider,
        id_token: &str,
    ) -> Result<IdTokenClaims>;

    /// Get user info from the provider
    async fn get_user_info(&self, provider: &OAuthProvider, access_token: &str)
        -> Result<UserInfo>;
}

/// Token response from OAuth provider
#[derive(Debug, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: Option<String>,
}

/// ID token claims
#[derive(Debug, Clone)]
pub struct IdTokenClaims {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    pub locale: Option<String>,
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

/// User info from OAuth provider
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    pub locale: Option<String>,
}

// =============================================================================
// Sync Traits
// =============================================================================

/// Sync configuration management
#[async_trait]
pub trait SyncConfigRepository: Send + Sync {
    async fn create(&self, config: &SyncConfig) -> Result<SyncConfig>;
    async fn get_by_id(&self, id: SyncConfigId) -> Result<Option<SyncConfig>>;
    async fn list_by_tenant(&self, tenant_id: TenantId) -> Result<Vec<SyncConfig>>;
    async fn update(&self, config: &SyncConfig) -> Result<SyncConfig>;
    async fn delete(&self, id: SyncConfigId) -> Result<()>;
}

/// SCIM protocol handler
#[async_trait]
pub trait ScimHandler: Send + Sync {
    /// Process SCIM user creation
    async fn create_user(&self, tenant_id: TenantId, scim_user: ScimUser) -> Result<User>;

    /// Process SCIM user update
    async fn update_user(
        &self,
        tenant_id: TenantId,
        external_id: &str,
        scim_user: ScimUser,
    ) -> Result<User>;

    /// Process SCIM user deletion
    async fn delete_user(&self, tenant_id: TenantId, external_id: &str) -> Result<()>;

    /// Process SCIM group creation
    async fn create_group(&self, tenant_id: TenantId, scim_group: ScimGroup) -> Result<Group>;

    /// Process SCIM group update
    async fn update_group(
        &self,
        tenant_id: TenantId,
        external_id: &str,
        scim_group: ScimGroup,
    ) -> Result<Group>;

    /// Process SCIM group deletion
    async fn delete_group(&self, tenant_id: TenantId, external_id: &str) -> Result<()>;
}

/// SCIM user representation
#[derive(Debug, Clone)]
pub struct ScimUser {
    pub external_id: Option<String>,
    pub user_name: String,
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub emails: Vec<ScimEmail>,
    pub active: bool,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ScimEmail {
    pub value: String,
    pub primary: bool,
    pub email_type: Option<String>,
}

/// SCIM group representation
#[derive(Debug, Clone)]
pub struct ScimGroup {
    pub external_id: Option<String>,
    pub display_name: String,
    pub members: Vec<ScimMember>,
}

#[derive(Debug, Clone)]
pub struct ScimMember {
    pub value: String,
    pub display: Option<String>,
}

// =============================================================================
// Audit Traits
// =============================================================================

/// Audit event logging
#[async_trait]
pub trait AuditRepository: Send + Sync {
    async fn log(&self, event: &AuditEvent) -> Result<()>;
    async fn query(
        &self,
        tenant_id: TenantId,
        filter: &AuditFilter,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<AuditEvent>>;
}

/// Filter for querying audit events
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub event_types: Option<Vec<AuditEventType>>,
    pub actor_id: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub from_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub to_timestamp: Option<chrono::DateTime<chrono::Utc>>,
}
