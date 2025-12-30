//! Domain models for the Separ authorization platform

use crate::ids::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Platform & Tenant Models
// =============================================================================

/// Platform represents the root of the authorization hierarchy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Platform {
    pub id: PlatformId,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Tenant represents a company/organization using the platform
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: TenantId,
    pub platform_id: PlatformId,
    pub name: String,
    pub slug: String,
    pub status: TenantStatus,
    pub settings: TenantSettings,
    pub metadata: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    Active,
    Suspended,
    PendingSetup,
    Deactivated,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TenantSettings {
    /// Maximum number of users allowed
    pub max_users: Option<u32>,
    /// Maximum number of applications allowed
    pub max_applications: Option<u32>,
    /// Whether to allow external OAuth providers
    pub allow_external_oauth: bool,
    /// Whether SCIM provisioning is enabled
    pub scim_enabled: bool,
    /// Custom domain for the tenant
    pub custom_domain: Option<String>,
    /// Session timeout in seconds
    pub session_timeout_secs: Option<u32>,
}

/// Workspace represents a logical grouping within a tenant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub tenant_id: TenantId,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Application represents a registered application within a workspace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    pub id: ApplicationId,
    pub workspace_id: WorkspaceId,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub app_type: ApplicationType,
    pub status: ApplicationStatus,
    pub redirect_uris: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationType {
    Web,
    Mobile,
    Spa,
    Backend,
    MachineToMachine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationStatus {
    Active,
    Inactive,
    Development,
}

// =============================================================================
// User & Identity Models
// =============================================================================

/// User represents a human user in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub tenant_id: TenantId,
    pub external_id: Option<String>,
    pub email: String,
    pub email_verified: bool,
    pub display_name: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture_url: Option<String>,
    pub locale: Option<String>,
    pub timezone: Option<String>,
    pub status: UserStatus,
    pub metadata: HashMap<String, serde_json::Value>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    Active,
    Inactive,
    Suspended,
    PendingVerification,
}

/// ServiceAccount represents a machine identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccount {
    pub id: ServiceAccountId,
    pub tenant_id: TenantId,
    pub application_id: Option<ApplicationId>,
    pub name: String,
    pub description: Option<String>,
    pub status: ServiceAccountStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAccountStatus {
    Active,
    Inactive,
    Revoked,
}

/// Group represents a collection of users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: GroupId,
    pub tenant_id: TenantId,
    pub name: String,
    pub description: Option<String>,
    pub external_id: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Role represents a named set of permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub tenant_id: Option<TenantId>, // None for platform-level roles
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// =============================================================================
// Authorization Models
// =============================================================================

/// Represents a subject (who) in a permission check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub subject_type: SubjectType,
    pub id: String,
    pub relation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    User,
    ServiceAccount,
    Group,
    Wildcard,
}

/// Represents a resource (what) in a permission check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub resource_type: String,
    pub id: String,
}

/// A relationship tuple in SpiceDB format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    pub resource: Resource,
    pub relation: String,
    pub subject: Subject,
    pub caveat: Option<Caveat>,
}

/// Caveat for conditional permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Caveat {
    pub name: String,
    pub context: HashMap<String, serde_json::Value>,
}

/// Result of a permission check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub allowed: bool,
    pub checked_at: DateTime<Utc>,
    pub debug_trace: Option<String>,
}

// =============================================================================
// OAuth & SSO Models
// =============================================================================

/// OAuth provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProvider {
    pub id: OAuthProviderId,
    pub tenant_id: TenantId,
    pub provider_type: OAuthProviderType,
    pub name: String,
    pub client_id: String,
    #[serde(skip_serializing)]
    pub client_secret_encrypted: Vec<u8>,
    pub issuer_url: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub scopes: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthProviderType {
    Microsoft,
    Google,
    Okta,
    Auth0,
    Custom,
    Saml,
}

/// OAuth session/token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthSession {
    pub session_id: SessionId,
    pub user_id: UserId,
    pub provider_id: OAuthProviderId,
    pub access_token_hash: String,
    pub refresh_token_hash: Option<String>,
    pub id_token_claims: HashMap<String, serde_json::Value>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

// =============================================================================
// Sync Configuration Models
// =============================================================================

/// Configuration for syncing with external IdPs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    pub id: SyncConfigId,
    pub tenant_id: TenantId,
    pub name: String,
    pub sync_type: SyncType,
    pub config: SyncConfigDetails,
    pub enabled: bool,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_sync_status: Option<SyncStatus>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncType {
    Scim,
    Webhook,
    LdapPull,
    ApiPull,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SyncConfigDetails {
    Scim {
        bearer_token_hash: String,
        user_schema: Option<String>,
        group_schema: Option<String>,
    },
    Webhook {
        secret_hash: String,
        events: Vec<String>,
    },
    LdapPull {
        server_url: String,
        bind_dn: String,
        base_dn: String,
        user_filter: String,
        group_filter: Option<String>,
        sync_interval_secs: u32,
    },
    ApiPull {
        endpoint_url: String,
        auth_type: String,
        sync_interval_secs: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    Success,
    PartialSuccess,
    Failed,
    InProgress,
}

// =============================================================================
// API Key & Webhook Models
// =============================================================================

/// API key for service-to-service authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: ApiKeyId,
    pub tenant_id: TenantId,
    pub application_id: Option<ApplicationId>,
    pub name: String,
    pub key_prefix: String,
    pub key_hash: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Webhook configuration for sending events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub id: WebhookId,
    pub tenant_id: TenantId,
    pub name: String,
    pub url: String,
    pub secret_hash: String,
    pub events: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// =============================================================================
// Audit Models
// =============================================================================

/// Audit event for tracking authorization-related actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: AuditEventId,
    pub tenant_id: TenantId,
    pub event_type: AuditEventType,
    pub actor: AuditActor,
    pub resource: Option<Resource>,
    pub action: String,
    pub result: AuditResult,
    pub metadata: HashMap<String, serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    PermissionCheck,
    RelationshipWrite,
    RelationshipDelete,
    UserLogin,
    UserLogout,
    UserCreated,
    UserUpdated,
    UserDeleted,
    TenantCreated,
    TenantUpdated,
    ApplicationCreated,
    ApplicationUpdated,
    SyncEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditActor {
    pub actor_type: SubjectType,
    pub id: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Success,
    Denied,
    Error,
}

