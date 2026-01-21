//! Domain models for the Separ authorization platform
//!
//! ## ZedToken Support
//! 
//! Key resource models include an optional `zed_token` field for SpiceDB consistency.
//! This follows SpiceDB best practices:
//! - Store ZedToken alongside resources after permission changes
//! - Use for `at_least_as_fresh` consistency in subsequent permission checks
//! - Ensures read-after-write consistency without `fully_consistent` overhead

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
    /// SpiceDB ZedToken for consistency tracking
    /// Updated when permissions for this platform are modified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zed_token: Option<String>,
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
    /// SpiceDB ZedToken for consistency tracking
    /// Updated when permissions for this tenant are modified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zed_token: Option<String>,
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
    /// SpiceDB ZedToken for consistency tracking
    /// Updated when permissions for this workspace are modified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zed_token: Option<String>,
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
    /// SpiceDB ZedToken for consistency tracking
    /// Updated when permissions for this application are modified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zed_token: Option<String>,
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
    /// SpiceDB ZedToken for consistency tracking
    /// Updated when permissions for this user are modified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zed_token: Option<String>,
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
    /// Individual user
    User,
    /// Service account for machine-to-machine auth
    ServiceAccount,
    /// Group of users
    Group,
    /// The entire platform (root level)
    Platform,
    /// A tenant/organization
    Tenant,
    /// A workspace within a tenant
    Workspace,
    /// An application within a workspace
    Application,
    /// A role that can be assigned to users
    Role,
    /// Anonymous/unauthenticated access
    Anonymous,
    /// Wildcard for all subjects
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
/// Following SpiceDB best practices: least privilege, rotation support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: ApiKeyId,
    /// First 12 characters of the key (for identification in logs/UI)
    pub key_prefix: String,
    /// SHA-256 hash of the full key (never store plaintext!)
    pub key_hash: String,
    /// Human-readable name
    pub name: String,
    /// Description of the key's purpose
    pub description: Option<String>,
    /// Service account this key belongs to (optional)
    pub service_account_id: Option<ServiceAccountId>,
    /// User who created this key
    pub created_by: Option<UserId>,
    /// Tenant the key belongs to
    pub tenant_id: Option<TenantId>,
    /// Application this key belongs to (optional)
    pub application_id: Option<ApplicationId>,
    /// Permission scopes (least privilege)
    pub scopes: Vec<String>,
    /// Rate limit per minute
    pub rate_limit_per_minute: i32,
    /// Expiration time (optional)
    pub expires_at: Option<DateTime<Utc>>,
    /// Last time the key was used
    pub last_used_at: Option<DateTime<Utc>>,
    /// When the key was revoked (None = active)
    pub revoked_at: Option<DateTime<Utc>>,
    /// Who revoked the key
    pub revoked_by: Option<UserId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ApiKey {
    /// Check if the key is currently valid
    pub fn is_valid(&self) -> bool {
        // Not revoked
        if self.revoked_at.is_some() {
            return false;
        }
        // Not expired
        if let Some(expires_at) = self.expires_at {
            if expires_at < Utc::now() {
                return false;
            }
        }
        true
    }

    /// Check if the key has a specific scope
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(&scope.to_string()) || self.scopes.contains(&"*".to_string())
    }
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
    // Permission events
    PermissionCheck,
    RelationshipWrite,
    RelationshipDelete,
    
    // Authentication events (SECURITY)
    UserLogin,
    UserLoginFailed,
    UserLogout,
    TokenRefresh,
    TokenRevoked,
    PasswordChanged,
    PasswordResetRequested,
    
    // API key events (SECURITY)
    ApiKeyCreated,
    ApiKeyRevoked,
    ApiKeyUsed,
    ApiKeyRateLimited,
    
    // User lifecycle events
    UserCreated,
    UserUpdated,
    UserDeleted,
    UserSuspended,
    UserActivated,
    
    // Tenant events
    TenantCreated,
    TenantUpdated,
    TenantSuspended,
    
    // Application events
    ApplicationCreated,
    ApplicationUpdated,
    ApplicationDeleted,
    
    // Admin events (SECURITY)
    AdminAction,
    PrivilegeEscalation,
    SuspiciousActivity,
    
    // Sync events
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

/// Request to create a new API key
#[derive(Debug, Clone, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub description: Option<String>,
    pub service_account_id: Option<ServiceAccountId>,
    pub scopes: Vec<String>,
    pub expires_in_days: Option<i32>,
    pub rate_limit_per_minute: Option<i32>,
}

/// Response when creating an API key (includes the plaintext key ONCE)
#[derive(Debug, Clone, Serialize)]
pub struct CreateApiKeyResponse {
    pub id: ApiKeyId,
    /// The full API key - ONLY returned once at creation time!
    pub key: String,
    pub key_prefix: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
