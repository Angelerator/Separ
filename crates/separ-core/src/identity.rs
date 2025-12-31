//! Identity Provider abstractions for multi-provider identity sync
//!
//! This module provides a flexible, pluggable architecture for integrating
//! with various identity providers (Azure AD, Okta, Google, etc.)

use crate::{
    error::Result,
    ids::{GroupId, IdentityProviderId, TenantId, UserId},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Provider Types and Configuration
// =============================================================================

/// Supported identity provider types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderType {
    /// Microsoft Azure Active Directory / Entra ID
    AzureAd,
    /// Okta Identity Platform
    Okta,
    /// Google Workspace / Cloud Identity
    Google,
    /// AWS IAM Identity Center (SSO)
    AwsSso,
    /// Keycloak Identity Server
    Keycloak,
    /// Auth0 Identity Platform
    Auth0,
    /// OneLogin
    OneLogin,
    /// Ping Identity
    PingIdentity,
    /// Generic OIDC Provider
    GenericOidc,
    /// Generic SAML Provider
    GenericSaml,
    /// LDAP / Active Directory
    Ldap,
    /// Direct (Separ-managed identities)
    Direct,
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AzureAd => write!(f, "azure_ad"),
            Self::Okta => write!(f, "okta"),
            Self::Google => write!(f, "google"),
            Self::AwsSso => write!(f, "aws_sso"),
            Self::Keycloak => write!(f, "keycloak"),
            Self::Auth0 => write!(f, "auth0"),
            Self::OneLogin => write!(f, "onelogin"),
            Self::PingIdentity => write!(f, "ping_identity"),
            Self::GenericOidc => write!(f, "generic_oidc"),
            Self::GenericSaml => write!(f, "generic_saml"),
            Self::Ldap => write!(f, "ldap"),
            Self::Direct => write!(f, "direct"),
        }
    }
}

/// Identity provider configuration stored in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProviderConfig {
    pub id: IdentityProviderId,
    pub tenant_id: TenantId,
    pub provider_type: ProviderType,
    pub name: String,
    pub display_name: Option<String>,
    
    /// Provider-specific configuration (encrypted at rest)
    pub config: ProviderConfigDetails,
    
    /// Feature flags
    pub features: ProviderFeatures,
    
    /// Sync settings
    pub sync_settings: SyncSettings,
    
    /// Domain associations (for automatic provider detection)
    pub domains: Vec<String>,
    
    /// Priority for provider selection (lower = higher priority)
    pub priority: i32,
    
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Provider feature flags
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderFeatures {
    /// Enable user sync from this provider
    pub sync_users: bool,
    /// Enable group sync from this provider
    pub sync_groups: bool,
    /// Enable application/service principal sync
    pub sync_apps: bool,
    /// Enable authentication via this provider
    pub authentication: bool,
    /// Enable JIT (Just-In-Time) provisioning
    pub jit_provisioning: bool,
    /// Enable nested group resolution
    pub resolve_nested_groups: bool,
}

/// Sync timing settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncSettings {
    /// How often to sync (in seconds), None for push-only
    pub interval_secs: Option<u32>,
    /// Maximum batch size for sync operations
    pub batch_size: u32,
    /// Timeout for sync operations (in seconds)
    pub timeout_secs: u32,
    /// Number of retry attempts
    pub max_retries: u32,
    /// Whether to perform full sync or incremental only
    pub full_sync_enabled: bool,
    /// How often to do full sync (in hours), only if incremental
    pub full_sync_interval_hours: Option<u32>,
}

impl Default for SyncSettings {
    fn default() -> Self {
        Self {
            interval_secs: Some(300), // 5 minutes
            batch_size: 100,
            timeout_secs: 300,
            max_retries: 3,
            full_sync_enabled: true,
            full_sync_interval_hours: Some(24),
        }
    }
}

/// Provider-specific configuration details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProviderConfigDetails {
    AzureAd(AzureAdConfig),
    Okta(OktaConfig),
    Google(GoogleConfig),
    AwsSso(AwsSsoConfig),
    Keycloak(KeycloakConfig),
    Auth0(Auth0Config),
    GenericOidc(OidcConfig),
    GenericSaml(SamlConfig),
    Ldap(LdapConfig),
    Direct(DirectConfig),
}

/// Azure AD / Entra ID configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureAdConfig {
    /// Azure AD Tenant ID
    pub tenant_id: String,
    /// Application (client) ID
    pub client_id: String,
    /// Client secret (encrypted)
    #[serde(skip_serializing)]
    pub client_secret: String,
    /// Optional: Use certificate auth instead of secret
    pub certificate_thumbprint: Option<String>,
    /// Scopes for Graph API access
    pub graph_scopes: Vec<String>,
    /// Filter for user sync (OData filter)
    pub user_filter: Option<String>,
    /// Filter for group sync
    pub group_filter: Option<String>,
    /// Whether to sync service principals
    pub sync_service_principals: bool,
    /// Whether to sync managed identities
    pub sync_managed_identities: bool,
}

impl Default for AzureAdConfig {
    fn default() -> Self {
        Self {
            tenant_id: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            certificate_thumbprint: None,
            graph_scopes: vec![
                "https://graph.microsoft.com/.default".to_string(),
            ],
            user_filter: None,
            group_filter: None,
            sync_service_principals: true,
            sync_managed_identities: false,
        }
    }
}

/// Okta configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaConfig {
    /// Okta domain (e.g., "company.okta.com")
    pub domain: String,
    /// API token for management API
    #[serde(skip_serializing)]
    pub api_token: String,
    /// Client ID for OIDC
    pub client_id: String,
    /// Client secret for OIDC
    #[serde(skip_serializing)]
    pub client_secret: String,
    /// Filter for user sync
    pub user_filter: Option<String>,
    /// Filter for group sync
    pub group_filter: Option<String>,
    /// SCIM endpoint (if using SCIM)
    pub scim_endpoint: Option<String>,
}

/// Google Workspace configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleConfig {
    /// Google Cloud project ID
    pub project_id: String,
    /// OAuth client ID
    pub client_id: String,
    /// OAuth client secret
    #[serde(skip_serializing)]
    pub client_secret: String,
    /// Service account email for admin SDK
    pub service_account_email: Option<String>,
    /// Service account key (JSON)
    #[serde(skip_serializing)]
    pub service_account_key: Option<String>,
    /// Admin email for domain-wide delegation
    pub admin_email: Option<String>,
    /// Customer ID for directory API
    pub customer_id: Option<String>,
}

/// AWS SSO / IAM Identity Center configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsSsoConfig {
    /// AWS Region
    pub region: String,
    /// Identity Store ID
    pub identity_store_id: String,
    /// SSO Instance ARN
    pub sso_instance_arn: Option<String>,
    /// Access method
    pub access_method: AwsAccessMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsAccessMethod {
    /// Use IAM role credentials
    IamRole { role_arn: String },
    /// Use access key
    AccessKey {
        access_key_id: String,
        #[serde(skip_serializing)]
        secret_access_key: String,
    },
    /// Use environment/instance profile
    Default,
}

/// Keycloak configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeycloakConfig {
    /// Keycloak server URL
    pub server_url: String,
    /// Realm name
    pub realm: String,
    /// Client ID
    pub client_id: String,
    /// Client secret
    #[serde(skip_serializing)]
    pub client_secret: String,
    /// Admin username (for sync)
    pub admin_username: Option<String>,
    /// Admin password
    #[serde(skip_serializing)]
    pub admin_password: Option<String>,
}

/// Auth0 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth0Config {
    /// Auth0 domain (e.g., "tenant.auth0.com")
    pub domain: String,
    /// Client ID
    pub client_id: String,
    /// Client secret
    #[serde(skip_serializing)]
    pub client_secret: String,
    /// Management API audience
    pub management_audience: String,
}

/// Generic OIDC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// Issuer URL (used for discovery)
    pub issuer_url: String,
    /// Client ID
    pub client_id: String,
    /// Client secret
    #[serde(skip_serializing)]
    pub client_secret: String,
    /// Authorization endpoint (override discovery)
    pub authorization_endpoint: Option<String>,
    /// Token endpoint (override discovery)
    pub token_endpoint: Option<String>,
    /// UserInfo endpoint (override discovery)
    pub userinfo_endpoint: Option<String>,
    /// JWKS URI (override discovery)
    pub jwks_uri: Option<String>,
    /// Scopes to request
    pub scopes: Vec<String>,
    /// Claim mappings
    pub claim_mappings: ClaimMappings,
}

/// SAML configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfig {
    /// IdP Entity ID
    pub idp_entity_id: String,
    /// IdP SSO URL
    pub idp_sso_url: String,
    /// IdP SLO URL (optional)
    pub idp_slo_url: Option<String>,
    /// IdP Certificate (PEM format)
    pub idp_certificate: String,
    /// SP Entity ID
    pub sp_entity_id: String,
    /// SP Assertion Consumer Service URL
    pub sp_acs_url: String,
    /// Attribute mappings
    pub attribute_mappings: AttributeMappings,
    /// Whether to sign requests
    pub sign_requests: bool,
    /// Whether to want assertions signed
    pub want_assertions_signed: bool,
}

/// LDAP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    /// LDAP server URL (e.g., "ldaps://ldap.company.com:636")
    pub server_url: String,
    /// Bind DN
    pub bind_dn: String,
    /// Bind password
    #[serde(skip_serializing)]
    pub bind_password: String,
    /// Base DN for user search
    pub user_base_dn: String,
    /// User search filter
    pub user_filter: String,
    /// Base DN for group search
    pub group_base_dn: Option<String>,
    /// Group search filter
    pub group_filter: Option<String>,
    /// Attribute mappings
    pub attribute_mappings: LdapAttributeMappings,
    /// Use StartTLS
    pub start_tls: bool,
    /// Skip TLS verification (not recommended)
    pub skip_tls_verify: bool,
}

/// Direct provider configuration (Separ-managed)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DirectConfig {
    /// Allow password authentication
    pub allow_password_auth: bool,
    /// Password requirements
    pub password_policy: PasswordPolicy,
    /// Allow API key authentication
    pub allow_api_keys: bool,
    /// Allow mTLS authentication
    pub allow_mtls: bool,
}

/// Password policy for direct authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_length: u8,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_numbers: bool,
    pub require_special: bool,
    pub max_age_days: Option<u32>,
    pub history_count: u8,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special: true,
            max_age_days: Some(90),
            history_count: 5,
        }
    }
}

/// Claim mappings for OIDC providers
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClaimMappings {
    /// Claim for unique user ID
    pub subject_claim: Option<String>,
    /// Claim for email
    pub email_claim: Option<String>,
    /// Claim for display name
    pub name_claim: Option<String>,
    /// Claim for given name
    pub given_name_claim: Option<String>,
    /// Claim for family name
    pub family_name_claim: Option<String>,
    /// Claim for groups
    pub groups_claim: Option<String>,
    /// Claim for roles
    pub roles_claim: Option<String>,
    /// Additional custom mappings
    pub custom: HashMap<String, String>,
}

/// Attribute mappings for SAML
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributeMappings {
    pub subject_attribute: Option<String>,
    pub email_attribute: Option<String>,
    pub name_attribute: Option<String>,
    pub groups_attribute: Option<String>,
    pub custom: HashMap<String, String>,
}

/// LDAP attribute mappings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapAttributeMappings {
    pub username: String,
    pub email: String,
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub member_of: Option<String>,
    pub group_name: Option<String>,
    pub group_member: Option<String>,
}

impl Default for LdapAttributeMappings {
    fn default() -> Self {
        Self {
            username: "sAMAccountName".to_string(),
            email: "mail".to_string(),
            display_name: Some("displayName".to_string()),
            given_name: Some("givenName".to_string()),
            family_name: Some("sn".to_string()),
            member_of: Some("memberOf".to_string()),
            group_name: Some("cn".to_string()),
            group_member: Some("member".to_string()),
        }
    }
}

// =============================================================================
// Synced Entity Types
// =============================================================================

/// A user synced from an external provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncedUser {
    /// External ID from the provider
    pub external_id: String,
    /// Email address
    pub email: String,
    /// Display name
    pub display_name: String,
    /// Given name / first name
    pub given_name: Option<String>,
    /// Family name / last name
    pub family_name: Option<String>,
    /// Profile picture URL
    pub picture_url: Option<String>,
    /// Whether the account is active
    pub active: bool,
    /// Email verified status
    pub email_verified: bool,
    /// Group memberships (external IDs)
    pub groups: Vec<String>,
    /// Role assignments from provider
    pub roles: Vec<String>,
    /// Additional attributes
    pub attributes: HashMap<String, serde_json::Value>,
    /// Last synced timestamp
    pub synced_at: DateTime<Utc>,
}

/// A group synced from an external provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncedGroup {
    /// External ID from the provider
    pub external_id: String,
    /// Group name
    pub name: String,
    /// Group description
    pub description: Option<String>,
    /// Group type/kind
    pub group_type: Option<String>,
    /// Member external IDs (users)
    pub members: Vec<String>,
    /// Parent group external IDs
    pub parent_groups: Vec<String>,
    /// Child group external IDs
    pub child_groups: Vec<String>,
    /// Additional attributes
    pub attributes: HashMap<String, serde_json::Value>,
    /// Last synced timestamp
    pub synced_at: DateTime<Utc>,
}

/// A service/application synced from an external provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncedApp {
    /// External ID from the provider
    pub external_id: String,
    /// Application/service name
    pub name: String,
    /// Application/service type
    pub app_type: SyncedAppType,
    /// Description
    pub description: Option<String>,
    /// Whether the app/service is enabled
    pub enabled: bool,
    /// Assigned permissions/roles
    pub assigned_permissions: Vec<String>,
    /// Additional attributes
    pub attributes: HashMap<String, serde_json::Value>,
    /// Last synced timestamp
    pub synced_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncedAppType {
    /// OAuth/OIDC application
    Application,
    /// Service principal / service account
    ServicePrincipal,
    /// Managed identity (e.g., Azure Managed Identity)
    ManagedIdentity,
    /// Machine-to-machine client
    M2MClient,
    /// Other
    Other,
}

// =============================================================================
// Authentication Types
// =============================================================================

/// Claims extracted from an authenticated token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedPrincipal {
    /// Principal type (user, service, etc.)
    pub principal_type: PrincipalType,
    /// Subject ID (from provider)
    pub subject: String,
    /// Separ user/service ID (if mapped)
    pub separ_id: Option<String>,
    /// Tenant ID this principal belongs to
    pub tenant_id: TenantId,
    /// Provider that authenticated this principal
    pub provider_id: IdentityProviderId,
    /// Provider type
    pub provider_type: ProviderType,
    /// Email (if available)
    pub email: Option<String>,
    /// Display name
    pub display_name: Option<String>,
    /// Group memberships
    pub groups: Vec<String>,
    /// Roles from provider
    pub roles: Vec<String>,
    /// Scopes/permissions from token
    pub scopes: Vec<String>,
    /// Token issued at
    pub issued_at: DateTime<Utc>,
    /// Token expires at
    pub expires_at: DateTime<Utc>,
    /// Original claims (for debugging/audit)
    pub raw_claims: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalType {
    User,
    Service,
    Application,
    ManagedIdentity,
}

/// Token validation options
#[derive(Debug, Clone, Default)]
pub struct ValidationOptions {
    /// Expected audience(s)
    pub audiences: Vec<String>,
    /// Expected issuer(s)
    pub issuers: Vec<String>,
    /// Clock skew tolerance in seconds
    pub clock_skew_secs: u64,
    /// Whether to validate expiration
    pub validate_exp: bool,
    /// Whether to validate not-before
    pub validate_nbf: bool,
}

// =============================================================================
// Provider Traits
// =============================================================================

/// Core trait for identity providers that support syncing
#[async_trait]
pub trait IdentitySync: Send + Sync {
    /// Get the provider type
    fn provider_type(&self) -> ProviderType;
    
    /// Get the provider configuration ID
    fn provider_id(&self) -> IdentityProviderId;
    
    /// Sync all users from the provider
    async fn sync_users(&self) -> Result<Vec<SyncedUser>>;
    
    /// Sync users incrementally (since last sync)
    async fn sync_users_incremental(&self, since: DateTime<Utc>) -> Result<Vec<SyncedUser>>;
    
    /// Sync all groups from the provider
    async fn sync_groups(&self) -> Result<Vec<SyncedGroup>>;
    
    /// Sync groups incrementally
    async fn sync_groups_incremental(&self, since: DateTime<Utc>) -> Result<Vec<SyncedGroup>>;
    
    /// Get a specific user by external ID
    async fn get_user(&self, external_id: &str) -> Result<Option<SyncedUser>>;
    
    /// Get a specific group by external ID
    async fn get_group(&self, external_id: &str) -> Result<Option<SyncedGroup>>;
    
    /// Resolve group memberships for a user
    async fn get_user_groups(&self, user_external_id: &str) -> Result<Vec<SyncedGroup>>;
    
    /// Test connectivity to the provider
    async fn test_connection(&self) -> Result<bool>;
}

/// Optional trait for providers that support app/service sync
#[async_trait]
pub trait IdentitySyncApps: IdentitySync {
    /// Sync applications/service principals
    async fn sync_apps(&self) -> Result<Vec<SyncedApp>>;
    
    /// Get a specific app by external ID
    async fn get_app(&self, external_id: &str) -> Result<Option<SyncedApp>>;
}

/// Trait for providers that support authentication
#[async_trait]
pub trait IdentityAuth: Send + Sync {
    /// Get the provider type
    fn provider_type(&self) -> ProviderType;
    
    /// Get the provider configuration ID
    fn provider_id(&self) -> IdentityProviderId;
    
    /// Validate an authentication token
    async fn validate_token(
        &self,
        token: &str,
        options: &ValidationOptions,
    ) -> Result<AuthenticatedPrincipal>;
    
    /// Get authorization URL for OAuth/OIDC flow
    async fn get_authorization_url(
        &self,
        state: &str,
        nonce: Option<&str>,
        redirect_uri: &str,
    ) -> Result<String>;
    
    /// Exchange authorization code for tokens
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<TokenExchangeResult>;
    
    /// Refresh an access token
    async fn refresh_token(&self, refresh_token: &str) -> Result<TokenExchangeResult>;
}

/// Result of token exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExchangeResult {
    /// Access token
    pub access_token: String,
    /// Token type (usually "Bearer")
    pub token_type: String,
    /// Expires in seconds
    pub expires_in: Option<u64>,
    /// Refresh token (if provided)
    pub refresh_token: Option<String>,
    /// ID token (for OIDC)
    pub id_token: Option<String>,
    /// Scopes granted
    pub scopes: Vec<String>,
    /// Authenticated principal from the ID token
    pub principal: Option<AuthenticatedPrincipal>,
}

/// Combined trait for full-featured identity providers
pub trait IdentityProvider: IdentitySync + IdentityAuth {}

// Blanket implementation
impl<T> IdentityProvider for T where T: IdentitySync + IdentityAuth {}

// =============================================================================
// Sync Results
// =============================================================================

/// Result of a sync operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    /// Provider ID
    pub provider_id: IdentityProviderId,
    /// Provider type
    pub provider_type: ProviderType,
    /// Status of the sync
    pub status: SyncResultStatus,
    /// Number of users synced
    pub users_created: u32,
    pub users_updated: u32,
    pub users_deleted: u32,
    /// Number of groups synced
    pub groups_created: u32,
    pub groups_updated: u32,
    pub groups_deleted: u32,
    /// Number of apps synced
    pub apps_created: u32,
    pub apps_updated: u32,
    pub apps_deleted: u32,
    /// Errors encountered
    pub errors: Vec<SyncError>,
    /// Start time
    pub started_at: DateTime<Utc>,
    /// End time
    pub completed_at: DateTime<Utc>,
    /// Duration in milliseconds
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncResultStatus {
    Success,
    PartialSuccess,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncError {
    pub entity_type: String,
    pub external_id: Option<String>,
    pub error_type: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

// =============================================================================
// Repository Traits
// =============================================================================

/// Repository for managing identity provider configurations
#[async_trait]
pub trait IdentityProviderRepository: Send + Sync {
    /// Create a new provider configuration
    async fn create(&self, config: &IdentityProviderConfig) -> Result<IdentityProviderConfig>;
    
    /// Get provider by ID
    async fn get_by_id(&self, id: IdentityProviderId) -> Result<Option<IdentityProviderConfig>>;
    
    /// List all providers for a tenant
    async fn list_by_tenant(&self, tenant_id: TenantId) -> Result<Vec<IdentityProviderConfig>>;
    
    /// List enabled providers for a tenant
    async fn list_enabled_by_tenant(&self, tenant_id: TenantId) -> Result<Vec<IdentityProviderConfig>>;
    
    /// Find provider by domain
    async fn find_by_domain(&self, domain: &str) -> Result<Option<IdentityProviderConfig>>;
    
    /// Update provider configuration
    async fn update(&self, config: &IdentityProviderConfig) -> Result<IdentityProviderConfig>;
    
    /// Delete provider configuration
    async fn delete(&self, id: IdentityProviderId) -> Result<()>;
}

/// Repository for mapping external identities to Separ IDs
#[async_trait]
pub trait IdentityMappingRepository: Send + Sync {
    /// Create or update a user mapping
    async fn upsert_user_mapping(
        &self,
        tenant_id: TenantId,
        provider_id: IdentityProviderId,
        external_id: &str,
        separ_user_id: UserId,
    ) -> Result<()>;
    
    /// Get Separ user ID by external ID
    async fn get_user_by_external_id(
        &self,
        tenant_id: TenantId,
        provider_id: IdentityProviderId,
        external_id: &str,
    ) -> Result<Option<UserId>>;
    
    /// Get external ID by Separ user ID
    async fn get_external_id_by_user(
        &self,
        tenant_id: TenantId,
        provider_id: IdentityProviderId,
        separ_user_id: UserId,
    ) -> Result<Option<String>>;
    
    /// Create or update a group mapping
    async fn upsert_group_mapping(
        &self,
        tenant_id: TenantId,
        provider_id: IdentityProviderId,
        external_id: &str,
        separ_group_id: GroupId,
    ) -> Result<()>;
    
    /// Get Separ group ID by external ID
    async fn get_group_by_external_id(
        &self,
        tenant_id: TenantId,
        provider_id: IdentityProviderId,
        external_id: &str,
    ) -> Result<Option<GroupId>>;
    
    /// Delete all mappings for a provider
    async fn delete_by_provider(&self, provider_id: IdentityProviderId) -> Result<()>;
}

