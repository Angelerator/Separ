//! Proxy configuration

use serde::{Deserialize, Serialize};

/// Proxy server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Address to listen on
    pub listen_addr: String,

    /// Backend database address (Tavana/PostgreSQL)
    pub backend_addr: String,

    /// Separ API endpoint for authorization checks
    pub separ_endpoint: String,

    /// Separ API token
    pub separ_token: String,

    /// Authentication configuration
    pub auth: AuthConfig,

    /// Connection pool settings
    pub pool: PoolConfig,

    /// TLS configuration
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Supported authentication methods
    pub methods: Vec<AuthMethod>,

    /// JWT validation settings
    #[serde(default)]
    pub jwt: JwtConfig,

    /// API key settings
    #[serde(default)]
    pub api_key: ApiKeyConfig,

    /// Service token settings
    #[serde(default)]
    pub service_token: ServiceTokenConfig,

    /// Maximum authentication attempts before temporary ban
    #[serde(default = "default_max_auth_attempts")]
    pub max_auth_attempts: u32,

    /// Ban duration after max attempts
    #[serde(default = "default_ban_duration_secs")]
    pub ban_duration_secs: u64,
}

/// Supported authentication methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// JWT token (passed as password)
    Jwt,
    /// API key (format: key_prefix:key_secret)
    ApiKey,
    /// Service account token
    ServiceToken,
    /// mTLS client certificate
    MtlsCertificate,
    /// SCRAM-SHA-256 with Separ password verification
    ScramSha256,
    /// Trust mode (for testing only)
    Trust,
}

/// JWT authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// Expected audiences
    #[serde(default)]
    pub audiences: Vec<String>,

    /// Expected issuers
    #[serde(default)]
    pub issuers: Vec<String>,

    /// Clock skew tolerance in seconds
    #[serde(default = "default_clock_skew")]
    pub clock_skew_secs: u64,

    /// Cache validated tokens for this duration
    #[serde(default = "default_token_cache_secs")]
    pub token_cache_secs: u64,
}

/// API key authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// Enable API key authentication
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// API key prefix format (e.g., "sk_")
    #[serde(default = "default_api_key_prefix")]
    pub prefix: String,
}

/// Service token configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceTokenConfig {
    /// Enable service token authentication
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Service token prefix format
    #[serde(default = "default_service_token_prefix")]
    pub prefix: String,
}

/// Connection pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Maximum connections per user
    #[serde(default = "default_max_connections_per_user")]
    pub max_connections_per_user: u32,

    /// Maximum total connections
    #[serde(default = "default_max_total_connections")]
    pub max_total_connections: u32,

    /// Connection timeout in seconds
    #[serde(default = "default_connection_timeout_secs")]
    pub connection_timeout_secs: u64,

    /// Idle connection timeout in seconds
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Enable TLS
    pub enabled: bool,

    /// Path to certificate file
    pub cert_path: String,

    /// Path to private key file
    pub key_path: String,

    /// Path to CA certificate for mTLS
    #[serde(default)]
    pub ca_cert_path: Option<String>,

    /// Require client certificates (mTLS)
    #[serde(default)]
    pub require_client_cert: bool,
}

// Default value functions
fn default_max_auth_attempts() -> u32 {
    5
}
fn default_ban_duration_secs() -> u64 {
    300
}
fn default_clock_skew() -> u64 {
    60
}
fn default_token_cache_secs() -> u64 {
    300
}
fn default_true() -> bool {
    true
}
fn default_api_key_prefix() -> String {
    "sk_".to_string()
}
fn default_service_token_prefix() -> String {
    "svc_".to_string()
}
fn default_max_connections_per_user() -> u32 {
    10
}
fn default_max_total_connections() -> u32 {
    1000
}
fn default_connection_timeout_secs() -> u64 {
    30
}
fn default_idle_timeout_secs() -> u64 {
    600
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            methods: vec![AuthMethod::Jwt, AuthMethod::ApiKey],
            jwt: JwtConfig::default(),
            api_key: ApiKeyConfig::default(),
            service_token: ServiceTokenConfig::default(),
            max_auth_attempts: default_max_auth_attempts(),
            ban_duration_secs: default_ban_duration_secs(),
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            audiences: vec![],
            issuers: vec![],
            clock_skew_secs: default_clock_skew(),
            token_cache_secs: default_token_cache_secs(),
        }
    }
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prefix: default_api_key_prefix(),
        }
    }
}

impl Default for ServiceTokenConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prefix: default_service_token_prefix(),
        }
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_user: default_max_connections_per_user(),
            max_total_connections: default_max_total_connections(),
            connection_timeout_secs: default_connection_timeout_secs(),
            idle_timeout_secs: default_idle_timeout_secs(),
        }
    }
}
