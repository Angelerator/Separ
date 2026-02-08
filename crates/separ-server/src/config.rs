//! Server configuration

use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub server: ServerSettings,
    pub database: DatabaseSettings,
    pub spicedb: SpiceDbSettings,
    pub jwt: JwtSettings,
    #[serde(default)]
    pub encryption: EncryptionSettings,
    #[serde(default)]
    pub azure_sso: AzureSsoSettings,
}

#[derive(Debug, Deserialize)]
pub struct ServerSettings {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseSettings {
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

#[derive(Debug, Deserialize)]
pub struct SpiceDbSettings {
    pub endpoint: String,
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct JwtSettings {
    pub secret: String,
    pub issuer: String,
    #[serde(default = "default_access_token_expiry")]
    pub access_token_expiry_secs: i64,
    #[serde(default = "default_refresh_token_expiry")]
    pub refresh_token_expiry_secs: i64,
}

/// Azure SSO / Entra ID settings for federated authentication.
/// Multi-tenant: per-customer Azure tenant IDs are stored in the DB (identity_providers table).
/// Only the app registration's client ID is configured here (same for all customers).
/// No client_secret needed — we use PKCE (public client) and validate ID tokens via JWKS.
#[derive(Debug, Deserialize)]
pub struct AzureSsoSettings {
    /// Enable Azure SSO authentication
    #[serde(default)]
    pub enabled: bool,
    /// Multi-tenant App Registration client ID (same for all customers)
    #[serde(default)]
    pub app_client_id: String,
}

impl Default for AzureSsoSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            app_client_id: String::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct EncryptionSettings {
    /// 32-byte hex-encoded key for encrypting storage connection credentials
    /// Generate with: openssl rand -hex 32
    #[serde(default = "default_encryption_key")]
    pub key: String,
}

impl Default for EncryptionSettings {
    fn default() -> Self {
        Self {
            key: default_encryption_key(),
        }
    }
}

fn default_encryption_key() -> String {
    // Default key for development only - MUST be overridden in production
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_max_connections() -> u32 {
    10
}

fn default_access_token_expiry() -> i64 {
    3600
}

fn default_refresh_token_expiry() -> i64 {
    2592000
}

impl Settings {
    pub fn load() -> Result<Self> {
        let config = config::Config::builder()
            // Start with default values
            .set_default("server.host", "0.0.0.0")?
            .set_default("server.port", 8080)?
            .set_default("database.max_connections", 10)?
            .set_default("jwt.access_token_expiry_secs", 3600)?
            .set_default("jwt.refresh_token_expiry_secs", 2592000)?
            .set_default("encryption.key", default_encryption_key())?
            // Load from config file if present
            .add_source(config::File::with_name("config/default").required(false))
            .add_source(config::File::with_name("config/local").required(false))
            // Load from environment variables with SEPAR_ prefix
            .add_source(
                config::Environment::with_prefix("SEPAR")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()?;

        Ok(config.try_deserialize()?)
    }

    /// Get the encryption key as bytes
    pub fn encryption_key_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.encryption.key)
            .map_err(|e| anyhow::anyhow!("Invalid encryption key hex: {}", e))
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            server: ServerSettings {
                host: "0.0.0.0".to_string(),
                port: 8080,
            },
            database: DatabaseSettings {
                url: "postgres://separ:separ@localhost:5432/separ".to_string(),
                max_connections: 10,
            },
            spicedb: SpiceDbSettings {
                endpoint: "http://localhost:50051".to_string(),
                token: "separ-preshared-key".to_string(),
            },
            jwt: JwtSettings {
                secret: "change-this-secret-in-production".to_string(),
                issuer: "separ".to_string(),
                access_token_expiry_secs: 3600,
                refresh_token_expiry_secs: 2592000,
            },
            encryption: EncryptionSettings::default(),
            azure_sso: AzureSsoSettings::default(),
        }
    }
}
