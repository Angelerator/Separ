//! Common utilities and types for provider implementations

use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use separ_core::{Result, SeparError};

/// HTTP client wrapper with retry logic
#[derive(Clone)]
pub struct HttpClient {
    client: Client,
    max_retries: u32,
    retry_delay_ms: u64,
}

impl HttpClient {
    pub fn new(max_retries: u32, retry_delay_ms: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| SeparError::Internal { 
                message: format!("Failed to create HTTP client: {}", e) 
            })?;
        
        Ok(Self {
            client,
            max_retries,
            retry_delay_ms,
        })
    }

    pub fn inner(&self) -> &Client {
        &self.client
    }

    /// Execute a request with retries
    pub async fn execute_with_retry(
        &self,
        request_builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response> {
        let mut last_error = None;
        
        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let delay = self.retry_delay_ms * 2u64.pow(attempt - 1);
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }

            match request_builder.try_clone() {
                Some(rb) => {
                    match rb.send().await {
                        Ok(response) => {
                            if response.status().is_success() || response.status().is_redirection() {
                                return Ok(response);
                            }
                            
                            // Don't retry client errors (4xx) except 429
                            if response.status().is_client_error() && response.status().as_u16() != 429 {
                                let status = response.status();
                                let body = response.text().await.unwrap_or_default();
                                return Err(SeparError::Internal {
                                    message: format!("HTTP {} - {}", status, body),
                                });
                            }
                            
                            last_error = Some(format!("HTTP {}", response.status()));
                        }
                        Err(e) => {
                            last_error = Some(e.to_string());
                        }
                    }
                }
                None => {
                    return Err(SeparError::Internal {
                        message: "Request cannot be cloned for retry".to_string(),
                    });
                }
            }
        }

        Err(SeparError::Internal {
            message: format!(
                "Request failed after {} retries: {}",
                self.max_retries,
                last_error.unwrap_or_default()
            ),
        })
    }
}

/// Cache for JWKS keys
pub struct JwksCache {
    keys: RwLock<HashMap<String, CachedJwks>>,
    ttl_secs: u64,
}

struct CachedJwks {
    keys: JwkSet,
    fetched_at: DateTime<Utc>,
}

impl JwksCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            ttl_secs,
        }
    }

    pub async fn get_or_fetch(
        &self,
        jwks_uri: &str,
        client: &HttpClient,
    ) -> Result<JwkSet> {
        // Check cache first
        {
            let cache = self.keys.read().await;
            if let Some(cached) = cache.get(jwks_uri) {
                let age = (Utc::now() - cached.fetched_at).num_seconds() as u64;
                if age < self.ttl_secs {
                    return Ok(cached.keys.clone());
                }
            }
        }

        // Fetch fresh keys
        debug!("Fetching JWKS from {}", jwks_uri);
        let response = client
            .execute_with_retry(client.inner().get(jwks_uri))
            .await?;

        let jwks: JwkSet = response
            .json()
            .await
            .map_err(|e| SeparError::Internal {
                message: format!("Failed to parse JWKS: {}", e),
            })?;

        // Update cache
        {
            let mut cache = self.keys.write().await;
            cache.insert(
                jwks_uri.to_string(),
                CachedJwks {
                    keys: jwks.clone(),
                    fetched_at: Utc::now(),
                },
            );
        }

        Ok(jwks)
    }

    pub async fn invalidate(&self, jwks_uri: &str) {
        let mut cache = self.keys.write().await;
        cache.remove(jwks_uri);
    }
}

/// JSON Web Key Set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// JSON Web Key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
}

impl JwkSet {
    /// Find a key by kid
    pub fn find_key(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }

    /// Get a decoding key for the given kid
    pub fn get_decoding_key(&self, kid: &str) -> Result<DecodingKey> {
        let jwk = self.find_key(kid).ok_or_else(|| SeparError::AuthError {
            message: format!("Key with kid '{}' not found in JWKS", kid),
        })?;

        match jwk.kty.as_str() {
            "RSA" => {
                let n = jwk.n.as_ref().ok_or_else(|| SeparError::AuthError {
                    message: "RSA key missing 'n' parameter".to_string(),
                })?;
                let e = jwk.e.as_ref().ok_or_else(|| SeparError::AuthError {
                    message: "RSA key missing 'e' parameter".to_string(),
                })?;
                DecodingKey::from_rsa_components(n, e).map_err(|e| SeparError::AuthError {
                    message: format!("Invalid RSA key: {}", e),
                })
            }
            "EC" => {
                let x = jwk.x.as_ref().ok_or_else(|| SeparError::AuthError {
                    message: "EC key missing 'x' parameter".to_string(),
                })?;
                let y = jwk.y.as_ref().ok_or_else(|| SeparError::AuthError {
                    message: "EC key missing 'y' parameter".to_string(),
                })?;
                DecodingKey::from_ec_components(x, y).map_err(|e| SeparError::AuthError {
                    message: format!("Invalid EC key: {}", e),
                })
            }
            other => Err(SeparError::AuthError {
                message: format!("Unsupported key type: {}", other),
            }),
        }
    }
}

/// OIDC Discovery document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
}

impl OidcDiscovery {
    /// Fetch discovery document from well-known endpoint
    pub async fn fetch(issuer: &str, client: &HttpClient) -> Result<Self> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        
        debug!("Fetching OIDC discovery from {}", url);
        
        let response = client
            .execute_with_retry(client.inner().get(&url))
            .await?;

        response.json().await.map_err(|e| SeparError::Internal {
            message: format!("Failed to parse OIDC discovery: {}", e),
        })
    }
}

/// Token claims that are common across providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Issuer
    pub iss: String,
    /// Audience (can be string or array)
    #[serde(default)]
    pub aud: Audience,
    /// Expiration time
    pub exp: i64,
    /// Issued at
    #[serde(default)]
    pub iat: Option<i64>,
    /// Not before
    #[serde(default)]
    pub nbf: Option<i64>,
    /// Email
    #[serde(default)]
    pub email: Option<String>,
    /// Email verified
    #[serde(default)]
    pub email_verified: Option<bool>,
    /// Name
    #[serde(default)]
    pub name: Option<String>,
    /// Given name
    #[serde(default)]
    pub given_name: Option<String>,
    /// Family name
    #[serde(default)]
    pub family_name: Option<String>,
    /// Picture URL
    #[serde(default)]
    pub picture: Option<String>,
    /// Preferred username
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// Groups (provider-specific claim name)
    #[serde(default)]
    pub groups: Option<Vec<String>>,
    /// Roles (provider-specific claim name)
    #[serde(default)]
    pub roles: Option<Vec<String>>,
    /// Scopes
    #[serde(default)]
    pub scope: Option<String>,
    /// Azure-specific: oid (object ID)
    #[serde(default)]
    pub oid: Option<String>,
    /// Azure-specific: tid (tenant ID)
    #[serde(default)]
    pub tid: Option<String>,
    /// Azure-specific: upn (user principal name)
    #[serde(default)]
    pub upn: Option<String>,
}

/// Audience can be a string or array
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Default for Audience {
    fn default() -> Self {
        Self::Multiple(vec![])
    }
}

impl Audience {
    pub fn contains(&self, aud: &str) -> bool {
        match self {
            Self::Single(s) => s == aud,
            Self::Multiple(v) => v.iter().any(|a| a == aud),
        }
    }

    pub fn as_vec(&self) -> Vec<String> {
        match self {
            Self::Single(s) => vec![s.clone()],
            Self::Multiple(v) => v.clone(),
        }
    }
}

/// Validate a JWT token
pub fn validate_jwt<T: for<'de> Deserialize<'de>>(
    token: &str,
    decoding_key: &DecodingKey,
    validation: &Validation,
) -> Result<T> {
    let token_data = decode::<T>(token, decoding_key, validation).map_err(|e| {
        SeparError::AuthError {
            message: format!("Token validation failed: {}", e),
        }
    })?;
    Ok(token_data.claims)
}

/// Extract kid from JWT header
pub fn extract_jwt_kid(token: &str) -> Result<String> {
    let header = decode_header(token).map_err(|e| SeparError::AuthError {
        message: format!("Failed to decode JWT header: {}", e),
    })?;
    
    header.kid.ok_or_else(|| SeparError::AuthError {
        message: "JWT header missing 'kid' claim".to_string(),
    })
}

/// Get algorithm from string
pub fn algorithm_from_str(alg: &str) -> Result<Algorithm> {
    match alg {
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "PS256" => Ok(Algorithm::PS256),
        "PS384" => Ok(Algorithm::PS384),
        "PS512" => Ok(Algorithm::PS512),
        other => Err(SeparError::AuthError {
            message: format!("Unsupported algorithm: {}", other),
        }),
    }
}

/// Pagination helper for API requests
#[derive(Debug, Clone)]
pub struct PaginatedRequest {
    pub page_size: u32,
    pub page_token: Option<String>,
}

impl Default for PaginatedRequest {
    fn default() -> Self {
        Self {
            page_size: 100,
            page_token: None,
        }
    }
}

/// Pagination response
#[derive(Debug, Clone)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub next_page_token: Option<String>,
    pub has_more: bool,
}

/// Helper to collect all pages
pub async fn collect_all_pages<T, F, Fut>(
    fetch_page: F,
    page_size: u32,
) -> Result<Vec<T>>
where
    F: Fn(PaginatedRequest) -> Fut,
    Fut: std::future::Future<Output = Result<PaginatedResponse<T>>>,
{
    let mut all_items = Vec::new();
    let mut page_token = None;

    loop {
        let request = PaginatedRequest {
            page_size,
            page_token: page_token.clone(),
        };

        let response = fetch_page(request).await?;
        all_items.extend(response.items);

        if !response.has_more {
            break;
        }

        page_token = response.next_page_token;
        if page_token.is_none() {
            break;
        }
    }

    Ok(all_items)
}

