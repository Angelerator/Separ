//! Authentication handlers for the proxy
//!
//! Supports multiple authentication methods:
//! - JWT tokens (from any configured identity provider)
//! - API keys
//! - Service account tokens
//! - mTLS certificates

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, instrument, warn};

use separ_core::{identity::*, TenantId, UserId};
use separ_identity::ProviderRegistry;

use crate::config::{AuthConfig, AuthMethod};

/// Authenticated principal with connection metadata
#[derive(Debug, Clone)]
pub struct ProxyPrincipal {
    /// Separ user/service ID
    pub separ_id: Option<UserId>,
    /// Principal type
    pub principal_type: ProxyPrincipalType,
    /// Tenant ID
    pub tenant_id: TenantId,
    /// Display identifier (email, service name, etc.)
    pub identifier: String,
    /// Granted scopes/permissions
    pub scopes: Vec<String>,
    /// Metadata from authentication
    pub metadata: HashMap<String, String>,
    /// When authentication was performed
    pub authenticated_at: DateTime<Utc>,
    /// When authentication expires (if applicable)
    pub expires_at: Option<DateTime<Utc>>,
}

/// Type of authenticated principal
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyPrincipalType {
    User,
    Service,
    ApiKey,
    System,
}

/// Authentication result
#[derive(Debug)]
pub enum AuthResult {
    /// Authentication successful
    Success(ProxyPrincipal),
    /// Authentication failed with reason
    Failed(AuthFailure),
    /// Try next authentication method
    NotApplicable,
}

/// Authentication failure details
#[derive(Debug)]
pub struct AuthFailure {
    pub code: String,
    pub message: String,
    pub should_retry: bool,
}

/// Authentication service that supports multiple providers
pub struct ProxyAuthenticator {
    config: AuthConfig,
    provider_registry: Arc<ProviderRegistry>,
    token_cache: DashMap<String, CachedAuth>,
    failed_attempts: DashMap<String, FailedAttempts>,
}

#[allow(dead_code)]
struct CachedAuth {
    principal: ProxyPrincipal,
    cached_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[allow(dead_code)]
struct FailedAttempts {
    count: u32,
    first_attempt: DateTime<Utc>,
    last_attempt: DateTime<Utc>,
    banned_until: Option<DateTime<Utc>>,
}

impl ProxyAuthenticator {
    /// Create a new authenticator
    pub fn new(config: AuthConfig, provider_registry: Arc<ProviderRegistry>) -> Self {
        Self {
            config,
            provider_registry,
            token_cache: DashMap::new(),
            failed_attempts: DashMap::new(),
        }
    }

    /// Authenticate using username and password
    ///
    /// The password field may contain:
    /// - A JWT token
    /// - An API key (format: sk_xxx)
    /// - A service token (format: svc_xxx)
    #[instrument(skip(self, password))]
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
        tenant_hint: Option<&str>,
    ) -> AuthResult {
        // Check if IP/user is banned
        if let Some(ban_check) = self.check_ban(username) {
            return ban_check;
        }

        // Check token cache first
        if let Some(cached) = self.check_cache(password) {
            return AuthResult::Success(cached);
        }

        // Try each enabled authentication method in order
        for method in &self.config.methods {
            let result = match method {
                AuthMethod::Jwt => self.auth_jwt(username, password, tenant_hint).await,
                AuthMethod::ApiKey => self.auth_api_key(username, password).await,
                AuthMethod::ServiceToken => self.auth_service_token(username, password).await,
                AuthMethod::ScramSha256 => AuthResult::NotApplicable, // Handled separately
                AuthMethod::MtlsCertificate => AuthResult::NotApplicable, // Handled in TLS layer
                AuthMethod::Trust => self.auth_trust(username, tenant_hint),
            };

            match result {
                AuthResult::Success(principal) => {
                    // Cache successful auth
                    self.cache_auth(password, &principal);
                    // Clear failed attempts
                    self.failed_attempts.remove(username);
                    return AuthResult::Success(principal);
                }
                AuthResult::Failed(failure) => {
                    // Record failed attempt
                    self.record_failure(username);
                    return AuthResult::Failed(failure);
                }
                AuthResult::NotApplicable => {
                    // Try next method
                    continue;
                }
            }
        }

        // No method matched
        self.record_failure(username);
        AuthResult::Failed(AuthFailure {
            code: "AUTH_METHOD_NOT_FOUND".to_string(),
            message: "No authentication method matched the provided credentials".to_string(),
            should_retry: false,
        })
    }

    /// Authenticate with JWT token
    async fn auth_jwt(&self, username: &str, token: &str, tenant_hint: Option<&str>) -> AuthResult {
        // Check if it looks like a JWT
        if !token.contains('.') || token.split('.').count() != 3 {
            return AuthResult::NotApplicable;
        }

        debug!("Attempting JWT authentication for user: {}", username);

        // Resolve tenant
        let tenant_id = match self.resolve_tenant(tenant_hint, username) {
            Some(id) => id,
            None => {
                return AuthResult::Failed(AuthFailure {
                    code: "TENANT_NOT_FOUND".to_string(),
                    message: "Could not determine tenant from credentials".to_string(),
                    should_retry: false,
                });
            }
        };

        // Try to authenticate with provider registry
        match self
            .provider_registry
            .authenticate_token(tenant_id, token)
            .await
        {
            Ok(principal) => {
                // Verify username matches if provided
                if !username.is_empty() && username != "jwt" {
                    let matches = principal
                        .email
                        .as_ref()
                        .map(|e| e == username || e.split('@').next() == Some(username))
                        .unwrap_or(false)
                        || principal.subject == username;

                    if !matches {
                        warn!(
                            "JWT subject {} doesn't match username {}",
                            principal.subject, username
                        );
                        return AuthResult::Failed(AuthFailure {
                            code: "USERNAME_MISMATCH".to_string(),
                            message: "Token subject doesn't match provided username".to_string(),
                            should_retry: false,
                        });
                    }
                }

                AuthResult::Success(ProxyPrincipal {
                    separ_id: principal.separ_id.map(|_| UserId::new()),
                    principal_type: match principal.principal_type {
                        PrincipalType::User => ProxyPrincipalType::User,
                        PrincipalType::Service
                        | PrincipalType::Application
                        | PrincipalType::ManagedIdentity => ProxyPrincipalType::Service,
                    },
                    tenant_id,
                    identifier: principal.email.unwrap_or(principal.subject),
                    scopes: principal.scopes,
                    metadata: principal
                        .raw_claims
                        .into_iter()
                        .map(|(k, v)| (k, v.to_string()))
                        .collect(),
                    authenticated_at: Utc::now(),
                    expires_at: Some(principal.expires_at),
                })
            }
            Err(e) => {
                warn!("JWT authentication failed: {}", e);
                AuthResult::Failed(AuthFailure {
                    code: "JWT_INVALID".to_string(),
                    message: format!("Token validation failed: {}", e),
                    should_retry: false,
                })
            }
        }
    }

    /// Authenticate with API key
    async fn auth_api_key(&self, username: &str, password: &str) -> AuthResult {
        if !self.config.api_key.enabled {
            return AuthResult::NotApplicable;
        }

        // Check if password looks like an API key
        if !password.starts_with(&self.config.api_key.prefix) {
            return AuthResult::NotApplicable;
        }

        debug!("Attempting API key authentication for user: {}", username);

        // TODO: Validate API key against Separ API
        // For now, return not implemented
        AuthResult::Failed(AuthFailure {
            code: "NOT_IMPLEMENTED".to_string(),
            message: "API key authentication not yet implemented".to_string(),
            should_retry: false,
        })
    }

    /// Authenticate with service token
    async fn auth_service_token(&self, username: &str, password: &str) -> AuthResult {
        if !self.config.service_token.enabled {
            return AuthResult::NotApplicable;
        }

        // Check if password looks like a service token
        if !password.starts_with(&self.config.service_token.prefix) {
            return AuthResult::NotApplicable;
        }

        debug!(
            "Attempting service token authentication for user: {}",
            username
        );

        // TODO: Validate service token against Separ API
        // For now, return not implemented
        AuthResult::Failed(AuthFailure {
            code: "NOT_IMPLEMENTED".to_string(),
            message: "Service token authentication not yet implemented".to_string(),
            should_retry: false,
        })
    }

    /// Trust mode authentication (for testing only)
    fn auth_trust(&self, username: &str, tenant_hint: Option<&str>) -> AuthResult {
        warn!("Using TRUST authentication mode - this should not be used in production!");

        let tenant_id = self
            .resolve_tenant(tenant_hint, username)
            .unwrap_or_default();

        AuthResult::Success(ProxyPrincipal {
            separ_id: None,
            principal_type: ProxyPrincipalType::User,
            tenant_id,
            identifier: username.to_string(),
            scopes: vec!["*".to_string()],
            metadata: HashMap::new(),
            authenticated_at: Utc::now(),
            expires_at: None,
        })
    }

    /// Resolve tenant ID from hints
    fn resolve_tenant(&self, tenant_hint: Option<&str>, username: &str) -> Option<TenantId> {
        // For now, just create a new tenant ID if we have a hint
        // In a real implementation, we would look up the tenant by slug/name
        if tenant_hint.is_some() || !username.is_empty() {
            Some(TenantId::new())
        } else {
            None
        }
    }

    /// Check if user is temporarily banned
    fn check_ban(&self, identifier: &str) -> Option<AuthResult> {
        if let Some(attempts) = self.failed_attempts.get(identifier) {
            if let Some(banned_until) = attempts.banned_until {
                if Utc::now() < banned_until {
                    return Some(AuthResult::Failed(AuthFailure {
                        code: "TEMPORARILY_BANNED".to_string(),
                        message: format!(
                            "Too many failed attempts. Try again after {}",
                            banned_until.format("%Y-%m-%d %H:%M:%S UTC")
                        ),
                        should_retry: false,
                    }));
                }
            }
        }
        None
    }

    /// Check token cache
    fn check_cache(&self, token: &str) -> Option<ProxyPrincipal> {
        let token_hash = self.hash_token(token);

        if let Some(cached) = self.token_cache.get(&token_hash) {
            if Utc::now() < cached.expires_at {
                debug!("Using cached authentication");
                return Some(cached.principal.clone());
            }
            // Remove expired entry
            drop(cached);
            self.token_cache.remove(&token_hash);
        }
        None
    }

    /// Cache successful authentication
    fn cache_auth(&self, token: &str, principal: &ProxyPrincipal) {
        let token_hash = self.hash_token(token);
        let cache_duration = chrono::Duration::seconds(self.config.jwt.token_cache_secs as i64);

        // Use earlier of token expiry or cache TTL
        let expires_at = principal
            .expires_at
            .map(|e| std::cmp::min(e, Utc::now() + cache_duration))
            .unwrap_or(Utc::now() + cache_duration);

        self.token_cache.insert(
            token_hash,
            CachedAuth {
                principal: principal.clone(),
                cached_at: Utc::now(),
                expires_at,
            },
        );
    }

    /// Record a failed authentication attempt
    fn record_failure(&self, identifier: &str) {
        let mut attempts = self
            .failed_attempts
            .entry(identifier.to_string())
            .or_insert_with(|| FailedAttempts {
                count: 0,
                first_attempt: Utc::now(),
                last_attempt: Utc::now(),
                banned_until: None,
            });

        attempts.count += 1;
        attempts.last_attempt = Utc::now();

        // Check if we should ban
        if attempts.count >= self.config.max_auth_attempts {
            let ban_duration = chrono::Duration::seconds(self.config.ban_duration_secs as i64);
            attempts.banned_until = Some(Utc::now() + ban_duration);
            warn!(
                "User {} temporarily banned until {} after {} failed attempts",
                identifier,
                attempts.banned_until.unwrap(),
                attempts.count
            );
        }
    }

    /// Hash a token for cache key
    fn hash_token(&self, token: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Clear expired cache entries (call periodically)
    pub fn cleanup_cache(&self) {
        let now = Utc::now();

        self.token_cache.retain(|_, cached| cached.expires_at > now);

        // Clear old failed attempts (keep for 24 hours)
        let cutoff = now - chrono::Duration::hours(24);
        self.failed_attempts
            .retain(|_, attempts| attempts.last_attempt > cutoff);
    }
}
