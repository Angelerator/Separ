//! Generic OIDC Identity Provider implementation
//!
//! This provider works with any OIDC-compliant identity provider,
//! using the discovery document to configure endpoints.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, instrument};

use separ_core::{identity::*, IdentityProviderId, Result, SeparError, TenantId};

use super::common::*;

/// Generic OIDC Identity Provider
#[allow(dead_code)]
pub struct GenericOidcProvider {
    config: OidcConfig,
    provider_id: IdentityProviderId,
    tenant_id: TenantId,
    http_client: HttpClient,
    jwks_cache: Arc<JwksCache>,
    discovery: Option<OidcDiscovery>,
    features: ProviderFeatures,
}

impl GenericOidcProvider {
    /// Create a new Generic OIDC provider instance
    pub async fn new(provider_config: &IdentityProviderConfig) -> Result<Self> {
        let config = match &provider_config.config {
            ProviderConfigDetails::GenericOidc(c) => c.clone(),
            _ => {
                return Err(SeparError::InvalidInput {
                    message: "Expected OIDC configuration".to_string(),
                })
            }
        };

        let http_client = HttpClient::new(provider_config.sync_settings.max_retries, 1000)?;

        // Fetch OIDC discovery
        let discovery = OidcDiscovery::fetch(&config.issuer_url, &http_client)
            .await
            .ok();

        Ok(Self {
            config,
            provider_id: provider_config.id,
            tenant_id: provider_config.tenant_id,
            http_client,
            jwks_cache: Arc::new(JwksCache::new(3600)),
            discovery,
            features: provider_config.features.clone(),
        })
    }

    /// Get authorization endpoint
    fn authorization_endpoint(&self) -> String {
        self.config
            .authorization_endpoint
            .clone()
            .or_else(|| {
                self.discovery
                    .as_ref()
                    .map(|d| d.authorization_endpoint.clone())
            })
            .unwrap_or_else(|| format!("{}/authorize", self.config.issuer_url))
    }

    /// Get token endpoint
    fn token_endpoint(&self) -> String {
        self.config
            .token_endpoint
            .clone()
            .or_else(|| self.discovery.as_ref().map(|d| d.token_endpoint.clone()))
            .unwrap_or_else(|| format!("{}/token", self.config.issuer_url))
    }

    /// Get userinfo endpoint
    #[allow(dead_code)]
    fn userinfo_endpoint(&self) -> Option<String> {
        self.config.userinfo_endpoint.clone().or_else(|| {
            self.discovery
                .as_ref()
                .and_then(|d| d.userinfo_endpoint.clone())
        })
    }

    /// Get JWKS URI
    fn jwks_uri(&self) -> String {
        self.config
            .jwks_uri
            .clone()
            .or_else(|| self.discovery.as_ref().map(|d| d.jwks_uri.clone()))
            .unwrap_or_else(|| format!("{}/.well-known/jwks.json", self.config.issuer_url))
    }

    /// Get issuer
    fn issuer(&self) -> String {
        self.discovery
            .as_ref()
            .map(|d| d.issuer.clone())
            .unwrap_or_else(|| self.config.issuer_url.clone())
    }

    /// Get scopes
    fn scopes(&self) -> String {
        if self.config.scopes.is_empty() {
            "openid profile email".to_string()
        } else {
            self.config.scopes.join(" ")
        }
    }

    /// Extract user info from claims using claim mappings
    #[allow(dead_code)]
    fn extract_user_from_claims(&self, claims: &CommonClaims) -> SyncedUser {
        let _mappings = &self.config.claim_mappings;

        SyncedUser {
            external_id: claims.sub.clone(),
            email: claims.email.clone().unwrap_or_default(),
            display_name: claims.name.clone().unwrap_or_else(|| {
                format!(
                    "{} {}",
                    claims.given_name.as_deref().unwrap_or(""),
                    claims.family_name.as_deref().unwrap_or("")
                )
                .trim()
                .to_string()
            }),
            given_name: claims.given_name.clone(),
            family_name: claims.family_name.clone(),
            picture_url: claims.picture.clone(),
            active: true,
            email_verified: claims.email_verified.unwrap_or(false),
            groups: claims.groups.clone().unwrap_or_default(),
            roles: claims.roles.clone().unwrap_or_default(),
            attributes: HashMap::new(),
            synced_at: Utc::now(),
        }
    }

    /// Fetch user info from userinfo endpoint
    #[allow(dead_code)]
    async fn fetch_userinfo(&self, access_token: &str) -> Result<Option<CommonClaims>> {
        let Some(endpoint) = self.userinfo_endpoint() else {
            return Ok(None);
        };

        let response = self
            .http_client
            .execute_with_retry(
                self.http_client
                    .inner()
                    .get(&endpoint)
                    .bearer_auth(access_token),
            )
            .await?;

        let claims: CommonClaims = response.json().await.map_err(|e| SeparError::AuthError {
            message: format!("Failed to parse userinfo response: {}", e),
        })?;

        Ok(Some(claims))
    }
}

#[async_trait]
impl IdentitySync for GenericOidcProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::GenericOidc
    }

    fn provider_id(&self) -> IdentityProviderId {
        self.provider_id
    }

    // Generic OIDC providers don't support user sync - they only do JIT provisioning
    async fn sync_users(&self) -> Result<Vec<SyncedUser>> {
        Ok(vec![])
    }

    async fn sync_users_incremental(&self, _since: DateTime<Utc>) -> Result<Vec<SyncedUser>> {
        Ok(vec![])
    }

    async fn sync_groups(&self) -> Result<Vec<SyncedGroup>> {
        Ok(vec![])
    }

    async fn sync_groups_incremental(&self, _since: DateTime<Utc>) -> Result<Vec<SyncedGroup>> {
        Ok(vec![])
    }

    async fn get_user(&self, _external_id: &str) -> Result<Option<SyncedUser>> {
        Ok(None)
    }

    async fn get_group(&self, _external_id: &str) -> Result<Option<SyncedGroup>> {
        Ok(None)
    }

    async fn get_user_groups(&self, _user_external_id: &str) -> Result<Vec<SyncedGroup>> {
        Ok(vec![])
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn test_connection(&self) -> Result<bool> {
        // Try to fetch JWKS
        let result = self
            .jwks_cache
            .get_or_fetch(&self.jwks_uri(), &self.http_client)
            .await;
        Ok(result.is_ok())
    }
}

#[async_trait]
impl IdentityAuth for GenericOidcProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::GenericOidc
    }

    fn provider_id(&self) -> IdentityProviderId {
        self.provider_id
    }

    #[instrument(skip(self, token), fields(provider_id = %self.provider_id))]
    async fn validate_token(
        &self,
        token: &str,
        options: &ValidationOptions,
    ) -> Result<AuthenticatedPrincipal> {
        debug!("Validating OIDC token");

        // Extract kid from token header
        let kid = extract_jwt_kid(token)?;

        // Get JWKS
        let jwks = self
            .jwks_cache
            .get_or_fetch(&self.jwks_uri(), &self.http_client)
            .await?;

        // Get decoding key
        let decoding_key = jwks.get_decoding_key(&kid)?;

        // Build validation
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer()]);

        if !options.audiences.is_empty() {
            validation.set_audience(&options.audiences);
        } else {
            validation.set_audience(&[&self.config.client_id]);
        }

        validation.validate_exp = options.validate_exp;
        validation.validate_nbf = options.validate_nbf;
        validation.leeway = options.clock_skew_secs;

        // Validate and decode
        let claims: CommonClaims = validate_jwt(token, &decoding_key, &validation)?;

        // Build principal
        let principal = AuthenticatedPrincipal {
            principal_type: PrincipalType::User,
            subject: claims.sub.clone(),
            separ_id: None,
            tenant_id: self.tenant_id,
            provider_id: self.provider_id,
            provider_type: ProviderType::GenericOidc,
            email: claims.email.clone(),
            display_name: claims.name.clone(),
            groups: claims.groups.clone().unwrap_or_default(),
            roles: claims.roles.clone().unwrap_or_default(),
            scopes: claims
                .scope
                .as_ref()
                .map(|s| s.split(' ').map(String::from).collect())
                .unwrap_or_default(),
            issued_at: DateTime::from_timestamp(claims.iat.unwrap_or(0), 0).unwrap_or(Utc::now()),
            expires_at: DateTime::from_timestamp(claims.exp, 0).unwrap_or(Utc::now()),
            raw_claims: HashMap::new(),
        };

        Ok(principal)
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn get_authorization_url(
        &self,
        state: &str,
        nonce: Option<&str>,
        redirect_uri: &str,
    ) -> Result<String> {
        let mut url = format!(
            "{}?\
            client_id={}&\
            response_type=code&\
            redirect_uri={}&\
            scope={}&\
            state={}",
            self.authorization_endpoint(),
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(&self.scopes()),
            urlencoding::encode(state),
        );

        if let Some(n) = nonce {
            url.push_str(&format!("&nonce={}", urlencoding::encode(n)));
        }

        Ok(url)
    }

    #[instrument(skip(self, code), fields(provider_id = %self.provider_id))]
    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> Result<TokenExchangeResult> {
        let params = [
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
        ];

        let response = self
            .http_client
            .execute_with_retry(
                self.http_client
                    .inner()
                    .post(self.token_endpoint())
                    .form(&params),
            )
            .await?;

        let token_response: OidcTokenResponse =
            response.json().await.map_err(|e| SeparError::AuthError {
                message: format!("Failed to parse token response: {}", e),
            })?;

        // Validate ID token if present
        let principal = if let Some(id_token) = &token_response.id_token {
            let options = ValidationOptions {
                audiences: vec![self.config.client_id.clone()],
                issuers: vec![self.issuer()],
                clock_skew_secs: 60,
                validate_exp: true,
                validate_nbf: true,
            };
            Some(self.validate_token(id_token, &options).await?)
        } else {
            None
        };

        Ok(TokenExchangeResult {
            access_token: token_response.access_token,
            token_type: token_response
                .token_type
                .unwrap_or_else(|| "Bearer".to_string()),
            expires_in: token_response.expires_in.map(|e| e as u64),
            refresh_token: token_response.refresh_token,
            id_token: token_response.id_token,
            scopes: token_response
                .scope
                .map(|s| s.split(' ').map(String::from).collect())
                .unwrap_or_default(),
            principal,
        })
    }

    #[instrument(skip(self, refresh_token), fields(provider_id = %self.provider_id))]
    async fn refresh_token(&self, refresh_token: &str) -> Result<TokenExchangeResult> {
        let params = [
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
        ];

        let response = self
            .http_client
            .execute_with_retry(
                self.http_client
                    .inner()
                    .post(self.token_endpoint())
                    .form(&params),
            )
            .await?;

        let token_response: OidcTokenResponse =
            response.json().await.map_err(|e| SeparError::AuthError {
                message: format!("Failed to parse token response: {}", e),
            })?;

        Ok(TokenExchangeResult {
            access_token: token_response.access_token,
            token_type: token_response
                .token_type
                .unwrap_or_else(|| "Bearer".to_string()),
            expires_in: token_response.expires_in.map(|e| e as u64),
            refresh_token: token_response.refresh_token,
            id_token: token_response.id_token,
            scopes: token_response
                .scope
                .map(|s| s.split(' ').map(String::from).collect())
                .unwrap_or_default(),
            principal: None,
        })
    }
}

#[derive(Debug, Deserialize)]
struct OidcTokenResponse {
    access_token: String,
    token_type: Option<String>,
    expires_in: Option<i64>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    scope: Option<String>,
}
