//! Okta Identity Provider implementation
//!
//! This provider supports:
//! - User sync via Okta Management API
//! - Group sync with membership resolution
//! - OIDC authentication with token validation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};

use separ_core::{
    identity::*,
    IdentityProviderId, TenantId,
    Result, SeparError,
};

use super::common::*;

/// Okta Identity Provider
pub struct OktaProvider {
    config: OktaConfig,
    provider_id: IdentityProviderId,
    tenant_id: TenantId,
    http_client: HttpClient,
    jwks_cache: Arc<JwksCache>,
    discovery: Option<OidcDiscovery>,
    features: ProviderFeatures,
}

impl OktaProvider {
    /// Create a new Okta provider instance
    pub async fn new(provider_config: &IdentityProviderConfig) -> Result<Self> {
        let config = match &provider_config.config {
            ProviderConfigDetails::Okta(c) => c.clone(),
            _ => return Err(SeparError::InvalidInput {
                message: "Expected Okta configuration".to_string(),
            }),
        };

        let http_client = HttpClient::new(
            provider_config.sync_settings.max_retries,
            1000,
        )?;

        // Fetch OIDC discovery
        let issuer = format!("https://{}", config.domain);
        let discovery = OidcDiscovery::fetch(&issuer, &http_client).await.ok();

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

    /// Base URL for Okta API
    fn api_base(&self) -> String {
        format!("https://{}/api/v1", self.config.domain)
    }

    /// Make an authenticated request to Okta Management API
    async fn api_request<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
    ) -> Result<T> {
        let url = format!("{}{}", self.api_base(), endpoint);
        
        let response = self.http_client
            .execute_with_retry(
                self.http_client.inner()
                    .get(&url)
                    .header("Authorization", format!("SSWS {}", self.config.api_token))
                    .header("Accept", "application/json")
            )
            .await?;

        response.json().await.map_err(|e| {
            SeparError::Internal {
                message: format!("Failed to parse Okta response: {}", e),
            }
        })
    }

    /// Make a paginated request to Okta API
    async fn api_request_paginated<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        filter: Option<&str>,
    ) -> Result<Vec<T>> {
        let mut all_items = Vec::new();
        let mut url = format!("{}{}", self.api_base(), endpoint);
        
        if let Some(f) = filter {
            url = format!("{}?filter={}", url, urlencoding::encode(f));
        }

        loop {
            let response = self.http_client
                .execute_with_retry(
                    self.http_client.inner()
                        .get(&url)
                        .header("Authorization", format!("SSWS {}", self.config.api_token))
                        .header("Accept", "application/json")
                )
                .await?;

            // Check for Link header for pagination
            let next_link = response
                .headers()
                .get("link")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| parse_okta_link_header(s));

            let items: Vec<T> = response.json().await.map_err(|e| {
                SeparError::Internal {
                    message: format!("Failed to parse Okta response: {}", e),
                }
            })?;

            all_items.extend(items);

            match next_link {
                Some(next) => url = next,
                None => break,
            }
        }

        Ok(all_items)
    }

    /// Convert Okta user to SyncedUser
    fn okta_user_to_synced(&self, user: &OktaUser) -> SyncedUser {
        let profile = &user.profile;
        
        SyncedUser {
            external_id: user.id.clone(),
            email: profile.email.clone().unwrap_or_default(),
            display_name: format!(
                "{} {}",
                profile.first_name.as_deref().unwrap_or(""),
                profile.last_name.as_deref().unwrap_or("")
            ).trim().to_string(),
            given_name: profile.first_name.clone(),
            family_name: profile.last_name.clone(),
            picture_url: None,
            active: user.status == "ACTIVE",
            email_verified: true,
            groups: vec![],
            roles: vec![],
            attributes: {
                let mut attrs = HashMap::new();
                if let Some(login) = &profile.login {
                    attrs.insert("login".to_string(), serde_json::json!(login));
                }
                if let Some(phone) = &profile.mobile_phone {
                    attrs.insert("mobile_phone".to_string(), serde_json::json!(phone));
                }
                if let Some(dept) = &profile.department {
                    attrs.insert("department".to_string(), serde_json::json!(dept));
                }
                attrs
            },
            synced_at: Utc::now(),
        }
    }

    /// Convert Okta group to SyncedGroup
    fn okta_group_to_synced(&self, group: &OktaGroup) -> SyncedGroup {
        SyncedGroup {
            external_id: group.id.clone(),
            name: group.profile.name.clone(),
            description: group.profile.description.clone(),
            group_type: Some(group.group_type.clone()),
            members: vec![],
            parent_groups: vec![],
            child_groups: vec![],
            attributes: HashMap::new(),
            synced_at: Utc::now(),
        }
    }

    /// Get JWKS URI
    fn jwks_uri(&self) -> String {
        self.discovery
            .as_ref()
            .map(|d| d.jwks_uri.clone())
            .unwrap_or_else(|| format!("https://{}/oauth2/v1/keys", self.config.domain))
    }

    /// Get issuer
    fn issuer(&self) -> String {
        self.discovery
            .as_ref()
            .map(|d| d.issuer.clone())
            .unwrap_or_else(|| format!("https://{}", self.config.domain))
    }
}

#[async_trait]
impl IdentitySync for OktaProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Okta
    }

    fn provider_id(&self) -> IdentityProviderId {
        self.provider_id
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn sync_users(&self) -> Result<Vec<SyncedUser>> {
        info!("Starting full user sync from Okta");
        
        let okta_users: Vec<OktaUser> = self.api_request_paginated(
            "/users",
            self.config.user_filter.as_deref(),
        ).await?;

        info!("Fetched {} users from Okta", okta_users.len());

        let mut users: Vec<SyncedUser> = okta_users
            .iter()
            .map(|u| self.okta_user_to_synced(u))
            .collect();

        // Fetch group memberships
        if self.features.sync_groups {
            for (i, okta_user) in okta_users.iter().enumerate() {
                match self.get_user_groups(&okta_user.id).await {
                    Ok(groups) => {
                        users[i].groups = groups.iter().map(|g| g.external_id.clone()).collect();
                    }
                    Err(e) => {
                        warn!("Failed to fetch groups for user {}: {}", okta_user.id, e);
                    }
                }
            }
        }

        Ok(users)
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn sync_users_incremental(&self, since: DateTime<Utc>) -> Result<Vec<SyncedUser>> {
        info!("Starting incremental user sync from Okta since {}", since);
        
        let filter = format!(
            "lastUpdated gt \"{}\"",
            since.format("%Y-%m-%dT%H:%M:%S%.3fZ")
        );
        
        let okta_users: Vec<OktaUser> = self.api_request_paginated(
            "/users",
            Some(&filter),
        ).await?;

        info!("Fetched {} modified users from Okta", okta_users.len());

        let users = okta_users
            .iter()
            .map(|u| self.okta_user_to_synced(u))
            .collect();

        Ok(users)
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn sync_groups(&self) -> Result<Vec<SyncedGroup>> {
        info!("Starting full group sync from Okta");
        
        let okta_groups: Vec<OktaGroup> = self.api_request_paginated(
            "/groups",
            self.config.group_filter.as_deref(),
        ).await?;

        info!("Fetched {} groups from Okta", okta_groups.len());

        let mut groups: Vec<SyncedGroup> = okta_groups
            .iter()
            .map(|g| self.okta_group_to_synced(g))
            .collect();

        // Fetch members for each group
        for (i, okta_group) in okta_groups.iter().enumerate() {
            match self.api_request_paginated::<OktaUser>(
                &format!("/groups/{}/users", okta_group.id),
                None,
            ).await {
                Ok(members) => {
                    groups[i].members = members.iter().map(|m| m.id.clone()).collect();
                }
                Err(e) => {
                    warn!("Failed to fetch members for group {}: {}", okta_group.id, e);
                }
            }
        }

        Ok(groups)
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn sync_groups_incremental(&self, since: DateTime<Utc>) -> Result<Vec<SyncedGroup>> {
        info!("Starting incremental group sync from Okta since {}", since);
        
        let filter = format!(
            "lastUpdated gt \"{}\"",
            since.format("%Y-%m-%dT%H:%M:%S%.3fZ")
        );
        
        let okta_groups: Vec<OktaGroup> = self.api_request_paginated(
            "/groups",
            Some(&filter),
        ).await?;

        info!("Fetched {} modified groups from Okta", okta_groups.len());

        let groups = okta_groups
            .iter()
            .map(|g| self.okta_group_to_synced(g))
            .collect();

        Ok(groups)
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn get_user(&self, external_id: &str) -> Result<Option<SyncedUser>> {
        let result: std::result::Result<OktaUser, _> = 
            self.api_request(&format!("/users/{}", external_id)).await;

        match result {
            Ok(user) => Ok(Some(self.okta_user_to_synced(&user))),
            Err(e) => {
                if e.to_string().contains("404") {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        }
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn get_group(&self, external_id: &str) -> Result<Option<SyncedGroup>> {
        let result: std::result::Result<OktaGroup, _> = 
            self.api_request(&format!("/groups/{}", external_id)).await;

        match result {
            Ok(group) => Ok(Some(self.okta_group_to_synced(&group))),
            Err(e) => {
                if e.to_string().contains("404") {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        }
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn get_user_groups(&self, user_external_id: &str) -> Result<Vec<SyncedGroup>> {
        let okta_groups: Vec<OktaGroup> = self.api_request_paginated(
            &format!("/users/{}/groups", user_external_id),
            None,
        ).await?;

        let groups = okta_groups
            .iter()
            .map(|g| self.okta_group_to_synced(g))
            .collect();

        Ok(groups)
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn test_connection(&self) -> Result<bool> {
        let result: std::result::Result<Vec<OktaUser>, _> = 
            self.api_request("/users?limit=1").await;
        Ok(result.is_ok())
    }
}

#[async_trait]
impl IdentityAuth for OktaProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Okta
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
        debug!("Validating Okta token");

        // Extract kid from token header
        let kid = extract_jwt_kid(token)?;

        // Get JWKS
        let jwks = self.jwks_cache
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
        let claims: OktaTokenClaims = validate_jwt(token, &decoding_key, &validation)?;

        // Build principal
        let principal = AuthenticatedPrincipal {
            principal_type: PrincipalType::User,
            subject: claims.uid.clone().unwrap_or(claims.sub.clone()),
            separ_id: None,
            tenant_id: self.tenant_id,
            provider_id: self.provider_id,
            provider_type: ProviderType::Okta,
            email: claims.email.clone(),
            display_name: claims.name.clone(),
            groups: claims.groups.clone().unwrap_or_default(),
            roles: vec![],
            scopes: claims.scp.clone().unwrap_or_default(),
            issued_at: DateTime::from_timestamp(claims.iat.unwrap_or(0), 0)
                .unwrap_or(Utc::now()),
            expires_at: DateTime::from_timestamp(claims.exp, 0)
                .unwrap_or(Utc::now()),
            raw_claims: serde_json::to_value(&claims)
                .map(|v| v.as_object().cloned().unwrap_or_default())
                .unwrap_or_default()
                .into_iter()
                .collect(),
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
        let auth_endpoint = self.discovery
            .as_ref()
            .map(|d| d.authorization_endpoint.clone())
            .unwrap_or_else(|| format!("https://{}/oauth2/v1/authorize", self.config.domain));

        let mut url = format!(
            "{}?\
            client_id={}&\
            response_type=code&\
            redirect_uri={}&\
            scope=openid%20profile%20email%20groups&\
            state={}",
            auth_endpoint,
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
        );

        if let Some(n) = nonce {
            url.push_str(&format!("&nonce={}", urlencoding::encode(n)));
        }

        Ok(url)
    }

    #[instrument(skip(self, code), fields(provider_id = %self.provider_id))]
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<TokenExchangeResult> {
        let token_endpoint = self.discovery
            .as_ref()
            .map(|d| d.token_endpoint.clone())
            .unwrap_or_else(|| format!("https://{}/oauth2/v1/token", self.config.domain));

        let params = [
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
        ];

        let response = self.http_client
            .execute_with_retry(
                self.http_client.inner()
                    .post(&token_endpoint)
                    .form(&params)
            )
            .await?;

        let token_response: OktaTokenResponse = response.json().await.map_err(|e| {
            SeparError::AuthError {
                message: format!("Failed to parse token response: {}", e),
            }
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
            token_type: token_response.token_type.unwrap_or_else(|| "Bearer".to_string()),
            expires_in: token_response.expires_in.map(|e| e as u64),
            refresh_token: token_response.refresh_token,
            id_token: token_response.id_token,
            scopes: token_response.scope
                .map(|s| s.split(' ').map(String::from).collect())
                .unwrap_or_default(),
            principal,
        })
    }

    #[instrument(skip(self, refresh_token), fields(provider_id = %self.provider_id))]
    async fn refresh_token(&self, refresh_token: &str) -> Result<TokenExchangeResult> {
        let token_endpoint = self.discovery
            .as_ref()
            .map(|d| d.token_endpoint.clone())
            .unwrap_or_else(|| format!("https://{}/oauth2/v1/token", self.config.domain));

        let params = [
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
        ];

        let response = self.http_client
            .execute_with_retry(
                self.http_client.inner()
                    .post(&token_endpoint)
                    .form(&params)
            )
            .await?;

        let token_response: OktaTokenResponse = response.json().await.map_err(|e| {
            SeparError::AuthError {
                message: format!("Failed to parse token response: {}", e),
            }
        })?;

        Ok(TokenExchangeResult {
            access_token: token_response.access_token,
            token_type: token_response.token_type.unwrap_or_else(|| "Bearer".to_string()),
            expires_in: token_response.expires_in.map(|e| e as u64),
            refresh_token: token_response.refresh_token,
            id_token: token_response.id_token,
            scopes: token_response.scope
                .map(|s| s.split(' ').map(String::from).collect())
                .unwrap_or_default(),
            principal: None,
        })
    }
}

// =============================================================================
// Okta API Types
// =============================================================================

#[derive(Debug, Deserialize)]
struct OktaUser {
    id: String,
    status: String,
    profile: OktaUserProfile,
}

#[derive(Debug, Deserialize)]
struct OktaUserProfile {
    login: Option<String>,
    email: Option<String>,
    #[serde(rename = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "lastName")]
    last_name: Option<String>,
    #[serde(rename = "mobilePhone")]
    mobile_phone: Option<String>,
    department: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OktaGroup {
    id: String,
    #[serde(rename = "type")]
    group_type: String,
    profile: OktaGroupProfile,
}

#[derive(Debug, Deserialize)]
struct OktaGroupProfile {
    name: String,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OktaTokenResponse {
    access_token: String,
    token_type: Option<String>,
    expires_in: Option<i64>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OktaTokenClaims {
    sub: String,
    iss: String,
    #[serde(default)]
    aud: Audience,
    exp: i64,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    uid: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    groups: Option<Vec<String>>,
    #[serde(default)]
    scp: Option<Vec<String>>,
}

/// Parse Okta Link header for pagination
fn parse_okta_link_header(header: &str) -> Option<String> {
    for part in header.split(',') {
        let parts: Vec<&str> = part.split(';').collect();
        if parts.len() == 2 {
            let rel = parts[1].trim();
            if rel == "rel=\"next\"" {
                let url = parts[0].trim();
                if url.starts_with('<') && url.ends_with('>') {
                    return Some(url[1..url.len()-1].to_string());
                }
            }
        }
    }
    None
}

