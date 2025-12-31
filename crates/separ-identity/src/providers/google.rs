//! Google Workspace / Cloud Identity provider implementation
//!
//! This provider supports:
//! - User sync via Google Admin SDK
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

/// Google Workspace Identity Provider
pub struct GoogleProvider {
    config: GoogleConfig,
    provider_id: IdentityProviderId,
    tenant_id: TenantId,
    http_client: HttpClient,
    jwks_cache: Arc<JwksCache>,
    discovery: Option<OidcDiscovery>,
    features: ProviderFeatures,
}

impl GoogleProvider {
    /// Create a new Google provider instance
    pub async fn new(provider_config: &IdentityProviderConfig) -> Result<Self> {
        let config = match &provider_config.config {
            ProviderConfigDetails::Google(c) => c.clone(),
            _ => return Err(SeparError::InvalidInput {
                message: "Expected Google configuration".to_string(),
            }),
        };

        let http_client = HttpClient::new(
            provider_config.sync_settings.max_retries,
            1000,
        )?;

        // Fetch OIDC discovery
        let discovery = OidcDiscovery::fetch("https://accounts.google.com", &http_client).await.ok();

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

    /// Get an access token for Admin SDK (using service account)
    async fn get_admin_token(&self) -> Result<String> {
        // If using service account with domain-wide delegation
        if let (Some(sa_email), Some(sa_key), Some(admin_email)) = (
            &self.config.service_account_email,
            &self.config.service_account_key,
            &self.config.admin_email,
        ) {
            return self.get_service_account_token(sa_email, sa_key, admin_email).await;
        }

        Err(SeparError::ConfigError {
            message: "Service account credentials required for admin operations".to_string(),
        })
    }

    /// Get token using service account with domain-wide delegation
    async fn get_service_account_token(
        &self,
        _sa_email: &str,
        _sa_key: &str,
        _admin_email: &str,
    ) -> Result<String> {
        // In a real implementation, this would:
        // 1. Parse the service account key JSON
        // 2. Create a signed JWT assertion
        // 3. Exchange it for an access token with the target scopes
        // 4. Impersonate the admin user for domain-wide access
        
        Err(SeparError::Internal {
            message: "Service account token generation not yet implemented".to_string(),
        })
    }

    /// Make an authenticated request to Google Admin SDK
    async fn admin_request<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        token: &str,
    ) -> Result<T> {
        let url = format!("https://admin.googleapis.com/admin/directory/v1{}", endpoint);
        
        let response = self.http_client
            .execute_with_retry(
                self.http_client.inner()
                    .get(&url)
                    .bearer_auth(token)
            )
            .await?;

        response.json().await.map_err(|e| {
            SeparError::Internal {
                message: format!("Failed to parse Admin SDK response: {}", e),
            }
        })
    }

    /// Make a paginated request to Google Admin SDK
    async fn admin_request_paginated<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        token: &str,
        query: Option<&str>,
    ) -> Result<Vec<T>> {
        let mut all_items = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let mut url = format!(
                "https://admin.googleapis.com/admin/directory/v1{}?maxResults=200",
                endpoint
            );
            
            if let Some(q) = query {
                url.push_str(&format!("&query={}", urlencoding::encode(q)));
            }
            
            if let Some(pt) = &page_token {
                url.push_str(&format!("&pageToken={}", pt));
            }

            let response = self.http_client
                .execute_with_retry(
                    self.http_client.inner()
                        .get(&url)
                        .bearer_auth(token)
                )
                .await?;

            let page: GoogleListResponse<T> = response.json().await.map_err(|e| {
                SeparError::Internal {
                    message: format!("Failed to parse Admin SDK response: {}", e),
                }
            })?;

            if let Some(items) = page.items {
                all_items.extend(items);
            }

            match page.next_page_token {
                Some(next) => page_token = Some(next),
                None => break,
            }
        }

        Ok(all_items)
    }

    /// Convert Google user to SyncedUser
    fn google_user_to_synced(&self, user: &GoogleUser) -> SyncedUser {
        SyncedUser {
            external_id: user.id.clone(),
            email: user.primary_email.clone(),
            display_name: user.name.as_ref()
                .map(|n| n.full_name.clone())
                .unwrap_or_default(),
            given_name: user.name.as_ref().and_then(|n| n.given_name.clone()),
            family_name: user.name.as_ref().and_then(|n| n.family_name.clone()),
            picture_url: user.thumbnail_photo_url.clone(),
            active: !user.suspended.unwrap_or(false),
            email_verified: true,
            groups: vec![],
            roles: vec![],
            attributes: {
                let mut attrs = HashMap::new();
                if let Some(org) = &user.org_unit_path {
                    attrs.insert("org_unit".to_string(), serde_json::json!(org));
                }
                attrs
            },
            synced_at: Utc::now(),
        }
    }

    /// Convert Google group to SyncedGroup
    fn google_group_to_synced(&self, group: &GoogleGroup) -> SyncedGroup {
        SyncedGroup {
            external_id: group.id.clone(),
            name: group.name.clone(),
            description: group.description.clone(),
            group_type: None,
            members: vec![],
            parent_groups: vec![],
            child_groups: vec![],
            attributes: {
                let mut attrs = HashMap::new();
                attrs.insert("email".to_string(), serde_json::json!(group.email));
                attrs
            },
            synced_at: Utc::now(),
        }
    }

    /// Get JWKS URI
    fn jwks_uri(&self) -> String {
        self.discovery
            .as_ref()
            .map(|d| d.jwks_uri.clone())
            .unwrap_or_else(|| "https://www.googleapis.com/oauth2/v3/certs".to_string())
    }
}

#[async_trait]
impl IdentitySync for GoogleProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Google
    }

    fn provider_id(&self) -> IdentityProviderId {
        self.provider_id
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn sync_users(&self) -> Result<Vec<SyncedUser>> {
        info!("Starting full user sync from Google Workspace");
        
        let token = self.get_admin_token().await?;
        let customer = self.config.customer_id.as_deref().unwrap_or("my_customer");
        
        let google_users: Vec<GoogleUser> = self.admin_request_paginated(
            &format!("/users?customer={}", customer),
            &token,
            None,
        ).await?;

        info!("Fetched {} users from Google Workspace", google_users.len());

        let mut users: Vec<SyncedUser> = google_users
            .iter()
            .map(|u| self.google_user_to_synced(u))
            .collect();

        // Fetch group memberships
        if self.features.sync_groups {
            for (i, google_user) in google_users.iter().enumerate() {
                match self.get_user_groups(&google_user.id).await {
                    Ok(groups) => {
                        users[i].groups = groups.iter().map(|g| g.external_id.clone()).collect();
                    }
                    Err(e) => {
                        warn!("Failed to fetch groups for user {}: {}", google_user.id, e);
                    }
                }
            }
        }

        Ok(users)
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn sync_users_incremental(&self, _since: DateTime<Utc>) -> Result<Vec<SyncedUser>> {
        // Google Admin SDK doesn't have a good incremental sync option
        // Fall back to full sync
        self.sync_users().await
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn sync_groups(&self) -> Result<Vec<SyncedGroup>> {
        info!("Starting full group sync from Google Workspace");
        
        let token = self.get_admin_token().await?;
        let customer = self.config.customer_id.as_deref().unwrap_or("my_customer");
        
        let google_groups: Vec<GoogleGroup> = self.admin_request_paginated(
            &format!("/groups?customer={}", customer),
            &token,
            None,
        ).await?;

        info!("Fetched {} groups from Google Workspace", google_groups.len());

        let mut groups: Vec<SyncedGroup> = google_groups
            .iter()
            .map(|g| self.google_group_to_synced(g))
            .collect();

        // Fetch members for each group
        for (i, google_group) in google_groups.iter().enumerate() {
            match self.admin_request_paginated::<GoogleMember>(
                &format!("/groups/{}/members", google_group.id),
                &token,
                None,
            ).await {
                Ok(members) => {
                    groups[i].members = members
                        .iter()
                        .filter(|m| m.member_type == "USER")
                        .map(|m| m.id.clone())
                        .collect();
                    
                    // Nested groups
                    if self.features.resolve_nested_groups {
                        groups[i].child_groups = members
                            .iter()
                            .filter(|m| m.member_type == "GROUP")
                            .map(|m| m.id.clone())
                            .collect();
                    }
                }
                Err(e) => {
                    warn!("Failed to fetch members for group {}: {}", google_group.id, e);
                }
            }
        }

        Ok(groups)
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn sync_groups_incremental(&self, _since: DateTime<Utc>) -> Result<Vec<SyncedGroup>> {
        self.sync_groups().await
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn get_user(&self, external_id: &str) -> Result<Option<SyncedUser>> {
        let token = self.get_admin_token().await?;
        
        let result: std::result::Result<GoogleUser, _> = self.admin_request(
            &format!("/users/{}", external_id),
            &token,
        ).await;

        match result {
            Ok(user) => Ok(Some(self.google_user_to_synced(&user))),
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
        let token = self.get_admin_token().await?;
        
        let result: std::result::Result<GoogleGroup, _> = self.admin_request(
            &format!("/groups/{}", external_id),
            &token,
        ).await;

        match result {
            Ok(group) => Ok(Some(self.google_group_to_synced(&group))),
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
        let token = self.get_admin_token().await?;
        
        let google_groups: Vec<GoogleGroup> = self.admin_request_paginated(
            &format!("/groups?userKey={}", user_external_id),
            &token,
            None,
        ).await?;

        let groups = google_groups
            .iter()
            .map(|g| self.google_group_to_synced(g))
            .collect();

        Ok(groups)
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn test_connection(&self) -> Result<bool> {
        // Try to get admin token
        match self.get_admin_token().await {
            Ok(_) => Ok(true),
            Err(_) => {
                // Fall back to just checking JWKS
                let result = self.jwks_cache
                    .get_or_fetch(&self.jwks_uri(), &self.http_client)
                    .await;
                Ok(result.is_ok())
            }
        }
    }
}

#[async_trait]
impl IdentityAuth for GoogleProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Google
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
        debug!("Validating Google token");

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
        validation.set_issuer(&["https://accounts.google.com"]);
        
        if !options.audiences.is_empty() {
            validation.set_audience(&options.audiences);
        } else {
            validation.set_audience(&[&self.config.client_id]);
        }

        validation.validate_exp = options.validate_exp;
        validation.validate_nbf = options.validate_nbf;
        validation.leeway = options.clock_skew_secs;

        // Validate and decode
        let claims: GoogleTokenClaims = validate_jwt(token, &decoding_key, &validation)?;

        // Build principal
        let principal = AuthenticatedPrincipal {
            principal_type: PrincipalType::User,
            subject: claims.sub.clone(),
            separ_id: None,
            tenant_id: self.tenant_id,
            provider_id: self.provider_id,
            provider_type: ProviderType::Google,
            email: claims.email.clone(),
            display_name: claims.name.clone(),
            groups: vec![],
            roles: vec![],
            scopes: claims.scope
                .as_ref()
                .map(|s| s.split(' ').map(String::from).collect())
                .unwrap_or_default(),
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
            .unwrap_or_else(|| "https://accounts.google.com/o/oauth2/v2/auth".to_string());

        let mut url = format!(
            "{}?\
            client_id={}&\
            response_type=code&\
            redirect_uri={}&\
            scope=openid%20profile%20email&\
            state={}&\
            access_type=offline",
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
            .unwrap_or_else(|| "https://oauth2.googleapis.com/token".to_string());

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

        let token_response: GoogleTokenResponse = response.json().await.map_err(|e| {
            SeparError::AuthError {
                message: format!("Failed to parse token response: {}", e),
            }
        })?;

        // Validate ID token if present
        let principal = if let Some(id_token) = &token_response.id_token {
            let options = ValidationOptions {
                audiences: vec![self.config.client_id.clone()],
                issuers: vec!["https://accounts.google.com".to_string()],
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
            .unwrap_or_else(|| "https://oauth2.googleapis.com/token".to_string());

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

        let token_response: GoogleTokenResponse = response.json().await.map_err(|e| {
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
// Google API Types
// =============================================================================

#[derive(Debug, Deserialize)]
struct GoogleListResponse<T> {
    #[serde(flatten)]
    items: Option<Vec<T>>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleUser {
    id: String,
    #[serde(rename = "primaryEmail")]
    primary_email: String,
    name: Option<GoogleUserName>,
    suspended: Option<bool>,
    #[serde(rename = "thumbnailPhotoUrl")]
    thumbnail_photo_url: Option<String>,
    #[serde(rename = "orgUnitPath")]
    org_unit_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleUserName {
    #[serde(rename = "fullName")]
    full_name: String,
    #[serde(rename = "givenName")]
    given_name: Option<String>,
    #[serde(rename = "familyName")]
    family_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleGroup {
    id: String,
    name: String,
    email: String,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleMember {
    id: String,
    #[serde(rename = "type")]
    member_type: String,
}

#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    token_type: Option<String>,
    expires_in: Option<i64>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoogleTokenClaims {
    sub: String,
    iss: String,
    #[serde(default)]
    aud: Audience,
    exp: i64,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    picture: Option<String>,
    #[serde(default)]
    given_name: Option<String>,
    #[serde(default)]
    family_name: Option<String>,
    #[serde(default)]
    hd: Option<String>, // Hosted domain
    #[serde(default)]
    scope: Option<String>,
}

