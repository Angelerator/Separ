//! Azure Active Directory / Entra ID provider implementation
//!
//! This provider supports:
//! - User sync via Microsoft Graph API
//! - Group sync with nested group resolution
//! - Service principal and managed identity sync
//! - OIDC authentication with token validation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};

use separ_core::{identity::*, IdentityProviderId, Result, SeparError, TenantId};

use super::common::*;

/// Azure AD / Entra ID Identity Provider
pub struct AzureAdProvider {
    config: AzureAdConfig,
    provider_id: IdentityProviderId,
    tenant_id: TenantId,
    http_client: HttpClient,
    jwks_cache: Arc<JwksCache>,
    features: ProviderFeatures,
}

impl AzureAdProvider {
    /// Create a new Azure AD provider instance
    pub fn new(provider_config: &IdentityProviderConfig) -> Result<Self> {
        let config = match &provider_config.config {
            ProviderConfigDetails::AzureAd(c) => c.clone(),
            _ => {
                return Err(SeparError::InvalidInput {
                    message: "Expected Azure AD configuration".to_string(),
                })
            }
        };

        let http_client = HttpClient::new(
            provider_config.sync_settings.max_retries,
            1000, // Base retry delay
        )?;

        Ok(Self {
            config,
            provider_id: provider_config.id,
            tenant_id: provider_config.tenant_id,
            http_client,
            jwks_cache: Arc::new(JwksCache::new(3600)), // 1 hour TTL
            features: provider_config.features.clone(),
        })
    }

    /// Get an access token for Microsoft Graph API
    async fn get_graph_token(&self) -> Result<String> {
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.config.tenant_id
        );

        let params = [
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
            ("scope", "https://graph.microsoft.com/.default"),
            ("grant_type", "client_credentials"),
        ];

        let response = self
            .http_client
            .execute_with_retry(self.http_client.inner().post(&token_url).form(&params))
            .await?;

        let token_response: AzureTokenResponse =
            response.json().await.map_err(|e| SeparError::AuthError {
                message: format!("Failed to parse token response: {}", e),
            })?;

        Ok(token_response.access_token)
    }

    /// Make an authenticated request to Microsoft Graph
    async fn graph_request<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        token: &str,
    ) -> Result<T> {
        let url = format!("https://graph.microsoft.com/v1.0{}", endpoint);

        let response = self
            .http_client
            .execute_with_retry(self.http_client.inner().get(&url).bearer_auth(token))
            .await?;

        response.json().await.map_err(|e| SeparError::Internal {
            message: format!("Failed to parse Graph response: {}", e),
        })
    }

    /// Make a paginated request to Microsoft Graph
    async fn graph_request_paginated<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        token: &str,
        filter: Option<&str>,
    ) -> Result<Vec<T>> {
        let mut all_items = Vec::new();
        let mut url = format!("https://graph.microsoft.com/v1.0{}", endpoint);

        if let Some(f) = filter {
            url = format!("{}?$filter={}", url, urlencoding::encode(f));
        }

        loop {
            let response = self
                .http_client
                .execute_with_retry(self.http_client.inner().get(&url).bearer_auth(token))
                .await?;

            let page: GraphListResponse<T> =
                response.json().await.map_err(|e| SeparError::Internal {
                    message: format!("Failed to parse Graph response: {}", e),
                })?;

            all_items.extend(page.value);

            match page.next_link {
                Some(next) => url = next,
                None => break,
            }
        }

        Ok(all_items)
    }

    /// Convert Azure user to SyncedUser
    fn azure_user_to_synced(&self, user: &AzureUser) -> SyncedUser {
        SyncedUser {
            external_id: user.id.clone(),
            email: user
                .mail
                .clone()
                .or_else(|| user.user_principal_name.clone())
                .unwrap_or_default(),
            display_name: user.display_name.clone().unwrap_or_default(),
            given_name: user.given_name.clone(),
            family_name: user.surname.clone(),
            picture_url: None, // Azure doesn't provide this directly
            active: user.account_enabled.unwrap_or(true),
            email_verified: true, // Azure verifies emails
            groups: vec![],       // Populated separately
            roles: vec![],
            attributes: {
                let mut attrs = HashMap::new();
                if let Some(upn) = &user.user_principal_name {
                    attrs.insert("upn".to_string(), serde_json::json!(upn));
                }
                if let Some(job) = &user.job_title {
                    attrs.insert("job_title".to_string(), serde_json::json!(job));
                }
                if let Some(dept) = &user.department {
                    attrs.insert("department".to_string(), serde_json::json!(dept));
                }
                attrs
            },
            synced_at: Utc::now(),
        }
    }

    /// Convert Azure group to SyncedGroup
    fn azure_group_to_synced(&self, group: &AzureGroup) -> SyncedGroup {
        SyncedGroup {
            external_id: group.id.clone(),
            name: group.display_name.clone().unwrap_or_default(),
            description: group.description.clone(),
            group_type: group.group_types.as_ref().and_then(|t| t.first().cloned()),
            members: vec![], // Populated separately
            parent_groups: vec![],
            child_groups: vec![],
            attributes: HashMap::new(),
            synced_at: Utc::now(),
        }
    }

    /// Get JWKS URI for Azure AD
    fn jwks_uri(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/discovery/v2.0/keys",
            self.config.tenant_id
        )
    }

    /// Get issuer for token validation
    fn issuer(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/v2.0",
            self.config.tenant_id
        )
    }
}

#[async_trait]
impl IdentitySync for AzureAdProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::AzureAd
    }

    fn provider_id(&self) -> IdentityProviderId {
        self.provider_id
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn sync_users(&self) -> Result<Vec<SyncedUser>> {
        info!("Starting full user sync from Azure AD");

        let token = self.get_graph_token().await?;

        let azure_users: Vec<AzureUser> = self
            .graph_request_paginated("/users", &token, self.config.user_filter.as_deref())
            .await?;

        info!("Fetched {} users from Azure AD", azure_users.len());

        let mut users: Vec<SyncedUser> = azure_users
            .iter()
            .map(|u| self.azure_user_to_synced(u))
            .collect();

        // Fetch group memberships for each user
        if self.features.sync_groups {
            for (i, azure_user) in azure_users.iter().enumerate() {
                match self.get_user_groups(&azure_user.id).await {
                    Ok(groups) => {
                        users[i].groups = groups.iter().map(|g| g.external_id.clone()).collect();
                    }
                    Err(e) => {
                        warn!("Failed to fetch groups for user {}: {}", azure_user.id, e);
                    }
                }
            }
        }

        Ok(users)
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn sync_users_incremental(&self, since: DateTime<Utc>) -> Result<Vec<SyncedUser>> {
        info!(
            "Starting incremental user sync from Azure AD since {}",
            since
        );

        let token = self.get_graph_token().await?;

        // Azure AD delta query for changes
        let filter = format!(
            "lastModifiedDateTime ge {}",
            since.format("%Y-%m-%dT%H:%M:%SZ")
        );

        let azure_users: Vec<AzureUser> = self
            .graph_request_paginated("/users", &token, Some(&filter))
            .await?;

        info!("Fetched {} modified users from Azure AD", azure_users.len());

        let users = azure_users
            .iter()
            .map(|u| self.azure_user_to_synced(u))
            .collect();

        Ok(users)
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn sync_groups(&self) -> Result<Vec<SyncedGroup>> {
        info!("Starting full group sync from Azure AD");

        let token = self.get_graph_token().await?;

        let azure_groups: Vec<AzureGroup> = self
            .graph_request_paginated("/groups", &token, self.config.group_filter.as_deref())
            .await?;

        info!("Fetched {} groups from Azure AD", azure_groups.len());

        let mut groups: Vec<SyncedGroup> = azure_groups
            .iter()
            .map(|g| self.azure_group_to_synced(g))
            .collect();

        // Fetch members for each group
        for (i, azure_group) in azure_groups.iter().enumerate() {
            match self
                .graph_request_paginated::<AzureDirectoryObject>(
                    &format!("/groups/{}/members", azure_group.id),
                    &token,
                    None,
                )
                .await
            {
                Ok(members) => {
                    groups[i].members = members
                        .iter()
                        .filter(|m| m.odata_type.as_deref() == Some("#microsoft.graph.user"))
                        .map(|m| m.id.clone())
                        .collect();

                    // Nested groups
                    if self.features.resolve_nested_groups {
                        groups[i].child_groups = members
                            .iter()
                            .filter(|m| m.odata_type.as_deref() == Some("#microsoft.graph.group"))
                            .map(|m| m.id.clone())
                            .collect();
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to fetch members for group {}: {}",
                        azure_group.id, e
                    );
                }
            }
        }

        Ok(groups)
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn sync_groups_incremental(&self, since: DateTime<Utc>) -> Result<Vec<SyncedGroup>> {
        info!(
            "Starting incremental group sync from Azure AD since {}",
            since
        );

        let token = self.get_graph_token().await?;

        let filter = format!(
            "lastModifiedDateTime ge {}",
            since.format("%Y-%m-%dT%H:%M:%SZ")
        );

        let azure_groups: Vec<AzureGroup> = self
            .graph_request_paginated("/groups", &token, Some(&filter))
            .await?;

        info!(
            "Fetched {} modified groups from Azure AD",
            azure_groups.len()
        );

        let groups = azure_groups
            .iter()
            .map(|g| self.azure_group_to_synced(g))
            .collect();

        Ok(groups)
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn get_user(&self, external_id: &str) -> Result<Option<SyncedUser>> {
        let token = self.get_graph_token().await?;

        let result: std::result::Result<AzureUser, _> = self
            .graph_request(&format!("/users/{}", external_id), &token)
            .await;

        match result {
            Ok(user) => Ok(Some(self.azure_user_to_synced(&user))),
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
        let token = self.get_graph_token().await?;

        let result: std::result::Result<AzureGroup, _> = self
            .graph_request(&format!("/groups/{}", external_id), &token)
            .await;

        match result {
            Ok(group) => Ok(Some(self.azure_group_to_synced(&group))),
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
        let token = self.get_graph_token().await?;

        let azure_groups: Vec<AzureGroup> = self
            .graph_request_paginated(
                &format!("/users/{}/memberOf/microsoft.graph.group", user_external_id),
                &token,
                None,
            )
            .await?;

        let groups = azure_groups
            .iter()
            .map(|g| self.azure_group_to_synced(g))
            .collect();

        Ok(groups)
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn test_connection(&self) -> Result<bool> {
        match self.get_graph_token().await {
            Ok(token) => {
                // Try to fetch organization info
                let result: std::result::Result<serde_json::Value, _> =
                    self.graph_request("/organization", &token).await;
                Ok(result.is_ok())
            }
            Err(_) => Ok(false),
        }
    }
}

#[async_trait]
impl IdentitySyncApps for AzureAdProvider {
    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn sync_apps(&self) -> Result<Vec<SyncedApp>> {
        if !self.config.sync_service_principals {
            return Ok(vec![]);
        }

        info!("Starting service principal sync from Azure AD");

        let token = self.get_graph_token().await?;

        let service_principals: Vec<AzureServicePrincipal> = self
            .graph_request_paginated("/servicePrincipals", &token, None)
            .await?;

        info!(
            "Fetched {} service principals from Azure AD",
            service_principals.len()
        );

        let apps = service_principals
            .iter()
            .map(|sp| SyncedApp {
                external_id: sp.id.clone(),
                name: sp.display_name.clone().unwrap_or_default(),
                app_type: if sp.service_principal_type.as_deref() == Some("ManagedIdentity") {
                    SyncedAppType::ManagedIdentity
                } else {
                    SyncedAppType::ServicePrincipal
                },
                description: sp.description.clone(),
                enabled: sp.account_enabled.unwrap_or(true),
                assigned_permissions: vec![],
                attributes: {
                    let mut attrs = HashMap::new();
                    if let Some(app_id) = &sp.app_id {
                        attrs.insert("app_id".to_string(), serde_json::json!(app_id));
                    }
                    attrs
                },
                synced_at: Utc::now(),
            })
            .collect();

        Ok(apps)
    }

    #[instrument(skip(self), fields(provider_id = %self.provider_id))]
    async fn get_app(&self, external_id: &str) -> Result<Option<SyncedApp>> {
        let token = self.get_graph_token().await?;

        let result: std::result::Result<AzureServicePrincipal, _> = self
            .graph_request(&format!("/servicePrincipals/{}", external_id), &token)
            .await;

        match result {
            Ok(sp) => Ok(Some(SyncedApp {
                external_id: sp.id.clone(),
                name: sp.display_name.clone().unwrap_or_default(),
                app_type: if sp.service_principal_type.as_deref() == Some("ManagedIdentity") {
                    SyncedAppType::ManagedIdentity
                } else {
                    SyncedAppType::ServicePrincipal
                },
                description: sp.description.clone(),
                enabled: sp.account_enabled.unwrap_or(true),
                assigned_permissions: vec![],
                attributes: HashMap::new(),
                synced_at: Utc::now(),
            })),
            Err(e) => {
                if e.to_string().contains("404") {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        }
    }
}

#[async_trait]
impl IdentityAuth for AzureAdProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::AzureAd
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
        debug!("Validating Azure AD token");

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
        let claims: AzureTokenClaims = validate_jwt(token, &decoding_key, &validation)?;

        // Determine principal type
        let principal_type = if claims.idtyp.as_deref() == Some("app") {
            PrincipalType::Service
        } else {
            PrincipalType::User
        };

        // Build principal
        let principal = AuthenticatedPrincipal {
            principal_type,
            subject: claims.oid.clone().unwrap_or(claims.sub.clone()),
            separ_id: None, // Will be resolved by caller
            tenant_id: self.tenant_id,
            provider_id: self.provider_id,
            provider_type: ProviderType::AzureAd,
            email: claims
                .email
                .clone()
                .or_else(|| claims.upn.clone())
                .or_else(|| claims.preferred_username.clone()),
            display_name: claims.name.clone(),
            groups: claims.groups.clone().unwrap_or_default(),
            roles: claims.roles.clone().unwrap_or_default(),
            scopes: claims
                .scp
                .as_ref()
                .map(|s| s.split(' ').map(String::from).collect())
                .unwrap_or_default(),
            issued_at: DateTime::from_timestamp(claims.iat.unwrap_or(0), 0).unwrap_or(Utc::now()),
            expires_at: DateTime::from_timestamp(claims.exp, 0).unwrap_or(Utc::now()),
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
        let mut url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize?\
            client_id={}&\
            response_type=code&\
            redirect_uri={}&\
            response_mode=query&\
            scope=openid%20profile%20email&\
            state={}",
            self.config.tenant_id,
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
    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> Result<TokenExchangeResult> {
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.config.tenant_id
        );

        let params = [
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
        ];

        let response = self
            .http_client
            .execute_with_retry(self.http_client.inner().post(&token_url).form(&params))
            .await?;

        let token_response: AzureTokenResponse =
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
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.config.tenant_id
        );

        let params = [
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
        ];

        let response = self
            .http_client
            .execute_with_retry(self.http_client.inner().post(&token_url).form(&params))
            .await?;

        let token_response: AzureTokenResponse =
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

// =============================================================================
// Azure AD API Types
// =============================================================================

#[derive(Debug, Deserialize)]
struct GraphListResponse<T> {
    value: Vec<T>,
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AzureUser {
    id: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "givenName")]
    given_name: Option<String>,
    surname: Option<String>,
    mail: Option<String>,
    #[serde(rename = "userPrincipalName")]
    user_principal_name: Option<String>,
    #[serde(rename = "accountEnabled")]
    account_enabled: Option<bool>,
    #[serde(rename = "jobTitle")]
    job_title: Option<String>,
    department: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AzureGroup {
    id: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    description: Option<String>,
    #[serde(rename = "groupTypes")]
    group_types: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct AzureDirectoryObject {
    id: String,
    #[serde(rename = "@odata.type")]
    odata_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AzureServicePrincipal {
    id: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    description: Option<String>,
    #[serde(rename = "appId")]
    app_id: Option<String>,
    #[serde(rename = "servicePrincipalType")]
    service_principal_type: Option<String>,
    #[serde(rename = "accountEnabled")]
    account_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct AzureTokenResponse {
    access_token: String,
    token_type: Option<String>,
    expires_in: Option<i64>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AzureTokenClaims {
    sub: String,
    iss: String,
    #[serde(default)]
    aud: Audience,
    exp: i64,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    nbf: Option<i64>,
    #[serde(default)]
    oid: Option<String>,
    #[serde(default)]
    tid: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    upn: Option<String>,
    #[serde(default)]
    given_name: Option<String>,
    #[serde(default)]
    family_name: Option<String>,
    #[serde(default)]
    groups: Option<Vec<String>>,
    #[serde(default)]
    roles: Option<Vec<String>>,
    #[serde(default)]
    scp: Option<String>,
    #[serde(default)]
    idtyp: Option<String>,
}
