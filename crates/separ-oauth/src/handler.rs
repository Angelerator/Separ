//! OAuth/OIDC authentication handler implementation

use async_trait::async_trait;
use std::collections::HashMap;
use tracing::{debug, info, instrument};

use separ_core::{
    IdTokenClaims, OAuthHandler, OAuthProvider, OAuthProviderType, Result, TokenResponse,
    UserInfo, SeparError,
};

/// Default OAuth handler implementation
pub struct DefaultOAuthHandler {
    redirect_base_url: String,
}

impl DefaultOAuthHandler {
    pub fn new(redirect_base_url: String) -> Self {
        Self { redirect_base_url }
    }

    fn get_auth_url(&self, provider: &OAuthProvider) -> Option<String> {
        provider.authorization_endpoint.clone().or_else(|| {
            match provider.provider_type {
                OAuthProviderType::Microsoft => {
                    Some("https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string())
                }
                OAuthProviderType::Google => {
                    Some("https://accounts.google.com/o/oauth2/v2/auth".to_string())
                }
                OAuthProviderType::Okta => None,
                OAuthProviderType::Auth0 => None,
                OAuthProviderType::Custom | OAuthProviderType::Saml => None,
            }
        })
    }

    fn get_token_url(&self, provider: &OAuthProvider) -> Option<String> {
        provider.token_endpoint.clone().or_else(|| {
            match provider.provider_type {
                OAuthProviderType::Microsoft => {
                    Some("https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string())
                }
                OAuthProviderType::Google => {
                    Some("https://oauth2.googleapis.com/token".to_string())
                }
                OAuthProviderType::Okta => None,
                OAuthProviderType::Auth0 => None,
                OAuthProviderType::Custom | OAuthProviderType::Saml => None,
            }
        })
    }

    fn get_userinfo_url(&self, provider: &OAuthProvider) -> Option<String> {
        provider.userinfo_endpoint.clone().or_else(|| {
            match provider.provider_type {
                OAuthProviderType::Microsoft => {
                    Some("https://graph.microsoft.com/oidc/userinfo".to_string())
                }
                OAuthProviderType::Google => {
                    Some("https://openidconnect.googleapis.com/v1/userinfo".to_string())
                }
                OAuthProviderType::Okta => None,
                OAuthProviderType::Auth0 => None,
                OAuthProviderType::Custom | OAuthProviderType::Saml => None,
            }
        })
    }

    fn get_scopes(&self, provider: &OAuthProvider) -> Vec<String> {
        if !provider.scopes.is_empty() {
            return provider.scopes.clone();
        }
        
        match provider.provider_type {
            OAuthProviderType::Microsoft => vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "offline_access".to_string(),
            ],
            OAuthProviderType::Google => vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            OAuthProviderType::Okta | OAuthProviderType::Auth0 => vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            OAuthProviderType::Custom | OAuthProviderType::Saml => vec![
                "openid".to_string(),
            ],
        }
    }
}

#[async_trait]
impl OAuthHandler for DefaultOAuthHandler {
    #[instrument(skip(self, provider))]
    async fn get_authorization_url(
        &self,
        provider: &OAuthProvider,
        state: &str,
        nonce: Option<&str>,
    ) -> Result<String> {
        let auth_url = self.get_auth_url(provider)
            .ok_or_else(|| SeparError::OAuthError {
                message: "Authorization endpoint not configured".to_string(),
            })?;

        let scopes = self.get_scopes(provider);

        let redirect_uri = format!(
            "{}/api/v1/oauth/{}/callback",
            self.redirect_base_url,
            provider.id
        );

        let mut url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
            auth_url,
            urlencoding::encode(&provider.client_id),
            urlencoding::encode(&redirect_uri),
            urlencoding::encode(&scopes.join(" ")),
            urlencoding::encode(state),
        );

        if let Some(n) = nonce {
            url.push_str(&format!("&nonce={}", urlencoding::encode(n)));
        }

        debug!("Generated authorization URL for provider {}", provider.name);
        Ok(url)
    }

    #[instrument(skip(self, provider, code))]
    async fn exchange_code(
        &self,
        provider: &OAuthProvider,
        code: &str,
    ) -> Result<TokenResponse> {
        let token_url = self.get_token_url(provider)
            .ok_or_else(|| SeparError::OAuthError {
                message: "Token endpoint not configured".to_string(),
            })?;

        let redirect_uri = format!(
            "{}/api/v1/oauth/{}/callback",
            self.redirect_base_url,
            provider.id
        );

        // Decrypt client secret (in real implementation)
        let client_secret = String::from_utf8_lossy(&provider.client_secret_encrypted).to_string();

        let client = reqwest::Client::new();
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &provider.client_id),
            ("client_secret", &client_secret),
        ];

        let response = client
            .post(&token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| SeparError::OAuthError {
                message: format!("Token exchange failed: {}", e),
            })?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(SeparError::OAuthError {
                message: format!("Token exchange failed: {}", error_text),
            });
        }

        let token_response: HashMap<String, serde_json::Value> = response.json().await
            .map_err(|e| SeparError::OAuthError {
                message: format!("Failed to parse token response: {}", e),
            })?;

        let access_token = token_response.get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SeparError::OAuthError {
                message: "Missing access_token in response".to_string(),
            })?
            .to_string();

        let result = TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: token_response.get("expires_in").and_then(|v| v.as_u64()),
            refresh_token: token_response.get("refresh_token").and_then(|v| v.as_str()).map(String::from),
            id_token: token_response.get("id_token").and_then(|v| v.as_str()).map(String::from),
            scope: token_response.get("scope").and_then(|v| v.as_str()).map(String::from),
        };

        info!("Successfully exchanged authorization code for tokens");
        Ok(result)
    }

    #[instrument(skip(self, _provider, id_token))]
    async fn validate_id_token(
        &self,
        _provider: &OAuthProvider,
        id_token: &str,
    ) -> Result<IdTokenClaims> {
        // Decode the JWT without verification first to get claims
        // In production, you should verify the signature using the provider's JWKS
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() != 3 {
            return Err(SeparError::OAuthError {
                message: "Invalid ID token format".to_string(),
            });
        }

        use base64::Engine;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| SeparError::OAuthError {
                message: format!("Failed to decode token payload: {}", e),
            })?;

        let claims: HashMap<String, serde_json::Value> = serde_json::from_slice(&payload)
            .map_err(|e| SeparError::OAuthError {
                message: format!("Failed to parse token claims: {}", e),
            })?;

        let sub = claims.get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SeparError::OAuthError {
                message: "Missing 'sub' claim".to_string(),
            })?
            .to_string();

        Ok(IdTokenClaims {
            sub,
            email: claims.get("email").and_then(|v| v.as_str()).map(String::from),
            email_verified: claims.get("email_verified").and_then(|v| v.as_bool()),
            name: claims.get("name").and_then(|v| v.as_str()).map(String::from),
            given_name: claims.get("given_name").and_then(|v| v.as_str()).map(String::from),
            family_name: claims.get("family_name").and_then(|v| v.as_str()).map(String::from),
            picture: claims.get("picture").and_then(|v| v.as_str()).map(String::from),
            locale: claims.get("locale").and_then(|v| v.as_str()).map(String::from),
            extra: claims.into_iter()
                .filter(|(k, _)| !["sub", "email", "email_verified", "name", "given_name", "family_name", "picture", "locale"].contains(&k.as_str()))
                .collect(),
        })
    }

    #[instrument(skip(self, provider, access_token))]
    async fn get_user_info(
        &self,
        provider: &OAuthProvider,
        access_token: &str,
    ) -> Result<UserInfo> {
        let userinfo_url = self.get_userinfo_url(provider)
            .ok_or_else(|| SeparError::OAuthError {
                message: "Userinfo endpoint not configured".to_string(),
            })?;

        let client = reqwest::Client::new();
        let response = client
            .get(&userinfo_url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| SeparError::OAuthError {
                message: format!("Failed to fetch user info: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(SeparError::OAuthError {
                message: format!("Userinfo request failed with status: {}", response.status()),
            });
        }

        let user_info: HashMap<String, serde_json::Value> = response.json().await
            .map_err(|e| SeparError::OAuthError {
                message: format!("Failed to parse user info: {}", e),
            })?;

        let sub = user_info.get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SeparError::OAuthError {
                message: "Missing 'sub' in userinfo response".to_string(),
            })?
            .to_string();

        Ok(UserInfo {
            sub,
            email: user_info.get("email").and_then(|v| v.as_str()).map(String::from),
            email_verified: user_info.get("email_verified").and_then(|v| v.as_bool()),
            name: user_info.get("name").and_then(|v| v.as_str()).map(String::from),
            given_name: user_info.get("given_name").and_then(|v| v.as_str()).map(String::from),
            family_name: user_info.get("family_name").and_then(|v| v.as_str()).map(String::from),
            picture: user_info.get("picture").and_then(|v| v.as_str()).map(String::from),
            locale: user_info.get("locale").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

// Simple URL encoding helper
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut result = String::new();
        for c in s.chars() {
            match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
                _ => {
                    for byte in c.to_string().as_bytes() {
                        result.push_str(&format!("%{:02X}", byte));
                    }
                }
            }
        }
        result
    }
}
