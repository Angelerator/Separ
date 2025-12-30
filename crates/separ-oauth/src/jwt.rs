//! JWT token service for Separ

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use separ_core::{Result, SeparError};

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Issuer
    pub iss: String,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Not before (Unix timestamp)
    pub nbf: i64,
    /// JWT ID
    pub jti: String,
    /// Token type (access or refresh)
    pub token_type: String,
    /// User email
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// User name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// User roles
    #[serde(default)]
    pub roles: Vec<String>,
    /// Additional scopes
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// Token pair returned after authentication
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

/// JWT service for creating and validating tokens
#[derive(Clone)]
pub struct JwtService {
    secret: String,
    issuer: String,
    access_token_expiry_secs: i64,
    refresh_token_expiry_secs: i64,
}

impl JwtService {
    /// Create a new JWT service
    pub fn new(
        secret: String,
        issuer: String,
        access_token_expiry_secs: i64,
        refresh_token_expiry_secs: i64,
    ) -> Self {
        Self {
            secret,
            issuer,
            access_token_expiry_secs,
            refresh_token_expiry_secs,
        }
    }

    /// Generate a token pair for a user
    #[instrument(skip(self))]
    pub fn generate_tokens(
        &self,
        user_id: &str,
        tenant_id: &str,
        email: Option<&str>,
        name: Option<&str>,
        roles: Vec<String>,
        scopes: Vec<String>,
    ) -> Result<TokenPair> {
        let now = Utc::now();
        let jti = uuid::Uuid::new_v4().to_string();

        // Create access token
        let access_claims = Claims {
            sub: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            iss: self.issuer.clone(),
            exp: (now + Duration::seconds(self.access_token_expiry_secs)).timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti: jti.clone(),
            token_type: "access".to_string(),
            email: email.map(String::from),
            name: name.map(String::from),
            roles: roles.clone(),
            scopes: scopes.clone(),
        };

        let access_token = encode(
            &Header::default(),
            &access_claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
        .map_err(|e| SeparError::JwtError {
            message: format!("Failed to encode access token: {}", e),
        })?;

        // Create refresh token
        let refresh_jti = uuid::Uuid::new_v4().to_string();
        let refresh_claims = Claims {
            sub: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            iss: self.issuer.clone(),
            exp: (now + Duration::seconds(self.refresh_token_expiry_secs)).timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti: refresh_jti,
            token_type: "refresh".to_string(),
            email: None,
            name: None,
            roles: vec![],
            scopes: vec![],
        };

        let refresh_token = encode(
            &Header::default(),
            &refresh_claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
        .map_err(|e| SeparError::JwtError {
            message: format!("Failed to encode refresh token: {}", e),
        })?;

        debug!("Generated tokens for user {}", user_id);

        Ok(TokenPair {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.access_token_expiry_secs,
        })
    }

    /// Validate and decode a token
    #[instrument(skip(self, token))]
    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.issuer]);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &validation,
        )
        .map_err(|e| SeparError::JwtError {
            message: format!("Token validation failed: {}", e),
        })?;

        debug!("Validated token for user {}", token_data.claims.sub);
        Ok(token_data.claims)
    }

    /// Refresh an access token using a refresh token
    #[instrument(skip(self, refresh_token))]
    pub fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenPair> {
        let claims = self.validate_token(refresh_token)?;

        if claims.token_type != "refresh" {
            return Err(SeparError::JwtError {
                message: "Invalid token type for refresh".to_string(),
            });
        }

        // Generate new token pair
        self.generate_tokens(
            &claims.sub,
            &claims.tenant_id,
            claims.email.as_deref(),
            claims.name.as_deref(),
            claims.roles,
            claims.scopes,
        )
    }
}

impl std::fmt::Debug for JwtService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtService")
            .field("issuer", &self.issuer)
            .field("access_token_expiry_secs", &self.access_token_expiry_secs)
            .field("refresh_token_expiry_secs", &self.refresh_token_expiry_secs)
            .finish()
    }
}
