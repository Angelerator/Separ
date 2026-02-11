//! JWT token service for Separ
//!
//! Security Features:
//! - Explicit algorithm enforcement (prevents algorithm confusion attacks)
//! - Required claims validation (iss, exp, nbf, aud)
//! - Token type validation (access vs refresh)
//! - JTI for token revocation support

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument, warn};

use separ_core::{Result, SeparError};

/// JWT claims structure
///
/// Contains all standard and custom claims for Separ tokens.
/// Security: All required claims (iss, aud, exp, nbf, iat, jti) are validated.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Workspace ID (active workspace context)
    #[serde(default)]
    pub workspace_id: String,
    /// Issuer
    pub iss: String,
    /// Audience - who this token is intended for
    pub aud: String,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Not before (Unix timestamp)
    pub nbf: i64,
    /// JWT ID (unique token identifier for revocation support)
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

/// Allowed algorithm for JWT signing/verification
/// Using HS256 with explicit enforcement to prevent algorithm confusion attacks
const JWT_ALGORITHM: Algorithm = Algorithm::HS256;

/// Minimum secret length (256 bits = 32 bytes)
const MIN_SECRET_LENGTH: usize = 32;

/// JWT service for creating and validating tokens
#[derive(Clone)]
pub struct JwtService {
    secret: String,
    issuer: String,
    audience: String,
    access_token_expiry_secs: i64,
    refresh_token_expiry_secs: i64,
}

impl JwtService {
    /// Create a new JWT service
    ///
    /// # Security Requirements
    /// - Secret must be at least 32 bytes (256 bits) for HS256
    /// - Issuer and audience should be unique to your deployment
    pub fn new(
        secret: String,
        issuer: String,
        access_token_expiry_secs: i64,
        refresh_token_expiry_secs: i64,
    ) -> Self {
        // Warn if secret is too short (but don't panic for backward compatibility)
        if secret.len() < MIN_SECRET_LENGTH {
            warn!(
                "JWT secret is only {} bytes, recommended minimum is {} bytes for HS256",
                secret.len(),
                MIN_SECRET_LENGTH
            );
        }

        let audience = issuer.clone(); // Use issuer as audience by default

        Self {
            secret,
            issuer,
            audience,
            access_token_expiry_secs,
            refresh_token_expiry_secs,
        }
    }

    /// Create a new JWT service with explicit audience
    pub fn with_audience(mut self, audience: String) -> Self {
        self.audience = audience;
        self
    }

    /// Generate a token pair for a user
    ///
    /// Security: Uses explicit algorithm header to prevent algorithm confusion attacks
    #[instrument(skip(self))]
    pub fn generate_tokens(
        &self,
        user_id: &str,
        tenant_id: &str,
        workspace_id: &str,
        email: Option<&str>,
        name: Option<&str>,
        roles: Vec<String>,
        scopes: Vec<String>,
    ) -> Result<TokenPair> {
        let now = Utc::now();
        let jti = uuid::Uuid::new_v4().to_string();

        // Explicit header with algorithm to prevent algorithm confusion attacks
        let header = Header::new(JWT_ALGORITHM);

        // Create access token
        let access_claims = Claims {
            sub: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            workspace_id: workspace_id.to_string(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
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
            &header,
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
            workspace_id: workspace_id.to_string(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
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
            &header,
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
    ///
    /// Security measures:
    /// - Explicit algorithm enforcement (only HS256 accepted)
    /// - Issuer validation
    /// - Audience validation
    /// - Expiration validation
    /// - Not-before validation
    #[instrument(skip(self, token))]
    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        // Create validation with explicit algorithm to prevent algorithm confusion attacks
        let mut validation = Validation::new(JWT_ALGORITHM);

        // Enforce issuer
        validation.set_issuer(&[&self.issuer]);

        // Enforce audience
        validation.set_audience(&[&self.audience]);

        // Enforce time-based claims
        validation.validate_exp = true;
        validation.validate_nbf = true;

        // Reject tokens with 'none' algorithm (already handled by explicit algorithm, but extra safety)
        validation.validate_aud = true;

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &validation,
        )
        .map_err(|e| {
            warn!(error = %e, "Token validation failed");
            SeparError::JwtError {
                message: format!("Token validation failed: {}", e),
            }
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
            &claims.workspace_id,
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

/// JWKS (JSON Web Key Set) response structure
#[derive(Debug, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

/// JSON Web Key structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(rename = "use")]
    pub key_use: String,
    pub kid: String,
    pub alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

impl JwtService {
    /// Get JWKS for token validation by external services
    /// Note: Currently using symmetric key (HMAC), so we return an empty JWKS
    /// Future: When using RSA, this will return the public key
    pub fn get_jwks(&self) -> JwksResponse {
        // For HMAC (symmetric), we cannot expose the key
        // Return metadata about the key without the actual secret
        JwksResponse {
            keys: vec![Jwk {
                kty: "oct".to_string(), // Octet sequence (symmetric)
                key_use: "sig".to_string(),
                kid: "separ-key-1".to_string(),
                alg: "HS256".to_string(),
                n: None,
                e: None,
            }],
        }
    }

    /// Get the issuer
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Get access token expiry in seconds
    pub fn access_token_expiry_secs(&self) -> i64 {
        self.access_token_expiry_secs
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_jwt_service() -> JwtService {
        JwtService::new(
            "test-secret-key-for-testing-only".to_string(),
            "separ-test".to_string(),
            3600,  // 1 hour access token
            86400, // 24 hour refresh token
        )
    }

    #[test]
    fn test_generate_tokens_creates_valid_access_token() {
        let service = create_test_jwt_service();

        let result = service.generate_tokens(
            "user_123",
            "tenant_456",
            "workspace_789",
            Some("test@example.com"),
            Some("Test User"),
            vec!["admin".to_string()],
            vec!["read".to_string(), "write".to_string()],
        );

        assert!(result.is_ok());
        let tokens = result.unwrap();

        assert!(!tokens.access_token.is_empty());
        assert!(!tokens.refresh_token.is_empty());
        assert_eq!(tokens.token_type, "Bearer");
        assert_eq!(tokens.expires_in, 3600);
    }

    #[test]
    fn test_validate_token_decodes_claims_correctly() {
        let service = create_test_jwt_service();

        let tokens = service
            .generate_tokens(
                "user_123",
                "tenant_456",
                "workspace_789",
                Some("test@example.com"),
                Some("Test User"),
                vec!["admin".to_string()],
                vec!["read".to_string(), "write".to_string()],
            )
            .unwrap();

        let claims = service.validate_token(&tokens.access_token).unwrap();

        assert_eq!(claims.sub, "user_123");
        assert_eq!(claims.tenant_id, "tenant_456");
        assert_eq!(claims.workspace_id, "workspace_789");
        assert_eq!(claims.email, Some("test@example.com".to_string()));
        assert_eq!(claims.name, Some("Test User".to_string()));
        assert_eq!(claims.token_type, "access");
        assert!(claims.roles.contains(&"admin".to_string()));
        assert!(claims.scopes.contains(&"read".to_string()));
    }

    #[test]
    fn test_validate_token_rejects_invalid_token() {
        let service = create_test_jwt_service();

        let result = service.validate_token("invalid.token.here");

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_token_rejects_wrong_issuer() {
        let service1 = JwtService::new(
            "same-secret".to_string(),
            "issuer-1".to_string(),
            3600,
            86400,
        );
        let service2 = JwtService::new(
            "same-secret".to_string(),
            "issuer-2".to_string(),
            3600,
            86400,
        );

        let tokens = service1
            .generate_tokens("user_123", "tenant_456", "ws_1", None, None, vec![], vec![])
            .unwrap();

        // Token from service1 should not validate with service2 (different issuer)
        let result = service2.validate_token(&tokens.access_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_refresh_token_generates_new_token_pair() {
        let service = create_test_jwt_service();

        let original_tokens = service
            .generate_tokens(
                "user_123",
                "tenant_456",
                "workspace_789",
                Some("test@example.com"),
                Some("Test User"),
                vec!["admin".to_string()],
                vec!["read".to_string()],
            )
            .unwrap();

        let new_tokens = service
            .refresh_access_token(&original_tokens.refresh_token)
            .unwrap();

        // New tokens should be different
        assert_ne!(new_tokens.access_token, original_tokens.access_token);
        assert_ne!(new_tokens.refresh_token, original_tokens.refresh_token);

        // But claims should be preserved
        let claims = service.validate_token(&new_tokens.access_token).unwrap();
        assert_eq!(claims.sub, "user_123");
        assert_eq!(claims.tenant_id, "tenant_456");
        assert_eq!(claims.workspace_id, "workspace_789");
    }

    #[test]
    fn test_refresh_with_access_token_fails() {
        let service = create_test_jwt_service();

        let tokens = service
            .generate_tokens("user_123", "tenant_456", "ws_1", None, None, vec![], vec![])
            .unwrap();

        // Should not be able to refresh using an access token
        let result = service.refresh_access_token(&tokens.access_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_jwks_returns_key_metadata() {
        let service = create_test_jwt_service();

        let jwks = service.get_jwks();

        assert!(!jwks.keys.is_empty());
        let key = &jwks.keys[0];
        assert_eq!(key.kty, "oct");
        assert_eq!(key.key_use, "sig");
        assert_eq!(key.alg, "HS256");
        assert_eq!(key.kid, "separ-key-1");
    }

    #[test]
    fn test_issuer_getter() {
        let service = create_test_jwt_service();
        assert_eq!(service.issuer(), "separ-test");
    }

    #[test]
    fn test_access_token_expiry_getter() {
        let service = create_test_jwt_service();
        assert_eq!(service.access_token_expiry_secs(), 3600);
    }
}
