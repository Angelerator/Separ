//! Authentication validation handlers
//!
//! These endpoints allow external applications (like Tavana) to validate
//! credentials and get identity information.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

use crate::state::AppState;

/// Request to validate credentials
#[derive(Debug, Deserialize)]
pub struct ValidateRequest {
    /// Username or principal identifier
    pub username: String,
    /// Credential (password, JWT, API key, etc.)
    pub credential: String,
    /// Type of credential
    pub credential_type: String,
    /// Tenant hint (optional)
    pub tenant_hint: Option<String>,
    /// Application requesting validation
    pub application: Option<String>,
    /// Client IP (for audit)
    pub client_ip: Option<String>,
}

/// Response from credential validation
#[derive(Debug, Serialize)]
pub struct ValidateResponse {
    /// User/principal ID
    pub user_id: String,
    /// Principal type (user, application, service_account, etc.)
    pub principal_type: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Tenant name (optional)
    pub tenant_name: Option<String>,
    /// Display name
    pub display_name: Option<String>,
    /// Email
    pub email: Option<String>,
    /// Groups the principal belongs to
    pub groups: Vec<String>,
    /// Permissions/scopes granted
    pub permissions: Vec<String>,
    /// Token expiration (Unix timestamp)
    pub expires_at: Option<i64>,
    /// Additional attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, serde_json::Value>>,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct AuthError {
    pub error: String,
    pub message: String,
}

/// Validate credentials for external applications
///
/// POST /api/v1/auth/validate
///
/// This endpoint allows applications like Tavana to validate user credentials
/// (JWTs, API keys, passwords) and get identity information.
pub async fn validate_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ValidateRequest>,
) -> Result<Json<ValidateResponse>, (StatusCode, Json<AuthError>)> {
    // Verify API key from headers (Tavana must authenticate itself)
    let api_key = headers
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if api_key.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "unauthorized".to_string(),
                message: "API key required".to_string(),
            }),
        ));
    }

    // TODO: Validate the API key belongs to a registered application

    debug!(
        username = %request.username,
        credential_type = %request.credential_type,
        application = ?request.application,
        "Validating credentials"
    );

    // Validate based on credential type
    match request.credential_type.as_str() {
        "jwt" => validate_jwt(&state, &request).await,
        "pat" => validate_personal_access_token(&state, &request).await,
        "sak" => validate_service_account_key(&state, &request).await,
        "api_key" => validate_api_key(&state, &request).await,
        "password" => validate_password(&state, &request).await,
        _ => Err((
            StatusCode::BAD_REQUEST,
            Json(AuthError {
                error: "invalid_credential_type".to_string(),
                message: format!("Unknown credential type: {}", request.credential_type),
            }),
        )),
    }
}

/// Validate a JWT token
async fn validate_jwt(
    state: &AppState,
    request: &ValidateRequest,
) -> Result<Json<ValidateResponse>, (StatusCode, Json<AuthError>)> {
    let token = &request.credential;

    // TODO: Use JwtService from state to validate the token
    // For now, return a mock response for demonstration

    // Parse JWT claims (without full validation for now)
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "invalid_token".to_string(),
                message: "Invalid JWT format".to_string(),
            }),
        ));
    }

    // Decode payload (base64)
    let payload = parts[1];
    let decoded = base64_decode(payload).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "invalid_token".to_string(),
                message: "Invalid JWT payload".to_string(),
            }),
        )
    })?;

    let claims: serde_json::Value = serde_json::from_slice(&decoded).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "invalid_token".to_string(),
                message: "Invalid JWT claims".to_string(),
            }),
        )
    })?;

    // Extract claims
    let user_id = claims["sub"]
        .as_str()
        .unwrap_or(&request.username)
        .to_string();
    let tenant_id = claims["tenant_id"]
        .as_str()
        .or(request.tenant_hint.as_deref())
        .unwrap_or("default")
        .to_string();
    let exp = claims["exp"].as_i64();

    // Check expiration
    if let Some(exp_time) = exp {
        let now = chrono::Utc::now().timestamp();
        if exp_time < now {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(AuthError {
                    error: "token_expired".to_string(),
                    message: "JWT token has expired".to_string(),
                }),
            ));
        }
    }

    info!(user_id = %user_id, tenant_id = %tenant_id, "JWT validated");

    Ok(Json(ValidateResponse {
        user_id: user_id.clone(),
        principal_type: claims["principal_type"]
            .as_str()
            .unwrap_or("user")
            .to_string(),
        tenant_id,
        tenant_name: claims["tenant_name"].as_str().map(String::from),
        display_name: claims["name"].as_str().map(String::from),
        email: claims["email"].as_str().map(String::from),
        groups: claims["groups"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        permissions: claims["scopes"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_else(|| vec!["read".to_string(), "query".to_string()]),
        expires_at: exp,
        attributes: None,
    }))
}

/// Validate a Personal Access Token
async fn validate_personal_access_token(
    _state: &AppState,
    request: &ValidateRequest,
) -> Result<Json<ValidateResponse>, (StatusCode, Json<AuthError>)> {
    let token = &request.credential;

    if !token.starts_with("pat_") {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "invalid_token".to_string(),
                message: "Invalid PAT format".to_string(),
            }),
        ));
    }

    // TODO: Look up PAT in database
    // For now, return mock response

    let tenant_id = request
        .tenant_hint
        .clone()
        .unwrap_or_else(|| "default".to_string());

    warn!("PAT validation not fully implemented - using mock response");

    Ok(Json(ValidateResponse {
        user_id: request.username.clone(),
        principal_type: "user".to_string(),
        tenant_id,
        tenant_name: None,
        display_name: Some(request.username.clone()),
        email: None,
        groups: vec![],
        permissions: vec!["read".to_string(), "query".to_string()],
        expires_at: None,
        attributes: None,
    }))
}

/// Validate a Service Account Key
async fn validate_service_account_key(
    _state: &AppState,
    request: &ValidateRequest,
) -> Result<Json<ValidateResponse>, (StatusCode, Json<AuthError>)> {
    let token = &request.credential;

    if !token.starts_with("sak_") {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "invalid_token".to_string(),
                message: "Invalid service account key format".to_string(),
            }),
        ));
    }

    // TODO: Look up service account key in database
    // For now, return mock response

    let tenant_id = request
        .tenant_hint
        .clone()
        .unwrap_or_else(|| "default".to_string());

    warn!("Service account key validation not fully implemented - using mock response");

    Ok(Json(ValidateResponse {
        user_id: request.username.clone(),
        principal_type: "service_account".to_string(),
        tenant_id,
        tenant_name: None,
        display_name: Some(format!("Service: {}", request.username)),
        email: None,
        groups: vec![],
        permissions: vec!["read".to_string(), "query".to_string(), "write".to_string()],
        expires_at: None,
        attributes: None,
    }))
}

/// Validate an API key
async fn validate_api_key(
    _state: &AppState,
    request: &ValidateRequest,
) -> Result<Json<ValidateResponse>, (StatusCode, Json<AuthError>)> {
    let key = &request.credential;

    if !key.starts_with("sk_") && !key.starts_with("tvn_") {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "invalid_token".to_string(),
                message: "Invalid API key format".to_string(),
            }),
        ));
    }

    // TODO: Look up API key in database
    // For now, return mock response

    let tenant_id = request
        .tenant_hint
        .clone()
        .unwrap_or_else(|| "default".to_string());

    warn!("API key validation not fully implemented - using mock response");

    Ok(Json(ValidateResponse {
        user_id: request.username.clone(),
        principal_type: "api_key".to_string(),
        tenant_id,
        tenant_name: None,
        display_name: None,
        email: None,
        groups: vec![],
        permissions: vec!["read".to_string()],
        expires_at: None,
        attributes: None,
    }))
}

/// Validate username/password
async fn validate_password(
    state: &AppState,
    request: &ValidateRequest,
) -> Result<Json<ValidateResponse>, (StatusCode, Json<AuthError>)> {
    // Extract tenant from email domain or hint
    let tenant_id = if let Some(hint) = &request.tenant_hint {
        hint.clone()
    } else if request.username.contains('@') {
        // Extract domain from email: user@company.com -> company
        request
            .username
            .split('@')
            .nth(1)
            .and_then(|domain| domain.split('.').next())
            .map(String::from)
            .unwrap_or_else(|| "default".to_string())
    } else {
        "default".to_string()
    };

    let username = &request.username;
    let password = &request.credential;

    // First, try to find user by email and verify password
    let stored_creds: Option<(String, String)> = sqlx::query_as(
        r#"
        SELECT uc.user_id, uc.password_hash
        FROM user_credentials uc
        WHERE uc.user_id IN (
            SELECT id::text FROM users WHERE email = $1
            UNION
            SELECT $1  -- Also try direct user_id lookup
        )
        AND (uc.locked_until IS NULL OR uc.locked_until < NOW())
        AND (uc.expires_at IS NULL OR uc.expires_at > NOW())
        LIMIT 1
        "#,
    )
    .bind(username)
    .fetch_optional(&state.db_pool)
    .await
    .unwrap_or(None);

    if let Some((user_id, password_hash)) = stored_creds {
        // Verify password using Argon2
        if crate::password::verify_password(password, &password_hash) {
            info!(username = %username, user_id = %user_id, "Password verified successfully");

            // Get user's roles from SpiceDB
            let has_platform_access = state
                .auth_service
                .client()
                .check_permission("platform", "main", "admin", "user", &user_id)
                .await
                .unwrap_or(false);

            let permissions = if has_platform_access {
                vec![
                    "read".to_string(),
                    "write".to_string(),
                    "query".to_string(),
                    "admin".to_string(),
                ]
            } else {
                vec!["read".to_string(), "query".to_string()]
            };

            return Ok(Json(ValidateResponse {
                user_id,
                principal_type: "user".to_string(),
                tenant_id,
                tenant_name: None,
                display_name: Some(username.clone()),
                email: Some(username.clone()),
                groups: if has_platform_access {
                    vec!["admins".to_string()]
                } else {
                    vec![]
                },
                permissions,
                expires_at: None,
                attributes: None,
            }));
        } else {
            // Password mismatch - increment failed attempts
            let _ = sqlx::query(
                "UPDATE user_credentials SET failed_attempts = failed_attempts + 1 WHERE user_id = $1",
            )
            .bind(&user_id)
            .execute(&state.db_pool)
            .await;

            warn!(username = %username, "Invalid password");
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(AuthError {
                    error: "invalid_credentials".to_string(),
                    message: "Invalid username or password".to_string(),
                }),
            ));
        }
    }

    // No stored credentials - check if user exists in database first
    let user_exists: Option<(String, String)> =
        sqlx::query_as("SELECT id::text, display_name FROM users WHERE email = $1 LIMIT 1")
            .bind(username)
            .fetch_optional(&state.db_pool)
            .await
            .unwrap_or(None);

    if let Some((user_id, display_name)) = user_exists {
        // User exists in DB but has no password - check if they have platform access
        let has_platform_access = state
            .auth_service
            .client()
            .check_permission("platform", "main", "admin", "user", &user_id)
            .await
            .unwrap_or(false);

        if has_platform_access {
            // Platform admin without password - warn but allow for initial setup
            warn!(
                username = %username,
                user_id = %user_id,
                "Platform admin authenticated without password - please set a password"
            );

            return Ok(Json(ValidateResponse {
                user_id,
                principal_type: "user".to_string(),
                tenant_id,
                tenant_name: None,
                display_name: Some(display_name),
                email: Some(username.clone()),
                groups: vec!["admins".to_string()],
                permissions: vec![
                    "read".to_string(),
                    "write".to_string(),
                    "query".to_string(),
                    "admin".to_string(),
                ],
                expires_at: None,
                attributes: None,
            }));
        }

        // User exists but no password and no platform access - reject
        warn!(username = %username, "User exists but has no password set");
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "password_required".to_string(),
                message: "Password not set for this user. Contact administrator.".to_string(),
            }),
        ));
    }

    // Check if there are ANY users in the system (first-time setup)
    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db_pool)
        .await
        .unwrap_or((0,));

    if user_count.0 == 0 {
        // No users exist yet - allow super admin setup for first user
        warn!("No users in system - allowing initial access for setup");
        return Ok(Json(ValidateResponse {
            user_id: username.clone(),
            principal_type: "user".to_string(),
            tenant_id,
            tenant_name: None,
            display_name: Some(username.clone()),
            email: Some(username.clone()),
            groups: vec!["admins".to_string()],
            permissions: vec![
                "read".to_string(),
                "write".to_string(),
                "query".to_string(),
                "admin".to_string(),
            ],
            expires_at: None,
            attributes: None,
        }));
    }

    // User not found
    warn!(username = %username, "User not found");
    Err((
        StatusCode::UNAUTHORIZED,
        Json(AuthError {
            error: "invalid_credentials".to_string(),
            message: "Invalid username or password".to_string(),
        }),
    ))
}

/// Validate a token (stateless validation endpoint)
///
/// POST /api/v1/auth/validate-token
///
/// Validates a bearer token from the Authorization header
pub async fn validate_token(
    State(_state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ValidateResponse>, (StatusCode, Json<AuthError>)> {
    // Extract bearer token
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !auth_header.starts_with("Bearer ") {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "unauthorized".to_string(),
                message: "Bearer token required".to_string(),
            }),
        ));
    }

    let token = &auth_header[7..]; // Skip "Bearer "

    // Create a validate request and call validate_jwt
    let request = ValidateRequest {
        username: "token".to_string(),
        credential: token.to_string(),
        credential_type: "jwt".to_string(),
        tenant_hint: None,
        application: None,
        client_ip: None,
    };

    // Decode and validate JWT locally (stateless validation)
    // Parse JWT claims
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "invalid_token".to_string(),
                message: "Invalid JWT format".to_string(),
            }),
        ));
    }

    // Decode payload
    let decoded = base64_decode(parts[1]).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "invalid_token".to_string(),
                message: "Invalid JWT payload".to_string(),
            }),
        )
    })?;

    let claims: serde_json::Value = serde_json::from_slice(&decoded).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "invalid_token".to_string(),
                message: "Invalid JWT claims".to_string(),
            }),
        )
    })?;

    // Extract claims
    let user_id = claims["sub"].as_str().unwrap_or("unknown").to_string();
    let tenant_id = claims["tenant_id"]
        .as_str()
        .unwrap_or("default")
        .to_string();
    let exp = claims["exp"].as_i64();

    // Check expiration
    if let Some(exp_time) = exp {
        let now = chrono::Utc::now().timestamp();
        if exp_time < now {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(AuthError {
                    error: "token_expired".to_string(),
                    message: "JWT token has expired".to_string(),
                }),
            ));
        }
    }

    Ok(Json(ValidateResponse {
        user_id: user_id.clone(),
        principal_type: claims["principal_type"]
            .as_str()
            .unwrap_or("user")
            .to_string(),
        tenant_id,
        tenant_name: claims["tenant_name"].as_str().map(String::from),
        display_name: claims["name"].as_str().map(String::from),
        email: claims["email"].as_str().map(String::from),
        groups: claims["groups"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        permissions: claims["scopes"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_else(|| vec!["read".to_string(), "query".to_string()]),
        expires_at: exp,
        attributes: None,
    }))
}

// Helper function to decode base64url
fn base64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.decode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        let encoded = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let decoded = base64_decode(encoded).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(json["alg"], "HS256");
        assert_eq!(json["typ"], "JWT");
    }
}
