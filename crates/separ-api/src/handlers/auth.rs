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

    // Normalize username (email) to lowercase for case-insensitive login
    let username = request.username.trim().to_lowercase();
    let password = &request.credential;

    // First, try to find user by email and verify password
    // Email lookup is case-insensitive (stored emails are normalized to lowercase)
    let stored_creds: Option<(String, String)> = sqlx::query_as(
        r#"
        SELECT uc.user_id, uc.password_hash
        FROM user_credentials uc
        WHERE uc.user_id IN (
            SELECT id::text FROM users WHERE LOWER(email) = $1
            UNION
            SELECT $1  -- Also try direct user_id lookup
        )
        AND (uc.locked_until IS NULL OR uc.locked_until < NOW())
        AND (uc.expires_at IS NULL OR uc.expires_at > NOW())
        LIMIT 1
        "#,
    )
    .bind(&username)
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
        sqlx::query_as("SELECT id::text, display_name FROM users WHERE LOWER(email) = $1 LIMIT 1")
            .bind(&username)
            .fetch_optional(&state.db_pool)
            .await
            .unwrap_or(None);

    if let Some((_user_id, _display_name)) = user_exists {
        // SECURITY: User exists but has no password - always require password
        // Even platform admins must have a password set
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
    // SECURITY: Even for first-time setup, we don't authenticate without proper credentials
    // The admin must use the admin API to create the first user
    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db_pool)
        .await
        .unwrap_or((0,));

    if user_count.0 == 0 {
        // No users exist - guide them to use admin API
        warn!(
            username = %username,
            "No users in system - use admin API to create first user"
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "no_users".to_string(),
                message: "No users configured. Use the admin API to create the first user."
                    .to_string(),
            }),
        ));
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

// =============================================================================
// Token Issuance (OAuth2 Password Grant)
// =============================================================================

/// Request for token issuance (OAuth2 password grant + Azure SSO)
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    /// Grant type: "password" or "azure_sso"
    pub grant_type: String,
    /// Username (email) for password grant
    #[serde(default)]
    pub username: Option<String>,
    /// Password for password grant
    #[serde(default)]
    pub password: Option<String>,
    /// Azure ID token for azure_sso grant
    #[serde(default)]
    pub id_token: Option<String>,
    /// Nonce for OIDC replay protection (must match nonce in id_token)
    #[serde(default)]
    pub nonce: Option<String>,
    /// Optional tenant hint
    #[serde(default)]
    pub tenant_hint: Option<String>,
}

/// Response from token issuance
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    /// JWT access token
    pub access_token: String,
    /// Refresh token for obtaining new access tokens
    pub refresh_token: String,
    /// Token type (always "Bearer")
    pub token_type: String,
    /// Access token expiry in seconds
    pub expires_in: i64,
    /// User ID
    pub user_id: String,
    /// Tenant ID
    pub tenant_id: String,
}

/// Issue JWT tokens after password validation or Azure SSO
///
/// POST /api/v1/auth/token
///
/// Supported grant types:
/// - "password": OAuth2 password grant (email + password)
/// - "azure_sso": Azure Entra ID SSO (id_token from Azure OIDC/PKCE flow)
pub async fn issue_token(
    State(state): State<AppState>,
    Json(request): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<AuthError>)> {
    match request.grant_type.as_str() {
        "password" => issue_token_password(&state, &request).await,
        "azure_sso" => issue_token_azure_sso(&state, &request).await,
        _ => Err((
            StatusCode::BAD_REQUEST,
            Json(AuthError {
                error: "unsupported_grant_type".to_string(),
                message: format!(
                    "Unsupported grant type '{}'. Use 'password' or 'azure_sso'.",
                    request.grant_type
                ),
            }),
        )),
    }
}

/// Issue tokens via password grant
async fn issue_token_password(
    state: &AppState,
    request: &TokenRequest,
) -> Result<Json<TokenResponse>, (StatusCode, Json<AuthError>)> {
    let username = request.username.as_deref().unwrap_or("");
    let password = request.password.as_deref().unwrap_or("");

    if username.is_empty() || password.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AuthError {
                error: "invalid_request".to_string(),
                message: "username and password are required for password grant".to_string(),
            }),
        ));
    }

    debug!(username = %username, "Processing password token request");

    let validate_req = ValidateRequest {
        username: username.to_string(),
        credential: password.to_string(),
        credential_type: "password".to_string(),
        tenant_hint: request.tenant_hint.clone(),
        application: None,
        client_ip: None,
    };

    let validated = validate_password_internal(state, &validate_req).await?;

    let tokens = state
        .jwt_service
        .generate_tokens(
            &validated.user_id,
            &validated.tenant_id,
            validated.email.as_deref(),
            validated.display_name.as_deref(),
            validated.groups.clone(),
            validated.permissions.clone(),
        )
        .map_err(|e| {
            warn!(error = %e, "Failed to generate tokens");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthError {
                    error: "token_generation_failed".to_string(),
                    message: "Failed to generate authentication tokens".to_string(),
                }),
            )
        })?;

    info!(
        user_id = %validated.user_id,
        tenant_id = %validated.tenant_id,
        "Token issued via password grant"
    );

    Ok(Json(TokenResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_type: tokens.token_type,
        expires_in: tokens.expires_in,
        user_id: validated.user_id,
        tenant_id: validated.tenant_id,
    }))
}

/// SSO Discovery response
#[derive(Debug, Serialize)]
pub struct SsoDiscoveryResponse {
    pub sso_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorize_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
}

/// SSO public config response (no secrets)
#[derive(Debug, Serialize)]
pub struct SsoConfigResponse {
    pub sso_enabled: bool,
    /// The multi-tenant app's client ID (public value)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Default authorize URL for direct SSO (no discovery needed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorize_url: Option<String>,
}

/// Returns the SSO configuration for the frontend.
/// No email required — just tells the client how to initiate SSO.
///
/// GET /api/v1/auth/sso-config
pub async fn sso_config(
    State(state): State<AppState>,
) -> Json<SsoConfigResponse> {
    if state.azure_sso.enabled && !state.azure_sso.app_client_id.is_empty() {
        Json(SsoConfigResponse {
            sso_enabled: true,
            client_id: Some(state.azure_sso.app_client_id.clone()),
            authorize_url: Some("https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize".to_string()),
        })
    } else {
        Json(SsoConfigResponse {
            sso_enabled: false,
            client_id: None,
            authorize_url: None,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct SsoDiscoveryRequest {
    pub email: String,
}

/// SSO Discovery endpoint — determines if an email domain has SSO configured.
/// Used by the frontend when the user has entered an email.
///
/// POST /api/v1/auth/sso-discovery
pub async fn sso_discovery(
    State(state): State<AppState>,
    Json(request): Json<SsoDiscoveryRequest>,
) -> Result<Json<SsoDiscoveryResponse>, (StatusCode, Json<AuthError>)> {
    if !state.azure_sso.enabled {
        return Ok(Json(SsoDiscoveryResponse {
            sso_required: false,
            provider_type: None,
            authorize_url: None,
            client_id: None,
            provider_name: None,
        }));
    }

    let email = request.email.trim().to_lowercase();
    let domain = email.split('@').nth(1).unwrap_or("");
    if domain.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AuthError {
                error: "invalid_email".to_string(),
                message: "Invalid email address".to_string(),
            }),
        ));
    }

    // Look up an enabled identity provider whose domains array contains this domain
    let provider: Option<(String, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT provider_type, id::text, display_name
        FROM identity_providers
        WHERE $1 = ANY(domains)
          AND enabled = true
        ORDER BY priority ASC
        LIMIT 1
        "#,
    )
    .bind(domain)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| {
        warn!(error = %e, "Database error during SSO discovery");
        (StatusCode::INTERNAL_SERVER_ERROR, Json(AuthError {
            error: "database_error".to_string(),
            message: "Internal error during SSO discovery".to_string(),
        }))
    })?;

    match provider {
        Some((provider_type, _provider_id, display_name)) if provider_type == "azure_ad" => {
            // Use /organizations endpoint (restricts to work accounts, safer than /common)
            let authorize_url = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize".to_string();
            Ok(Json(SsoDiscoveryResponse {
                sso_required: true,
                provider_type: Some(provider_type),
                authorize_url: Some(authorize_url),
                client_id: Some(state.azure_sso.app_client_id.clone()),
                provider_name: display_name.or(Some("Microsoft SSO".to_string())),
            }))
        }
        Some((provider_type, _provider_id, display_name)) => {
            // Future: handle okta, google, generic_oidc, etc.
            Ok(Json(SsoDiscoveryResponse {
                sso_required: true,
                provider_type: Some(provider_type),
                authorize_url: None,
                client_id: None,
                provider_name: display_name,
            }))
        }
        None => Ok(Json(SsoDiscoveryResponse {
            sso_required: false,
            provider_type: None,
            authorize_url: None,
            client_id: None,
            provider_name: None,
        })),
    }
}

/// Issue tokens via Azure SSO (Entra ID) — multi-tenant
///
/// Flow:
/// 1. Client obtains Azure ID token via PKCE flow (no secret needed on client)
/// 2. Client sends ID token to this endpoint
/// 3. Separ extracts `tid` claim → looks up registered identity provider in DB
/// 4. Separ validates the ID token signature via per-tenant JWKS cache
/// 5. Separ JIT provisions or links user by email
/// 6. Separ issues its own JWT tokens
async fn issue_token_azure_sso(
    state: &AppState,
    request: &TokenRequest,
) -> Result<Json<TokenResponse>, (StatusCode, Json<AuthError>)> {
    if !state.azure_sso.enabled {
        return Err((StatusCode::BAD_REQUEST, Json(AuthError {
            error: "sso_disabled".to_string(),
            message: "Azure SSO is not enabled on this server".to_string(),
        })));
    }

    let id_token = request.id_token.as_deref().unwrap_or("");
    if id_token.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(AuthError {
            error: "invalid_request".to_string(),
            message: "id_token is required for azure_sso grant".to_string(),
        })));
    }

    debug!("Processing Azure SSO token request");

    // =========================================================================
    // Step 1: Pre-parse the ID token to extract tid (before full validation)
    // =========================================================================
    let pre_claims = pre_parse_jwt_claims(id_token).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(AuthError {
            error: "invalid_id_token".to_string(),
            message: format!("Cannot parse ID token: {}", e),
        }))
    })?;

    let token_tid = pre_claims.get("tid").and_then(|v| v.as_str()).unwrap_or("");
    if token_tid.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(AuthError {
            error: "invalid_id_token".to_string(),
            message: "ID token missing 'tid' (tenant ID) claim".to_string(),
        })));
    }

    // =========================================================================
    // Step 1b: Look up the identity provider by Azure tenant ID in DB
    // =========================================================================
    let provider_row: Option<(uuid::Uuid, uuid::Uuid)> = sqlx::query_as(
        r#"
        SELECT id, tenant_id
        FROM identity_providers
        WHERE provider_type = 'azure_ad'
          AND enabled = true
          AND (
            config->>'azure_tenant_id' = $1
            OR $1 = ANY(domains)
          )
        LIMIT 1
        "#,
    )
    .bind(token_tid)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| {
        warn!(error = %e, "Database error looking up identity provider");
        (StatusCode::INTERNAL_SERVER_ERROR, Json(AuthError {
            error: "database_error".to_string(),
            message: "Internal error during authentication".to_string(),
        }))
    })?;

    let (provider_id, provider_tenant_id) = provider_row.ok_or_else(|| {
        warn!(tid = %token_tid, "No registered identity provider for Azure tenant");
        (StatusCode::UNAUTHORIZED, Json(AuthError {
            error: "unknown_tenant".to_string(),
            message: "Your organization is not registered for SSO. Contact your administrator.".to_string(),
        }))
    })?;

    // =========================================================================
    // Step 1c: Validate the ID token with per-tenant JWKS cache
    // =========================================================================
    let azure_claims = validate_azure_id_token_cached(
        id_token,
        token_tid,
        &state.azure_sso.app_client_id,
        &state.jwks_cache,
    )
    .await
    .map_err(|e| {
        warn!(error = %e, "Azure ID token validation failed");
        (StatusCode::UNAUTHORIZED, Json(AuthError {
            error: "invalid_id_token".to_string(),
            message: format!("Azure ID token validation failed: {}", e),
        }))
    })?;

    // =========================================================================
    // Step 1d: Validate nonce if provided (OIDC replay protection)
    // =========================================================================
    if let Some(expected_nonce) = &request.nonce {
        let token_nonce = azure_claims
            .get("nonce")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if token_nonce != expected_nonce.as_str() {
            warn!("Nonce mismatch: possible token replay attack");
            return Err((StatusCode::UNAUTHORIZED, Json(AuthError {
                error: "nonce_mismatch".to_string(),
                message: "ID token nonce does not match expected value".to_string(),
            })));
        }
    }

    // =========================================================================
    // Step 1e: Extract user info from Azure claims
    // =========================================================================
    let azure_oid = azure_claims
        .get("oid")
        .or_else(|| azure_claims.get("sub"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let azure_email = azure_claims
        .get("email")
        .or_else(|| azure_claims.get("upn"))
        .or_else(|| azure_claims.get("preferred_username"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    let azure_name = azure_claims
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if azure_oid.is_empty() || azure_email.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(AuthError {
            error: "incomplete_claims".to_string(),
            message: "Azure ID token missing required claims (oid/sub, email/upn)".to_string(),
        })));
    }

    // Verify email domain matches the provider's registered domains (defense-in-depth)
    let email_domain = azure_email.split('@').nth(1).unwrap_or("");
    let domain_ok: bool = sqlx::query_scalar(
        "SELECT $1 = ANY(domains) FROM identity_providers WHERE id = $2",
    )
    .bind(email_domain)
    .bind(provider_id)
    .fetch_optional(&state.db_pool)
    .await
    .unwrap_or(None)
    .unwrap_or(false);

    if !domain_ok {
        warn!(
            email_domain = %email_domain,
            provider_id = %provider_id,
            "Email domain does not match registered provider domains"
        );
        return Err((StatusCode::UNAUTHORIZED, Json(AuthError {
            error: "domain_mismatch".to_string(),
            message: "Your email domain is not authorized for this SSO provider".to_string(),
        })));
    }

    info!(
        azure_oid = %azure_oid,
        azure_email = %azure_email,
        azure_name = %azure_name,
        provider_id = %provider_id,
        "Azure ID token validated (multi-tenant)"
    );

    // =========================================================================
    // Step 2: Find or create Separ user (JIT provisioning + account linking)
    // =========================================================================
    let existing_by_oid: Option<(String,)> = sqlx::query_as(
        "SELECT separ_user_id::text FROM identity_user_mappings WHERE external_id = $1 LIMIT 1",
    )
    .bind(&azure_oid)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| {
        warn!(error = %e, "Database error looking up identity mapping");
        (StatusCode::INTERNAL_SERVER_ERROR, Json(AuthError {
            error: "database_error".to_string(),
            message: "Internal error during authentication".to_string(),
        }))
    })?;

    let (user_id, tenant_id) = if let Some((existing_user_id,)) = existing_by_oid {
        info!(user_id = %existing_user_id, "Found existing SSO-linked user");
        let tenant_id: String = sqlx::query_scalar(
            "SELECT COALESCE(tenant_id::text, $2) FROM users WHERE id = $1::uuid",
        )
        .bind(uuid::Uuid::parse_str(&existing_user_id).unwrap())
        .bind(provider_tenant_id.to_string())
        .fetch_optional(&state.db_pool)
        .await
        .map_err(|e| {
            warn!(error = %e, "Database error fetching user tenant");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(AuthError {
                error: "database_error".to_string(),
                message: "Internal error during authentication".to_string(),
            }))
        })?
        .unwrap_or_else(|| provider_tenant_id.to_string());

        (existing_user_id, tenant_id)
    } else {
        // Try email-based linking
        let existing_by_email: Option<(String, Option<uuid::Uuid>)> = sqlx::query_as(
            "SELECT id::text, tenant_id FROM users WHERE LOWER(email) = $1 LIMIT 1",
        )
        .bind(&azure_email)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(|e| {
            warn!(error = %e, "Database error looking up user by email");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(AuthError {
                error: "database_error".to_string(),
                message: "Internal error during authentication".to_string(),
            }))
        })?;

        if let Some((existing_user_id, tenant_uuid)) = existing_by_email {
            info!(user_id = %existing_user_id, azure_oid = %azure_oid, "Linking existing user to Azure SSO by email");
            let effective_tenant = tenant_uuid.unwrap_or(provider_tenant_id);

            // Assign tenant if user has none
            if tenant_uuid.is_none() {
                let _ = sqlx::query("UPDATE users SET tenant_id = $1 WHERE id = $2::uuid")
                    .bind(effective_tenant)
                    .bind(uuid::Uuid::parse_str(&existing_user_id).unwrap())
                    .execute(&state.db_pool)
                    .await;
            }

            sqlx::query(
                r#"INSERT INTO identity_user_mappings (tenant_id, provider_id, external_id, separ_user_id, created_at, updated_at)
                   VALUES ($1, $2, $3, $4::uuid, NOW(), NOW()) ON CONFLICT DO NOTHING"#,
            )
            .bind(effective_tenant)
            .bind(provider_id)
            .bind(&azure_oid)
            .bind(uuid::Uuid::parse_str(&existing_user_id).unwrap())
            .execute(&state.db_pool)
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to create identity mapping");
                (StatusCode::INTERNAL_SERVER_ERROR, Json(AuthError {
                    error: "database_error".to_string(),
                    message: "Failed to link Azure identity".to_string(),
                }))
            })?;

            (existing_user_id, effective_tenant.to_string())
        } else {
            // JIT provision new user
            info!(azure_email = %azure_email, azure_oid = %azure_oid, "JIT provisioning new user from Azure SSO");
            let new_user_id = uuid::Uuid::new_v4();
            let new_user_id_str = new_user_id.to_string();

            sqlx::query(
                r#"INSERT INTO users (id, email, display_name, tenant_id, status, email_verified, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, 'active', true, NOW(), NOW())"#,
            )
            .bind(new_user_id)
            .bind(&azure_email)
            .bind(&azure_name)
            .bind(provider_tenant_id)
            .execute(&state.db_pool)
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to create SSO user");
                (StatusCode::INTERNAL_SERVER_ERROR, Json(AuthError {
                    error: "user_creation_failed".to_string(),
                    message: "Failed to create user from SSO".to_string(),
                }))
            })?;

            sqlx::query(
                r#"INSERT INTO identity_user_mappings (tenant_id, provider_id, external_id, separ_user_id, created_at, updated_at)
                   VALUES ($1, $2, $3, $4, NOW(), NOW())"#,
            )
            .bind(provider_tenant_id)
            .bind(provider_id)
            .bind(&azure_oid)
            .bind(new_user_id)
            .execute(&state.db_pool)
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to create identity mapping");
                (StatusCode::INTERNAL_SERVER_ERROR, Json(AuthError {
                    error: "database_error".to_string(),
                    message: "Failed to create identity mapping".to_string(),
                }))
            })?;

            // Create personal workspace
            let workspace_id = uuid::Uuid::new_v4();
            let workspace_slug = format!("personal-{}", new_user_id_str.chars().take(8).collect::<String>());
            let _ = sqlx::query(
                r#"INSERT INTO workspaces (id, tenant_id, owner_user_id, name, slug, description, workspace_type, created_at, updated_at)
                   VALUES ($1, NULL, $2, 'My Workspace', $3, 'Personal workspace', 'personal', NOW(), NOW())"#,
            )
            .bind(workspace_id).bind(new_user_id).bind(&workspace_slug)
            .execute(&state.db_pool).await;

            let _ = sqlx::query(
                "INSERT INTO workspace_members (workspace_id, user_id, role, joined_at) VALUES ($1, $2, 'owner', NOW())",
            )
            .bind(workspace_id).bind(new_user_id)
            .execute(&state.db_pool).await;

            // SpiceDB relationships (non-fatal)
            let _ = state.auth_service.client()
                .write_relationship("workspace", &workspace_id.to_string(), "owner", "user", &new_user_id_str)
                .await;

            (new_user_id_str, provider_tenant_id.to_string())
        }
    };

    // =========================================================================
    // Step 3: Issue Separ JWT tokens
    // =========================================================================
    let has_platform_access = state.auth_service.client()
        .check_permission("platform", "main", "admin", "user", &user_id)
        .await.unwrap_or(false);

    let permissions = if has_platform_access {
        vec!["read".to_string(), "write".to_string(), "query".to_string(), "admin".to_string()]
    } else {
        vec!["read".to_string(), "query".to_string()]
    };
    let groups = if has_platform_access { vec!["admins".to_string()] } else { vec![] };

    let tokens = state.jwt_service.generate_tokens(
        &user_id, &tenant_id, Some(&azure_email),
        if azure_name.is_empty() { None } else { Some(&azure_name) },
        groups, permissions,
    ).map_err(|e| {
        warn!(error = %e, "Failed to generate tokens for SSO user");
        (StatusCode::INTERNAL_SERVER_ERROR, Json(AuthError {
            error: "token_generation_failed".to_string(),
            message: "Failed to generate authentication tokens".to_string(),
        }))
    })?;

    info!(user_id = %user_id, azure_oid = %azure_oid, "Token issued via Azure SSO");
    Ok(Json(TokenResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_type: tokens.token_type,
        expires_in: tokens.expires_in,
        user_id,
        tenant_id,
    }))
}

/// Pre-parse JWT claims without validation (to extract tid for provider lookup)
fn pre_parse_jwt_claims(token: &str) -> Result<serde_json::Value, String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("Invalid JWT payload encoding: {}", e))?;
    serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("Invalid JWT payload JSON: {}", e))
}

// =============================================================================
// Per-Tenant JWKS Cache
// =============================================================================

/// Per-tenant JWKS cache: azure_tenant_id -> JwksCacheEntry
pub type PerTenantJwksCache = std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, JwksCacheEntry>>>;

pub struct JwksCacheEntry {
    pub keys: std::collections::HashMap<String, (String, String)>,
    pub fetched_at: std::time::Instant,
}

impl JwksCacheEntry {
    pub fn is_stale(&self) -> bool {
        self.fetched_at.elapsed() > std::time::Duration::from_secs(3600)
    }
}

/// Fetch JWKS from Azure for a specific tenant and update the per-tenant cache
async fn refresh_jwks_for_tenant(
    azure_tenant_id: &str,
    cache: &PerTenantJwksCache,
) -> Result<(), String> {
    let jwks_url = format!(
        "https://login.microsoftonline.com/{}/discovery/v2.0/keys",
        azure_tenant_id
    );
    debug!("Fetching Azure JWKS from {}", jwks_url);

    let jwks_response = reqwest::get(&jwks_url)
        .await
        .map_err(|e| format!("Failed to fetch Azure JWKS: {}", e))?;
    let jwks: serde_json::Value = jwks_response
        .json()
        .await
        .map_err(|e| format!("Failed to parse Azure JWKS: {}", e))?;

    let keys = jwks.get("keys").and_then(|v| v.as_array())
        .ok_or("JWKS missing 'keys' array")?;

    let mut key_map = std::collections::HashMap::new();
    for key in keys {
        if let (Some(kid), Some(n), Some(e)) = (
            key.get("kid").and_then(|v| v.as_str()),
            key.get("n").and_then(|v| v.as_str()),
            key.get("e").and_then(|v| v.as_str()),
        ) {
            key_map.insert(kid.to_string(), (n.to_string(), e.to_string()));
        }
    }

    let mut cache_map = cache.write().await;
    cache_map.insert(azure_tenant_id.to_string(), JwksCacheEntry {
        keys: key_map,
        fetched_at: std::time::Instant::now(),
    });
    debug!("Azure JWKS cache updated for tenant {}", azure_tenant_id);

    Ok(())
}

/// Validate an Azure AD ID token with per-tenant JWKS caching
async fn validate_azure_id_token_cached(
    id_token: &str,
    azure_tenant_id: &str,
    app_client_id: &str,
    jwks_cache: &PerTenantJwksCache,
) -> Result<serde_json::Value, String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| format!("Invalid JWT header encoding: {}", e))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("Invalid JWT header JSON: {}", e))?;
    let kid = header.get("kid").and_then(|v| v.as_str())
        .ok_or("JWT header missing 'kid'")?.to_string();

    // Try to get key from per-tenant cache
    let rsa_components = {
        let cache = jwks_cache.read().await;
        cache.get(azure_tenant_id).and_then(|entry| {
            if !entry.is_stale() { entry.keys.get(&kid).cloned() } else { None }
        })
    };

    let (n, e) = if let Some(components) = rsa_components {
        components
    } else {
        refresh_jwks_for_tenant(azure_tenant_id, jwks_cache).await?;
        let cache = jwks_cache.read().await;
        cache.get(azure_tenant_id)
            .and_then(|entry| entry.keys.get(&kid).cloned())
            .ok_or_else(|| format!("No JWKS key found for kid '{}' (tenant {})", kid, azure_tenant_id))?
    };

    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(&n, &e)
        .map_err(|e| format!("Failed to create decoding key: {}", e))?;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&[format!("https://login.microsoftonline.com/{}/v2.0", azure_tenant_id)]);
    validation.set_audience(&[app_client_id]);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = 120;

    let token_data = jsonwebtoken::decode::<serde_json::Value>(id_token, &decoding_key, &validation)
        .map_err(|e| format!("Token validation failed: {}", e))?;

    Ok(token_data.claims)
}

/// JWKS endpoint for external services to verify tokens
///
/// GET /.well-known/jwks.json
///
/// Returns the JSON Web Key Set for token signature verification.
/// Yekta uses this to verify JWT signatures without calling Separ on every request.
pub async fn jwks(State(state): State<AppState>) -> Json<separ_oauth::jwt::JwksResponse> {
    Json(state.jwt_service.get_jwks())
}

/// Internal password validation that returns ValidateResponse directly
/// (not wrapped in Json for internal use)
async fn validate_password_internal(
    state: &AppState,
    request: &ValidateRequest,
) -> Result<ValidateResponse, (StatusCode, Json<AuthError>)> {
    // Extract tenant from email domain or hint
    let tenant_id = if let Some(hint) = &request.tenant_hint {
        hint.clone()
    } else if request.username.contains('@') {
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

    // Normalize username (email) to lowercase for case-insensitive login
    let username = request.username.trim().to_lowercase();
    let password = &request.credential;

    // First, try to find user by email and verify password
    // Email lookup is case-insensitive (stored emails are normalized to lowercase)
    let stored_creds: Option<(String, String)> = sqlx::query_as(
        r#"
        SELECT uc.user_id, uc.password_hash
        FROM user_credentials uc
        WHERE uc.user_id IN (
            SELECT id::text FROM users WHERE LOWER(email) = $1
            UNION
            SELECT $1
        )
        AND (uc.locked_until IS NULL OR uc.locked_until < NOW())
        AND (uc.expires_at IS NULL OR uc.expires_at > NOW())
        LIMIT 1
        "#,
    )
    .bind(&username)
    .fetch_optional(&state.db_pool)
    .await
    .unwrap_or(None);

    if let Some((user_id, password_hash)) = stored_creds {
        if crate::password::verify_password(password, &password_hash) {
            info!(username = %username, user_id = %user_id, "Password verified for token issuance");

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

            return Ok(ValidateResponse {
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
            });
        } else {
            let _ = sqlx::query(
                "UPDATE user_credentials SET failed_attempts = failed_attempts + 1 WHERE user_id = $1",
            )
            .bind(&user_id)
            .execute(&state.db_pool)
            .await;

            warn!(username = %username, "Invalid password for token request");
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(AuthError {
                    error: "invalid_credentials".to_string(),
                    message: "Invalid username or password".to_string(),
                }),
            ));
        }
    }

    // Check if user exists but has no password
    let user_exists: Option<(String, String)> =
        sqlx::query_as("SELECT id::text, display_name FROM users WHERE LOWER(email) = $1 LIMIT 1")
            .bind(&username)
            .fetch_optional(&state.db_pool)
            .await
            .unwrap_or(None);

    if let Some((_user_id, _display_name)) = user_exists {
        // SECURITY: User exists but has no password - always require password
        // Even platform admins must have a password set
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
    // SECURITY: Even for first-time setup, we don't issue tokens without proper setup
    // The admin must use the /api/v1/auth/register endpoint first
    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db_pool)
        .await
        .unwrap_or((0,));

    if user_count.0 == 0 {
        // No users exist - guide them to register first
        warn!(
            username = %username,
            "No users in system - use /api/v1/auth/register to create first user"
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "no_users".to_string(),
                message: "No users configured. Use the admin API to create the first user."
                    .to_string(),
            }),
        ));
    }

    warn!(username = %username, "User not found for token request");
    Err((
        StatusCode::UNAUTHORIZED,
        Json(AuthError {
            error: "invalid_credentials".to_string(),
            message: "Invalid username or password".to_string(),
        }),
    ))
}

// =============================================================================
// User Self-Registration (for desktop apps like Hormoz)
// =============================================================================

/// Request for user self-registration
#[derive(Debug, Deserialize)]
pub struct RegisterUserRequest {
    /// Email address (will be username)
    pub email: String,
    /// Password (minimum 12 characters)
    pub password: String,
    /// Display name
    pub display_name: String,
    /// Optional tenant hint
    #[serde(default)]
    pub tenant_hint: Option<String>,
}

/// Response from user registration
#[derive(Debug, Serialize)]
pub struct RegisterUserResponse {
    pub success: bool,
    pub user_id: String,
    pub workspace_id: String,
    pub message: Option<String>,
}

/// Register a new user (self-service)
///
/// POST /api/v1/auth/register
///
/// This endpoint allows users to self-register from desktop apps like Hormoz.
///
/// ## Workspace-First Model
/// - Creates a new user WITHOUT assigning to a tenant
/// - Creates a personal workspace for the user (user is owner)
/// - Tenants are only created when a domain is claimed by platform admin
pub async fn register_user(
    State(state): State<AppState>,
    Json(request): Json<RegisterUserRequest>,
) -> Result<Json<RegisterUserResponse>, (StatusCode, Json<AuthError>)> {
    // Normalize email to lowercase for consistent storage and lookup
    let normalized_email = request.email.trim().to_lowercase();

    // Validate email format
    if !normalized_email.contains('@') || !normalized_email.contains('.') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AuthError {
                error: "invalid_email".to_string(),
                message: "Invalid email format".to_string(),
            }),
        ));
    }

    // Validate password strength
    if request.password.len() < 12 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AuthError {
                error: "weak_password".to_string(),
                message: "Password must be at least 12 characters".to_string(),
            }),
        ));
    }

    // Check if user already exists (case-insensitive via normalized email)
    let existing_user: Option<(String,)> =
        sqlx::query_as("SELECT id::text FROM users WHERE LOWER(email) = $1 LIMIT 1")
            .bind(&normalized_email)
            .fetch_optional(&state.db_pool)
            .await
            .unwrap_or(None);

    if existing_user.is_some() {
        return Err((
            StatusCode::CONFLICT,
            Json(AuthError {
                error: "user_exists".to_string(),
                message: "User already exists".to_string(),
            }),
        ));
    }

    // =========================================================================
    // WORKSPACE-FIRST MODEL
    // =========================================================================
    // 1. Create user WITHOUT tenant (tenant_id = NULL)
    // 2. Create personal workspace for user
    // 3. User owns their workspace
    // 4. No tenant governance until domain is claimed by platform admin
    // =========================================================================

    // Create user ID
    let user_id = separ_core::UserId::new();
    let user_id_str = user_id.to_string();

    info!(
        email = %normalized_email,
        user_id = %user_id_str,
        "Registering new user (workspace-first model)"
    );

    // Hash the password
    let password_hash = crate::password::hash_password(&request.password).map_err(|e| {
        warn!("Failed to hash password: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuthError {
                error: "registration_failed".to_string(),
                message: "Failed to process registration".to_string(),
            }),
        )
    })?;

    // Insert user into database WITHOUT tenant (tenant_id = NULL)
    // Email is stored in normalized (lowercase) form
    let result = sqlx::query(
        r#"
        INSERT INTO users (id, email, display_name, tenant_id, status, created_at, updated_at)
        VALUES ($1::uuid, $2, $3, NULL, 'active', NOW(), NOW())
        "#,
    )
    .bind(uuid::Uuid::parse_str(&user_id_str).unwrap())
    .bind(&normalized_email)
    .bind(&request.display_name)
    .execute(&state.db_pool)
    .await;

    if let Err(e) = result {
        warn!("Failed to create user: {}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuthError {
                error: "registration_failed".to_string(),
                message: format!("Failed to create user: {}", e),
            }),
        ));
    }

    // Store password hash
    let cred_result = sqlx::query(
        r#"
        INSERT INTO user_credentials (user_id, password_hash, created_at, updated_at)
        VALUES ($1, $2, NOW(), NOW())
        "#,
    )
    .bind(&user_id_str)
    .bind(&password_hash)
    .execute(&state.db_pool)
    .await;

    if let Err(e) = cred_result {
        warn!("Failed to store credentials: {}", e);
        // Rollback user creation
        let _ = sqlx::query("DELETE FROM users WHERE id = $1::uuid")
            .bind(uuid::Uuid::parse_str(&user_id_str).unwrap())
            .execute(&state.db_pool)
            .await;
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuthError {
                error: "registration_failed".to_string(),
                message: "Failed to store credentials".to_string(),
            }),
        ));
    }

    // Create personal workspace for user
    let workspace_id = uuid::Uuid::new_v4();
    let workspace_id_str = workspace_id.to_string();
    let workspace_slug = format!(
        "personal-{}",
        user_id_str.chars().take(8).collect::<String>()
    );

    let workspace_result = sqlx::query(
        r#"
        INSERT INTO workspaces (id, tenant_id, owner_user_id, name, slug, description, workspace_type, created_at, updated_at)
        VALUES ($1, NULL, $2::uuid, 'My Workspace', $3, 'Personal workspace', 'personal', NOW(), NOW())
        "#,
    )
    .bind(workspace_id)
    .bind(uuid::Uuid::parse_str(&user_id_str).unwrap())
    .bind(&workspace_slug)
    .execute(&state.db_pool)
    .await;

    if let Err(e) = workspace_result {
        warn!("Failed to create personal workspace: {}", e);
        // Continue - user is still created, workspace creation is not critical
    } else {
        // Add user as owner of workspace in workspace_members table
        let _ = sqlx::query(
            r#"
            INSERT INTO workspace_members (workspace_id, user_id, role, joined_at)
            VALUES ($1, $2::uuid, 'owner', NOW())
            "#,
        )
        .bind(workspace_id)
        .bind(uuid::Uuid::parse_str(&user_id_str).unwrap())
        .execute(&state.db_pool)
        .await;

        // Create workspace ownership in SpiceDB
        let _ = state
            .auth_service
            .client()
            .write_relationship(
                "workspace",
                &workspace_id_str,
                "owner",
                "user",
                &user_id_str,
            )
            .await;
    }

    info!(
        email = %request.email,
        user_id = %user_id_str,
        workspace_id = %workspace_id_str,
        "User registered with personal workspace"
    );

    Ok(Json(RegisterUserResponse {
        success: true,
        user_id: user_id_str,
        workspace_id: workspace_id_str,
        message: Some("User registered successfully".to_string()),
    }))
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

    #[test]
    fn test_token_request_deserialization() {
        let json = r#"{
            "grant_type": "password",
            "username": "test@example.com",
            "password": "secret123"
        }"#;

        let request: TokenRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.grant_type, "password");
        assert_eq!(request.username, "test@example.com");
        assert_eq!(request.password, "secret123");
        assert!(request.tenant_hint.is_none());
    }

    #[test]
    fn test_token_request_with_tenant_hint() {
        let json = r#"{
            "grant_type": "password",
            "username": "test@example.com",
            "password": "secret123",
            "tenant_hint": "my-tenant"
        }"#;

        let request: TokenRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.tenant_hint, Some("my-tenant".to_string()));
    }

    #[test]
    fn test_token_response_serialization() {
        let response = TokenResponse {
            access_token: "access.token.here".to_string(),
            refresh_token: "refresh.token.here".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            user_id: "user_123".to_string(),
            tenant_id: "tenant_456".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("access_token"));
        assert!(json.contains("refresh_token"));
        assert!(json.contains("Bearer"));
        assert!(json.contains("3600"));
        assert!(json.contains("user_123"));
        assert!(json.contains("tenant_456"));
    }
}
