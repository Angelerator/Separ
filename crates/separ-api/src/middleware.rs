//! API middleware for authentication, logging, and more

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::sync::Arc;
use tracing::{debug, info, warn};

use separ_core::{TenantId, UserId};
use separ_oauth::JwtService;

/// Authenticated user context
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user_id: UserId,
    pub tenant_id: Option<TenantId>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub scopes: Vec<String>,
    pub auth_method: AuthMethod,
}

/// How the request was authenticated
#[derive(Debug, Clone, PartialEq)]
pub enum AuthMethod {
    AdminApiKey,
    ServiceApiKey,
    JwtToken,
    Internal,
}

/// Error response for auth failures
#[derive(Debug, Serialize)]
pub struct AuthError {
    error: String,
    message: String,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let body = Json(self);
        (StatusCode::UNAUTHORIZED, body).into_response()
    }
}

// =============================================================================
// Admin API Key Middleware (for bootstrap/management operations)
// =============================================================================

/// Validates admin API key from environment variable
/// Use this for sensitive management endpoints
pub async fn require_admin_api_key(
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<AuthError>)> {
    let admin_key = std::env::var("SEPAR_ADMIN_API_KEY").ok();

    // If no admin key is configured, reject all requests
    let expected_key = match admin_key {
        Some(key) if !key.is_empty() => key,
        _ => {
            warn!("SEPAR_ADMIN_API_KEY not configured - admin endpoints disabled");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(AuthError {
                    error: "admin_not_configured".to_string(),
                    message: "Admin API key not configured. Set SEPAR_ADMIN_API_KEY environment variable.".to_string(),
                }),
            ));
        }
    };

    // Check X-Admin-Key header
    let provided_key = request
        .headers()
        .get("X-Admin-Key")
        .and_then(|h| h.to_str().ok());

    match provided_key {
        Some(key) if key == expected_key => {
            debug!("Admin API key validated successfully");
            Ok(next.run(request).await)
        }
        Some(_) => {
            warn!("Invalid admin API key provided");
            Err((
                StatusCode::UNAUTHORIZED,
                Json(AuthError {
                    error: "invalid_admin_key".to_string(),
                    message: "Invalid admin API key".to_string(),
                }),
            ))
        }
        None => {
            warn!("Missing X-Admin-Key header for admin endpoint");
            Err((
                StatusCode::UNAUTHORIZED,
                Json(AuthError {
                    error: "missing_admin_key".to_string(),
                    message: "X-Admin-Key header required for admin operations".to_string(),
                }),
            ))
        }
    }
}

// =============================================================================
// Service API Key Middleware (for service-to-service auth)
// =============================================================================

/// Validates service API key
/// Services get an API key when registered
pub async fn require_service_api_key(
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<AuthError>)> {
    let api_key = request
        .headers()
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok());

    match api_key {
        Some(key) if key.len() >= 32 => {
            // In production, validate against SpiceDB/database
            // For now, accept any well-formed key
            let prefix = &key[..8];
            debug!("Service API key validated: {}...", prefix);
            Ok(next.run(request).await)
        }
        Some(_) => {
            warn!("Invalid API key format");
            Err((
                StatusCode::UNAUTHORIZED,
                Json(AuthError {
                    error: "invalid_api_key".to_string(),
                    message: "Invalid API key format".to_string(),
                }),
            ))
        }
        None => {
            warn!("Missing X-API-Key header");
            Err((
                StatusCode::UNAUTHORIZED,
                Json(AuthError {
                    error: "missing_api_key".to_string(),
                    message: "X-API-Key header required".to_string(),
                }),
            ))
        }
    }
}

// =============================================================================
// Combined Auth Middleware (Admin Key OR Service Key)
// =============================================================================

/// Accepts either admin API key or service API key
pub async fn require_api_key(
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<AuthError>)> {
    // Check for admin key first
    let admin_key = std::env::var("SEPAR_ADMIN_API_KEY").ok();
    let provided_admin_key = request
        .headers()
        .get("X-Admin-Key")
        .and_then(|h| h.to_str().ok());

    if let (Some(expected), Some(provided)) = (&admin_key, provided_admin_key) {
        if !expected.is_empty() && expected == provided {
            debug!("Authenticated via admin API key");
            return Ok(next.run(request).await);
        }
    }

    // Check for service API key
    let service_key = request
        .headers()
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok());

    if let Some(key) = service_key {
        if key.len() >= 32 {
            // TODO: Validate against database/SpiceDB
            debug!("Authenticated via service API key: {}...", &key[..8]);
            return Ok(next.run(request).await);
        }
    }

    // No valid auth provided
    Err((
        StatusCode::UNAUTHORIZED,
        Json(AuthError {
            error: "authentication_required".to_string(),
            message: "Valid X-Admin-Key or X-API-Key header required".to_string(),
        }),
    ))
}

// =============================================================================
// JWT Authentication Middleware
// =============================================================================

/// Extract auth context from JWT token
pub async fn auth_middleware(
    jwt_service: Arc<JwtService>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => {
            warn!("Missing or invalid Authorization header");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let claims = jwt_service.validate_token(token).map_err(|e| {
        warn!("Token validation failed: {}", e);
        StatusCode::UNAUTHORIZED
    })?;

    let user_id: UserId = claims.sub.parse().map_err(|_| {
        warn!("Invalid user ID in token");
        StatusCode::UNAUTHORIZED
    })?;

    let tenant_id: Option<TenantId> = claims.tenant_id.parse().ok();

    let auth_context = AuthContext {
        user_id,
        tenant_id,
        email: claims.email,
        name: claims.name,
        scopes: claims.scopes,
        auth_method: AuthMethod::JwtToken,
    };

    // Add auth context to request extensions
    request.extensions_mut().insert(auth_context);

    Ok(next.run(request).await)
}

// =============================================================================
// Tenant Context Middleware
// =============================================================================

/// Tenant context middleware - extracts tenant from path or header
pub async fn tenant_middleware(mut request: Request, next: Next) -> Result<Response, StatusCode> {
    // Try to get tenant from X-Tenant-ID header
    let tenant_id = request
        .headers()
        .get("X-Tenant-ID")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<TenantId>().ok());

    if let Some(tenant_id) = tenant_id {
        request.extensions_mut().insert(tenant_id);
    }

    Ok(next.run(request).await)
}

// =============================================================================
// Logging Middleware
// =============================================================================

/// Request logging middleware
pub async fn logging_middleware(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let start = std::time::Instant::now();

    let response = next.run(request).await;

    let latency = start.elapsed();
    let status = response.status();

    info!(
        method = %method,
        uri = %uri,
        status = %status.as_u16(),
        latency_ms = %latency.as_millis(),
        "Request completed"
    );

    response
}

// =============================================================================
// Rate Limiting Middleware (placeholder)
// =============================================================================

/// Rate limiting middleware (placeholder)
pub async fn rate_limit_middleware(request: Request, next: Next) -> Result<Response, StatusCode> {
    // In a real implementation, implement token bucket or sliding window rate limiting
    Ok(next.run(request).await)
}
