//! API middleware for authentication, authorization, rate limiting, and more
//!
//! Implements SpiceDB best practices:
//! - Database-backed API key validation with caching
//! - Rate limiting with governor
//! - Request ID tracing
//! - Constant-time comparisons

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use governor::clock::Clock;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use separ_core::{ApiKeyId, TenantId, UserId, WorkspaceId};
use separ_db::repositories::ApiKeyRepository;
use separ_oauth::JwtService;

use crate::state::AppState;

// =============================================================================
// Types & Configuration
// =============================================================================

/// Authenticated user context
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user_id: UserId,
    pub tenant_id: Option<TenantId>,
    pub workspace_id: Option<WorkspaceId>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub scopes: Vec<String>,
    pub auth_method: AuthMethod,
    /// API key ID if authenticated via API key
    pub api_key_id: Option<ApiKeyId>,
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
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let body = Json(self);
        (StatusCode::UNAUTHORIZED, body).into_response()
    }
}

/// Rate limit exceeded error with standard headers
#[derive(Debug, Serialize)]
pub struct RateLimitError {
    pub error: String,
    pub message: String,
    pub retry_after_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining: Option<u32>,
}

impl IntoResponse for RateLimitError {
    fn into_response(self) -> Response {
        let retry_after = self.retry_after_seconds.to_string();
        let body = Json(&self);
        let mut response = (StatusCode::TOO_MANY_REQUESTS, body).into_response();

        let headers = response.headers_mut();

        // Standard rate limit headers per RFC 6585 / IETF draft
        headers.insert("Retry-After", HeaderValue::from_str(&retry_after).unwrap());

        if let Some(limit) = self.limit {
            headers.insert(
                "X-RateLimit-Limit",
                HeaderValue::from_str(&limit.to_string()).unwrap(),
            );
        }
        if let Some(remaining) = self.remaining {
            headers.insert(
                "X-RateLimit-Remaining",
                HeaderValue::from_str(&remaining.to_string()).unwrap(),
            );
        }

        // Reset time (Unix timestamp when limit resets)
        let reset_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + self.retry_after_seconds;
        headers.insert(
            "X-RateLimit-Reset",
            HeaderValue::from_str(&reset_time.to_string()).unwrap(),
        );

        response
    }
}

/// Rate limit info for successful requests
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    pub limit: u32,
    pub remaining: u32,
    pub reset_at: u64,
}

// =============================================================================
// Request ID Middleware
// =============================================================================

/// Request ID wrapper for extensions
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

/// Add unique request ID to every request
pub async fn request_id_middleware(mut request: Request, next: Next) -> Response {
    let request_id = Uuid::now_v7().to_string();

    // Add to request extensions
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));

    // Continue processing
    let mut response = next.run(request).await;

    // Add to response headers
    response
        .headers_mut()
        .insert("X-Request-ID", HeaderValue::from_str(&request_id).unwrap());

    response
}

// =============================================================================
// Rate Limiting Middleware
// =============================================================================

/// Default rate limit (requests per second)
const DEFAULT_RATE_LIMIT: u32 = 100;
/// Default burst size
const DEFAULT_BURST_SIZE: u32 = 200;

/// Rate limiting middleware using token bucket algorithm
///
/// Uses IP-based rate limiting with governor.
/// Adds standard rate limit headers to all responses.
pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, RateLimitError> {
    let client_ip = addr.ip().to_string();

    match state.rate_limiter.check_key(&client_ip) {
        Ok(_) => {
            let mut response = next.run(request).await;

            // Add rate limit headers to successful responses
            add_rate_limit_headers(
                response.headers_mut(),
                DEFAULT_RATE_LIMIT,
                DEFAULT_BURST_SIZE, // Approximate remaining (actual tracking would need state)
            );

            Ok(response)
        }
        Err(not_until) => {
            let clock = governor::clock::DefaultClock::default();
            let retry_after = not_until.wait_time_from(clock.now());
            warn!(
                client_ip = %client_ip,
                retry_after_ms = %retry_after.as_millis(),
                "Rate limit exceeded"
            );
            Err(RateLimitError {
                error: "rate_limit_exceeded".to_string(),
                message: "Too many requests. Please slow down.".to_string(),
                retry_after_seconds: retry_after.as_secs().max(1),
                limit: Some(DEFAULT_RATE_LIMIT),
                remaining: Some(0),
            })
        }
    }
}

/// Add rate limit headers to response
fn add_rate_limit_headers(headers: &mut axum::http::HeaderMap, limit: u32, remaining: u32) {
    headers.insert(
        "X-RateLimit-Limit",
        HeaderValue::from_str(&limit.to_string()).unwrap(),
    );
    headers.insert(
        "X-RateLimit-Remaining",
        HeaderValue::from_str(&remaining.to_string()).unwrap(),
    );

    // Reset time (1 second from now for per-second limits)
    let reset_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 1;
    headers.insert(
        "X-RateLimit-Reset",
        HeaderValue::from_str(&reset_time.to_string()).unwrap(),
    );
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
    let request_id = request.extensions().get::<RequestId>().map(|r| r.0.clone());

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
                    request_id,
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
        Some(key) if constant_time_eq(key.as_bytes(), expected_key.as_bytes()) => {
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
                    request_id,
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
                    request_id,
                }),
            ))
        }
    }
}

// =============================================================================
// Service API Key Middleware (Database-backed validation with per-key rate limiting)
// =============================================================================

/// Rate limit error specific to API key limits
#[derive(Debug, Serialize)]
pub struct ApiKeyRateLimitError {
    pub error: String,
    pub message: String,
    pub retry_after_seconds: u64,
    pub limit_per_minute: i32,
}

impl IntoResponse for ApiKeyRateLimitError {
    fn into_response(self) -> Response {
        let retry_after = self.retry_after_seconds.to_string();
        let limit_per_second = (self.limit_per_minute / 60).max(1);
        let body = Json(&self);
        let mut response = (StatusCode::TOO_MANY_REQUESTS, body).into_response();

        let headers = response.headers_mut();
        headers.insert("Retry-After", HeaderValue::from_str(&retry_after).unwrap());
        headers.insert(
            "X-RateLimit-Limit",
            HeaderValue::from_str(&limit_per_second.to_string()).unwrap(),
        );
        headers.insert("X-RateLimit-Remaining", HeaderValue::from_str("0").unwrap());

        let reset_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + self.retry_after_seconds;
        headers.insert(
            "X-RateLimit-Reset",
            HeaderValue::from_str(&reset_time.to_string()).unwrap(),
        );

        response
    }
}

/// Validates service API key against database with caching and per-key rate limiting
pub async fn require_service_api_key(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    let request_id = request.extensions().get::<RequestId>().map(|r| r.0.clone());

    let api_key_header = request
        .headers()
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok());

    let key = match api_key_header {
        Some(k) if k.len() >= 20 => k,
        Some(_) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(AuthError {
                    error: "invalid_api_key".to_string(),
                    message: "Invalid API key format".to_string(),
                    request_id,
                }),
            )
                .into_response());
        }
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(AuthError {
                    error: "missing_api_key".to_string(),
                    message: "X-API-Key header required".to_string(),
                    request_id,
                }),
            )
                .into_response());
        }
    };

    // Hash the key for cache lookup
    let key_hash = hash_api_key(key);

    // Helper to check rate limit and run request
    async fn check_rate_limit_and_run(
        state: &AppState,
        api_key: &separ_db::repositories::ApiKey,
        auth_context: AuthContext,
        mut request: Request,
        next: Next,
    ) -> Result<Response, Response> {
        // Check per-key rate limit
        match state.check_api_key_rate_limit(api_key).await {
            Ok(remaining) => {
                request.extensions_mut().insert(auth_context);
                let mut response = next.run(request).await;

                // Add rate limit headers to successful response
                let limit_per_second = (api_key.rate_limit_per_minute / 60).max(1);
                add_rate_limit_headers(response.headers_mut(), limit_per_second as u32, remaining);

                Ok(response)
            }
            Err(retry_after) => {
                warn!(
                    key_prefix = %api_key.key_prefix,
                    rate_limit = %api_key.rate_limit_per_minute,
                    "API key rate limit exceeded"
                );
                Err(ApiKeyRateLimitError {
                    error: "api_key_rate_limit_exceeded".to_string(),
                    message: format!(
                        "Rate limit exceeded for this API key ({} requests/min)",
                        api_key.rate_limit_per_minute
                    ),
                    retry_after_seconds: retry_after,
                    limit_per_minute: api_key.rate_limit_per_minute,
                }
                .into_response())
            }
        }
    }

    // Check cache first
    if let Some(cached_key) = state.api_key_cache.get(&key_hash).await {
        if cached_key.is_valid() {
            debug!(
                key_prefix = %cached_key.key_prefix,
                "API key validated from cache"
            );

            let auth_context = AuthContext {
                user_id: cached_key.created_by.unwrap_or_else(UserId::new),
                tenant_id: cached_key.tenant_id,
                workspace_id: cached_key.workspace_id,
                email: None,
                name: Some(cached_key.name.clone()),
                scopes: cached_key.scopes.clone(),
                auth_method: AuthMethod::ServiceApiKey,
                api_key_id: Some(cached_key.id),
            };

            return check_rate_limit_and_run(&state, &cached_key, auth_context, request, next)
                .await;
        }
    }

    // Validate against database
    match state.api_key_repo.validate(key).await {
        Ok(Some(api_key)) => {
            debug!(
                key_prefix = %api_key.key_prefix,
                rate_limit = %api_key.rate_limit_per_minute,
                "API key validated from database"
            );

            // Update last used (fire and forget)
            let repo = state.api_key_repo.clone();
            let key_id = api_key.id;
            tokio::spawn(async move {
                let _ = repo.update_last_used(key_id).await;
            });

            // Cache the valid key
            state.api_key_cache.insert(key_hash, api_key.clone()).await;

            let auth_context = AuthContext {
                user_id: api_key.created_by.unwrap_or_else(UserId::new),
                tenant_id: api_key.tenant_id,
                workspace_id: api_key.workspace_id,
                email: None,
                name: Some(api_key.name.clone()),
                scopes: api_key.scopes.clone(),
                auth_method: AuthMethod::ServiceApiKey,
                api_key_id: Some(api_key.id),
            };

            check_rate_limit_and_run(&state, &api_key, auth_context, request, next).await
        }
        Ok(None) => {
            warn!("Invalid or expired API key");
            Err((
                StatusCode::UNAUTHORIZED,
                Json(AuthError {
                    error: "invalid_api_key".to_string(),
                    message: "Invalid or expired API key".to_string(),
                    request_id,
                }),
            )
                .into_response())
        }
        Err(e) => {
            warn!(error = %e, "Failed to validate API key");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthError {
                    error: "validation_error".to_string(),
                    message: "Failed to validate API key".to_string(),
                    request_id,
                }),
            )
                .into_response())
        }
    }
}

// =============================================================================
// Combined Auth Middleware (Admin Key OR Service Key)
// =============================================================================

/// Accepts either admin API key or database-backed service API key
///
/// - Admin keys (X-Admin-Key) bypass per-key rate limiting
/// - Service keys (X-API-Key) are subject to per-key rate limits from database
pub async fn require_api_key(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, Response> {
    let request_id = request.extensions().get::<RequestId>().map(|r| r.0.clone());

    // Check for admin key first (no rate limiting for admins)
    let admin_key = std::env::var("SEPAR_ADMIN_API_KEY").ok();
    let provided_admin_key = request
        .headers()
        .get("X-Admin-Key")
        .and_then(|h| h.to_str().ok());

    if let (Some(expected), Some(provided)) = (&admin_key, provided_admin_key) {
        if !expected.is_empty() && constant_time_eq(expected.as_bytes(), provided.as_bytes()) {
            debug!("Authenticated via admin API key");

            // Add admin auth context
            let auth_context = AuthContext {
                user_id: UserId::new(), // System user
                tenant_id: None,
                workspace_id: None,
                email: None,
                name: Some("Admin".to_string()),
                scopes: vec!["*".to_string()], // Full access
                auth_method: AuthMethod::AdminApiKey,
                api_key_id: None,
            };
            request.extensions_mut().insert(auth_context);

            // Admin keys bypass rate limiting
            return Ok(next.run(request).await);
        }
    }

    // Fall back to database-backed service API key validation with per-key rate limiting
    require_service_api_key(State(state), request, next).await
}

// =============================================================================
// JWT Authentication Middleware
// =============================================================================

/// Extract auth context from JWT token
pub async fn auth_middleware(
    jwt_service: Arc<JwtService>,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<AuthError>)> {
    let request_id = request.extensions().get::<RequestId>().map(|r| r.0.clone());

    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => {
            warn!("Missing or invalid Authorization header");
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(AuthError {
                    error: "missing_token".to_string(),
                    message: "Authorization header with Bearer token required".to_string(),
                    request_id,
                }),
            ));
        }
    };

    let claims = jwt_service.validate_token(token).map_err(|e| {
        warn!("Token validation failed: {}", e);
        (
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "invalid_token".to_string(),
                message: "Token validation failed".to_string(),
                request_id: request_id.clone(),
            }),
        )
    })?;

    let user_id: UserId = claims.sub.parse().map_err(|_| {
        warn!("Invalid user ID in token");
        (
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "invalid_token".to_string(),
                message: "Invalid user ID in token".to_string(),
                request_id: request_id.clone(),
            }),
        )
    })?;

    let tenant_id: Option<TenantId> = claims.tenant_id.parse().ok();
    let workspace_id: Option<WorkspaceId> = claims.workspace_id.parse().ok();

    let auth_context = AuthContext {
        user_id,
        tenant_id,
        workspace_id,
        email: claims.email,
        name: claims.name,
        scopes: claims.scopes,
        auth_method: AuthMethod::JwtToken,
        api_key_id: None,
    };

    // Add auth context to request extensions
    request.extensions_mut().insert(auth_context);

    Ok(next.run(request).await)
}

// =============================================================================
// Logging Middleware
// =============================================================================

/// Request logging middleware with request ID
pub async fn logging_middleware(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let start = std::time::Instant::now();

    let response = next.run(request).await;

    let latency = start.elapsed();
    let status = response.status();

    info!(
        request_id = %request_id,
        method = %method,
        uri = %uri,
        status = %status.as_u16(),
        latency_ms = %latency.as_millis(),
        "Request completed"
    );

    response
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Hash an API key using SHA-256
fn hash_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

// =============================================================================
// Health Check Middleware (skip auth for health endpoints)
// =============================================================================

/// Check if URI is a health endpoint
#[allow(dead_code)]
pub fn is_health_endpoint(uri: &str) -> bool {
    matches!(uri, "/health" | "/ready" | "/live" | "/metrics")
}
