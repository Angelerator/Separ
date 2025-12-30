//! API middleware for authentication, logging, and more

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tracing::{info, warn};

use separ_core::{TenantId, UserId};
use separ_oauth::JwtService;

/// Authenticated user context
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub email: Option<String>,
    pub name: Option<String>,
    pub scopes: Vec<String>,
}

/// Extract auth context from request
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

    let tenant_id: TenantId = claims.tenant_id.parse().map_err(|_| {
        warn!("Invalid tenant ID in token");
        StatusCode::UNAUTHORIZED
    })?;

    let auth_context = AuthContext {
        user_id,
        tenant_id,
        email: claims.email,
        name: claims.name,
        scopes: claims.scopes,
    };

    // Add auth context to request extensions
    request.extensions_mut().insert(auth_context);

    Ok(next.run(request).await)
}

/// Tenant context middleware - extracts tenant from path or header
pub async fn tenant_middleware(
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
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

/// API key authentication middleware
pub async fn api_key_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let api_key = request
        .headers()
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok());

    if let Some(key) = api_key {
        // In a real implementation, validate the API key against the database
        // and extract the associated tenant/service account
        
        // For now, just pass through
        let prefix = if key.len() > 8 { &key[..8] } else { key };
        info!("API key authentication attempted with prefix: {}...", prefix);
    }

    Ok(next.run(request).await)
}

/// Rate limiting middleware (placeholder)
pub async fn rate_limit_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // In a real implementation, implement token bucket or sliding window rate limiting
    Ok(next.run(request).await)
}
