//! API route definitions
//!
//! Security measures applied:
//! - Request size limits to prevent DoS
//! - Security headers (HSTS, X-Frame-Options, X-Content-Type-Options, etc.)
//! - CORS configuration
//! - Rate limiting
//! - Request ID tracing

use axum::{
    http::{header, HeaderValue, Method},
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    set_header::SetResponseHeaderLayer,
};

use crate::handlers;
use crate::middleware::{
    logging_middleware, request_id_middleware, require_admin_api_key, require_api_key,
};
use crate::state::AppState;

/// Maximum request body size (1 MB default)
const MAX_BODY_SIZE: usize = 1024 * 1024;

/// Create the main API router (without state - for basic endpoints)
///
/// Note: For full health checks, use `create_router_with_state` instead.
pub fn create_router() -> Router {
    Router::new()
        // Basic liveness only - full health requires state
        .route("/health/live", get(handlers::liveness))
}

/// Create the full API router with application state
///
/// Security layers applied (in order):
/// 1. Request body size limit (DoS prevention)
/// 2. Security headers (HSTS, X-Frame-Options, etc.)
/// 3. CORS configuration
/// 4. Request ID tracing
/// 5. Request logging
pub fn create_router_with_state(state: AppState) -> Router {
    // CORS configuration - restrict to known origins in production
    // For development, this allows common localhost ports
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|origin: &HeaderValue, _| {
            // Allow localhost for development
            if let Ok(origin_str) = origin.to_str() {
                origin_str.starts_with("http://localhost")
                    || origin_str.starts_with("https://localhost")
                    || origin_str.starts_with("http://127.0.0.1")
                    || origin_str.starts_with("https://127.0.0.1")
            } else {
                false
            }
        }))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
            "X-API-Key".parse().unwrap(),
            "X-Admin-Key".parse().unwrap(),
            "X-Request-ID".parse().unwrap(),
        ])
        .expose_headers([
            "X-Request-ID".parse().unwrap(),
            "X-RateLimit-Limit".parse().unwrap(),
            "X-RateLimit-Remaining".parse().unwrap(),
            "X-RateLimit-Reset".parse().unwrap(),
        ])
        .max_age(std::time::Duration::from_secs(86400));

    Router::new()
        // Health endpoints (PUBLIC - no auth required)
        .route("/health", get(handlers::health_check))
        .route("/health/live", get(handlers::liveness))
        .route("/health/ready", get(handlers::readiness))
        // JWKS endpoint for JWT verification (PUBLIC - no auth required)
        // External services like Yekta use this to verify token signatures
        .route("/.well-known/jwks.json", get(handlers::auth::jwks))
        // API v1 routes with state
        .merge(api_v1_routes(state.clone()))
        // === Security Layers (order matters!) ===
        // 1. Request body size limit (prevent DoS)
        .layer(RequestBodyLimitLayer::new(MAX_BODY_SIZE))
        // 2. Security Headers
        // HSTS - Force HTTPS (only effective when served over HTTPS)
        .layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        ))
        // Prevent clickjacking
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        // Prevent MIME sniffing
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        // Content Security Policy (restrictive for API)
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
        ))
        // Referrer Policy
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        // Cache Control (no caching by default for API responses)
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
        ))
        // 3. CORS
        .layer(cors)
        // 4. Request ID tracing
        .layer(middleware::from_fn(request_id_middleware))
        // 5. Request logging
        .layer(middleware::from_fn(logging_middleware))
        .with_state(state)
}

/// API v1 routes
fn api_v1_routes(state: AppState) -> Router<AppState> {
    Router::new()
        // === ADMIN ROUTES (require X-Admin-Key) ===
        // These are for initial setup and platform management
        .nest("/api/v1/admin/tenants", admin_tenant_routes())
        .nest("/api/v1/admin/users", admin_user_routes())
        .nest("/api/v1/admin/workspaces", admin_workspace_routes())
        .nest("/api/v1/admin/permissions", admin_permission_routes())
        .nest("/api/v1/admin/identity", admin_identity_routes())
        .nest("/api/v1/admin/domains", admin_domain_routes())
        .nest("/api/v1/admin/platform-admins", admin_platform_routes())
        .nest(
            "/api/v1/admin/storage-connections",
            admin_storage_connection_routes(),
        )
        // === PROTECTED ROUTES (require X-Admin-Key OR X-API-Key) ===
        // These are for service-to-service communication with database-backed validation
        .nest("/api/v1/tenants", protected_tenant_routes(state.clone()))
        .nest("/api/v1/users", protected_user_routes(state.clone()))
        .nest("/api/v1/authz", protected_authz_routes(state.clone()))
        .nest("/api/v1/identity", protected_identity_routes(state.clone()))
        .nest(
            "/api/v1/storage-connections",
            protected_storage_connection_routes(state.clone()),
        )
        // === RESOURCE GRANTS ROUTES (for managing path-level access control) ===
        .nest("/api/v1/workspaces", grant_routes(state.clone()))
        // === AUTHENTICATED USER ROUTES ===
        // These are for authenticated users (x-user-id header from token validation)
        .nest("/api/v1/workspaces", workspace_routes())
        // === PUBLIC ROUTES (for external validation) ===
        // Auth validation endpoints can be called by services like Tavana
        .nest("/api/v1/auth", auth_routes())
        // Placeholder routes (to be implemented)
        .nest("/api/v1/applications", placeholder_routes())
        .nest("/api/v1/oauth", placeholder_routes())
        .nest("/api/v1/sync", placeholder_routes())
        .nest("/api/v1/scim/v2", placeholder_routes())
}

// =============================================================================
// ADMIN ROUTES (X-Admin-Key required)
// =============================================================================

/// Admin tenant routes - full CRUD with admin key
fn admin_tenant_routes() -> Router<AppState> {
    Router::new()
        .route("/", post(handlers::tenants::create_tenant))
        .route("/", get(handlers::tenants::list_tenants))
        .route("/{id}", get(handlers::tenants::get_tenant))
        .route("/{id}", put(handlers::tenants::update_tenant))
        .route("/{id}", delete(handlers::tenants::delete_tenant))
        .layer(middleware::from_fn(require_admin_api_key))
}

/// Admin user routes - full CRUD with admin key
fn admin_user_routes() -> Router<AppState> {
    Router::new()
        .route("/", post(handlers::users::create_user))
        .route("/", get(handlers::users::list_users))
        .route("/{id}", get(handlers::users::get_user))
        .route("/{id}", delete(handlers::users::delete_user))
        .route("/{id}/roles", get(handlers::users::get_roles))
        .route("/{id}/roles", post(handlers::users::assign_role))
        .route("/{id}/roles", delete(handlers::users::remove_role))
        .route(
            "/{id}/permissions",
            get(handlers::users::get_user_permissions),
        )
        .route("/{id}/password", post(handlers::users::set_password))
        .route(
            "/{id}/password/generate",
            post(handlers::users::generate_password),
        )
        .layer(middleware::from_fn(require_admin_api_key))
}

/// Admin identity provider routes
fn admin_identity_routes() -> Router<AppState> {
    Router::new()
        .route("/providers", post(handlers::identity::create_provider))
        .route("/providers/{id}", put(handlers::identity::update_provider))
        .route(
            "/providers/{id}",
            delete(handlers::identity::delete_provider),
        )
        .route(
            "/providers/{id}/sync",
            post(handlers::identity::trigger_sync),
        )
        .layer(middleware::from_fn(require_admin_api_key))
}

/// Admin domain claiming routes - platform admin assigns tenant owners
fn admin_domain_routes() -> Router<AppState> {
    Router::new()
        // Claim a domain and assign owner
        .route("/claim", post(handlers::tenants::claim_domain))
        // List all claimable domains (users registered but no tenant)
        .route("/unclaimed", get(handlers::tenants::list_unclaimed_domains))
        // Get users for a domain
        .route("/{domain}/users", get(handlers::tenants::get_domain_users))
        .layer(middleware::from_fn(require_admin_api_key))
}

/// Admin platform admin management routes
fn admin_platform_routes() -> Router<AppState> {
    Router::new()
        // Create/promote platform admin (super admin)
        .route("/", post(handlers::tenants::create_platform_admin))
        // List all platform admins
        .route("/", get(handlers::tenants::list_platform_admins))
        .layer(middleware::from_fn(require_admin_api_key))
}

/// Admin workspace routes - list all workspaces (admin overview)
fn admin_workspace_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(handlers::workspaces::admin_list_workspaces))
        .route("/{id}", get(handlers::workspaces::get_workspace))
        .layer(middleware::from_fn(require_admin_api_key))
}

/// Admin permission routes - permission registry
fn admin_permission_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/registry",
            get(handlers::permissions::get_permission_registry),
        )
        .route(
            "/categories",
            get(handlers::permissions::get_permission_categories),
        )
        .layer(middleware::from_fn(require_admin_api_key))
}

/// Admin storage connection routes - full CRUD with admin key
fn admin_storage_connection_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/",
            post(handlers::storage_connections::create_storage_connection),
        )
        .route(
            "/",
            get(handlers::storage_connections::list_storage_connections),
        )
        .route(
            "/{id}",
            get(handlers::storage_connections::get_storage_connection),
        )
        .route(
            "/{id}",
            put(handlers::storage_connections::update_storage_connection),
        )
        .route(
            "/{id}",
            delete(handlers::storage_connections::delete_storage_connection),
        )
        .route(
            "/{id}/test",
            post(handlers::storage_connections::test_storage_connection),
        )
        .layer(middleware::from_fn(require_admin_api_key))
}

/// Workspace routes for authenticated users
fn workspace_routes() -> Router<AppState> {
    Router::new()
        .route("/", post(handlers::workspaces::create_workspace))
        .route("/", get(handlers::workspaces::list_workspaces))
        .route("/switch", post(handlers::workspaces::switch_workspace))
        .route("/{id}", get(handlers::workspaces::get_workspace))
        .route("/{id}", put(handlers::workspaces::update_workspace))
        .route("/{id}", delete(handlers::workspaces::delete_workspace))
        .route("/{id}/members", post(handlers::workspaces::invite_member))
        .route("/{id}/members", get(handlers::workspaces::list_members))
        .route(
            "/{id}/members/{user_id}",
            delete(handlers::workspaces::remove_member),
        )
        .route(
            "/{id}/members/{user_id}",
            put(handlers::workspaces::update_member_role),
        )
        .route("/{id}/leave", post(handlers::workspaces::leave_workspace))
        .route(
            "/{id}/transfer-ownership",
            post(handlers::workspaces::transfer_ownership),
        )
        .route(
            "/{id}/invitations",
            post(handlers::workspaces::invite_by_email),
        )
        .route(
            "/{id}/invitations",
            get(handlers::workspaces::list_invitations),
        )
        .route(
            "/accept-invitation",
            post(handlers::workspaces::accept_invitation),
        )
}

// =============================================================================
// PROTECTED ROUTES (X-Admin-Key OR X-API-Key required)
// Database-backed API key validation with caching
// =============================================================================

/// Protected tenant routes - read-only for services
fn protected_tenant_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(handlers::tenants::list_tenants))
        .route("/{id}", get(handlers::tenants::get_tenant))
        .layer(middleware::from_fn_with_state(state, require_api_key))
}

/// Protected user routes - read-only for services
fn protected_user_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(handlers::users::list_users))
        .route("/{id}", get(handlers::users::get_user))
        .route("/{id}/roles", get(handlers::users::get_roles))
        .layer(middleware::from_fn_with_state(state, require_api_key))
}

/// Protected authorization routes
fn protected_authz_routes(state: AppState) -> Router<AppState> {
    Router::new()
        // Read operations
        .route("/check", post(handlers::authz::check_permission))
        .route("/relationships", get(handlers::authz::read_relationships))
        .route("/lookup/resources", post(handlers::authz::lookup_resources))
        .route("/lookup/subjects", post(handlers::authz::lookup_subjects))
        // Write operations (still require auth)
        .route("/relationships", post(handlers::authz::write_relationship))
        .route(
            "/relationships",
            delete(handlers::authz::delete_relationship),
        )
        .layer(middleware::from_fn_with_state(state, require_api_key))
}

/// Protected identity routes - read-only
fn protected_identity_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/providers", get(handlers::identity::list_providers))
        .route("/providers/{id}", get(handlers::identity::get_provider))
        .route(
            "/providers/{id}/sync/history",
            get(handlers::identity::get_sync_history),
        )
        .route(
            "/providers/{id}/test",
            post(handlers::identity::test_connection),
        )
        .route("/health", get(handlers::identity::health_check))
        .layer(middleware::from_fn_with_state(state, require_api_key))
}

/// Protected storage connection routes - for Yekta and other services
fn protected_storage_connection_routes(state: AppState) -> Router<AppState> {
    Router::new()
        // List connections for a tenant
        .route(
            "/",
            get(handlers::storage_connections::list_storage_connections),
        )
        // Get connection details (without secrets)
        .route(
            "/{id}",
            get(handlers::storage_connections::get_storage_connection),
        )
        // Get connection with credentials (for authorized services like Yekta)
        .route(
            "/{id}/credentials",
            get(handlers::storage_connections::get_storage_connection_credentials),
        )
        // Vend temporary SAS credentials (preferred over raw credentials)
        .route(
            "/{id}/vend",
            post(handlers::storage_connections::vend_credentials),
        )
        .layer(middleware::from_fn_with_state(state, require_api_key))
}

/// Resource grant routes — for managing path-level access control
/// Uses admin key auth (same as workspace management routes)
fn grant_routes(_state: AppState) -> Router<AppState> {
    Router::new()
        .route(
            "/{workspace_id}/grants",
            post(handlers::resource_grants::create_grant),
        )
        .route(
            "/{workspace_id}/grants",
            get(handlers::resource_grants::list_grants),
        )
        .route(
            "/{workspace_id}/grants/{grant_id}",
            delete(handlers::resource_grants::delete_grant),
        )
        .layer(middleware::from_fn(require_admin_api_key))
}

// =============================================================================
// PUBLIC ROUTES (no auth required)
// =============================================================================

/// Authentication validation routes (for external services like Tavana)
/// These endpoints validate credentials/tokens - caller provides the secret
fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/validate", post(handlers::auth::validate_credentials))
        .route("/validate-token", post(handlers::auth::validate_token))
        // Token issuance endpoint (OAuth2 password grant + Azure SSO)
        .route("/token", post(handlers::auth::issue_token))
        // SSO config — returns client_id + authorize_url (no email needed)
        .route("/sso-config", get(handlers::auth::sso_config))
        // SSO discovery — validates a specific email domain has SSO configured
        .route("/sso-discovery", post(handlers::auth::sso_discovery))
        // User self-registration (for desktop apps like Hormoz)
        .route("/register", post(handlers::auth::register_user))
}

/// Placeholder routes for unimplemented endpoints
fn placeholder_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(handlers::not_implemented))
        .route("/", post(handlers::not_implemented))
        .route("/{id}", get(handlers::not_implemented))
        .route("/{id}", put(handlers::not_implemented))
        .route("/{id}", delete(handlers::not_implemented))
}
