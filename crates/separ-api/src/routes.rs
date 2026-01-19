//! API route definitions

use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};

use crate::handlers;
use crate::middleware::{logging_middleware, require_admin_api_key, require_api_key};
use crate::state::AppState;

/// Create the main API router (without state - for basic endpoints)
pub fn create_router() -> Router {
    Router::new()
        // Health endpoints (no state needed)
        .route("/health", get(handlers::health_check))
        .route("/health/live", get(handlers::liveness))
        .route("/health/ready", get(handlers::readiness))
}

/// Create the full API router with application state
pub fn create_router_with_state(state: AppState) -> Router {
    Router::new()
        // Health endpoints (PUBLIC - no auth required)
        .route("/health", get(handlers::health_check))
        .route("/health/live", get(handlers::liveness))
        .route("/health/ready", get(handlers::readiness))
        // JWKS endpoint for JWT verification (PUBLIC - no auth required)
        // External services like Yekta use this to verify token signatures
        .route("/.well-known/jwks.json", get(handlers::auth::jwks))
        // API v1 routes with state
        .merge(api_v1_routes())
        // Add logging middleware to all routes
        .layer(middleware::from_fn(logging_middleware))
        .with_state(state)
}

/// API v1 routes
fn api_v1_routes() -> Router<AppState> {
    Router::new()
        // === ADMIN ROUTES (require X-Admin-Key) ===
        // These are for initial setup and platform management
        .nest("/api/v1/admin/tenants", admin_tenant_routes())
        .nest("/api/v1/admin/users", admin_user_routes())
        .nest("/api/v1/admin/identity", admin_identity_routes())
        // === PROTECTED ROUTES (require X-Admin-Key OR X-API-Key) ===
        // These are for service-to-service communication
        .nest("/api/v1/tenants", protected_tenant_routes())
        .nest("/api/v1/users", protected_user_routes())
        .nest("/api/v1/authz", protected_authz_routes())
        .nest("/api/v1/identity", protected_identity_routes())
        // === PUBLIC ROUTES (for external validation) ===
        // Auth validation endpoints can be called by services like Tavana
        .nest("/api/v1/auth", auth_routes())
        // Placeholder routes (to be implemented)
        .nest("/api/v1/workspaces", placeholder_routes())
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
        .route("/{id}/password", post(handlers::users::set_password))
        .route("/{id}/password/generate", post(handlers::users::generate_password))
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

// =============================================================================
// PROTECTED ROUTES (X-Admin-Key OR X-API-Key required)
// =============================================================================

/// Protected tenant routes - read-only for services
fn protected_tenant_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(handlers::tenants::list_tenants))
        .route("/{id}", get(handlers::tenants::get_tenant))
        .layer(middleware::from_fn(require_api_key))
}

/// Protected user routes - read-only for services
fn protected_user_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(handlers::users::list_users))
        .route("/{id}", get(handlers::users::get_user))
        .route("/{id}/roles", get(handlers::users::get_roles))
        .layer(middleware::from_fn(require_api_key))
}

/// Protected authorization routes
fn protected_authz_routes() -> Router<AppState> {
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
        .layer(middleware::from_fn(require_api_key))
}

/// Protected identity routes - read-only
fn protected_identity_routes() -> Router<AppState> {
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
        .layer(middleware::from_fn(require_api_key))
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
        // Token issuance endpoint (OAuth2 password grant)
        .route("/token", post(handlers::auth::issue_token))
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
