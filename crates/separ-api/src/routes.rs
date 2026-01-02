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
        // API v1 routes with state
        .nest("/api/v1", api_v1_routes(state))
        // Add logging middleware to all routes
        .layer(middleware::from_fn(logging_middleware))
}

/// API v1 routes
fn api_v1_routes(state: AppState) -> Router {
    Router::new()
        // === ADMIN ROUTES (require X-Admin-Key) ===
        // These are for initial setup and platform management
        .nest("/admin/tenants", admin_tenant_routes(state.clone()))
        .nest("/admin/users", admin_user_routes(state.clone()))
        .nest("/admin/identity", admin_identity_routes(state.clone()))
        // === PROTECTED ROUTES (require X-Admin-Key OR X-API-Key) ===
        // These are for service-to-service communication
        .nest("/tenants", protected_tenant_routes(state.clone()))
        .nest("/users", protected_user_routes(state.clone()))
        .nest("/authz", protected_authz_routes(state.clone()))
        .nest("/identity", protected_identity_routes(state.clone()))
        // === PUBLIC ROUTES (for external validation) ===
        // Auth validation endpoints can be called by services like Tavana
        .nest("/auth", auth_routes(state.clone()))
        // Permission check endpoint (read-only, service needs API key)
        .route(
            "/authz/check",
            post(handlers::authz::check_permission).with_state(state.clone()),
        )
        // Placeholder routes (to be implemented)
        .nest("/workspaces", placeholder_routes())
        .nest("/applications", placeholder_routes())
        .nest("/oauth", placeholder_routes())
        .nest("/sync", placeholder_routes())
        .nest("/scim/v2", placeholder_routes())
}

// =============================================================================
// ADMIN ROUTES (X-Admin-Key required)
// =============================================================================

/// Admin tenant routes - full CRUD with admin key
fn admin_tenant_routes(state: AppState) -> Router {
    Router::new()
        .route("/", post(handlers::tenants::create_tenant))
        .route("/", get(handlers::tenants::list_tenants))
        .route("/{id}", get(handlers::tenants::get_tenant))
        .route("/{id}", put(handlers::tenants::update_tenant))
        .route("/{id}", delete(handlers::tenants::delete_tenant))
        .layer(middleware::from_fn(require_admin_api_key))
        .with_state(state)
}

/// Admin user routes - full CRUD with admin key
fn admin_user_routes(state: AppState) -> Router {
    Router::new()
        .route("/", post(handlers::users::create_user))
        .route("/", get(handlers::users::list_users))
        .route("/{id}", get(handlers::users::get_user))
        .route("/{id}", delete(handlers::users::delete_user))
        .route("/{id}/roles", get(handlers::users::get_roles))
        .route("/{id}/roles", post(handlers::users::assign_role))
        .route("/{id}/roles", delete(handlers::users::remove_role))
        .layer(middleware::from_fn(require_admin_api_key))
        .with_state(state)
}

/// Admin identity provider routes
fn admin_identity_routes(state: AppState) -> Router {
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
        .with_state(state)
}

// =============================================================================
// PROTECTED ROUTES (X-Admin-Key OR X-API-Key required)
// =============================================================================

/// Protected tenant routes - read-only for services
fn protected_tenant_routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(handlers::tenants::list_tenants))
        .route("/{id}", get(handlers::tenants::get_tenant))
        .layer(middleware::from_fn(require_api_key))
        .with_state(state)
}

/// Protected user routes - read-only for services
fn protected_user_routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(handlers::users::list_users))
        .route("/{id}", get(handlers::users::get_user))
        .route("/{id}/roles", get(handlers::users::get_roles))
        .layer(middleware::from_fn(require_api_key))
        .with_state(state)
}

/// Protected authorization routes
fn protected_authz_routes(state: AppState) -> Router {
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
        .with_state(state)
}

/// Protected identity routes - read-only
fn protected_identity_routes(state: AppState) -> Router {
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
        .with_state(state)
}

// =============================================================================
// PUBLIC ROUTES (no auth required)
// =============================================================================

/// Authentication validation routes (for external services like Tavana)
/// These endpoints validate credentials/tokens - caller provides the secret
fn auth_routes(state: AppState) -> Router {
    Router::new()
        .route("/validate", post(handlers::auth::validate_credentials))
        .route("/validate-token", post(handlers::auth::validate_token))
        .with_state(state)
}

/// Placeholder routes for unimplemented endpoints
fn placeholder_routes() -> Router {
    Router::new()
        .route("/", get(handlers::not_implemented))
        .route("/", post(handlers::not_implemented))
        .route("/{id}", get(handlers::not_implemented))
        .route("/{id}", put(handlers::not_implemented))
        .route("/{id}", delete(handlers::not_implemented))
}
