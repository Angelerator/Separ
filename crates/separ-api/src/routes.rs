//! API route definitions

use axum::{
    routing::{delete, get, post, put},
    Router,
};

use crate::handlers;
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
        // Health endpoints
        .route("/health", get(handlers::health_check))
        .route("/health/live", get(handlers::liveness))
        .route("/health/ready", get(handlers::readiness))
        // API v1 routes with state
        .nest("/api/v1", api_v1_routes(state))
}

/// API v1 routes
fn api_v1_routes(state: AppState) -> Router {
    Router::new()
        // Tenant management
        .nest("/tenants", tenant_routes(state.clone()))
        // Authorization endpoints
        .nest("/authz", authz_routes(state.clone()))
        // Placeholder routes (to be implemented)
        .nest("/workspaces", placeholder_routes())
        .nest("/applications", placeholder_routes())
        .nest("/users", placeholder_routes())
        .nest("/oauth", placeholder_routes())
        .nest("/sync", placeholder_routes())
        .nest("/scim/v2", placeholder_routes())
}

/// Tenant CRUD routes
fn tenant_routes(state: AppState) -> Router {
    Router::new()
        .route("/", post(handlers::tenants::create_tenant))
        .route("/", get(handlers::tenants::list_tenants))
        .route("/{id}", get(handlers::tenants::get_tenant))
        .route("/{id}", put(handlers::tenants::update_tenant))
        .route("/{id}", delete(handlers::tenants::delete_tenant))
        .with_state(state)
}

/// Authorization routes
fn authz_routes(state: AppState) -> Router {
    Router::new()
        .route("/check", post(handlers::authz::check_permission))
        .route("/relationships", get(handlers::authz::read_relationships))
        .route("/relationships", post(handlers::authz::write_relationship))
        .route("/relationships", delete(handlers::authz::delete_relationship))
        .route("/lookup/resources", post(handlers::authz::lookup_resources))
        .route("/lookup/subjects", post(handlers::authz::lookup_subjects))
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
