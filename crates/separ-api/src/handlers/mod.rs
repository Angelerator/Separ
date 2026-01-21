//! API request handlers

pub mod auth;
pub mod authz;
pub mod health;
pub mod identity;
pub mod tenants;
pub mod users;
pub mod workspaces;

use axum::http::StatusCode;

pub use health::{health_check, liveness, readiness};

/// Placeholder handler for unimplemented endpoints
pub async fn not_implemented() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}
