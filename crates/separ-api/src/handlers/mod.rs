//! API request handlers

pub mod authz;
pub mod health;
pub mod identity;
pub mod tenants;

use axum::http::StatusCode;

pub use health::{health_check, liveness, readiness};

/// Placeholder handler for unimplemented endpoints
pub async fn not_implemented() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}
