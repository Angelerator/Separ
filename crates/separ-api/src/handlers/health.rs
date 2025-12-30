//! Health check handlers

use axum::{http::StatusCode, Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

/// Basic health check
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Kubernetes liveness probe
pub async fn liveness() -> StatusCode {
    StatusCode::OK
}

/// Kubernetes readiness probe
pub async fn readiness() -> StatusCode {
    // TODO: Check database and SpiceDB connectivity
    StatusCode::OK
}
