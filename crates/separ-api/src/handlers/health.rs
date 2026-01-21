//! Health check handlers
//!
//! Provides comprehensive health checks for all dependencies:
//! - SpiceDB (authorization)
//! - PostgreSQL (data store)
//! - Cache layer
//!
//! Follows Kubernetes health check patterns:
//! - /health - comprehensive status
//! - /live - simple liveness (is the process running?)
//! - /ready - readiness (can it serve traffic?)

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use crate::state::AppState;

/// Overall health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Individual component health
#[derive(Debug, Serialize)]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub latency_ms: u64,
}

/// Comprehensive health response
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: HealthStatus,
    pub version: String,
    pub uptime_seconds: u64,
    pub components: Vec<ComponentHealth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_hit_rate: Option<f64>,
}

/// Simple health response for liveness/readiness probes
#[derive(Serialize)]
pub struct SimpleHealthResponse {
    pub status: String,
}

/// Start time for uptime calculation
static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// Get or initialize start time
fn get_uptime_seconds() -> u64 {
    let start = START_TIME.get_or_init(Instant::now);
    start.elapsed().as_secs()
}

/// Comprehensive health check
///
/// Checks all dependencies:
/// - SpiceDB: Can read schema
/// - Database: Can execute query
pub async fn health_check(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let mut components = Vec::new();
    let mut overall_status = HealthStatus::Healthy;

    // Check SpiceDB
    let spicedb_health = check_spicedb(&state).await;
    if spicedb_health.status != HealthStatus::Healthy {
        overall_status = HealthStatus::Degraded;
    }
    components.push(spicedb_health);

    // Check Database
    let db_health = check_database(&state).await;
    if db_health.status == HealthStatus::Unhealthy {
        overall_status = HealthStatus::Unhealthy;
    } else if db_health.status == HealthStatus::Degraded && overall_status == HealthStatus::Healthy
    {
        overall_status = HealthStatus::Degraded;
    }
    components.push(db_health);

    // Get cache hit rate if available
    let cache_hit_rate = None; // Would come from middleware state in full implementation

    let response = HealthResponse {
        status: overall_status,
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: get_uptime_seconds(),
        components,
        cache_hit_rate,
    };

    let status_code = match overall_status {
        HealthStatus::Healthy => StatusCode::OK,
        HealthStatus::Degraded => StatusCode::OK, // Still serving traffic
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };

    (status_code, Json(response))
}

/// Check SpiceDB health
async fn check_spicedb(state: &AppState) -> ComponentHealth {
    let start = Instant::now();

    match tokio::time::timeout(Duration::from_secs(5), state.spicedb_client.health_check()).await {
        Ok(Ok(true)) => {
            debug!("SpiceDB health check passed");
            ComponentHealth {
                name: "spicedb".to_string(),
                status: HealthStatus::Healthy,
                message: None,
                latency_ms: start.elapsed().as_millis() as u64,
            }
        }
        Ok(Ok(false)) => {
            warn!("SpiceDB health check returned false");
            ComponentHealth {
                name: "spicedb".to_string(),
                status: HealthStatus::Degraded,
                message: Some("SpiceDB returned unhealthy status".to_string()),
                latency_ms: start.elapsed().as_millis() as u64,
            }
        }
        Ok(Err(e)) => {
            warn!("SpiceDB health check failed: {}", e);
            ComponentHealth {
                name: "spicedb".to_string(),
                status: HealthStatus::Unhealthy,
                message: Some(format!("Connection error: {}", e)),
                latency_ms: start.elapsed().as_millis() as u64,
            }
        }
        Err(_) => {
            warn!("SpiceDB health check timed out");
            ComponentHealth {
                name: "spicedb".to_string(),
                status: HealthStatus::Unhealthy,
                message: Some("Health check timed out after 5 seconds".to_string()),
                latency_ms: 5000,
            }
        }
    }
}

/// Check database health
async fn check_database(state: &AppState) -> ComponentHealth {
    let start = Instant::now();

    // Simple query to check database connectivity
    match tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::query("SELECT 1").fetch_one(&state.db_pool),
    )
    .await
    {
        Ok(Ok(_)) => {
            debug!("Database health check passed");
            ComponentHealth {
                name: "database".to_string(),
                status: HealthStatus::Healthy,
                message: None,
                latency_ms: start.elapsed().as_millis() as u64,
            }
        }
        Ok(Err(e)) => {
            warn!("Database health check failed: {}", e);
            ComponentHealth {
                name: "database".to_string(),
                status: HealthStatus::Unhealthy,
                message: Some(format!("Query failed: {}", e)),
                latency_ms: start.elapsed().as_millis() as u64,
            }
        }
        Err(_) => {
            warn!("Database health check timed out");
            ComponentHealth {
                name: "database".to_string(),
                status: HealthStatus::Unhealthy,
                message: Some("Health check timed out after 5 seconds".to_string()),
                latency_ms: 5000,
            }
        }
    }
}

/// Kubernetes liveness probe
///
/// Returns 200 if the process is alive.
/// This should NOT check external dependencies - it's just "is the process running?"
pub async fn liveness() -> (StatusCode, Json<SimpleHealthResponse>) {
    (
        StatusCode::OK,
        Json(SimpleHealthResponse {
            status: "alive".to_string(),
        }),
    )
}

/// Kubernetes readiness probe
///
/// Returns 200 if the service can handle traffic.
/// Checks critical dependencies (database, SpiceDB).
pub async fn readiness(State(state): State<AppState>) -> (StatusCode, Json<SimpleHealthResponse>) {
    // Check SpiceDB (critical for authorization)
    let spicedb_ok = matches!(
        tokio::time::timeout(Duration::from_secs(2), state.spicedb_client.health_check()).await,
        Ok(Ok(true))
    );

    // Check database (critical for data)
    let db_ok = matches!(
        tokio::time::timeout(
            Duration::from_secs(2),
            sqlx::query("SELECT 1").fetch_one(&state.db_pool)
        )
        .await,
        Ok(Ok(_))
    );

    if spicedb_ok && db_ok {
        (
            StatusCode::OK,
            Json(SimpleHealthResponse {
                status: "ready".to_string(),
            }),
        )
    } else {
        let mut issues = Vec::new();
        if !spicedb_ok {
            issues.push("spicedb");
        }
        if !db_ok {
            issues.push("database");
        }

        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SimpleHealthResponse {
                status: format!("not ready: {} unavailable", issues.join(", ")),
            }),
        )
    }
}
