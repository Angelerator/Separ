//! Database connection pool management

use separ_core::{Result, SeparError};
use sqlx::postgres::{PgPool, PgPoolOptions};
use tracing::info;

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// PostgreSQL connection URL
    pub url: String,
    /// Maximum number of connections in the pool
    pub max_connections: u32,
    /// Minimum number of connections to maintain
    pub min_connections: u32,
    /// Connection acquire timeout in seconds
    pub acquire_timeout_secs: u64,
    /// Idle connection timeout in seconds
    pub idle_timeout_secs: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgres://separ:separ@localhost:5432/separ".to_string(),
            max_connections: 10,
            min_connections: 2,
            acquire_timeout_secs: 30,
            idle_timeout_secs: 600,
        }
    }
}

/// Create a new database connection pool
pub async fn create_pool(config: &DatabaseConfig) -> Result<PgPool> {
    info!("Creating database connection pool");

    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(std::time::Duration::from_secs(config.acquire_timeout_secs))
        .idle_timeout(std::time::Duration::from_secs(config.idle_timeout_secs))
        .connect(&config.url)
        .await
        .map_err(|e| SeparError::database_error(format!("Failed to connect: {}", e)))?;

    info!("Database connection pool created successfully");
    Ok(pool)
}
