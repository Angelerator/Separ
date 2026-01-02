//! Sync configuration repository implementation (simplified)

use async_trait::async_trait;
use sqlx::PgPool;
use tracing::instrument;

use separ_core::{Result, SeparError, SyncConfig, SyncConfigId, SyncConfigRepository, TenantId};

/// PostgreSQL implementation of SyncConfigRepository
#[allow(dead_code)]
pub struct PgSyncConfigRepository {
    pool: PgPool,
}

impl PgSyncConfigRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SyncConfigRepository for PgSyncConfigRepository {
    #[instrument(skip(self, _config))]
    async fn create(&self, _config: &SyncConfig) -> Result<SyncConfig> {
        Err(SeparError::Internal {
            message: "Not implemented".to_string(),
        })
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, _id: SyncConfigId) -> Result<Option<SyncConfig>> {
        Ok(None)
    }

    #[instrument(skip(self))]
    async fn list_by_tenant(&self, _tenant_id: TenantId) -> Result<Vec<SyncConfig>> {
        Ok(vec![])
    }

    #[instrument(skip(self, _config))]
    async fn update(&self, _config: &SyncConfig) -> Result<SyncConfig> {
        Err(SeparError::Internal {
            message: "Not implemented".to_string(),
        })
    }

    #[instrument(skip(self))]
    async fn delete(&self, _id: SyncConfigId) -> Result<()> {
        Ok(())
    }
}
