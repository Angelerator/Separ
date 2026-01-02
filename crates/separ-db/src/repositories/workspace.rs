//! Workspace repository implementation (simplified)

use async_trait::async_trait;
use sqlx::PgPool;
use tracing::instrument;

use separ_core::{Result, SeparError, TenantId, Workspace, WorkspaceId, WorkspaceRepository};

/// PostgreSQL implementation of WorkspaceRepository
#[allow(dead_code)]
pub struct PgWorkspaceRepository {
    pool: PgPool,
}

impl PgWorkspaceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl WorkspaceRepository for PgWorkspaceRepository {
    #[instrument(skip(self, _workspace))]
    async fn create(&self, _workspace: &Workspace) -> Result<Workspace> {
        Err(SeparError::Internal {
            message: "Not implemented".to_string(),
        })
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, _id: WorkspaceId) -> Result<Option<Workspace>> {
        Ok(None)
    }

    #[instrument(skip(self))]
    async fn list_by_tenant(
        &self,
        _tenant_id: TenantId,
        _offset: u32,
        _limit: u32,
    ) -> Result<Vec<Workspace>> {
        Ok(vec![])
    }

    #[instrument(skip(self, _workspace))]
    async fn update(&self, _workspace: &Workspace) -> Result<Workspace> {
        Err(SeparError::Internal {
            message: "Not implemented".to_string(),
        })
    }

    #[instrument(skip(self))]
    async fn delete(&self, _id: WorkspaceId) -> Result<()> {
        Ok(())
    }
}
