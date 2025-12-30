//! Application repository implementation (simplified)

use async_trait::async_trait;
use sqlx::PgPool;
use tracing::instrument;

use separ_core::{
    Result, Application, ApplicationId, ApplicationRepository, WorkspaceId, SeparError,
};

/// PostgreSQL implementation of ApplicationRepository
pub struct PgApplicationRepository {
    pool: PgPool,
}

impl PgApplicationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ApplicationRepository for PgApplicationRepository {
    #[instrument(skip(self, _application))]
    async fn create(&self, _application: &Application) -> Result<Application> {
        Err(SeparError::Internal { message: "Not implemented".to_string() })
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, _id: ApplicationId) -> Result<Option<Application>> {
        Ok(None)
    }

    #[instrument(skip(self))]
    async fn get_by_slug(&self, _workspace_id: WorkspaceId, _slug: &str) -> Result<Option<Application>> {
        Ok(None)
    }

    #[instrument(skip(self))]
    async fn list_by_workspace(&self, _workspace_id: WorkspaceId, _offset: u32, _limit: u32) -> Result<Vec<Application>> {
        Ok(vec![])
    }

    #[instrument(skip(self, _application))]
    async fn update(&self, _application: &Application) -> Result<Application> {
        Err(SeparError::Internal { message: "Not implemented".to_string() })
    }

    #[instrument(skip(self))]
    async fn delete(&self, _id: ApplicationId) -> Result<()> {
        Ok(())
    }
}
