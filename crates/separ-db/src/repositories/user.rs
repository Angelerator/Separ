//! User repository implementation (simplified)

use async_trait::async_trait;
use sqlx::PgPool;
use tracing::instrument;

use separ_core::{Result, SeparError, TenantId, User, UserId, UserRepository};

/// PostgreSQL implementation of UserRepository
#[allow(dead_code)]
pub struct PgUserRepository {
    pool: PgPool,
}

impl PgUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    #[instrument(skip(self, _user))]
    async fn create(&self, _user: &User) -> Result<User> {
        Err(SeparError::Internal {
            message: "Not implemented".to_string(),
        })
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, _id: UserId) -> Result<Option<User>> {
        Ok(None)
    }

    #[instrument(skip(self))]
    async fn get_by_email(&self, _tenant_id: TenantId, _email: &str) -> Result<Option<User>> {
        Ok(None)
    }

    #[instrument(skip(self))]
    async fn get_by_external_id(
        &self,
        _tenant_id: TenantId,
        _external_id: &str,
    ) -> Result<Option<User>> {
        Ok(None)
    }

    #[instrument(skip(self))]
    async fn list_by_tenant(
        &self,
        _tenant_id: TenantId,
        _offset: u32,
        _limit: u32,
    ) -> Result<Vec<User>> {
        Ok(vec![])
    }

    #[instrument(skip(self, _user))]
    async fn update(&self, _user: &User) -> Result<User> {
        Err(SeparError::Internal {
            message: "Not implemented".to_string(),
        })
    }

    #[instrument(skip(self))]
    async fn delete(&self, _id: UserId) -> Result<()> {
        Ok(())
    }

    #[instrument(skip(self))]
    async fn count_by_tenant(&self, _tenant_id: TenantId) -> Result<u64> {
        Ok(0)
    }
}
