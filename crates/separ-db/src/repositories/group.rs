//! Group repository implementation (simplified)

use async_trait::async_trait;
use sqlx::PgPool;
use tracing::instrument;

use separ_core::{Group, GroupId, GroupRepository, Result, SeparError, TenantId, User, UserId};

/// PostgreSQL implementation of GroupRepository
#[allow(dead_code)]
pub struct PgGroupRepository {
    pool: PgPool,
}

impl PgGroupRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl GroupRepository for PgGroupRepository {
    #[instrument(skip(self, _group))]
    async fn create(&self, _group: &Group) -> Result<Group> {
        Err(SeparError::Internal {
            message: "Not implemented".to_string(),
        })
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, _id: GroupId) -> Result<Option<Group>> {
        Ok(None)
    }

    #[instrument(skip(self))]
    async fn list_by_tenant(
        &self,
        _tenant_id: TenantId,
        _offset: u32,
        _limit: u32,
    ) -> Result<Vec<Group>> {
        Ok(vec![])
    }

    #[instrument(skip(self, _group))]
    async fn update(&self, _group: &Group) -> Result<Group> {
        Err(SeparError::Internal {
            message: "Not implemented".to_string(),
        })
    }

    #[instrument(skip(self))]
    async fn delete(&self, _id: GroupId) -> Result<()> {
        Ok(())
    }

    #[instrument(skip(self))]
    async fn add_member(&self, _group_id: GroupId, _user_id: UserId) -> Result<()> {
        Ok(())
    }

    #[instrument(skip(self))]
    async fn remove_member(&self, _group_id: GroupId, _user_id: UserId) -> Result<()> {
        Ok(())
    }

    #[instrument(skip(self))]
    async fn list_members(
        &self,
        _group_id: GroupId,
        _offset: u32,
        _limit: u32,
    ) -> Result<Vec<User>> {
        Ok(vec![])
    }
}
