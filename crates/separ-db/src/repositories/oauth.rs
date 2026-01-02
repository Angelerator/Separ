//! OAuth provider repository implementation (simplified)

use async_trait::async_trait;
use sqlx::PgPool;
use tracing::instrument;

use separ_core::{
    OAuthProvider, OAuthProviderId, OAuthProviderRepository, Result, SeparError, TenantId,
};

/// PostgreSQL implementation of OAuthProviderRepository
#[allow(dead_code)]
pub struct PgOAuthProviderRepository {
    pool: PgPool,
}

impl PgOAuthProviderRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl OAuthProviderRepository for PgOAuthProviderRepository {
    #[instrument(skip(self, _provider))]
    async fn create(&self, _provider: &OAuthProvider) -> Result<OAuthProvider> {
        Err(SeparError::Internal {
            message: "Not implemented".to_string(),
        })
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, _id: OAuthProviderId) -> Result<Option<OAuthProvider>> {
        Ok(None)
    }

    #[instrument(skip(self))]
    async fn list_by_tenant(&self, _tenant_id: TenantId) -> Result<Vec<OAuthProvider>> {
        Ok(vec![])
    }

    #[instrument(skip(self, _provider))]
    async fn update(&self, _provider: &OAuthProvider) -> Result<OAuthProvider> {
        Err(SeparError::Internal {
            message: "Not implemented".to_string(),
        })
    }

    #[instrument(skip(self))]
    async fn delete(&self, _id: OAuthProviderId) -> Result<()> {
        Ok(())
    }
}
