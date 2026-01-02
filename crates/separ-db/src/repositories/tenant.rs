//! Tenant repository implementation

use async_trait::async_trait;
use sqlx::{PgPool, Row};
use tracing::instrument;

use separ_core::{
    PlatformId, Result, SeparError, Tenant, TenantId, TenantRepository, TenantSettings,
    TenantStatus,
};

/// PostgreSQL implementation of TenantRepository
pub struct PgTenantRepository {
    pool: PgPool,
}

impl PgTenantRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TenantRepository for PgTenantRepository {
    #[instrument(skip(self, tenant))]
    async fn create(&self, tenant: &Tenant) -> Result<Tenant> {
        let settings_json =
            serde_json::to_value(&tenant.settings).map_err(|e| SeparError::Internal {
                message: e.to_string(),
            })?;

        let metadata_json =
            serde_json::to_value(&tenant.metadata).map_err(|e| SeparError::Internal {
                message: e.to_string(),
            })?;

        let status_str = match tenant.status {
            TenantStatus::Active => "active",
            TenantStatus::Suspended => "suspended",
            TenantStatus::PendingSetup => "pending_setup",
            TenantStatus::Deactivated => "deactivated",
        };

        sqlx::query(
            r#"
            INSERT INTO tenants (id, platform_id, name, slug, status, settings, metadata, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#
        )
        .bind(tenant.id.as_uuid())
        .bind(tenant.platform_id.as_uuid())
        .bind(&tenant.name)
        .bind(&tenant.slug)
        .bind(status_str)
        .bind(&settings_json)
        .bind(&metadata_json)
        .bind(tenant.created_at)
        .bind(tenant.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        Ok(tenant.clone())
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: TenantId) -> Result<Option<Tenant>> {
        let row = sqlx::query(
            r#"
            SELECT id, platform_id, name, slug, status, settings, metadata, created_at, updated_at
            FROM tenants
            WHERE id = $1
            "#,
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        match row {
            Some(row) => {
                let status_str: String = row.get("status");
                let status = match status_str.as_str() {
                    "active" => TenantStatus::Active,
                    "suspended" => TenantStatus::Suspended,
                    "pending_setup" => TenantStatus::PendingSetup,
                    "deactivated" => TenantStatus::Deactivated,
                    _ => TenantStatus::Active,
                };

                let settings_json: serde_json::Value = row.get("settings");
                let settings: TenantSettings =
                    serde_json::from_value(settings_json).unwrap_or_default();

                let metadata_json: serde_json::Value = row.get("metadata");
                let metadata = serde_json::from_value(metadata_json).unwrap_or_default();

                Ok(Some(Tenant {
                    id: TenantId::from_uuid(row.get("id")),
                    platform_id: PlatformId::from_uuid(row.get("platform_id")),
                    name: row.get("name"),
                    slug: row.get("slug"),
                    status,
                    settings,
                    metadata,
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                }))
            }
            None => Ok(None),
        }
    }

    #[instrument(skip(self))]
    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>> {
        let row = sqlx::query(
            r#"
            SELECT id, platform_id, name, slug, status, settings, metadata, created_at, updated_at
            FROM tenants
            WHERE slug = $1
            "#,
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        match row {
            Some(row) => {
                let status_str: String = row.get("status");
                let status = match status_str.as_str() {
                    "active" => TenantStatus::Active,
                    "suspended" => TenantStatus::Suspended,
                    "pending_setup" => TenantStatus::PendingSetup,
                    "deactivated" => TenantStatus::Deactivated,
                    _ => TenantStatus::Active,
                };

                let settings_json: serde_json::Value = row.get("settings");
                let settings: TenantSettings =
                    serde_json::from_value(settings_json).unwrap_or_default();

                let metadata_json: serde_json::Value = row.get("metadata");
                let metadata = serde_json::from_value(metadata_json).unwrap_or_default();

                Ok(Some(Tenant {
                    id: TenantId::from_uuid(row.get("id")),
                    platform_id: PlatformId::from_uuid(row.get("platform_id")),
                    name: row.get("name"),
                    slug: row.get("slug"),
                    status,
                    settings,
                    metadata,
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                }))
            }
            None => Ok(None),
        }
    }

    #[instrument(skip(self))]
    async fn list(&self, offset: u32, limit: u32) -> Result<Vec<Tenant>> {
        let rows = sqlx::query(
            r#"
            SELECT id, platform_id, name, slug, status, settings, metadata, created_at, updated_at
            FROM tenants
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        let tenants = rows
            .into_iter()
            .map(|row| {
                let status_str: String = row.get("status");
                let status = match status_str.as_str() {
                    "active" => TenantStatus::Active,
                    "suspended" => TenantStatus::Suspended,
                    "pending_setup" => TenantStatus::PendingSetup,
                    "deactivated" => TenantStatus::Deactivated,
                    _ => TenantStatus::Active,
                };

                let settings_json: serde_json::Value = row.get("settings");
                let settings: TenantSettings =
                    serde_json::from_value(settings_json).unwrap_or_default();

                let metadata_json: serde_json::Value = row.get("metadata");
                let metadata = serde_json::from_value(metadata_json).unwrap_or_default();

                Tenant {
                    id: TenantId::from_uuid(row.get("id")),
                    platform_id: PlatformId::from_uuid(row.get("platform_id")),
                    name: row.get("name"),
                    slug: row.get("slug"),
                    status,
                    settings,
                    metadata,
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                }
            })
            .collect();

        Ok(tenants)
    }

    #[instrument(skip(self, tenant))]
    async fn update(&self, tenant: &Tenant) -> Result<Tenant> {
        let settings_json =
            serde_json::to_value(&tenant.settings).map_err(|e| SeparError::Internal {
                message: e.to_string(),
            })?;

        let metadata_json =
            serde_json::to_value(&tenant.metadata).map_err(|e| SeparError::Internal {
                message: e.to_string(),
            })?;

        let status_str = match tenant.status {
            TenantStatus::Active => "active",
            TenantStatus::Suspended => "suspended",
            TenantStatus::PendingSetup => "pending_setup",
            TenantStatus::Deactivated => "deactivated",
        };

        sqlx::query(
            r#"
            UPDATE tenants
            SET name = $1, slug = $2, status = $3, settings = $4, metadata = $5, updated_at = $6
            WHERE id = $7
            "#,
        )
        .bind(&tenant.name)
        .bind(&tenant.slug)
        .bind(status_str)
        .bind(&settings_json)
        .bind(&metadata_json)
        .bind(tenant.updated_at)
        .bind(tenant.id.as_uuid())
        .execute(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        Ok(tenant.clone())
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: TenantId) -> Result<()> {
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(|e| SeparError::database_error(e.to_string()))?;

        Ok(())
    }
}
