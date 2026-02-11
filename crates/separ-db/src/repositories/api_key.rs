//! API Key repository for secure service-to-service authentication
//!
//! Following SpiceDB best practices:
//! - Store hashed keys (never plaintext)
//! - Support key rotation
//! - Least privilege via scopes

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use separ_core::{
    ApiKeyId, CreateApiKeyRequest, CreateApiKeyResponse, Result, SeparError, ServiceAccountId,
    TenantId, UserId, WorkspaceId,
};

/// Extended API Key for the repository (includes all fields)
#[derive(Debug, Clone)]
pub struct ApiKey {
    pub id: ApiKeyId,
    pub key_prefix: String,
    pub key_hash: String,
    pub name: String,
    pub description: Option<String>,
    pub service_account_id: Option<ServiceAccountId>,
    pub created_by: Option<UserId>,
    pub tenant_id: Option<TenantId>,
    pub workspace_id: Option<WorkspaceId>,
    pub scopes: Vec<String>,
    pub rate_limit_per_minute: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<UserId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ApiKey {
    /// Check if the key is currently valid
    pub fn is_valid(&self) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at < Utc::now() {
                return false;
            }
        }
        true
    }

    /// Check if the key has a specific scope
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(&scope.to_string()) || self.scopes.contains(&"*".to_string())
    }
}

/// API Key repository trait
#[async_trait]
pub trait ApiKeyRepository: Send + Sync {
    /// Create a new API key (returns plaintext key ONCE)
    async fn create(
        &self,
        request: CreateApiKeyRequest,
        created_by: Option<UserId>,
        tenant_id: Option<TenantId>,
        workspace_id: Option<WorkspaceId>,
    ) -> Result<CreateApiKeyResponse>;

    /// Validate an API key and return the key info if valid
    async fn validate(&self, key: &str) -> Result<Option<ApiKey>>;

    /// Get API key by ID
    async fn get_by_id(&self, id: ApiKeyId) -> Result<Option<ApiKey>>;

    /// List API keys by tenant
    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<ApiKey>>;

    /// List API keys by workspace
    async fn list_by_workspace(
        &self,
        workspace_id: WorkspaceId,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<ApiKey>>;

    /// List API keys by service account
    async fn list_by_service_account(
        &self,
        service_account_id: ServiceAccountId,
    ) -> Result<Vec<ApiKey>>;

    /// Revoke an API key
    async fn revoke(&self, id: ApiKeyId, revoked_by: UserId) -> Result<()>;

    /// Update last used timestamp
    async fn update_last_used(&self, id: ApiKeyId) -> Result<()>;
}

/// PostgreSQL implementation of API key repository
pub struct PgApiKeyRepository {
    pool: PgPool,
}

impl PgApiKeyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Generate a secure API key
    fn generate_key() -> String {
        // Format: sk_live_<32 random chars>
        let random_part: String = (0..32)
            .map(|_| {
                let idx = rand::random::<u8>() % 62;
                match idx {
                    0..=9 => (b'0' + idx) as char,
                    10..=35 => (b'a' + idx - 10) as char,
                    _ => (b'A' + idx - 36) as char,
                }
            })
            .collect();
        format!("sk_live_{}", random_part)
    }

    /// Hash an API key using SHA-256
    fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Extract prefix from key (first 12 chars)
    fn get_prefix(key: &str) -> String {
        key.chars().take(12).collect()
    }

    /// Parse row into ApiKey
    fn row_to_api_key(row: &sqlx::postgres::PgRow) -> Result<ApiKey> {
        Ok(ApiKey {
            id: ApiKeyId::from_uuid(
                row.try_get("id")
                    .map_err(|e| SeparError::database_error(e.to_string()))?,
            ),
            key_prefix: row
                .try_get("key_prefix")
                .map_err(|e| SeparError::database_error(e.to_string()))?,
            key_hash: row
                .try_get("key_hash")
                .map_err(|e| SeparError::database_error(e.to_string()))?,
            name: row
                .try_get("name")
                .map_err(|e| SeparError::database_error(e.to_string()))?,
            description: row
                .try_get("description")
                .map_err(|e| SeparError::database_error(e.to_string()))?,
            service_account_id: row
                .try_get::<Option<Uuid>, _>("service_account_id")
                .map_err(|e| SeparError::database_error(e.to_string()))?
                .map(ServiceAccountId::from_uuid),
            created_by: row
                .try_get::<Option<Uuid>, _>("created_by")
                .map_err(|e| SeparError::database_error(e.to_string()))?
                .map(UserId::from_uuid),
            tenant_id: row
                .try_get::<Option<Uuid>, _>("tenant_id")
                .map_err(|e| SeparError::database_error(e.to_string()))?
                .map(TenantId::from_uuid),
            workspace_id: row
                .try_get::<Option<Uuid>, _>("workspace_id")
                .unwrap_or(None)
                .map(WorkspaceId::from_uuid),
            scopes: row.try_get::<Vec<String>, _>("scopes").unwrap_or_default(),
            rate_limit_per_minute: row
                .try_get::<Option<i32>, _>("rate_limit_per_minute")
                .map_err(|e| SeparError::database_error(e.to_string()))?
                .unwrap_or(1000),
            expires_at: row
                .try_get("expires_at")
                .map_err(|e| SeparError::database_error(e.to_string()))?,
            last_used_at: row
                .try_get("last_used_at")
                .map_err(|e| SeparError::database_error(e.to_string()))?,
            revoked_at: row
                .try_get("revoked_at")
                .map_err(|e| SeparError::database_error(e.to_string()))?,
            revoked_by: row
                .try_get::<Option<Uuid>, _>("revoked_by")
                .map_err(|e| SeparError::database_error(e.to_string()))?
                .map(UserId::from_uuid),
            created_at: row
                .try_get("created_at")
                .map_err(|e| SeparError::database_error(e.to_string()))?,
            updated_at: row
                .try_get("updated_at")
                .map_err(|e| SeparError::database_error(e.to_string()))?,
        })
    }
}

#[async_trait]
impl ApiKeyRepository for PgApiKeyRepository {
    async fn create(
        &self,
        request: CreateApiKeyRequest,
        created_by: Option<UserId>,
        tenant_id: Option<TenantId>,
        workspace_id: Option<WorkspaceId>,
    ) -> Result<CreateApiKeyResponse> {
        let id = ApiKeyId::new();
        let key = Self::generate_key();
        let key_prefix = Self::get_prefix(&key);
        let key_hash = Self::hash_key(&key);

        let expires_at = request
            .expires_in_days
            .map(|days| Utc::now() + Duration::days(days as i64));

        let rate_limit = request.rate_limit_per_minute.unwrap_or(1000);

        sqlx::query(
            r#"
            INSERT INTO api_keys (
                id, key_prefix, key_hash, name, description,
                service_account_id, created_by, tenant_id, workspace_id,
                scopes, rate_limit_per_minute, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
        )
        .bind(id.as_uuid())
        .bind(&key_prefix)
        .bind(&key_hash)
        .bind(&request.name)
        .bind(&request.description)
        .bind(request.service_account_id.map(|id| *id.as_uuid()))
        .bind(created_by.map(|id| *id.as_uuid()))
        .bind(tenant_id.map(|id| *id.as_uuid()))
        .bind(workspace_id.map(|id| *id.as_uuid()))
        .bind(&request.scopes)
        .bind(rate_limit)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        Ok(CreateApiKeyResponse {
            id,
            key, // Plaintext - only returned once!
            key_prefix,
            name: request.name,
            scopes: request.scopes,
            expires_at,
            created_at: Utc::now(),
        })
    }

    async fn validate(&self, key: &str) -> Result<Option<ApiKey>> {
        let key_prefix = Self::get_prefix(key);
        let key_hash = Self::hash_key(key);

        let row = sqlx::query(
            r#"
            SELECT 
                id, key_prefix, key_hash, name, description,
                service_account_id, created_by, tenant_id, workspace_id,
                scopes, rate_limit_per_minute, expires_at,
                last_used_at, revoked_at, revoked_by,
                created_at, updated_at
            FROM api_keys
            WHERE key_prefix = $1 
              AND key_hash = $2
              AND revoked_at IS NULL
            "#,
        )
        .bind(&key_prefix)
        .bind(&key_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        match row {
            Some(r) => {
                let api_key = Self::row_to_api_key(&r)?;
                if !api_key.is_valid() {
                    return Ok(None);
                }
                Ok(Some(api_key))
            }
            None => Ok(None),
        }
    }

    async fn get_by_id(&self, id: ApiKeyId) -> Result<Option<ApiKey>> {
        let row = sqlx::query(
            r#"
            SELECT 
                id, key_prefix, key_hash, name, description,
                service_account_id, created_by, tenant_id, workspace_id,
                scopes, rate_limit_per_minute, expires_at,
                last_used_at, revoked_at, revoked_by,
                created_at, updated_at
            FROM api_keys
            WHERE id = $1
            "#,
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        match row {
            Some(r) => Ok(Some(Self::row_to_api_key(&r)?)),
            None => Ok(None),
        }
    }

    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<ApiKey>> {
        let rows = sqlx::query(
            r#"
            SELECT 
                id, key_prefix, key_hash, name, description,
                service_account_id, created_by, tenant_id, workspace_id,
                scopes, rate_limit_per_minute, expires_at,
                last_used_at, revoked_at, revoked_by,
                created_at, updated_at
            FROM api_keys
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            OFFSET $2 LIMIT $3
            "#,
        )
        .bind(tenant_id.as_uuid())
        .bind(offset as i64)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        rows.iter().map(Self::row_to_api_key).collect()
    }

    async fn list_by_workspace(
        &self,
        workspace_id: WorkspaceId,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<ApiKey>> {
        let rows = sqlx::query(
            r#"
            SELECT 
                id, key_prefix, key_hash, name, description,
                service_account_id, created_by, tenant_id, workspace_id,
                scopes, rate_limit_per_minute, expires_at,
                last_used_at, revoked_at, revoked_by,
                created_at, updated_at
            FROM api_keys
            WHERE workspace_id = $1
            ORDER BY created_at DESC
            OFFSET $2 LIMIT $3
            "#,
        )
        .bind(workspace_id.as_uuid())
        .bind(offset as i64)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        rows.iter().map(Self::row_to_api_key).collect()
    }

    async fn list_by_service_account(
        &self,
        service_account_id: ServiceAccountId,
    ) -> Result<Vec<ApiKey>> {
        let rows = sqlx::query(
            r#"
            SELECT 
                id, key_prefix, key_hash, name, description,
                service_account_id, created_by, tenant_id, workspace_id,
                scopes, rate_limit_per_minute, expires_at,
                last_used_at, revoked_at, revoked_by,
                created_at, updated_at
            FROM api_keys
            WHERE service_account_id = $1 AND revoked_at IS NULL
            ORDER BY created_at DESC
            "#,
        )
        .bind(service_account_id.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        rows.iter().map(Self::row_to_api_key).collect()
    }

    async fn revoke(&self, id: ApiKeyId, revoked_by: UserId) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE api_keys
            SET revoked_at = NOW(), revoked_by = $2, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id.as_uuid())
        .bind(revoked_by.as_uuid())
        .execute(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        Ok(())
    }

    async fn update_last_used(&self, id: ApiKeyId) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE api_keys
            SET last_used_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id.as_uuid())
        .execute(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        Ok(())
    }
}
