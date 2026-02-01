//! Storage connection repository implementation

use async_trait::async_trait;
use chrono::Utc;
use sqlx::PgPool;
use tracing::instrument;

use separ_core::{
    AzureAuthMethod, CreateStorageConnectionRequest, Result, SeparError, StorageConnection,
    StorageConnectionId, StorageConnectionRepository, StorageConnectionStatus,
    StorageConnectionWithCredentials, StorageType, TenantId, UpdateStorageConnectionRequest,
    UserId,
};

/// PostgreSQL implementation of StorageConnectionRepository
pub struct PgStorageConnectionRepository {
    pool: PgPool,
    encryption_key: Vec<u8>,
}

impl PgStorageConnectionRepository {
    pub fn new(pool: PgPool, encryption_key: Vec<u8>) -> Self {
        Self { pool, encryption_key }
    }

    /// Encrypt a secret using AES-256-GCM
    fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use rand::RngCore;

        if self.encryption_key.len() != 32 {
            return Err(SeparError::internal_error("Invalid encryption key length"));
        }

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| SeparError::internal_error(format!("Cipher init failed: {}", e)))?;

        // Generate random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| SeparError::internal_error(format!("Encryption failed: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    /// Decrypt a secret using AES-256-GCM
    fn decrypt(&self, ciphertext: &[u8]) -> Result<String> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        if ciphertext.len() < 12 {
            return Err(SeparError::internal_error("Invalid ciphertext length"));
        }

        if self.encryption_key.len() != 32 {
            return Err(SeparError::internal_error("Invalid encryption key length"));
        }

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| SeparError::internal_error(format!("Cipher init failed: {}", e)))?;

        // Extract nonce and ciphertext
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let encrypted = &ciphertext[12..];

        // Decrypt
        let plaintext = cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| SeparError::internal_error(format!("Decryption failed: {}", e)))?;

        String::from_utf8(plaintext)
            .map_err(|e| SeparError::internal_error(format!("Invalid UTF-8: {}", e)))
    }
}

#[async_trait]
impl StorageConnectionRepository for PgStorageConnectionRepository {
    #[instrument(skip(self, request))]
    async fn create(
        &self,
        tenant_id: TenantId,
        created_by: UserId,
        request: &CreateStorageConnectionRequest,
    ) -> Result<StorageConnection> {
        let id = StorageConnectionId::new();
        let now = Utc::now();
        let storage_type_str = request.storage_type.to_string();
        let azure_auth_method_str = request.azure_auth_method.map(|m| m.to_string());

        // Encrypt secrets
        let azure_secret_encrypted = request
            .azure_client_secret
            .as_ref()
            .map(|s| self.encrypt(s))
            .transpose()?;
        let azure_access_key_encrypted = request
            .azure_access_key
            .as_ref()
            .map(|s| self.encrypt(s))
            .transpose()?;
        let azure_sas_token_encrypted = request
            .azure_sas_token
            .as_ref()
            .map(|s| self.encrypt(s))
            .transpose()?;
        let s3_secret_encrypted = request
            .s3_secret_access_key
            .as_ref()
            .map(|s| self.encrypt(s))
            .transpose()?;
        let gcs_key_encrypted = request
            .gcs_service_account_key
            .as_ref()
            .map(|s| self.encrypt(s))
            .transpose()?;

        sqlx::query(
            r#"
            INSERT INTO storage_connections (
                id, tenant_id, name, description, storage_type,
                azure_account_name, azure_container, azure_auth_method,
                azure_tenant_id, azure_client_id, azure_client_secret_encrypted,
                azure_access_key_encrypted, azure_sas_token_encrypted,
                azure_managed_identity_client_id,
                s3_bucket, s3_region, s3_access_key_id, 
                s3_secret_access_key_encrypted, s3_endpoint_url,
                gcs_bucket, gcs_project_id, gcs_service_account_key_encrypted,
                key_prefix, status, created_by, created_at, updated_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23,
                'active', $24, $25, $26
            )
            "#,
        )
        .bind(id.as_uuid())
        .bind(tenant_id.as_uuid())
        .bind(&request.name)
        .bind(&request.description)
        .bind(&storage_type_str)
        .bind(&request.azure_account_name)
        .bind(&request.azure_container)
        .bind(&azure_auth_method_str)
        .bind(&request.azure_tenant_id)
        .bind(&request.azure_client_id)
        .bind(&azure_secret_encrypted)
        .bind(&azure_access_key_encrypted)
        .bind(&azure_sas_token_encrypted)
        .bind(&request.azure_managed_identity_client_id)
        .bind(&request.s3_bucket)
        .bind(&request.s3_region)
        .bind(&request.s3_access_key_id)
        .bind(&s3_secret_encrypted)
        .bind(&request.s3_endpoint_url)
        .bind(&request.gcs_bucket)
        .bind(&request.gcs_project_id)
        .bind(&gcs_key_encrypted)
        .bind(&request.key_prefix)
        .bind(created_by.as_uuid())
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        Ok(StorageConnection {
            id,
            tenant_id,
            name: request.name.clone(),
            description: request.description.clone(),
            storage_type: request.storage_type,
            azure_account_name: request.azure_account_name.clone(),
            azure_container: request.azure_container.clone(),
            azure_auth_method: request.azure_auth_method,
            azure_tenant_id: request.azure_tenant_id.clone(),
            azure_client_id: request.azure_client_id.clone(),
            azure_client_secret_encrypted: azure_secret_encrypted,
            azure_access_key_encrypted,
            azure_sas_token_encrypted,
            azure_managed_identity_client_id: request.azure_managed_identity_client_id.clone(),
            s3_bucket: request.s3_bucket.clone(),
            s3_region: request.s3_region.clone(),
            s3_access_key_id: request.s3_access_key_id.clone(),
            s3_secret_access_key_encrypted: s3_secret_encrypted,
            s3_endpoint_url: request.s3_endpoint_url.clone(),
            gcs_bucket: request.gcs_bucket.clone(),
            gcs_project_id: request.gcs_project_id.clone(),
            gcs_service_account_key_encrypted: gcs_key_encrypted,
            key_prefix: request.key_prefix.clone(),
            status: StorageConnectionStatus::Active,
            last_tested_at: None,
            last_error: None,
            created_by: Some(created_by),
            created_at: now,
            updated_at: now,
        })
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: StorageConnectionId) -> Result<Option<StorageConnection>> {
        let row = sqlx::query_as::<_, StorageConnectionRow>(
            r#"
            SELECT id, tenant_id, name, description, storage_type,
                   azure_account_name, azure_container, azure_auth_method,
                   azure_tenant_id, azure_client_id, azure_client_secret_encrypted,
                   azure_access_key_encrypted, azure_sas_token_encrypted,
                   azure_managed_identity_client_id,
                   s3_bucket, s3_region, s3_access_key_id, 
                   s3_secret_access_key_encrypted, s3_endpoint_url,
                   gcs_bucket, gcs_project_id, gcs_service_account_key_encrypted,
                   key_prefix, status, last_tested_at, last_error,
                   created_by, created_at, updated_at
            FROM storage_connections
            WHERE id = $1
            "#,
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        Ok(row.map(|r| r.into_model()))
    }

    #[instrument(skip(self))]
    async fn get_with_credentials(
        &self,
        id: StorageConnectionId,
    ) -> Result<Option<StorageConnectionWithCredentials>> {
        let connection = self.get_by_id(id).await?;

        match connection {
            Some(conn) => {
                let azure_secret = conn
                    .azure_client_secret_encrypted
                    .as_ref()
                    .map(|e| self.decrypt(e))
                    .transpose()?;
                let azure_access_key = conn
                    .azure_access_key_encrypted
                    .as_ref()
                    .map(|e| self.decrypt(e))
                    .transpose()?;
                let azure_sas_token = conn
                    .azure_sas_token_encrypted
                    .as_ref()
                    .map(|e| self.decrypt(e))
                    .transpose()?;
                let s3_secret = conn
                    .s3_secret_access_key_encrypted
                    .as_ref()
                    .map(|e| self.decrypt(e))
                    .transpose()?;
                let gcs_key = conn
                    .gcs_service_account_key_encrypted
                    .as_ref()
                    .map(|e| self.decrypt(e))
                    .transpose()?;

                Ok(Some(StorageConnectionWithCredentials {
                    connection: conn,
                    azure_client_secret: azure_secret,
                    azure_access_key,
                    azure_sas_token,
                    s3_secret_access_key: s3_secret,
                    gcs_service_account_key: gcs_key,
                }))
            }
            None => Ok(None),
        }
    }

    #[instrument(skip(self))]
    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<StorageConnection>> {
        let rows = sqlx::query_as::<_, StorageConnectionRow>(
            r#"
            SELECT id, tenant_id, name, description, storage_type,
                   azure_account_name, azure_container, azure_auth_method,
                   azure_tenant_id, azure_client_id, azure_client_secret_encrypted,
                   azure_access_key_encrypted, azure_sas_token_encrypted,
                   azure_managed_identity_client_id,
                   s3_bucket, s3_region, s3_access_key_id, 
                   s3_secret_access_key_encrypted, s3_endpoint_url,
                   gcs_bucket, gcs_project_id, gcs_service_account_key_encrypted,
                   key_prefix, status, last_tested_at, last_error,
                   created_by, created_at, updated_at
            FROM storage_connections
            WHERE tenant_id = $1
            ORDER BY name
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id.as_uuid())
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.into_model()).collect())
    }

    #[instrument(skip(self))]
    async fn find_by_storage_location(
        &self,
        tenant_id: TenantId,
        storage_type: &str,
        account_or_bucket: &str,
        container_or_prefix: &str,
    ) -> Result<Option<StorageConnection>> {
        let row = sqlx::query_as::<_, StorageConnectionRow>(
            r#"
            SELECT id, tenant_id, name, description, storage_type,
                   azure_account_name, azure_container, azure_auth_method,
                   azure_tenant_id, azure_client_id, azure_client_secret_encrypted,
                   azure_access_key_encrypted, azure_sas_token_encrypted,
                   azure_managed_identity_client_id,
                   s3_bucket, s3_region, s3_access_key_id, 
                   s3_secret_access_key_encrypted, s3_endpoint_url,
                   gcs_bucket, gcs_project_id, gcs_service_account_key_encrypted,
                   key_prefix, status, last_tested_at, last_error,
                   created_by, created_at, updated_at
            FROM storage_connections
            WHERE tenant_id = $1
              AND storage_type = $2
              AND (
                  (storage_type = 'adls' AND azure_account_name = $3 AND azure_container = $4)
                  OR (storage_type = 's3' AND s3_bucket = $3)
                  OR (storage_type = 'gcs' AND gcs_bucket = $3)
              )
              AND status = 'active'
            LIMIT 1
            "#,
        )
        .bind(tenant_id.as_uuid())
        .bind(storage_type)
        .bind(account_or_bucket)
        .bind(container_or_prefix)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        Ok(row.map(|r| r.into_model()))
    }

    #[instrument(skip(self, request))]
    async fn update(
        &self,
        id: StorageConnectionId,
        request: &UpdateStorageConnectionRequest,
    ) -> Result<StorageConnection> {
        let now = Utc::now();

        // Get existing connection
        let existing = self
            .get_by_id(id)
            .await?
            .ok_or_else(|| SeparError::not_found("storage_connection", id.to_string()))?;

        // Encrypt new secrets if provided
        let azure_secret = if request.azure_client_secret.is_some() {
            request
                .azure_client_secret
                .as_ref()
                .map(|s| self.encrypt(s))
                .transpose()?
        } else {
            existing.azure_client_secret_encrypted.clone()
        };

        let azure_access_key = if request.azure_access_key.is_some() {
            request
                .azure_access_key
                .as_ref()
                .map(|s| self.encrypt(s))
                .transpose()?
        } else {
            existing.azure_access_key_encrypted.clone()
        };

        let azure_sas_token = if request.azure_sas_token.is_some() {
            request
                .azure_sas_token
                .as_ref()
                .map(|s| self.encrypt(s))
                .transpose()?
        } else {
            existing.azure_sas_token_encrypted.clone()
        };

        let s3_secret = if request.s3_secret_access_key.is_some() {
            request
                .s3_secret_access_key
                .as_ref()
                .map(|s| self.encrypt(s))
                .transpose()?
        } else {
            existing.s3_secret_access_key_encrypted.clone()
        };

        let gcs_key = if request.gcs_service_account_key.is_some() {
            request
                .gcs_service_account_key
                .as_ref()
                .map(|s| self.encrypt(s))
                .transpose()?
        } else {
            existing.gcs_service_account_key_encrypted.clone()
        };

        let name = request.name.as_ref().unwrap_or(&existing.name);
        let description = request.description.as_ref().or(existing.description.as_ref());
        let status = request.status.unwrap_or(existing.status).to_string();
        let azure_auth_method_str = request.azure_auth_method.map(|m| m.to_string());

        sqlx::query(
            r#"
            UPDATE storage_connections SET
                name = $2,
                description = $3,
                status = $4,
                azure_account_name = COALESCE($5, azure_account_name),
                azure_container = COALESCE($6, azure_container),
                azure_auth_method = COALESCE($7, azure_auth_method),
                azure_tenant_id = COALESCE($8, azure_tenant_id),
                azure_client_id = COALESCE($9, azure_client_id),
                azure_client_secret_encrypted = COALESCE($10, azure_client_secret_encrypted),
                azure_access_key_encrypted = COALESCE($11, azure_access_key_encrypted),
                azure_sas_token_encrypted = COALESCE($12, azure_sas_token_encrypted),
                azure_managed_identity_client_id = COALESCE($13, azure_managed_identity_client_id),
                s3_bucket = COALESCE($14, s3_bucket),
                s3_region = COALESCE($15, s3_region),
                s3_access_key_id = COALESCE($16, s3_access_key_id),
                s3_secret_access_key_encrypted = COALESCE($17, s3_secret_access_key_encrypted),
                s3_endpoint_url = COALESCE($18, s3_endpoint_url),
                gcs_bucket = COALESCE($19, gcs_bucket),
                gcs_project_id = COALESCE($20, gcs_project_id),
                gcs_service_account_key_encrypted = COALESCE($21, gcs_service_account_key_encrypted),
                key_prefix = COALESCE($22, key_prefix),
                updated_at = $23
            WHERE id = $1
            "#,
        )
        .bind(id.as_uuid())
        .bind(name)
        .bind(description)
        .bind(&status)
        .bind(&request.azure_account_name)
        .bind(&request.azure_container)
        .bind(&azure_auth_method_str)
        .bind(&request.azure_tenant_id)
        .bind(&request.azure_client_id)
        .bind(&azure_secret)
        .bind(&azure_access_key)
        .bind(&azure_sas_token)
        .bind(&request.azure_managed_identity_client_id)
        .bind(&request.s3_bucket)
        .bind(&request.s3_region)
        .bind(&request.s3_access_key_id)
        .bind(&s3_secret)
        .bind(&request.s3_endpoint_url)
        .bind(&request.gcs_bucket)
        .bind(&request.gcs_project_id)
        .bind(&gcs_key)
        .bind(&request.key_prefix)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        self.get_by_id(id)
            .await?
            .ok_or_else(|| SeparError::not_found("storage_connection", id.to_string()))
    }

    #[instrument(skip(self))]
    async fn update_status(
        &self,
        id: StorageConnectionId,
        status: StorageConnectionStatus,
        error: Option<&str>,
    ) -> Result<()> {
        let now = Utc::now();
        let status_str = status.to_string();

        sqlx::query(
            r#"
            UPDATE storage_connections SET
                status = $2,
                last_error = $3,
                last_tested_at = $4,
                updated_at = $4
            WHERE id = $1
            "#,
        )
        .bind(id.as_uuid())
        .bind(&status_str)
        .bind(error)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: StorageConnectionId) -> Result<()> {
        sqlx::query("DELETE FROM storage_connections WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(|e| SeparError::database_error(e.to_string()))?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn count_by_tenant(&self, tenant_id: TenantId) -> Result<u64> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM storage_connections WHERE tenant_id = $1",
        )
        .bind(tenant_id.as_uuid())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| SeparError::database_error(e.to_string()))?;

        Ok(count.0 as u64)
    }
}

/// Row type for storage connection queries
#[derive(Debug, sqlx::FromRow)]
struct StorageConnectionRow {
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    name: String,
    description: Option<String>,
    storage_type: String,
    azure_account_name: Option<String>,
    azure_container: Option<String>,
    azure_auth_method: Option<String>,
    azure_tenant_id: Option<String>,
    azure_client_id: Option<String>,
    azure_client_secret_encrypted: Option<Vec<u8>>,
    azure_access_key_encrypted: Option<Vec<u8>>,
    azure_sas_token_encrypted: Option<Vec<u8>>,
    azure_managed_identity_client_id: Option<String>,
    s3_bucket: Option<String>,
    s3_region: Option<String>,
    s3_access_key_id: Option<String>,
    s3_secret_access_key_encrypted: Option<Vec<u8>>,
    s3_endpoint_url: Option<String>,
    gcs_bucket: Option<String>,
    gcs_project_id: Option<String>,
    gcs_service_account_key_encrypted: Option<Vec<u8>>,
    key_prefix: Option<String>,
    status: String,
    last_tested_at: Option<chrono::DateTime<Utc>>,
    last_error: Option<String>,
    created_by: Option<uuid::Uuid>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl StorageConnectionRow {
    fn into_model(self) -> StorageConnection {
        StorageConnection {
            id: StorageConnectionId::from_uuid(self.id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            name: self.name,
            description: self.description,
            storage_type: self.storage_type.parse().unwrap_or(StorageType::Adls),
            azure_account_name: self.azure_account_name,
            azure_container: self.azure_container,
            azure_auth_method: self.azure_auth_method.as_ref().and_then(|s| s.parse().ok()),
            azure_tenant_id: self.azure_tenant_id,
            azure_client_id: self.azure_client_id,
            azure_client_secret_encrypted: self.azure_client_secret_encrypted,
            azure_access_key_encrypted: self.azure_access_key_encrypted,
            azure_sas_token_encrypted: self.azure_sas_token_encrypted,
            azure_managed_identity_client_id: self.azure_managed_identity_client_id,
            s3_bucket: self.s3_bucket,
            s3_region: self.s3_region,
            s3_access_key_id: self.s3_access_key_id,
            s3_secret_access_key_encrypted: self.s3_secret_access_key_encrypted,
            s3_endpoint_url: self.s3_endpoint_url,
            gcs_bucket: self.gcs_bucket,
            gcs_project_id: self.gcs_project_id,
            gcs_service_account_key_encrypted: self.gcs_service_account_key_encrypted,
            key_prefix: self.key_prefix,
            status: match self.status.as_str() {
                "active" => StorageConnectionStatus::Active,
                "inactive" => StorageConnectionStatus::Inactive,
                "error" => StorageConnectionStatus::Error,
                _ => StorageConnectionStatus::Active,
            },
            last_tested_at: self.last_tested_at,
            last_error: self.last_error,
            created_by: self.created_by.map(UserId::from_uuid),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}
