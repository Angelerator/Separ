//! Storage Connection Models
//!
//! Types for managing cloud storage connections (Azure ADLS, S3, GCS)
//! with encrypted credentials and multiple authentication methods.

use crate::ids::{TenantId, UserId};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

// =============================================================================
// Storage Connection ID
// =============================================================================

/// Strongly-typed storage connection ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StorageConnectionId(Uuid);

impl StorageConnectionId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for StorageConnectionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for StorageConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for StorageConnectionId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(Self)
    }
}

// =============================================================================
// Storage Types
// =============================================================================

/// Type of cloud storage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageType {
    /// Azure Data Lake Storage Gen2
    Adls,
    /// Amazon S3
    S3,
    /// Google Cloud Storage
    Gcs,
}

impl fmt::Display for StorageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageType::Adls => write!(f, "adls"),
            StorageType::S3 => write!(f, "s3"),
            StorageType::Gcs => write!(f, "gcs"),
        }
    }
}

impl FromStr for StorageType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "adls" | "azure" | "blob" => Ok(StorageType::Adls),
            "s3" | "aws" => Ok(StorageType::S3),
            "gcs" | "gcp" | "google" => Ok(StorageType::Gcs),
            _ => Err(format!("Unknown storage type: {}", s)),
        }
    }
}

/// Azure authentication method
///
/// Secure authentication options for Azure Storage:
/// - ServicePrincipal: Recommended for local development (App Registration)
/// - ManagedIdentity: Recommended for production (most secure, no credentials)
/// - WorkloadIdentity: For Kubernetes deployments
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AzureAuthMethod {
    /// Service Principal with client ID and secret (recommended for local dev)
    ServicePrincipal,
    /// Managed Identity (recommended for production - most secure)
    ManagedIdentity,
    /// Workload Identity (for Kubernetes)
    WorkloadIdentity,
}

impl fmt::Display for AzureAuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AzureAuthMethod::ServicePrincipal => write!(f, "service_principal"),
            AzureAuthMethod::ManagedIdentity => write!(f, "managed_identity"),
            AzureAuthMethod::WorkloadIdentity => write!(f, "workload_identity"),
        }
    }
}

impl FromStr for AzureAuthMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "service_principal" | "serviceprincipal" | "spn" => {
                Ok(AzureAuthMethod::ServicePrincipal)
            }
            "managed_identity" | "managedidentity" | "mi" => Ok(AzureAuthMethod::ManagedIdentity),
            "workload_identity" | "workloadidentity" | "wi" => {
                Ok(AzureAuthMethod::WorkloadIdentity)
            }
            _ => Err(format!("Unknown Azure auth method: {}. Valid options: service_principal, managed_identity, workload_identity", s)),
        }
    }
}

/// Storage connection status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageConnectionStatus {
    /// Connection is active and working
    Active,
    /// Connection is disabled
    Inactive,
    /// Connection has errors
    Error,
}

impl fmt::Display for StorageConnectionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageConnectionStatus::Active => write!(f, "active"),
            StorageConnectionStatus::Inactive => write!(f, "inactive"),
            StorageConnectionStatus::Error => write!(f, "error"),
        }
    }
}

// =============================================================================
// Storage Connection Model
// =============================================================================

/// A storage connection with encrypted credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConnection {
    pub id: StorageConnectionId,
    pub tenant_id: TenantId,
    pub name: String,
    pub description: Option<String>,
    pub storage_type: StorageType,

    // Azure ADLS/Blob specific
    pub azure_account_name: Option<String>,
    pub azure_container: Option<String>,
    pub azure_auth_method: Option<AzureAuthMethod>,
    pub azure_tenant_id: Option<String>,
    pub azure_client_id: Option<String>,
    #[serde(skip_serializing)]
    pub azure_client_secret_encrypted: Option<Vec<u8>>,
    #[serde(skip_serializing)]
    pub azure_access_key_encrypted: Option<Vec<u8>>,
    #[serde(skip_serializing)]
    pub azure_sas_token_encrypted: Option<Vec<u8>>,
    pub azure_managed_identity_client_id: Option<String>,

    // S3 specific
    pub s3_bucket: Option<String>,
    pub s3_region: Option<String>,
    pub s3_access_key_id: Option<String>,
    #[serde(skip_serializing)]
    pub s3_secret_access_key_encrypted: Option<Vec<u8>>,
    pub s3_endpoint_url: Option<String>,

    // GCS specific
    pub gcs_bucket: Option<String>,
    pub gcs_project_id: Option<String>,
    #[serde(skip_serializing)]
    pub gcs_service_account_key_encrypted: Option<Vec<u8>>,

    // Common
    pub key_prefix: Option<String>,
    pub status: StorageConnectionStatus,
    pub last_tested_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub created_by: Option<UserId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Storage connection with decrypted credentials (for authorized access)
#[derive(Debug, Clone)]
pub struct StorageConnectionWithCredentials {
    pub connection: StorageConnection,
    pub azure_client_secret: Option<String>,
    pub azure_access_key: Option<String>,
    pub azure_sas_token: Option<String>,
    pub s3_secret_access_key: Option<String>,
    pub gcs_service_account_key: Option<String>,
}

// =============================================================================
// Request/Response Types
// =============================================================================

/// Request to create a new storage connection
#[derive(Debug, Clone, Deserialize)]
pub struct CreateStorageConnectionRequest {
    pub name: String,
    pub description: Option<String>,
    pub storage_type: StorageType,

    // Azure
    pub azure_account_name: Option<String>,
    pub azure_container: Option<String>,
    pub azure_auth_method: Option<AzureAuthMethod>,
    pub azure_tenant_id: Option<String>,
    pub azure_client_id: Option<String>,
    pub azure_client_secret: Option<String>,
    pub azure_access_key: Option<String>,
    pub azure_sas_token: Option<String>,
    pub azure_managed_identity_client_id: Option<String>,

    // S3
    pub s3_bucket: Option<String>,
    pub s3_region: Option<String>,
    pub s3_access_key_id: Option<String>,
    pub s3_secret_access_key: Option<String>,
    pub s3_endpoint_url: Option<String>,

    // GCS
    pub gcs_bucket: Option<String>,
    pub gcs_project_id: Option<String>,
    pub gcs_service_account_key: Option<String>,

    pub key_prefix: Option<String>,
}

/// Request to update a storage connection
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateStorageConnectionRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<StorageConnectionStatus>,

    // Azure
    pub azure_account_name: Option<String>,
    pub azure_container: Option<String>,
    pub azure_auth_method: Option<AzureAuthMethod>,
    pub azure_tenant_id: Option<String>,
    pub azure_client_id: Option<String>,
    pub azure_client_secret: Option<String>,
    pub azure_access_key: Option<String>,
    pub azure_sas_token: Option<String>,
    pub azure_managed_identity_client_id: Option<String>,

    // S3
    pub s3_bucket: Option<String>,
    pub s3_region: Option<String>,
    pub s3_access_key_id: Option<String>,
    pub s3_secret_access_key: Option<String>,
    pub s3_endpoint_url: Option<String>,

    // GCS
    pub gcs_bucket: Option<String>,
    pub gcs_project_id: Option<String>,
    pub gcs_service_account_key: Option<String>,

    pub key_prefix: Option<String>,
}

// =============================================================================
// Repository Trait
// =============================================================================

/// Repository trait for storage connections
#[async_trait]
pub trait StorageConnectionRepository: Send + Sync {
    /// Create a new storage connection
    async fn create(
        &self,
        tenant_id: TenantId,
        created_by: UserId,
        request: &CreateStorageConnectionRequest,
    ) -> crate::Result<StorageConnection>;

    /// Get a storage connection by ID (without credentials)
    async fn get_by_id(&self, id: StorageConnectionId) -> crate::Result<Option<StorageConnection>>;

    /// Get a storage connection by ID with decrypted credentials
    async fn get_with_credentials(
        &self,
        id: StorageConnectionId,
    ) -> crate::Result<Option<StorageConnectionWithCredentials>>;

    /// List storage connections for a tenant
    async fn list_by_tenant(
        &self,
        tenant_id: TenantId,
        offset: u32,
        limit: u32,
    ) -> crate::Result<Vec<StorageConnection>>;

    /// Find a storage connection by storage location
    async fn find_by_storage_location(
        &self,
        tenant_id: TenantId,
        storage_type: &str,
        account_or_bucket: &str,
        container_or_prefix: &str,
    ) -> crate::Result<Option<StorageConnection>>;

    /// Update a storage connection
    async fn update(
        &self,
        id: StorageConnectionId,
        request: &UpdateStorageConnectionRequest,
    ) -> crate::Result<StorageConnection>;

    /// Update connection status after testing
    async fn update_status(
        &self,
        id: StorageConnectionId,
        status: StorageConnectionStatus,
        error: Option<&str>,
    ) -> crate::Result<()>;

    /// Delete a storage connection
    async fn delete(&self, id: StorageConnectionId) -> crate::Result<()>;

    /// Count connections for a tenant
    async fn count_by_tenant(&self, tenant_id: TenantId) -> crate::Result<u64>;
}
