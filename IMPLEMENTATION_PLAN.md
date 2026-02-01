# Separ Implementation Plan

## Implementation Status

| Phase | Feature | Status |
|-------|---------|--------|
| 1.1 | Update SpiceDB Schema | ✅ Complete |
| 1.2 | Update Embedded Schema in Rust | ✅ Complete |
| 1.3 | Add Permission Registry Entries | ⏳ Pending |
| 1.4 | Create Database Migration | ✅ Complete |
| 1.5 | Implement Repository | ✅ Complete |
| 1.6 | Add API Handlers | ✅ Complete |
| 1.7 | Add Routes | ✅ Complete |
| 1.8 | Integrate into AppState | ✅ Complete |
| 2.1 | Complete Audit Repository | ⏳ Pending (partial) |
| 2.2 | Add Audit API Handler | ✅ Complete |
| 2.3 | Add Audit Routes | ✅ Complete |

**All Core Features Implemented!**

Configuration required for production:
- Set `SEPAR__ENCRYPTION__KEY` environment variable (64-character hex string, 32 bytes)
- Generate with: `openssl rand -hex 32`

## Executive Summary

This document outlines the comprehensive implementation plan for enhancing Separ to fully support:
1. Storage connection permissions for Yekta data catalog
2. Complete audit logging with queryable API
3. Enhanced permission registry for storage operations

---

## Current State Analysis

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Separ                                      │
├─────────────────────────────────────────────────────────────────────┤
│  separ-api          HTTP REST API (Axum)                            │
│  separ-spicedb      SpiceDB gRPC client & authorization service     │
│  separ-db           PostgreSQL repositories (SQLx)                   │
│  separ-oauth        JWT & OAuth provider handling                    │
│  separ-core         Domain models, traits, error types               │
│  separ-identity     Identity provider integrations                   │
│  separ-sync         SCIM, webhooks, directory sync                   │
│  separ-proxy        PostgreSQL wire protocol proxy                   │
│  separ-server       Main entry point                                 │
└─────────────────────────────────────────────────────────────────────┘
```

### Existing SpiceDB Schema (Yekta-related)

```zed
definition yekta_catalog {
    relation tenant: tenant
    relation admin: user | service_account | group#member
    relation editor: user | service_account | group#member
    relation viewer: user | service_account | group#member
    
    permission manage = admin + tenant->manage
    permission write = admin + editor + tenant->manage
    permission read = admin + editor + viewer + tenant->view
}

definition yekta_resource {
    relation tenant: tenant
    relation catalog: yekta_catalog
    relation owner: user | service_account | group#member
    relation editor: user | service_account | group#member
    relation viewer: user | service_account | group#member
    
    permission manage = owner + catalog->manage + tenant->manage
    permission write = owner + editor + catalog->write + tenant->manage
    permission read = owner + editor + viewer + catalog->read + tenant->view
}

definition yekta_alias {
    relation tenant: tenant
    relation catalog: yekta_catalog
    relation owner: user | service_account | group#member
    relation editor: user | service_account | group#member
    relation viewer: user | service_account | group#member
    
    permission manage = owner + catalog->manage + tenant->manage
    permission write = owner + editor + catalog->write + tenant->manage
    permission read = owner + editor + viewer + catalog->read + tenant->view
}
```

### What's Missing

| Feature | Status | Priority |
|---------|--------|----------|
| Storage Connection permissions | ❌ Missing | P0 |
| Audit log query API | ❌ Missing | P1 |
| Storage connection admin endpoints | ❌ Missing | P1 |
| Enhanced permission registry | ⚠️ Partial | P2 |

---

## Phase 1: Storage Connection Permissions (P0)

### 1.1 Update SpiceDB Schema

**File:** `spicedb/schema.zed`

Add after `yekta_alias` definition:

```zed
// =============================================================================
// Storage Connections - Cloud Storage Credential Management
// =============================================================================

// Storage Connection - credentials for accessing cloud storage
// Used by Yekta to access Azure ADLS, S3, GCS on behalf of users
definition storage_connection {
    // Parent relationships for inheritance
    relation tenant: tenant
    relation catalog: yekta_catalog
    
    // Direct access relationships
    relation owner: user | service_account | group#member     // Full control
    relation admin: user | service_account | group#member     // Can manage and use
    relation user: user | service_account | group#member      // Can use for resources
    relation viewer: user | service_account | group#member    // Can see exists
    
    // Permissions with inheritance from catalog and tenant
    permission manage = owner + admin + catalog->manage + tenant->manage
    permission use = owner + admin + user + catalog->write + tenant->manage
    permission read = owner + admin + user + viewer + catalog->read + tenant->view
}
```

### 1.2 Update Embedded Schema in Rust

**File:** `crates/separ-spicedb/src/schema.rs`

Update the `SCHEMA` constant to include the new `storage_connection` definition.

### 1.3 Add Permission Registry Entries

**File:** `crates/separ-api/src/handlers/permissions.rs`

Add to the permission registry:

```rust
// In the registry initialization
PermissionEntry {
    resource_type: "storage_connection".to_string(),
    relation: "owner".to_string(),
    name: "Storage Connection Owner".to_string(),
    description: "Full control over storage connection including credentials".to_string(),
    category: "storage".to_string(),
    requires_resource_id: true,
},
PermissionEntry {
    resource_type: "storage_connection".to_string(),
    relation: "admin".to_string(),
    name: "Storage Connection Admin".to_string(),
    description: "Manage storage connection settings".to_string(),
    category: "storage".to_string(),
    requires_resource_id: true,
},
PermissionEntry {
    resource_type: "storage_connection".to_string(),
    relation: "user".to_string(),
    name: "Storage Connection User".to_string(),
    description: "Use storage connection for data resources".to_string(),
    category: "storage".to_string(),
    requires_resource_id: true,
},
PermissionEntry {
    resource_type: "storage_connection".to_string(),
    relation: "viewer".to_string(),
    name: "Storage Connection Viewer".to_string(),
    description: "View storage connection metadata (not credentials)".to_string(),
    category: "storage".to_string(),
    requires_resource_id: true,
},
```

### 1.4 Create Database Migration

**File:** `crates/separ-db/migrations/20260131000001_storage_connections.sql`

```sql
-- Storage Connections for Yekta Data Catalog
-- Stores encrypted credentials for Azure ADLS, S3, GCS

CREATE TABLE storage_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- Identification
    name VARCHAR(255) NOT NULL,
    description TEXT,
    
    -- Storage type and configuration
    storage_type VARCHAR(50) NOT NULL CHECK (storage_type IN ('adls', 's3', 'gcs')),
    
    -- Azure ADLS specific
    azure_account_name VARCHAR(255),
    azure_container VARCHAR(255),
    azure_tenant_id VARCHAR(255),
    azure_client_id VARCHAR(255),
    azure_client_secret_encrypted BYTEA,  -- Encrypted with server key
    
    -- S3 specific
    s3_bucket VARCHAR(255),
    s3_region VARCHAR(50),
    s3_access_key_id VARCHAR(255),
    s3_secret_access_key_encrypted BYTEA,
    s3_endpoint_url VARCHAR(500),  -- For S3-compatible (MinIO, etc.)
    
    -- GCS specific
    gcs_bucket VARCHAR(255),
    gcs_project_id VARCHAR(255),
    gcs_service_account_key_encrypted BYTEA,
    
    -- Common fields
    key_prefix VARCHAR(500),  -- Optional path prefix
    
    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'error')),
    last_tested_at TIMESTAMPTZ,
    last_error TEXT,
    
    -- Audit
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Constraints
    UNIQUE(tenant_id, name)
);

-- Indexes
CREATE INDEX idx_storage_connections_tenant ON storage_connections(tenant_id);
CREATE INDEX idx_storage_connections_type ON storage_connections(storage_type);

-- Trigger to update updated_at
CREATE TRIGGER update_storage_connections_timestamp
    BEFORE UPDATE ON storage_connections
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Function to encrypt secrets (use application-level encryption)
COMMENT ON COLUMN storage_connections.azure_client_secret_encrypted IS 'Encrypted with server encryption key using AES-256-GCM';
COMMENT ON COLUMN storage_connections.s3_secret_access_key_encrypted IS 'Encrypted with server encryption key using AES-256-GCM';
COMMENT ON COLUMN storage_connections.gcs_service_account_key_encrypted IS 'Encrypted with server encryption key using AES-256-GCM';
```

### 1.5 Implement Repository

**File:** `crates/separ-db/src/repositories/storage_connection.rs` (NEW)

```rust
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use separ_core::{Error, Result, StorageConnection, CreateStorageConnectionRequest};

#[async_trait]
pub trait StorageConnectionRepository: Send + Sync {
    async fn create(&self, tenant_id: Uuid, created_by: Uuid, request: CreateStorageConnectionRequest) -> Result<StorageConnection>;
    async fn get(&self, id: Uuid) -> Result<Option<StorageConnection>>;
    async fn list_by_tenant(&self, tenant_id: Uuid) -> Result<Vec<StorageConnection>>;
    async fn update(&self, id: Uuid, request: UpdateStorageConnectionRequest) -> Result<StorageConnection>;
    async fn delete(&self, id: Uuid) -> Result<()>;
    async fn find_by_account(&self, tenant_id: Uuid, storage_type: &str, account: &str, container: &str) -> Result<Option<StorageConnection>>;
}

pub struct PgStorageConnectionRepository {
    pool: PgPool,
    encryption_key: Vec<u8>,  // For encrypting/decrypting secrets
}

impl PgStorageConnectionRepository {
    pub fn new(pool: PgPool, encryption_key: Vec<u8>) -> Self {
        Self { pool, encryption_key }
    }
    
    fn encrypt(&self, plaintext: &str) -> Vec<u8> {
        // Use AES-256-GCM encryption
        // Implementation using ring or aes-gcm crate
        todo!()
    }
    
    fn decrypt(&self, ciphertext: &[u8]) -> Result<String> {
        // Use AES-256-GCM decryption
        todo!()
    }
}

#[async_trait]
impl StorageConnectionRepository for PgStorageConnectionRepository {
    // ... implement all methods ...
}
```

### 1.6 Add API Handlers

**File:** `crates/separ-api/src/handlers/storage_connections.rs` (NEW)

```rust
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};

use crate::{ApiError, ApiResult, AppState};

/// Create a new storage connection
/// 
/// Requires: Platform admin OR tenant admin
pub async fn create_storage_connection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<CreateStorageConnectionRequest>,
) -> ApiResult<(StatusCode, Json<StorageConnectionResponse>)> {
    // 1. Verify user is tenant admin or platform admin
    // 2. Encrypt credentials
    // 3. Insert into database
    // 4. Grant owner permission to creator
    // 5. Link to tenant for inheritance
    todo!()
}

/// List storage connections for tenant
/// 
/// Requires: Tenant viewer or higher
/// Note: Credentials are NOT included in response
pub async fn list_storage_connections(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> ApiResult<Json<Vec<StorageConnectionSummary>>> {
    // Only return metadata, not credentials
    todo!()
}

/// Get storage connection details
/// 
/// Requires: storage_connection:read permission
/// Note: Credentials included only if manage permission
pub async fn get_storage_connection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<StorageConnectionResponse>> {
    todo!()
}

/// Update storage connection
/// 
/// Requires: storage_connection:manage permission
pub async fn update_storage_connection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateStorageConnectionRequest>,
) -> ApiResult<Json<StorageConnectionResponse>> {
    todo!()
}

/// Delete storage connection
/// 
/// Requires: storage_connection:manage permission
pub async fn delete_storage_connection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    todo!()
}

/// Test storage connection
/// 
/// Requires: storage_connection:use permission
pub async fn test_storage_connection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<TestConnectionResponse>> {
    todo!()
}
```

### 1.7 Add Routes

**File:** `crates/separ-api/src/routes.rs`

Add to admin routes:

```rust
// Storage Connections (admin only)
.route("/api/v1/admin/storage-connections", 
    get(storage_connections::list_storage_connections)
    .post(storage_connections::create_storage_connection))
.route("/api/v1/admin/storage-connections/:id",
    get(storage_connections::get_storage_connection)
    .put(storage_connections::update_storage_connection)
    .delete(storage_connections::delete_storage_connection))
.route("/api/v1/admin/storage-connections/:id/test",
    post(storage_connections::test_storage_connection))
```

---

## Phase 2: Audit Log Query API (P1)

### 2.1 Complete Audit Repository

**File:** `crates/separ-db/src/repositories/audit.rs`

The `query` method is currently stubbed. Implement it:

```rust
async fn query(&self, filter: AuditFilter) -> Result<Vec<AuditEvent>> {
    let mut query = QueryBuilder::new(
        "SELECT id, timestamp, event_type, actor_id, actor_type, resource_type, 
                resource_id, action, result, metadata, ip_address, user_agent
         FROM audit_events WHERE 1=1"
    );
    
    if let Some(actor_id) = &filter.actor_id {
        query.push(" AND actor_id = ");
        query.push_bind(actor_id);
    }
    
    if let Some(resource_type) = &filter.resource_type {
        query.push(" AND resource_type = ");
        query.push_bind(resource_type);
    }
    
    if let Some(resource_id) = &filter.resource_id {
        query.push(" AND resource_id = ");
        query.push_bind(resource_id);
    }
    
    if let Some(action) = &filter.action {
        query.push(" AND action = ");
        query.push_bind(action);
    }
    
    if let Some(from) = &filter.from_timestamp {
        query.push(" AND timestamp >= ");
        query.push_bind(from);
    }
    
    if let Some(to) = &filter.to_timestamp {
        query.push(" AND timestamp <= ");
        query.push_bind(to);
    }
    
    query.push(" ORDER BY timestamp DESC");
    
    if let Some(limit) = filter.limit {
        query.push(" LIMIT ");
        query.push_bind(limit as i64);
    }
    
    if let Some(offset) = filter.offset {
        query.push(" OFFSET ");
        query.push_bind(offset as i64);
    }
    
    let events = query
        .build_query_as::<AuditEvent>()
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Database(e.to_string()))?;
    
    Ok(events)
}
```

### 2.2 Add Audit API Handler

**File:** `crates/separ-api/src/handlers/audit.rs` (NEW)

```rust
use axum::{
    extract::{Query, State},
    Json,
};

#[derive(Debug, Deserialize)]
pub struct AuditQueryParams {
    pub actor_id: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub action: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// Query audit logs
/// 
/// Requires: Platform admin OR tenant admin (scoped to tenant)
pub async fn query_audit_logs(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<AuditQueryParams>,
) -> ApiResult<Json<PaginatedResponse<AuditEvent>>> {
    // 1. Check if platform admin (sees all) or tenant admin (sees tenant only)
    // 2. Apply tenant filter if not platform admin
    // 3. Query audit repository
    // 4. Return paginated results
    todo!()
}

/// Get audit log for specific resource
/// 
/// Requires: manage permission on resource
pub async fn get_resource_audit_log(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path((resource_type, resource_id)): Path<(String, String)>,
    Query(params): Query<AuditQueryParams>,
) -> ApiResult<Json<Vec<AuditEvent>>> {
    todo!()
}
```

### 2.3 Add Audit Routes

**File:** `crates/separ-api/src/routes.rs`

```rust
// Audit logs (admin only)
.route("/api/v1/admin/audit", get(audit::query_audit_logs))
.route("/api/v1/admin/audit/:resource_type/:resource_id", 
    get(audit::get_resource_audit_log))
```

### 2.4 Add Storage Connection Audit Events

Update audit logging to include storage connection events:

```rust
// In storage_connections.rs handlers, add audit logging

// On create
state.audit.log(AuditEvent {
    event_type: AuditEventType::StorageConnectionCreated,
    actor_id: auth.user_id.clone(),
    actor_type: "user".to_string(),
    resource_type: "storage_connection".to_string(),
    resource_id: connection.id.to_string(),
    action: "create".to_string(),
    result: "success".to_string(),
    metadata: json!({
        "name": connection.name,
        "storage_type": connection.storage_type,
        "tenant_id": tenant_id.to_string(),
    }),
    ..Default::default()
}).await?;

// On delete
state.audit.log(AuditEvent {
    event_type: AuditEventType::StorageConnectionDeleted,
    // ...
}).await?;

// On test
state.audit.log(AuditEvent {
    event_type: AuditEventType::StorageConnectionTested,
    // ...
}).await?;
```

---

## Phase 3: Enhanced Permission Registry (P2)

### 3.1 Add Permission Categories

**File:** `crates/separ-api/src/handlers/permissions.rs`

```rust
// Add "storage" category
pub fn get_permission_categories() -> Vec<PermissionCategory> {
    vec![
        PermissionCategory {
            id: "platform".to_string(),
            name: "Platform".to_string(),
            description: "Platform-wide administrative permissions".to_string(),
        },
        PermissionCategory {
            id: "tenant".to_string(),
            name: "Organization".to_string(),
            description: "Organization/tenant management permissions".to_string(),
        },
        PermissionCategory {
            id: "workspace".to_string(),
            name: "Workspace".to_string(),
            description: "Workspace and project permissions".to_string(),
        },
        PermissionCategory {
            id: "data".to_string(),
            name: "Data Catalog".to_string(),
            description: "Yekta data catalog permissions".to_string(),
        },
        // NEW
        PermissionCategory {
            id: "storage".to_string(),
            name: "Storage Connections".to_string(),
            description: "Cloud storage connection and credential permissions".to_string(),
        },
        PermissionCategory {
            id: "identity".to_string(),
            name: "Identity".to_string(),
            description: "User, group, and identity provider permissions".to_string(),
        },
    ]
}
```

---

## Testing Plan

### Unit Tests

1. **SpiceDB Schema Tests**
   - Verify `storage_connection` permissions work correctly
   - Test inheritance from `catalog` and `tenant`
   - Test cross-tenant access prevention

2. **Repository Tests**
   - Encryption/decryption of credentials
   - CRUD operations
   - Constraint violations

3. **Handler Tests**
   - Permission checks on all endpoints
   - Credential masking in responses
   - Error handling

### Integration Tests

1. **End-to-End Flow**
   - Create tenant → Create storage connection → Grant permission → Access via Yekta

2. **Audit Log Verification**
   - Verify all operations are logged
   - Test query filtering
   - Verify tenant scoping

---

## Deployment Steps

1. **Database Migration**
   ```bash
   cd crates/separ-db
   sqlx migrate run
   ```

2. **SpiceDB Schema Update**
   ```bash
   zed schema write spicedb/schema.zed
   ```

3. **Build and Deploy**
   ```bash
   cargo build --release
   docker build -t separ:latest .
   docker compose up -d
   ```

4. **Verify**
   ```bash
   curl http://localhost:8080/health
   curl http://localhost:8080/api/v1/admin/permissions/registry | jq '.[] | select(.category == "storage")'
   ```

---

## Configuration Changes

Add to `config/default.toml`:

```toml
[encryption]
# Key for encrypting storage credentials (32 bytes, base64 encoded)
# Generate with: openssl rand -base64 32
storage_key = ""

[storage]
# Default SAS token validity in seconds
default_sas_validity_seconds = 3600

# Maximum storage connections per tenant
max_connections_per_tenant = 100
```

---

## Summary

| Phase | Feature | Files Changed | Estimated Effort |
|-------|---------|---------------|------------------|
| 1 | Storage Connection Permissions | 7 new/modified | 3 days |
| 2 | Audit Log Query API | 3 new/modified | 1 day |
| 3 | Enhanced Permission Registry | 1 modified | 0.5 days |

**Total Estimated Effort: 4.5 days**

---

## Next Steps After Separ

Once Separ is complete:
1. Yekta needs to call Separ's storage connection API
2. Yekta uses decrypted credentials to access Azure/S3
3. Hormoz UI needs storage connection management screens
