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
    -- Azure authentication method
    azure_auth_method VARCHAR(50) CHECK (azure_auth_method IN (
        'service_principal',  -- Client ID + Secret
        'access_key',         -- Storage account access key
        'sas_token',          -- Shared Access Signature
        'managed_identity',   -- Azure Managed Identity (no secrets needed)
        'workload_identity',  -- Kubernetes Workload Identity (no secrets needed)
        'cli'                 -- Azure CLI (development only)
    )),
    -- Service Principal credentials
    azure_tenant_id VARCHAR(255),
    azure_client_id VARCHAR(255),
    azure_client_secret_encrypted BYTEA,
    -- Access Key credential
    azure_access_key_encrypted BYTEA,
    -- SAS Token credential
    azure_sas_token_encrypted BYTEA,
    -- Managed Identity / Workload Identity settings
    azure_managed_identity_client_id VARCHAR(255),  -- Optional: specific managed identity
    
    -- S3 specific
    s3_bucket VARCHAR(255),
    s3_region VARCHAR(50),
    s3_access_key_id VARCHAR(255),
    s3_secret_access_key_encrypted BYTEA,
    s3_endpoint_url VARCHAR(500),
    
    -- GCS specific
    gcs_bucket VARCHAR(255),
    gcs_project_id VARCHAR(255),
    gcs_service_account_key_encrypted BYTEA,
    
    -- Common fields
    key_prefix VARCHAR(500),
    
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
CREATE INDEX idx_storage_connections_status ON storage_connections(status);

-- Trigger to update updated_at
CREATE TRIGGER update_storage_connections_timestamp
    BEFORE UPDATE ON storage_connections
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Comments
COMMENT ON TABLE storage_connections IS 'Cloud storage connection credentials for Yekta data catalog';
COMMENT ON COLUMN storage_connections.azure_client_secret_encrypted IS 'Encrypted with server encryption key using AES-256-GCM';
COMMENT ON COLUMN storage_connections.s3_secret_access_key_encrypted IS 'Encrypted with server encryption key using AES-256-GCM';
COMMENT ON COLUMN storage_connections.gcs_service_account_key_encrypted IS 'Encrypted with server encryption key using AES-256-GCM';
