-- API Keys table for service-to-service authentication
-- Following SpiceDB best practices: store hashed keys, support rotation, least privilege

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Key identification
    key_prefix VARCHAR(12) NOT NULL,  -- First 12 chars for lookup (e.g., "sk_live_abc1")
    key_hash VARCHAR(128) NOT NULL,   -- SHA-256 hash of full key
    
    -- Ownership
    name VARCHAR(255) NOT NULL,       -- Human-readable name
    description TEXT,
    
    -- Service account linkage (optional)
    service_account_id UUID REFERENCES service_accounts(id) ON DELETE CASCADE,
    
    -- For user-created keys
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- Permissions (least privilege)
    scopes TEXT[] NOT NULL DEFAULT '{}',  -- e.g., ['read:resources', 'write:relationships']
    
    -- Rate limiting
    rate_limit_per_minute INT DEFAULT 1000,
    
    -- Lifecycle
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revoked_by UUID REFERENCES users(id),
    
    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for fast lookup by prefix
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix) WHERE revoked_at IS NULL;

-- Index for listing by tenant
CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id) WHERE revoked_at IS NULL;

-- Index for listing by service account
CREATE INDEX idx_api_keys_service_account ON api_keys(service_account_id) WHERE revoked_at IS NULL;

-- Service accounts table (if not exists)
CREATE TABLE IF NOT EXISTS service_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, name)
);

-- Audit log for API key usage
CREATE TABLE IF NOT EXISTS api_key_usage_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id UUID REFERENCES api_keys(id) ON DELETE CASCADE,
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    status_code INT,
    client_ip INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partition by time for efficient cleanup
CREATE INDEX idx_api_key_usage_created ON api_key_usage_log(created_at);
