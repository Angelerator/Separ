-- Identity Providers Schema Migration
-- Adds support for multi-provider identity sync and authentication

-- =============================================================================
-- Identity Providers Table
-- =============================================================================

CREATE TABLE identity_providers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_type VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    
    -- Provider-specific configuration (encrypted sensitive fields)
    config JSONB NOT NULL,
    
    -- Feature flags
    features JSONB NOT NULL DEFAULT '{
        "sync_users": true,
        "sync_groups": true,
        "sync_apps": false,
        "authentication": true,
        "jit_provisioning": true,
        "resolve_nested_groups": false
    }'::jsonb,
    
    -- Sync settings
    sync_settings JSONB NOT NULL DEFAULT '{
        "interval_secs": 300,
        "batch_size": 100,
        "timeout_secs": 300,
        "max_retries": 3,
        "full_sync_enabled": true,
        "full_sync_interval_hours": 24
    }'::jsonb,
    
    -- Domain associations (for automatic provider detection)
    domains TEXT[] NOT NULL DEFAULT '{}',
    
    -- Priority for provider selection (lower = higher priority)
    priority INTEGER NOT NULL DEFAULT 0,
    
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT identity_providers_type_check CHECK (
        provider_type IN (
            'azure_ad', 'okta', 'google', 'aws_sso', 'keycloak',
            'auth0', 'onelogin', 'ping_identity', 'generic_oidc',
            'generic_saml', 'ldap', 'direct'
        )
    )
);

CREATE INDEX idx_identity_providers_tenant_id ON identity_providers(tenant_id);
CREATE INDEX idx_identity_providers_type ON identity_providers(provider_type);
CREATE INDEX idx_identity_providers_enabled ON identity_providers(tenant_id, enabled);
CREATE INDEX idx_identity_providers_domains ON identity_providers USING GIN (domains);

-- =============================================================================
-- Identity Mappings Table
-- Maps external identities to Separ IDs
-- =============================================================================

CREATE TABLE identity_user_mappings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    external_id VARCHAR(512) NOT NULL,
    separ_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, provider_id, external_id)
);

CREATE INDEX idx_identity_user_mappings_tenant ON identity_user_mappings(tenant_id);
CREATE INDEX idx_identity_user_mappings_provider ON identity_user_mappings(provider_id);
CREATE INDEX idx_identity_user_mappings_external ON identity_user_mappings(provider_id, external_id);
CREATE INDEX idx_identity_user_mappings_separ ON identity_user_mappings(separ_user_id);

CREATE TABLE identity_group_mappings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    external_id VARCHAR(512) NOT NULL,
    separ_group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, provider_id, external_id)
);

CREATE INDEX idx_identity_group_mappings_tenant ON identity_group_mappings(tenant_id);
CREATE INDEX idx_identity_group_mappings_provider ON identity_group_mappings(provider_id);
CREATE INDEX idx_identity_group_mappings_external ON identity_group_mappings(provider_id, external_id);
CREATE INDEX idx_identity_group_mappings_separ ON identity_group_mappings(separ_group_id);

-- =============================================================================
-- Sync History Table
-- Tracks sync operations for audit and debugging
-- =============================================================================

CREATE TABLE identity_sync_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sync_type VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL,
    
    -- Stats
    users_created INTEGER NOT NULL DEFAULT 0,
    users_updated INTEGER NOT NULL DEFAULT 0,
    users_deleted INTEGER NOT NULL DEFAULT 0,
    groups_created INTEGER NOT NULL DEFAULT 0,
    groups_updated INTEGER NOT NULL DEFAULT 0,
    groups_deleted INTEGER NOT NULL DEFAULT 0,
    apps_created INTEGER NOT NULL DEFAULT 0,
    apps_updated INTEGER NOT NULL DEFAULT 0,
    apps_deleted INTEGER NOT NULL DEFAULT 0,
    
    -- Errors
    errors JSONB NOT NULL DEFAULT '[]'::jsonb,
    
    -- Timing
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    duration_ms BIGINT,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT sync_history_type_check CHECK (sync_type IN ('full', 'incremental', 'jit')),
    CONSTRAINT sync_history_status_check CHECK (status IN ('success', 'partial_success', 'failed', 'in_progress'))
);

CREATE INDEX idx_sync_history_provider ON identity_sync_history(provider_id);
CREATE INDEX idx_sync_history_tenant ON identity_sync_history(tenant_id);
CREATE INDEX idx_sync_history_started ON identity_sync_history(started_at DESC);

-- =============================================================================
-- Service Principals Table (for synced apps/services)
-- =============================================================================

CREATE TABLE service_principals (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id UUID REFERENCES identity_providers(id) ON DELETE SET NULL,
    external_id VARCHAR(512),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    app_type VARCHAR(50) NOT NULL DEFAULT 'service_principal',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT sp_type_check CHECK (
        app_type IN ('application', 'service_principal', 'managed_identity', 'm2m_client', 'other')
    )
);

CREATE INDEX idx_service_principals_tenant ON service_principals(tenant_id);
CREATE INDEX idx_service_principals_provider ON service_principals(provider_id);
CREATE INDEX idx_service_principals_external ON service_principals(provider_id, external_id);

-- =============================================================================
-- Add source column to users and groups
-- =============================================================================

ALTER TABLE users ADD COLUMN IF NOT EXISTS source VARCHAR(50) DEFAULT 'direct';
ALTER TABLE groups ADD COLUMN IF NOT EXISTS source VARCHAR(50) DEFAULT 'direct';

CREATE INDEX IF NOT EXISTS idx_users_source ON users(tenant_id, source);
CREATE INDEX IF NOT EXISTS idx_groups_source ON groups(tenant_id, source);

-- =============================================================================
-- Triggers for updated_at
-- =============================================================================

CREATE TRIGGER update_identity_providers_updated_at 
    BEFORE UPDATE ON identity_providers 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_identity_user_mappings_updated_at 
    BEFORE UPDATE ON identity_user_mappings 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_identity_group_mappings_updated_at 
    BEFORE UPDATE ON identity_group_mappings 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_service_principals_updated_at 
    BEFORE UPDATE ON service_principals 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

