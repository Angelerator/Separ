-- Resource grants: fine-grained per-user/group access control on catalog paths
--
-- Follows the same patterns as:
-- - Unity Catalog: GRANT SELECT ON TABLE ... TO user
-- - Apache Polaris: catalog_role privileges
-- - Lakekeeper: OpenFGA select/modify/describe grants
--
-- Grants are synced to SpiceDB for fast permission checks.
-- This table is the source of truth; SpiceDB is the enforcement layer.

CREATE TABLE resource_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    
    -- What path is this grant for?
    -- Supports wildcards: "/production/gold" covers everything under that prefix
    path_prefix VARCHAR(1000) NOT NULL,
    
    -- Who is the grant for?
    principal_type VARCHAR(20) NOT NULL CHECK (principal_type IN ('user', 'group')),
    principal_id UUID NOT NULL,
    
    -- What permission level?
    -- read: can preview, describe, list files
    -- read_write: can also create/modify resources
    -- admin: can manage grants, delete resources
    -- deny: explicitly block access (overrides workspace role)
    permission VARCHAR(20) NOT NULL CHECK (permission IN ('read', 'read_write', 'admin', 'deny')),
    
    -- Does this apply to sub-paths?
    recursive BOOLEAN NOT NULL DEFAULT true,
    
    -- Audit
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Prevent duplicate grants
    UNIQUE(workspace_id, path_prefix, principal_type, principal_id)
);

-- Indexes for common queries
CREATE INDEX idx_resource_grants_workspace ON resource_grants(workspace_id);
CREATE INDEX idx_resource_grants_principal ON resource_grants(principal_type, principal_id);
CREATE INDEX idx_resource_grants_path ON resource_grants(workspace_id, path_prefix);
