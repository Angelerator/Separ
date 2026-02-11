-- Workspace Data Scoping Migration
-- Move data isolation from tenant-level to workspace-level

-- 1. API Keys: add workspace_id
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_api_keys_workspace ON api_keys(workspace_id) WHERE revoked_at IS NULL;

-- 2. Storage Connections: add workspace_id
ALTER TABLE storage_connections ADD COLUMN IF NOT EXISTS workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_storage_connections_workspace ON storage_connections(workspace_id);

-- 3. Groups: add workspace_id
ALTER TABLE groups ADD COLUMN IF NOT EXISTS workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_groups_workspace ON groups(workspace_id);

-- 4. Audit Events: add workspace_id for filtering
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS workspace_id UUID;
CREATE INDEX IF NOT EXISTS idx_audit_events_workspace ON audit_events(workspace_id);

-- 5. Webhook Configs: add workspace_id
ALTER TABLE webhook_configs ADD COLUMN IF NOT EXISTS workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE;

-- 6. Roles: add workspace_id
ALTER TABLE roles ADD COLUMN IF NOT EXISTS workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE;

-- 7. Service Accounts: add workspace_id
ALTER TABLE service_accounts ADD COLUMN IF NOT EXISTS workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE;
