-- Workspace-First, Tenant-Later Model
-- This migration updates the schema to support:
-- 1. Users can exist WITHOUT a tenant
-- 2. Users own workspaces (not tenants)
-- 3. Tenants only created when domain is claimed
-- 4. Platform admin assigns tenant owners

-- =============================================================================
-- Step 1: Make users.tenant_id nullable (users can exist without tenant)
-- =============================================================================

ALTER TABLE users 
  ALTER COLUMN tenant_id DROP NOT NULL;

-- =============================================================================
-- Step 2: Add domain and ownership fields to tenants
-- =============================================================================

-- Domain is the email domain (e.g., "acme.com")
ALTER TABLE tenants 
  ADD COLUMN IF NOT EXISTS domain VARCHAR(255);

-- Owner user ID - the user who owns/claimed this tenant
ALTER TABLE tenants 
  ADD COLUMN IF NOT EXISTS owner_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

-- Claimed timestamp
ALTER TABLE tenants 
  ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;

-- Update status constraint to include 'unclaimed' and 'claimed'
ALTER TABLE tenants 
  DROP CONSTRAINT IF EXISTS tenants_status_check;

ALTER TABLE tenants 
  ADD CONSTRAINT tenants_status_check 
  CHECK (status IN ('active', 'suspended', 'pending_setup', 'deactivated', 'unclaimed', 'claimed'));

-- Create unique index on domain (one tenant per domain)
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_domain ON tenants(domain) WHERE domain IS NOT NULL;

-- =============================================================================
-- Step 3: Update workspaces to support user ownership (not just tenant)
-- =============================================================================

-- Add owner_user_id to workspaces (workspace can be owned by a user directly)
ALTER TABLE workspaces 
  ADD COLUMN IF NOT EXISTS owner_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

-- Make tenant_id nullable (personal workspaces don't have a tenant)
ALTER TABLE workspaces 
  ALTER COLUMN tenant_id DROP NOT NULL;

-- Add workspace type
ALTER TABLE workspaces 
  ADD COLUMN IF NOT EXISTS workspace_type VARCHAR(50) DEFAULT 'personal';

ALTER TABLE workspaces 
  ADD CONSTRAINT workspaces_type_check 
  CHECK (workspace_type IN ('personal', 'team', 'organization'));

-- =============================================================================
-- Step 4: Create workspace_members table for collaboration
-- =============================================================================

CREATE TABLE IF NOT EXISTS workspace_members (
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    PRIMARY KEY (workspace_id, user_id),
    CONSTRAINT workspace_members_role_check CHECK (role IN ('owner', 'admin', 'member', 'viewer'))
);

CREATE INDEX IF NOT EXISTS idx_workspace_members_user_id ON workspace_members(user_id);

-- =============================================================================
-- Step 5: Add public email domains blocklist table (for tenant claiming)
-- =============================================================================

CREATE TABLE IF NOT EXISTS public_email_domains (
    domain VARCHAR(255) PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Insert common public email domains
INSERT INTO public_email_domains (domain) VALUES
    ('gmail.com'),
    ('googlemail.com'),
    ('outlook.com'),
    ('hotmail.com'),
    ('live.com'),
    ('msn.com'),
    ('yahoo.com'),
    ('yahoo.co.uk'),
    ('ymail.com'),
    ('icloud.com'),
    ('me.com'),
    ('mac.com'),
    ('proton.me'),
    ('protonmail.com'),
    ('aol.com'),
    ('mail.com'),
    ('zoho.com'),
    ('yandex.com'),
    ('yandex.ru'),
    ('qq.com'),
    ('163.com'),
    ('126.com'),
    ('tutanota.com'),
    ('fastmail.com'),
    ('gmx.com'),
    ('gmx.net'),
    ('hey.com')
ON CONFLICT (domain) DO NOTHING;

-- =============================================================================
-- Step 6: Create indexes for common queries
-- =============================================================================

-- Find users by email domain (for tenant claiming)
CREATE INDEX IF NOT EXISTS idx_users_email_domain ON users (
    SUBSTRING(email FROM POSITION('@' IN email) + 1)
);

-- Find workspaces by owner
CREATE INDEX IF NOT EXISTS idx_workspaces_owner_user_id ON workspaces(owner_user_id);
