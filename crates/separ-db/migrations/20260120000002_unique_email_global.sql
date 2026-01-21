-- Add global unique constraint on email
-- This ensures no duplicate emails regardless of tenant_id
-- Required for workspace-first model where tenant_id can be NULL

-- =============================================================================
-- Step 1: Drop the old tenant-scoped unique constraint
-- =============================================================================

-- The old constraint: UNIQUE(tenant_id, email) allows duplicate emails
-- when tenant_id is NULL (because NULL != NULL in PostgreSQL)
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_tenant_id_email_key;

-- =============================================================================
-- Step 2: Add a global unique constraint on email
-- =============================================================================

-- Email must be globally unique across all users
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(email);

-- =============================================================================
-- Step 3: Also add index for faster email lookups
-- =============================================================================

-- For login/authentication queries
CREATE INDEX IF NOT EXISTS idx_users_email_lookup ON users(LOWER(email));
