-- User credentials table for password authentication
-- Passwords are stored as Argon2id hashes

CREATE TABLE IF NOT EXISTS user_credentials (
    user_id TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    -- Password expiry (optional)
    expires_at TIMESTAMPTZ,
    -- Password change tracking
    last_changed_at TIMESTAMPTZ,
    -- Failed login tracking
    failed_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for expiry checks
CREATE INDEX IF NOT EXISTS idx_user_credentials_expires ON user_credentials(expires_at) WHERE expires_at IS NOT NULL;

-- Index for locked accounts
CREATE INDEX IF NOT EXISTS idx_user_credentials_locked ON user_credentials(locked_until) WHERE locked_until IS NOT NULL;

COMMENT ON TABLE user_credentials IS 'User password credentials with Argon2id hashing';
COMMENT ON COLUMN user_credentials.password_hash IS 'Argon2id password hash';
COMMENT ON COLUMN user_credentials.failed_attempts IS 'Number of consecutive failed login attempts';
COMMENT ON COLUMN user_credentials.locked_until IS 'Account locked until this time due to failed attempts';

