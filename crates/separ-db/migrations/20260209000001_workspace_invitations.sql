-- Workspace Invitations
CREATE TABLE IF NOT EXISTS workspace_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    inviter_user_id UUID NOT NULL REFERENCES users(id),
    invitee_email VARCHAR(255) NOT NULL,
    invitee_user_id UUID REFERENCES users(id),
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    token VARCHAR(255) UNIQUE,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '7 days',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    accepted_at TIMESTAMPTZ,
    CONSTRAINT workspace_invitations_role_check CHECK (role IN ('admin', 'member', 'viewer')),
    CONSTRAINT workspace_invitations_status_check CHECK (status IN ('pending', 'accepted', 'declined', 'expired'))
);

CREATE INDEX IF NOT EXISTS idx_workspace_invitations_workspace ON workspace_invitations(workspace_id);
CREATE INDEX IF NOT EXISTS idx_workspace_invitations_email ON workspace_invitations(invitee_email);
CREATE INDEX IF NOT EXISTS idx_workspace_invitations_token ON workspace_invitations(token);

-- Soft delete for workspaces
ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

-- Last used workspace per user
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_workspace_id UUID REFERENCES workspaces(id) ON DELETE SET NULL;

-- Invite link settings
ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS invite_link_enabled BOOLEAN DEFAULT false;
ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS invite_link_token VARCHAR(255);
