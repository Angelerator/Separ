-- Simplify workspace types: rename 'team' and 'organization' to 'shared'
UPDATE workspaces SET workspace_type = 'shared' WHERE workspace_type IN ('team', 'organization');

-- Update the CHECK constraint
ALTER TABLE workspaces DROP CONSTRAINT IF EXISTS workspaces_workspace_type_check;
ALTER TABLE workspaces ADD CONSTRAINT workspaces_workspace_type_check 
    CHECK (workspace_type IN ('personal', 'shared'));
