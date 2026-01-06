-- +goose Up
-- Insert default permissions
INSERT INTO permissions (name, description) VALUES
    -- User Management Permissions
    ('create_user', 'Create a new user'),
    ('update_user', 'Update user information'),
    ('delete_user', 'Delete a user'),
    ('view_user', 'View user details'),
    ('disable_user', 'Disable a user account'),
    ('restore_user', 'Restore a disabled user account'),
    ('list_users', 'List all users'),

    -- Role Management Permissions
    ('create_role', 'Create a new role'),
    ('update_role', 'Update role information'),
    ('delete_role', 'Delete a role'),
    ('view_role', 'View role details'),
    ('list_roles', 'List all roles'),
    ('assign_role', 'Assign role to user'),
    ('revoke_role', 'Revoke role from user'),

    -- Permission Management Permissions
    ('create_permission', 'Create a new permission'),
    ('update_permission', 'Update permission information'),
    ('delete_permission', 'Delete a permission'),
    ('view_permission', 'View permission details'),
    ('list_permissions', 'List all permissions'),

    -- Auth Permissions
    ('login', 'Login to the system'),
    ('logout', 'Logout from the system'),
    ('register', 'Register a new user'),
    ('refresh_token', 'Refresh access token'),
    ('reset_password', 'Reset password'),
    ('verify_email', 'Verify email address'),
    ('change_password', 'Change own password'),

    -- Self Management Permissions (for all authenticated users)
    ('view_own_profile', 'View own profile'),
    ('update_own_profile', 'Update own profile'),
    ('delete_own_account', 'Delete own account')
ON CONFLICT (name) DO NOTHING;

-- Insert default roles
INSERT INTO roles (name, description) VALUES
    ('admin', 'Administrator with full system access'),
    ('user_manager', 'Can manage users but not roles or permissions'),
    ('user', 'Default user with basic permissions')
ON CONFLICT (name) DO NOTHING;

-- Assign all permissions to admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'admin'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Assign user management permissions to user_manager role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.name IN (
    'create_user', 'update_user', 'view_user', 'disable_user', 'restore_user', 'list_users'
)
WHERE r.name = 'user_manager'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Assign basic permissions to default user role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.name IN (
    'login', 'logout', 'refresh_token', 'view_own_profile', 'update_own_profile',
    'change_password', 'delete_own_account'
)
WHERE r.name = 'user'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Note: Admin user will be created programmatically on first startup
-- with a randomly generated password that will be logged to console


