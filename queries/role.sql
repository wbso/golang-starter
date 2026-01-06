-- name: GetRoleByID :one
SELECT * FROM roles
WHERE id = $1 AND deleted_at IS NULL;

-- name: GetRoleByName :one
SELECT * FROM roles
WHERE name = $1 AND deleted_at IS NULL;

-- name: ListRoles :many
SELECT * FROM roles
WHERE deleted_at IS NULL
ORDER BY name ASC
LIMIT $1 OFFSET $2;

-- name: CreateRole :one
INSERT INTO roles (
    name,
    description,
    created_by,
    updated_by
) VALUES (
    $1, $2, $3, $4
)
RETURNING *;

-- name: UpdateRole :one
UPDATE roles
SET
    name = COALESCE($2, name),
    description = COALESCE($3, description),
    updated_by = $4,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: DeleteRole :one
UPDATE roles
SET
    deleted_at = CURRENT_TIMESTAMP,
    updated_by = $2,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: CountRoles :one
SELECT COUNT(*) FROM roles WHERE deleted_at IS NULL;

-- name: GetUserRoles :many
SELECT r.* FROM roles r
JOIN user_roles ur ON ur.role_id = r.id
WHERE ur.user_id = $1 AND r.deleted_at IS NULL
ORDER BY r.name ASC;

-- name: AssignRoleToUser :one
INSERT INTO user_roles (
    user_id,
    role_id,
    assigned_by
) VALUES (
    $1, $2, $3
)
ON CONFLICT (user_id, role_id) DO NOTHING
RETURNING *;

-- name: RevokeRoleFromUser :exec
DELETE FROM user_roles
WHERE user_id = $1 AND role_id = $2;

-- name: GetRolePermissions :many
SELECT p.* FROM permissions p
JOIN role_permissions rp ON rp.permission_id = p.id
WHERE rp.role_id = $1
ORDER BY p.name ASC;

-- name: AssignPermissionToRole :one
INSERT INTO role_permissions (
    role_id,
    permission_id,
    assigned_by
) VALUES (
    $1, $2, $3
)
ON CONFLICT (role_id, permission_id) DO NOTHING
RETURNING *;

-- name: RevokePermissionFromRole :exec
DELETE FROM role_permissions
WHERE role_id = $1 AND permission_id = $2;

-- name: CheckRoleAssigned :one
SELECT COUNT(*) FROM user_roles
WHERE role_id = $1
LIMIT 1;

-- name: GetUserPermissions :many
SELECT DISTINCT p.* FROM permissions p
JOIN role_permissions rp ON rp.permission_id = p.id
JOIN user_roles ur ON ur.role_id = rp.role_id
WHERE ur.user_id = $1
ORDER BY p.name ASC;
