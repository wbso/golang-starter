-- name: GetPermissionByID :one
SELECT * FROM permissions
WHERE id = $1;

-- name: GetPermissionByName :one
SELECT * FROM permissions
WHERE name = $1;

-- name: ListPermissions :many
SELECT * FROM permissions
ORDER BY name ASC
LIMIT $1 OFFSET $2;

-- name: CreatePermission :one
INSERT INTO permissions (
    name,
    description,
    created_by,
    updated_by
) VALUES (
    $1, $2, $3, $4
)
RETURNING *;

-- name: UpdatePermission :one
UPDATE permissions
SET
    name = COALESCE($2, name),
    description = COALESCE($3, description),
    updated_by = $4,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1
RETURNING *;

-- name: DeletePermission :exec
DELETE FROM permissions
WHERE id = $1;

-- name: CountPermissions :one
SELECT COUNT(*) FROM permissions;
