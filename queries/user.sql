-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1 AND deleted_at IS NULL;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1 AND deleted_at IS NULL;

-- name: GetUserByUsername :one
SELECT * FROM users
WHERE username = $1 AND deleted_at IS NULL;

-- name: ListUsers :many
SELECT * FROM users
WHERE deleted_at IS NULL
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CreateUser :one
INSERT INTO users (
    username,
    email,
    password_hash,
    full_name,
    created_by,
    updated_by
) VALUES (
    $1, $2, $3, $4, $5, $6
)
RETURNING *;

-- name: UpdateUser :one
UPDATE users
SET
    username = COALESCE($2, username),
    email = COALESCE($3, email),
    full_name = COALESCE($4, full_name),
    updated_by = $5,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: DisableUser :one
UPDATE users
SET
    is_disabled = true,
    updated_by = $2,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: EnableUser :one
UPDATE users
SET
    is_disabled = false,
    failed_login_attempts = 0,
    locked_until = NULL,
    updated_by = $2,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: SoftDeleteUser :one
UPDATE users
SET
    deleted_at = CURRENT_TIMESTAMP,
    updated_by = $2,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: RestoreUser :one
UPDATE users
SET
    deleted_at = NULL,
    is_disabled = false,
    failed_login_attempts = 0,
    locked_until = NULL,
    updated_by = $2,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND deleted_at IS NOT NULL
RETURNING *;

-- name: UpdateLastLogin :one
UPDATE users
SET
    last_login_at = CURRENT_TIMESTAMP,
    failed_login_attempts = 0,
    locked_until = NULL
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: IncrementFailedLoginAttempts :one
UPDATE users
SET
    failed_login_attempts = failed_login_attempts + 1,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: LockUser :one
UPDATE users
SET
    locked_until = $2,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: UpdatePassword :one
UPDATE users
SET
    password_hash = $2,
    updated_by = $3,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: VerifyEmail :one
UPDATE users
SET
    is_email_verified = true,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: CountUsers :one
SELECT COUNT(*) FROM users WHERE deleted_at IS NULL;
