-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (
    user_id,
    token_hash,
    expires_at
) VALUES (
    $1, $2, $3
)
RETURNING *;

-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens
WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP;

-- name: RevokeRefreshToken :one
UPDATE refresh_tokens
SET
    revoked_at = CURRENT_TIMESTAMP
WHERE token_hash = $1 AND revoked_at IS NULL
RETURNING *;

-- name: RevokeAllUserRefreshTokens :exec
UPDATE refresh_tokens
SET
    revoked_at = CURRENT_TIMESTAMP
WHERE user_id = $1 AND revoked_at IS NULL;

-- name: CleanupExpiredTokens :exec
DELETE FROM refresh_tokens
WHERE expires_at < CURRENT_TIMESTAMP OR (revoked_at IS NOT NULL AND revoked_at < CURRENT_TIMESTAMP - INTERVAL '7 days');

-- name: BlacklistToken :one
INSERT INTO jwt_blacklist (
    token_id,
    user_id,
    expires_at
) VALUES (
    $1, $2, $3
)
ON CONFLICT (token_id) DO NOTHING
RETURNING *;

-- name: IsTokenBlacklisted :one
SELECT COUNT(*) > 0 as blacklisted FROM jwt_blacklist
WHERE token_id = $1 AND expires_at > CURRENT_TIMESTAMP;

-- name: CleanupExpiredBlacklistTokens :exec
DELETE FROM jwt_blacklist
WHERE expires_at < CURRENT_TIMESTAMP;

-- name: CreateEmailVerificationToken :one
INSERT INTO email_verification_tokens (
    user_id,
    token,
    expires_at
) VALUES (
    $1, $2, $3
)
RETURNING *;

-- name: GetEmailVerificationToken :one
SELECT * FROM email_verification_tokens
WHERE token = $1 AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP;

-- name: MarkEmailVerificationTokenUsed :one
UPDATE email_verification_tokens
SET
    used_at = CURRENT_TIMESTAMP
WHERE token = $1 AND used_at IS NULL
RETURNING *;

-- name: CreatePasswordResetToken :one
INSERT INTO password_reset_tokens (
    user_id,
    token,
    expires_at
) VALUES (
    $1, $2, $3
)
RETURNING *;

-- name: GetPasswordResetToken :one
SELECT * FROM password_reset_tokens
WHERE token = $1 AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP;

-- name: MarkPasswordResetTokenUsed :one
UPDATE password_reset_tokens
SET
    used_at = CURRENT_TIMESTAMP
WHERE token = $1 AND used_at IS NULL
RETURNING *;

-- name: RevokeAllUserTokens :exec
-- Revoke refresh tokens
UPDATE refresh_tokens
SET revoked_at = CURRENT_TIMESTAMP
WHERE user_id = $1 AND revoked_at IS NULL;

-- Invalidate email verification tokens
UPDATE email_verification_tokens
SET used_at = CURRENT_TIMESTAMP
WHERE user_id = $1 AND used_at IS NULL;

-- Invalidate password reset tokens
UPDATE password_reset_tokens
SET used_at = CURRENT_TIMESTAMP
WHERE user_id = $1 AND used_at IS NULL;
