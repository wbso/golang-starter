package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/wbso/golang-starter/db"
)

// Repository handles authentication data operations
type Repository struct {
	db *sqlx.DB
	q  *db.Queries
}

// New creates a new auth repository
func New(database *sqlx.DB) *Repository {
	return &Repository{
		db: database,
		q:  db.New(database),
	}
}

// RefreshToken wraps the generated RefreshToken type
type RefreshToken = db.RefreshToken

// EmailVerificationToken wraps the generated EmailVerificationToken type
type EmailVerificationToken = db.EmailVerificationToken

// PasswordResetToken wraps the generated PasswordResetToken type
type PasswordResetToken = db.PasswordResetToken

// CreateRefreshToken creates a new refresh token
func (r *Repository) CreateRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	_, err := r.q.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	})
	return err
}

// GetRefreshToken gets a refresh token by hash
func (r *Repository) GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	token, err := r.q.GetRefreshToken(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// RevokeRefreshToken revokes a refresh token
func (r *Repository) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	_, err := r.q.RevokeRefreshToken(ctx, tokenHash)
	return err
}

// RevokeAllUserRefreshTokens revokes all refresh tokens for a user
func (r *Repository) RevokeAllUserRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	return r.q.RevokeAllUserRefreshTokens(ctx, userID)
}

// CleanupExpiredTokens cleans up expired tokens
func (r *Repository) CleanupExpiredTokens(ctx context.Context) error {
	return r.q.CleanupExpiredTokens(ctx)
}

// BlacklistToken adds a token to the blacklist
func (r *Repository) BlacklistToken(ctx context.Context, tokenID string, userID uuid.UUID, expiresAt time.Time) error {
	var uid uuid.NullUUID
	if userID != uuid.Nil {
		uid = uuid.NullUUID{UUID: userID, Valid: true}
	}
	_, err := r.q.BlacklistToken(ctx, db.BlacklistTokenParams{
		TokenID:   tokenID,
		UserID:    uid,
		ExpiresAt: expiresAt,
	})
	return err
}

// IsTokenBlacklisted checks if a token is blacklisted
func (r *Repository) IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	return r.q.IsTokenBlacklisted(ctx, tokenID)
}

// CleanupExpiredBlacklistTokens cleans up expired blacklist tokens
func (r *Repository) CleanupExpiredBlacklistTokens(ctx context.Context) error {
	return r.q.CleanupExpiredBlacklistTokens(ctx)
}

// CreateEmailVerificationToken creates a new email verification token
func (r *Repository) CreateEmailVerificationToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error {
	_, err := r.q.CreateEmailVerificationToken(ctx, db.CreateEmailVerificationTokenParams{
		UserID:    userID,
		Token:     token,
		ExpiresAt: expiresAt,
	})
	return err
}

// GetEmailVerificationToken gets an email verification token
func (r *Repository) GetEmailVerificationToken(ctx context.Context, token string) (*EmailVerificationToken, error) {
	t, err := r.q.GetEmailVerificationToken(ctx, token)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// MarkEmailVerificationTokenUsed marks a token as used
func (r *Repository) MarkEmailVerificationTokenUsed(ctx context.Context, token string) error {
	_, err := r.q.MarkEmailVerificationTokenUsed(ctx, token)
	return err
}

// CreatePasswordResetToken creates a new password reset token
func (r *Repository) CreatePasswordResetToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error {
	_, err := r.q.CreatePasswordResetToken(ctx, db.CreatePasswordResetTokenParams{
		UserID:    userID,
		Token:     token,
		ExpiresAt: expiresAt,
	})
	return err
}

// GetPasswordResetToken gets a password reset token
func (r *Repository) GetPasswordResetToken(ctx context.Context, token string) (*PasswordResetToken, error) {
	t, err := r.q.GetPasswordResetToken(ctx, token)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// MarkPasswordResetTokenUsed marks a token as used
func (r *Repository) MarkPasswordResetTokenUsed(ctx context.Context, token string) error {
	_, err := r.q.MarkPasswordResetTokenUsed(ctx, token)
	return err
}

// RevokeAllUserTokens revokes all tokens for a user
func (r *Repository) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	return r.q.RevokeAllUserTokens(ctx, userID)
}

// HashToken hashes a token using SHA256
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// GenerateToken generates a random token
func GenerateToken() (string, error) {
	return uuid.New().String(), nil
}

// GenerateVerificationToken generates a verification token
func GenerateVerificationToken() (string, error) {
	return GenerateToken()
}

// GenerateResetToken generates a password reset token
func GenerateResetToken() (string, error) {
	return GenerateToken()
}
