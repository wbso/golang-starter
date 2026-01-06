package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/wbso/golang-starter/db"
)

// Repository handles user data operations
type Repository struct {
	db *sqlx.DB
	q  *db.Queries
}

// New creates a new user repository
func New(database *sqlx.DB) *Repository {
	return &Repository{
		db: database,
		q:  db.New(database),
	}
}

// User wraps the generated User type
type User = db.User

// CreateUserParams holds parameters for creating a user
type CreateUserParams struct {
	Username     string
	Email        string
	PasswordHash string
	FullName     string
}

// GetByID gets a user by ID
func (r *Repository) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	user, err := r.q.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetByEmail gets a user by email
func (r *Repository) GetByEmail(ctx context.Context, email string) (*User, error) {
	user, err := r.q.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetByUsername gets a user by username
func (r *Repository) GetByUsername(ctx context.Context, username string) (*User, error) {
	user, err := r.q.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetByEmailOrUsername gets a user by email or username
func (r *Repository) GetByEmailOrUsername(ctx context.Context, identifier string) (*User, error) {
	// Try email first
	user, err := r.q.GetUserByEmail(ctx, identifier)
	if err == nil {
		return &user, nil
	}
	// Try username
	user, err = r.q.GetUserByUsername(ctx, identifier)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// List gets a list of users
func (r *Repository) List(ctx context.Context, limit, offset int32) ([]User, error) {
	return r.q.ListUsers(ctx, db.ListUsersParams{
		Limit:  limit,
		Offset: offset,
	})
}

// Create creates a new user
func (r *Repository) Create(ctx context.Context, params CreateUserParams) (*User, error) {
	var fullName sql.NullString
	if params.FullName != "" {
		fullName = sql.NullString{String: params.FullName, Valid: true}
	}
	user, err := r.q.CreateUser(ctx, db.CreateUserParams{
		Username:     params.Username,
		Email:        params.Email,
		PasswordHash: params.PasswordHash,
		FullName:     fullName,
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// Update updates a user
func (r *Repository) Update(ctx context.Context, id uuid.UUID, params db.UpdateUserParams) (*User, error) {
	user, err := r.q.UpdateUser(ctx, params)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// Disable disables a user
func (r *Repository) Disable(ctx context.Context, id, updatedBy uuid.UUID) error {
	var ub uuid.NullUUID
	if updatedBy != uuid.Nil {
		ub = uuid.NullUUID{UUID: updatedBy, Valid: true}
	}
	_, err := r.q.DisableUser(ctx, db.DisableUserParams{
		ID:        id,
		UpdatedBy: ub,
	})
	return err
}

// Enable enables a user
func (r *Repository) Enable(ctx context.Context, id, updatedBy uuid.UUID) error {
	var ub uuid.NullUUID
	if updatedBy != uuid.Nil {
		ub = uuid.NullUUID{UUID: updatedBy, Valid: true}
	}
	_, err := r.q.EnableUser(ctx, db.EnableUserParams{
		ID:        id,
		UpdatedBy: ub,
	})
	return err
}

// SoftDelete soft deletes a user
func (r *Repository) SoftDelete(ctx context.Context, id, updatedBy uuid.UUID) error {
	var ub uuid.NullUUID
	if updatedBy != uuid.Nil {
		ub = uuid.NullUUID{UUID: updatedBy, Valid: true}
	}
	_, err := r.q.SoftDeleteUser(ctx, db.SoftDeleteUserParams{
		ID:        id,
		UpdatedBy: ub,
	})
	return err
}

// Restore restores a soft deleted user
func (r *Repository) Restore(ctx context.Context, id, updatedBy uuid.UUID) error {
	var ub uuid.NullUUID
	if updatedBy != uuid.Nil {
		ub = uuid.NullUUID{UUID: updatedBy, Valid: true}
	}
	_, err := r.q.RestoreUser(ctx, db.RestoreUserParams{
		ID:        id,
		UpdatedBy: ub,
	})
	return err
}

// UpdateLastLogin updates the last login timestamp
func (r *Repository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	_, err := r.q.UpdateLastLogin(ctx, id)
	return err
}

// IncrementFailedLoginAttempts increments the failed login attempts counter
func (r *Repository) IncrementFailedLoginAttempts(ctx context.Context, id uuid.UUID) error {
	_, err := r.q.IncrementFailedLoginAttempts(ctx, id)
	return err
}

// LockUser locks a user account until a specified time
func (r *Repository) LockUser(ctx context.Context, id uuid.UUID, lockedUntil interface{}) error {
	// This needs proper implementation based on actual timestamp type
	// For now, skip this
	return nil
}

// UpdatePassword updates a user's password
func (r *Repository) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	_, err := r.q.UpdatePassword(ctx, db.UpdatePasswordParams{
		ID:           id,
		PasswordHash: passwordHash,
	})
	return err
}

// VerifyEmail marks a user's email as verified
func (r *Repository) VerifyEmail(ctx context.Context, id uuid.UUID) error {
	_, err := r.q.VerifyEmail(ctx, id)
	return err
}

// Count returns the total number of users
func (r *Repository) Count(ctx context.Context) (int64, error) {
	return r.q.CountUsers(ctx)
}
