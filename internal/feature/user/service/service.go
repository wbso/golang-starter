package service

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/wbso/golang-starter/db"
	"github.com/wbso/golang-starter/internal/domain/user"
	userrepo "github.com/wbso/golang-starter/internal/feature/user/repository"
	"github.com/wbso/golang-starter/internal/pkg/utils"
)

// Service handles user business logic
type Service struct {
	userRepo *userrepo.Repository
}

// New creates a new user service
func New(userRepo *userrepo.Repository) *Service {
	return &Service{
		userRepo: userRepo,
	}
}

// List returns a paginated list of users
func (s *Service) List(ctx context.Context, req user.ListUsersRequest) ([]user.UserResponse, int64, error) {
	pagination := utils.ParsePaginationFromInt(req.Limit, req.Page)

	// Get users
	dbUsers, err := s.userRepo.List(ctx, pagination.Limit, pagination.Offset)
	if err != nil {
		return nil, 0, err
	}

	// Get total count
	total, err := s.userRepo.Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	// Convert to response
	users := make([]user.UserResponse, len(dbUsers))
	for i, dbUser := range dbUsers {
		u := convertDBUserToDomain(&dbUser)
		users[i] = u.ToResponse()
	}

	return users, total, nil
}

// GetByID returns a user by ID
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (*user.UserResponse, error) {
	dbUser, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	u := convertDBUserToDomain(dbUser)
	resp := u.ToResponse()
	return &resp, nil
}

// GetMe returns the current authenticated user
func (s *Service) GetMe(ctx context.Context, userID uuid.UUID) (*user.UserResponse, error) {
	return s.GetByID(ctx, userID)
}

// Create creates a new user
func (s *Service) Create(ctx context.Context, req user.CreateUserRequest, createdBy *uuid.UUID) (*user.UserResponse, error) {
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create user
	params := userrepo.CreateUserParams{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		FullName:     req.FullName,
	}

	dbUser, err := s.userRepo.Create(ctx, params)
	if err != nil {
		// Check for unique constraint violations
		if isUniqueViolation(err) {
			if containsConstraint(err.Error(), "users_username_key") {
				return nil, errors.New("username already exists")
			}
			if containsConstraint(err.Error(), "users_email_key") {
				return nil, errors.New("email already exists")
			}
		}
		return nil, err
	}

	u := convertDBUserToDomain(dbUser)
	resp := u.ToResponse()
	return &resp, nil
}

// Update updates a user
func (s *Service) Update(ctx context.Context, id uuid.UUID, req user.UpdateUserRequest, updatedBy *uuid.UUID) (*user.UserResponse, error) {
	// Check if user exists
	existingUser, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	// Build update parameters - use existing values if not provided
	username := existingUser.Username
	if req.Username != nil {
		username = *req.Username
	}

	email := existingUser.Email
	if req.Email != nil {
		email = *req.Email
	}

	fullName := existingUser.FullName
	if req.FullName != nil {
		fullName = sql.NullString{String: *req.FullName, Valid: true}
	}

	var ub uuid.NullUUID
	if updatedBy != nil {
		ub = uuid.NullUUID{UUID: *updatedBy, Valid: true}
	}

	// Update user
	dbUser, err := s.userRepo.Update(ctx, id, db.UpdateUserParams{
		ID:        id,
		Username:  username,
		Email:     email,
		FullName:  fullName,
		UpdatedBy: ub,
	})
	if err != nil {
		// Check for unique constraint violations
		if isUniqueViolation(err) {
			if containsConstraint(err.Error(), "users_username_key") {
				return nil, errors.New("username already exists")
			}
			if containsConstraint(err.Error(), "users_email_key") {
				return nil, errors.New("email already exists")
			}
		}
		return nil, err
	}

	u := convertDBUserToDomain(dbUser)
	resp := u.ToResponse()
	return &resp, nil
}

// UpdateMe updates the current authenticated user
func (s *Service) UpdateMe(ctx context.Context, userID uuid.UUID, req user.UpdateUserRequest) (*user.UserResponse, error) {
	return s.Update(ctx, userID, req, &userID)
}

// ChangePassword changes a user's password
func (s *Service) ChangePassword(ctx context.Context, userID uuid.UUID, req user.ChangePasswordRequest) error {
	// Get user
	dbUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("user not found")
		}
		return err
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(dbUser.PasswordHash), []byte(req.OldPassword)); err != nil {
		return errors.New("invalid current password")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Update password
	return s.userRepo.UpdatePassword(ctx, userID, string(hashedPassword))
}

// Disable disables a user
func (s *Service) Disable(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	// Check if user exists
	_, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("user not found")
		}
		return err
	}

	return s.userRepo.Disable(ctx, id, *updatedBy)
}

// Enable enables a disabled user
func (s *Service) Enable(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	// Check if user exists
	_, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("user not found")
		}
		return err
	}

	return s.userRepo.Enable(ctx, id, *updatedBy)
}

// Delete soft deletes a user
func (s *Service) Delete(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	// Check if user exists
	_, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("user not found")
		}
		return err
	}

	return s.userRepo.SoftDelete(ctx, id, *updatedBy)
}

// DeleteMe deletes the current authenticated user
func (s *Service) DeleteMe(ctx context.Context, userID uuid.UUID) error {
	return s.Delete(ctx, userID, &userID)
}

// Helper functions

func convertDBUserToDomain(dbUser *userrepo.User) *user.User {
	var fullName *string
	if dbUser.FullName.Valid {
		fullName = &dbUser.FullName.String
	}

	var lockedUntil *time.Time
	if dbUser.LockedUntil.Valid {
		lockedUntil = &dbUser.LockedUntil.Time
	}

	var lastLoginAt *time.Time
	if dbUser.LastLoginAt.Valid {
		lastLoginAt = &dbUser.LastLoginAt.Time
	}

	var createdBy *uuid.UUID
	if dbUser.CreatedBy.Valid {
		createdBy = &dbUser.CreatedBy.UUID
	}

	var updatedBy *uuid.UUID
	if dbUser.UpdatedBy.Valid {
		updatedBy = &dbUser.UpdatedBy.UUID
	}

	var deletedAt *time.Time
	if dbUser.DeletedAt.Valid {
		deletedAt = &dbUser.DeletedAt.Time
	}

	return &user.User{
		ID:              dbUser.ID,
		Username:        dbUser.Username,
		Email:           dbUser.Email,
		PasswordHash:    dbUser.PasswordHash,
		FullName:        fullName,
		IsDisabled:      dbUser.IsDisabled.Bool,
		IsEmailVerified: dbUser.IsEmailVerified.Bool,
		LockedUntil:     lockedUntil,
		LastLoginAt:     lastLoginAt,
		CreatedBy:       createdBy,
		UpdatedBy:       updatedBy,
		CreatedAt:       dbUser.CreatedAt.Time,
		UpdatedAt:       dbUser.UpdatedAt.Time,
		DeletedAt:       deletedAt,
	}
}

func isUniqueViolation(err error) bool {
	return strings.Contains(err.Error(), "duplicate key") ||
		strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func containsConstraint(err string, constraint string) bool {
	return strings.Contains(err, constraint)
}
