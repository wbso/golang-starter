package user

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user entity
type User struct {
	ID                  uuid.UUID
	Username            string
	Email               string
	PasswordHash        string
	FullName            *string
	IsDisabled          bool
	IsEmailVerified     bool
	FailedLoginAttempts int
	LockedUntil         *time.Time
	LastLoginAt         *time.Time
	CreatedBy           *uuid.UUID
	UpdatedBy           *uuid.UUID
	CreatedAt           time.Time
	UpdatedAt           time.Time
	DeletedAt           *time.Time
}

// IsLocked returns true if the user account is locked
func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return u.LockedUntil.After(time.Now())
}

// CanLogin returns true if the user can login (not disabled, not locked, email verified)
func (u *User) CanLogin() bool {
	if u.IsDisabled {
		return false
	}
	if u.IsLocked() {
		return false
	}
	if !u.IsEmailVerified {
		return false
	}
	return true
}

// CreateUserRequest represents a request to create a user
type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"full_name,omitempty"`
}

// UpdateUserRequest represents a request to update a user
type UpdateUserRequest struct {
	Username *string `json:"username,omitempty"`
	Email    *string `json:"email,omitempty"`
	FullName *string `json:"full_name,omitempty"`
}

// ChangePasswordRequest represents a request to change password
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// ListUsersRequest represents a request to list users
type ListUsersRequest struct {
	Page   int    `json:"page" query:"page"`
	Limit  int    `json:"limit" query:"limit"`
	Sort   string `json:"sort,omitempty" query:"sort"`
	Filter string `json:"filter,omitempty" query:"filter"`
}

// UserResponse represents a user response
type UserResponse struct {
	ID              uuid.UUID  `json:"id"`
	Username        string     `json:"username"`
	Email           string     `json:"email"`
	FullName        *string    `json:"full_name,omitempty"`
	IsDisabled      bool       `json:"is_disabled"`
	IsEmailVerified bool       `json:"is_email_verified"`
	LastLoginAt     *time.Time `json:"last_login_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// ToResponse converts a User to UserResponse (excludes sensitive fields)
func (u *User) ToResponse() UserResponse {
	return UserResponse{
		ID:              u.ID,
		Username:        u.Username,
		Email:           u.Email,
		FullName:        u.FullName,
		IsDisabled:      u.IsDisabled,
		IsEmailVerified: u.IsEmailVerified,
		LastLoginAt:     u.LastLoginAt,
		CreatedAt:       u.CreatedAt,
		UpdatedAt:       u.UpdatedAt,
	}
}
