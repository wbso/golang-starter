package permission

import (
	"time"

	"github.com/google/uuid"
)

// Permission represents a permission entity
type Permission struct {
	ID          uuid.UUID
	Name        string
	Description *string
	CreatedBy   *uuid.UUID
	UpdatedBy   *uuid.UUID
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// CreatePermissionRequest represents a request to create a permission
type CreatePermissionRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// UpdatePermissionRequest represents a request to update a permission
type UpdatePermissionRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

// PermissionResponse represents a permission response
type PermissionResponse struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description *string   `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ToResponse converts a Permission to PermissionResponse
func (p *Permission) ToResponse() PermissionResponse {
	return PermissionResponse{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
}

// AssignPermissionRequest represents a request to assign a permission to a role
type AssignPermissionRequest struct {
	PermissionID uuid.UUID `json:"permission_id"`
}
