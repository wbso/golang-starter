package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/wbso/golang-starter/db"
)

// Repository handles role data operations
type Repository struct {
	db *sqlx.DB
	q  *db.Queries
}

// New creates a new role repository
func New(database *sqlx.DB) *Repository {
	return &Repository{
		db: database,
		q:  db.New(database),
	}
}

// Role wraps the generated Role type
type Role = db.Role

// ListRolesParams holds parameters for listing roles
type ListRolesParams struct {
	Limit  int32
	Offset int32
}

// GetByID gets a role by ID
func (r *Repository) GetByID(ctx context.Context, id uuid.UUID) (*Role, error) {
	role, err := r.q.GetRoleByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return &role, nil
}

// GetByName gets a role by name
func (r *Repository) GetByName(ctx context.Context, name string) (*Role, error) {
	role, err := r.q.GetRoleByName(ctx, name)
	if err != nil {
		return nil, err
	}
	return &role, nil
}

// List gets a list of roles
func (r *Repository) List(ctx context.Context, limit, offset int32) ([]Role, error) {
	return r.q.ListRoles(ctx, db.ListRolesParams{
		Limit:  limit,
		Offset: offset,
	})
}

// Create creates a new role
func (r *Repository) Create(ctx context.Context, name string, description sql.NullString, createdBy uuid.NullUUID) (*Role, error) {
	role, err := r.q.CreateRole(ctx, db.CreateRoleParams{
		Name:        name,
		Description: description,
		CreatedBy:   createdBy,
		UpdatedBy:   createdBy,
	})
	if err != nil {
		return nil, err
	}
	return &role, nil
}

// Update updates a role
func (r *Repository) Update(ctx context.Context, id uuid.UUID, name string, description sql.NullString, updatedBy uuid.NullUUID) (*Role, error) {
	role, err := r.q.UpdateRole(ctx, db.UpdateRoleParams{
		ID:          id,
		Name:        name,
		Description: description,
		UpdatedBy:   updatedBy,
	})
	if err != nil {
		return nil, err
	}
	return &role, nil
}

// Delete soft deletes a role
func (r *Repository) Delete(ctx context.Context, id uuid.UUID, updatedBy uuid.NullUUID) error {
	_, err := r.q.DeleteRole(ctx, db.DeleteRoleParams{
		ID:        id,
		UpdatedBy: updatedBy,
	})
	return err
}

// Count returns the total number of roles
func (r *Repository) Count(ctx context.Context) (int64, error) {
	return r.q.CountRoles(ctx)
}

// IsAssigned checks if a role is assigned to any users
func (r *Repository) IsAssigned(ctx context.Context, roleID uuid.UUID) (bool, error) {
	count, err := r.q.CheckRoleAssigned(ctx, roleID)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// GetPermissions gets permissions for a role
func (r *Repository) GetPermissions(ctx context.Context, roleID uuid.UUID) ([]db.Permission, error) {
	return r.q.GetRolePermissions(ctx, roleID)
}

// AssignPermission assigns a permission to a role
func (r *Repository) AssignPermission(ctx context.Context, roleID, permissionID uuid.UUID, assignedBy uuid.NullUUID) error {
	_, err := r.q.AssignPermissionToRole(ctx, db.AssignPermissionToRoleParams{
		RoleID:       roleID,
		PermissionID: permissionID,
		AssignedBy:   assignedBy,
	})
	return err
}

// RevokePermission revokes a permission from a role
func (r *Repository) RevokePermission(ctx context.Context, roleID, permissionID uuid.UUID) error {
	return r.q.RevokePermissionFromRole(ctx, db.RevokePermissionFromRoleParams{
		RoleID:       roleID,
		PermissionID: permissionID,
	})
}

// GetUserRoles gets roles for a user
func (r *Repository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]Role, error) {
	return r.q.GetUserRoles(ctx, userID)
}

// AssignToUser assigns a role to a user
func (r *Repository) AssignToUser(ctx context.Context, userID, roleID uuid.UUID, assignedBy uuid.NullUUID) error {
	_, err := r.q.AssignRoleToUser(ctx, db.AssignRoleToUserParams{
		UserID:     userID,
		RoleID:     roleID,
		AssignedBy: assignedBy,
	})
	return err
}

// RevokeFromUser revokes a role from a user
func (r *Repository) RevokeFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	return r.q.RevokeRoleFromUser(ctx, db.RevokeRoleFromUserParams{
		UserID: userID,
		RoleID: roleID,
	})
}

// GetUserPermissions gets all permissions for a user (via their roles)
func (r *Repository) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]db.Permission, error) {
	return r.q.GetUserPermissions(ctx, userID)
}
