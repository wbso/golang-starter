package service

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/wbso/golang-starter/db"
	"github.com/wbso/golang-starter/internal/domain/permission"
	"github.com/wbso/golang-starter/internal/domain/role"
	rolerepo "github.com/wbso/golang-starter/internal/feature/role/repository"
)

// Service handles role business logic
type Service struct {
	roleRepo *rolerepo.Repository
}

// New creates a new role service
func New(roleRepo *rolerepo.Repository) *Service {
	return &Service{
		roleRepo: roleRepo,
	}
}

// List returns a paginated list of roles
func (s *Service) List(ctx context.Context, page, limit int) ([]role.RoleResponse, int64, error) {
	// Default pagination values
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	offset := (page - 1) * limit
	if offset < 0 || offset > int(^uint32(0)>>1) {
		return nil, 0, errors.New("invalid offset calculation")
	}

	// Get roles
	//nolint:gosec // G115 - offset is bounds checked above
	dbRoles, err := s.roleRepo.List(ctx, int32(limit), int32(offset))
	if err != nil {
		return nil, 0, err
	}

	// Get total count
	total, err := s.roleRepo.Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	// Convert to response
	roles := make([]role.RoleResponse, len(dbRoles))
	for i, dbRole := range dbRoles {
		r := convertDBRoleToDomain(&dbRole)
		roles[i] = r.ToResponse()
	}

	return roles, total, nil
}

// GetByID returns a role by ID
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (*role.RoleResponse, error) {
	dbRole, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("role not found")
		}
		return nil, err
	}

	r := convertDBRoleToDomain(dbRole)
	resp := r.ToResponse()
	return &resp, nil
}

// GetPermissions returns permissions for a role
func (s *Service) GetPermissions(ctx context.Context, roleID uuid.UUID) ([]permission.PermissionResponse, error) {
	dbPermissions, err := s.roleRepo.GetPermissions(ctx, roleID)
	if err != nil {
		return nil, err
	}

	permissions := make([]permission.PermissionResponse, len(dbPermissions))
	for i, dbPerm := range dbPermissions {
		p := convertDBPermissionToDomain(&dbPerm)
		permissions[i] = p.ToResponse()
	}

	return permissions, nil
}

// Create creates a new role
func (s *Service) Create(ctx context.Context, req role.CreateRoleRequest, createdBy *uuid.UUID) (*role.RoleResponse, error) {
	var description sql.NullString
	if req.Description != "" {
		description = sql.NullString{String: req.Description, Valid: true}
	}

	var cb uuid.NullUUID
	if createdBy != nil {
		cb = uuid.NullUUID{UUID: *createdBy, Valid: true}
	}

	dbRole, err := s.roleRepo.Create(ctx, req.Name, description, cb)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, errors.New("role name already exists")
		}
		return nil, err
	}

	r := convertDBRoleToDomain(dbRole)
	resp := r.ToResponse()
	return &resp, nil
}

// Update updates a role
func (s *Service) Update(ctx context.Context, id uuid.UUID, req role.UpdateRoleRequest, updatedBy *uuid.UUID) (*role.RoleResponse, error) {
	// Check if role exists
	existingRole, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("role not found")
		}
		return nil, err
	}

	// Build update parameters
	name := existingRole.Name
	if req.Name != nil {
		name = *req.Name
	}

	description := existingRole.Description
	if req.Description != nil {
		description = sql.NullString{String: *req.Description, Valid: true}
	}

	var ub uuid.NullUUID
	if updatedBy != nil {
		ub = uuid.NullUUID{UUID: *updatedBy, Valid: true}
	}

	dbRole, err := s.roleRepo.Update(ctx, id, name, description, ub)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, errors.New("role name already exists")
		}
		return nil, err
	}

	r := convertDBRoleToDomain(dbRole)
	resp := r.ToResponse()
	return &resp, nil
}

// Delete deletes a role
func (s *Service) Delete(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	// Check if role exists
	_, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("role not found")
		}
		return err
	}

	// Check if role is assigned to users
	isAssigned, err := s.roleRepo.IsAssigned(ctx, id)
	if err != nil {
		return err
	}
	if isAssigned {
		return errors.New("role is assigned to users and cannot be deleted")
	}

	var ub uuid.NullUUID
	if updatedBy != nil {
		ub = uuid.NullUUID{UUID: *updatedBy, Valid: true}
	}

	return s.roleRepo.Delete(ctx, id, ub)
}

// AssignPermission assigns a permission to a role
func (s *Service) AssignPermission(ctx context.Context, roleID, permissionID uuid.UUID, assignedBy *uuid.UUID) error {
	// Check if role exists
	_, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("role not found")
		}
		return err
	}

	var ab uuid.NullUUID
	if assignedBy != nil {
		ab = uuid.NullUUID{UUID: *assignedBy, Valid: true}
	}

	return s.roleRepo.AssignPermission(ctx, roleID, permissionID, ab)
}

// RevokePermission revokes a permission from a role
func (s *Service) RevokePermission(ctx context.Context, roleID, permissionID uuid.UUID) error {
	// Check if role exists
	_, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("role not found")
		}
		return err
	}

	return s.roleRepo.RevokePermission(ctx, roleID, permissionID)
}

// AssignToUser assigns a role to a user
func (s *Service) AssignToUser(ctx context.Context, userID, roleID uuid.UUID, assignedBy *uuid.UUID) error {
	// Check if role exists
	_, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("role not found")
		}
		return err
	}

	var ab uuid.NullUUID
	if assignedBy != nil {
		ab = uuid.NullUUID{UUID: *assignedBy, Valid: true}
	}

	return s.roleRepo.AssignToUser(ctx, userID, roleID, ab)
}

// RevokeFromUser revokes a role from a user
func (s *Service) RevokeFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	// Check if role exists
	_, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("role not found")
		}
		return err
	}

	return s.roleRepo.RevokeFromUser(ctx, userID, roleID)
}

// GetUserRoles returns roles for a user
func (s *Service) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]role.RoleResponse, error) {
	dbRoles, err := s.roleRepo.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	roles := make([]role.RoleResponse, len(dbRoles))
	for i, dbRole := range dbRoles {
		r := convertDBRoleToDomain(&dbRole)
		roles[i] = r.ToResponse()
	}

	return roles, nil
}

// Helper functions

func convertDBRoleToDomain(dbRole *db.Role) *role.Role {
	var description *string
	if dbRole.Description.Valid {
		description = &dbRole.Description.String
	}

	var createdBy *uuid.UUID
	if dbRole.CreatedBy.Valid {
		createdBy = &dbRole.CreatedBy.UUID
	}

	var updatedBy *uuid.UUID
	if dbRole.UpdatedBy.Valid {
		updatedBy = &dbRole.UpdatedBy.UUID
	}

	var deletedAt *time.Time
	if dbRole.DeletedAt.Valid {
		deletedAt = &dbRole.DeletedAt.Time
	}

	return &role.Role{
		ID:          dbRole.ID,
		Name:        dbRole.Name,
		Description: description,
		CreatedBy:   createdBy,
		UpdatedBy:   updatedBy,
		CreatedAt:   dbRole.CreatedAt.Time,
		UpdatedAt:   dbRole.UpdatedAt.Time,
		DeletedAt:   deletedAt,
	}
}

func convertDBPermissionToDomain(dbPerm *db.Permission) *permission.Permission {
	var description *string
	if dbPerm.Description.Valid {
		description = &dbPerm.Description.String
	}

	var createdBy *uuid.UUID
	if dbPerm.CreatedBy.Valid {
		createdBy = &dbPerm.CreatedBy.UUID
	}

	var updatedBy *uuid.UUID
	if dbPerm.UpdatedBy.Valid {
		updatedBy = &dbPerm.UpdatedBy.UUID
	}

	return &permission.Permission{
		ID:          dbPerm.ID,
		Name:        dbPerm.Name,
		Description: description,
		CreatedBy:   createdBy,
		UpdatedBy:   updatedBy,
		CreatedAt:   dbPerm.CreatedAt.Time,
		UpdatedAt:   dbPerm.UpdatedAt.Time,
	}
}

func isUniqueViolation(err error) bool {
	return strings.Contains(err.Error(), "duplicate key") ||
		strings.Contains(err.Error(), "UNIQUE constraint failed")
}
