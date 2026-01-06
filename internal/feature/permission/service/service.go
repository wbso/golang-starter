package service

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/google/uuid"

	"github.com/wbso/golang-starter/db"
	"github.com/wbso/golang-starter/internal/domain/permission"
	permissionrepo "github.com/wbso/golang-starter/internal/feature/permission/repository"
)

// Service handles permission business logic
type Service struct {
	permissionRepo *permissionrepo.Repository
}

// New creates a new permission service
func New(permissionRepo *permissionrepo.Repository) *Service {
	return &Service{
		permissionRepo: permissionRepo,
	}
}

// List returns a paginated list of permissions
func (s *Service) List(ctx context.Context, page, limit int) ([]permission.PermissionResponse, int64, error) {
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

	offset := int32((page - 1) * limit)

	// Get permissions
	dbPermissions, err := s.permissionRepo.List(ctx, int32(limit), offset)
	if err != nil {
		return nil, 0, err
	}

	// Get total count
	total, err := s.permissionRepo.Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	// Convert to response
	permissions := make([]permission.PermissionResponse, len(dbPermissions))
	for i, dbPerm := range dbPermissions {
		p := convertDBPermissionToDomain(&dbPerm)
		permissions[i] = p.ToResponse()
	}

	return permissions, total, nil
}

// GetByID returns a permission by ID
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (*permission.PermissionResponse, error) {
	dbPermission, err := s.permissionRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("permission not found")
		}
		return nil, err
	}

	p := convertDBPermissionToDomain(dbPermission)
	resp := p.ToResponse()
	return &resp, nil
}

// Create creates a new permission
func (s *Service) Create(ctx context.Context, req permission.CreatePermissionRequest, createdBy *uuid.UUID) (*permission.PermissionResponse, error) {
	var description sql.NullString
	if req.Description != "" {
		description = sql.NullString{String: req.Description, Valid: true}
	}

	var cb uuid.NullUUID
	if createdBy != nil {
		cb = uuid.NullUUID{UUID: *createdBy, Valid: true}
	}

	dbPermission, err := s.permissionRepo.Create(ctx, req.Name, description, cb)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, errors.New("permission name already exists")
		}
		return nil, err
	}

	p := convertDBPermissionToDomain(dbPermission)
	resp := p.ToResponse()
	return &resp, nil
}

// Update updates a permission
func (s *Service) Update(ctx context.Context, id uuid.UUID, req permission.UpdatePermissionRequest, updatedBy *uuid.UUID) (*permission.PermissionResponse, error) {
	// Check if permission exists
	existingPerm, err := s.permissionRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("permission not found")
		}
		return nil, err
	}

	// Build update parameters
	name := existingPerm.Name
	if req.Name != nil {
		name = *req.Name
	}

	description := existingPerm.Description
	if req.Description != nil {
		description = sql.NullString{String: *req.Description, Valid: true}
	}

	var ub uuid.NullUUID
	if updatedBy != nil {
		ub = uuid.NullUUID{UUID: *updatedBy, Valid: true}
	}

	dbPermission, err := s.permissionRepo.Update(ctx, id, name, description, ub)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, errors.New("permission name already exists")
		}
		return nil, err
	}

	p := convertDBPermissionToDomain(dbPermission)
	resp := p.ToResponse()
	return &resp, nil
}

// Delete deletes a permission
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	// Check if permission exists
	_, err := s.permissionRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("permission not found")
		}
		return err
	}

	return s.permissionRepo.Delete(ctx, id)
}

// Helper functions

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
