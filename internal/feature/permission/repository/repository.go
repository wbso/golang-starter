package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/wbso/golang-starter/db"
)

// Repository handles permission data operations
type Repository struct {
	db *sqlx.DB
	q  *db.Queries
}

// New creates a new permission repository
func New(database *sqlx.DB) *Repository {
	return &Repository{
		db: database,
		q:  db.New(database),
	}
}

// Permission wraps the generated Permission type
type Permission = db.Permission

// GetByID gets a permission by ID
func (r *Repository) GetByID(ctx context.Context, id uuid.UUID) (*Permission, error) {
	permission, err := r.q.GetPermissionByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return &permission, nil
}

// GetByName gets a permission by name
func (r *Repository) GetByName(ctx context.Context, name string) (*Permission, error) {
	permission, err := r.q.GetPermissionByName(ctx, name)
	if err != nil {
		return nil, err
	}
	return &permission, nil
}

// List gets a list of permissions
func (r *Repository) List(ctx context.Context, limit, offset int32) ([]Permission, error) {
	return r.q.ListPermissions(ctx, db.ListPermissionsParams{
		Limit:  limit,
		Offset: offset,
	})
}

// Create creates a new permission
func (r *Repository) Create(ctx context.Context, name string, description sql.NullString, createdBy uuid.NullUUID) (*Permission, error) {
	permission, err := r.q.CreatePermission(ctx, db.CreatePermissionParams{
		Name:        name,
		Description: description,
		CreatedBy:   createdBy,
		UpdatedBy:   createdBy,
	})
	if err != nil {
		return nil, err
	}
	return &permission, nil
}

// Update updates a permission
func (r *Repository) Update(ctx context.Context, id uuid.UUID, name string, description sql.NullString, updatedBy uuid.NullUUID) (*Permission, error) {
	permission, err := r.q.UpdatePermission(ctx, db.UpdatePermissionParams{
		ID:          id,
		Name:        name,
		Description: description,
		UpdatedBy:   updatedBy,
	})
	if err != nil {
		return nil, err
	}
	return &permission, nil
}

// Delete deletes a permission
func (r *Repository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.q.DeletePermission(ctx, id)
}

// Count returns the total number of permissions
func (r *Repository) Count(ctx context.Context) (int64, error) {
	return r.q.CountPermissions(ctx)
}
