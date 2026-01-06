package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/wbso/golang-starter/db"
	rolerepo "github.com/wbso/golang-starter/internal/feature/role/repository"
)

// PermissionChecker implements the middleware.PermissionChecker interface
type PermissionChecker struct {
	roleRepo *rolerepo.Repository
}

// NewPermissionChecker creates a new permission checker
func NewPermissionChecker(roleRepo *rolerepo.Repository) *PermissionChecker {
	return &PermissionChecker{
		roleRepo: roleRepo,
	}
}

// GetUserPermissions gets all permissions for a user (via their roles)
func (pc *PermissionChecker) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	dbPermissions, err := pc.roleRepo.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Convert to permission names and add role names as "role:{name}" format
	permissions := make([]string, 0, len(dbPermissions)*2)

	for _, perm := range dbPermissions {
		permissions = append(permissions, perm.Name)
	}

	// Also get user roles and add them as permissions
	dbRoles, err := pc.roleRepo.GetUserRoles(ctx, userID)
	if err != nil {
		return permissions, nil // Return what we have
	}

	for _, role := range dbRoles {
		// Add role as a permission in format "role:{name}"
		permissions = append(permissions, "role:"+role.Name)
	}

	return permissions, nil
}

// GetPermissionNames gets permission names from db.Permission slice
func GetPermissionNames(dbPermissions []db.Permission) []string {
	names := make([]string, len(dbPermissions))
	for i, perm := range dbPermissions {
		names[i] = perm.Name
	}
	return names
}
