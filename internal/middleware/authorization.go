package middleware

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/wbso/golang-starter/internal/pkg/apperrors"
)

// PermissionChecker defines the interface for checking user permissions
type PermissionChecker interface {
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error)
}

// PermissionCache caches user permissions
type PermissionCache struct {
	mu          sync.RWMutex
	permissions map[uuid.UUID][]string
}

// NewPermissionCache creates a new permission cache
func NewPermissionCache() *PermissionCache {
	return &PermissionCache{
		permissions: make(map[uuid.UUID][]string),
	}
}

// Get gets cached permissions for a user
func (c *PermissionCache) Get(userID uuid.UUID) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	perms, ok := c.permissions[userID]
	return perms, ok
}

// Set sets permissions for a user
func (c *PermissionCache) Set(userID uuid.UUID, permissions []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.permissions[userID] = permissions
}

// Invalidate clears cached permissions for a user
func (c *PermissionCache) Invalidate(userID uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.permissions, userID)
}

// RequirePermission creates a middleware that requires a specific permission
func RequirePermission(checker PermissionChecker, cache *PermissionCache, permission string) echo.MiddlewareFunc {
	return RequireAnyPermission(checker, cache, permission)
}

// RequireAnyPermission creates a middleware that requires any of the specified permissions
func RequireAnyPermission(checker PermissionChecker, cache *PermissionCache, permissions ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userID := GetUserID(c)
			if userID == uuid.Nil {
				return apperrors.NewErrUnauthorized()
			}

			// Check cache first
			userPerms, found := cache.Get(userID)
			if !found {
				// Fetch from database
				dbPerms, err := checker.GetUserPermissions(c.Request().Context(), userID)
				if err != nil {
					return apperrors.NewErrInternal().WithError(err)
				}

				// Convert to permission names
				userPerms = dbPerms
				cache.Set(userID, userPerms)
			}

			// Check if user has any of the required permissions
			hasPermission := false
			for _, requiredPerm := range permissions {
				if containsPermission(userPerms, requiredPerm) {
					hasPermission = true
					break
				}
			}

			if !hasPermission {
				return apperrors.NewErrInsufficientPermissions().WithDetail(fmt.Sprintf("Required permission: %s", permissions[0]))
			}

			return next(c)
		}
	}
}

// RequireAllPermissions creates a middleware that requires all of the specified permissions
func RequireAllPermissions(checker PermissionChecker, cache *PermissionCache, permissions ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userID := GetUserID(c)
			if userID == uuid.Nil {
				return apperrors.NewErrUnauthorized()
			}

			// Check cache first
			userPerms, found := cache.Get(userID)
			if !found {
				// Fetch from database
				dbPerms, err := checker.GetUserPermissions(c.Request().Context(), userID)
				if err != nil {
					return apperrors.NewErrInternal().WithError(err)
				}

				// Convert to permission names
				userPerms = dbPerms
				cache.Set(userID, userPerms)
			}

			// Check if user has all required permissions
			for _, requiredPerm := range permissions {
				if !containsPermission(userPerms, requiredPerm) {
					return apperrors.NewErrInsufficientPermissions().WithDetail(fmt.Sprintf("Required permission: %s", requiredPerm))
				}
			}

			return next(c)
		}
	}
}

// RequireRole creates a middleware that requires a specific role
func RequireRole(checker PermissionChecker, cache *PermissionCache, role string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userID := GetUserID(c)
			if userID == uuid.Nil {
				return apperrors.NewErrUnauthorized()
			}

			// Check cache first
			userPerms, found := cache.Get(userID)
			if !found {
				// Fetch from database
				dbPerms, err := checker.GetUserPermissions(c.Request().Context(), userID)
				if err != nil {
					return apperrors.NewErrInternal().WithError(err)
				}

				// Convert to permission names
				userPerms = dbPerms
				cache.Set(userID, userPerms)
			}

			// Check if user has the role
			// Roles are stored as permissions with the format "role:{role_name}"
			rolePermission := fmt.Sprintf("role:%s", role)
			if !containsPermission(userPerms, rolePermission) {
				return apperrors.NewErrInsufficientPermissions().WithDetail(fmt.Sprintf("Required role: %s", role))
			}

			return next(c)
		}
	}
}

// HasPermission checks if a user has a specific permission (helper for use in handlers)
func HasPermission(c echo.Context, checker PermissionChecker, cache *PermissionCache, permission string) (bool, error) {
	userID := GetUserID(c)
	if userID == uuid.Nil {
		return false, nil
	}

	// Check cache first
	userPerms, found := cache.Get(userID)
	if !found {
		// Fetch from database
		dbPerms, err := checker.GetUserPermissions(c.Request().Context(), userID)
		if err != nil {
			return false, err
		}

		// Convert to permission names
		userPerms = dbPerms
		cache.Set(userID, userPerms)
	}

	return containsPermission(userPerms, permission), nil
}

// InvalidateUserCache invalidates the permission cache for a user
func InvalidateUserCache(cache *PermissionCache, userID uuid.UUID) {
	if cache != nil {
		cache.Invalidate(userID)
	}
}

// containsPermission checks if a permission exists in a slice
func containsPermission(permissions []string, permission string) bool {
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}
