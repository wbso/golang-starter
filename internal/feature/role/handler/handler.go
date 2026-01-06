package handler

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/wbso/golang-starter/internal/domain/permission"
	"github.com/wbso/golang-starter/internal/domain/role"
	"github.com/wbso/golang-starter/internal/feature/role/service"
	appmiddleware "github.com/wbso/golang-starter/internal/middleware"
	"github.com/wbso/golang-starter/internal/pkg/apperrors"
	"github.com/wbso/golang-starter/internal/pkg/validator"
)

// Handler handles role HTTP requests
type Handler struct {
	roleSvc *service.Service
}

// New creates a new role handler
func New(roleSvc *service.Service) *Handler {
	return &Handler{
		roleSvc: roleSvc,
	}
}

// List handles listing roles with pagination
// @Summary List roles
// @Description Get a paginated list of roles
// @Tags roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Success 200 {object} Response{data=PaginatedRolesResponse}
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Router /roles [get]
func (h *Handler) List(c echo.Context) error {
	// Parse query parameters
	page, _ := strconv.Atoi(c.QueryParam("page"))
	limit, _ := strconv.Atoi(c.QueryParam("limit"))

	roles, total, err := h.roleSvc.List(c.Request().Context(), page, limit)
	if err != nil {
		return apperrors.NewErrInternal().WithError(err)
	}

	// Calculate pagination
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 20
	}
	totalPages := int(total) / limit
	if int(total)%limit > 0 {
		totalPages++
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data: PaginatedRolesResponse{
			Items: roles,
			Pagination: Pagination{
				Page:       page,
				Limit:      limit,
				Total:      int(total),
				TotalPages: totalPages,
			},
		},
	})
}

// GetByID handles getting a role by ID
// @Summary Get role by ID
// @Description Get a role by their ID
// @Tags roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Role ID"
// @Success 200 {object} Response{data=role.RoleResponse}
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 404 {object} Response
// @Router /roles/{id} [get]
func (h *Handler) GetByID(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	resp, err := h.roleSvc.GetByID(c.Request().Context(), id)
	if err != nil {
		if err.Error() == "role not found" {
			return apperrors.NewErrNotFound().WithError(err)
		}
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   resp,
	})
}

// GetPermissions handles getting permissions for a role
// @Summary Get role permissions
// @Description Get permissions for a role
// @Tags roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Role ID"
// @Success 200 {object} Response{data=[]permission.PermissionResponse}
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 404 {object} Response
// @Router /roles/{id}/permissions [get]
func (h *Handler) GetPermissions(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	permissions, err := h.roleSvc.GetPermissions(c.Request().Context(), id)
	if err != nil {
		if err.Error() == "role not found" {
			return apperrors.NewErrNotFound().WithError(err)
		}
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   permissions,
	})
}

// Create handles creating a new role
// @Summary Create role
// @Description Create a new role
// @Tags roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body role.CreateRoleRequest true "Role details"
// @Success 201 {object} Response{data=role.RoleResponse}
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 409 {object} Response
// @Router /roles [post]
func (h *Handler) Create(c echo.Context) error {
	var req role.CreateRoleRequest
	if err := c.Bind(&req); err != nil {
		return apperrors.NewErrInvalidInput().WithError(err)
	}

	// Validate
	v := validator.New()
	v.Required("name", req.Name).MinLength("name", req.Name, 2)

	if v.HasErrors() {
		return apperrors.NewErrValidation().WithFieldErrors(v.Errors())
	}

	// Get current user ID for audit
	userID := appmiddleware.GetUserID(c)

	resp, err := h.roleSvc.Create(c.Request().Context(), req, &userID)
	if err != nil {
		if err.Error() == "role name already exists" {
			return apperrors.NewErrConflict().WithError(err)
		}
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusCreated, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusCreated,
		Data:   resp,
	})
}

// Update handles updating a role
// @Summary Update role
// @Description Update a role by ID
// @Tags roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Role ID"
// @Param request body role.UpdateRoleRequest true "Role details"
// @Success 200 {object} Response{data=role.RoleResponse}
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 404 {object} Response
// @Failure 409 {object} Response
// @Router /roles/{id} [put]
func (h *Handler) Update(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	var req role.UpdateRoleRequest
	if err := c.Bind(&req); err != nil {
		return apperrors.NewErrInvalidInput().WithError(err)
	}

	// Validate if fields are provided
	v := validator.New()
	if req.Name != nil {
		v.MinLength("name", *req.Name, 2)
	}

	if v.HasErrors() {
		return apperrors.NewErrValidation().WithFieldErrors(v.Errors())
	}

	// Get current user ID for audit
	userID := appmiddleware.GetUserID(c)

	resp, err := h.roleSvc.Update(c.Request().Context(), id, req, &userID)
	if err != nil {
		if err.Error() == "role not found" {
			return apperrors.NewErrNotFound().WithError(err)
		}
		if err.Error() == "role name already exists" {
			return apperrors.NewErrConflict().WithError(err)
		}
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   resp,
	})
}

// Delete handles deleting a role
// @Summary Delete role
// @Description Delete a role by ID
// @Tags roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Role ID"
// @Success 200 {object} Response
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 404 {object} Response
// @Failure 409 {object} Response
// @Router /roles/{id} [delete]
func (h *Handler) Delete(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	userID := appmiddleware.GetUserID(c)

	if err := h.roleSvc.Delete(c.Request().Context(), id, &userID); err != nil {
		if err.Error() == "role not found" {
			return apperrors.NewErrNotFound().WithError(err)
		}
		if err.Error() == "role is assigned to users and cannot be deleted" {
			return apperrors.NewErrRoleAssigned().WithError(err)
		}
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   map[string]string{"message": "Role deleted successfully"},
	})
}

// AssignPermission handles assigning a permission to a role
// @Summary Assign permission to role
// @Description Assign a permission to a role
// @Tags roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Role ID"
// @Param request body permission.AssignPermissionRequest true "Permission details"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 404 {object} Response
// @Router /roles/{id}/permissions [post]
func (h *Handler) AssignPermission(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	var req permission.AssignPermissionRequest
	if err := c.Bind(&req); err != nil {
		return apperrors.NewErrInvalidInput().WithError(err)
	}

	// Validate
	v := validator.New()
	if req.PermissionID == uuid.Nil {
		v.Custom("permission_id", "permission_id is required")
	}

	if v.HasErrors() {
		return apperrors.NewErrValidation().WithFieldErrors(v.Errors())
	}

	userID := appmiddleware.GetUserID(c)

	if err := h.roleSvc.AssignPermission(c.Request().Context(), id, req.PermissionID, &userID); err != nil {
		if err.Error() == "role not found" {
			return apperrors.NewErrNotFound().WithError(err)
		}
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   map[string]string{"message": "Permission assigned successfully"},
	})
}

// RevokePermission handles revoking a permission from a role
// @Summary Revoke permission from role
// @Description Revoke a permission from a role
// @Tags roles
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Role ID"
// @Param permissionId path string true "Permission ID"
// @Success 200 {object} Response
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 404 {object} Response
// @Router /roles/{id}/permissions/{permissionId} [delete]
func (h *Handler) RevokePermission(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	permissionID, err := uuid.Parse(c.Param("permissionId"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	if err := h.roleSvc.RevokePermission(c.Request().Context(), id, permissionID); err != nil {
		if err.Error() == "role not found" {
			return apperrors.NewErrNotFound().WithError(err)
		}
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   map[string]string{"message": "Permission revoked successfully"},
	})
}

// GetUserRoles handles getting roles for a user
// @Summary Get user roles
// @Description Get roles for a user
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} Response{data=[]role.RoleResponse}
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Router /users/{id}/roles [get]
func (h *Handler) GetUserRoles(c echo.Context) error {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	roles, err := h.roleSvc.GetUserRoles(c.Request().Context(), userID)
	if err != nil {
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   roles,
	})
}

// AssignRole handles assigning a role to a user
// @Summary Assign role to user
// @Description Assign a role to a user
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Param request body role.AssignRoleRequest true "Role details"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 404 {object} Response
// @Router /users/{id}/roles [post]
func (h *Handler) AssignRole(c echo.Context) error {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	var req role.AssignRoleRequest
	if err := c.Bind(&req); err != nil {
		return apperrors.NewErrInvalidInput().WithError(err)
	}

	// Validate
	v := validator.New()
	if req.RoleID == uuid.Nil {
		v.Custom("role_id", "role_id is required")
	}

	if v.HasErrors() {
		return apperrors.NewErrValidation().WithFieldErrors(v.Errors())
	}

	currentUserID := appmiddleware.GetUserID(c)

	if err := h.roleSvc.AssignToUser(c.Request().Context(), userID, req.RoleID, &currentUserID); err != nil {
		if err.Error() == "role not found" {
			return apperrors.NewErrNotFound().WithError(err)
		}
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   map[string]string{"message": "Role assigned successfully"},
	})
}

// RevokeRole handles revoking a role from a user
// @Summary Revoke role from user
// @Description Revoke a role from a user
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Param roleId path string true "Role ID"
// @Success 200 {object} Response
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 404 {object} Response
// @Router /users/{id}/roles/{roleId} [delete]
func (h *Handler) RevokeRole(c echo.Context) error {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	roleID, err := uuid.Parse(c.Param("roleId"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	if err := h.roleSvc.RevokeFromUser(c.Request().Context(), userID, roleID); err != nil {
		if err.Error() == "role not found" {
			return apperrors.NewErrNotFound().WithError(err)
		}
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   map[string]string{"message": "Role revoked successfully"},
	})
}

// Response represents a standard API response
type Response struct {
	Type   string      `json:"type"`
	Title  string      `json:"title"`
	Status int         `json:"status"`
	Data   interface{} `json:"data,omitempty"`
}

// PaginatedRolesResponse represents a paginated roles response
type PaginatedRolesResponse struct {
	Items      []role.RoleResponse `json:"items"`
	Pagination Pagination          `json:"pagination"`
}

// Pagination represents pagination metadata
type Pagination struct {
	Page       int `json:"page"`
	Limit      int `json:"limit"`
	Total      int `json:"total"`
	TotalPages int `json:"totalPages"`
}
