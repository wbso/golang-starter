package handler

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/wbso/golang-starter/internal/domain/permission"
	"github.com/wbso/golang-starter/internal/feature/permission/service"
	appmiddleware "github.com/wbso/golang-starter/internal/middleware"
	"github.com/wbso/golang-starter/internal/pkg/apperrors"
	"github.com/wbso/golang-starter/internal/pkg/validator"
)

// Handler handles permission HTTP requests
type Handler struct {
	permissionSvc *service.Service
}

// New creates a new permission handler
func New(permissionSvc *service.Service) *Handler {
	return &Handler{
		permissionSvc: permissionSvc,
	}
}

// List handles listing permissions with pagination
// @Summary List permissions
// @Description Get a paginated list of permissions
// @Tags permissions
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Success 200 {object} Response{data=PaginatedPermissionsResponse}
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Router /permissions [get]
func (h *Handler) List(c echo.Context) error {
	// Parse query parameters
	page, _ := strconv.Atoi(c.QueryParam("page"))
	limit, _ := strconv.Atoi(c.QueryParam("limit"))

	permissions, total, err := h.permissionSvc.List(c.Request().Context(), page, limit)
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
		Data: PaginatedPermissionsResponse{
			Items: permissions,
			Pagination: Pagination{
				Page:       page,
				Limit:      limit,
				Total:      int(total),
				TotalPages: totalPages,
			},
		},
	})
}

// GetByID handles getting a permission by ID
// @Summary Get permission by ID
// @Description Get a permission by their ID
// @Tags permissions
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Permission ID"
// @Success 200 {object} Response{data=permission.PermissionResponse}
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 404 {object} Response
// @Router /permissions/{id} [get]
func (h *Handler) GetByID(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	resp, err := h.permissionSvc.GetByID(c.Request().Context(), id)
	if err != nil {
		if err.Error() == "permission not found" {
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

// Create handles creating a new permission
// @Summary Create permission
// @Description Create a new permission
// @Tags permissions
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body permission.CreatePermissionRequest true "Permission details"
// @Success 201 {object} Response{data=permission.PermissionResponse}
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 409 {object} Response
// @Router /permissions [post]
func (h *Handler) Create(c echo.Context) error {
	var req permission.CreatePermissionRequest
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

	resp, err := h.permissionSvc.Create(c.Request().Context(), req, &userID)
	if err != nil {
		if err.Error() == "permission name already exists" {
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

// Update handles updating a permission
// @Summary Update permission
// @Description Update a permission by ID
// @Tags permissions
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Permission ID"
// @Param request body permission.UpdatePermissionRequest true "Permission details"
// @Success 200 {object} Response{data=permission.PermissionResponse}
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 404 {object} Response
// @Failure 409 {object} Response
// @Router /permissions/{id} [put]
func (h *Handler) Update(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	var req permission.UpdatePermissionRequest
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

	resp, err := h.permissionSvc.Update(c.Request().Context(), id, req, &userID)
	if err != nil {
		if err.Error() == "permission not found" {
			return apperrors.NewErrNotFound().WithError(err)
		}
		if err.Error() == "permission name already exists" {
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

// Delete handles deleting a permission
// @Summary Delete permission
// @Description Delete a permission by ID
// @Tags permissions
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Permission ID"
// @Success 200 {object} Response
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 404 {object} Response
// @Router /permissions/{id} [delete]
func (h *Handler) Delete(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	if err := h.permissionSvc.Delete(c.Request().Context(), id); err != nil {
		if err.Error() == "permission not found" {
			return apperrors.NewErrNotFound().WithError(err)
		}
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   map[string]string{"message": "Permission deleted successfully"},
	})
}

// Response represents a standard API response
type Response struct {
	Type   string      `json:"type"`
	Title  string      `json:"title"`
	Status int         `json:"status"`
	Data   interface{} `json:"data,omitempty"`
}

// PaginatedPermissionsResponse represents a paginated permissions response
type PaginatedPermissionsResponse struct {
	Items      []permission.PermissionResponse `json:"items"`
	Pagination Pagination                      `json:"pagination"`
}

// Pagination represents pagination metadata
type Pagination struct {
	Page       int `json:"page"`
	Limit      int `json:"limit"`
	Total      int `json:"total"`
	TotalPages int `json:"totalPages"`
}
