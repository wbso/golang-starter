package handler

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/wbso/golang-starter/internal/domain/user"
	"github.com/wbso/golang-starter/internal/feature/user/service"
	appmiddleware "github.com/wbso/golang-starter/internal/middleware"
	"github.com/wbso/golang-starter/internal/pkg/apperrors"
	"github.com/wbso/golang-starter/internal/pkg/validator"
)

// Handler handles user HTTP requests
type Handler struct {
	userSvc *service.Service
}

// New creates a new user handler
func New(userSvc *service.Service) *Handler {
	return &Handler{
		userSvc: userSvc,
	}
}

// List handles listing users with pagination
// @Summary List users
// @Description Get a paginated list of users
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Param sort query string false "Sort field and direction (e.g., created_at:desc)"
// @Param filter query string false "Filter expression (e.g., status:active)"
// @Success 200 {object} Response{data=PaginatedUsersResponse}
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Router /users [get]
func (h *Handler) List(c echo.Context) error {
	var req user.ListUsersRequest
	bindErr := c.Bind(&req)
	if bindErr != nil {
		return apperrors.NewErrInvalidInput().WithError(bindErr)
	}

	users, total, err := h.userSvc.List(c.Request().Context(), req)
	if err != nil {
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data: PaginatedUsersResponse{
			Items: users,
			Pagination: Pagination{
				Page:       0,
				Limit:      0,
				Total:      int(total),
				TotalPages: 0,
			},
		},
	})
}

// GetByID handles getting a user by ID
// @Summary Get user by ID
// @Description Get a user by their ID
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} Response{data=user.UserResponse}
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 404 {object} Response
// @Router /users/{id} [get]
func (h *Handler) GetByID(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	resp, err := h.userSvc.GetByID(c.Request().Context(), id)
	if err != nil {
		if err.Error() == "user not found" {
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

// GetMe handles getting the current user
// @Summary Get current user
// @Description Get the currently authenticated user
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} Response{data=user.UserResponse}
// @Failure 401 {object} Response
// @Router /users/me [get]
func (h *Handler) GetMe(c echo.Context) error {
	userID := appmiddleware.GetUserID(c)

	resp, err := h.userSvc.GetMe(c.Request().Context(), userID)
	if err != nil {
		if err.Error() == "user not found" {
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

// Create handles creating a new user
// @Summary Create user
// @Description Create a new user
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body user.CreateUserRequest true "User details"
// @Success 201 {object} Response{data=user.UserResponse}
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 409 {object} Response
// @Router /users [post]
func (h *Handler) Create(c echo.Context) error {
	var req user.CreateUserRequest
	if err := c.Bind(&req); err != nil {
		return apperrors.NewErrInvalidInput().WithError(err)
	}

	// Validate
	v := validator.New()
	v.Required("username", req.Username).
		MinLength("username", req.Username, 3).
		Username("username", req.Username).
		Required("email", req.Email).
		Email("email", req.Email).
		Required("password", req.Password).
		Password("password", req.Password)

	if v.HasErrors() {
		return apperrors.NewErrValidation().WithFieldErrors(v.Errors())
	}

	// Get current user ID for audit
	userID := appmiddleware.GetUserID(c)

	resp, err := h.userSvc.Create(c.Request().Context(), req, &userID)
	if err != nil {
		if err.Error() == "username already exists" {
			return apperrors.NewErrConflict().WithError(err)
		}
		if err.Error() == "email already exists" {
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

// Update handles updating a user
// @Summary Update user
// @Description Update a user by ID
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Param request body user.UpdateUserRequest true "User details"
// @Success 200 {object} Response{data=user.UserResponse}
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 404 {object} Response
// @Failure 409 {object} Response
// @Router /users/{id} [put]
func (h *Handler) Update(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	var req user.UpdateUserRequest
	if err := c.Bind(&req); err != nil {
		return apperrors.NewErrInvalidInput().WithError(err)
	}

	// Validate if fields are provided
	v := validator.New()
	if req.Username != nil {
		v.MinLength("username", *req.Username, 3).Username("username", *req.Username)
	}
	if req.Email != nil {
		v.Email("email", *req.Email)
	}

	if v.HasErrors() {
		return apperrors.NewErrValidation().WithFieldErrors(v.Errors())
	}

	// Get current user ID for audit
	userID := appmiddleware.GetUserID(c)

	resp, err := h.userSvc.Update(c.Request().Context(), id, req, &userID)
	if err != nil {
		if err.Error() == "user not found" {
			return apperrors.NewErrNotFound().WithError(err)
		}
		if err.Error() == "username already exists" {
			return apperrors.NewErrConflict().WithError(err)
		}
		if err.Error() == "email already exists" {
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

// UpdateMe handles updating the current user
// @Summary Update current user
// @Description Update the currently authenticated user
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body user.UpdateUserRequest true "User details"
// @Success 200 {object} Response{data=user.UserResponse}
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Failure 409 {object} Response
// @Router /users/me [put]
func (h *Handler) UpdateMe(c echo.Context) error {
	var req user.UpdateUserRequest
	if err := c.Bind(&req); err != nil {
		return apperrors.NewErrInvalidInput().WithError(err)
	}

	// Validate if fields are provided
	v := validator.New()
	if req.Username != nil {
		v.MinLength("username", *req.Username, 3).Username("username", *req.Username)
	}
	if req.Email != nil {
		v.Email("email", *req.Email)
	}

	if v.HasErrors() {
		return apperrors.NewErrValidation().WithFieldErrors(v.Errors())
	}

	userID := appmiddleware.GetUserID(c)

	resp, err := h.userSvc.UpdateMe(c.Request().Context(), userID, req)
	if err != nil {
		if err.Error() == "user not found" {
			return apperrors.NewErrNotFound().WithError(err)
		}
		if err.Error() == "username already exists" {
			return apperrors.NewErrConflict().WithError(err)
		}
		if err.Error() == "email already exists" {
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

// ChangePassword handles changing the current user's password
// @Summary Change password
// @Description Change the current user's password
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body user.ChangePasswordRequest true "Password details"
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 401 {object} Response
// @Router /users/me/change-password [post]
func (h *Handler) ChangePassword(c echo.Context) error {
	var req user.ChangePasswordRequest
	if err := c.Bind(&req); err != nil {
		return apperrors.NewErrInvalidInput().WithError(err)
	}

	// Validate
	v := validator.New()
	v.Required("old_password", req.OldPassword).
		Required("new_password", req.NewPassword).
		Password("new_password", req.NewPassword)

	if v.HasErrors() {
		return apperrors.NewErrValidation().WithFieldErrors(v.Errors())
	}

	userID := appmiddleware.GetUserID(c)

	if err := h.userSvc.ChangePassword(c.Request().Context(), userID, req); err != nil {
		if err.Error() == "invalid current password" {
			return apperrors.NewErrValidation().WithError(err).WithFieldErrors(map[string][]string{
				"old_password": {err.Error()},
			})
		}
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   map[string]string{"message": "Password changed successfully"},
	})
}

// Disable handles disabling a user
// @Summary Disable user
// @Description Disable a user by ID
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} Response
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 404 {object} Response
// @Router /users/{id}/disable [post]
func (h *Handler) Disable(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	userID := appmiddleware.GetUserID(c)

	if err := h.userSvc.Disable(c.Request().Context(), id, &userID); err != nil {
		if err.Error() == "user not found" {
			return apperrors.NewErrNotFound().WithError(err)
		}
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   map[string]string{"message": "User disabled successfully"},
	})
}

// Enable handles enabling a disabled user
// @Summary Enable user
// @Description Enable (restore) a disabled user by ID
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} Response
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 404 {object} Response
// @Router /users/{id}/enable [post]
func (h *Handler) Enable(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	userID := appmiddleware.GetUserID(c)

	if err := h.userSvc.Enable(c.Request().Context(), id, &userID); err != nil {
		if err.Error() == "user not found" {
			return apperrors.NewErrNotFound().WithError(err)
		}
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   map[string]string{"message": "User enabled successfully"},
	})
}

// Delete handles soft deleting a user
// @Summary Delete user
// @Description Soft delete a user by ID
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} Response
// @Failure 401 {object} Response
// @Failure 403 {object} Response
// @Failure 404 {object} Response
// @Router /users/{id} [delete]
func (h *Handler) Delete(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apperrors.NewErrValidation().WithError(err)
	}

	userID := appmiddleware.GetUserID(c)

	if err := h.userSvc.Delete(c.Request().Context(), id, &userID); err != nil {
		if err.Error() == "user not found" {
			return apperrors.NewErrNotFound().WithError(err)
		}
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   map[string]string{"message": "User deleted successfully"},
	})
}

// DeleteMe handles deleting the current user
// @Summary Delete current user
// @Description Delete the currently authenticated user
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} Response
// @Failure 401 {object} Response
// @Router /users/me [delete]
func (h *Handler) DeleteMe(c echo.Context) error {
	userID := appmiddleware.GetUserID(c)

	if err := h.userSvc.DeleteMe(c.Request().Context(), userID); err != nil {
		if err.Error() == "user not found" {
			return apperrors.NewErrNotFound().WithError(err)
		}
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   map[string]string{"message": "Account deleted successfully"},
	})
}

// Response represents a standard API response
type Response struct {
	Type   string      `json:"type"`
	Title  string      `json:"title"`
	Status int         `json:"status"`
	Data   interface{} `json:"data,omitempty"`
}

// PaginatedUsersResponse represents a paginated users response
type PaginatedUsersResponse struct {
	Items      []user.UserResponse `json:"items"`
	Pagination Pagination          `json:"pagination"`
}

// Pagination represents pagination metadata
type Pagination struct {
	Page       int `json:"page"`
	Limit      int `json:"limit"`
	Total      int `json:"total"`
	TotalPages int `json:"totalPages"`
}
