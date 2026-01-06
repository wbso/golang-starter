package handler

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/wbso/golang-starter/internal/domain/auth"
	"github.com/wbso/golang-starter/internal/feature/auth/service"
	"github.com/wbso/golang-starter/internal/middleware"
	"github.com/wbso/golang-starter/internal/pkg/apperrors"
	"github.com/wbso/golang-starter/internal/pkg/validator"
)

// Handler handles authentication HTTP requests
type Handler struct {
	authSvc *service.Service
}

// New creates a new auth handler
func New(authSvc *service.Service) *Handler {
	return &Handler{
		authSvc: authSvc,
	}
}

// Register handles user registration
// @Summary Register a new user
// @Description Register a new user account
// @Tags auth
// @Accept json
// @Produce json
// @Param request body auth.RegisterRequest true "Registration details"
// @Success 201 {object} Response{data=auth.AuthResponse}
// @Failure 400 {object} Response
// @Router /auth/register [post]
func (h *Handler) Register(c echo.Context) error {
	var req auth.RegisterRequest
	if err := c.Bind(&req); err != nil {
		return apperrors.NewErrInvalidInput().WithError(err)
	}

	resp, err := h.authSvc.Register(c.Request().Context(), req)
	if err != nil {
		return fmt.Errorf("failed to register user: %w", err)
	}

	return c.JSON(http.StatusCreated, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusCreated,
		Data:   resp,
	})
}

// Login handles user login
// @Summary Login
// @Description Login with username/email and password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body auth.LoginRequest true "Login credentials"
// @Success 200 {object} Response{data=auth.AuthResponse}
// @Failure 401 {object} Response
// @Router /auth/login [post]
func (h *Handler) Login(c echo.Context) error {
	var req auth.LoginRequest
	if err := c.Bind(&req); err != nil {
		return apperrors.NewErrInvalidInput().WithError(err)
	}

	// Validate
	v := validator.New()
	v.Required("username", req.Username).
		Required("password", req.Password)

	if v.HasErrors() {
		return apperrors.NewErrValidation().WithFieldErrors(v.Errors())
	}

	// Login
	resp, err := h.authSvc.Login(c.Request().Context(), req)
	if err != nil {
		if err.Error() == "invalid credentials" {
			return apperrors.NewErrInvalidCredentials().WithError(err)
		}
		if err.Error() == "account is disabled" {
			return apperrors.NewErrForbidden().WithError(err)
		}
		if err.Error() == "account locked" {
			return apperrors.NewErrForbidden().WithError(err)
		}
		if err.Error() == "email is not verified" {
			return apperrors.NewErrForbidden().WithError(err)
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

// RefreshToken handles token refresh
// @Summary Refresh access token
// @Description Refresh access token using refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body auth.RefreshTokenRequest true "Refresh token"
// @Success 200 {object} Response{data=auth.TokenPair}
// @Failure 401 {object} Response
// @Router /auth/refresh [post]
func (h *Handler) RefreshToken(c echo.Context) error {
	var req auth.RefreshTokenRequest
	if err := c.Bind(&req); err != nil {
		return apperrors.NewErrInvalidInput().WithError(err)
	}

	// Refresh
	tokens, err := h.authSvc.RefreshToken(c.Request().Context(), req)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   tokens,
	})
}

// Logout handles user logout
// @Summary Logout
// @Description Logout and revoke tokens
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} Response
// @Router /auth/logout [post]
func (h *Handler) Logout(c echo.Context) error {
	userID := middleware.GetUserID(c)
	accessToken := c.Request().Header.Get("Authorization")
	if len(accessToken) > 7 && accessToken[:7] == "Bearer " {
		accessToken = accessToken[7:]
	}

	if err := h.authSvc.Logout(c.Request().Context(), userID, accessToken); err != nil {
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   map[string]string{"message": "Logged out successfully"},
	})
}

// VerifyEmail handles email verification
// @Summary Verify email
// @Description Verify user email address
// @Tags auth
// @Accept json
// @Produce json
// @Param request body auth.VerifyEmailRequest true "Verification token"
// @Success 200 {object} Response
// @Router /auth/verify-email [post]
func (h *Handler) VerifyEmail(c echo.Context) error {
	var req auth.VerifyEmailRequest
	if err := c.Bind(&req); err != nil {
		return apperrors.NewErrInvalidInput().WithError(err)
	}

	// Validate
	v := validator.New()
	v.Required("token", req.Token)

	if v.HasErrors() {
		return apperrors.NewErrValidation().WithFieldErrors(v.Errors())
	}

	// Verify
	if err := h.authSvc.VerifyEmail(c.Request().Context(), req.Token); err != nil {
		return apperrors.NewErrInvalidToken().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   map[string]string{"message": "Email verified successfully"},
	})
}

// ForgotPassword handles forgot password
// @Summary Forgot password
// @Description Request password reset email
// @Tags auth
// @Accept json
// @Produce json
// @Param request body auth.ForgotPasswordRequest true "Email"
// @Success 200 {object} Response
// @Router /auth/forgot-password [post]
func (h *Handler) ForgotPassword(c echo.Context) error {
	var req auth.ForgotPasswordRequest
	if err := c.Bind(&req); err != nil {
		return apperrors.NewErrInvalidInput().WithError(err)
	}

	// Validate
	v := validator.New()
	v.Required("email", req.Email).
		Email("email", req.Email)

	if v.HasErrors() {
		return apperrors.NewErrValidation().WithFieldErrors(v.Errors())
	}

	// Send reset email
	if err := h.authSvc.ForgotPassword(c.Request().Context(), req); err != nil {
		return apperrors.NewErrInternal().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   map[string]string{"message": "If the email exists, a password reset link has been sent"},
	})
}

// ResetPassword handles password reset
// @Summary Reset password
// @Description Reset password with token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body auth.ResetPasswordRequest true "Token and new password"
// @Success 200 {object} Response
// @Router /auth/reset-password [post]
func (h *Handler) ResetPassword(c echo.Context) error {
	var req auth.ResetPasswordRequest
	if err := c.Bind(&req); err != nil {
		return apperrors.NewErrInvalidInput().WithError(err)
	}

	// Validate
	v := validator.New()
	v.Required("token", req.Token).
		Required("new_password", req.NewPassword).
		Password("new_password", req.NewPassword)

	if v.HasErrors() {
		return apperrors.NewErrValidation().WithFieldErrors(v.Errors())
	}

	// Reset password
	if err := h.authSvc.ResetPassword(c.Request().Context(), req); err != nil {
		return apperrors.NewErrInvalidToken().WithError(err)
	}

	return c.JSON(http.StatusOK, Response{
		Type:   "about:blank",
		Title:  "Success",
		Status: http.StatusOK,
		Data:   map[string]string{"message": "Password reset successfully"},
	})
}

// Response represents a standard API response
type Response struct {
	Type   string      `json:"type"`
	Title  string      `json:"title"`
	Status int         `json:"status"`
	Data   interface{} `json:"data,omitempty"`
}
