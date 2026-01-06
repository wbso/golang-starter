package middleware

import (
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/wbso/golang-starter/internal/pkg/apperrors"
	"github.com/wbso/golang-starter/internal/pkg/jwt"
)

// JWTAuth creates a JWT authentication middleware
func JWTAuth(jwtMgr *jwt.Manager) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get authorization header
			auth := c.Request().Header.Get("Authorization")
			if auth == "" {
				return apperrors.NewErrUnauthorized()
			}

			// Check bearer format
			parts := strings.Split(auth, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				return apperrors.NewErrUnauthorized()
			}

			token := parts[1]

			// Check if token is blacklisted
			// TODO: Implement blacklist checking

			// Validate token
			claims, err := jwtMgr.ValidateToken(token)
			if err != nil {
				if strings.Contains(err.Error(), "expired") {
					return apperrors.NewErrTokenExpired().WithError(err)
				}
				return apperrors.NewErrInvalidToken().WithError(err)
			}

			// Set user context
			SetUserID(c, claims.UserID)
			c.Set("email", claims.Email)

			return next(c)
		}
	}
}

// RequireAuth is an alias for JWTAuth
func RequireAuth(jwtMgr *jwt.Manager) echo.MiddlewareFunc {
	return JWTAuth(jwtMgr)
}

// OptionalAuth is an optional authentication middleware
func OptionalAuth(jwtMgr *jwt.Manager) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			auth := c.Request().Header.Get("Authorization")
			if auth == "" {
				return next(c)
			}

			parts := strings.Split(auth, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				return next(c)
			}

			token := parts[1]
			claims, err := jwtMgr.ValidateToken(token)
			if err != nil {
				return next(c)
			}

			SetUserID(c, claims.UserID)
			c.Set("email", claims.Email)

			return next(c)
		}
	}
}

// GetUserEmail returns the user email from context
func GetUserEmail(c echo.Context) string {
	email, _ := c.Get("email").(string)
	return email
}

// SetUserID sets the user ID in context (for internal use)
func setUserID(c echo.Context, userID uuid.UUID) {
	c.Set(UserKey, userID)
}
