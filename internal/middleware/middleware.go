package middleware

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/wbso/golang-starter/internal/pkg/apperrors"
	"github.com/wbso/golang-starter/internal/pkg/logger"
	"golang.org/x/time/rate"
)

const (
	// RequestIDHeader is the header name for request ID
	RequestIDHeader = "X-Request-ID"
	// RequestIDKey is the context key for request ID
	RequestIDKey = "request_id"
	// UserKey is the context key for user ID
	UserKey = "user_id"
)

// RequestID is a middleware that adds a unique request ID to each request
func RequestID() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get or generate request ID
			rid := c.Request().Header.Get(RequestIDHeader)
			if rid == "" {
				rid = uuid.New().String()
			}

			// Set header and context
			c.Response().Header().Set(RequestIDHeader, rid)
			c.Set(RequestIDKey, rid)

			// Add to logger context
			ctx := logger.ToContext(c.Request().Context(), logger.With("request_id", rid))
			c.SetRequest(c.Request().WithContext(ctx))

			return next(c)
		}
	}
}

// Logger is a middleware that logs request details
func Logger() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()

			// Process request
			err := next(c)

			// Calculate latency
			latency := time.Since(start)

			// Get request ID
			rid, _ := c.Get(RequestIDKey).(string)

			// Get user ID if authenticated
			userID, _ := c.Get(UserKey).(string)

			// Get status code
			status := c.Response().Status
			if err != nil {
				var e *echo.HTTPError
				if errors.As(err, &e) {
					status = e.Code
				}

				var appErr *apperrors.AppError
				if errors.As(err, &appErr) {
					status = appErr.Code
				}
			}

			// Log request
			logFunc := logger.Info
			if status >= 400 && status < 500 {
				logFunc = logger.Warn
			} else if status >= 500 {
				logFunc = logger.Error
			}

			logFunc("request completed",
				"request_id", rid,
				"method", c.Request().Method,
				"path", c.Request().URL.Path,
				"status", status,
				"latency", latency.String(),
				"user_id", userID,
				"ip", c.RealIP(),
				"user_agent", c.Request().UserAgent(),
			)

			return err
		}
	}
}

// PanicRecovery is a middleware that recovers from panics
func PanicRecovery() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			defer func() {
				if r := recover(); r != nil {
					rid, _ := c.Get(RequestIDKey).(string)
					logger.Error("panic recovered",
						"request_id", rid,
						"panic", r,
						"path", c.Request().URL.Path,
					)
					c.Error(echo.NewHTTPError(http.StatusInternalServerError, "Internal server error"))
				}
			}()
			return next(c)
		}
	}
}

// NewRateLimiter creates a new rate limiter middleware
func NewRateLimiter(requestsPerMinute float64, burst int) echo.MiddlewareFunc {
	// Create a simple in-memory rate limiter
	// For production, consider using Redis or a more sophisticated solution
	limiterMap := make(map[string]*rate.Limiter)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ip := c.RealIP()

			// Get or create limiter for this IP
			l, exists := limiterMap[ip]
			if !exists {
				l = rate.NewLimiter(rate.Every(time.Minute/time.Duration(requestsPerMinute)), burst)
				limiterMap[ip] = l
			}

			// Check rate limit
			if !l.Allow() {
				return echo.NewHTTPError(http.StatusTooManyRequests, "Rate limit exceeded")
			}

			return next(c)
		}
	}
}

// Timeout is a middleware that adds a timeout to requests
func Timeout(timeout time.Duration) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx, cancel := context.WithTimeout(c.Request().Context(), timeout)
			defer cancel()

			c.SetRequest(c.Request().WithContext(ctx))

			// Create a channel to receive the result
			type result struct {
				err error
			}
			resultCh := make(chan result, 1)

			go func() {
				resultCh <- result{err: next(c)}
			}()

			select {
			case res := <-resultCh:
				return res.err
			case <-ctx.Done():
				return echo.NewHTTPError(http.StatusRequestTimeout, "Request timeout")
			}
		}
	}
}

// CORS is a middleware that adds CORS headers
func CORS() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Response().Header().Set("Access-Control-Allow-Origin", "*")
			c.Response().Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Response().Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
			c.Response().Header().Set("Access-Control-Expose-Headers", "X-Request-ID")

			if c.Request().Method == http.MethodOptions {
				return c.NoContent(http.StatusNoContent)
			}

			return next(c)
		}
	}
}

// GetRequestID returns the request ID from context
func GetRequestID(c echo.Context) string {
	rid, ok := c.Get(RequestIDKey).(string)
	if !ok {
		return ""
	}
	return rid
}

// GetUserID returns the user ID from context
func GetUserID(c echo.Context) uuid.UUID {
	uid, ok := c.Get(UserKey).(uuid.UUID)
	if !ok {
		return uuid.Nil
	}
	return uid
}

// SetUserID sets the user ID in context
func SetUserID(c echo.Context, userID uuid.UUID) {
	c.Set(UserKey, userID)
}
