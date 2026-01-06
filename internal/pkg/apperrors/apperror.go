package apperrors

import (
	"errors"
	"net/http"
)

// AppError represents an application error with HTTP status code
type AppError struct {
	Code        int                 `json:"code"`
	Type        string              `json:"type"`
	Title       string              `json:"title"`
	Detail      string              `json:"detail,omitempty"`
	Errors      map[string][]string `json:"errors,omitempty"`
	internalErr error               `json:"-"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	return e.Title
}

// Unwrap returns the underlying error
func (e *AppError) Unwrap() error {
	return e.internalErr
}

// NewAppError creates a new application error
func NewAppError(code int, title string) *AppError {
	return &AppError{
		Code:  code,
		Type:  getErrorType(code),
		Title: title,
	}
}

// WithDetail adds detail to the error
func (e *AppError) WithDetail(detail string) *AppError {
	e.Detail = detail
	return e
}

// WithError adds an underlying error
func (e *AppError) WithError(err error) *AppError {
	e.internalErr = err
	return e
}

// WithFieldErrors adds field-specific validation errors
func (e *AppError) WithFieldErrors(fieldErrors map[string][]string) *AppError {
	e.Errors = fieldErrors
	return e
}

// getErrorType returns the error type based on HTTP status code
func getErrorType(code int) string {
	switch code {
	case http.StatusBadRequest:
		return "https://example.com/probs/validation"
	case http.StatusUnauthorized:
		return "https://example.com/probs/unauthorized"
	case http.StatusForbidden:
		return "https://example.com/probs/forbidden"
	case http.StatusNotFound:
		return "https://example.com/probs/not-found"
	case http.StatusConflict:
		return "https://example.com/probs/conflict"
	case http.StatusTooManyRequests:
		return "https://example.com/probs/rate-limit"
	case http.StatusInternalServerError:
		return "https://example.com/probs/internal"
	default:
		return "about:blank"
	}
}

// IsNotFound checks if an error is a not found error
func IsNotFound(err error) bool {
	var appErr *AppError
	return errors.As(err, &appErr) && appErr.Code == http.StatusNotFound
}

// IsValidation checks if an error is a validation error
func IsValidation(err error) bool {
	var appErr *AppError
	return errors.As(err, &appErr) && appErr.Code == http.StatusBadRequest
}
