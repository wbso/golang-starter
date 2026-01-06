package apperrors

import "net/http"

func NewErrValidation() *AppError {
	return NewAppError(http.StatusBadRequest, "Validation Error")
}

func NewErrInvalidInput() *AppError {
	return NewAppError(http.StatusBadRequest, "Invalid Input")
}

func NewErrUnauthorized() *AppError {
	return NewAppError(http.StatusUnauthorized, "Unauthorized")
}

func NewErrInvalidCredentials() *AppError {
	return NewAppError(http.StatusUnauthorized, "Invalid Credentials")
}

func NewErrTokenExpired() *AppError {
	return NewAppError(http.StatusUnauthorized, "Token Expired")
}

func NewErrInvalidToken() *AppError {
	return NewAppError(http.StatusUnauthorized, "Invalid Token")
}

func NewErrForbidden() *AppError {
	return NewAppError(http.StatusForbidden, "Forbidden")
}

func NewErrInsufficientPermissions() *AppError {
	return NewAppError(http.StatusForbidden, "Insufficient Permissions")
}

func NewErrNotFound() *AppError {
	return NewAppError(http.StatusNotFound, "Resource Not Found")
}

func NewErrUserNotFound() *AppError {
	return NewAppError(http.StatusNotFound, "User Not Found")
}

func NewErrRoleNotFound() *AppError {
	return NewAppError(http.StatusNotFound, "Role Not Found")
}

func NewErrPermissionNotFound() *AppError {
	return NewAppError(http.StatusNotFound, "Permission Not Found")
}

func NewErrConflict() *AppError {
	return NewAppError(http.StatusConflict, "Conflict")
}

func NewErrEmailExists() *AppError {
	return NewAppError(http.StatusConflict, "Email Already Exists")
}

func NewErrUsernameExists() *AppError {
	return NewAppError(http.StatusConflict, "Username Already Exists")
}

func NewErrRoleAssigned() *AppError {
	return NewAppError(http.StatusConflict, "Role is Assigned to Users")
}

func NewErrRateLimit() *AppError {
	return NewAppError(http.StatusTooManyRequests, "Rate Limit Exceeded")
}

func NewErrAccountDisabled() *AppError {
	return NewAppError(http.StatusForbidden, "Account Disabled")
}

func NewErrAccountLocked() *AppError {
	return NewAppError(http.StatusForbidden, "Account Locked")
}

func NewErrEmailNotVerified() *AppError {
	return NewAppError(http.StatusForbidden, "Email Not Verified")
}

func NewErrInternal() *AppError {
	return NewAppError(http.StatusInternalServerError, "Internal Server Error")
}

func NewErrDatabase() *AppError {
	return NewAppError(http.StatusInternalServerError, "Database Error")
}
