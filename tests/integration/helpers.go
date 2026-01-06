package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/wbso/golang-starter/internal/domain/user"
)

// TestUser represents a test user with all necessary fields
type TestUser struct {
	ID              uuid.UUID
	Username        string
	Email           string
	Password        string
	AccessToken     string
	RefreshToken    string
	IsEmailVerified bool
	IsDisabled      bool
}

// CreateTestUser creates a test user in the database
func CreateTestUser(t require.TestingT, username, email, password string) *TestUser {
	ctx := context.Background()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)

	var userID uuid.UUID
	var fullName string
	err = TestDB.QueryRowContext(ctx, `
		INSERT INTO users (username, email, password_hash, is_email_verified)
		VALUES ($1, $2, $3, TRUE)
		RETURNING id, full_name
	`, username, email, string(hashedPassword)).Scan(&userID, &fullName)
	require.NoError(t, err)

	return &TestUser{
		ID:       userID,
		Username: username,
		Email:    email,
		Password: password,
	}
}

// CreateTestUserWithVerification creates a test user with optional email verification
func CreateTestUserWithVerification(t require.TestingT, username, email, password string, isEmailVerified bool) *TestUser {
	ctx := context.Background()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)

	var userID uuid.UUID
	err = TestDB.QueryRowContext(ctx, `
		INSERT INTO users (username, email, password_hash, is_email_verified)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`, username, email, string(hashedPassword), isEmailVerified).Scan(&userID)
	require.NoError(t, err)

	return &TestUser{
		ID:              userID,
		Username:        username,
		Email:           email,
		Password:        password,
		IsEmailVerified: isEmailVerified,
	}
}

// GenerateTestTokens generates access and refresh tokens for a test user
func GenerateTestTokens(t require.TestingT, userID uuid.UUID, email string) (accessToken, refreshToken string) {
	tokens, err := TestJWTMgr.GenerateTokenPair(userID, email)
	require.NoError(t, err)

	// Store refresh token in database
	ctx := context.Background()
	tokenHash := tokens.RefreshToken[:32] // Simple hash for testing
	_, err = TestDB.ExecContext(ctx, `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, userID, tokenHash, tokens.ExpiresAt.Add(7*24*3600))
	require.NoError(t, err)

	return tokens.AccessToken, tokens.RefreshToken
}

// CreateAuthenticatedRequest creates an HTTP request with Bearer token
func CreateAuthenticatedRequest(method, url string, token string) *http.Request {
	req := httptest.NewRequest(method, url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// SetupEchoContext creates an echo context for testing
func SetupEchoContext(e *echo.Echo, req *http.Request, path string, pathParams map[string]string) echo.Context {
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath(path)

	for key, val := range pathParams {
		c.SetParamNames(key)
		c.SetParamValues(val)
	}

	return c
}

// GrantRoleToUser grants a role to a test user
func GrantRoleToUser(t require.TestingT, userID uuid.UUID, roleName string) {
	ctx := context.Background()

	// Get role ID
	var roleID uuid.UUID
	err := TestDB.QueryRowContext(ctx, "SELECT id FROM roles WHERE name = $1", roleName).Scan(&roleID)
	if err != nil {
		// Create role if it doesn't exist
		err = TestDB.QueryRowContext(ctx, `
			INSERT INTO roles (name, description)
			VALUES ($1, $2)
			RETURNING id
		`, roleName, fmt.Sprintf("%s role", roleName)).Scan(&roleID)
		require.NoError(t, err)
	}

	// Assign role to user
	_, err = TestDB.ExecContext(ctx, `
		INSERT INTO user_roles (user_id, role_id)
		VALUES ($1, $2)
		ON CONFLICT (user_id, role_id) DO NOTHING
	`, userID, roleID)
	require.NoError(t, err)
}

// GrantPermissionToRole grants a permission to a role
func GrantPermissionToRole(t require.TestingT, roleName, permissionName string) {
	ctx := context.Background()

	// Get role and permission IDs
	var roleID, permissionID uuid.UUID

	err := TestDB.QueryRowContext(ctx, "SELECT id FROM roles WHERE name = $1", roleName).Scan(&roleID)
	require.NoError(t, err)

	err = TestDB.QueryRowContext(ctx, "SELECT id FROM permissions WHERE name = $1", permissionName).Scan(&permissionID)
	if err != nil {
		// Create permission if it doesn't exist
		err = TestDB.QueryRowContext(ctx, `
			INSERT INTO permissions (name, description)
			VALUES ($1, $2)
			RETURNING id
		`, permissionName, fmt.Sprintf("%s permission", permissionName)).Scan(&permissionID)
		require.NoError(t, err)
	}

	// Assign permission to role
	_, err = TestDB.ExecContext(ctx, `
		INSERT INTO role_permissions (role_id, permission_id)
		VALUES ($1, $2)
		ON CONFLICT (role_id, permission_id) DO NOTHING
	`, roleID, permissionID)
	require.NoError(t, err)
}

// GetTestUser retrieves a user from the database by ID
func GetTestUser(t require.TestingT, userID uuid.UUID) *user.User {
	ctx := context.Background()
	var u user.User

	err := TestDB.QueryRowContext(ctx, `
		SELECT id, username, email, full_name, is_disabled, is_email_verified,
		       last_login_at, created_at, updated_at
		FROM users
		WHERE id = $1 AND deleted_at IS NULL
	`, userID).Scan(
		&u.ID, &u.Username, &u.Email, &u.FullName, &u.IsDisabled, &u.IsEmailVerified,
		&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
	)
	require.NoError(t, err)

	return &u
}

// CleanupTestUser soft deletes a test user
func CleanupTestUser(t require.TestingT, userID uuid.UUID) {
	ctx := context.Background()
	_, err := TestDB.ExecContext(ctx, "UPDATE users SET deleted_at = NOW() WHERE id = $1", userID)
	require.NoError(t, err)
}

// AssertUserCount asserts the number of users in the database
func AssertUserCount(t require.TestingT, expected int) {
	ctx := context.Background()
	var count int
	err := TestDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE deleted_at IS NULL").Scan(&count)
	require.NoError(t, err)
	require.Equal(t, expected, count)
}
