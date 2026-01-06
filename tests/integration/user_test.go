package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/wbso/golang-starter/internal/domain/user"
	"github.com/wbso/golang-starter/internal/feature/user/handler"
	userrepo "github.com/wbso/golang-starter/internal/feature/user/repository"
	"github.com/wbso/golang-starter/internal/feature/user/service"
)

func TestUser_GetMe(t *testing.T) {
	SetupTest(t)
	defer TeardownTest(t)

	userHandler := setupUserHandler(t)

	// Create a test user
	testUser := createTestUser(t, "meuser", "me@example.com", "Test12345!")
	accessToken := generateAccessToken(t, testUser.ID)

	tests := []struct {
		name           string
		setupToken     string
		expectedStatus int
	}{
		{
			name:           "get current user",
			setupToken:     accessToken,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "no token",
			setupToken:     "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "invalid token",
			setupToken:     "invalid-token",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
			if tt.setupToken != "" {
				req.Header.Set("Authorization", "Bearer "+tt.setupToken)
			}

			rec := httptest.NewRecorder()
			c := TestServer.NewContext(req, rec)
			c.SetPath("/api/v1/users/me")

			err := userHandler.GetMe(c)
			if tt.expectedStatus == http.StatusOK {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.expectedStatus, rec.Code)

			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				require.NoError(t, err)

				data := response["data"].(map[string]interface{})
				assert.Equal(t, testUser.Username, data["username"])
				assert.Equal(t, testUser.Email, data["email"])
			}
		})
	}
}

func TestUser_UpdateMe(t *testing.T) {
	SetupTest(t)
	defer TeardownTest(t)

	userHandler := setupUserHandler(t)

	// Create a test user
	testUser := createTestUser(t, "updatemeuser", "updateme@example.com", "Test12345!")
	accessToken := generateAccessToken(t, testUser.ID)

	tests := []struct {
		name           string
		request        user.UpdateUserRequest
		expectedStatus int
	}{
		{
			name: "update full name",
			request: user.UpdateUserRequest{
				FullName: strPtr("Updated Name"),
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "update username",
			request: user.UpdateUserRequest{
				Username: strPtr("newusername"),
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "update email",
			request: user.UpdateUserRequest{
				Email: strPtr("newemail@example.com"),
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPut, "/api/v1/users/me", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+accessToken)
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()
			c := TestServer.NewContext(req, rec)
			c.SetPath("/api/v1/users/me")

			err = userHandler.UpdateMe(c)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				require.NoError(t, err)

				data := response["data"].(map[string]interface{})
				if tt.request.FullName != nil {
					assert.Equal(t, *tt.request.FullName, data["full_name"])
				}
				if tt.request.Username != nil {
					assert.Equal(t, *tt.request.Username, data["username"])
				}
				if tt.request.Email != nil {
					assert.Equal(t, *tt.request.Email, data["email"])
				}
			}
		})
	}
}

func TestUser_ChangePassword(t *testing.T) {
	SetupTest(t)
	defer TeardownTest(t)

	userHandler := setupUserHandler(t)

	// Create a test user
	testUser := createTestUser(t, "changepassuser", "changepass@example.com", "OldPass123!")
	accessToken := generateAccessToken(t, testUser.ID)

	tests := []struct {
		name           string
		request        user.ChangePasswordRequest
		expectedStatus int
	}{
		{
			name: "successful password change",
			request: user.ChangePasswordRequest{
				OldPassword: "OldPass123!",
				NewPassword: "NewPass456!",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "wrong old password",
			request: user.ChangePasswordRequest{
				OldPassword: "WrongPass123!",
				NewPassword: "NewPass456!",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "weak new password",
			request: user.ChangePasswordRequest{
				OldPassword: "OldPass123!",
				NewPassword: "weak",
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/users/me/change-password", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+accessToken)
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()
			c := TestServer.NewContext(req, rec)
			c.SetPath("/api/v1/users/me/change-password")

			err = userHandler.ChangePassword(c)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, rec.Code)
		})
	}
}

func TestUser_DeleteMe(t *testing.T) {
	SetupTest(t)
	defer TeardownTest(t)

	userHandler := setupUserHandler(t)

	// Create a test user
	testUser := createTestUser(t, "deletemeuser", "deleteme@example.com", "Test12345!")
	accessToken := generateAccessToken(t, testUser.ID)

	// Delete the user
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rec := httptest.NewRecorder()
	c := TestServer.NewContext(req, rec)
	c.SetPath("/api/v1/users/me")

	err := userHandler.DeleteMe(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify user is soft deleted
	ctx := context.Background()
	var deletedAt interface{}
	err = TestDB.QueryRowContext(ctx, "SELECT deleted_at FROM users WHERE id = $1", testUser.ID).Scan(&deletedAt)
	require.NoError(t, err)
	assert.NotNil(t, deletedAt)
}

func TestUser_List(t *testing.T) {
	SetupTest(t)
	defer TeardownTest(t)

	userHandler := setupUserHandler(t)

	// Create admin user with permissions
	adminUser := createTestUser(t, "adminuser", "admin@example.com", "Test12345!")
	grantAllPermissions(t, adminUser.ID)
	adminToken := generateAccessToken(t, adminUser.ID)

	// Create some test users
	for i := 0; i < 5; i++ {
		createTestUser(t, uuid.New().String()[:20], uuid.New().String()+"@example.com", "Test12345!")
	}

	// Test listing users
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users?page=1&limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)

	rec := httptest.NewRecorder()
	c := TestServer.NewContext(req, rec)
	c.SetPath("/api/v1/users")
	c.QueryParams().Set("page", "1")
	c.QueryParams().Set("limit", "10")

	err := userHandler.List(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	data := response["data"].(map[string]interface{})
	assert.NotEmpty(t, data["items"])

	pagination := data["pagination"].(map[string]interface{})
	assert.Equal(t, float64(1), pagination["page"])
	assert.Equal(t, float64(10), pagination["limit"])
}

func TestUser_Disable_Enable(t *testing.T) {
	SetupTest(t)
	defer TeardownTest(t)

	userHandler := setupUserHandler(t)

	// Create admin user
	adminUser := createTestUser(t, "adminuser2", "admin2@example.com", "Test12345!")
	grantAllPermissions(t, adminUser.ID)
	adminToken := generateAccessToken(t, adminUser.ID)

	// Create a user to disable
	targetUser := createTestUser(t, "disableuser", "disable@example.com", "Test12345!")

	// Disable the user
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+targetUser.ID.String()+"/disable", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)

	rec := httptest.NewRecorder()
	c := TestServer.NewContext(req, rec)
	c.SetPath("/api/v1/users/:id/disable")
	c.SetParamNames("id")
	c.SetParamValues(targetUser.ID.String())

	err := userHandler.Disable(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify user is disabled
	ctx := context.Background()
	var isDisabled bool
	err = TestDB.QueryRowContext(ctx, "SELECT is_disabled FROM users WHERE id = $1", targetUser.ID).Scan(&isDisabled)
	require.NoError(t, err)
	assert.True(t, isDisabled)

	// Enable the user
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/"+targetUser.ID.String()+"/enable", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)

	rec = httptest.NewRecorder()
	c = TestServer.NewContext(req, rec)
	c.SetPath("/api/v1/users/:id/enable")
	c.SetParamNames("id")
	c.SetParamValues(targetUser.ID.String())

	err = userHandler.Enable(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify user is enabled
	err = TestDB.QueryRowContext(ctx, "SELECT is_disabled FROM users WHERE id = $1", targetUser.ID).Scan(&isDisabled)
	require.NoError(t, err)
	assert.False(t, isDisabled)
}

// Helper functions

func setupUserHandler(t *testing.T) *handler.Handler {
	userRepo := userrepo.New(TestDB.DB)
	userSvc := service.New(userRepo)
	return handler.New(userSvc)
}

func createTestUser(t *testing.T, username, email, password string) *user.User {
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

	return &user.User{
		ID:       userID,
		Username: username,
		Email:    email,
		FullName: &fullName,
	}
}

func generateAccessToken(t *testing.T, userID uuid.UUID) string {
	token, err := TestJWTMgr.GenerateTokenPair(userID, "test@example.com")
	require.NoError(t, err)
	return token.AccessToken
}

func grantAllPermissions(t *testing.T, userID uuid.UUID) {
	ctx := context.Background()

	// Get admin role ID
	var adminRoleID uuid.UUID
	err := TestDB.QueryRowContext(ctx, "SELECT id FROM roles WHERE name = 'admin' LIMIT 1").Scan(&adminRoleID)
	if err != nil {
		// Create admin role if it doesn't exist
		err = TestDB.QueryRowContext(ctx, `
			INSERT INTO roles (name, description)
			VALUES ('admin', 'Administrator')
			RETURNING id
		`).Scan(&adminRoleID)
		require.NoError(t, err)
	}

	// Assign admin role to user
	_, err = TestDB.ExecContext(ctx, `
		INSERT INTO user_roles (user_id, role_id)
		VALUES ($1, $2)
		ON CONFLICT (user_id, role_id) DO NOTHING
	`, userID, adminRoleID)
	require.NoError(t, err)
}
