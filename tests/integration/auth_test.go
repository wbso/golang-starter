package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/wbso/golang-starter/internal/domain/auth"
	"github.com/wbso/golang-starter/internal/feature/auth/handler"
	"github.com/wbso/golang-starter/internal/feature/auth/repository"
	"github.com/wbso/golang-starter/internal/feature/auth/service"
	userrepo "github.com/wbso/golang-starter/internal/feature/user/repository"
	"github.com/wbso/golang-starter/internal/pkg/apperrors"
	"github.com/wbso/golang-starter/internal/pkg/email"
)

func TestAuth_Register(t *testing.T) {
	SetupTest(t)
	defer TeardownTest(t)

	// Create auth handler
	authHandler := setupAuthHandler(t)

	tests := []struct {
		name           string
		request        auth.RegisterRequest
		expectedStatus int
		checkResponse  bool
	}{
		{
			name: "successful registration",
			request: auth.RegisterRequest{
				Username: "testregister",
				Email:    "testregister@example.com",
				Password: "Test12345!",
				FullName: "Test User",
			},
			expectedStatus: http.StatusCreated,
			checkResponse:  true,
		},
		{
			name: "duplicate email",
			request: auth.RegisterRequest{
				Username: "testuser2",
				Email:    "testregister@example.com", // Same as above
				Password: "Test12345!",
			},
			expectedStatus: http.StatusConflict,
			checkResponse:  false,
		},
		{
			name: "duplicate username",
			request: auth.RegisterRequest{
				Username: "testregister", // Same as first
				Email:    "test2@example.com",
				Password: "Test12345!",
			},
			expectedStatus: http.StatusConflict,
			checkResponse:  false,
		},
		{
			name: "weak password",
			request: auth.RegisterRequest{
				Username: "testuser3",
				Email:    "test3@example.com",
				Password: "weak",
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			e := echo.New()
			e.HTTPErrorHandler = apperrors.CustomHTTPErrorHandler
			e.POST("/api/v1/auth/register", authHandler.Register)
			// c := e.NewContext(req, rec)
			// authHandler.Register(e.NewContext(req, rec))

			// errHandler := authHandler.Register(c)
			e.ServeHTTP(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			if tt.checkResponse {
				var response struct {
					Data struct {
						User struct {
							ID       string `json:"id"`
							Username string `json:"username"`
							Email    string `json:"email"`
							FullName string `json:"full_name"`
						} `json:"user"`
						AccessToken  string `json:"access_token"`
						RefreshToken string `json:"refresh_token"`
						ExpiresAt    string `json:"expires_at"`
					} `json:"data"`
				}

				dataBytes := rec.Body.Bytes()

				err = json.Unmarshal(dataBytes, &response)
				require.NoError(t, err)

				data := response.Data
				assert.NotEmpty(t, data.User.ID)
				assert.Equal(t, tt.request.Username, data.User.Username)
				assert.Equal(t, tt.request.Email, data.User.Email)
			}
		})
	}
}

func TestAuth_Login(t *testing.T) {
	SetupTest(t)
	defer TeardownTest(t)

	authHandler := setupAuthHandler(t)

	// First, register a user and verify email
	registerReq := auth.RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "Test12345!",
		FullName: "Test User",
	}

	// Create user directly in DB with verified email
	ctx := context.Background()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(registerReq.Password), bcrypt.DefaultCost)
	require.NoError(t, err)

	var userID uuid.UUID
	err = TestDB.QueryRowContext(ctx, `
		INSERT INTO users (username, email, password_hash, full_name, is_email_verified)
		VALUES ($1, $2, $3, $4, TRUE)
		RETURNING id
	`, registerReq.Username, registerReq.Email, string(hashedPassword), registerReq.FullName).Scan(&userID)
	require.NoError(t, err)

	tests := []struct {
		name           string
		request        auth.LoginRequest
		expectedStatus int
		checkToken     bool
	}{
		{
			name: "successful login with email",
			request: auth.LoginRequest{
				Username: registerReq.Email,
				Password: registerReq.Password,
			},
			expectedStatus: http.StatusOK,
			checkToken:     true,
		},
		{
			name: "successful login with username",
			request: auth.LoginRequest{
				Username: registerReq.Username,
				Password: registerReq.Password,
			},
			expectedStatus: http.StatusOK,
			checkToken:     true,
		},
		{
			name: "invalid email",
			request: auth.LoginRequest{
				Username: "nonexistent@example.com",
				Password: registerReq.Password,
			},
			expectedStatus: http.StatusUnauthorized,
			checkToken:     false,
		},
		{
			name: "invalid password",
			request: auth.LoginRequest{
				Username: registerReq.Email,
				Password: "WrongPassword123!",
			},
			expectedStatus: http.StatusUnauthorized,
			checkToken:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			e := echo.New()

			_ = authHandler.Login(e.NewContext(req, rec))
			assert.Equal(t, tt.expectedStatus, rec.Code)

			if tt.checkToken {
				var response map[string]interface{}
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				require.NoError(t, err)

				data := response["data"].(map[string]interface{})
				assert.NotEmpty(t, data["access_token"])
				assert.NotEmpty(t, data["refresh_token"])
				assert.NotEmpty(t, data["expires_at"])

				user := data["user"].(map[string]interface{})
				assert.Equal(t, registerReq.Username, user["username"])
				assert.Equal(t, registerReq.Email, user["email"])
			}
		})
	}
}

func TestAuth_AccountLockout(t *testing.T) {
	SetupTest(t)
	defer TeardownTest(t)

	authHandler := setupAuthHandler(t)

	// Create a user
	ctx := context.Background()
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("Test12345!"), bcrypt.DefaultCost)

	var userID uuid.UUID
	err := TestDB.QueryRowContext(ctx, `
		INSERT INTO users (username, email, password_hash, is_email_verified)
		VALUES ($1, $2, $3, TRUE)
		RETURNING id
	`, "lockoutuser", "lockout@example.com", string(hashedPassword)).Scan(&userID)
	require.NoError(t, err)

	loginReq := auth.LoginRequest{
		Username: "lockoutuser",
		Password: "WrongPassword123!",
	}

	// Attempt 5 failed logins
	for i := 0; i < 5; i++ {
		body, _ := json.Marshal(loginReq)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		e := echo.New()

		_ = authHandler.Login(e.NewContext(req, rec))

		if i < 4 {
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
		} else {
			// 5th attempt should return account locked
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			var response map[string]interface{}
			_ = json.Unmarshal(rec.Body.Bytes(), &response)
			assert.Contains(t, response["title"], "account locked")
		}
	}

	// Even correct password should fail after lockout
	correctReq := auth.LoginRequest{
		Username: "lockoutuser",
		Password: "Test12345!",
	}
	body, _ := json.Marshal(correctReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e := echo.New()

	_ = authHandler.Login(e.NewContext(req, rec))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuth_VerifyEmail(t *testing.T) {
	SetupTest(t)
	defer TeardownTest(t)

	authHandler := setupAuthHandler(t)

	// Create user with email verification token
	ctx := context.Background()
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("Test12345!"), bcrypt.DefaultCost)

	var userID uuid.UUID
	err := TestDB.QueryRowContext(ctx, `
		INSERT INTO users (username, email, password_hash, is_email_verified)
		VALUES ($1, $2, $3, FALSE)
		RETURNING id
	`, "verifyuser", "verify@example.com", string(hashedPassword)).Scan(&userID)
	require.NoError(t, err)

	// Create verification token
	_, err = TestDB.ExecContext(ctx, `
		INSERT INTO email_verification_tokens (token, user_id, expires_at)
		VALUES ($1, $2, NOW() + INTERVAL '24 hours')
	`, "test-verification-token", userID)
	require.NoError(t, err)

	// Test verification
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/verify-email?token=test-verification-token", nil)
	rec := httptest.NewRecorder()

	c := TestServer.NewContext(req, rec)
	c.SetPath("/api/v1/auth/verify-email")
	c.QueryParams().Add("token", "test-verification-token")

	err = authHandler.VerifyEmail(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Check that email is now verified
	var isVerified bool
	err = TestDB.QueryRowContext(ctx, "SELECT is_email_verified FROM users WHERE id = $1", userID).Scan(&isVerified)
	require.NoError(t, err)
	assert.True(t, isVerified)
}

func TestAuth_RefreshToken(t *testing.T) {
	SetupTest(t)
	defer TeardownTest(t)

	authHandler := setupAuthHandler(t)

	// Create user
	ctx := context.Background()
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("Test12345!"), bcrypt.DefaultCost)

	var userID uuid.UUID
	err := TestDB.QueryRowContext(ctx, `
		INSERT INTO users (username, email, password_hash, is_email_verified)
		VALUES ($1, $2, $3, TRUE)
		RETURNING id
	`, "refreshuser", "refresh@example.com", string(hashedPassword)).Scan(&userID)
	require.NoError(t, err)

	// First login to get tokens
	loginReq := auth.LoginRequest{
		Username: "refresh@example.com",
		Password: "Test12345!",
	}
	body, _ := json.Marshal(loginReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e := echo.New()

	_ = authHandler.Login(e.NewContext(req, rec))
	require.Equal(t, http.StatusOK, rec.Code)

	var loginResp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &loginResp)
	data := loginResp["data"].(map[string]interface{})
	refreshToken := data["refresh_token"].(string)

	// Now refresh the token
	refreshReq := auth.RefreshTokenRequest{
		RefreshToken: refreshToken,
	}
	body, _ = json.Marshal(refreshReq)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()

	_ = authHandler.RefreshToken(e.NewContext(req, rec))
	assert.Equal(t, http.StatusOK, rec.Code)

	var refreshResp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &refreshResp)
	refreshData := refreshResp["data"].(map[string]interface{})
	assert.NotEmpty(t, refreshData["access_token"])
	assert.NotEmpty(t, refreshData["refresh_token"])
}

// Helper functions

func setupAuthHandler(t *testing.T) *handler.Handler {
	userRepo := userrepo.New(TestDB.DB)
	authRepo := repository.New(TestDB.DB)
	emailSvc := email.New(TestConfig.Email)

	authSvc := service.New(userRepo, authRepo, TestJWTMgr, emailSvc, TestConfig.JWT.Secret)
	return handler.New(authSvc)
}

func strPtr(s string) *string {
	return &s
}
