package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"github.com/wbso/golang-starter/internal/config"
	"github.com/wbso/golang-starter/internal/infrastructure/database"
	"github.com/wbso/golang-starter/internal/pkg/jwt"
)

var (
	TestDB       *database.DB
	TestServer   *echo.Echo
	TestJWTMgr   *jwt.Manager
	TestConfig   *config.Config
	CleanupFuncs []func()
)

// SetupTest initializes the test environment
func SetupTest(t *testing.T) {

	// Set test environment variables
	t.Setenv("DB_HOST", "localhost")
	t.Setenv("DB_PORT", "10012")
	t.Setenv("DB_USER", "postgres")
	t.Setenv("DB_PASSWORD", "Secretcom123")
	t.Setenv("DB_NAME", "golang_starter")
	t.Setenv("JWT_SECRET", "test-secret-key-that-is-at-least-32-chars-long")
	t.Setenv("SMTP_HOST", "localhost")
	t.Setenv("SMTP_PORT", "1025")
	t.Setenv("APP_ENV", "test")

	// Load config
	cfg, err := config.Load()
	require.NoError(t, err)
	TestConfig = cfg

	// Setup database
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := database.NewPool(ctx, cfg.Database)
	require.NoError(t, err)
	TestDB = pool

	// Run migrations
	err = runMigrations(t)
	require.NoError(t, err)

	// Seed test data
	err = seedTestData(ctx, t)
	require.NoError(t, err)

	CleanupFuncs = append(CleanupFuncs, func() {
		cleanupDatabase(t)
		_ = pool.Close()
	})

	// Setup JWT manager
	TestJWTMgr = jwt.New(cfg.JWT.Secret, 15*time.Minute, 7*24*time.Hour)

	// Setup test server
	TestServer = setupTestServer(t)
}

// TeardownTest cleans up the test environment
func TeardownTest(t *testing.T) {
	if TestServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = TestServer.Shutdown(ctx)
		cancel()
	}

	// Run cleanup functions in reverse order
	for i := len(CleanupFuncs) - 1; i >= 0; i-- {
		CleanupFuncs[i]()
	}
}

// runMigrations runs database migrations for tests
func runMigrations(t *testing.T) error {
	// For integration tests, we'll use a simpler approach:
	// Create tables directly using SQL

	schema := `
	-- Extensions
	CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

	-- Users table
	CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		username VARCHAR(50) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		full_name VARCHAR(100),
		is_disabled BOOLEAN DEFAULT FALSE,
		is_email_verified BOOLEAN DEFAULT FALSE,
		locked_until TIMESTAMPTZ,
		failed_login_attempts INT DEFAULT 0,
		last_login_at TIMESTAMPTZ,
		created_by UUID REFERENCES users(id),
		updated_by UUID REFERENCES users(id),
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW(),
		deleted_at TIMESTAMPTZ
	);

	-- Roles table
	CREATE TABLE IF NOT EXISTS roles (
		id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		name VARCHAR(50) UNIQUE NOT NULL,
		description TEXT,
		created_by UUID REFERENCES users(id),
		updated_by UUID REFERENCES users(id),
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	);

	-- Permissions table
	CREATE TABLE IF NOT EXISTS permissions (
		id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		name VARCHAR(100) UNIQUE NOT NULL,
		description TEXT,
		created_by UUID REFERENCES users(id),
		updated_by UUID REFERENCES users(id),
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	);

	-- User roles junction table
	CREATE TABLE IF NOT EXISTS user_roles (
		user_id UUID REFERENCES users(id) ON DELETE CASCADE,
		role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
		assigned_by UUID REFERENCES users(id),
		assigned_at TIMESTAMPTZ DEFAULT NOW(),
		PRIMARY KEY (user_id, role_id)
	);

	-- Role permissions junction table
	CREATE TABLE IF NOT EXISTS role_permissions (
		role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
		permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
		assigned_by UUID REFERENCES users(id),
		assigned_at TIMESTAMPTZ DEFAULT NOW(),
		PRIMARY KEY (role_id, permission_id)
	);

	-- Refresh tokens table
	CREATE TABLE IF NOT EXISTS refresh_tokens (
		id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash VARCHAR(255) UNIQUE NOT NULL,
		expires_at TIMESTAMPTZ NOT NULL,
		revoked_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	-- JWT blacklist table
	CREATE TABLE IF NOT EXISTS jwt_blacklist (
		token_id VARCHAR(255) PRIMARY KEY,
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		expires_at TIMESTAMPTZ NOT NULL,
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	-- Email verification tokens table
	CREATE TABLE IF NOT EXISTS email_verification_tokens (
		id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		token VARCHAR(255) UNIQUE NOT NULL,
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		expires_at TIMESTAMPTZ NOT NULL,
		used_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	-- Password reset tokens table
	CREATE TABLE IF NOT EXISTS password_reset_tokens (
		token VARCHAR(255) PRIMARY KEY,
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		expires_at TIMESTAMPTZ NOT NULL,
		used_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ DEFAULT NOW()
	);

	-- Indexes
	CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);
	CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
	CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
	CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
	CREATE INDEX IF NOT EXISTS idx_jwt_blacklist_expires_at ON jwt_blacklist(expires_at);
	CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_user_id ON email_verification_tokens(user_id);
	CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
	`

	_, err := TestDB.Exec(schema)
	return err
}

// cleanupDatabase drops all tables
func cleanupDatabase(t *testing.T) {
	dropSQL := `
	DROP TABLE IF EXISTS password_reset_tokens CASCADE;
	DROP TABLE IF EXISTS email_verification_tokens CASCADE;
	DROP TABLE IF EXISTS jwt_blacklist CASCADE;
	DROP TABLE IF EXISTS refresh_tokens CASCADE;
	DROP TABLE IF EXISTS role_permissions CASCADE;
	DROP TABLE IF EXISTS user_roles CASCADE;
	DROP TABLE IF EXISTS permissions CASCADE;
	DROP TABLE IF EXISTS roles CASCADE;
	DROP TABLE IF EXISTS users CASCADE;
	`

	_, err := TestDB.Exec(dropSQL)
	if err != nil {
		t.Logf("Warning: cleanup failed: %v", err)
	}
}

// seedTestData inserts initial test data
func seedTestData(ctx context.Context, t *testing.T) error {
	// Insert test permissions
	permissions := []struct {
		name        string
		description string
	}{
		{"list_users", "List all users"},
		{"create_user", "Create a new user"},
		{"view_user", "View user details"},
		{"update_user", "Update user information"},
		{"delete_user", "Delete a user"},
		{"manage_roles", "Manage roles"},
		{"manage_permissions", "Manage permissions"},
		{"assign_roles", "Assign roles to users"},
	}

	for _, p := range permissions {
		_, err := TestDB.Exec(`
			INSERT INTO permissions (name, description, created_by, updated_by)
			VALUES ($1, $2, NULL, NULL)
			ON CONFLICT (name) DO NOTHING
		`, p.name, p.description)
		if err != nil {
			return fmt.Errorf("failed to insert permission %s: %w", p.name, err)
		}
	}

	// Insert test roles
	roles := []struct {
		name        string
		description string
	}{
		{"admin", "Administrator with full access"},
		{"user", "Regular user with limited access"},
		{"moderator", "Moderator with intermediate permissions"},
	}

	for _, r := range roles {
		_, err := TestDB.Exec(`
			INSERT INTO roles (name, description, created_by, updated_by)
			VALUES ($1, $2, NULL, NULL)
			ON CONFLICT (name) DO NOTHING
		`, r.name, r.description)
		if err != nil {
			return fmt.Errorf("failed to insert role %s: %w", r.name, err)
		}
	}

	// Assign all permissions to admin role
	_, err := TestDB.Exec(`
		INSERT INTO role_permissions (role_id, permission_id, assigned_by)
		SELECT r.id, p.id, NULL
		FROM roles r, permissions p
		WHERE r.name = 'admin'
		ON CONFLICT DO NOTHING
	`)
	if err != nil {
		return fmt.Errorf("failed to assign permissions to admin role: %w", err)
	}

	return nil
}

// setupTestServer creates a test echo server
func setupTestServer(t *testing.T) *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	return e
}

// TruncateTables truncates all tables between tests
func TruncateTables(t *testing.T) {
	ctx := context.Background()

	tables := []string{
		"password_reset_tokens",
		"email_verification_tokens",
		"jwt_blacklist",
		"refresh_tokens",
		"user_roles",
		"role_permissions",
		"permissions",
		"roles",
		"users",
	}

	for _, table := range tables {
		_, err := TestDB.Exec(fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table))
		require.NoError(t, err)
	}

	// Reseed basic data
	err := seedTestData(ctx, t)
	require.NoError(t, err)
}
