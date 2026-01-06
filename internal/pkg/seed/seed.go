package seed

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const (
	defaultAdminUsername = "admin"
	defaultAdminEmail    = "admin@example.com"
)

// Seeder handles database seeding operations
type Seeder struct {
	db     *sqlx.DB
	config *Config
}

// Config holds seeder configuration
type Config struct {
	AdminUsername       string
	AdminEmail          string
	AdminPassword       string
	GeneratePassword    bool
	RequireVerification bool
}

// New creates a new seeder
func New(db *sqlx.DB, config *Config) *Seeder {
	if config == nil {
		config = &Config{}
	}
	if config.AdminUsername == "" {
		config.AdminUsername = defaultAdminUsername
	}
	if config.AdminEmail == "" {
		config.AdminEmail = defaultAdminEmail
	}

	return &Seeder{
		db:     db,
		config: config,
	}
}

// SeedAdmin creates the initial admin user if it doesn't exist
func (s *Seeder) SeedAdmin(ctx context.Context) error {
	// Check if admin user already exists
	var exists bool
	err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM users
			WHERE username = $1 OR email = $2
		)
	`, s.config.AdminUsername, s.config.AdminEmail).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check admin user: %w", err)
	}

	if exists {
		return nil // Admin already exists, skip
	}

	// Generate password if needed
	password := s.config.AdminPassword
	if s.config.GeneratePassword || password == "" {
		generated, err := generateRandomPassword(16)
		if err != nil {
			return fmt.Errorf("failed to generate password: %w", err)
		}
		password = generated
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Create admin user
	var adminID uuid.UUID
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO users (username, email, password_hash, is_email_verified)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`, s.config.AdminUsername, s.config.AdminEmail, string(hashedPassword), !s.config.RequireVerification).Scan(&adminID)
	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	// Get or create admin role
	var adminRoleID uuid.UUID
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO roles (name, description, created_by, updated_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (name) DO UPDATE
		SET name = EXCLUDED.name
		RETURNING id
	`, "admin", "Administrator with full access", adminID, adminID).Scan(&adminRoleID)
	if err != nil {
		return fmt.Errorf("failed to create admin role: %w", err)
	}

	// Assign all permissions to admin role
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO role_permissions (role_id, permission_id, assigned_by)
		SELECT $1, id, $2
		FROM permissions
		ON CONFLICT (role_id, permission_id) DO NOTHING
	`, adminRoleID, adminID)
	if err != nil {
		return fmt.Errorf("failed to assign permissions to admin role: %w", err)
	}

	// Assign admin role to admin user
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO user_roles (user_id, role_id, assigned_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, role_id) DO NOTHING
	`, adminID, adminRoleID, adminID)
	if err != nil {
		return fmt.Errorf("failed to assign admin role to user: %w", err)
	}

	// Print admin credentials
	s.printAdminCredentials(s.config.AdminUsername, s.config.AdminEmail, password)

	return nil
}

// SeedPermissions creates default permissions if they don't exist
func (s *Seeder) SeedPermissions(ctx context.Context) error {
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
		{"list_roles", "List roles"},
		{"create_role", "Create role"},
		{"update_role", "Update role"},
		{"delete_role", "Delete role"},
		{"view_role", "View role details"},
		{"list_permissions", "List permissions"},
		{"create_permission", "Create permission"},
		{"update_permission", "Update permission"},
		{"delete_permission", "Delete permission"},
		{"view_permission", "View permission details"},
	}

	for _, p := range permissions {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO permissions (name, description)
			VALUES ($1, $2)
			ON CONFLICT (name) DO NOTHING
		`, p.name, p.description)
		if err != nil {
			return fmt.Errorf("failed to create permission %s: %w", p.name, err)
		}
	}

	return nil
}

// SeedRoles creates default roles if they don't exist
func (s *Seeder) SeedRoles(ctx context.Context) error {
	roles := []struct {
		name        string
		description string
	}{
		{"admin", "Administrator with full access"},
		{"user", "Regular user with limited access"},
		{"moderator", "Moderator with intermediate permissions"},
	}

	for _, r := range roles {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO roles (name, description)
			VALUES ($1, $2)
			ON CONFLICT (name) DO NOTHING
		`, r.name, r.description)
		if err != nil {
			return fmt.Errorf("failed to create role %s: %w", r.name, err)
		}
	}

	return nil
}

// SeedAll runs all seeding operations
func (s *Seeder) SeedAll(ctx context.Context) error {
	// Seed permissions first (they're needed for admin role)
	if err := s.SeedPermissions(ctx); err != nil {
		return err
	}

	// Seed roles
	if err := s.SeedRoles(ctx); err != nil {
		return err
	}

	// Seed admin user
	if err := s.SeedAdmin(ctx); err != nil {
		return err
	}

	return nil
}

// printAdminCredentials prints the admin user credentials
func (s *Seeder) printAdminCredentials(username, email, password string) {
	fmt.Printf(`
========================================
INITIAL ADMIN USER CREATED
========================================

Username:  %s
Email:     %s
Password:  %s

IMPORTANT: Please change the password after first login!

========================================
`, username, email, password)
}

// generateRandomPassword generates a random password of specified length
func generateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"

	password := make([]byte, length)
	for i := range password {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		password[i] = charset[randomIndex.Int64()]
	}

	return string(password), nil
}
