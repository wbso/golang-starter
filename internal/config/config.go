package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the application
type Config struct {
	Server    ServerConfig
	Database  DatabaseConfig
	JWT       JWTConfig
	Email     EmailConfig
	RateLimit RateLimitConfig
	Security  SecurityConfig
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Host string
	Port string
	Env  string
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Host                  string
	Port                  string
	User                  string
	Password              string
	Name                  string
	MaxConnections        int
	MaxIdleConnections    int
	ConnectionMaxLifetime time.Duration
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret        string
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
	RS256         JWTRs256Config
}

// JWTRs256Config holds RS256 JWT verification configuration for external Auth Server
type JWTRs256Config struct {
	Enabled            bool
	JWKSURL            string
	Issuer             string
	Audience           string
	KeyRefreshInterval time.Duration
}

// EmailConfig holds email configuration
type EmailConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	From     string
	FromName string
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	RequestsPerMinute float64
	Burst             int
}

// SecurityConfig holds security configuration
type SecurityConfig struct {
	BcryptCost       int
	MaxLoginAttempts int
	LockoutDuration  time.Duration
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Host: getEnv("SERVER_HOST", "0.0.0.0"),
			Port: getEnv("SERVER_PORT", "8080"),
			Env:  getEnv("APP_ENV", "development"),
		},
		Database: DatabaseConfig{
			Host:                  getEnv("DB_HOST", ""),
			Port:                  getEnv("DB_PORT", ""),
			User:                  getEnv("DB_USER", ""),
			Password:              getEnv("DB_PASSWORD", ""),
			Name:                  getEnv("DB_NAME", ""),
			MaxConnections:        getEnvAsInt("DB_MAX_CONNECTIONS", 25),
			MaxIdleConnections:    getEnvAsInt("DB_MAX_IDLE_CONNECTIONS", 5),
			ConnectionMaxLifetime: getEnvAsDuration("DB_CONNECTION_MAX_LIFETIME", 5) * time.Minute,
		},
		JWT: JWTConfig{
			Secret:        getEnv("JWT_SECRET", ""),
			AccessExpiry:  getEnvAsDuration("JWT_ACCESS_EXPIRY", 15) * time.Minute,
			RefreshExpiry: getEnvAsDuration("JWT_REFRESH_EXPIRY", 168) * time.Hour,
			RS256: JWTRs256Config{
				Enabled:            getEnvAsBool("JWT_RS256_ENABLED", false),
				JWKSURL:            getEnv("JWT_RS256_JWKS_URL", ""),
				Issuer:             getEnv("JWT_RS256_ISSUER", ""),
				Audience:           getEnv("JWT_RS256_AUDIENCE", ""),
				KeyRefreshInterval: getEnvAsDuration("JWT_RS256_KEY_REFRESH", 60) * time.Minute,
			},
		},
		Email: EmailConfig{
			Host:     getEnv("SMTP_HOST", ""),
			Port:     getEnv("SMTP_PORT", ""),
			User:     getEnv("SMTP_USER", ""),
			Password: getEnv("SMTP_PASSWORD", ""),
			From:     getEnv("SMTP_FROM", "noreply@example.com"),
			FromName: getEnv("SMTP_FROM_NAME", "Golang Starter"),
		},
		RateLimit: RateLimitConfig{
			RequestsPerMinute: float64(getEnvAsInt("RATE_LIMIT_REQUESTS", 60)),
			Burst:             getEnvAsInt("RATE_LIMIT_BURST", 10),
		},
		Security: SecurityConfig{
			BcryptCost:       getEnvAsInt("BCRYPT_COST", 10),
			MaxLoginAttempts: getEnvAsInt("MAX_LOGIN_ATTEMPTS", 5),
			LockoutDuration:  getEnvAsDuration("LOCKOUT_DURATION", 30) * time.Minute,
		},
	}

	// Validate required fields
	if cfg.Database.Password == "" {
		return nil, fmt.Errorf("DB_PASSWORD is required")
	}
	if cfg.JWT.Secret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}

	return cfg, nil
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvAsInt gets an environment variable as an integer or returns a default value
func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// getEnvAsDuration gets an environment variable as a duration (in minutes) or returns a default value
func getEnvAsDuration(key string, defaultValue int) time.Duration {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return time.Duration(intVal)
		}
	}
	return time.Duration(defaultValue)
}

// getEnvAsBool gets an environment variable as a boolean or returns a default value
func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

// Address returns the server address
func (c *ServerConfig) Address() string {
	return fmt.Sprintf("%s:%s", c.Host, c.Port)
}

// DSN returns the database connection string
func (c *DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		c.Host, c.Port, c.User, c.Password, c.Name,
	)
}
