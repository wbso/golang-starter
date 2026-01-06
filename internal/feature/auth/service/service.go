package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/wbso/golang-starter/internal/pkg/apperrors"
	"github.com/wbso/golang-starter/internal/pkg/validator"
	"golang.org/x/crypto/bcrypt"

	"github.com/wbso/golang-starter/db"
	"github.com/wbso/golang-starter/internal/domain/auth"
	"github.com/wbso/golang-starter/internal/feature/auth/repository"
	userrepo "github.com/wbso/golang-starter/internal/feature/user/repository"
	"github.com/wbso/golang-starter/internal/pkg/email"
	"github.com/wbso/golang-starter/internal/pkg/jwt"
)

// Service handles authentication business logic
type Service struct {
	userRepo *userrepo.Repository
	authRepo *repository.Repository
	jwtMgr   *jwt.Manager
	emailSvc *email.Service
	secret   string
}

// New creates a new auth service
func New(
	userRepo *userrepo.Repository,
	authRepo *repository.Repository,
	jwtMgr *jwt.Manager,
	emailSvc *email.Service,
	secret string,
) *Service {
	return &Service{
		userRepo: userRepo,
		authRepo: authRepo,
		jwtMgr:   jwtMgr,
		emailSvc: emailSvc,
		secret:   secret,
	}
}

// Login authenticates a user and returns tokens
func (s *Service) Login(ctx context.Context, req auth.LoginRequest) (*auth.AuthResponse, error) {
	// Get user by email or username
	user, err := s.userRepo.GetByEmailOrUsername(ctx, req.Username)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Check if user can login
	if isDisabled(user) {
		return nil, errors.New("account is disabled")
	}
	if isLocked(user) {
		return nil, errors.New("account locked")
	}
	if !isEmailVerified(user) {
		return nil, errors.New("email is not verified")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		// Increment failed login attempts
		_ = s.userRepo.IncrementFailedLoginAttempts(ctx, user.ID)

		// Check if we should lock the account
		failedAttempts := int(user.FailedLoginAttempts.Int32)
		if failedAttempts+1 >= 5 {
			lockUntil := time.Now().Add(30 * time.Minute)
			_ = s.userRepo.LockUser(ctx, user.ID, lockUntil)
			return nil, errors.New("account locked due to too many failed attempts")
		}

		return nil, errors.New("invalid credentials")
	}

	// Update last login
	_ = s.userRepo.UpdateLastLogin(ctx, user.ID)

	// Generate tokens
	tokens, err := s.jwtMgr.GenerateTokenPair(user.ID, user.Email)
	if err != nil {
		return nil, err
	}

	// Store refresh token
	if err := s.authRepo.CreateRefreshToken(ctx, user.ID, tokens.RefreshTokenID, tokens.RefreshExpiresAt); err != nil {
		return nil, err
	}

	fullName := nullStringToString(user.FullName)

	return &auth.AuthResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    tokens.ExpiresAt,
		User: auth.UserInfo{
			ID:       user.ID,
			Username: user.Username,
			Email:    user.Email,
			FullName: fullName,
		},
	}, nil
}

// Register creates a new user
func (s *Service) Register(ctx context.Context, req auth.RegisterRequest) (*auth.AuthResponse, error) {
	// Validate
	v := validator.New()
	v.Required("username", req.Username).
		MinLength("username", req.Username, 3).
		Username("username", req.Username).
		Required("email", req.Email).
		Email("email", req.Email).
		Required("password", req.Password).
		Password("password", req.Password).
		MinLength("password", req.Password, 8)

	if v.HasErrors() {
		return nil, apperrors.NewErrValidation().WithFieldErrors(v.Errors())
	}
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// find existing user by email, return error if found
	existingUser, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("failed to find existing user: %w", err)
	}

	if existingUser != nil {
		return nil, apperrors.NewErrConflict().WithError(err).WithDetail("email already exists")
	}

	// find existing user by username
	existingUser, err = s.userRepo.GetByUsername(ctx, req.Username)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("failed to find existing user: %w", err)
	}

	if existingUser != nil {
		return nil, apperrors.NewErrConflict().WithError(err).WithDetail("username already exists")

	}

	// Create user
	user, err := s.userRepo.Create(ctx, userrepo.CreateUserParams{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		FullName:     req.FullName,
	})
	if err != nil {
		if db.IsUniqueViolation(err) {
			return nil, apperrors.NewErrConflict().WithError(err)
		}

		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Generate email verification token
	token, err := repository.GenerateVerificationToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Store verification token
	expiresAt := time.Now().Add(24 * time.Hour)
	if err := s.authRepo.CreateEmailVerificationToken(ctx, user.ID, token, expiresAt); err != nil {
		return nil, fmt.Errorf("failed to store verification token: %w", err)
	}

	// Send verification email
	verificationURL := s.buildVerificationURL(token)
	name := nullStringToString(user.FullName)
	if name == "" {
		name = user.Username
	}
	if err := s.emailSvc.SendEmailVerification(user.Email, name, verificationURL); err != nil {
		// Log error but don't fail registration
		// TODO: In production, this should be properly logged
		_ = err // Explicitly ignore to satisfy linter
	}

	// Assign default role
	// TODO: Assign default user role

	fullName := nullStringToString(user.FullName)

	return &auth.AuthResponse{
		AccessToken:  "", // No access token until email is verified
		RefreshToken: "",
		ExpiresAt:    time.Time{},
		User: auth.UserInfo{
			ID:       user.ID,
			Username: user.Username,
			Email:    user.Email,
			FullName: fullName,
		},
	}, nil
}

// RefreshToken refreshes an access token using a refresh token
func (s *Service) RefreshToken(ctx context.Context, req auth.RefreshTokenRequest) (*auth.TokenPair, error) {
	// Validate
	v := validator.New()
	v.Required("refresh_token", req.RefreshToken)

	if v.HasErrors() {
		return nil, apperrors.NewErrValidation().WithFieldErrors(v.Errors())
	}

	// Validate refresh token
	claims, err := s.jwtMgr.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, apperrors.NewErrInvalidToken()
	}

	// Check if refresh token exists in database
	refreshToken, err := s.authRepo.GetRefreshToken(ctx, claims.ID)
	if err != nil {
		return nil, errors.New("refresh token not found")
	}

	// Check if token is revoked
	if refreshToken.RevokedAt.Valid {
		return nil, errors.New("refresh token has been revoked")
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Generate new tokens
	tokens, err := s.jwtMgr.GenerateTokenPair(user.ID, user.Email)
	if err != nil {
		return nil, err
	}

	// Store new refresh token
	if err := s.authRepo.CreateRefreshToken(ctx, user.ID, tokens.RefreshTokenID, tokens.RefreshExpiresAt); err != nil {
		return nil, err
	}

	// Revoke old refresh token
	_ = s.authRepo.RevokeRefreshToken(ctx, refreshToken.ID.String())

	return &auth.TokenPair{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    tokens.ExpiresAt,
	}, nil
}

// Logout logs out a user by revoking tokens
func (s *Service) Logout(ctx context.Context, userID uuid.UUID, accessToken string) error {
	// Get token ID
	tokenID, err := s.jwtMgr.GetTokenID(accessToken)
	if err != nil {
		return err
	}

	// Get expiration
	expiresAt, err := s.jwtMgr.GetExpiration(accessToken)
	if err != nil {
		return err
	}

	// Blacklist access token
	if err := s.authRepo.BlacklistToken(ctx, tokenID, userID, expiresAt); err != nil {
		return err
	}

	// Revoke all refresh tokens
	return s.authRepo.RevokeAllUserRefreshTokens(ctx, userID)
}

// VerifyEmail verifies a user's email
func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	// Get token
	emailToken, err := s.authRepo.GetEmailVerificationToken(ctx, token)
	if err != nil {
		return errors.New("invalid or expired token")
	}

	// Mark token as used
	if err := s.authRepo.MarkEmailVerificationTokenUsed(ctx, token); err != nil {
		return err
	}

	// Verify user email
	return s.userRepo.VerifyEmail(ctx, emailToken.UserID)
}

// ForgotPassword initiates a password reset
func (s *Service) ForgotPassword(ctx context.Context, req auth.ForgotPasswordRequest) error {
	// Get user
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		// Don't reveal if user exists - return successfully to prevent enumeration
		//nolint:nilerr // intentional - we don't want to reveal if user exists
		return nil
	}

	// Generate reset token
	token, err := repository.GenerateResetToken()
	if err != nil {
		return err
	}

	// Store reset token
	expiresAt := time.Now().Add(1 * time.Hour)
	if err := s.authRepo.CreatePasswordResetToken(ctx, user.ID, token, expiresAt); err != nil {
		return err
	}

	// Send reset email
	resetURL := s.buildResetURL(token)
	name := nullStringToString(user.FullName)
	if name == "" {
		name = user.Username
	}
	if err := s.emailSvc.SendPasswordReset(user.Email, name, resetURL); err != nil {
		// Log error but don't fail
		// TODO: In production, this should be properly logged
		_ = err // Explicitly ignore to satisfy linter
	}

	return nil
}

// ResetPassword resets a user's password
func (s *Service) ResetPassword(ctx context.Context, req auth.ResetPasswordRequest) error {
	// Get token
	resetToken, err := s.authRepo.GetPasswordResetToken(ctx, req.Token)
	if err != nil {
		return errors.New("invalid or expired token")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Mark token as used
	if err := s.authRepo.MarkPasswordResetTokenUsed(ctx, req.Token); err != nil {
		return err
	}

	// Update password
	return s.userRepo.UpdatePassword(ctx, resetToken.UserID, string(hashedPassword))
}

// buildVerificationURL builds the email verification URL
func (s *Service) buildVerificationURL(token string) string {
	// TODO: Get base URL from config
	return "http://localhost:8080/api/v1/auth/verify-email?token=" + token
}

// buildResetURL builds the password reset URL
func (s *Service) buildResetURL(token string) string {
	// TODO: Get base URL from config
	return "http://localhost:8080/api/v1/auth/reset-password?token=" + token
}

// Helper functions for sql.NullString types
func nullStringToString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

func stringToNullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: s, Valid: true}
}

func isDisabled(user *userrepo.User) bool {
	return user.IsDisabled.Valid && user.IsDisabled.Bool
}

func isLocked(user *userrepo.User) bool {
	return user.LockedUntil.Valid && user.LockedUntil.Time.After(time.Now())
}

func isEmailVerified(user *userrepo.User) bool {
	return user.IsEmailVerified.Valid && user.IsEmailVerified.Bool
}
