package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"github.com/lmittmann/tint"

	"github.com/joho/godotenv"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	echoSwagger "github.com/swaggo/echo-swagger"

	_ "github.com/wbso/golang-starter/docs" // Swagger docs
	"github.com/wbso/golang-starter/internal/config"
	"github.com/wbso/golang-starter/internal/feature/auth/handler"
	authrepository "github.com/wbso/golang-starter/internal/feature/auth/repository"
	"github.com/wbso/golang-starter/internal/feature/auth/service"
	permissionhandler "github.com/wbso/golang-starter/internal/feature/permission/handler"
	permissionrepo "github.com/wbso/golang-starter/internal/feature/permission/repository"
	permissionservice "github.com/wbso/golang-starter/internal/feature/permission/service"
	rolehandler "github.com/wbso/golang-starter/internal/feature/role/handler"
	rolerepo "github.com/wbso/golang-starter/internal/feature/role/repository"
	roleservice "github.com/wbso/golang-starter/internal/feature/role/service"
	userhandler "github.com/wbso/golang-starter/internal/feature/user/handler"
	userrepo "github.com/wbso/golang-starter/internal/feature/user/repository"
	userservice "github.com/wbso/golang-starter/internal/feature/user/service"
	"github.com/wbso/golang-starter/internal/infrastructure/database"
	appmiddleware "github.com/wbso/golang-starter/internal/middleware"
	"github.com/wbso/golang-starter/internal/pkg/apperrors"
	"github.com/wbso/golang-starter/internal/pkg/email"
	"github.com/wbso/golang-starter/internal/pkg/jwt"
	"github.com/wbso/golang-starter/internal/pkg/seed"
)

// @title           Golang Starter API
// @version         1.0
// @description     A Golang starter project with Vertical Slice Architecture
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.email  support@example.com

// @license.name  MIT
// @license.url  https://opensource.org/licenses/MIT

// @host      localhost:8080
// @BasePath  /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

func main() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize logger
	initLogger(cfg.Server.Env == "production")

	// Connect to database
	db, err := database.New(
		cfg.Database.DSN(),
		cfg.Database.MaxConnections,
		cfg.Database.MaxIdleConnections,
		cfg.Database.ConnectionMaxLifetime,
	)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Warning: failed to close database: %v", err)
		}
	}()

	slog.Info("Database connected successfully")

	// Run database seeding
	slog.Info("Running database seeding...")
	seeder := seed.New(db.DB, &seed.Config{
		GeneratePassword:    true,
		RequireVerification: false,
	})
	if err := seeder.SeedAll(context.Background()); err != nil {
		slog.Warn("Failed to run database seeding", "error", err)
		// Don't fail on seeding errors, just log and continue
	}

	// Initialize dependencies
	jwtMgr := jwt.New(cfg.JWT.Secret, cfg.JWT.AccessExpiry, cfg.JWT.RefreshExpiry)
	emailSvc := email.New(cfg.Email)

	// Initialize repositories
	userRepo := userrepo.New(db.DB)
	authRepo := authrepository.New(db.DB)
	roleRepo := rolerepo.New(db.DB)
	permissionRepo := permissionrepo.New(db.DB)

	// Initialize services
	authSvc := service.New(userRepo, authRepo, jwtMgr, emailSvc, cfg.JWT.Secret)
	userSvc := userservice.New(userRepo)
	roleSvc := roleservice.New(roleRepo)
	permissionSvc := permissionservice.New(permissionRepo)

	// Initialize permission checker and cache
	permissionChecker := roleservice.NewPermissionChecker(roleRepo)
	permissionCache := appmiddleware.NewPermissionCache()

	// Initialize handlers
	authHandler := handler.New(authSvc)
	userHandler := userhandler.New(userSvc)
	roleHandler := rolehandler.New(roleSvc)
	permissionHandler := permissionhandler.New(permissionSvc)

	// Create Echo instance
	e := echo.New()

	// Middleware
	e.Use(appmiddleware.RequestID())
	e.Use(appmiddleware.Logger())
	e.Use(middleware.Recover())

	e.HTTPErrorHandler = apperrors.CustomHTTPErrorHandler

	// Rate limiting
	e.Use(appmiddleware.NewRateLimiter(cfg.RateLimit.RequestsPerMinute, cfg.RateLimit.Burst))

	// Health check
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"status": "healthy",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	e.GET("/health/db", func(c echo.Context) error {
		ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
		defer cancel()

		if err := db.HealthCheck(ctx); err != nil {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{
				"status": "unhealthy",
				"error":  err.Error(),
			})
		}

		return c.JSON(http.StatusOK, map[string]string{
			"status": "healthy",
		})
	})

	// API v1 routes
	v1 := e.Group("/api/v1")

	// Auth routes (public)
	authGroup := v1.Group("/auth")
	{
		authGroup.POST("/register", authHandler.Register)
		authGroup.POST("/login", authHandler.Login)
		authGroup.POST("/logout", authHandler.Logout, appmiddleware.JWTAuth(jwtMgr))
		authGroup.POST("/refresh", authHandler.RefreshToken)
		authGroup.POST("/verify-email", authHandler.VerifyEmail)
		authGroup.POST("/resend-verification", func(c echo.Context) error {
			// TODO: Implement resend verification
			return c.JSON(http.StatusNotImplemented, map[string]string{"message": "Not implemented"})
		})
		authGroup.POST("/forgot-password", authHandler.ForgotPassword)
		authGroup.POST("/reset-password", authHandler.ResetPassword)
	}

	// User routes (protected)
	usersGroup := v1.Group("/users")
	usersGroup.Use(appmiddleware.JWTAuth(jwtMgr))
	{
		// Routes that require specific permissions
		usersGroup.GET("", userHandler.List, appmiddleware.RequirePermission(permissionChecker, permissionCache, "list_users"))
		usersGroup.POST("", userHandler.Create, appmiddleware.RequirePermission(permissionChecker, permissionCache, "create_user"))
		usersGroup.GET("/:id", userHandler.GetByID, appmiddleware.RequirePermission(permissionChecker, permissionCache, "view_user"))
		usersGroup.PUT("/:id", userHandler.Update, appmiddleware.RequirePermission(permissionChecker, permissionCache, "update_user"))
		usersGroup.POST("/:id/disable", userHandler.Disable, appmiddleware.RequirePermission(permissionChecker, permissionCache, "disable_user"))
		usersGroup.POST("/:id/enable", userHandler.Enable, appmiddleware.RequirePermission(permissionChecker, permissionCache, "restore_user"))
		usersGroup.DELETE("/:id", userHandler.Delete, appmiddleware.RequirePermission(permissionChecker, permissionCache, "delete_user"))
		usersGroup.GET("/:id/roles", roleHandler.GetUserRoles, appmiddleware.RequirePermission(permissionChecker, permissionCache, "view_user"))
		usersGroup.POST("/:id/roles", roleHandler.AssignRole, appmiddleware.RequirePermission(permissionChecker, permissionCache, "assign_role"))
		usersGroup.DELETE("/:id/roles/:roleId", roleHandler.RevokeRole, appmiddleware.RequirePermission(permissionChecker, permissionCache, "revoke_role"))

		// Routes accessible to authenticated users for their own account
		usersGroup.GET("/me", userHandler.GetMe)
		usersGroup.PUT("/me", userHandler.UpdateMe)
		usersGroup.POST("/me/change-password", userHandler.ChangePassword)
		usersGroup.DELETE("/me", userHandler.DeleteMe)
	}

	// Role routes (protected)
	rolesGroup := v1.Group("/roles")
	rolesGroup.Use(appmiddleware.JWTAuth(jwtMgr))
	{
		rolesGroup.GET("", roleHandler.List, appmiddleware.RequirePermission(permissionChecker, permissionCache, "list_roles"))
		rolesGroup.POST("", roleHandler.Create, appmiddleware.RequirePermission(permissionChecker, permissionCache, "create_role"))
		rolesGroup.GET("/:id", roleHandler.GetByID, appmiddleware.RequirePermission(permissionChecker, permissionCache, "view_role"))
		rolesGroup.PUT("/:id", roleHandler.Update, appmiddleware.RequirePermission(permissionChecker, permissionCache, "update_role"))
		rolesGroup.DELETE("/:id", roleHandler.Delete, appmiddleware.RequirePermission(permissionChecker, permissionCache, "delete_role"))
		rolesGroup.GET("/:id/permissions", roleHandler.GetPermissions, appmiddleware.RequirePermission(permissionChecker, permissionCache, "view_role"))
		rolesGroup.POST("/:id/permissions", roleHandler.AssignPermission, appmiddleware.RequirePermission(permissionChecker, permissionCache, "assign_role"))
		rolesGroup.DELETE("/:id/permissions/:permissionId", roleHandler.RevokePermission, appmiddleware.RequirePermission(permissionChecker, permissionCache, "assign_role"))
	}

	// Permission routes (protected)
	permissionsGroup := v1.Group("/permissions")
	permissionsGroup.Use(appmiddleware.JWTAuth(jwtMgr))
	{
		permissionsGroup.GET("", permissionHandler.List, appmiddleware.RequirePermission(permissionChecker, permissionCache, "list_permissions"))
		permissionsGroup.POST("", permissionHandler.Create, appmiddleware.RequirePermission(permissionChecker, permissionCache, "create_permission"))
		permissionsGroup.GET("/:id", permissionHandler.GetByID, appmiddleware.RequirePermission(permissionChecker, permissionCache, "view_permission"))
		permissionsGroup.PUT("/:id", permissionHandler.Update, appmiddleware.RequirePermission(permissionChecker, permissionCache, "update_permission"))
		permissionsGroup.DELETE("/:id", permissionHandler.Delete, appmiddleware.RequirePermission(permissionChecker, permissionCache, "delete_permission"))
	}

	// Swagger documentation (protected)
	swaggerGroup := v1.Group("/swagger")
	// swaggerGroup.Use(appmiddleware.JWTAuth(jwtMgr))

	swaggerGroup.GET("*", echoSwagger.WrapHandler)

	// Start server
	go func() {
		slog.Info("Starting server", "address", cfg.Server.Address())
		if err := e.Start(cfg.Server.Address()); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	slog.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := e.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	slog.Info("Server exited")
}

func initLogger(isProduction bool) {
	var handler slog.Handler

	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}

	switch isProduction {
	case true:
		handler = slog.NewJSONHandler(os.Stderr, opts)
	default:
		handler = tint.NewHandler(os.Stderr, &tint.Options{
			Level:      slog.LevelDebug,
			TimeFormat: time.Kitchen,
			AddSource:  true,
		})
	}

	slog.SetDefault(slog.New(handler))
}
