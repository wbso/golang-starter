# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A production-ready Golang starter project implementing **Vertical Slice Architecture** with User Management and RBAC (Role-Based Access Control). Module: `github.com/wbso/golang-starter`

**Status**: 100% Complete - All features implemented and tested.

## Progress Tracking

Use `PROGRESS.md` for tracking implementation progress.

## Development Commands

```bash
# Run the server
make run

# Fix imports
make fix-imports #run this command to fix imports

# Database migrations
make migrate-up                  # Run all pending migrations
make migrate-down               # Rollback last migration
make migrate-create NAME=name   # Create new migration

# Generate sqlc code from query files
make sqlc-generate

# Testing
make test                       # Run all tests
make test-unit                  # Run unit tests only
make test-integration           # Run integration tests only

# Docker services (PostgreSQL + Mailhog)
make docker-up                  # Start services
make docker-down                # Stop services
make docker-logs                # View logs

# Build & Lint
make build                      # Build the application
make lint                       # Run golangci-lint
make fmt                        # Format code with goimports

# Development tools
make install-tools              # Install sqlc, goose, swag
make deps                       # Download and tidy dependencies

# Swagger documentation
make swagger-generate           # Generate Swagger docs from annotations
```

## Architecture

### Vertical Slice Structure

The codebase follows **Vertical Slice Architecture** where features are organized by capability rather than layer:

```
internal/
├── domain/                 # Shared domain models (DTOs, request/response types)
│   ├── user/
│   ├── role/
│   ├── permission/
│   └── auth/
├── feature/                # Vertical slices - complete features end-to-end
│   ├── auth/
│   │   ├── handler/       # HTTP layer (Echo handlers)
│   │   ├── service/       # Business logic layer
│   │   └── repository/    # Data access layer (wraps sqlc)
│   ├── user/
│   │   ├── handler/       # User CRUD, profile, password change
│   │   ├── service/       # User business logic
│   │   └── repository/    # User data access
│   ├── role/
│   │   ├── handler/       # Role CRUD, permission assignment
│   │   ├── service/       # Role business logic + PermissionChecker
│   │   └── repository/    # Role data access
│   └── permission/
│       ├── handler/       # Permission CRUD
│       ├── service/       # Permission business logic
│       └── repository/    # Permission data access
├── middleware/             # Echo middleware (auth, logging, rate limiting, authorization)
│   ├── auth.go            # JWT authentication middleware
│   ├── authorization.go   # Permission-based authorization middleware
│   └── ...                # Other middleware (logger, cors, rate limiting)
├── pkg/                    # Internal utilities
│   ├── email/             # SMTP email service with HTML templates
│   ├── jwt/               # JWT token management (access + refresh)
│   ├── validator/         # Fluent validation builder
│   ├── errors/            # AppError with RFC 7807 Problem Details
│   ├── logger/            # Structured slog wrapper
│   └── seed/              # Database seeding (admin user creation)
├── infrastructure/
│   └── database/          # Connection pooling, health check (sqlx)
└── config/                # Environment-based configuration

tests/
└── integration/           # Integration tests (auth, user flows)
    ├── setup.go           # Test environment setup
    ├── auth_test.go       # Authentication flow tests
    ├── user_test.go       # User management tests
    └── helpers.go         # Test utilities
```

### Key Patterns

**sqlc Organization**: Queries are organized per-feature in `queries/` (e.g., `user.sql`, `auth.sql`, `role.sql`, `permission.sql`). Each generates code into `db/`. Add new queries to the appropriate feature's `.sql` file, then run `make sqlc-generate`.

**Repository Layer**: Repositories in `feature/*/repository/` wrap sqlc-generated code. They handle `sql.NullString` to `string` conversions and provide business-specific query methods (e.g., `GetByEmailOrUsername`).

**Domain Models**: `internal/domain/` contains request/response DTOs and domain types used by handlers and services. These are shared across the application.

**Error Handling**: Use `internal/pkg/errors` for typed errors following RFC 7807 Problem Details. Errors have HTTP status codes and support field-level validation errors.

**Validation**: `internal/pkg/validator` provides a fluent validation builder used in handlers before calling services. Supports: Required, MinLength, MaxLength, Email, Password, Username, Match, Custom.

**Authentication Flow**: JWT with access tokens (15min) + refresh tokens (7 days, stored in DB). Logout blacklists access tokens via `jwt_blacklist` table. Passwords use bcrypt. Account lockout after 5 failed attempts (30 min).

**Authorization**: Permission-based middleware checks user permissions before allowing access. Uses `PermissionChecker` interface with in-memory caching. Supports:

- `RequirePermission()` - single permission check
- `RequireAnyPermission()` - needs at least one of multiple permissions
- `RequireAllPermissions()` - needs all specified permissions
- `RequireRole()` - role-based check

**Middleware Chain**: RequestID → Logger → PanicRecovery → CORS → Gzip → RateLimiter → JWTAuth (optional) → PermissionCheck (optional). Context keys: `request_id`, `user_id`.

**Database**: Uses `sqlx` (not pgx) with PostgreSQL. Connection pooling, health checks, transaction support.

## Go Code Style Guide

Follow these idiomatic Go conventions throughout the codebase:

### Naming Conventions

- **Packages**: Use short, lowercase, single-word names (e.g., `user`, `auth`, `jwt`). Avoid underscores or mixedCaps.
- **Interfaces**: Name with `-er` suffix for single-method interfaces (e.g., `Reader`, `Writer`, `PermissionChecker`).
- **Variables**: Use camelCase for local variables, PascalCase for exported identifiers.
- **Acronyms**: Keep consistent case (e.g., `userID`, `HTTPServer`, `URLPath`).
- **Receivers**: Use short, consistent names (1-2 chars), typically first letter of type (e.g., `u *User`, `s *Service`).

### Error Handling

- **Always check return values**: Never ignore errors. Use `_` explicitly if intentionally discarding.
- **Avoid inline error handling**: Don't handle errors inline in complex expressions.

  ```go
  // ✅ Good - clear separation
  user, err := s.repo.GetByID(ctx, id)
  if err != nil {
      return nil, err
  }
  return user, nil
  ```

- **Wrap errors with context**: Use `fmt.Errorf` with `%w` to wrap errors with additional context.
- **Return early**: Use guard clauses to reduce nesting.

### Logging

- **Prefer `slog` for structured logging** over `fmt.Println`:

  ```go
  // ✅ Good - structured logging
  slog.Info("User created", slog.String("user_id", userID), slog.String("email", email))
  ```

- Use appropriate log levels: `Debug`, `Info`, `Warn`, `Error`.

### Pointers

- **Avoid returning pointers except for shared resources**:

  - Return pointers for large structs to avoid copying.
  - Return pointers when the function needs to modify the receiver.
  - Return pointers for shared resources (e.g., database connections, caches).
  - Return values for small structs and primitives.

- **Receiver types**: Use pointer receivers for methods that modify the receiver or for large structs. Use value receivers for small, immutable types.

### Variables

- **Avoid shadowing variables**: Don't redeclare variables in inner scopes.
- **Use short variable names** in limited scopes, descriptive names in wider scopes.
- **Declare variables close to usage**: Minimize the distance between declaration and use.

### Types

- **Always use `any` instead of `interface{}`**: Modern Go prefers the `any` type alias.
- **Prefer composition over inheritance**: Use embedded structs and interfaces.
- **Make zero values useful**: Design structs so their zero value is valid and usable.

### Functions

- **Keep functions small and focused**: Each function should do one thing well.
- **Limit function parameters**: Use structs for functions with many parameters.
- **Return errors as the last return value**: Follow the convention `(result, error)`.
- **Accept interfaces, return structs**: Makes code more testable and flexible.

### Concurrency

- **Use contexts for cancellation**: Pass `context.Context` as the first parameter.
- **Don't leak goroutines**: Ensure all goroutines have a way to exit.
- **Use channels for communication**: Prefer channels over shared memory with locks.
- **Protect shared state**: Use `sync.Mutex` or `sync.RWMutex` for shared data.

### Testing

- **Table-driven tests**: Use subtests with `t.Run()` for multiple test cases.
- **Test file naming**: Use `_test.go` suffix (e.g., `user_test.go`).
- **Test function naming**: Use `TestFunctionName` format.
- **Use testify/assert**: For readable assertions (already in use).
- **Mock interfaces**: Use interfaces for dependencies to enable mocking.

### Code Organization

- **Group related declarations**: Group imports, constants, variables, and types logically.
- **Order of declarations**: Constants → Variables → Types → Functions.

### Comments

- **Document exported identifiers**: All exported functions, types, and constants should have doc comments.
- **Start with the identifier name**: `// GetUser retrieves a user by ID` (not `// This function gets a user`).
- **Explain why, not what**: Code should be self-explanatory; comments explain rationale.
- **TODO comments**: Use `// TODO: description` for future improvements.

### Performance

- **Preallocate slices**: Use `make([]T, 0, capacity)` when size is known.
- **Use string builders**: Use `strings.Builder` for string concatenation in loops.
- **Avoid unnecessary allocations**: Reuse buffers and objects where appropriate.
- **Profile before optimizing**: Use `pprof` to identify actual bottlenecks.

## Environment Setup

Copy `.env.example` to `.env` and configure:

- Database connection (PostgreSQL 18)
- JWT secret (must be 32+ chars)
- SMTP settings (Mailhog for dev: localhost:1025)
- Rate limiting defaults: 60 req/min, burst 10
- Bcrypt cost: 10, Max login attempts: 5, Lockout: 30min

**First Run**: The server automatically seeds the database on startup:

- Creates 18 default permissions
- Creates 3 default roles (admin, user, moderator)
- Creates admin user with auto-generated password (printed to console)

## Database

**Migrations**: Use Goose. Files in `migrations/` numbered sequentially (`00001_*.sql`).

**Key Tables**:

- `users`: Soft delete via `deleted_at`, account lockout via `locked_until`, email verification via `is_email_verified`
- `roles`, `permissions`: Core RBAC tables
- `user_roles`: Junction table for user-role assignments
- `role_permissions`: Junction table for role-permission assignments
- `refresh_tokens`: Hashed tokens with revocation support
- `jwt_blacklist`: Token revocation for logout
- `email_verification_tokens`: Email verification tokens
- `password_reset_tokens`: Password reset tokens

**Audit Fields**: Most tables have `created_by`/`updated_by` (UUID FK to users) for audit trails.

## API Conventions

Base path: `/api/v1/`

**Response Format** (RFC 7807 Problem Details):

```json
{
  "type": "about:blank",
  "title": "Success",
  "status": 200,
  "data": { ... }
}
```

**Error Response**:

```json
{
  "type": "about:blank",
  "title": "Validation Error",
  "status": 400,
  "detail": "One or more fields failed validation",
  "invalid_fields": {
    "email": ["Email is required"]
  }
}
```

**Pagination**: `page`, `limit` (max 100), `sort` (field:dir), `filter` (key:value). Response includes `pagination` meta with `total`, `totalPages`.

**Authentication**: Public endpoints: `/auth/register`, `/auth/login`, `/auth/refresh`, `/auth/verify-email`, `/auth/forgot-password`, `/auth/reset-password`. Protected endpoints require `Authorization: Bearer <token>`.

**Swagger**: Protected at `/api/v1/swagger/*` (requires auth). Generate with `make swagger-generate` after adding/updating Swagger annotations.

## Implemented Features

### Authentication (`internal/feature/auth/`)

- ✅ Register with email verification
- ✅ Login (email or username)
- ✅ Logout with token blacklist
- ✅ Token refresh
- ✅ Email verification
- ✅ Forgot password / Reset password
- ✅ Account lockout (5 failed attempts, 30 min)

### User Management (`internal/feature/user/`)

- ✅ List users (paginated, filtered, sorted)
- ✅ Create user
- ✅ Get user by ID
- ✅ Update user
- ✅ Delete user (soft delete)
- ✅ Disable/Enable user
- ✅ Get current user (`/me`)
- ✅ Update current user
- ✅ Change password
- ✅ Delete own account

### Role Management (`internal/feature/role/`)

- ✅ List roles
- ✅ Create role
- ✅ Get role by ID
- ✅ Update role
- ✅ Delete role (if not assigned)
- ✅ Get role permissions
- ✅ Assign permission to role
- ✅ Revoke permission from role
- ✅ Get user roles
- ✅ Assign role to user
- ✅ Revoke role from user

### Permission Management (`internal/feature/permission/`)

- ✅ List permissions
- ✅ Create permission
- ✅ Get permission by ID
- ✅ Update permission
- ✅ Delete permission

### Authorization (`internal/middleware/authorization.go`)

- ✅ PermissionChecker interface
- ✅ In-memory permission cache
- ✅ RequirePermission middleware
- ✅ RequireAnyPermission middleware
- ✅ RequireAllPermissions middleware
- ✅ RequireRole middleware

## Default Permissions & Roles

### Permissions (18 total)

- `list_users`, `create_user`, `view_user`, `update_user`, `delete_user`
- `list_roles`, `create_role`, `update_role`, `delete_role`, `view_role`
- `list_permissions`, `create_permission`, `update_permission`, `delete_permission`, `view_permission`
- `manage_roles`, `manage_permissions`, `assign_roles`

### Roles

- `admin`: Full access (all permissions)
- `user`: Basic user access
- `moderator`: Intermediate access

## Testing

**Unit Tests**: Located with packages (e.g., `internal/pkg/validator/validator_test.go`, `internal/domain/user/user_test.go`)

**Integration Tests**: Located in `tests/integration/`

- `setup.go`: Test database setup, schema creation, seeding
- `auth_test.go`: Auth flow tests (register, login, lockout, refresh)
- `user_test.go`: User management tests (CRUD, profile, permissions)
- `helpers.go`: Test utilities (user creation, token generation, role assignment)

Run integration tests: `make test-integration`

## Common Tasks

**Adding a new permission**:

1. Add to seed data in `internal/pkg/seed/seed.go`
2. Assign to appropriate role in role_permissions

**Adding a new protected endpoint**:

1. Add handler in appropriate feature
2. Register route in `cmd/server/main.go`
3. Add permission middleware: `RequirePermission(checker, cache, "permission_name")`

**Creating a database migration**:

```bash
make migrate-create NAME=add_new_table
# Edit migrations/000XX_add_new_table.sql
make migrate-up
```

**Regenerating sqlc code after query changes**:

```bash
make sqlc-generate
```

## Notes

- Use `middleware.GetUserID(c)` to extract authenticated user ID in handlers
- Use `logger.Info/Warn/Error` for structured logging with context
- Manual validation using `validator.New()` fluent builder
- Rate limiter is in-memory (consider Redis for production)
- Swagger UI is protected and requires JWT auth to access
- Admin user is auto-created on first run with random password
- Email templates in `email/templates/` (HTML format)
- All datetime fields use `time.Time` (not pointers)
- Nullable strings use `sql.NullString` converted in repositories
