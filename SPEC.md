# Golang Starter Project with Vertical Slice Architecture

## Project Overview

A production-ready Golang starter project implementing **Vertical Slice Architecture** with comprehensive User Management and RBAC (Role-Based Access Control) functionality.

**Module:** `github.com/wbso/golang-starter`
**Go Version:** 1.25.5

---

## Table of Contents

1. [Technology Stack](#technology-stack)
2. [Project Structure](#project-structure)
3. [Environment Variables](#environment-variables)
4. [Database Schema](#database-schema)
5. [API Endpoints](#api-endpoints)
6. [Development](#development)
7. [Implementation Status](#implementation-status)

---

## Technology Stack

| Category | Technology | Version |
|----------|------------|---------|
| **HTTP Framework** | Echo | v4.15.0 |
| **Architecture** | Vertical Slice (Feature-based) | - |
| **Authentication** | JWT (Access + Refresh tokens) | - |
| **Database** | PostgreSQL | 18.1 |
| **Migrations** | Goose | v3.x |
| **Database Queries** | sqlc (per feature organization) | - |
| **Validation** | Manual validation | - |
| **Logging** | slog (Go 1.21+ structured logging) | - |
| **Password Hashing** | bcrypt | - |
| **API Documentation** | Swagger UI (swaggo/swag, protected) | - |
| **Email Service** | SMTP support | - |
| **Email Templates** | HTML templates | - |
| **Testing** | Unit tests + Integration tests | - |

---

## Project Structure

```
golang-starter/
├── cmd/
│   └── server/
│       └── main.go                 # Application entry point
├── internal/
│   ├── config/                     # Configuration loading
│   ├── domain/                     # Shared domain models
│   │   ├── user/
│   │   ├── role/
│   │   └── permission/
│   ├── feature/                    # Vertical slices (features)
│   │   ├── auth/                   # Authentication feature
│   │   │   ├── handler/
│   │   │   ├── service/
│   │   │   └── repository/
│   │   ├── user/                   # User management feature
│   │   │   ├── handler/
│   │   │   ├── service/
│   │   │   └── repository/
│   │   ├── role/                   # Role management feature
│   │   └── permission/             # Permission management feature
│   ├── middleware/                 # Echo middleware
│   ├── pkg/                        # Internal packages
│   │   ├── email/
│   │   ├── jwt/
│   │   ├── validator/
│   │   ├── errors/
│   │   └── logger/
│   └── infrastructure/
│       ├── database/
│       └── migrations/
├── migrations/                     # Goose migration files
│   ├── 00001_users.sql
│   ├── 00002_roles.sql
│   ├── 00003_permissions.sql
│   ├── 00004_user_roles.sql
│   ├── 00005_role_permissions.sql
│   ├── 00006_refresh_tokens.sql
│   ├── 00007_jwt_blacklist.sql
│   ├── 00008_email_verification_tokens.sql
│   ├── 00009_password_reset_tokens.sql
│   └── 00010_seed_data.sql
├── queries/                        # sqlc query files (per feature)
│   ├── user.sql
│   ├── role.sql
│   └── auth.sql
├── db/                             # sqlc generated code (per feature)
│   ├── user.sql.go
│   ├── role.sql.go
│   ├── auth.sql.go
│   ├── models.go
│   └── db.go
├── email/templates/                # HTML email templates
│   ├── email_verification.html
│   └── password_reset.html
├── compose.yml                     # Docker Compose (PostgreSQL + Mailhog)
├── Makefile                        # Common tasks
├── go.mod
├── .env.example                    # Environment variables template
└── SPEC.md                         # This specification
```

---

## Environment Variables

Create a `.env` file based on `.env.example`:

```bash
# Server Config
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
APP_ENV=development

# Database Config
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=Secretcom123
DB_NAME=golang_starter
DB_MAX_CONNECTIONS=25
DB_MAX_IDLE_CONNECTIONS=5
DB_CONNECTION_MAX_LIFETIME=5

# JWT Config
JWT_SECRET=change-this-to-a-random-secret-key-at-least-32-characters
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=168h

# Email Config
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=noreply@example.com
SMTP_FROM_NAME=Golang Starter

# Rate Limiting
RATE_LIMIT_REQUESTS=60
RATE_LIMIT_BURST=10

# Security
BCRYPT_COST=10
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=30m
```

---

## Database Schema

### Core Tables

**Users Table** (`users`)
- id (UUID, PK)
- username (VARCHAR(50), UNIQUE)
- email (VARCHAR(255), UNIQUE)
- password_hash (VARCHAR(255))
- full_name (VARCHAR(100), NULLABLE)
- is_disabled (BOOLEAN, default: FALSE)
- is_email_verified (BOOLEAN, default: FALSE)
- failed_login_attempts (INT, default: 0)
- locked_until (TIMESTAMP, NULLABLE)
- last_login_at (TIMESTAMP, NULLABLE)
- created_by (UUID, FK to users, NULLABLE)
- updated_by (UUID, FK to users, NULLABLE)
- created_at (TIMESTAMP, default: CURRENT_TIMESTAMP)
- updated_at (TIMESTAMP, default: CURRENT_TIMESTAMP)
- deleted_at (TIMESTAMP, NULLABLE) - Soft delete

**Roles Table** (`roles`)
- id (UUID, PK)
- name (VARCHAR(50), UNIQUE)
- description (TEXT, NULLABLE)
- created_by (UUID, FK to users, NULLABLE)
- updated_by (UUID, FK to users, NULLABLE)
- created_at (TIMESTAMP, default: CURRENT_TIMESTAMP)
- updated_at (TIMESTAMP, default: CURRENT_TIMESTAMP)
- deleted_at (TIMESTAMP, NULLABLE) - Soft delete

**Permissions Table** (`permissions`)
- id (UUID, PK)
- name (VARCHAR(100), UNIQUE)
- description (TEXT, NULLABLE)
- created_by (UUID, FK to users, NULLABLE)
- updated_by (UUID, FK to users, NULLABLE)
- created_at (TIMESTAMP, default: CURRENT_TIMESTAMP)
- updated_at (TIMESTAMP, default: CURRENT_TIMESTAMP)

### Junction Tables

**User Roles** (`user_roles`)
- id (UUID, PK)
- user_id (UUID, FK to users, CASCADE)
- role_id (UUID, FK to roles, CASCADE)
- assigned_by (UUID, FK to users, NULLABLE)
- assigned_at (TIMESTAMP, default: CURRENT_TIMESTAMP)
- UNIQUE(user_id, role_id)

**Role Permissions** (`role_permissions`)
- id (UUID, PK)
- role_id (UUID, FK to roles, CASCADE)
- permission_id (UUID, FK to permissions, CASCADE)
- assigned_by (UUID, FK to users, NULLABLE)
- assigned_at (TIMESTAMP, default: CURRENT_TIMESTAMP)
- UNIQUE(role_id, permission_id)

### Authentication Tables

**Refresh Tokens** (`refresh_tokens`)
- id (UUID, PK)
- user_id (UUID, FK to users, CASCADE)
- token_hash (VARCHAR(255), UNIQUE)
- expires_at (TIMESTAMP)
- created_at (TIMESTAMP)
- revoked_at (TIMESTAMP, NULLABLE)

**JWT Blacklist** (`jwt_blacklist`)
- id (UUID, PK)
- token_id (VARCHAR(255), UNIQUE)
- user_id (UUID, FK to users, CASCADE)
- revoked_at (TIMESTAMP)
- expires_at (TIMESTAMP)

**Email Verification Tokens** (`email_verification_tokens`)
- id (UUID, PK)
- user_id (UUID, FK to users, CASCADE)
- token (VARCHAR(255), UNIQUE)
- expires_at (TIMESTAMP)
- created_at (TIMESTAMP)
- used_at (TIMESTAMP, NULLABLE)

**Password Reset Tokens** (`password_reset_tokens`)
- id (UUID, PK)
- user_id (UUID, FK to users, CASCADE)
- token (VARCHAR(255), UNIQUE)
- expires_at (TIMESTAMP)
- created_at (TIMESTAMP)
- used_at (TIMESTAMP, NULLABLE)

---

## API Endpoints

Base path: `/api/v1/`

### Authentication Endpoints (Public)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Register new user (requires email verification) |
| POST | `/auth/login` | Login with username/email + password |
| POST | `/auth/logout` | Logout (revoke tokens) - Requires Auth |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/verify-email` | Verify email with token |
| POST | `/auth/resend-verification` | Resend verification email |
| POST | `/auth/forgot-password` | Request password reset |
| POST | `/auth/reset-password` | Reset password with token |

### User Endpoints (Protected)

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/users/me` | Get current user profile | - |
| PUT | `/users/me` | Update current user profile | - |
| POST | `/users/me/change-password` | Change current user password | - |
| DELETE | `/users/me` | Delete own account | - |
| GET | `/users` | List users (with pagination, filter, sort) | list_users |
| POST | `/users` | Create new user | create_user |
| GET | `/users/:id` | Get user by ID | view_user |
| PUT | `/users/:id` | Update user | update_user |
| POST | `/users/:id/disable` | Disable user | disable_user |
| POST | `/users/:id/enable` | Enable (restore) user | restore_user |
| DELETE | `/users/:id` | Soft delete user | delete_user |

### Role Endpoints (Protected)

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/roles` | List roles | list_roles |
| POST | `/roles` | Create role | create_role |
| GET | `/roles/:id` | Get role by ID | view_role |
| PUT | `/roles/:id` | Update role | update_role |
| DELETE | `/roles/:id` | Delete role (if not assigned) | delete_role |
| GET | `/roles/:id/permissions` | Get role permissions | view_role |
| POST | `/roles/:id/permissions` | Assign permission to role | assign_role |

### Permission Endpoints (Protected)

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/permissions` | List permissions | list_permissions |
| POST | `/permissions` | Create permission | create_permission |
| GET | `/permissions/:id` | Get permission by ID | view_permission |
| PUT | `/permissions/:id` | Update permission | update_permission |
| DELETE | `/permissions/:id` | Delete permission | delete_permission |

### User Role Assignment (Protected)

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/users/:id/roles` | Get user roles | view_user |
| POST | `/users/:id/roles` | Assign role to user | assign_role |
| DELETE | `/users/:id/roles/:roleId` | Remove role from user | revoke_role |

### Health Check (Public)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Basic health check |
| GET | `/health/db` | Database connection check |

### API Documentation (Protected)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/swagger/*` | Swagger UI (requires authentication) |

---

## API Response Format

### Success Response (Problem Details - RFC 7807)

```json
{
  "type": "about:blank",
  "title": "Success",
  "status": 200,
  "data": { ... }
}
```

### Error Response

```json
{
  "type": "https://example.com/probs/validation",
  "title": "Validation Error",
  "status": 400,
  "detail": "One or more fields failed validation",
  "errors": {
    "email": ["Email is required", "Email already exists"]
  }
}
```

---

## Pagination & Filtering

### Query Parameters

- `page`: Page number (default: 1)
- `limit`: Items per page (default: 20, max: 100)
- `sort`: Sort field and direction (e.g., `created_at:desc`)
- `filter`: Filter expressions (e.g., `status:active`)

### Response Format

```json
{
  "type": "about:blank",
  "title": "Success",
  "status": 200,
  "data": {
    "items": [...],
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 100,
      "totalPages": 5
    }
  }
}
```

---

## Development

### Prerequisites

- Go 1.25.5+
- Docker and Docker Compose
- PostgreSQL 18

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd golang-starter
   ```

2. **Install dependencies**
   ```bash
   go mod download
   ```

3. **Install development tools**
   ```bash
   make install-tools
   ```

4. **Start Docker services**
   ```bash
   make docker-up
   ```

5. **Run migrations**
   ```bash
   make migrate-up
   ```

6. **Copy environment file**
   ```bash
   cp .env.example .env
   # Update .env with your configuration
   ```

7. **Run the server**
   ```bash
   make run
   ```

### Available Make Targets

| Target | Description |
|--------|-------------|
| `make run` | Run the server |
| `make migrate-up` | Run all pending migrations |
| `make migrate-down` | Rollback last migration |
| `make migrate-create NAME=migration_name` | Create new migration |
| `make sqlc-generate` | Generate SQL code from queries |
| `make test` | Run all tests |
| `make test-unit` | Run unit tests only |
| `make test-integration` | Run integration tests only |
| `make swagger-generate` | Generate Swagger documentation |
| `make docker-up` | Start Docker services |
| `make docker-down` | Stop Docker services |
| `make clean` | Clean build artifacts |
| `make build` | Build the application |
| `make deps` | Download dependencies |
| `make install-tools` | Install development tools |

---

## Implementation Status

### Completed ✅ - 100%

**Core Infrastructure**
- [x] Project structure with vertical slice architecture
- [x] Environment configuration
- [x] Database connection with connection pooling
- [x] Structured logging with slog
- [x] Base middleware (Request ID, Logger, Panic Recovery, Rate Limiting, CORS, Timeout)
- [x] JWT authentication middleware
- [x] Authorization middleware (permission checking)
- [x] Database migrations (all tables)
- [x] sqlc configuration and generated code
- [x] Seed data (permissions, roles)
- [x] Makefile with common tasks
- [x] Docker Compose (PostgreSQL + Mailhog)

**Authentication Feature**
- [x] Auth handlers (register, login, logout, refresh, verify-email, forgot-password, reset-password)
- [x] Auth service and repository
- [x] Email service with SMTP support
- [x] Email templates (HTML)
- [x] Password hashing (bcrypt)
- [x] Token revocation (JWT blacklist)
- [x] Account lockout after failed attempts

**User Management Feature**
- [x] User CRUD handlers
- [x] User service and repository
- [x] User profile endpoints (/me)
- [x] Password change endpoint
- [x] User disable/enable endpoints
- [x] Soft delete support

**Role & Permission Features**
- [x] Role CRUD handlers
- [x] Permission CRUD handlers
- [x] Role-Permission assignment handlers
- [x] User-Role assignment handlers
- [x] Permission-based authorization
- [x] In-memory permission caching

**Testing & Documentation**
- [x] Unit tests (validator, domain models)
- [x] Integration tests (auth, user flows)
- [x] Swagger documentation generation
- [x] README.md with setup instructions
- [x] Initial admin user creation on startup

**Security**
- [x] Password strength validation
- [x] Rate limiting (per IP)
- [x] CORS configuration
- [x] Request ID tracking
- [x] Audit fields (created_by, updated_by)

---

## Security Considerations

1. **Password Requirements**: Minimum 8 characters, must include uppercase, lowercase, number
2. **Rate Limiting**: 60 requests/minute per IP, 10 burst
3. **Account Lockout**: 5 failed login attempts locks account for 30 minutes
4. **JWT Storage**: Access tokens (15min) + Refresh tokens (7 days, stored in DB)
5. **Token Revocation**: Full revocation support via JWT blacklist
6. **Email Verification**: Required for new users
7. **Audit Logging**: Track created_by/updated_by for all records
8. **Soft Delete**: Users, roles can be restored
9. **Role Deletion**: Prevent deletion if role is assigned to users
10. **Password Reset**: Secure token-based reset flow

---

## License

MIT
