# Golang Starter Project

A production-ready Golang starter project implementing **Vertical Slice Architecture** with User Management and RBAC (Role-Based Access Control).

## Features

- **Authentication & Authorization**
  - JWT-based authentication with access and refresh tokens
  - Email verification workflow
  - Password reset via email
  - Account lockout after failed login attempts
  - Role-Based Access Control (RBAC)
  - Permission-based authorization middleware

- **User Management**
  - Full CRUD operations for users
  - User profile management (`/me` endpoints)
  - Password change functionality
  - User disable/enable capabilities
  - Soft delete support

- **Role & Permission Management**
  - Role CRUD operations
  - Permission CRUD operations
  - Role-Permission assignments
  - User-Role assignments
  - Cached permission checking

- **Developer Experience**
  - OpenAPI/Swagger documentation
  - Comprehensive test suite (unit + integration tests)
  - Type-safe database queries via sqlc
  - Migration management with Goose
  - Structured logging with slog
  - RFC 7807 Problem Details error handling

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Framework | [Echo](https://echo.labstack.com/) v4 |
| Database | PostgreSQL 18+ |
| ORM | [sqlc](https://sqlc.dev/) (SQL to Go code generation) |
| Migrations | [Goose](https://github.com/pressly/goose) |
| Authentication | JWT (access + refresh tokens) |
| Password Hashing | bcrypt |
| Email | SMTP with HTML templates |
| Validation | Custom fluent validator |
| Documentation | Swagger/OpenAPI |

## Project Structure

```
.
├── cmd/
│   └── server/
│       └── main.go          # Application entry point
├── internal/
│   ├── config/              # Configuration management
│   ├── domain/              # Shared domain models (DTOs, requests/responses)
│   │   ├── auth/
│   │   ├── user/
│   │   ├── role/
│   │   └── permission/
│   ├── feature/             # Vertical slices (complete features)
│   │   ├── auth/
│   │   │   ├── handler/     # HTTP layer
│   │   │   ├── service/     # Business logic layer
│   │   │   └── repository/  # Data access layer
│   │   ├── user/
│   │   ├── role/
│   │   └── permission/
│   ├── middleware/          # Echo middleware
│   ├── pkg/                 # Internal utilities
│   │   ├── email/
│   │   ├── jwt/
│   │   ├── validator/
│   │   ├── errors/
│   │   └── logger/
│   └── infrastructure/
│       └── database/        # Database connection & health
├── migrations/              # Database migrations
├── queries/                 # SQL queries for sqlc
├── db/                      # Generated database code (by sqlc)
├── docs/                    # Swagger documentation
├── tests/                   # Integration tests
├── compose.yml              # Docker Compose for PostgreSQL + Mailhog
├── Makefile                 # Development commands
├── SPEC.md                  # Detailed specification
└── PROGRESS.md              # Implementation progress
```

## Getting Started

### Prerequisites

- Go 1.23+
- PostgreSQL 18+
- Docker (for services)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd golang-starter
```

2. Install dependencies:
```bash
make deps
```

3. Install development tools:
```bash
make install-tools
```

4. Copy environment configuration:
```bash
cp .env.example .env
```

5. Edit `.env` with your configuration:
```env
# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=your_password
DB_NAME=golang_starter

# JWT
JWT_SECRET=your-secret-key-at-least-32-characters-long

# SMTP (for email verification/password reset)
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_FROM=noreply@example.com
SMTP_FROM_NAME=MyApp

# Application
APP_ENV=development
APP_PORT=8080
```

6. Start Docker services (PostgreSQL + Mailhog):
```bash
make docker-up
```

7. Run database migrations:
```bash
make migrate-up
```

8. Generate database code from SQL queries:
```bash
make sqlc-generate
```

9. Run the server:
```bash
make run
```

The API will be available at `http://localhost:8080`

### Running Tests

```bash
# Run all tests
make test

# Run unit tests only
make test-unit

# Run integration tests only
make test-integration
```

## API Documentation

### Swagger UI

Once the server is running, access the Swagger documentation at:

```
http://localhost:8080/api/v1/swagger/index.html
```

**Note:** Swagger UI requires authentication. Use your JWT token to access it.

### Public Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/register` | POST | Register a new user |
| `/api/v1/auth/login` | POST | Login with email/username |
| `/api/v1/auth/refresh` | POST | Refresh access token |
| `/api/v1/auth/verify-email` | POST | Verify email address |
| `/api/v1/auth/forgot-password` | POST | Request password reset |
| `/api/v1/auth/reset-password` | POST | Reset password with token |

### Protected Endpoints

All other endpoints require a valid JWT token:

```bash
curl -H "Authorization: Bearer <your-token>" http://localhost:8080/api/v1/users/me
```

#### User Management

| Endpoint | Method | Description | Permission |
|----------|--------|-------------|------------|
| `/api/v1/users` | GET | List users (paginated) | `list_users` |
| `/api/v1/users` | POST | Create user | `create_user` |
| `/api/v1/users/:id` | GET | Get user by ID | `view_user` |
| `/api/v1/users/:id` | PUT | Update user | `update_user` |
| `/api/v1/users/:id` | DELETE | Delete user | `delete_user` |
| `/api/v1/users/:id/disable` | POST | Disable user | `update_user` |
| `/api/v1/users/:id/enable` | POST | Enable user | `update_user` |
| `/api/v1/users/me` | GET | Get current user | - (self) |
| `/api/v1/users/me` | PUT | Update current user | - (self) |
| `/api/v1/users/me/change-password` | POST | Change password | - (self) |
| `/api/v1/users/me` | DELETE | Delete own account | - (self) |

#### Role Management

| Endpoint | Method | Description | Permission |
|----------|--------|-------------|------------|
| `/api/v1/roles` | GET | List roles | - (authenticated) |
| `/api/v1/roles` | POST | Create role | `manage_roles` |
| `/api/v1/roles/:id` | GET | Get role by ID | - (authenticated) |
| `/api/v1/roles/:id` | PUT | Update role | `manage_roles` |
| `/api/v1/roles/:id` | DELETE | Delete role | `manage_roles` |
| `/api/v1/roles/:id/permissions` | GET | Get role permissions | - (authenticated) |
| `/api/v1/roles/:id/permissions` | POST | Assign permission | `manage_roles` |
| `/api/v1/roles/:id/permissions/:permissionId` | DELETE | Revoke permission | `manage_roles` |

#### Permission Management

| Endpoint | Method | Description | Permission |
|----------|--------|-------------|------------|
| `/api/v1/permissions` | GET | List permissions | - (authenticated) |
| `/api/v1/permissions` | POST | Create permission | `manage_permissions` |
| `/api/v1/permissions/:id` | GET | Get permission by ID | - (authenticated) |
| `/api/v1/permissions/:id` | PUT | Update permission | `manage_permissions` |
| `/api/v1/permissions/:id` | DELETE | Delete permission | `manage_permissions` |

#### User-Role Assignments

| Endpoint | Method | Description | Permission |
|----------|--------|-------------|------------|
| `/api/v1/users/:id/roles` | GET | Get user roles | - (authenticated) |
| `/api/v1/users/:id/roles` | POST | Assign role to user | `assign_roles` |
| `/api/v1/users/:id/roles/:roleId` | DELETE | Revoke role from user | `assign_roles` |

## Response Format

All API responses follow RFC 7807 Problem Details format:

```json
{
  "type": "about:blank",
  "title": "Success",
  "status": 200,
  "data": {
    // Response data here
  }
}
```

Error responses include additional details:

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

## Development

### Adding New SQL Queries

1. Add your query to the appropriate file in `queries/`:
```sql
-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL;
```

2. Generate the Go code:
```bash
make sqlc-generate
```

3. Use the generated code in your repository.

### Creating Migrations

```bash
make migrate-create NAME=add_new_table
```

Edit the created migration file in `migrations/`, then run:
```bash
make migrate-up
```

### Generating Swagger Docs

After adding/updating Swagger annotations in handlers:
```bash
make swagger-generate
```

### Code Formatting

```bash
make fmt
```

### Linting

```bash
make lint
```

## Security Features

- **Password Hashing**: bcrypt with configurable cost factor
- **Account Lockout**: 5 failed attempts locks account for 30 minutes
- **JWT Tokens**:
  - Access tokens expire in 15 minutes
  - Refresh tokens expire in 7 days (stored in database)
  - Token blacklist for logout
- **Email Verification**: Required for new users
- **Rate Limiting**: Configurable per-endpoint limits
- **CORS**: Configurable allowed origins
- **Input Validation**: Fluent validator with custom rules

## Default Permissions & Roles

The seed migration creates the following:

### Permissions

- `list_users` - List all users
- `create_user` - Create new users
- `view_user` - View user details
- `update_user` - Update user information
- `delete_user` - Delete users
- `manage_roles` - Manage roles
- `manage_permissions` - Manage permissions
- `assign_roles` - Assign roles to users

### Roles

- `admin` - Full system access (all permissions)
- `user` - Basic user access (minimal permissions)
- `moderator` - Intermediate access

## Docker Services

The project includes Docker Compose configuration for:

- **PostgreSQL**: Primary database
- **Mailhog**: Email testing (catches all emails at http://localhost:8025)

### Commands

```bash
# Start services
make docker-up

# Stop services
make docker-down

# View logs
make docker-logs
```

## Configuration

Configuration is managed via environment variables. See `.env.example` for all available options.

Key configuration areas:
- Database connection
- JWT settings (secret, expiration times)
- SMTP/email settings
- Rate limiting
- CORS settings
- Password policy

## Testing

### Unit Tests

Unit tests cover individual components in isolation:
- Validator tests
- Domain model tests
- Service layer tests (with mocks)

### Integration Tests

Integration tests cover full request/response cycles:
- Auth flow (register, login, refresh)
- User CRUD operations
- Role/Permission management
- Authorization middleware

Integration tests require a test database and are tagged with `integration`.

## Troubleshooting

### Migration Errors

If migrations fail:
```bash
# Check current version
psql -U postgres -d golang_starter -c "SELECT * FROM goose_db_version;"

# Rollback if needed
make migrate-down
```

### Database Connection Issues

Ensure PostgreSQL is running:
```bash
docker compose ps
```

Check database logs:
```bash
make docker-logs
```

### Email Not Sending

For development, Mailhog catches all emails. Access at:
- Web UI: http://localhost:8025
- SMTP: localhost:1025

## Contributing

1. Create a feature branch
2. Make your changes
3. Add/update tests
4. Run `make fmt` and `make lint`
5. Ensure all tests pass: `make test`
6. Submit a pull request

## License

[Your License Here]

## Support

For detailed specification, see [SPEC.md](SPEC.md)
For implementation progress, see [PROGRESS.md](PROGRESS.md)
