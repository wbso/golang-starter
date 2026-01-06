.PHONY: run migrate-up migrate-down migrate-create sqlc-generate test test-unit test-integration swagger-generate docker-up docker-down clean help

# Variables
DB_HOST=localhost
DB_PORT=10012
DB_USER=postgres
DB_PASSWORD=Secretcom123
DB_NAME=golang_starter
MIGRATIONS_DIR=./migrations

# Tools
goose_cmd = github.com/pressly/goose/v3/cmd/goose@v3.26.0
golangci_cmd = github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.7.2
air_cmd = github.com/air-verse/air@v1.63.4
goimports_cmd = golang.org/x/tools/cmd/goimports@v0.40.0
gofumpt_cmd = mvdan.cc/gofumpt@v0.9.2
govulncheck_cmd = golang.org/x/vuln/cmd/govulncheck@v1.1.4
sqlc_cmd = github.com/sqlc-dev/sqlc/cmd/sqlc@v1.30.0
air_cmd = github.com/air-verse/air@v1.63.4

## dev: run the application with reloading on file changes
.PHONY: dev
dev:
	go run ${air_cmd} -c .air.toml

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

migrate-up: ## Run all pending migrations
	@echo "Running migrations..."
	@~/go/bin/goose -dir $(MIGRATIONS_DIR) postgres "host=$(DB_HOST) port=$(DB_PORT) user=$(DB_USER) password=$(DB_PASSWORD) dbname=$(DB_NAME) sslmode=disable" up

migrate-down: ## Rollback last migration
	@echo "Rolling back last migration..."
	@~/go/bin/goose -dir $(MIGRATIONS_DIR) postgres "host=$(DB_HOST) port=$(DB_PORT) user=$(DB_USER) password=$(DB_PASSWORD) dbname=$(DB_NAME) sslmode=disable" down

migrate-create: ## Create a new migration (use NAME=name.sql)
	@echo "Creating migration..."
	@~/go/bin/goose -dir $(MIGRATIONS_DIR) create $(NAME) sql

generate: ## Generate SQL code from queries
	@echo "Generating SQL code..."
	@go run ${sqlc_cmd} generate

test: ## Run all tests
	@echo "Running all tests..."
	@go test -v ./...

test-unit: ## Run unit tests only
	@echo "Running unit tests..."
	@go test -v -short ./...

test-integration: ## Run integration tests only
	@echo "Running integration tests..."
	@go test -v ./tests/integration/... -tags=integration

swagger-generate: ## Generate Swagger documentation
	@echo "Generating Swagger documentation..."
	@~/go/bin/swag init -g cmd/server/main.go -o docs

clean: ## Clean build artifacts
	@echo "Cleaning..."
	@go clean
	@rm -f /tmp/go-build*

build: ## Build the application
	@echo "Building..."
	@go build -o build/server cmd/server/main.go

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy

install-tools: ## Install development tools
	@echo "Installing development tools..."
	@go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	@go install github.com/pressly/goose/v3/cmd/goose@latest
	@go install github.com/swaggo/swag/cmd/swag@latest
	@go install github.com/swaggo/echo-swagger/cmd/swag@latest

.PHONY: lint
lint: fix-imports
	@echo "Running linter..."
	go run ${golangci_cmd} run ./...

seed: ## Seed the database with initial data
	@echo "Seeding database..."
	@echo "This will be implemented as a separate command"

## format: format .go files
.PHONY: format
format:
	go run ${goimports_cmd} -l -w .
	go mod tidy
	go mod verify
	go run ${gofumpt_cmd} -l -w .
	go fmt ./...
	go vet ./...

.PHONY: fix-imports
fix-imports:
	go run ${goimports_cmd} -l -w .

default: help
