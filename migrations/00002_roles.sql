-- +goose Up
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_by UUID REFERENCES users(id),
    updated_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

-- Create index for faster lookups
CREATE INDEX idx_roles_name ON roles(name) WHERE deleted_at IS NULL;
CREATE INDEX idx_roles_deleted_at ON roles(deleted_at);

-- +goose Down
DROP INDEX IF EXISTS idx_roles_deleted_at;
DROP INDEX IF EXISTS idx_roles_name;
DROP TABLE IF EXISTS roles;
