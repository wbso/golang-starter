-- +goose Up
CREATE TABLE IF NOT EXISTS jwt_blacklist (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    token_id VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

-- Create indexes for faster lookups and cleanup
CREATE INDEX idx_jwt_blacklist_token_id ON jwt_blacklist(token_id);
CREATE INDEX idx_jwt_blacklist_user_id ON jwt_blacklist(user_id);
CREATE INDEX idx_jwt_blacklist_expires_at ON jwt_blacklist(expires_at);

-- +goose Down
DROP INDEX IF EXISTS idx_jwt_blacklist_expires_at;
DROP INDEX IF EXISTS idx_jwt_blacklist_user_id;
DROP INDEX IF EXISTS idx_jwt_blacklist_token_id;
DROP TABLE IF EXISTS jwt_blacklist;
