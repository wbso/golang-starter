package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/wbso/golang-starter/internal/config"
)

// DB wraps sqlx.DB with additional functionality
type DB struct {
	*sqlx.DB
}

// New creates a new database connection
func New(dsn string, maxConn, maxIdleConn int, connMaxLifetime time.Duration) (*DB, error) {
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(maxConn)
	db.SetMaxIdleConns(maxIdleConn)
	db.SetConnMaxLifetime(connMaxLifetime)

	return &DB{DB: db}, nil
}

// NewPool creates a new database connection pool
func NewPool(ctx context.Context, cfg config.DatabaseConfig) (*DB, error) {
	return New(cfg.DSN(), cfg.MaxConnections, cfg.MaxIdleConnections, cfg.ConnectionMaxLifetime)
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.DB.Close()
}

// Ping checks if the database connection is alive
func (db *DB) Ping() error {
	return db.DB.Ping()
}

// HealthCheck performs a health check on the database
func (db *DB) HealthCheck(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return db.PingContext(ctx)
	}
}

// BeginTx starts a transaction with the given options
func (db *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sqlx.Tx, error) {
	return db.BeginTxx(ctx, opts)
}

// InTransaction executes a function within a transaction
func (db *DB) InTransaction(ctx context.Context, fn func(*sqlx.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("tx error: %v, rollback error: %w", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
