package db

import (
	"errors"

	"github.com/lib/pq"
)

// IsUniqueViolation checks if the error is a PostgreSQL unique constraint violation
func IsUniqueViolation(err error) bool {
	if pqErr, ok := err.(*pq.Error); ok {
		return pqErr.Code == "23505"
	}
	return false
}

var ErrUniqueViolation = errors.New("unique violation")
