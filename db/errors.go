package db

import (
	"errors"

	"github.com/lib/pq"
)

// IsUniqueViolation checks if the error is a PostgreSQL unique constraint violation
func IsUniqueViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	return false
}

var ErrUniqueViolation = errors.New("unique violation")
