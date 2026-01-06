package utils

import "strconv"

type Pagination struct {
	Limit  int32
	Offset int32
}

func ParsePaginationFromString(limit string, page string) Pagination {
	limitInt, _ := strconv.Atoi(limit)
	pageInt, _ := strconv.Atoi(page)
	return ParsePaginationFromInt(limitInt, pageInt)
}

// ParsePaginationFromInt
func ParsePaginationFromInt(limit int, page int) Pagination {
	if limit <= 0 {
		limit = 10
	}

	// Limit max to 100
	if limit > 100 {
		limit = 100
	}

	pageInt := max(page, 1)

	offset := (pageInt - 1) * limit

	return Pagination{Limit: SafeConvertDefaultInt32(limit, 10), Offset: SafeConvertDefaultInt32(offset, 0)}
}
