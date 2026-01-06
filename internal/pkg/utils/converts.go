package utils

import (
	"fmt"
	"math"
)

func convertSafely(value int) (int32, error) {
	if value > math.MaxInt32 || value < math.MinInt32 {
		return 0, fmt.Errorf("value %d overflows int32", value)
	}
	return int32(value), nil
}

func SafeConvertDefaultInt32(value int, defaultValue int32) int32 {
	v, err := convertSafely(value)
	if err != nil {
		return defaultValue
	}
	return v
}
