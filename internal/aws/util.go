package aws

import (
	"strings"
)

func StringValue(x *string) string {
	if x != nil {
		y := strings.TrimPrefix(*x, "\"")
		return strings.TrimSuffix(y, "\"")
	}
	return ""
}

func BoolValue(x *bool) bool {
	if x != nil {
		return *x
	}
	return false
}

func Int64Value(x *int64) int64 {
	if x != nil {
		return *x
	}
	return 0
}

func Float64Value(x *float64) float64 {
	if x != nil {
		return *x
	}
	return 0
}
