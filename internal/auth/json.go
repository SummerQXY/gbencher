package auth

import (
	"fmt"
	"strconv"

	"github.com/SummerQXY/gbencher/internal/collect"
)

func jsonString(value any) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	default:
		return "", fmt.Errorf("expected a JSON string or integer, got %T", value)
	}
}

func invalidJSON(message string) error {
	return collect.ClassifyParse(fmt.Errorf("%s", message))
}
