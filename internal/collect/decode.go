package collect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// DecodeJSON decodes JSON using int64 for integral numeric tokens and float64 otherwise.
func DecodeJSON(data []byte) (any, error) {
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("multiple JSON values")
		}
		return nil, fmt.Errorf("trailing content after JSON value: %w", err)
	}
	return convertNumbers(value)
}

func convertNumbers(value any) (any, error) {
	switch v := value.(type) {
	case json.Number:
		if !containsDecimalOrExponent(string(v)) {
			integer, err := v.Int64()
			if err != nil {
				return nil, fmt.Errorf("JSON integer %q is outside the int64 range: %w", v, err)
			}
			return integer, nil
		}
		floating, err := v.Float64()
		if err != nil {
			return nil, fmt.Errorf("invalid JSON number %q: %w", v, err)
		}
		return floating, nil
	case []any:
		for i := range v {
			converted, err := convertNumbers(v[i])
			if err != nil {
				return nil, err
			}
			v[i] = converted
		}
		return v, nil
	case map[string]any:
		for key, item := range v {
			converted, err := convertNumbers(item)
			if err != nil {
				return nil, err
			}
			v[key] = converted
		}
		return v, nil
	default:
		return value, nil
	}
}

func containsDecimalOrExponent(number string) bool {
	for _, r := range number {
		if r == '.' || r == 'e' || r == 'E' {
			return true
		}
	}
	return false
}
