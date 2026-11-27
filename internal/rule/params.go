package rule

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Check reports whether v satisfies c. Its error describes the failed constraint without
// including the value being checked.
func (c ParamConstraint) Check(v any) error {
	problems := constraintViolations(v, c)
	if len(problems) == 0 {
		return nil
	}
	return errors.New(strings.Join(problems, "; "))
}

func constraintViolations(v any, c ParamConstraint) []string {
	if !constraintIsSet(c) {
		return nil
	}
	if !isScalar(v) {
		return []string{"the value is not a scalar, so no limit can hold for it"}
	}

	var out []string
	if c.Pattern != "" {
		re, err := compileWhole(c.Pattern)
		s, isString := v.(string)
		switch {
		case err != nil:
			out = append(out, "pattern is not a valid RE2 expression")
		case !isString:
			out = append(out, "the value is not a string, so pattern cannot match it")
		case !re.MatchString(s):
			out = append(out, "the value does not match pattern as a whole")
		}
	}
	if c.Minimum != nil || c.Maximum != nil {
		if !isNumberValue(v) {
			out = append(out, "the value is not a number, so minimum and maximum cannot hold for it")
		} else {
			n, finite := rationalNumber(v)
			if !finite {
				f, _ := number(v)
				if c.Minimum != nil {
					if _, ok := rationalNumber(*c.Minimum); !ok {
						out = append(out, "minimum is not a finite number")
					} else if math.IsNaN(f) || f < *c.Minimum {
						out = append(out, "the value is below minimum "+formatNumber(*c.Minimum))
					}
				}
				if c.Maximum != nil {
					if _, ok := rationalNumber(*c.Maximum); !ok {
						out = append(out, "maximum is not a finite number")
					} else if math.IsNaN(f) || f > *c.Maximum {
						out = append(out, "the value is above maximum "+formatNumber(*c.Maximum))
					}
				}
			} else {
				if c.Minimum != nil {
					minimum, ok := rationalNumber(*c.Minimum)
					if !ok {
						out = append(out, "minimum is not a finite number")
					} else if n.Cmp(minimum) < 0 {
						out = append(out, "the value is below minimum "+formatNumber(*c.Minimum))
					}
				}
				if c.Maximum != nil {
					maximum, ok := rationalNumber(*c.Maximum)
					if !ok {
						out = append(out, "maximum is not a finite number")
					} else if n.Cmp(maximum) > 0 {
						out = append(out, "the value is above maximum "+formatNumber(*c.Maximum))
					}
				}
			}
		}
	}
	if len(c.Enum) > 0 && !containsScalar(c.Enum, v) {
		out = append(out, "the value is not one of enum")
	}
	if c.MaxLength != nil {
		s, ok := v.(string)
		switch {
		case !ok:
			out = append(out, "the value is not a string, so max_length cannot hold for it")
		case utf8.RuneCountInString(s) > *c.MaxLength:
			out = append(out, fmt.Sprintf("the value is longer than max_length %d characters", *c.MaxLength))
		}
	}
	return out
}

func constraintIsSet(c ParamConstraint) bool {
	return c.Pattern != "" || c.Minimum != nil || c.Maximum != nil || len(c.Enum) > 0 || c.MaxLength != nil
}

func compileWhole(pattern string) (*regexp.Regexp, error) {
	if _, err := regexp.Compile(pattern); err != nil {
		return nil, err
	}
	return regexp.Compile("^(?:" + pattern + ")$")
}

func isScalar(v any) bool {
	_, ok := number(v)
	if ok {
		return true
	}
	switch v.(type) {
	case string, bool:
		return true
	default:
		return false
	}
}

func number(v any) (float64, bool) {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return 0, false
	}
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(rv.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(rv.Uint()), true
	case reflect.Float32, reflect.Float64:
		return rv.Float(), true
	}
	return 0, false
}

func isNumberValue(v any) bool {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return false
	}
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	default:
		return false
	}
}

func rationalNumber(v any) (*big.Rat, bool) {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return nil, false
	}
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return new(big.Rat).SetInt64(rv.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return new(big.Rat).SetInt(new(big.Int).SetUint64(rv.Uint())), true
	case reflect.Float32, reflect.Float64:
		rat := new(big.Rat).SetFloat64(rv.Float())
		return rat, rat != nil
	default:
		return nil, false
	}
}

func formatNumber(n float64) string { return strconv.FormatFloat(n, 'g', -1, 64) }

func containsScalar(values []any, want any) bool {
	if isNumberValue(want) {
		x, ok := rationalNumber(want)
		if !ok {
			return false
		}
		for _, value := range values {
			if !isNumberValue(value) {
				continue
			}
			y, ok := rationalNumber(value)
			if ok && x.Cmp(y) == 0 {
				return true
			}
		}
		return false
	}
	for _, value := range values {
		if reflect.TypeOf(value) == reflect.TypeOf(want) && reflect.DeepEqual(value, want) {
			return true
		}
	}
	return false
}

// ApplyParams deep-merges layers over a copy of r.Params and validates the resulting values.
func ApplyParams(r *Rule, layers ...map[string]any) (map[string]any, error) {
	if r == nil {
		return nil, errors.New("cannot apply params to a nil rule")
	}
	params := cloneMap(r.Params)
	for _, layer := range layers {
		for _, name := range sortedKeys(layer) {
			def, ok := r.Params[name]
			if !ok {
				return nil, fmt.Errorf("rule %s has unknown param %s", r.ID, name)
			}
			overlay, err := normalizeJSONNumbers(layer[name])
			if err != nil {
				return nil, fmt.Errorf("rule %s param %s: %w", r.ID, name, err)
			}
			value, err := mergeValue(def, params[name], overlay)
			if err != nil {
				return nil, fmt.Errorf("rule %s param %s: %w", r.ID, name, err)
			}
			params[name] = value
		}
	}
	for _, name := range sortedKeys(params) {
		if c, ok := r.ParamsConstraints[name]; ok {
			if err := c.Check(params[name]); err != nil {
				return nil, fmt.Errorf("rule %s param %s violates constraint: %w", r.ID, name, err)
			}
		}
	}
	return params, nil
}

func mergeValue(def, current, overlay any) (any, error) {
	if containsNull(overlay) {
		return nil, errors.New("null is not allowed")
	}
	if base, ok := current.(map[string]any); ok {
		incoming, ok := overlay.(map[string]any)
		if !ok {
			return nil, errors.New("expected an object")
		}
		merged := cloneMap(base)
		for key, value := range incoming {
			if old, exists := merged[key]; exists {
				merged[key] = deepMerge(old, value)
			} else {
				merged[key] = cloneValue(value)
			}
		}
		return merged, nil
	}

	value, err := normalizeValue(def, overlay)
	if err != nil {
		return nil, err
	}
	return value, nil
}

func containsNull(value any) bool {
	switch v := value.(type) {
	case nil:
		return true
	case map[string]any:
		for _, item := range v {
			if containsNull(item) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if containsNull(item) {
				return true
			}
		}
	}
	return false
}

func normalizeValue(def, value any) (any, error) {
	if value == nil {
		return nil, errors.New("null is not allowed")
	}
	switch d := def.(type) {
	case string:
		if _, ok := value.(string); !ok {
			return nil, errors.New("expected a string")
		}
	case bool:
		if _, ok := value.(bool); !ok {
			return nil, errors.New("expected a boolean")
		}
	case int:
		normalized, err := normalizeInteger(value)
		if err != nil {
			return nil, err
		}
		if integer, ok := normalized.(int64); ok {
			return int(integer), nil
		}
		return normalized, nil
	case int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return normalizeInteger(value)
	case float32, float64:
		return normalizeNumber(value)
	case []any:
		items, ok := value.([]any)
		if !ok {
			return nil, errors.New("expected an array")
		}
		out := make([]any, len(items))
		for i, item := range items {
			var element any
			var err error
			if len(d) == 0 {
				element, err = normalizeEmptyArrayScalar(item)
			} else {
				element, err = normalizeValue(d[0], item)
			}
			if err != nil {
				return nil, fmt.Errorf("element %d: %w", i, err)
			}
			out[i] = element
		}
		return out, nil
	case map[string]any:
		object, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("expected an object")
		}
		return cloneMap(object), nil
	default:
		return nil, fmt.Errorf("unsupported default type %T", def)
	}
	return cloneValue(value), nil
}

func normalizeInteger(value any) (any, error) {
	if n, ok := value.(json.Number); ok {
		if strings.ContainsAny(string(n), ".eE") {
			return nil, errors.New("expected an integer")
		}
		i, err := strconv.ParseInt(string(n), 10, 64)
		if err != nil {
			return nil, errors.New("expected an integer")
		}
		return int(i), nil
	}
	rv := reflect.ValueOf(value)
	if rv.IsValid() {
		switch rv.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return value, nil
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			if rv.Uint() <= uint64(1<<63-1) {
				return value, nil
			}
			return nil, errors.New("integer is outside the int64 range")
		}
	}
	return nil, errors.New("expected an integer")
}

func normalizeNumber(value any) (any, error) {
	if n, ok := value.(json.Number); ok {
		f, err := strconv.ParseFloat(string(n), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return nil, errors.New("expected a number")
		}
		return f, nil
	}
	if _, ok := number(value); ok {
		return value, nil
	}
	return nil, errors.New("expected a number")
}

func normalizeEmptyArrayScalar(value any) (any, error) {
	if value == nil {
		return nil, errors.New("array elements must be scalars")
	}
	if n, ok := value.(json.Number); ok {
		if !strings.ContainsAny(string(n), ".eE") {
			return normalizeInteger(n)
		}
		return normalizeNumber(n)
	}
	if isScalar(value) {
		return value, nil
	}
	return nil, errors.New("array elements must be scalars")
}

func deepMerge(base, overlay any) any {
	left, leftOK := base.(map[string]any)
	right, rightOK := overlay.(map[string]any)
	if !leftOK || !rightOK {
		return cloneValue(overlay)
	}
	out := cloneMap(left)
	for key, value := range right {
		if old, exists := out[key]; exists {
			out[key] = deepMerge(old, value)
		} else {
			out[key] = cloneValue(value)
		}
	}
	return out
}

func cloneMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for key, value := range src {
		out[key] = cloneValue(value)
	}
	return out
}

func cloneValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		return cloneMap(v)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = cloneValue(item)
		}
		return out
	default:
		return value
	}
}

func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// ParseSetArg parses <rule-id>.<param>=<json> and the optional .params. form.
func ParseSetArg(arg string) (ParamSet, error) {
	left, raw, ok := strings.Cut(arg, "=")
	if !ok {
		return ParamSet{}, errors.New("--set must be <rule-id>.<param>=<json>")
	}
	dot := strings.LastIndexByte(left, '.')
	if dot <= 0 || dot == len(left)-1 {
		return ParamSet{}, errors.New("--set must include a rule id and param")
	}
	param, ruleID := left[dot+1:], left[:dot]
	if strings.HasSuffix(ruleID, ".params") {
		ruleID = strings.TrimSuffix(ruleID, ".params")
	}
	if ruleID == "" {
		return ParamSet{}, errors.New("--set must include a rule id")
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return ParamSet{}, fmt.Errorf("--set value must be valid JSON: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return ParamSet{}, errors.New("--set value must contain one JSON value")
	}
	value, err := normalizeJSONNumbers(value)
	if err != nil {
		return ParamSet{}, fmt.Errorf("--set value: %w", err)
	}
	return ParamSet{RuleID: ruleID, Param: param, Value: value}, nil
}

func normalizeJSONNumbers(value any) (any, error) {
	switch v := value.(type) {
	case json.Number:
		if !strings.ContainsAny(string(v), ".eE") {
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
		out := make([]any, len(v))
		for i, item := range v {
			converted, err := normalizeJSONNumbers(item)
			if err != nil {
				return nil, fmt.Errorf("array element %d: %w", i, err)
			}
			out[i] = converted
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(v))
		for _, key := range sortedKeys(v) {
			converted, err := normalizeJSONNumbers(v[key])
			if err != nil {
				return nil, fmt.Errorf("object field %s: %w", key, err)
			}
			out[key] = converted
		}
		return out, nil
	case float32:
		if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
			return nil, errors.New("number must be finite")
		}
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, errors.New("number must be finite")
		}
	case uint, uint8, uint16, uint32, uint64:
		rv := reflect.ValueOf(v)
		if rv.Uint() > uint64(1<<63-1) {
			return nil, errors.New("integer is outside the int64 range")
		}
	default:
		return value, nil
	}
	return value, nil
}
