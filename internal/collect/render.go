package collect

import (
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/SummerQXY/gbencher/internal/cmdline"
)

var fieldPathExpression = regexp.MustCompile(`^\.[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)

// RenderArgv renders each command word independently and returns argv without re-splitting values.
func RenderArgv(tmpl string, values map[string]any) ([]string, error) {
	words, err := cmdline.Split(tmpl)
	if err != nil {
		return nil, fmt.Errorf("split command template: %w", err)
	}
	argv := make([]string, 0, len(words))
	for wordIndex, word := range words {
		var rendered strings.Builder
		for _, part := range word.Parts {
			if !part.Action {
				rendered.WriteString(part.Text)
				continue
			}
			value, renderErr := renderScalarAction(part.Text, values)
			if renderErr != nil {
				return nil, fmt.Errorf("render command word %d: %w", wordIndex, renderErr)
			}
			if hasWhitespaceOrControl(value) {
				return nil, fmt.Errorf("rendered command value contains whitespace or control characters")
			}
			rendered.WriteString(value)
		}
		value := rendered.String()
		if len(word.Parts) > 0 && word.Parts[0].Action && strings.HasPrefix(value, "-") {
			return nil, fmt.Errorf("rendered positional command argument starts with a dash")
		}
		argv = append(argv, value)
	}
	return argv, nil
}

// RenderURL renders action values as escaped URL components and validates the resulting HTTPS URL.
func RenderURL(tmpl string, values map[string]any) (string, error) {
	if !strings.HasPrefix(tmpl, "https://") {
		return "", fmt.Errorf("URL template must start with https://")
	}
	if hasTemplateLiteralWhitespaceOrControl(tmpl) {
		return "", fmt.Errorf("URL template contains whitespace or control characters")
	}
	if err := validateURLTemplateHost(tmpl); err != nil {
		return "", err
	}

	var rendered strings.Builder
	for i := 0; i < len(tmpl); {
		start := strings.Index(tmpl[i:], "{{")
		if start < 0 {
			rendered.WriteString(tmpl[i:])
			break
		}
		start += i
		endOffset := strings.Index(tmpl[start+2:], "}}")
		if endOffset < 0 {
			return "", fmt.Errorf("unterminated URL template action")
		}
		end := start + 2 + endOffset + 2
		if !isURLActionBoundaryBefore(tmpl, start) || !isURLActionBoundaryAfter(tmpl, end) {
			return "", fmt.Errorf("URL template action must occupy a complete component")
		}
		rendered.WriteString(tmpl[i:start])
		value, err := renderScalarAction(tmpl[start:end], values)
		if err != nil {
			return "", fmt.Errorf("render URL component: %w", err)
		}
		rendered.WriteString(escapeRFC3986Component(value))
		i = end
	}

	result := rendered.String()
	if hasWhitespaceOrControl(result) {
		return "", fmt.Errorf("rendered URL contains whitespace or control characters")
	}
	parsed, err := url.Parse(result)
	if err != nil {
		return "", fmt.Errorf("parse rendered URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("rendered URL must be HTTPS and must not contain userinfo")
	}
	return result, nil
}

func renderScalarAction(action string, values map[string]any) (string, error) {
	if len(action) < 4 || !strings.HasPrefix(action, "{{") || !strings.HasSuffix(action, "}}") {
		return "", fmt.Errorf("invalid template action")
	}
	expression := strings.TrimSpace(action[2 : len(action)-2])
	if expression == "" {
		return "", fmt.Errorf("empty template action")
	}
	if !fieldPathExpression.MatchString(expression) {
		return "", fmt.Errorf("template action must be a field path")
	}
	value, err := resolveFieldPath(values, expression)
	if err != nil {
		return "", err
	}
	return scalarString(value)
}

func resolveFieldPath(values any, expression string) (any, error) {
	value := reflect.ValueOf(values)
	for _, name := range strings.Split(strings.TrimPrefix(expression, "."), ".") {
		for value.IsValid() && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
			if value.IsNil() {
				return nil, fmt.Errorf("template field path traverses a nil value")
			}
			value = value.Elem()
		}
		if !value.IsValid() {
			return nil, fmt.Errorf("template field path is missing")
		}

		switch value.Kind() {
		case reflect.Map:
			if value.Type().Key().Kind() != reflect.String {
				return nil, fmt.Errorf("template field path requires string map keys")
			}
			key := reflect.ValueOf(name)
			if key.Type() != value.Type().Key() {
				key = key.Convert(value.Type().Key())
			}
			value = value.MapIndex(key)
			if !value.IsValid() {
				return nil, fmt.Errorf("template field path is missing")
			}
		case reflect.Struct:
			field, ok := value.Type().FieldByName(name)
			if !ok || field.PkgPath != "" {
				return nil, fmt.Errorf("template field path must select data fields")
			}
			fieldValue, err := value.FieldByIndexErr(field.Index)
			if err != nil {
				return nil, fmt.Errorf("template field path traverses a nil embedded field")
			}
			value = fieldValue
		default:
			return nil, fmt.Errorf("template field path must select data fields")
		}
	}
	for value.IsValid() && value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil, fmt.Errorf("template field path resolves to nil")
		}
		value = value.Elem()
	}
	if !value.IsValid() || !value.CanInterface() {
		return nil, fmt.Errorf("template field path does not expose a data value")
	}
	return value.Interface(), nil
}

func scalarString(value any) (string, error) {
	if value == nil {
		return "", fmt.Errorf("template value must be a scalar")
	}
	reflected := reflect.ValueOf(value)
	kind := reflected.Kind()
	switch kind {
	case reflect.String:
		return reflected.String(), nil
	case reflect.Bool:
		return strconv.FormatBool(reflected.Bool()), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(reflected.Int(), 10), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(reflected.Uint(), 10), nil
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(reflected.Float(), 'g', -1, reflected.Type().Bits()), nil
	default:
		return "", fmt.Errorf("template value must be a scalar")
	}
}

func hasWhitespaceOrControl(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0
}

func hasTemplateLiteralWhitespaceOrControl(value string) bool {
	for i := 0; i < len(value); {
		start := strings.Index(value[i:], "{{")
		if start < 0 {
			return hasWhitespaceOrControl(value[i:])
		}
		start += i
		if hasWhitespaceOrControl(value[i:start]) {
			return true
		}
		endOffset := strings.Index(value[start+2:], "}}")
		if endOffset < 0 {
			return false
		}
		i = start + 2 + endOffset + 2
	}
	return false
}

func validateURLTemplateHost(tmpl string) error {
	const prefix = "https://"
	hostStart := len(prefix)
	hostEnd := len(tmpl)
	if offset := strings.IndexAny(tmpl[hostStart:], "/?#"); offset >= 0 {
		hostEnd = hostStart + offset
	}
	if strings.Contains(tmpl[hostStart:hostEnd], "{{") {
		return fmt.Errorf("URL template actions are not allowed in the host")
	}
	parsed, err := url.Parse(tmpl)
	if err != nil {
		return fmt.Errorf("parse URL template: %w", err)
	}
	if parsed.User != nil || strings.Contains(parsed.Host, "@") {
		return fmt.Errorf("URL template must not contain userinfo")
	}
	if parsed.Host == "" {
		return fmt.Errorf("URL template must contain a host")
	}
	return nil
}

func isURLActionBoundaryBefore(value string, start int) bool {
	return start == 0 || isURLDelimiter(value[start-1])
}

func isURLActionBoundaryAfter(value string, end int) bool {
	return end == len(value) || isURLDelimiter(value[end])
}

func isURLDelimiter(value byte) bool {
	switch value {
	case '/', '?', '&', '=':
		return true
	default:
		return false
	}
}

func escapeRFC3986Component(value string) string {
	const hex = "0123456789ABCDEF"
	var escaped strings.Builder
	escaped.Grow(len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		if isUnreserved(c) {
			escaped.WriteByte(c)
			continue
		}
		escaped.WriteByte('%')
		escaped.WriteByte(hex[c>>4])
		escaped.WriteByte(hex[c&0x0f])
	}
	return escaped.String()
}

func isUnreserved(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || value == '-' || value == '.' || value == '_' || value == '~'
}
