package collect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// RESTRequestValidator checks a fully rendered REST request before it can be constructed.
type RESTRequestValidator func(method, rawURL string, body []byte) error

// PreparedRESTRequest contains only a request that passed the caller's final-target validator.
// Its fields are private so HTTP execution cannot accept a caller-constructed http.Request.
type PreparedRESTRequest struct {
	method   string
	url      *url.URL
	body     []byte
	header   http.Header
	validate RESTRequestValidator
}

// Method returns the validated HTTP method.
func (r *PreparedRESTRequest) Method() string {
	if r == nil {
		return ""
	}
	return r.method
}

// URL returns the validated target URL.
func (r *PreparedRESTRequest) URL() *url.URL {
	if r == nil || r.url == nil {
		return nil
	}
	copy := *r.url
	return &copy
}

// Body returns a copy of the validated request body.
func (r *PreparedRESTRequest) Body() []byte {
	if r == nil {
		return nil
	}
	return bytes.Clone(r.body)
}

// SetAuthorization attaches a token only as an Authorization header.
func (r *PreparedRESTRequest) SetAuthorization(token string) {
	if r == nil {
		return
	}
	r.header.Set("Authorization", token)
}

// PrepareRESTRequest renders a REST request and validates its complete target before execution.
func PrepareRESTRequest(method, urlTemplate string, bodyTemplate map[string]any, values map[string]any, validate RESTRequestValidator) (*PreparedRESTRequest, error) {
	if validate == nil {
		return nil, fmt.Errorf("REST request validator is required")
	}
	renderedURL, err := RenderURL(urlTemplate, values)
	if err != nil {
		return nil, fmt.Errorf("render REST URL: %w", err)
	}
	renderedBody, err := renderBody(bodyTemplate, values)
	if err != nil {
		return nil, fmt.Errorf("render REST body: %w", err)
	}
	if err := validate(method, renderedURL, renderedBody); err != nil {
		return nil, err
	}
	parsedURL, err := url.Parse(renderedURL)
	if err != nil {
		return nil, fmt.Errorf("prepare REST request: %w", err)
	}
	request := &PreparedRESTRequest{method: method, url: parsedURL, body: bytes.Clone(renderedBody), header: make(http.Header), validate: validate}
	if bodyTemplate != nil {
		request.header.Set("Content-Type", "application/json")
	}
	return request, nil
}

func renderBody(body map[string]any, values map[string]any) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	rendered, err := renderBodyValue(body, values)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(rendered)
	if err != nil {
		return nil, fmt.Errorf("encode REST body: %w", err)
	}
	return encoded, nil
}

func renderBodyValue(value any, values map[string]any) (any, error) {
	switch value := value.(type) {
	case string:
		return renderBodyString(value, values)
	case map[string]any:
		rendered := make(map[string]any, len(value))
		for key, item := range value {
			renderedKey, err := renderBodyString(key, values)
			if err != nil {
				return nil, err
			}
			if _, exists := rendered[renderedKey]; exists {
				return nil, fmt.Errorf("rendered REST body has duplicate object keys")
			}
			renderedItem, err := renderBodyValue(item, values)
			if err != nil {
				return nil, err
			}
			rendered[renderedKey] = renderedItem
		}
		return rendered, nil
	case []any:
		rendered := make([]any, len(value))
		for index, item := range value {
			renderedItem, err := renderBodyValue(item, values)
			if err != nil {
				return nil, err
			}
			rendered[index] = renderedItem
		}
		return rendered, nil
	default:
		switch value.(type) {
		case nil, bool, int, int8, int16, int32, int64,
			uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
			return value, nil
		default:
			return nil, fmt.Errorf("REST body contains unsupported value type %T", value)
		}
	}
}

func renderBodyString(value string, values map[string]any) (string, error) {
	if !strings.Contains(value, "{{") && !strings.Contains(value, "}}") {
		return value, nil
	}
	var rendered strings.Builder
	for offset := 0; offset < len(value); {
		start := strings.Index(value[offset:], "{{")
		closeBefore := strings.Index(value[offset:], "}}")
		if closeBefore >= 0 && (start < 0 || closeBefore < start) {
			return "", fmt.Errorf("malformed REST body template")
		}
		if start < 0 {
			rendered.WriteString(value[offset:])
			break
		}
		start += offset
		endOffset := strings.Index(value[start+2:], "}}")
		if endOffset < 0 {
			return "", fmt.Errorf("unterminated REST body template action")
		}
		end := start + 2 + endOffset + 2
		rendered.WriteString(value[offset:start])
		action, err := renderScalarAction(value[start:end], values)
		if err != nil {
			return "", fmt.Errorf("render REST body value: %w", err)
		}
		rendered.WriteString(action)
		offset = end
	}
	return rendered.String(), nil
}
