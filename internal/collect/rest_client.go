package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/SummerQXY/gbencher/internal/failure"
)

// RESTResult contains a decoded successful response and its HTTP status.
type RESTResult struct {
	StatusCode int
	Value      any
}

// RESTClient executes guarded REST requests with bounded time and response size.
type RESTClient struct {
	client  *http.Client
	timeout time.Duration
	maxBody int64
}

// RESTTokenSource supplies and invalidates the token for one scan identity.
type RESTTokenSource interface {
	Token(context.Context) (string, error)
	InvalidateToken(string) bool
}

// NewRESTClient creates a client with an injectable transport. Redirects are never followed.
func NewRESTClient(timeout time.Duration, maxBodyBytes int64, transport http.RoundTripper) *RESTClient {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	if maxBodyBytes <= 0 {
		maxBodyBytes = 64 << 20
	}
	return &RESTClient{
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		timeout: timeout,
		maxBody: maxBodyBytes,
	}
}

// Do executes a prepared request. Arbitrary http.Request values cannot cross this boundary.
func (c *RESTClient) Do(ctx context.Context, prepared *PreparedRESTRequest) (*RESTResult, error) {
	return c.do(ctx, prepared, "", "")
}

// DoAuthenticated applies the scan identity, optional quota project, bounded auth refresh and transient retries.
func (c *RESTClient) DoAuthenticated(ctx context.Context, prepared *PreparedRESTRequest, identity RESTTokenSource, quotaProject string) (*RESTResult, error) {
	if identity == nil {
		return nil, newFailure(failure.GuardRejected, "REST token source is required", 0)
	}
	if c == nil {
		return nil, newFailure(failure.GuardRejected, "REST client is required", 0)
	}
	if !validPreparedRESTRequest(prepared) {
		return nil, newFailure(failure.GuardRejected, "prepared REST request is invalid", 0)
	}
	requestContext, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if !safeHeaderValue(quotaProject) {
		return nil, newFailure(failure.GuardRejected, "REST quota project header is invalid", 0)
	}
	refreshed := false
	attempts := 0
	for {
		if attempts >= 4 {
			return nil, newFailure(failure.Unknown, "REST request attempt limit was reached", 0)
		}
		if err := requestContext.Err(); err != nil {
			return nil, newFailure(failure.Timeout, "REST request was canceled or timed out", 0)
		}
		token, err := identity.Token(requestContext)
		if err != nil {
			return nil, newFailure(failure.AuthExpired, "REST token acquisition failed", 0)
		}
		if token == "" || !safeHeaderValue(token) {
			return nil, newFailure(failure.AuthExpired, "REST token is invalid", 0)
		}
		attempts++
		result, status, requestErr := c.doStatus(requestContext, prepared, token, quotaProject)
		if status == http.StatusUnauthorized && !refreshed {
			if attempts >= 4 {
				return result, requestErr
			}
			identity.InvalidateToken(token)
			refreshed = true
			continue
		}
		if (status == http.StatusTooManyRequests || status >= http.StatusInternalServerError) && attempts < 4 {
			delay := time.Duration(100*(1<<min(attempts-1, 3))) * time.Millisecond
			timer := time.NewTimer(delay)
			select {
			case <-requestContext.Done():
				timer.Stop()
				return nil, newFailure(failure.Timeout, "REST request was canceled or timed out", 0)
			case <-timer.C:
			}
			continue
		}
		return result, requestErr
	}
}

func validPreparedRESTRequest(prepared *PreparedRESTRequest) bool {
	if prepared == nil || prepared.method == "" || prepared.url == nil || prepared.validate == nil {
		return false
	}
	return prepared.validate(prepared.method, prepared.url.String(), prepared.body) == nil
}

// DoPaginated collects a bounded Google-style list response and returns its list_field shape.
func (c *RESTClient) DoPaginated(ctx context.Context, prepared *PreparedRESTRequest, identity RESTTokenSource, quotaProject, listField string, maxPages, maxItems int) (*RESTResult, error) {
	if listField == "" {
		return nil, newFailure(failure.Parse, "REST list field is required", 0)
	}
	if maxPages <= 0 {
		maxPages = 100
	}
	if maxItems <= 0 {
		maxItems = 100000
	}
	if maxPages > 1000 {
		maxPages = 1000
	}
	if maxItems > 1000000 {
		maxItems = 1000000
	}
	if prepared == nil || prepared.url == nil || prepared.validate == nil {
		return nil, newFailure(failure.GuardRejected, "prepared REST request is required", 0)
	}
	if c == nil {
		return nil, newFailure(failure.GuardRejected, "REST client is required", 0)
	}
	requestContext, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	items := make([]any, 0)
	seen := make(map[string]struct{})
	pageRequest := prepared
	var status int
	for page := 0; page < maxPages; page++ {
		result, err := c.DoAuthenticated(requestContext, pageRequest, identity, quotaProject)
		if err != nil {
			return nil, err
		}
		status = result.StatusCode
		object, ok := result.Value.(map[string]any)
		if !ok {
			return nil, newFailure(failure.Parse, "REST paginated response must be an object", 0)
		}
		pageToken, tokenExists := object["nextPageToken"]
		var token string
		if tokenExists {
			var ok bool
			token, ok = pageToken.(string)
			if !ok {
				return nil, newFailure(failure.Parse, "REST pagination token is not a string", 0)
			}
		}
		pageItemsValue, listFieldExists := object[listField]
		var pageItems []any
		if !listFieldExists && !tokenExists {
			pageItems = []any{}
			object[listField] = pageItems
		} else if pageItems, ok = pageItemsValue.([]any); !ok {
			return nil, newFailure(failure.Parse, "REST paginated response has an invalid list field", 0)
		}
		if len(items)+len(pageItems) > maxItems {
			return nil, newFailure(failure.OutputTooLarge, "REST paginated output exceeds the item limit", 0)
		}
		items = append(items, pageItems...)
		object[listField] = items
		partial, marshalErr := json.Marshal(object)
		if marshalErr != nil || int64(len(partial)) > c.maxBody {
			return nil, newFailure(failure.OutputTooLarge, "REST paginated output exceeds the configured byte limit", 0)
		}
		if tokenExists {
			if token == "" {
				object[listField] = items
				delete(object, "nextPageToken")
				return &RESTResult{StatusCode: status, Value: object}, nil
			}
		}
		if !tokenExists {
			object[listField] = items
			delete(object, "nextPageToken")
			return &RESTResult{StatusCode: status, Value: object}, nil
		}
		if _, exists := seen[token]; exists {
			return nil, newFailure(failure.Parse, "REST pagination returned a repeated page token", 0)
		}
		seen[token] = struct{}{}
		if page+1 == maxPages {
			return nil, newFailure(failure.OutputTooLarge, "REST pagination exceeds the page limit", 0)
		}
		pageRequest, err = pageRequestWithToken(prepared, token)
		if err != nil {
			return nil, newFailure(failure.GuardRejected, "REST pagination target was rejected", 0)
		}
	}
	return nil, newFailure(failure.OutputTooLarge, "REST pagination exceeds the page limit", 0)
}

func pageRequestWithToken(prepared *PreparedRESTRequest, token string) (*PreparedRESTRequest, error) {
	copyURL := *prepared.url
	query := copyURL.Query()
	query.Set("pageToken", token)
	copyURL.RawQuery = query.Encode()
	if err := prepared.validate(prepared.method, copyURL.String(), prepared.body); err != nil {
		return nil, err
	}
	copyRequest := *prepared
	copyRequest.url = &copyURL
	copyRequest.header = prepared.header.Clone()
	return &copyRequest, nil
}

func safeHeaderValue(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (c *RESTClient) do(ctx context.Context, prepared *PreparedRESTRequest, token, quotaProject string) (*RESTResult, error) {
	result, _, err := c.doStatus(ctx, prepared, token, quotaProject)
	return result, err
}

func (c *RESTClient) doStatus(ctx context.Context, prepared *PreparedRESTRequest, token, quotaProject string) (*RESTResult, int, error) {
	if c == nil || c.client == nil || prepared == nil || prepared.url == nil {
		return nil, 0, newFailure(failure.GuardRejected, "prepared REST request is required", 0)
	}
	requestContext, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var body io.Reader
	if prepared.body != nil {
		body = bytes.NewReader(prepared.body)
	}
	request, err := http.NewRequestWithContext(requestContext, prepared.method, prepared.url.String(), body)
	if err != nil {
		return nil, 0, newFailure(failure.GuardRejected, "prepared REST request is invalid", 0)
	}
	request.Header = prepared.header.Clone()
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if quotaProject != "" {
		request.Header.Set("X-Goog-User-Project", quotaProject)
	}
	response, err := c.client.Do(request)
	if err != nil {
		if errors.Is(requestContext.Err(), context.DeadlineExceeded) || errors.Is(requestContext.Err(), context.Canceled) {
			return nil, 0, newFailure(failure.Timeout, "REST request was canceled or timed out", 0)
		}
		return nil, 0, newFailure(failure.Unknown, "REST request failed", 0)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, c.maxBody+1))
	if err != nil {
		if errors.Is(requestContext.Err(), context.DeadlineExceeded) || errors.Is(requestContext.Err(), context.Canceled) {
			return nil, response.StatusCode, newFailure(failure.Timeout, "REST response was canceled or timed out", 0)
		}
		return nil, response.StatusCode, newFailure(failure.Unknown, "REST response could not be read", 0)
	}
	if int64(len(data)) > c.maxBody {
		return nil, response.StatusCode, newFailure(failure.OutputTooLarge, "REST response exceeds the configured byte limit", 0)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, response.StatusCode, classifyRESTResponse(response.StatusCode, data)
	}
	value, err := DecodeJSON(data)
	if err != nil {
		return nil, response.StatusCode, newFailure(failure.Parse, "REST response contains invalid JSON", 0)
	}
	return &RESTResult{StatusCode: response.StatusCode, Value: value}, response.StatusCode, nil
}

func classifyRESTStatus(status int) *failure.Failure {
	class := failure.Unknown
	switch status {
	case http.StatusForbidden:
		class = failure.Permission
	case http.StatusNotFound:
		class = failure.NotFound
	case http.StatusTooManyRequests:
		class = failure.RateLimited
	default:
		if status >= http.StatusInternalServerError {
			class = failure.ServerError
		}
	}
	return newFailure(class, fmt.Sprintf("REST request returned HTTP status %d", status), 0)
}

func classifyRESTResponse(status int, body []byte) *failure.Failure {
	if status == http.StatusForbidden {
		var payload struct {
			Error struct {
				Status string `json:"status"`
				Errors []struct {
					Reason string `json:"reason"`
				} `json:"errors"`
				Details []struct {
					Reason string `json:"reason"`
				} `json:"details"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &payload) == nil {
			switch payload.Error.Status {
			case "SERVICE_DISABLED":
				return newFailure(failure.ServiceDisabled, "REST API service is disabled", 0)
			case "FAILED_PRECONDITION":
				return newFailure(failure.FailedPrecondition, "REST request failed precondition", 0)
			}
			for _, reason := range append(payload.Error.Errors, payload.Error.Details...) {
				switch reason.Reason {
				case "SERVICE_DISABLED":
					return newFailure(failure.ServiceDisabled, "REST API service is disabled", 0)
				case "FAILED_PRECONDITION":
					return newFailure(failure.FailedPrecondition, "REST request failed precondition", 0)
				}
			}
		}
	}
	return classifyRESTStatus(status)
}
