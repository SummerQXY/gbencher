package collect_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/failure"
)

type testTokenSource struct {
	mu          sync.Mutex
	tokens      []string
	index       int
	invalidated []string
}

func (s *testTokenSource) Token(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.index
	if i >= len(s.tokens) {
		i = len(s.tokens) - 1
	}
	s.index++
	return s.tokens[i], nil
}

func (s *testTokenSource) InvalidateToken(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalidated = append(s.invalidated, token)
	return true
}

func TestRESTClient_UsesPinnedTokenAndOptionalQuota(t *testing.T) {
	t.Run("omitted quota", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer pinned-token" {
				t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
			}
			if got := r.Header.Get("X-Goog-User-Project"); got != "" {
				t.Errorf("quota header = %q, want omitted", got)
			}
			_, _ = io.WriteString(w, `{"items":[]}`)
		}))
		defer server.Close()
		source := &testTokenSource{tokens: []string{"pinned-token"}}
		if _, err := collect.NewRESTClient(time.Second, 1024, server.Client().Transport).DoAuthenticated(context.Background(), prepareLocalREST(t, server.URL), source, ""); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("distinct quota project", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("X-Goog-User-Project"); got != "billing-project" {
				t.Errorf("quota header = %q", got)
			}
			_, _ = io.WriteString(w, `{"items":[]}`)
		}))
		defer server.Close()
		source := &testTokenSource{tokens: []string{"pinned-token"}}
		if _, err := collect.NewRESTClient(time.Second, 1024, server.Client().Transport).DoAuthenticated(context.Background(), prepareLocalREST(t, server.URL), source, "billing-project"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRESTClient_RefreshesOnceAfter401(t *testing.T) {
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("Authorization"); got != []string{"Bearer old", "Bearer new"}[calls-1] {
			t.Errorf("request %d token = %q", calls, got)
		}
		if calls == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer server.Close()
	source := &testTokenSource{tokens: []string{"old", "new"}}
	if _, err := collect.NewRESTClient(time.Second, 1024, server.Client().Transport).DoAuthenticated(context.Background(), prepareLocalREST(t, server.URL), source, ""); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !reflect.DeepEqual(source.invalidated, []string{"old"}) {
		t.Fatalf("calls=%d invalidated=%v", calls, source.invalidated)
	}
}

func TestRESTClient_RejectsInvalidPreparedRequestBeforeToken(t *testing.T) {
	for _, prepared := range []*collect.PreparedRESTRequest{nil, {}} {
		source := &testTokenSource{tokens: []string{"fixed"}}
		var transportCalls int
		transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
			transportCalls++
			return nil, fmt.Errorf("unexpected transport call")
		})
		_, err := collect.NewRESTClient(time.Second, 1024, transport).DoAuthenticated(context.Background(), prepared, source, "")
		if err == nil {
			t.Fatal("DoAuthenticated() error = nil, want invalid prepared request")
		}
		if source.index != 0 {
			t.Fatalf("token calls=%d, want 0", source.index)
		}
		if transportCalls != 0 {
			t.Fatalf("transport calls=%d, want 0", transportCalls)
		}
	}
}

func TestRESTClient_RejectsEmptyTokenBeforeHTTP(t *testing.T) {
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; _, _ = io.WriteString(w, `{}`) }))
	defer server.Close()
	source := &testTokenSource{tokens: []string{""}}
	_, err := collect.NewRESTClient(time.Second, 1024, server.Client().Transport).DoAuthenticated(context.Background(), prepareLocalREST(t, server.URL), source, "")
	if err == nil {
		t.Fatal("DoAuthenticated() error = nil, want empty-token error")
	}
	if calls != 0 {
		t.Fatalf("HTTP calls=%d, want 0", calls)
	}
}

func TestRESTClient_401AndTransientRetriesShareAttemptLimit(t *testing.T) {
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			w.WriteHeader(http.StatusUnauthorized)
		case 2:
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	source := &testTokenSource{tokens: []string{"old", "new"}}
	_, err := collect.NewRESTClient(3*time.Second, 1024, server.Client().Transport).DoAuthenticated(context.Background(), prepareLocalREST(t, server.URL), source, "")
	assertFailureClass(t, err, failure.ServerError)
	if calls != 4 {
		t.Fatalf("HTTP calls=%d, want 4", calls)
	}
	if source.index != 4 {
		t.Fatalf("token calls=%d, want no token acquisition after final attempt", source.index)
	}
}

func TestRESTClient_RetriesTransientResponses(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls int
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls < 4 {
					w.WriteHeader(status)
					return
				}
				_, _ = io.WriteString(w, `{"ok":true}`)
			}))
			defer server.Close()
			source := &testTokenSource{tokens: []string{"fixed"}}
			if _, err := collect.NewRESTClient(3*time.Second, 1024, server.Client().Transport).DoAuthenticated(context.Background(), prepareLocalREST(t, server.URL), source, ""); err != nil {
				t.Fatal(err)
			}
			if calls != 4 {
				t.Fatalf("requests=%d, want 4", calls)
			}
		})
	}
}

func TestRESTClient_DoesNotRetryOtherClientErrors(t *testing.T) {
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(http.StatusBadRequest) }))
	defer server.Close()
	_, err := collect.NewRESTClient(time.Second, 1024, server.Client().Transport).DoAuthenticated(context.Background(), prepareLocalREST(t, server.URL), &testTokenSource{tokens: []string{"fixed"}}, "")
	assertFailureClass(t, err, failure.Unknown)
	if calls != 1 {
		t.Fatalf("requests=%d, want 1", calls)
	}
}

func TestRESTClient_PaginatesWithoutEscapingScope(t *testing.T) {
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			if r.URL.Query().Get("pageToken") != "" {
				t.Errorf("first page has token")
			}
			_, _ = io.WriteString(w, `{"items":[1],"nextPageToken":"two"}`)
		case 2:
			if r.URL.Query().Get("pageToken") != "two" {
				t.Errorf("second page token = %q", r.URL.Query().Get("pageToken"))
			}
			_, _ = io.WriteString(w, `{"items":[2]}`)
		}
	}))
	defer server.Close()
	guardCalls := 0
	prepared, err := collect.PrepareRESTRequest("GET", server.URL+"/projects/target/items", nil, nil, func(method, rawURL string, _ []byte) error {
		guardCalls++
		if !strings.Contains(rawURL, "/projects/target/") {
			return fmt.Errorf("scope escaped")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	source := &testTokenSource{tokens: []string{"fixed"}}
	result, err := collect.NewRESTClient(time.Second, 1024, server.Client().Transport).DoPaginated(context.Background(), prepared, source, "", "items", 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	object := result.Value.(map[string]any)
	if got := object["items"].([]any); len(got) != 2 || got[0] != int64(1) || got[1] != int64(2) {
		t.Fatalf("items=%#v", got)
	}
	if guardCalls != 4 {
		t.Fatalf("guard calls=%d, want preparation, execution and next-page validation", guardCalls)
	}
}

func TestRESTClient_PaginatedResponseAllowsOmittedEmptyListField(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"kind":"bigquery#datasetList","etag":"stable"}`)
	}))
	defer server.Close()
	prepared := prepareLocalREST(t, server.URL)
	result, err := collect.NewRESTClient(time.Second, 1024, server.Client().Transport).DoPaginated(context.Background(), prepared, &testTokenSource{tokens: []string{"fixed"}}, "", "datasets", 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	object, ok := result.Value.(map[string]any)
	if !ok {
		t.Fatalf("value type = %T, want object", result.Value)
	}
	if object["kind"] != "bigquery#datasetList" || object["etag"] != "stable" {
		t.Fatalf("response metadata changed: %#v", object)
	}
	datasets, ok := object["datasets"].([]any)
	if !ok || len(datasets) != 0 {
		t.Fatalf("datasets = %#v, want empty array", object["datasets"])
	}
}

func TestRESTClient_PaginationRejectsRepeatedTokensAndLimits(t *testing.T) {
	t.Run("repeated token", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"items":[1],"nextPageToken":"again"}`)
		}))
		defer server.Close()
		prepared := prepareLocalREST(t, server.URL)
		_, err := collect.NewRESTClient(time.Second, 1024, server.Client().Transport).DoPaginated(context.Background(), prepared, &testTokenSource{tokens: []string{"fixed"}}, "", "items", 10, 10)
		assertFailureClass(t, err, failure.Parse)
	})
	t.Run("page limit", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"items":[],"nextPageToken":"next"}`)
		}))
		defer server.Close()
		prepared := prepareLocalREST(t, server.URL)
		_, err := collect.NewRESTClient(time.Second, 1024, server.Client().Transport).DoPaginated(context.Background(), prepared, &testTokenSource{tokens: []string{"fixed"}}, "", "items", 1, 10)
		assertFailureClass(t, err, failure.OutputTooLarge)
	})
	t.Run("item limit", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"items":[1,2]}`)
		}))
		defer server.Close()
		prepared := prepareLocalREST(t, server.URL)
		_, err := collect.NewRESTClient(time.Second, 1024, server.Client().Transport).DoPaginated(context.Background(), prepared, &testTokenSource{tokens: []string{"fixed"}}, "", "items", 10, 1)
		assertFailureClass(t, err, failure.OutputTooLarge)
	})
}

func TestRESTClient_PaginationRejectsMalformedShape(t *testing.T) {
	for _, body := range []string{
		`{"items":[],"nextPageToken":17}`,
		`{"nextPageToken":"next"}`,
		`{"items":"not-an-array"}`,
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
		prepared := prepareLocalREST(t, server.URL)
		_, err := collect.NewRESTClient(time.Second, 1024, server.Client().Transport).DoPaginated(context.Background(), prepared, &testTokenSource{tokens: []string{"fixed"}}, "", "items", 10, 10)
		server.Close()
		assertFailureClass(t, err, failure.Parse)
	}
}

func TestRESTClient_PaginationRejectsExpandedByteLimit(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"kind":"x"}`)
	}))
	defer server.Close()
	prepared := prepareLocalREST(t, server.URL)
	_, err := collect.NewRESTClient(time.Second, 16, server.Client().Transport).DoPaginated(context.Background(), prepared, &testTokenSource{tokens: []string{"fixed"}}, "", "datasets", 10, 10)
	assertFailureClass(t, err, failure.OutputTooLarge)
}

func TestRESTClient_ClassifiesStructuredForbiddenErrors(t *testing.T) {
	for _, test := range []struct {
		status string
		want   failure.Class
	}{
		{"SERVICE_DISABLED", failure.ServiceDisabled},
		{"FAILED_PRECONDITION", failure.FailedPrecondition},
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":{"status":"`+test.status+`","message":"sensitive response text"}}`)
		}))
		prepared := prepareLocalREST(t, server.URL)
		_, err := collect.NewRESTClient(time.Second, 1024, server.Client().Transport).Do(context.Background(), prepared)
		server.Close()
		assertFailureClass(t, err, test.want)
		if strings.Contains(fmt.Sprint(err), "sensitive") {
			t.Fatalf("error leaked response body: %v", err)
		}
	}
}

func TestRESTClient_DoesNotFollowRedirect(t *testing.T) {
	var redirectedAuth string
	second := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer second.Close()
	first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			t.Errorf("first request Authorization = %q, want prepared token", r.Header.Get("Authorization"))
		}
		http.Redirect(w, r, second.URL, http.StatusFound)
	}))
	defer first.Close()

	prepared := prepareLocalREST(t, first.URL)
	prepared.SetAuthorization("Bearer secret-token")
	client := collect.NewRESTClient(time.Second, 1024, first.Client().Transport)
	result, err := client.Do(context.Background(), prepared)
	if err == nil || result != nil {
		t.Fatalf("Do() = (%v, %v), want redirect failure", result, err)
	}
	if redirectedAuth != "" {
		t.Fatalf("redirected request carried Authorization %q", redirectedAuth)
	}
}

func TestRESTClient_BoundsBodyAndTime(t *testing.T) {
	t.Run("body", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"long":"123456789"}`)
		}))
		defer server.Close()
		client := collect.NewRESTClient(time.Second, 8, server.Client().Transport)
		_, err := client.Do(context.Background(), prepareLocalREST(t, server.URL))
		assertFailureClass(t, err, failure.OutputTooLarge)
	})
	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer server.Close()
		client := collect.NewRESTClient(20*time.Millisecond, 1024, server.Client().Transport)
		_, err := client.Do(context.Background(), prepareLocalREST(t, server.URL))
		assertFailureClass(t, err, failure.Timeout)
	})
}

func TestRESTClient_ClassifiesStatusAndJSON(t *testing.T) {
	tests := []struct {
		name string
		code int
		body string
		want failure.Class
	}{
		{"forbidden", http.StatusForbidden, `{"error":"secret"}`, failure.Permission},
		{"not found", http.StatusNotFound, `{"error":"secret"}`, failure.NotFound},
		{"rate limited", http.StatusTooManyRequests, `{"error":"secret"}`, failure.RateLimited},
		{"server error", http.StatusServiceUnavailable, `{"error":"secret"}`, failure.ServerError},
		{"malformed success", http.StatusOK, `{broken`, failure.Parse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.code)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			prepared := prepareLocalREST(t, server.URL)
			prepared.SetAuthorization("Bearer diagnostic-secret")
			_, err := collect.NewRESTClient(time.Second, 1024, server.Client().Transport).Do(context.Background(), prepared)
			assertFailureClass(t, err, test.want)
			if strings.Contains(fmt.Sprint(err), "secret") || strings.Contains(fmt.Sprint(err), "diagnostic-secret") {
				t.Fatalf("diagnostic leaked response body: %v", err)
			}
		})
	}
	t.Run("valid success", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"ok":true,"count":2}`)
		}))
		defer server.Close()
		result, err := collect.NewRESTClient(time.Second, 1024, server.Client().Transport).Do(context.Background(), prepareLocalREST(t, server.URL))
		if err != nil || result == nil || result.StatusCode != http.StatusOK {
			t.Fatalf("Do() = (%v, %v), want a successful decoded response", result, err)
		}
		if result.Value.(map[string]any)["ok"] != true {
			t.Fatalf("decoded response = %#v, want ok=true", result.Value)
		}
	})
}

func TestRESTClient_CancelStopsRequest(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := collect.NewRESTClient(time.Second, 1024, server.Client().Transport).Do(ctx, prepareLocalREST(t, server.URL))
		done <- err
	}()
	<-started
	cancel()
	assertFailureClass(t, <-done, failure.Timeout)
}

func prepareLocalREST(t *testing.T, rawURL string) *collect.PreparedRESTRequest {
	t.Helper()
	prepared, err := collect.PrepareRESTRequest("GET", rawURL, nil, nil, func(method, url string, body []byte) error {
		if !strings.HasPrefix(url, "https://127.0.0.1:") && !strings.HasPrefix(url, "https://[::1]:") {
			return fmt.Errorf("unexpected local test target")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func assertFailureClass(t *testing.T, err error, want failure.Class) {
	t.Helper()
	got, ok := failure.As(err)
	if !ok || got.Class != want {
		t.Fatalf("failure = (%v, %v), want class %q", got, ok, want)
	}
}
