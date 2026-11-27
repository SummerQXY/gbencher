package collect_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/plan"
	"github.com/SummerQXY/gbencher/internal/rule"
)

func TestRESTRequest_RejectsUnsafeRenderedTargets(t *testing.T) {
	guard := testRESTGuard(t)
	target := plan.Target{Type: "project", ProjectID: "example-prod"}
	tests := []struct {
		name   string
		method string
		url    string
		values map[string]any
	}{
		{"wrong project path", "GET", "https://bigquery.googleapis.com/projects/{{ .project }}/datasets", map[string]any{"project": "other"}},
		{"dot segment changes project path", "GET", "https://bigquery.googleapis.com/v2/projects/example-prod/../other/datasets", nil},
		{"encoded dot segment changes project path", "GET", "https://bigquery.googleapis.com/v2/projects/example-prod/%2e%2e/other/datasets", nil},
		{"multiply encoded dot segment changes project path", "GET", "https://bigquery.googleapis.com/v2/projects/example-prod/%252e%252e/other/datasets", nil},
		{"encoded cross project path separator", "GET", "https://bigquery.googleapis.com/projects%2Fother/datasets", nil},
		{"wrong project query", "GET", "https://bigquery.googleapis.com/v1?parent=projects%2F{{ .project }}", map[string]any{"project": "other"}},
		{"encoded separator", "GET", "https://bigquery.googleapis.com/%70rojects/{{ .project }}/datasets", map[string]any{"project": "other"}},
		{"malformed query", "GET", "https://bigquery.googleapis.com/projects/example-prod?x=%ZZ", nil},
		{"host lookalike", "GET", "https://bigquery.googleapis.com.example.test/projects/example-prod", nil},
		{"userinfo", "GET", "https://user@bigquery.googleapis.com/projects/example-prod", nil},
		{"port", "GET", "https://bigquery.googleapis.com:443/projects/example-prod", nil},
		{"non HTTPS", "GET", "http://bigquery.googleapis.com/projects/example-prod", nil},
		{"forbidden method", "DELETE", "https://bigquery.googleapis.com/projects/example-prod", nil},
		{"POST without approved suffix", "POST", "https://bigquery.googleapis.com/projects/example-prod", nil},
		{"control character in value", "GET", "https://bigquery.googleapis.com/projects/{{ .project }}/datasets", map[string]any{"project": "example-prod\n"}},
		{"option shaped value", "GET", "https://bigquery.googleapis.com/projects/{{ .project }}/datasets", map[string]any{"project": "--project=other"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transportCalls := 0
			if err := fakeRESTBoundary(guard, target, test.method, test.url, nil, test.values, func(*http.Request) {
				transportCalls++
			}); err == nil {
				t.Fatal("request was accepted, want rejection")
			}
			if transportCalls != 0 {
				t.Fatalf("fake transport called %d times after rejection", transportCalls)
			}
		})
	}
}

func TestRESTRequest_RejectsUnsafeBody(t *testing.T) {
	guard := testRESTGuard(t)
	target := plan.Target{Type: "project", ProjectID: "example-prod"}
	tests := []struct {
		name   string
		body   map[string]any
		values map[string]any
	}{
		{"cross project resource reference", map[string]any{"parent": "projects/other"}, nil},
		{"encoded cross project reference", map[string]any{"parent": "projects%2Fother"}, nil},
		{"deeply encoded cross project reference", map[string]any{"parent": "projects%252525252Fother"}, nil},
		{"rendered cross project resource reference", map[string]any{"parent": "projects/{{ .resource }}"}, map[string]any{"resource": "other"}},
		{"unrenderable template value", map[string]any{"parent": "projects/{{ .resource }}"}, map[string]any{"resource": []string{"projects/other"}}},
		{"unsupported body value", map[string]any{"value": make(chan int)}, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transportCalls := 0
			if err := fakeRESTBoundary(guard, target, "POST", "https://bigquery.googleapis.com/projects/example-prod:search", test.body, test.values, func(*http.Request) {
				transportCalls++
			}); err == nil {
				t.Fatal("request was accepted, want rejection")
			}
			if transportCalls != 0 {
				t.Fatalf("fake transport called %d times after rejection", transportCalls)
			}
		})
	}
}

func TestRESTRequest_AllowsBoundProjectAndApprovedHost(t *testing.T) {
	guard := testRESTGuard(t)
	target := plan.Target{Type: "project", ProjectID: "example-prod"}
	values := map[string]any{"project": "example-prod", "dataset": "analytics"}
	body := map[string]any{"parent": "projects/{{ .project }}", "dataset": "{{ .dataset }}"}
	request, err := collect.PrepareRESTRequest("POST", "https://bigquery.googleapis.com/bigquery/v2/projects/{{ .project }}/datasets:search", body, values, validateRESTRequest(guard, target))
	if err != nil {
		t.Fatalf("PrepareRESTRequest() rejected safe request: %v", err)
	}
	if request.Method() != "POST" || request.URL().Host != "bigquery.googleapis.com" {
		t.Fatalf("request method/host = %s/%s, want POST/bigquery.googleapis.com", request.Method(), request.URL().Host)
	}
	encoded := request.Body()
	if !strings.Contains(string(encoded), `"parent":"projects/example-prod"`) || !strings.Contains(string(encoded), `"dataset":"analytics"`) {
		t.Fatalf("rendered body = %s, missing rendered fields", encoded)
	}
}

func TestRESTRequest_RequiresValidator(t *testing.T) {
	request, err := collect.PrepareRESTRequest("GET", "https://bigquery.googleapis.com/projects/example-prod", nil, nil, nil)
	if err == nil || request != nil {
		t.Fatalf("PrepareRESTRequest() = (%v, %v), want nil request and validation error", request, err)
	}
}

func fakeRESTBoundary(guard plan.Guard, target plan.Target, method, rawURL string, body map[string]any, values map[string]any, transport func(*http.Request)) error {
	request, err := collect.PrepareRESTRequest(method, rawURL, body, values, validateRESTRequest(guard, target))
	if err != nil {
		return err
	}
	client := collect.NewRESTClient(0, 1<<20, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		transport(r)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: r}, nil
	}))
	_, err = client.Do(context.Background(), request)
	return err
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func validateRESTRequest(guard plan.Guard, target plan.Target) collect.RESTRequestValidator {
	return func(method, rawURL string, body []byte) error {
		return guard.CheckAPIRequest(method, rawURL, body, target)
	}
}

func testRESTGuard(t *testing.T) plan.Guard {
	t.Helper()
	allow, err := rule.LoadAllowlist()
	if err != nil {
		t.Fatal(err)
	}
	return plan.Guard{Allow: allow}
}
