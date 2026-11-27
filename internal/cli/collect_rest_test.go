package cli_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/cli"
	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/collecttest"
	"github.com/SummerQXY/gbencher/internal/engine"
	"github.com/SummerQXY/gbencher/internal/rule"
)

type rewriteTransport struct {
	base  *url.URL
	inner http.RoundTripper
}

func (r rewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.URL = new(url.URL)
	*copy.URL = *request.URL
	copy.URL.Scheme = r.base.Scheme
	copy.URL.Host = r.base.Host
	copy.Host = r.base.Host
	return r.inner.RoundTrip(copy)
}

func withRESTTransport(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	previous := http.DefaultTransport
	http.DefaultTransport = rewriteTransport{base: parsed, inner: server.Client().Transport}
	t.Cleanup(func() {
		http.DefaultTransport = previous
		server.Close()
	})
	return server
}

func restCollectEnv(t *testing.T) []string {
	t.Helper()
	dir := collecttest.FakeGcloud(t, `case "$*" in
  "--version"*) echo "Google Cloud SDK 1.2.3" ;;
  *"auth print-access-token"*) echo "test-access-token" ;;
  *) echo 'unexpected command' >&2; exit 1 ;;
esac`)
	return []string{"PATH=" + collecttest.PathWith(dir)}
}

func restCollectEnvWithConfiguredAccount(t *testing.T, account string) []string {
	t.Helper()
	dir := collecttest.FakeGcloud(t, fmt.Sprintf(`case "$*" in
  "--version"*) echo "Google Cloud SDK 1.2.3" ;;
  *"config get account"*) echo %q ;;
  *"auth print-access-token"*) echo "test-access-token" ;;
  *) echo 'unexpected command' >&2; exit 1 ;;
esac`, account))
	return []string{"PATH=" + collecttest.PathWith(dir)}
}

func TestCollect_RESTStepUsesScopeGuard(t *testing.T) {
	var calls int
	var authorization, quota string
	withRESTTransport(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/bigquery/v2/projects/example-prod/datasets" {
			t.Errorf("request path = %q", r.URL.Path)
		}
		authorization = r.Header.Get("Authorization")
		quota = r.Header.Get("X-Goog-User-Project")
		_, _ = io.WriteString(w, `{"datasets":[]}`)
	})
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"collect", "--rule=cis-gcp-7.1", "--project=example-prod", "--step=datasets", "--account=scanner@example.com"}, nil, &stdout, &stderr, restCollectEnv(t))
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if calls != 1 {
		t.Fatalf("HTTP calls = %d, want 1", calls)
	}
	if authorization != "Bearer test-access-token" {
		t.Fatalf("Authorization = %q", authorization)
	}
	if quota != "" {
		t.Fatalf("quota header = %q, want omitted", quota)
	}
	if strings.Contains(stdout.String(), "test-access-token") || strings.Contains(stderr.String(), "test-access-token") {
		t.Fatal("token leaked to command output")
	}
	var secondQuota string
	withRESTTransport(t, func(w http.ResponseWriter, r *http.Request) {
		secondQuota = r.Header.Get("X-Goog-User-Project")
		_, _ = io.WriteString(w, `{"datasets":[]}`)
	})
	stdout.Reset()
	stderr.Reset()
	code = cli.Execute([]string{"collect", "--rule=cis-gcp-7.1", "--project=example-prod", "--step=datasets", "--account=scanner@example.com", "--quota-project=quota-other"}, nil, &stdout, &stderr, restCollectEnv(t))
	if code != 0 {
		t.Fatalf("quota-project code=%d stderr=%q", code, stderr.String())
	}
	if secondQuota != "quota-other" {
		t.Fatalf("explicit quota header = %q", secondQuota)
	}

	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	guardRule, ok := set.Get("cis-gcp-7.1")
	if !ok {
		t.Fatal("REST rule is unavailable")
	}
	mutatedRule := *guardRule
	mutatedSteps := append([]rule.Step(nil), guardRule.Collect...)
	mutatedSteps[0].API = &rule.APIStep{Method: "GET", URL: "https://bigquery.googleapis.com/bigquery/v2/projects/outside-project/datasets", Paginate: true, ListField: "datasets"}
	mutatedRule.Collect = mutatedSteps
	var tokenCalls, rejectedHTTPCalls int
	runner := collectRunnerFunc(func(_ context.Context, exec collect.Exec, _ collect.Limits) (collect.Output, error) {
		if strings.Contains(strings.Join(exec.Argv, " "), "auth print-access-token") {
			tokenCalls++
			return collect.Output{Stdout: []byte("test-access-token\n")}, nil
		}
		return collect.Output{Stdout: []byte("Google Cloud SDK 1.2.3\n")}, nil
	})
	allow, err := rule.LoadAllowlist()
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.CollectRule(context.Background(), engine.Options{Projects: []string{"example-prod"}, Account: "scanner@example.com"}, engine.Deps{
		Runner: runner, Gcloud: "gcloud", Allow: allow,
		HTTPTransport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			rejectedHTTPCalls++
			return nil, fmt.Errorf("unexpected request")
		}),
	}, &mutatedRule, "datasets")
	if err == nil || tokenCalls != 0 || rejectedHTTPCalls != 0 {
		t.Fatalf("out-of-scope collection error=%v token calls=%d HTTP calls=%d", err, tokenCalls, rejectedHTTPCalls)
	}
}

type collectRunnerFunc func(context.Context, collect.Exec, collect.Limits) (collect.Output, error)

func (f collectRunnerFunc) Run(ctx context.Context, exec collect.Exec, limits collect.Limits) (collect.Output, error) {
	return f(ctx, exec, limits)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestCollect_RESTSanitizeDoesNotLeakIdentifiers(t *testing.T) {
	withRESTTransport(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"datasets":[{"datasetReference":{"projectId":"example-prod","datasetId":"example-prod"},"description":"scanner@example.com"}]}`)
	})
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"collect", "--rule=cis-gcp-7.1", "--project=example-prod", "--step=datasets", "--account=scanner@example.com", "--sanitize"}, nil, &stdout, &stderr, restCollectEnv(t))
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	for _, identifier := range []string{"example-prod", "scanner@example.com"} {
		if strings.Contains(stdout.String(), identifier) {
			t.Errorf("unsanitized identifier %q remains in stdout %q", identifier, stdout.String())
		}
		if strings.Contains(stderr.String(), identifier) {
			t.Errorf("sanitization diagnostic contains identifier %q: %q", identifier, stderr.String())
		}
	}
	if strings.Contains(stdout.String(), "test-access-token") || strings.Contains(stderr.String(), "test-access-token") {
		t.Fatal("token leaked to command output")
	}
	if !strings.Contains(stderr.String(), "best-effort") {
		t.Fatalf("best-effort warning missing: %q", stderr.String())
	}
}

func TestCollect_RESTSanitizeUsesConfiguredAccount(t *testing.T) {
	const account = "scanner@tenant.example"
	withRESTTransport(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"datasets":[{"description":%q}]}`, account)
	})
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"collect", "--rule=cis-gcp-7.1", "--project=example-prod", "--step=datasets", "--sanitize"}, nil, &stdout, &stderr, restCollectEnvWithConfiguredAccount(t, account))
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), account) || strings.Contains(stderr.String(), account) {
		t.Fatalf("configured account leaked: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "scanner@example-sec.iam.gserviceaccount.com") {
		t.Fatalf("configured account was not replaced using the resolved identity: %q", stdout.String())
	}
}

func TestCollect_RESTFailureHasNoRawBody(t *testing.T) {
	const body = `private-project-identifier private-response-body`
	calls := 0
	withRESTTransport(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, body)
	})
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"collect", "--rule=cis-gcp-7.1", "--project=example-prod", "--step=datasets", "--account=scanner@example.com"}, nil, &stdout, &stderr, restCollectEnv(t))
	if code == 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q, want collection failure", code, stdout.String(), stderr.String())
	}
	if calls != 1 {
		t.Fatalf("HTTP calls = %d, want REST failure response", calls)
	}
	for _, raw := range []string{body, "private-project-identifier", "private-response-body", "example-prod", "scanner@example.com", "test-access-token"} {
		if strings.Contains(stderr.String(), raw) || strings.Contains(stdout.String(), raw) {
			t.Errorf("raw REST diagnostic %q leaked: stdout=%q stderr=%q", raw, stdout.String(), stderr.String())
		}
	}
}
