package auth

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/failure"
)

type fakeResult struct {
	stdout   string
	stderr   string
	exitCode int
	err      error
}

type fakeRunner struct {
	mu      sync.Mutex
	results map[string]fakeResult
	calls   []collect.Exec
}

func newFakeRunner(results map[string]fakeResult) *fakeRunner {
	return &fakeRunner{results: results}
}

func (r *fakeRunner) Run(_ context.Context, e collect.Exec, _ collect.Limits) (collect.Output, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e.Argv = append([]string(nil), e.Argv...)
	e.Env = append([]string(nil), e.Env...)
	r.calls = append(r.calls, e)
	result, ok := r.results[strings.Join(e.Argv, " ")]
	if !ok {
		return collect.Output{}, errors.New("unexpected command")
	}
	return collect.Output{
		Stdout:   []byte(result.stdout),
		Stderr:   []byte(result.stderr),
		ExitCode: result.exitCode,
	}, result.err
}

func (r *fakeRunner) callArgvs() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	argvs := make([][]string, len(r.calls))
	for i, call := range r.calls {
		argvs[i] = append([]string(nil), call.Argv...)
	}
	return argvs
}

func TestResolve_UnpinnedAccountUsesConfiguredAccount(t *testing.T) {
	r := newFakeRunner(map[string]fakeResult{
		"--version":          {stdout: "Google Cloud SDK 570.0.0\n"},
		"config get account": {stdout: "scanner@example.com\n"},
	})
	var checked [][]string
	check := func(argv []string) error {
		checked = append(checked, append([]string(nil), argv...))
		return nil
	}
	c, err := Resolve(context.Background(), r, "gcloud", []string{"PATH=/bin"}, check, Options{})
	if err != nil || c.Version != "570.0.0" || c.Identity.Account != "scanner@example.com" {
		t.Fatalf("Resolve() = %+v, %v", c, err)
	}
	wantArgvs := [][]string{{"--version"}, {"config", "get", "account"}}
	if got := r.callArgvs(); !reflect.DeepEqual(got, wantArgvs) {
		t.Fatalf("runner argv = %#v, want %#v", got, wantArgvs)
	}
	if !reflect.DeepEqual(checked, wantArgvs) {
		t.Fatalf("checked argv = %#v, want %#v", checked, wantArgvs)
	}
}

func TestResolve_NoAccountIsError(t *testing.T) {
	r := newFakeRunner(map[string]fakeResult{
		"--version":          {stdout: "Google Cloud SDK 570.0.0\n"},
		"config get account": {stdout: " \n"},
	})
	_, err := Resolve(context.Background(), r, "gcloud", nil, allowAll, Options{})
	if err == nil || !strings.Contains(err.Error(), "gcloud auth login") {
		t.Fatalf("Resolve() error = %v, want login guidance", err)
	}
}

func TestResolve_RejectsCommandBeforeExecution(t *testing.T) {
	r := newFakeRunner(map[string]fakeResult{"--version": {stdout: "Google Cloud SDK 570.0.0\n"}})
	_, err := Resolve(context.Background(), r, "gcloud", nil, func([]string) error {
		return errors.New("not allowlisted")
	}, Options{})
	f, ok := failure.As(err)
	if !ok || f.Class != failure.GuardRejected {
		t.Fatalf("Resolve() error = %v, want guard_rejected", err)
	}
	if calls := r.callArgvs(); len(calls) != 0 {
		t.Fatalf("runner calls = %#v, want none", calls)
	}
}

func TestResolve_GuardFailureRedactsAndDoesNotExecute(t *testing.T) {
	r := newFakeRunner(nil)
	_, err := Resolve(context.Background(), r, "gcloud", nil, func([]string) error {
		return errors.New("blocked \x1b[31mya29.synthetic-secret\x1b[0m" + strings.Repeat("x", 600))
	}, Options{})
	f, ok := failure.As(err)
	if !ok || f.Class != failure.GuardRejected {
		t.Fatalf("Resolve() error = %v, want guard_rejected", err)
	}
	if strings.Contains(f.Summary, "ya29.synthetic-secret") || !strings.Contains(f.Summary, "[REDACTED]") {
		t.Fatalf("Resolve() summary = %q, want redacted secret", f.Summary)
	}
	if strings.ContainsRune(f.Summary, '\x1b') {
		t.Fatalf("Resolve() summary contains terminal control: %q", f.Summary)
	}
	if len([]rune(f.Summary)) > 500 {
		t.Fatalf("Resolve() summary has %d runes, want at most 500", len([]rune(f.Summary)))
	}
	if calls := r.callArgvs(); len(calls) != 0 {
		t.Fatalf("runner calls = %#v, want none", calls)
	}
}

func TestResolve_RequiresVersionOnFirstLineAndNumericTriplet(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
	}{
		{name: "warning before version", stdout: "WARNING: unexpected\nGoogle Cloud SDK 570.0.0\n"},
		{name: "non-numeric version", stdout: "Google Cloud SDK fake\n"},
		{name: "incomplete version", stdout: "Google Cloud SDK 570.0\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newFakeRunner(map[string]fakeResult{"--version": {stdout: tc.stdout}})
			c, err := Resolve(context.Background(), r, "gcloud", nil, allowAll, Options{Account: "scanner@example.com"})
			if err == nil || c != nil {
				t.Fatalf("Resolve() = %+v, %v; want invalid version error", c, err)
			}
		})
	}
}

func TestResolve_PinnedAccountSkipsConfiguredAccountLookup(t *testing.T) {
	r := newFakeRunner(map[string]fakeResult{"--version": {stdout: "Google Cloud SDK 570.0.0\n"}})
	c, err := Resolve(context.Background(), r, "gcloud", nil, allowAll, Options{Account: "scanner@example.com"})
	if err != nil || c.Identity.Account != "scanner@example.com" {
		t.Fatalf("Resolve() = %+v, %v", c, err)
	}
	if got, want := r.callArgvs(), [][]string{{"--version"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("runner argv = %#v, want %#v", got, want)
	}
}

func TestCommonArgs_IncludesBillingProjectWhenQuotaProjectSet(t *testing.T) {
	c := &Client{Identity: Options{Account: "scanner@example.com", QuotaProject: "quota-proj"}}
	want := []string{"--quiet", "--account=scanner@example.com", "--billing-project=quota-proj"}
	if got := c.CommonArgs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("CommonArgs() = %#v, want %#v", got, want)
	}
}

func TestCommonArgs_IncludesPinnedAccountAndImpersonation(t *testing.T) {
	c := &Client{Identity: Options{Account: "scanner@example.com", Impersonate: "reader@example.iam.gserviceaccount.com"}}
	want := []string{"--quiet", "--account=scanner@example.com", "--impersonate-service-account=reader@example.iam.gserviceaccount.com"}
	if got := c.CommonArgs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("CommonArgs() = %#v, want %#v", got, want)
	}
}

func TestRun_AppendsCommonArgsAfterRuleArgv(t *testing.T) {
	r := newFakeRunner(map[string]fakeResult{
		"projects list --project=example-prod --format=json --quiet --account=scanner@example.com --billing-project=quota-proj": {stdout: "[]", exitCode: 0},
	})
	c := &Client{Gcloud: "gcloud", Identity: Options{Account: "scanner@example.com", QuotaProject: "quota-proj"}, runner: r}
	if _, err := c.Run(context.Background(), []string{"projects", "list", "--project=example-prod", "--format=json"}, collect.Limits{}); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"projects", "list", "--project=example-prod", "--format=json", "--quiet", "--account=scanner@example.com", "--billing-project=quota-proj"}}
	if got := r.callArgvs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("runner argv = %#v, want %#v", got, want)
	}
}

func TestClient_CommandRejectedByCheckIsNotExecuted(t *testing.T) {
	r := newFakeRunner(nil)
	c := &Client{Gcloud: "gcloud", Identity: Options{Account: "scanner@example.com"}, runner: r, check: func([]string) error { return errors.New("rejected") }}
	_, err := c.ProjectNumber(context.Background(), "example-prod")
	f, ok := failure.As(err)
	if !ok || f.Class != failure.GuardRejected {
		t.Fatalf("ProjectNumber() error = %v, want guard_rejected", err)
	}
	if calls := r.callArgvs(); len(calls) != 0 {
		t.Fatalf("runner calls = %#v, want none", calls)
	}
}

func TestClient_GuardFailureRedactsAndDoesNotExecute(t *testing.T) {
	r := newFakeRunner(nil)
	c := &Client{
		Gcloud:   "gcloud",
		Identity: Options{Account: "scanner@example.com"},
		runner:   r,
		check: func([]string) error {
			return errors.New("blocked \x1b[31mya29.synthetic-secret\x1b[0m" + strings.Repeat("x", 600))
		},
	}
	_, err := c.ProjectNumber(context.Background(), "example-prod")
	f, ok := failure.As(err)
	if !ok || f.Class != failure.GuardRejected {
		t.Fatalf("ProjectNumber() error = %v, want guard_rejected", err)
	}
	if strings.Contains(f.Summary, "ya29.synthetic-secret") || !strings.Contains(f.Summary, "[REDACTED]") {
		t.Fatalf("ProjectNumber() summary = %q, want redacted secret", f.Summary)
	}
	if strings.ContainsRune(f.Summary, '\x1b') {
		t.Fatalf("ProjectNumber() summary contains terminal control: %q", f.Summary)
	}
	if len([]rune(f.Summary)) > 500 {
		t.Fatalf("ProjectNumber() summary has %d runes, want at most 500", len([]rune(f.Summary)))
	}
	if calls := r.callArgvs(); len(calls) != 0 {
		t.Fatalf("runner calls = %#v, want none", calls)
	}
}

func TestClient_InternalCommandsUseAllowlistArgv(t *testing.T) {
	r := newFakeRunner(map[string]fakeResult{
		"config get account --quiet --account=scanner@example.com":                                           {stdout: "scanner@example.com\n"},
		"projects describe example-prod --format=json --quiet --account=scanner@example.com":                 {stdout: `{"projectNumber":"123456789012"}`},
		"projects get-ancestors example-prod --format=json --quiet --account=scanner@example.com":            {stdout: `[{"id":"example-prod","type":"project"},{"id":"folders/123","type":"folder"},{"id":"organizations/456","type":"organization"}]`},
		"organizations describe organizations/456 --format=json --quiet --account=scanner@example.com":       {stdout: `{"displayName":"example.com"}`},
		"container clusters list --project=example-prod --format=json --quiet --account=scanner@example.com": {stdout: `[{"name":"cluster-a"}]`},
		"services list --enabled --project=example-prod --format=json --quiet --account=scanner@example.com": {stdout: `[{"config":{"name":"compute.googleapis.com"}}]`},
		"auth print-access-token --quiet --account=scanner@example.com":                                      {stdout: "token-value\n"},
	})
	checked := make([][]string, 0, 7)
	c := &Client{Gcloud: "gcloud", Identity: Options{Account: "scanner@example.com"}, runner: r, check: func(argv []string) error {
		checked = append(checked, append([]string(nil), argv...))
		return nil
	}}
	if account, err := c.Account(context.Background()); err != nil || account != "scanner@example.com" {
		t.Fatalf("Account() = %q, %v", account, err)
	}
	if number, err := c.ProjectNumber(context.Background(), "example-prod"); err != nil || number != "123456789012" {
		t.Fatalf("ProjectNumber() = %q, %v", number, err)
	}
	orgID, folderID, err := c.Ancestors(context.Background(), "example-prod")
	if err != nil || orgID != "organizations/456" || folderID != "folders/123" {
		t.Fatalf("Ancestors() = %q, %q, %v", orgID, folderID, err)
	}
	if domain, err := c.OrganizationDomain(context.Background(), "organizations/456"); err != nil || domain != "example.com" {
		t.Fatalf("OrganizationDomain() = %q, %v", domain, err)
	}
	if clusters, err := c.Clusters(context.Background(), "example-prod"); err != nil || len(clusters) != 1 {
		t.Fatalf("Clusters() = %#v, %v", clusters, err)
	}
	if services, err := c.EnabledServices(context.Background(), "example-prod"); err != nil || !services["compute.googleapis.com"] {
		t.Fatalf("EnabledServices() = %#v, %v", services, err)
	}
	if token, err := c.Token(context.Background()); err != nil || token != "token-value" {
		t.Fatalf("Token() = %q, %v", token, err)
	}
	want := [][]string{
		{"config", "get", "account"},
		{"projects", "describe", "example-prod", "--format=json"},
		{"projects", "get-ancestors", "example-prod", "--format=json"},
		{"organizations", "describe", "organizations/456", "--format=json"},
		{"container", "clusters", "list", "--project=example-prod", "--format=json"},
		{"services", "list", "--enabled", "--project=example-prod", "--format=json"},
		{"auth", "print-access-token"},
	}
	if got := checked; !reflect.DeepEqual(got, want) {
		t.Fatalf("checked argv = %#v, want %#v", got, want)
	}
	wantCalls := make([][]string, len(want))
	for i, argv := range want {
		wantCalls[i] = append(append([]string(nil), argv...), "--quiet", "--account=scanner@example.com")
	}
	if got := r.callArgvs(); !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("runner argv = %#v, want %#v", got, wantCalls)
	}
}

func TestAncestors_ProjectOnly(t *testing.T) {
	r := newFakeRunner(map[string]fakeResult{
		"projects get-ancestors example-prod --format=json --quiet --account=scanner@example.com": {stdout: `[{"id":"example-prod","type":"project"}]`},
	})
	c := &Client{Gcloud: "gcloud", Identity: Options{Account: "scanner@example.com"}, runner: r, check: allowAll}
	orgID, folderID, err := c.Ancestors(context.Background(), "example-prod")
	if err != nil || orgID != "" || folderID != "" {
		t.Fatalf("Ancestors() = %q, %q, %v", orgID, folderID, err)
	}
}

func TestAncestors_MissingFolderOrOrganizationIDIsParseError(t *testing.T) {
	tests := []struct {
		name  string
		entry string
	}{
		{name: "folder", entry: `{"type":"folder"}`},
		{name: "organization", entry: `{"type":"organization"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stdout := `[{"id":"example-prod","type":"project"},` + tc.entry + `]`
			r := newFakeRunner(map[string]fakeResult{
				"projects get-ancestors example-prod --format=json --quiet --account=scanner@example.com": {stdout: stdout},
			})
			c := &Client{Gcloud: "gcloud", Identity: Options{Account: "scanner@example.com"}, runner: r, check: allowAll}
			_, _, err := c.Ancestors(context.Background(), "example-prod")
			f, ok := failure.As(err)
			if !ok || f.Class != failure.Parse {
				t.Fatalf("Ancestors() error = %v, want parse_error", err)
			}
		})
	}
}

func TestEnabledServices_MissingServiceNameIsParseError(t *testing.T) {
	r := newFakeRunner(map[string]fakeResult{
		"services list --enabled --project=example-prod --format=json --quiet --account=scanner@example.com": {stdout: `[{"config":{}}]`},
	})
	c := &Client{Gcloud: "gcloud", Identity: Options{Account: "scanner@example.com"}, runner: r, check: allowAll}
	_, err := c.EnabledServices(context.Background(), "example-prod")
	f, ok := failure.As(err)
	if !ok || f.Class != failure.Parse {
		t.Fatalf("EnabledServices() error = %v, want parse_error", err)
	}
}

func TestToken_CachesAndRefreshesAfterTTL(t *testing.T) {
	r := newFakeRunner(map[string]fakeResult{"auth print-access-token --quiet --account=scanner@example.com": {stdout: "token-value\n"}})
	c := &Client{Gcloud: "gcloud", Identity: Options{Account: "scanner@example.com"}, runner: r, check: allowAll}
	current := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return current }
	for i := 0; i < 2; i++ {
		if token, err := c.Token(context.Background()); err != nil || token != "token-value" {
			t.Fatalf("Token() = %q, %v", token, err)
		}
	}
	if got := len(r.callArgvs()); got != 1 {
		t.Fatalf("runner calls = %d, want 1", got)
	}
	current = current.Add(50 * time.Minute)
	if token, err := c.Token(context.Background()); err != nil || token != "token-value" {
		t.Fatalf("Token() after expiration = %q, %v", token, err)
	}
	if got := len(r.callArgvs()); got != 2 {
		t.Fatalf("runner calls = %d, want 2", got)
	}
}

func TestToken_InvalidationOnlyClearsMatchingCachedValue(t *testing.T) {
	r := newFakeRunner(map[string]fakeResult{"auth print-access-token --quiet --account=scanner@example.com": {stdout: "token-value\n"}})
	c := &Client{Gcloud: "gcloud", Identity: Options{Account: "scanner@example.com"}, runner: r, check: allowAll}
	first, err := c.Token(context.Background())
	if err != nil || first != "token-value" {
		t.Fatalf("Token() = %q, %v", first, err)
	}
	if c.InvalidateToken("other-token") {
		t.Fatal("InvalidateToken(other-token) = true, want false")
	}
	if token, err := c.Token(context.Background()); err != nil || token != first {
		t.Fatalf("Token() after mismatch = %q, %v", token, err)
	}
	if !c.InvalidateToken(first) {
		t.Fatal("InvalidateToken(cached token) = false, want true")
	}
	if token, err := c.Token(context.Background()); err != nil || token != first {
		t.Fatalf("Token() after invalidation = %q, %v", token, err)
	}
	if got := len(r.callArgvs()); got != 2 {
		t.Fatalf("token command calls = %d, want 2", got)
	}
}

func TestProjectNumber_NonNumericIsError(t *testing.T) {
	r := newFakeRunner(map[string]fakeResult{
		"projects describe example-prod --format=json --quiet --account=scanner@example.com": {stdout: `{"projectNumber":"not-a-number"}`},
	})
	c := &Client{Gcloud: "gcloud", Identity: Options{Account: "scanner@example.com"}, runner: r, check: allowAll}
	_, err := c.ProjectNumber(context.Background(), "example-prod")
	f, ok := failure.As(err)
	if !ok || f.Class != failure.Parse {
		t.Fatalf("ProjectNumber() error = %v, want parse_error", err)
	}
}

func TestRun_PreservesRunnerErrorWithSuccessfulExitCode(t *testing.T) {
	waitDelayErr := errors.New("subprocess output may be incomplete")
	r := newFakeRunner(map[string]fakeResult{"projects describe example-prod --format=json --quiet --account=scanner@example.com": {
		stdout: `{"projectNumber":"123456789012"}`, err: waitDelayErr,
	}})
	c := &Client{Gcloud: "gcloud", Identity: Options{Account: "scanner@example.com"}, runner: r, check: allowAll}
	if _, err := c.ProjectNumber(context.Background(), "example-prod"); !errors.Is(err, waitDelayErr) {
		t.Fatalf("ProjectNumber() error = %v, want runner error", err)
	}
}

func allowAll([]string) error { return nil }
