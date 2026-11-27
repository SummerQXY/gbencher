package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/eval"
	"github.com/SummerQXY/gbencher/internal/failure"
	"github.com/SummerQXY/gbencher/internal/report"
	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/schemas"
)

type scanRunner struct {
	calls          atomic.Int32
	tokenCalls     atomic.Int32
	computeCalls   atomic.Int32
	services       []byte
	clusters       []byte
	compute        []byte
	computeErr     []byte
	describeErr    []byte
	noOrganization bool
	delay          time.Duration
	mu             sync.Mutex
	argv           [][]string
}

type kubectlIntegrationRunner struct {
	cloud                  *scanRunner
	mu                     sync.Mutex
	calls                  [][]string
	failEndpoint           string
	malformedEndpoint      string
	malformedProbeEndpoint string
}

func (r *kubectlIntegrationRunner) Run(ctx context.Context, e collect.Exec, limits collect.Limits) (collect.Output, error) {
	if e.Path != "kubectl" {
		return r.cloud.Run(ctx, e, limits)
	}
	r.mu.Lock()
	r.calls = append(r.calls, append([]string(nil), e.Argv...))
	r.mu.Unlock()
	if len(e.Argv) > 0 && e.Argv[0] == "version" && !strings.Contains(strings.Join(e.Argv, " "), "--kubeconfig=") {
		return collect.Output{Stdout: []byte(`{"clientVersion":{"gitVersion":"v1.33.0"}}`)}, nil
	}
	config := ""
	for _, arg := range e.Argv {
		if strings.HasPrefix(arg, "--kubeconfig=") {
			config = strings.TrimPrefix(arg, "--kubeconfig=")
		}
	}
	data, err := os.ReadFile(config)
	if err != nil {
		return collect.Output{}, err
	}
	if r.failEndpoint != "" && strings.Contains(string(data), r.failEndpoint) && len(e.Argv) > 0 && e.Argv[0] == "version" {
		return collect.Output{ExitCode: 1, Stderr: []byte("Unable to connect to the server: connection refused")}, nil
	}
	if len(e.Argv) > 0 && e.Argv[0] == "version" {
		if r.malformedProbeEndpoint != "" && strings.Contains(string(data), r.malformedProbeEndpoint) {
			return collect.Output{Stdout: []byte("not json")}, nil
		}
		return collect.Output{Stdout: []byte(`{"clientVersion":{"gitVersion":"v1.33.0"},"serverVersion":{"gitVersion":"v1.33.0"}}`)}, nil
	}
	if r.malformedEndpoint != "" && strings.Contains(string(data), r.malformedEndpoint) {
		return collect.Output{Stdout: []byte("not json")}, nil
	}
	return collect.Output{Stdout: []byte(`{"items":[]}`)}, nil
}

func (r *kubectlIntegrationRunner) recordedCalls() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([][]string, len(r.calls))
	for i := range r.calls {
		result[i] = append([]string(nil), r.calls[i]...)
	}
	return result
}

func kubectlIntegrationRule(id string) *rule.Rule {
	return &rule.Rule{
		ID: id, Ref: "1.1", Title: id, Profile: "L1", Scope: "cluster", Mode: "deterministic", Severity: "high",
		Requires: []string{"kubectl"},
		Collect:  []rule.Step{{ID: "pods", Kubectl: "get pods -o json", Parse: "json"}},
		Resource: &rule.Resource{From: "data.pods.items", Kind: "v1/Pod", Name: "r.metadata.name"},
		Check:    rule.Check{Assert: "true"},
	}
}

func kubectlIntegrationClusters() []byte {
	return []byte(`[
		{"name":"cluster-a","location":"region-a","endpoint":"192.0.2.1","masterAuth":{"clusterCaCertificate":"Y2E="}},
		{"name":"cluster-b","location":"region-a","endpoint":"192.0.2.2","masterAuth":{"clusterCaCertificate":"Y2E="}}
	]`)
}

func TestRun_ProbesBeforeFirstKubectlCall(t *testing.T) {
	cloud := &scanRunner{clusters: kubectlIntegrationClusters()}
	runner := &kubectlIntegrationRunner{cloud: cloud}
	deps := fixtureDeps(t, runner)
	deps.Kubectl = "kubectl"
	_, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{kubectlIntegrationRule("kubectl-order")}, Enable: []string{"kubectl"}}, deps)
	if err != nil {
		t.Fatal(err)
	}
	calls := runner.recordedCalls()
	probed := map[string]bool{}
	for _, call := range calls {
		config := ""
		for _, arg := range call {
			if strings.HasPrefix(arg, "--kubeconfig=") {
				config = strings.TrimPrefix(arg, "--kubeconfig=")
			}
		}
		if config == "" {
			continue
		}
		if call[0] == "version" {
			probed[config] = true
		}
		if call[0] == "get" && !probed[config] {
			t.Fatalf("rule call preceded probe for %s: %q", config, calls)
		}
	}
	if len(probed) != 2 {
		t.Fatalf("probed clusters = %d, want 2; calls=%q", len(probed), calls)
	}
}

func TestRun_ClusterProbeFailureMapsUnitStatus(t *testing.T) {
	runner := &kubectlIntegrationRunner{cloud: &scanRunner{clusters: kubectlIntegrationClusters()}, failEndpoint: "192.0.2.1"}
	deps := fixtureDeps(t, runner)
	deps.Kubectl = "kubectl"
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{kubectlIntegrationRule("kubectl-failure")}, Enable: []string{"kubectl"}}, deps)
	if err != nil {
		t.Fatal(err)
	}
	var bad, healthy bool
	for _, result := range rep.Results {
		if strings.Contains(result.Target.Key, "cluster-a") {
			bad = result.Assessment.Status == "SKIPPED" && strings.Contains(result.Assessment.Message, "cluster_unreachable")
		}
		if strings.Contains(result.Target.Key, "cluster-b") {
			healthy = result.Assessment.Status != "SKIPPED" && result.Assessment.Status != "ERROR"
		}
	}
	if !bad || !healthy {
		t.Fatalf("results = %+v, want cluster-a skipped and cluster-b retained", rep.Results)
	}
	if got := rep.Scan.Targets[0].Clusters.Unreachable; len(got) != 1 || got[0] != "cluster-a" {
		t.Fatalf("unreachable clusters = %v, want [cluster-a]", got)
	}
}

func TestRun_ClusterProbeDoesNotAffectOtherClusters(t *testing.T) {
	runner := &kubectlIntegrationRunner{cloud: &scanRunner{clusters: kubectlIntegrationClusters()}, failEndpoint: "192.0.2.1"}
	deps := fixtureDeps(t, runner)
	deps.Kubectl = "kubectl"
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{kubectlIntegrationRule("kubectl-isolation")}, Enable: []string{"kubectl"}}, deps)
	if err != nil {
		t.Fatal(err)
	}
	var seen map[string]int = map[string]int{}
	for _, result := range rep.Results {
		seen[result.Target.Key]++
	}
	if len(seen) != 2 {
		t.Fatalf("targets = %v, want both clusters", seen)
	}
	for target, count := range seen {
		if count != 1 {
			t.Errorf("target %s has %d results", target, count)
		}
	}
}

func TestRun_ExecutesKubectlStepsAndRecordsCollector(t *testing.T) {
	runner := &kubectlIntegrationRunner{cloud: &scanRunner{clusters: kubectlIntegrationClusters()}}
	deps := fixtureDeps(t, runner)
	deps.Kubectl = "kubectl"
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{kubectlIntegrationRule("kubectl-collector")}, Enable: []string{"kubectl"}}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Collectors) != 2 {
		t.Fatalf("collectors = %d, want one rule collector per cluster; probe calls are internal", len(rep.Collectors))
	}
	for _, collector := range rep.Collectors {
		if collector.Type != "kubectl" || !strings.HasPrefix(collector.Key, "kubectl\x00") {
			t.Errorf("collector = %+v", collector)
		}
	}
	for _, result := range rep.Results {
		if len(result.CollectorKeys) != 1 || !strings.HasPrefix(result.CollectorKeys[0], "kubectl\x00") {
			t.Errorf("collector refs = %v", result.CollectorKeys)
		}
	}
}

func TestRun_KubectlCapabilityDisabledMakesNoCall(t *testing.T) {
	cloud := &scanRunner{clusters: kubectlIntegrationClusters()}
	runner := &kubectlIntegrationRunner{cloud: cloud}
	deps := fixtureDeps(t, runner)
	deps.Kubectl = "kubectl"
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{kubectlIntegrationRule("kubectl-disabled")}}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(runner.recordedCalls()); got != 0 {
		t.Fatalf("kubectl calls = %d, want 0", got)
	}
	for _, result := range rep.Results {
		if result.Assessment.Status != "SKIPPED" {
			t.Errorf("status = %s, want SKIPPED", result.Assessment.Status)
		}
	}
}

func TestRun_KubectlFailureMapsToAssessmentStatus(t *testing.T) {
	runner := &kubectlIntegrationRunner{cloud: &scanRunner{clusters: kubectlIntegrationClusters()}, malformedEndpoint: "192.0.2.2"}
	deps := fixtureDeps(t, runner)
	deps.Kubectl = "kubectl"
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{kubectlIntegrationRule("kubectl-bad-output")}, Enable: []string{"kubectl"}}, deps)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, result := range rep.Results {
		if strings.Contains(result.Target.Key, "cluster-b") {
			found = true
			if result.Assessment.Status != "ERROR" {
				t.Errorf("status = %s, want ERROR", result.Assessment.Status)
			}
		}
	}
	if !found {
		t.Fatal("cluster-b result is missing")
	}
}

func TestRun_UnexpectedClusterProbeFailureMapsUnitStatus(t *testing.T) {
	runner := &kubectlIntegrationRunner{cloud: &scanRunner{clusters: kubectlIntegrationClusters()}, malformedProbeEndpoint: "192.0.2.1"}
	deps := fixtureDeps(t, runner)
	deps.Kubectl = "kubectl"
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{kubectlIntegrationRule("kubectl-probe-error")}, Enable: []string{"kubectl"}}, deps)
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range rep.Results {
		if strings.Contains(result.Target.Key, "cluster-a") && result.Assessment.Status != "ERROR" {
			t.Fatalf("cluster-a status = %s, want ERROR", result.Assessment.Status)
		}
	}
}

type workspaceTokenSource struct {
	account string
	token   string
	err     error
}

func (s *workspaceTokenSource) Account() string                       { return s.account }
func (s *workspaceTokenSource) Token(context.Context) (string, error) { return s.token, s.err }
func (s *workspaceTokenSource) InvalidateToken(string) bool           { return true }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func workspaceRule(id string, onError string) *rule.Rule {
	return &rule.Rule{
		ID: id, Ref: "1.3", Title: id, Profile: "L1", Scope: "project", Mode: "deterministic", Severity: "high",
		Requires: []string{"workspace-admin"},
		Collect: []rule.Step{{ID: "directory_users", OnError: onError, API: &rule.APIStep{
			Method: "GET", URL: "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=500",
			Paginate: true, ListField: "users", Scopes: []string{"https://www.googleapis.com/auth/admin.directory.user.readonly"},
		}}},
		Resource: &rule.Resource{From: "data.directory_users", Kind: "admin.googleapis.com/User", Name: "r.primaryEmail"},
		Check:    rule.Check{Assert: "true"},
	}
}

func TestRun_WorkspaceDisabledMakesNoADCOrHTTPCall(t *testing.T) {
	runner := &scanRunner{}
	var httpCalls atomic.Int32
	deps := fixtureDeps(t, runner)
	deps.HTTPTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		httpCalls.Add(1)
		return nil, fmt.Errorf("unexpected HTTP call")
	})
	deps.WorkspaceADC = func(context.Context, []string) (WorkspaceTokenSource, error) {
		t.Fatal("ADC was requested while Workspace capability was disabled")
		return nil, nil
	}
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{workspaceRule("workspace-disabled", "empty")}}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Assessment.Status != "SKIPPED" || runner.tokenCalls.Load() != 0 || httpCalls.Load() != 0 {
		t.Fatalf("result=%+v gcloudTokens=%d HTTP=%d", rep.Results[0], runner.tokenCalls.Load(), httpCalls.Load())
	}
}

func TestWorkspaceRulesRequireOptIn(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cis-gcp-1.1.1", "cis-gcp-1.1.2", "cis-gcp-1.2", "cis-gcp-1.3", "cis-gcp-1.4", "cis-gcp-2.2"}
	for _, id := range want {
		var found *rule.Rule
		for _, candidate := range set.Rules {
			if candidate.ID == id {
				found = candidate
				break
			}
		}
		if found == nil || !contains(found.Requires, "workspace-admin") {
			t.Errorf("%s does not declare workspace-admin", id)
		}
	}
}

func TestRun_WorkspaceUnavailableADCSkipsDespiteEmptyPolicy(t *testing.T) {
	runner := &scanRunner{}
	deps := fixtureDeps(t, runner)
	var httpCalls atomic.Int32
	deps.WorkspaceADC = func(context.Context, []string) (WorkspaceTokenSource, error) {
		return nil, fmt.Errorf("missing ADC")
	}
	deps.HTTPTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		httpCalls.Add(1)
		return nil, fmt.Errorf("unexpected HTTP call")
	})
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{workspaceRule("workspace-no-adc", "empty")}, Enable: []string{"workspace-admin"}}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Assessment.Status != "SKIPPED" || httpCalls.Load() != 0 {
		t.Fatalf("result=%+v HTTP=%d", rep.Results[0], httpCalls.Load())
	}
}

func TestRun_WorkspaceADCFailureCompletesDeduplicatedRequests(t *testing.T) {
	runner := &scanRunner{}
	deps := fixtureDeps(t, runner)
	entered := make(chan struct{})
	release := make(chan struct{})
	deps.WorkspaceADC = func(context.Context, []string) (WorkspaceTokenSource, error) {
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-release
		return nil, fmt.Errorf("missing ADC")
	}
	var httpCalls atomic.Int32
	deps.HTTPTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		httpCalls.Add(1)
		return nil, fmt.Errorf("unexpected HTTP call")
	})
	opts := Options{
		Projects: []string{"example-prod"},
		Rules:    []*rule.Rule{workspaceRule("workspace-1", "empty"), workspaceRule("workspace-2", "empty")},
		Enable:   []string{"workspace-admin"}, Parallel: 2,
	}
	type runResult struct {
		report *report.Report
		err    error
	}
	done := make(chan runResult, 1)
	go func() {
		rep, err := Run(context.Background(), opts, deps)
		done <- runResult{report: rep, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("ADC source was not requested")
	}
	close(release)
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if len(got.report.Results) != 2 || len(got.report.Collectors) != 1 {
			t.Fatalf("results=%d collectors=%d", len(got.report.Results), len(got.report.Collectors))
		}
		collectorID := got.report.Collectors[0].ID
		for _, result := range got.report.Results {
			if result.Assessment.Status != "SKIPPED" || result.Collection.Status != "FAILED" || len(result.Collection.CollectorIDs) != 1 || result.Collection.CollectorIDs[0] != collectorID {
				t.Fatalf("result does not reference shared failed collector: %+v collector=%+v", result, got.report.Collectors[0])
			}
		}
		if got.report.Collectors[0].Status != "FAILED" || httpCalls.Load() != 0 {
			t.Fatalf("collector=%+v HTTP=%d", got.report.Collectors[0], httpCalls.Load())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent Workspace requests did not complete after ADC failure")
	}
}

func TestRun_WorkspaceGuardRejectsBeforeADCOrHTTP(t *testing.T) {
	runner := &scanRunner{}
	deps := fixtureDeps(t, runner)
	var adcCalls atomic.Int32
	var httpCalls atomic.Int32
	deps.WorkspaceADC = func(context.Context, []string) (WorkspaceTokenSource, error) {
		adcCalls.Add(1)
		return &workspaceTokenSource{account: "workspace-admin@example.com", token: "adc-token"}, nil
	}
	deps.HTTPTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		httpCalls.Add(1)
		return nil, fmt.Errorf("unexpected HTTP call")
	})
	r := workspaceRule("workspace-guard", "empty")
	r.Collect[0].API.URL = "https://admin.googleapis.com.evil.test/admin/directory/v1/users?customer=my_customer"
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}, Enable: []string{"workspace-admin"}}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Assessment.Status != "ERROR" || adcCalls.Load() != 0 || httpCalls.Load() != 0 {
		t.Fatalf("result=%+v ADC=%d HTTP=%d", rep.Results[0], adcCalls.Load(), httpCalls.Load())
	}
}

func TestRun_WorkspaceEnabledReportsADCIdentity(t *testing.T) {
	runner := &scanRunner{}
	deps := fixtureDeps(t, runner)
	adc := &workspaceTokenSource{account: "workspace-admin@example.com", token: "adc-token"}
	workspaceRule := workspaceRule("workspace-enabled", "empty")
	workspaceRule.Collect[0].API.Scopes = append(workspaceRule.Collect[0].API.Scopes, "https://www.googleapis.com/auth/admin.directory.user")
	var requestedScopes []string
	deps.WorkspaceADC = func(_ context.Context, scopes []string) (WorkspaceTokenSource, error) {
		requestedScopes = append([]string(nil), scopes...)
		return adc, nil
	}
	deps.HTTPTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer adc-token" {
			t.Fatalf("Authorization = %q", req.Header.Get("Authorization"))
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"users":[]}`)), Request: req}, nil
	})
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{workspaceRule}, Enable: []string{"workspace-admin"}}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if rep.SchemaVersion != "1.1" || rep.Scan.Identity.ADCAccount == nil || *rep.Scan.Identity.ADCAccount != adc.account || rep.Scan.Identity.Account == adc.account {
		t.Fatalf("schema=%q identity=%+v", rep.SchemaVersion, rep.Scan.Identity)
	}
	if runner.tokenCalls.Load() != 0 || len(requestedScopes) != 1 || requestedScopes[0] != "https://www.googleapis.com/auth/admin.directory.user.readonly" {
		t.Fatalf("gcloudTokens=%d scopes=%v", runner.tokenCalls.Load(), requestedScopes)
	}
	if rep.RuleSummaries[0].Verification != "none" {
		t.Fatalf("verification=%q", rep.RuleSummaries[0].Verification)
	}
}

func TestRun_WorkspaceMissingOrMismatchedADCIdentitySkips(t *testing.T) {
	for _, account := range []string{"", "different@example.com"} {
		t.Run(account, func(t *testing.T) {
			runner := &scanRunner{}
			deps := fixtureDeps(t, runner)
			var httpCalls atomic.Int32
			adc := &workspaceTokenSource{account: account, token: "adc-token"}
			deps.WorkspaceADC = func(context.Context, []string) (WorkspaceTokenSource, error) { return adc, nil }
			deps.HTTPTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				httpCalls.Add(1)
				return nil, fmt.Errorf("unexpected HTTP call")
			})
			rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{workspaceRule("workspace-identity", "empty")}, Enable: []string{"workspace-admin"}, Account: "tester@example.com"}, deps)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Results[0].Assessment.Status != "SKIPPED" || httpCalls.Load() != 0 {
				t.Fatalf("result=%+v HTTP=%d", rep.Results[0], httpCalls.Load())
			}
		})
	}
}

func TestRun_WorkspaceInaccessibleTenantCannotBeEmptied(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			runner := &scanRunner{}
			deps := fixtureDeps(t, runner)
			deps.WorkspaceADC = func(context.Context, []string) (WorkspaceTokenSource, error) {
				return &workspaceTokenSource{account: "workspace-admin@example.com", token: "adc-token"}, nil
			}
			deps.HTTPTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":{"status":"PERMISSION_DENIED"}}`)), Request: req}, nil
			})
			rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{workspaceRule("workspace-denied", "empty")}, Enable: []string{"workspace-admin"}}, deps)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Results[0].Assessment.Status != "SKIPPED" || rep.Results[0].Collection.Status != "FAILED" {
				t.Fatalf("result=%+v", rep.Results[0])
			}
		})
	}
}

func TestReport_IdentitySchemaAcceptsNullableADCAccount(t *testing.T) {
	runner := &scanRunner{}
	r := fixtureRule("identity-schema")
	r.Hash = "sha256:" + strings.Repeat("a", 64)
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}, RulesetHash: "sha256:" + strings.Repeat("b", 64), ProfileHash: "sha256:" + strings.Repeat("c", 64), RulesetSource: "embedded"}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	rep.Scan.Identity.ADCAccount = nil
	if err := schemas.ValidateJSON("report", mustMarshal(t, rep)); err != nil {
		t.Fatalf("report with null ADC identity is invalid: %v", err)
	}
}

func TestRun_InvalidClusterKubeconfigDoesNotFailOtherClusters(t *testing.T) {
	cloud := &scanRunner{clusters: []byte(`[
		{"name":"broken","location":"region-a","endpoint":"","masterAuth":{"clusterCaCertificate":""}},
		{"name":"healthy","location":"region-a","endpoint":"10.0.0.1","masterAuth":{"clusterCaCertificate":"Y2E="}}
	]`)}
	runner := &kubectlIntegrationRunner{cloud: cloud}
	deps := fixtureDeps(t, runner)
	deps.Kubectl = "kubectl"
	clusterRule := &rule.Rule{
		ID: "cluster-kubectl", Ref: "1.1", Title: "cluster kubectl", Profile: "L1", Scope: "cluster",
		Mode: "deterministic", Severity: "low", Requires: []string{"kubectl"},
		Collect: []rule.Step{{ID: "pods", Kubectl: "get pods"}}, Check: rule.Check{Assert: "true"},
	}
	_, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{clusterRule}, Enable: []string{"kubectl"}}, deps)
	if err != nil {
		t.Fatalf("Run() failed globally because one cluster lacks kubeconfig data: %v", err)
	}
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (r *scanRunner) Run(ctx context.Context, e collect.Exec, _ collect.Limits) (collect.Output, error) {
	r.calls.Add(1)
	r.mu.Lock()
	r.argv = append(r.argv, append([]string(nil), e.Argv...))
	r.mu.Unlock()
	if len(e.Argv) > 0 && e.Argv[0] == "compute" {
		r.computeCalls.Add(1)
		if r.describeErr != nil {
			for _, arg := range e.Argv {
				if strings.Contains(arg, "two") {
					return collect.Output{ExitCode: 1, Stderr: r.describeErr}, nil
				}
			}
		}
		if r.delay > 0 {
			select {
			case <-time.After(r.delay):
			case <-ctx.Done():
				return collect.Output{}, ctx.Err()
			}
		}
		if r.computeErr != nil {
			return collect.Output{ExitCode: 1, Stderr: r.computeErr}, nil
		}
		if r.compute != nil {
			return collect.Output{Stdout: r.compute}, nil
		}
		return collect.Output{Stdout: []byte("[]")}, nil
	}
	switch {
	case len(e.Argv) >= 1 && e.Argv[0] == "--version":
		return collect.Output{Stdout: []byte("Google Cloud SDK 1.2.3\n")}, nil
	case len(e.Argv) >= 3 && strings.Join(e.Argv[:3], " ") == "config get account":
		return collect.Output{Stdout: []byte("tester@example.com\n")}, nil
	case len(e.Argv) >= 2 && strings.Join(e.Argv[:2], " ") == "auth print-access-token":
		r.tokenCalls.Add(1)
		return collect.Output{Stdout: []byte("fake-token\n")}, nil
	case len(e.Argv) >= 2 && strings.Join(e.Argv[:2], " ") == "projects describe":
		return collect.Output{Stdout: []byte(`{"projectNumber":"123456789012"}`)}, nil
	case len(e.Argv) >= 3 && strings.Join(e.Argv[:3], " ") == "projects get-ancestors example-prod":
		if r.noOrganization {
			return collect.Output{Stdout: []byte("[]")}, nil
		}
		return collect.Output{Stdout: []byte(`[{"type":"organization","id":"123456789012"}]`)}, nil
	case len(e.Argv) >= 2 && strings.Join(e.Argv[:2], " ") == "organizations describe":
		return collect.Output{Stdout: []byte(`{"displayName":"example.com"}`)}, nil
	case len(e.Argv) >= 2 && e.Argv[0] == "services" && e.Argv[1] == "list":
		if r.services != nil {
			return collect.Output{Stdout: r.services}, nil
		}
		return collect.Output{Stdout: []byte("[]")}, nil
	case len(e.Argv) >= 2 && e.Argv[0] == "container" && e.Argv[1] == "clusters":
		if r.clusters != nil {
			return collect.Output{Stdout: r.clusters}, nil
		}
		return collect.Output{Stdout: []byte("[]")}, nil
	default:
		return collect.Output{}, fmt.Errorf("unexpected argv %q", e.Argv)
	}
}

func fixtureRule(id string) *rule.Rule {
	return &rule.Rule{ID: id, Ref: "1.1", Title: id, Profile: "L1", Scope: "project", Mode: "deterministic", Severity: "low", Collect: []rule.Step{{ID: "instances", Gcloud: "compute instances list --project={{.project}} --format=json", Parse: "json"}}, Check: rule.Check{Assert: "true"}}
}

func fixtureDeps(t *testing.T, runner collect.Runner) Deps {
	t.Helper()
	allow, err := rule.LoadAllowlist()
	if err != nil {
		t.Fatal(err)
	}
	envs, err := eval.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	return Deps{Runner: runner, Gcloud: "gcloud", Allow: allow, Envs: envs, Rand: strings.NewReader(strings.Repeat("x", 128))}
}

func TestRun_DedupExecutesSharedCommandOnce(t *testing.T) {
	runner := &scanRunner{}
	deps := fixtureDeps(t, runner)
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{fixtureRule("a"), fixtureRule("b")}, Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if got := runner.computeCalls.Load(); got != 1 {
		t.Fatalf("compute list calls=%d", got)
	}
	if got := len(rep.Collectors); got != 1 {
		t.Fatalf("collectors=%d", got)
	}
	if rep.Scan.Coverage.Evaluated != 2 {
		t.Fatalf("coverage=%+v", rep.Scan.Coverage)
	}
}

func TestRun_ServicesDisabledYieldsNotApplicable(t *testing.T) {
	runner := &scanRunner{services: []byte("[]")}
	r := fixtureRule("service")
	r.Services = []string{"compute.googleapis.com"}
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Assessment.Status != "NOT_APPLICABLE" || runner.computeCalls.Load() != 0 {
		t.Fatalf("result=%+v calls=%d", rep.Results[0], runner.computeCalls.Load())
	}
}

func TestRun_PermissionDeniedYieldsSkippedAndGap(t *testing.T) {
	runner := &scanRunner{computeErr: []byte("PERMISSION_DENIED")}
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{fixtureRule("permission")}}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Scan.Status != "completed_with_gaps" || rep.Scan.Coverage.Skipped != 1 || rep.Results[0].Assessment.Status != "SKIPPED" {
		t.Fatalf("report=%+v", rep)
	}
}

func TestRun_EmptyConvertedFailureKeepsFailWithPartialCollection(t *testing.T) {
	runner := &scanRunner{computeErr: []byte("SERVICE_DISABLED")}
	r := fixtureRule("must-exist")
	r.Check.Assert = "size(data.instances) > 0"
	r.Check.Message = "resource missing"
	r.Collect[0].OnError = "empty"
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Results[0]
	if got.Assessment.Status != "FAIL" || got.Collection.Status != "PARTIAL" || got.Collection.Error == nil || got.Collection.Error.Class != "service_disabled" {
		t.Fatalf("result=%+v", got)
	}
}

func TestRun_EmptyPolicyPassesEmptyAndFilteredResources(t *testing.T) {
	hash := "sha256:" + strings.Repeat("a", 64)
	tests := []struct {
		name    string
		compute []byte
		filter  string
	}{
		{name: "empty resource source"},
		{name: "filtered resource source", compute: []byte(`[{"name":"sample"}]`), filter: "false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &scanRunner{compute: tt.compute}
			r := fixtureRule("empty-policy-pass")
			r.Hash = hash
			r.Resource = &rule.Resource{From: "data.instances", Filter: tt.filter, Kind: "compute.googleapis.com/Instance", Name: "r.name", Empty: "pass"}
			rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}, RulesetHash: hash, RulesetSource: "embedded", ProfileHash: hash}, fixtureDeps(t, runner))
			if err != nil {
				t.Fatal(err)
			}
			if len(rep.Results) != 1 || rep.Results[0].Assessment.Status != "PASS" || rep.Results[0].Resource.Key != "projects/example-prod" {
				t.Fatalf("results=%+v", rep.Results)
			}
			if rep.Results[0].Collection.Status != "SUCCEEDED" || rep.Scan.Coverage.Evaluated != 1 || rep.Scan.Coverage.NotApplicable != 0 {
				t.Fatalf("collection=%+v coverage=%+v", rep.Results[0].Collection, rep.Scan.Coverage)
			}
			if err := schemas.ValidateJSON("report", mustMarshal(t, rep)); err != nil {
				t.Fatalf("report schema: %v", err)
			}
		})
	}
}

func TestRun_EmptyResourcesRemainNotApplicableByDefault(t *testing.T) {
	runner := &scanRunner{}
	r := fixtureRule("empty-policy-default")
	r.Resource = &rule.Resource{From: "data.instances", Kind: "compute.googleapis.com/Instance", Name: "r.name"}
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Results[0].Assessment.Status; got != "NOT_APPLICABLE" || rep.Scan.Coverage.NotApplicable != 1 {
		t.Fatalf("result=%+v coverage=%+v", rep.Results[0], rep.Scan.Coverage)
	}
}

func TestRun_EmptyPolicySkipsWhenPopulationStepCapabilityIsMissing(t *testing.T) {
	runner := &scanRunner{}
	r := fixtureRule("empty-policy-missing-population-capability")
	r.Collect[0].Requires = []string{"kubectl"}
	r.Resource = &rule.Resource{From: "data.?instances.orValue([])", Kind: "compute.googleapis.com/Instance", Name: "r.name", Empty: "pass"}
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Results[0]
	if got.Assessment.Status != "SKIPPED" || got.Collection.Status != "FAILED" || got.Collection.Error == nil || !strings.Contains(got.Collection.Error.Summary, "instances: capability_missing") {
		t.Fatalf("result=%+v", got)
	}
}

func TestRun_EmptyPolicySkipsWhenDynamicResourceSourceMayUseMissingStep(t *testing.T) {
	hash := "sha256:" + strings.Repeat("a", 64)
	runner := &scanRunner{}
	r := fixtureRule("empty-policy-dynamic-population-capability")
	r.Hash = hash
	r.Collect[0].Requires = []string{"kubectl"}
	r.Resource = &rule.Resource{From: `['instances'].map(id, data[?id].orValue([])).flatten()`, Kind: "compute.googleapis.com/Instance", Name: "r.name", Empty: "pass"}
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}, RulesetHash: hash, RulesetSource: "embedded", ProfileHash: hash}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Results[0]
	if got.Assessment.Status != "SKIPPED" || got.Collection.Status != "FAILED" || got.Collection.Error == nil || !strings.Contains(got.Collection.Error.Summary, "instances: capability_missing") || rep.Scan.Coverage.Skipped != 1 {
		t.Fatalf("result=%+v", got)
	}
	if err := schemas.ValidateJSON("report", mustMarshal(t, rep)); err != nil {
		t.Fatalf("report schema: %v", err)
	}
}

func TestRun_EmptyPolicyAllowsUnrelatedMissingStepCapability(t *testing.T) {
	runner := &scanRunner{}
	r := fixtureRule("empty-policy-unrelated-missing-capability")
	r.Collect = append(r.Collect, rule.Step{ID: "optional", Gcloud: "compute disks list --project={{.project}} --format=json", Parse: "json", Requires: []string{"kubectl"}})
	r.Resource = &rule.Resource{From: "data.instances", Kind: "compute.googleapis.com/Instance", Name: "r.name", Empty: "pass"}
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Results[0]
	if got.Assessment.Status != "PASS" || got.Collection.Status != "PARTIAL" || got.Collection.Error == nil || !strings.Contains(got.Collection.Error.Summary, "optional: capability_missing") {
		t.Fatalf("result=%+v", got)
	}
}

func TestRun_EmptyPolicyPassesToleratedCollectionFailure(t *testing.T) {
	runner := &scanRunner{computeErr: []byte("SERVICE_DISABLED")}
	r := fixtureRule("empty-policy-tolerated")
	r.Collect[0].OnError = "empty"
	r.Resource = &rule.Resource{From: "data.instances", Kind: "compute.googleapis.com/Instance", Name: "r.name", Empty: "pass"}
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Results[0]
	if got.Assessment.Status != "PASS" || got.Resource.Key != "projects/example-prod" || got.Collection.Status != "PARTIAL" || got.Collection.Error == nil || got.Collection.Error.Class != "service_disabled" {
		t.Fatalf("result=%+v", got)
	}
}

func TestRun_EmptyPolicyDoesNotOverrideServiceOrCapabilityGates(t *testing.T) {
	tests := []struct {
		name string
		rule func() *rule.Rule
		want string
	}{
		{name: "service disabled", rule: func() *rule.Rule {
			r := fixtureRule("empty-policy-service-disabled")
			r.Services = []string{"compute.googleapis.com"}
			return r
		}, want: "NOT_APPLICABLE"},
		{name: "capability missing", rule: func() *rule.Rule {
			r := fixtureRule("empty-policy-capability-missing")
			r.Requires = []string{"kubectl"}
			return r
		}, want: "SKIPPED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &scanRunner{services: []byte("[]")}
			r := tt.rule()
			r.Resource = &rule.Resource{From: "data.instances", Kind: "compute.googleapis.com/Instance", Name: "r.name", Empty: "pass"}
			rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
			if err != nil {
				t.Fatal(err)
			}
			if rep.Results[0].Assessment.Status != tt.want || runner.computeCalls.Load() != 0 {
				t.Fatalf("result=%+v calls=%d", rep.Results[0], runner.computeCalls.Load())
			}
		})
	}
}

func TestRun_EmptyPolicyDoesNotOverrideCollectionOrResourceExpressionErrors(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*rule.Rule)
		runner    *scanRunner
	}{
		{name: "collection error", runner: &scanRunner{computeErr: []byte("PERMISSION_DENIED")}},
		{name: "resource expression error", runner: &scanRunner{}, configure: func(r *rule.Rule) { r.Resource.From = "data.instances[" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := fixtureRule("empty-policy-error")
			r.Resource = &rule.Resource{From: "data.instances", Kind: "compute.googleapis.com/Instance", Name: "r.name", Empty: "pass"}
			r.Collect[0].OnError = "empty"
			if tt.configure != nil {
				tt.configure(r)
			}
			rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, tt.runner))
			if err != nil {
				t.Fatal(err)
			}
			if rep.Results[0].Assessment.Status != "SKIPPED" && rep.Results[0].Assessment.Status != "ERROR" {
				t.Fatalf("result=%+v", rep.Results[0])
			}
		})
	}
}

func TestRun_AuthExpiredAbortsWithCode3(t *testing.T) {
	runner := &scanRunner{}
	runner.computeErr = []byte("Reauthentication failed")
	_, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{fixtureRule("auth")}}, fixtureDeps(t, runner))
	runErr, ok := err.(*RunError)
	if !ok || runErr.Code != 3 {
		t.Fatalf("error=%T %v", err, err)
	}
}

func TestRun_CancelStopsSchedulingAndReturnsErrCanceled(t *testing.T) {
	runner := &scanRunner{delay: 200 * time.Millisecond}
	rules := []*rule.Rule{fixtureRule("a"), fixtureRule("b"), fixtureRule("c")}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	_, err := Run(ctx, Options{Projects: []string{"example-prod"}, Rules: rules, Parallel: 1}, fixtureDeps(t, runner))
	if err != ErrCanceled {
		t.Fatalf("error=%v", err)
	}
	if runner.computeCalls.Load() > 1 {
		t.Fatalf("scheduled %d commands", runner.computeCalls.Load())
	}
}

func TestRun_DeterministicAcrossRuns(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	run := func() []byte {
		runner := &scanRunner{}
		deps := fixtureDeps(t, runner)
		rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{fixtureRule("stable")}, Now: now}, deps)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		collectors := doc["collectors"].([]any)
		for _, item := range collectors {
			c := item.(map[string]any)
			c["started_at"] = ""
			c["duration_ms"] = float64(0)
		}
		scan := doc["scan"].(map[string]any)
		scan["started_at"] = ""
		scan["finished_at"] = ""
		normalized, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return normalized
	}
	a, b := run(), run()
	if string(a) != string(b) {
		t.Fatalf("reports differ\n%s\n%s", a, b)
	}
}

func TestRun_RESTGuardFailureIsReportedAndNotOmitted(t *testing.T) {
	runner := &scanRunner{}
	r := fixtureRule("rest")
	r.Collect = []rule.Step{{ID: "rest", API: &rule.APIStep{Method: "GET", URL: "https://example.com/v1"}}}
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Assessment.Status != "ERROR" || rep.Results[0].Collection.Error == nil || rep.Results[0].Collection.Error.Class != "guard_rejected" || runner.tokenCalls.Load() != 0 {
		t.Fatalf("results=%+v", rep.Results)
	}
}

func TestRun_UnsatisfiedStepRequiresIsDroppedAndMarkedPartial(t *testing.T) {
	runner := &scanRunner{}
	r := fixtureRule("optional-step")
	r.Collect[0].Requires = []string{"kubectl"}
	r.Check.Assert = "true"
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Collection.Status != "PARTIAL" || runner.computeCalls.Load() != 0 {
		t.Fatalf("result=%+v calls=%d", rep.Results[0], runner.computeCalls.Load())
	}
}

func TestRun_GuardRejectionYieldsErrorWithoutExecution(t *testing.T) {
	runner := &scanRunner{}
	r := fixtureRule("guard")
	r.Collect[0].Gcloud = "compute instances list --project=other-project --format=json"
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Results[0]
	if got.Assessment.Status != "ERROR" || got.Collection.Error == nil || got.Collection.Error.Class != "guard_rejected" || runner.computeCalls.Load() != 0 {
		t.Fatalf("result=%+v calls=%d", got, runner.computeCalls.Load())
	}
}

func TestRun_OrganizationDomainResolvedOnlyWhenRuleNeedsIt(t *testing.T) {
	for _, tc := range []struct {
		name, assert string
		want         int
	}{{"unused", "true", 0}, {"needed", `organization_domain == "example.com"`, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &scanRunner{}
			r := fixtureRule("org")
			r.Scope = "organization"
			r.EvaluatePer = "organization"
			r.Collect = nil
			r.Check.Assert = tc.assert
			_, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			runner.mu.Lock()
			for _, argv := range runner.argv {
				if len(argv) > 1 && argv[0] == "organizations" && argv[1] == "describe" {
					count++
				}
			}
			runner.mu.Unlock()
			if count != tc.want {
				t.Fatalf("organizations describe calls=%d want %d", count, tc.want)
			}
		})
	}
}

func TestRun_OrganizationRuleSkippedWithoutOrg(t *testing.T) {
	runner := &scanRunner{noOrganization: true}
	r := fixtureRule("org-no-parent")
	r.Scope = "organization"
	r.EvaluatePer = "organization"
	r.Collect = nil
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Assessment.Status != "SKIPPED" || rep.Scan.Coverage.Skipped != 1 {
		t.Fatalf("report=%+v", rep)
	}
}

func TestRun_FanoutTruncationEvaluatesFirstItemsAndReportsError(t *testing.T) {
	runner := &scanRunner{compute: []byte(`[{"name":"one"},{"name":"two"},{"name":"three"}]`)}
	r := fixtureRule("fanout")
	r.Collect = []rule.Step{{ID: "instances", Gcloud: "compute instances list --project={{.project}} --format=json", Parse: "json"}, {ID: "details", Gcloud: "compute instances list --project={{.project}} --filter=name={{.item.name}} --format=json", Parse: "json", Foreach: "data.instances", As: "item"}}
	r.Resource = &rule.Resource{From: "data.instances", Kind: "compute.googleapis.com/Instance", Name: "r.name", Key: "r.name"}
	r.Check.Assert = "true"
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}, MaxFanout: 1}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, result := range rep.Results {
		if result.Assessment.Status == "ERROR" && strings.Contains(result.Assessment.Message, "evaluated 1 of 3") {
			found = true
			if result.Collection.Status != "PARTIAL" || result.Collection.Error == nil || result.Collection.Error.Class != "fanout_exceeded" || !strings.Contains(result.Collection.Error.Summary, "evaluated 1 of 3") {
				t.Fatalf("fanout aggregate collection=%+v", result.Collection)
			}
		} else if result.Assessment.Status == "ERROR" && result.Collection.Status != "PARTIAL" {
			t.Fatalf("fanout item collection=%+v", result.Collection)
		}
	}
	if !found {
		t.Fatalf("fanout aggregate error missing: %+v", rep.Results)
	}
	if runner.computeCalls.Load() != 2 {
		t.Fatalf("compute calls=%d", runner.computeCalls.Load())
	}
}

func TestRun_AggregateRuleWithFailedForeachItemIsNotEvaluated(t *testing.T) {
	runner := &scanRunner{compute: []byte(`[{"name":"one"},{"name":"two"},{"name":"three"}]`), describeErr: []byte("PERMISSION_DENIED")}
	r := fixtureRule("aggregate-foreach")
	r.Resource = nil
	r.Collect = []rule.Step{{ID: "instances", Gcloud: "compute instances list --project={{.project}} --format=json", Parse: "json"}, {ID: "details", Gcloud: "compute instances list --project={{.project}} --filter=name={{.item.name}} --format=json", Parse: "json", Foreach: "data.instances", As: "item"}}
	r.Check.Assert = "true"
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Assessment.Status != "SKIPPED" {
		t.Fatalf("results=%+v", rep.Results)
	}
	collection := rep.Results[0].Collection
	if collection.Status != "PARTIAL" || collection.Error == nil || collection.Error.Class != "permission_denied" || !strings.Contains(collection.Error.Summary, "details") {
		t.Fatalf("aggregate failed-item collection=%+v", collection)
	}
}

func TestRun_ForeachSingleFailureMarksCollectionPartial(t *testing.T) {
	runner := &scanRunner{compute: []byte(`[{"name":"one"},{"name":"two"},{"name":"three"}]`), describeErr: []byte("PERMISSION_DENIED")}
	r := fixtureRule("resource-foreach-failure")
	r.Collect = []rule.Step{{ID: "instances", Gcloud: "compute instances list --project={{.project}} --format=json", Parse: "json"}, {ID: "details", Gcloud: "compute instances list --project={{.project}} --filter=name={{.item.name}} --format=json", Parse: "json", Foreach: "data.instances", As: "item"}}
	r.Resource = &rule.Resource{From: "data.instances", Kind: "compute.googleapis.com/Instance", Name: "r.name", Key: "r.name"}
	r.Check.Assert = "true"
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	var failed *report.Result
	for i := range rep.Results {
		if rep.Results[i].Resource.Key == "two" {
			failed = &rep.Results[i]
			break
		}
	}
	if failed == nil || failed.Assessment.Status != "SKIPPED" || failed.Collection.Status != "PARTIAL" || failed.Collection.Error == nil || failed.Collection.Error.Class != "permission_denied" || !strings.Contains(failed.Collection.Error.Summary, "details") {
		t.Fatalf("failed result=%+v all=%+v", failed, rep.Results)
	}
}

func TestRun_ClusterUnitExposesDataClusterAndCtxCluster(t *testing.T) {
	runner := &scanRunner{clusters: []byte(`[{"name":"demo","location":"us-central1"}]`)}
	r := fixtureRule("cluster")
	r.Scope = "cluster"
	r.Collect = nil
	r.Check.Assert = "data.cluster.name == ctx.cluster.name && ctx.cluster.name == \"demo\""
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Assessment.Status != "PASS" || rep.Results[0].Target.Type != "cluster" {
		t.Fatalf("results=%+v", rep.Results)
	}
}

func TestRun_ClusterInventoryNotRunWithoutClusterRules(t *testing.T) {
	runner := &scanRunner{}
	r := fixtureRule("project-only")
	r.Hash = "sha256:" + strings.Repeat("0", 64)
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}, RulesetHash: "sha256:" + strings.Repeat("0", 64), RulesetSource: "embedded", ProfileHash: "sha256:" + strings.Repeat("0", 64)}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	target := rep.Scan.Targets[0]
	if target.Clusters.Status != "NOT_RUN" || len(target.Clusters.Names) != 0 || len(target.Clusters.Unreachable) != 0 {
		t.Fatalf("clusters=%+v", target.Clusters)
	}
	doc, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateJSON("report", doc); err != nil {
		t.Fatalf("report schema: %v", err)
	}
}

func TestRun_ClusterInventorySucceededWhenEnumerated(t *testing.T) {
	runner := &scanRunner{clusters: []byte(`[]`)}
	r := fixtureRule("cluster-empty")
	r.Scope = "cluster"
	r.Collect = nil
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Scan.Targets[0].Clusters.Status; got != "SUCCEEDED" {
		t.Fatalf("cluster status=%s", got)
	}
}

func TestRun_ProjectMetadataReusedFromPlanResolution(t *testing.T) {
	runner := &scanRunner{}
	r := fixtureRule("project-meta")
	r.Collect = nil
	r.Check.Assert = `ctx.project_number == "123456789012"`
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Assessment.Status != "PASS" || rep.Scan.Targets[0].Number == nil || *rep.Scan.Targets[0].Number != "123456789012" {
		t.Fatalf("result=%+v target=%+v", rep.Results[0], rep.Scan.Targets[0])
	}
	if countArgv(runner, "projects", "describe") != 1 || countArgv(runner, "projects", "get-ancestors") != 1 {
		t.Fatalf("project metadata commands repeated: describe=%d ancestors=%d", countArgv(runner, "projects", "describe"), countArgv(runner, "projects", "get-ancestors"))
	}
}

func TestRun_OrganizationMetadataOnlyForExecutableDependencies(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*rule.Rule)
		want      int
	}{
		{name: "notes_do_not_trigger", configure: func(r *rule.Rule) { r.Notes = "organization_domain" }, want: 0},
		{name: "remediation_does_not_trigger", configure: func(r *rule.Rule) { r.Remediation = "organization_domain" }, want: 0},
		{name: "capability_skip", configure: func(r *rule.Rule) {
			r.Requires = []string{"kubectl"}
			r.Check.Assert = "ctx.organization_domain != \"\""
		}, want: 0},
		{name: "service_skip", configure: func(r *rule.Rule) {
			r.Services = []string{"compute.googleapis.com"}
			r.Check.Assert = "ctx.organization_domain != \"\""
		}, want: 0},
		{name: "step_requirement_filter", configure: func(r *rule.Rule) {
			r.Check.Assert = "true"
			r.Collect[0].Requires = []string{"kubectl"}
			r.Collect[0].Gcloud = "compute instances list --project={{.project}} --filter=name={{.organization_domain}} --format=json"
		}, want: 0},
		{name: "rest_guard_rejection", configure: func(r *rule.Rule) {
			r.Check.Assert = "true"
			r.Collect = []rule.Step{{ID: "api", API: &rule.APIStep{Method: "GET", URL: "https://example.com/v1"}}}
		}, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &scanRunner{}
			r := fixtureRule(tc.name)
			tc.configure(r)
			_, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
			if err != nil {
				t.Fatal(err)
			}
			if got := countArgv(runner, "organizations", "describe"); got != tc.want {
				t.Fatalf("organization domain calls=%d want %d", got, tc.want)
			}
		})
	}
}

func TestRun_AllUnitsSkippedYieldsExitFour(t *testing.T) {
	runner := &scanRunner{}
	r := fixtureRule("needs-kubectl")
	r.Requires = []string{"kubectl"}
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, fixtureDeps(t, runner))
	if err != nil {
		t.Fatal(err)
	}
	if code := rep.ExitCode(nil); code != 4 {
		t.Fatalf("exit code=%d", code)
	}
}

func TestCollectRule_RunsOnlySelectedGcloudStep(t *testing.T) {
	runner := &scanRunner{}
	r := fixtureRule("collect-only")
	r.Params = map[string]any{"limit": int64(4)}
	result, err := CollectRule(context.Background(), Options{Projects: []string{"example-prod"}}, fixtureDeps(t, runner), r, "instances")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Collectors) != 1 || result.Data["instances"] == nil || result.Params["limit"] != int64(4) {
		t.Fatalf("result=%+v", result)
	}
	for _, argv := range runner.argv {
		if len(argv) > 1 && argv[0] == "services" {
			t.Fatal("CollectRule performed service preflight")
		}
	}
}

type engineRoundTripper func(*http.Request) (*http.Response, error)

func (f engineRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func restResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}
}

func restFixtureRule(id, url string) *rule.Rule {
	r := fixtureRule(id)
	r.Collect = []rule.Step{{ID: "datasets", API: &rule.APIStep{Method: "GET", URL: url, Paginate: true, ListField: "datasets"}}}
	r.Resource = &rule.Resource{From: "data.datasets", Kind: "bigquery.googleapis.com/Dataset", Name: "r.datasetReference.datasetId", Key: "r.datasetReference.datasetId"}
	r.Check.Assert = "true"
	return r
}

func TestRun_ExecutesRESTStepsAndKeepsCollectorReferences(t *testing.T) {
	runner := &scanRunner{}
	var calls atomic.Int32
	deps := fixtureDeps(t, runner)
	deps.HTTPTransport = engineRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		if request.Header.Get("Authorization") != "Bearer fake-token" {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		if request.URL.Query().Get("pageToken") == "next" {
			return restResponse(request, http.StatusOK, `{"datasets":[{"datasetReference":{"datasetId":"two"}}]}`), nil
		}
		return restResponse(request, http.StatusOK, `{"datasets":[{"datasetReference":{"datasetId":"one"}}],"nextPageToken":"next"}`), nil
	})
	r := restFixtureRule("rest-pages", "https://bigquery.googleapis.com/bigquery/v2/projects/{{.project}}/datasets")
	r.Hash = "sha256:" + strings.Repeat("a", 64)
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}, RulesetHash: r.Hash, RulesetSource: "embedded", ProfileHash: r.Hash}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || runner.tokenCalls.Load() != 1 {
		t.Fatalf("HTTP calls=%d token calls=%d", calls.Load(), runner.tokenCalls.Load())
	}
	if len(rep.Results) != 2 || len(rep.Collectors) != 1 {
		t.Fatalf("results=%+v collectors=%+v", rep.Results, rep.Collectors)
	}
	for _, result := range rep.Results {
		if result.Assessment.Status != "PASS" || len(result.Collection.CollectorIDs) != 1 || result.Collection.CollectorIDs[0] != rep.Collectors[0].ID {
			t.Fatalf("result lost collector reference: %+v", result)
		}
	}
	if rep.Collectors[0].Type != "api" || strings.Contains(rep.Collectors[0].Command, "fake-token") {
		t.Fatalf("collector=%+v", rep.Collectors[0])
	}
	doc, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateJSON("report", doc); err != nil {
		t.Fatalf("report schema: %v", err)
	}
}

func TestRun_DeduplicatesRESTAndIsolatesUnitData(t *testing.T) {
	runner := &scanRunner{}
	var calls atomic.Int32
	deps := fixtureDeps(t, runner)
	deps.HTTPTransport = engineRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		if !strings.Contains(request.URL.Path, "example-prod") && !strings.Contains(request.URL.Path, "second-prod") {
			t.Errorf("unexpected URL %q", request.URL)
		}
		return restResponse(request, http.StatusOK, `{"datasets":[{"datasetReference":{"datasetId":"one"}}]}`), nil
	})
	url := "https://bigquery.googleapis.com/bigquery/v2/projects/{{.project}}/datasets"
	rules := []*rule.Rule{restFixtureRule("rest-a", url), restFixtureRule("rest-b", url)}
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod", "second-prod"}, Rules: rules}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || len(rep.Collectors) != 2 || len(rep.Results) != 4 {
		t.Fatalf("HTTP calls=%d collectors=%d results=%d", calls.Load(), len(rep.Collectors), len(rep.Results))
	}
	seen := map[string]map[string]bool{}
	for _, result := range rep.Results {
		if result.Assessment.Status != "PASS" || result.Resource.Key != "one" || len(result.Collection.CollectorIDs) != 1 {
			t.Fatalf("unexpected isolated result: %+v", result)
		}
		if seen[result.Target.Key] == nil {
			seen[result.Target.Key] = map[string]bool{}
		}
		seen[result.Target.Key][result.Collection.CollectorIDs[0]] = true
	}
	if len(seen) != 2 {
		t.Fatalf("unit data was not isolated: %v", seen)
	}
}

func TestRun_RESTFailureMapsToAssessmentStatus(t *testing.T) {
	runner := &scanRunner{}
	deps := fixtureDeps(t, runner)
	deps.HTTPTransport = engineRoundTripper(func(request *http.Request) (*http.Response, error) {
		return restResponse(request, http.StatusForbidden, `{"error":{"status":"PERMISSION_DENIED"}}`), nil
	})
	r := restFixtureRule("rest-denied", "https://bigquery.googleapis.com/bigquery/v2/projects/{{.project}}/datasets")
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Assessment.Status != "SKIPPED" || rep.Results[0].Collection.Status != "FAILED" || rep.Results[0].Collection.Error == nil || rep.Results[0].Collection.Error.Class != "permission_denied" {
		t.Fatalf("failure mapping = %+v", rep.Results)
	}

	missingRunner := &scanRunner{}
	missingDeps := fixtureDeps(t, missingRunner)
	missingDeps.HTTPTransport = engineRoundTripper(func(request *http.Request) (*http.Response, error) {
		return restResponse(request, http.StatusNotFound, `{"error":{"status":"NOT_FOUND"}}`), nil
	})
	missing := restFixtureRule("rest-missing", "https://bigquery.googleapis.com/bigquery/v2/projects/{{.project}}/datasets")
	missing.Resource = nil
	missing.Collect[0].OnError = "empty"
	missing.Check.Assert = "size(data.datasets) > 0"
	missingRep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{missing}}, missingDeps)
	if err != nil {
		t.Fatal(err)
	}
	if len(missingRep.Results) != 1 || missingRep.Results[0].Assessment.Status != "FAIL" || missingRep.Results[0].Collection.Status != "PARTIAL" || missingRep.Results[0].Collection.Error == nil || missingRep.Results[0].Collection.Error.Class != "not_found" {
		t.Fatalf("tolerated REST failure mapping = %+v", missingRep.Results)
	}
}

func TestRun_RESTForeachAttachKeepsIdentityOnPartialFailure(t *testing.T) {
	runner := &scanRunner{}
	deps := fixtureDeps(t, runner)
	deps.HTTPTransport = engineRoundTripper(func(request *http.Request) (*http.Response, error) {
		if strings.HasSuffix(request.URL.Path, "/datasets") {
			return restResponse(request, http.StatusOK, `{"datasets":[{"datasetReference":{"datasetId":"one"}},{"datasetReference":{"datasetId":"two"}}]}`), nil
		}
		if strings.HasSuffix(request.URL.Path, "/two") {
			return restResponse(request, http.StatusForbidden, `{"error":{"status":"PERMISSION_DENIED"}}`), nil
		}
		return restResponse(request, http.StatusOK, `{"allowed":true}`), nil
	})
	r := restFixtureRule("rest-foreach", "https://bigquery.googleapis.com/bigquery/v2/projects/{{.project}}/datasets")
	r.Collect = append(r.Collect, rule.Step{ID: "details", Foreach: "data.datasets", As: "item", Attach: "details", API: &rule.APIStep{Method: "GET", URL: "https://bigquery.googleapis.com/bigquery/v2/projects/{{.project}}/datasets/{{.item.datasetReference.datasetId}}"}})
	r.Check.Assert = "r.details.allowed == true"
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 2 {
		t.Fatalf("results=%+v", rep.Results)
	}
	for _, result := range rep.Results {
		if result.Resource.Key == "one" {
			if result.Assessment.Status != "PASS" || result.Collection.Status != "PARTIAL" || len(result.Collection.CollectorIDs) != 3 {
				t.Fatalf("successful foreach result=%+v", result)
			}
		} else if result.Resource.Key == "two" {
			if result.Assessment.Status != "SKIPPED" || result.Collection.Status != "PARTIAL" || len(result.Collection.CollectorIDs) != 3 {
				t.Fatalf("failed foreach result=%+v", result)
			}
		} else {
			t.Fatalf("unexpected resource identity: %+v", result)
		}
	}
}

func TestRun_RESTGuardRejectsBeforeToken(t *testing.T) {
	runner := &scanRunner{}
	var calls atomic.Int32
	deps := fixtureDeps(t, runner)
	deps.HTTPTransport = engineRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return restResponse(request, http.StatusOK, `{"datasets":[]}`), nil
	})
	r := restFixtureRule("rest-guard", "https://bigquery.googleapis.com/bigquery/v2/projects/other-prod/datasets")
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Assessment.Status != "ERROR" || rep.Results[0].Collection.Error == nil || rep.Results[0].Collection.Error.Class != "guard_rejected" {
		t.Fatalf("guard result = %+v", rep.Results)
	}
	if runner.tokenCalls.Load() != 0 || calls.Load() != 0 {
		t.Fatalf("guard rejection reached token or transport: tokenCalls=%d transportCalls=%d", runner.tokenCalls.Load(), calls.Load())
	}
}

func TestRun_RESTGuardRejectsOrganizationProjectReferenceBeforeToken(t *testing.T) {
	runner := &scanRunner{}
	var calls atomic.Int32
	deps := fixtureDeps(t, runner)
	deps.HTTPTransport = engineRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		return restResponse(request, http.StatusOK, `{"items":[]}`), nil
	})
	r := fixtureRule("org-rest-guard")
	r.Scope = "organization"
	r.EvaluatePer = "organization"
	r.Collect = []rule.Step{{ID: "items", API: &rule.APIStep{Method: "GET", URL: "https://bigquery.googleapis.com/v2/projects/other-prod/items"}}}
	rep, err := Run(context.Background(), Options{Projects: []string{"example-prod"}, Rules: []*rule.Rule{r}}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Assessment.Status != "ERROR" || rep.Results[0].Collection.Error == nil || rep.Results[0].Collection.Error.Class != "guard_rejected" {
		t.Fatalf("organization guard result = %+v", rep.Results)
	}
	if runner.tokenCalls.Load() != 0 || calls.Load() != 0 {
		t.Fatalf("organization guard rejection reached token or transport: tokenCalls=%d transportCalls=%d", runner.tokenCalls.Load(), calls.Load())
	}
}

func TestCollectRule_ExecutesAllGcloudStepsAndAppliesSelectedStepScope(t *testing.T) {
	runner := &scanRunner{}
	r := fixtureRule("collect-multi")
	r.Collect = append(r.Collect, rule.Step{ID: "disks", Gcloud: "compute disks list --project={{.project}} --format=json", Parse: "json"})
	all, err := CollectRule(context.Background(), Options{Projects: []string{"example-prod"}}, fixtureDeps(t, runner), r, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Data) != 2 || len(all.Collectors) != 2 {
		t.Fatalf("all steps result=%+v", all)
	}
	runner = &scanRunner{}
	second, err := CollectRule(context.Background(), Options{Projects: []string{"example-prod"}}, fixtureDeps(t, runner), r, "disks")
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Data) != 1 || second.Data["disks"] == nil || len(second.Collectors) != 1 || runner.computeCalls.Load() != 1 {
		t.Fatalf("selected result=%+v calls=%d", second, runner.computeCalls.Load())
	}
}

func TestCollectRule_AppliesAllowlistAndProjectScopeGuard(t *testing.T) {
	for _, tc := range []struct{ name, command string }{{"project_scope", "compute instances list --project=other-project --format=json"}, {"flag_whitelist", "compute instances list --project=example-prod --bad-flag=value"}} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &scanRunner{}
			r := fixtureRule("collect-guard")
			r.Collect[0].Gcloud = tc.command
			_, err := CollectRule(context.Background(), Options{Projects: []string{"example-prod"}}, fixtureDeps(t, runner), r, "instances")
			f, ok := failure.As(err)
			if !ok || f.Class != "guard_rejected" || runner.computeCalls.Load() != 0 {
				t.Fatalf("err=%v calls=%d", err, runner.computeCalls.Load())
			}
		})
	}
}

func countArgv(r *scanRunner, prefix ...string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, argv := range r.argv {
		if len(argv) >= len(prefix) {
			matches := true
			for i, v := range prefix {
				if argv[i] != v {
					matches = false
					break
				}
			}
			if matches {
				count++
			}
		}
	}
	return count
}

func TestGcloudEnvOverrides_DisableLoggingUpdatesPromptsAndUsageReporting(t *testing.T) {
	got := GcloudEnvOverrides()
	want := map[string]string{"CLOUDSDK_CORE_DISABLE_FILE_LOGGING": "1", "CLOUDSDK_CORE_DISABLE_USAGE_REPORTING": "true", "CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK": "1", "CLOUDSDK_CORE_DISABLE_PROMPTS": "1"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s=%q want %q", k, got[k], v)
		}
	}
}

var _ = report.Report{}
