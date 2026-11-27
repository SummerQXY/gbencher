package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/SummerQXY/gbencher/internal/auth"
	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/eval"
	"github.com/SummerQXY/gbencher/internal/failure"
	"github.com/SummerQXY/gbencher/internal/plan"
	"github.com/SummerQXY/gbencher/internal/report"
	"github.com/SummerQXY/gbencher/internal/rule"
)

type Options struct {
	Projects                                             []string
	Rules                                                []*rule.Rule
	Enable                                               []string
	Parallel, MaxFanout                                  int
	CommandTimeout, Timeout                              time.Duration
	Account, Impersonate, QuotaProject                   string
	Now                                                  time.Time
	ToolVersion, RulesetHash, RulesetSource, ProfileHash string
	Benchmarks, Levels                                   []string
}

type Deps struct {
	Runner         collect.Runner
	Gcloud         string
	Kubectl        string
	Env            []string
	Allow          *rule.Allowlist
	Envs           *eval.Env
	Rand           io.Reader
	HTTPTransport  http.RoundTripper
	WorkspaceADC   func(context.Context, []string) (WorkspaceTokenSource, error)
	Kubeconfigs    *auth.KubeconfigManager
	workspaceAuth  *workspaceAuthManager
	kubectlVersion *string
}

func GcloudEnvOverrides() map[string]string {
	return map[string]string{"CLOUDSDK_CORE_DISABLE_FILE_LOGGING": "1", "CLOUDSDK_CORE_DISABLE_USAGE_REPORTING": "true", "CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK": "1", "CLOUDSDK_CORE_DISABLE_PROMPTS": "1"}
}

var ErrCanceled = errors.New("scan canceled")

type RunError struct {
	Code int
	Err  error
}

func (e *RunError) Error() string {
	if e == nil || e.Err == nil {
		return "scan cannot run"
	}
	return e.Err.Error()
}
func (e *RunError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type CollectResult struct {
	Params, Data map[string]any
	Collectors   []report.Collector
	Account      string
}

type limitedRunner struct {
	inner   collect.Runner
	timeout time.Duration
}

func (r limitedRunner) Run(ctx context.Context, e collect.Exec, l collect.Limits) (collect.Output, error) {
	if l.Timeout <= 0 {
		l.Timeout = r.timeout
	}
	if l.MaxOutput <= 0 {
		l.MaxOutput = 64 << 20
	}
	return r.inner.Run(ctx, e, l)
}

func readKubectlClientVersion(ctx context.Context, runner collect.Runner, path string, env []string, timeout time.Duration) (*string, error) {
	if runner == nil || path == "" {
		return nil, errors.New("kubectl executable is unavailable")
	}
	if timeout <= 0 || timeout > 15*time.Second {
		timeout = 15 * time.Second
	}
	versionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := runner.Run(versionCtx, collect.Exec{Path: path, Argv: []string{"version", "--client", "-o", "json"}, Env: collect.ChildEnv(env, nil)}, collect.Limits{Timeout: timeout, MaxOutput: 1 << 20})
	if err != nil {
		return nil, errors.New("kubectl client version could not be read")
	}
	if out.TimedOut || out.Truncated || out.ExitCode != 0 {
		return nil, errors.New("kubectl client version check failed")
	}
	value, err := collect.DecodeJSON(out.Stdout)
	if err != nil {
		return nil, errors.New("kubectl client version output is invalid JSON")
	}
	document, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("kubectl client version output is invalid")
	}
	client, ok := document["clientVersion"].(map[string]any)
	if !ok {
		return nil, errors.New("kubectl client version output is missing clientVersion")
	}
	version, ok := client["gitVersion"].(string)
	if !ok || strings.TrimSpace(version) == "" {
		return nil, errors.New("kubectl client version output has no gitVersion")
	}
	return &version, nil
}

func Run(parent context.Context, opts Options, deps Deps) (*report.Report, error) {
	if parent.Err() != nil {
		return nil, ErrCanceled
	}
	if deps.Runner == nil || deps.Allow == nil || deps.Gcloud == "" {
		return nil, &RunError{Code: 3, Err: errors.New("runner, gcloud path, and allowlist are required")}
	}
	if opts.Parallel <= 0 {
		opts.Parallel = 8
	}
	if opts.MaxFanout <= 0 {
		opts.MaxFanout = 500
	}
	if opts.CommandTimeout <= 0 {
		opts.CommandTimeout = 120 * time.Second
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	ctx := parent
	cancel := func() {}
	if opts.Timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, opts.Timeout)
	}
	defer cancel()
	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	check := func(argv []string) error { return checkGcloud(deps.Allow, argv, true) }
	client, err := auth.Resolve(runCtx, limitedRunner{deps.Runner, opts.CommandTimeout}, deps.Gcloud, deps.Env, check, auth.Options{Account: opts.Account, Impersonate: opts.Impersonate, QuotaProject: opts.QuotaProject})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ErrCanceled
		}
		return nil, &RunError{Code: 3, Err: err}
	}
	if contains(opts.Enable, "workspace-admin") {
		deps.workspaceAuth = newWorkspaceAuthManager(deps.WorkspaceADC, opts.Account)
	}
	pd := &clientPlanDeps{client: client, projects: make(map[string]*projectMetadata)}
	units, issues, buildErr := plan.Build(runCtx, opts.Rules, opts.Projects, pd)
	if buildErr != nil {
		if ctx.Err() != nil {
			return nil, ErrCanceled
		}
		return nil, &RunError{Code: 3, Err: buildErr}
	}
	if contains(opts.Enable, "kubectl") && hasKubectlRules(opts.Rules) {
		if deps.Kubectl == "" {
			return nil, &RunError{Code: 3, Err: errors.New("kubectl executable is required when kubectl collection is enabled")}
		}
		kubectlVersion, versionErr := readKubectlClientVersion(runCtx, deps.Runner, deps.Kubectl, deps.Env, opts.CommandTimeout)
		if versionErr != nil {
			if runCtx.Err() != nil {
				return nil, ErrCanceled
			}
			return nil, &RunError{Code: 3, Err: versionErr}
		}
		deps.kubectlVersion = kubectlVersion
		executable, executableErr := os.Executable()
		if executableErr != nil {
			return nil, &RunError{Code: 3, Err: errors.New("cannot locate gbench executable")}
		}
		manager, managerErr := auth.NewKubeconfigManager(runCtx, executable, client.Identity)
		if managerErr != nil {
			return nil, &RunError{Code: 3, Err: managerErr}
		}
		deps.Kubeconfigs = manager
		defer func() { _ = manager.Close() }()
	}
	projectMetadata := pd.snapshot()
	enabled := make(map[string]map[string]bool)
	for _, project := range unique(opts.Projects) {
		services, e := client.EnabledServices(runCtx, project)
		if e == nil {
			enabled[project] = services
		} else if f, ok := failure.As(e); ok && f.Fatal() {
			return nil, &RunError{Code: 3, Err: f}
		}
	}
	if deps.Envs == nil {
		deps.Envs, err = eval.NewEnv()
		if err != nil {
			return nil, &RunError{Code: 3, Err: err}
		}
	}
	guard := plan.Guard{Allow: deps.Allow}
	shared := newExecutor(ctx, client, limitedRunner{deps.Runner, opts.CommandTimeout}, deps.Gcloud, deps.Env, guard, "", rule.Step{}, opts.CommandTimeout)
	shared.rest = collect.NewRESTClient(opts.CommandTimeout, 64<<20, deps.HTTPTransport)
	shared.workspaceAuth = deps.workspaceAuth
	if deps.Kubeconfigs != nil && contains(opts.Enable, "kubectl") && hasKubectlRules(opts.Rules) {
		kubectlCollector, collectorErr := collect.NewKubectlCollector(deps.Runner, deps.Kubectl, deps.Env, deps.Allow, deps.Kubeconfigs, opts.CommandTimeout)
		if collectorErr != nil {
			return nil, &RunError{Code: 3, Err: collectorErr}
		}
		clusters := make(map[string]any)
		for _, unit := range units {
			if unit.Target.Type == "cluster" {
				clusters[unit.Target.Key] = unit.Target.Cluster
			}
		}
		shared.kubectl = kubectlCollector
		shared.probe = newClusterProbeFuse(func(ctx context.Context, request clusterProbeRequest) (collect.Output, error) {
			cluster, ok := clusters[request.ClusterKey]
			if !ok {
				return collect.Output{}, errors.New("cluster description is unavailable")
			}
			return runClusterProbe(ctx, deps.Runner, deps.Kubectl, deps.Env, deps.Kubeconfigs, cluster, request)
		})
	}
	orgCache := &domainCache{values: map[string]domainValue{}}
	type unitOutput struct {
		results []report.Result
		unit    report.UnitRef
		err     error
		fatal   bool
	}
	outputs := make([]unitOutput, len(units))
	var fatalMu sync.Mutex
	var fatalErr error
	jobs := make(chan int)
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for i := range jobs {
			if runCtx.Err() != nil {
				continue
			}
			metadata := projectMetadata[units[i].Target.ProjectID]
			outputs[i] = runUnit(runCtx, opts, deps, client, shared, guard, deps.Envs, units[i], metadata.number, enabled[units[i].Target.ProjectID], orgCache)
			if outputs[i].fatal {
				fatalMu.Lock()
				if fatalErr == nil {
					fatalErr = outputs[i].err
				}
				fatalMu.Unlock()
				stopRun()
			}
		}
	}
	n := min(opts.Parallel, max(1, len(units)))
	for i := 0; i < n; i++ {
		wg.Add(1)
		go worker()
	}
	schedule := true
	for i := range units {
		if parent.Err() != nil || ctx.Err() != nil {
			schedule = false
			break
		}
		select {
		case jobs <- i:
		case <-runCtx.Done():
			schedule = false
		}
		if !schedule {
			break
		}
	}
	close(jobs)
	wg.Wait()
	if fatalErr != nil {
		return nil, &RunError{Code: 3, Err: fatalErr}
	}
	if parent.Err() != nil || ctx.Err() != nil {
		return nil, ErrCanceled
	}
	var results []report.Result
	refs := make([]report.UnitRef, 0, len(units))
	for i, out := range outputs {
		if out.fatal {
			return nil, &RunError{Code: 3, Err: out.err}
		}
		if out.err != nil {
			return nil, out.err
		}
		results = append(results, out.results...)
		refs = append(refs, out.unit)
		_ = i
	}
	started := opts.Now.UTC().Format(time.RFC3339Nano)
	selectionCaps := append([]string(nil), opts.Enable...)
	sort.Strings(selectionCaps)
	toolVersion := opts.ToolVersion
	if toolVersion == "" {
		toolVersion = "dev"
	}
	version := client.Version
	identity := report.Identity{Account: client.Identity.Account}
	if deps.workspaceAuth != nil {
		identity.ADCAccount = deps.workspaceAuth.Account()
	}
	if client.Identity.Impersonate != "" {
		s := client.Identity.Impersonate
		identity.Impersonated = &s
	}
	if client.Identity.QuotaProject != "" {
		s := client.Identity.QuotaProject
		identity.QuotaProject = &s
	}
	targets := scanTargets(opts.Projects, projectMetadata, hasClusterRules(opts.Rules), units, issues)
	if shared.probe != nil {
		probeResults := shared.probe.Results()
		for i := range targets {
			for _, unit := range units {
				if unit.Target.Type != "cluster" || unit.Target.ProjectID != targets[i].ID {
					continue
				}
				result, ok := probeResults[unit.Target.Key]
				if ok && result.Outcome == clusterProbeSkipped {
					targets[i].Clusters.Unreachable = append(targets[i].Clusters.Unreachable, unit.Target.ClusterName)
				}
			}
			sort.Strings(targets[i].Clusters.Unreachable)
			targets[i].Clusters.Unreachable = unique(targets[i].Clusters.Unreachable)
		}
	}
	scan := report.Scan{ID: report.NewScanID(opts.Now, deps.Rand), StartedAt: started, FinishedAt: started, Tool: report.Tool{Name: "gbench", Version: toolVersion, RulesetHash: opts.RulesetHash, RulesetSource: opts.RulesetSource}, Environment: report.Environment{GcloudVersion: version, KubectlVersion: deps.kubectlVersion, OS: runtime.GOOS, Arch: runtime.GOARCH}, Identity: identity, Targets: targets, Selection: report.Selection{ProfileHash: opts.ProfileHash, Benchmarks: append([]string(nil), opts.Benchmarks...), Levels: append([]string(nil), opts.Levels...), Capabilities: selectionCaps, RulesSelected: len(opts.Rules)}}
	return report.Assemble(report.Input{Scan: scan, Rules: opts.Rules, Units: refs, Results: results, Collectors: shared.records()})
}

func CollectRule(ctx context.Context, opts Options, deps Deps, r *rule.Rule, stepID string) (CollectResult, error) {
	if r == nil {
		return CollectResult{}, errors.New("rule is required")
	}
	if deps.Runner == nil || deps.Allow == nil {
		return CollectResult{}, errors.New("runner and allowlist are required")
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	if opts.CommandTimeout <= 0 {
		opts.CommandTimeout = 120 * time.Second
	}
	if opts.MaxFanout <= 0 {
		opts.MaxFanout = 500
	}
	if len(opts.Projects) == 0 {
		return CollectResult{}, errors.New("project is required")
	}
	check := func(argv []string) error { return checkGcloud(deps.Allow, argv, true) }
	client, err := auth.Resolve(ctx, limitedRunner{deps.Runner, opts.CommandTimeout}, deps.Gcloud, deps.Env, check, auth.Options{Account: opts.Account, Impersonate: opts.Impersonate, QuotaProject: opts.QuotaProject})
	if err != nil {
		return CollectResult{}, err
	}
	target := plan.Target{Type: "project", Key: "projects/" + first(opts.Projects), ProjectID: first(opts.Projects)}
	ex := newExecutor(ctx, client, limitedRunner{deps.Runner, opts.CommandTimeout}, deps.Gcloud, deps.Env, plan.Guard{Allow: deps.Allow}, target.Key, rule.Step{}, opts.CommandTimeout)
	ex.useTarget(target)
	ex.rest = collect.NewRESTClient(opts.CommandTimeout, 64<<20, deps.HTTPTransport)
	params := collectRuleParams(r)
	data := eval.NewData()
	c := eval.Context{Project: target.ProjectID, Account: client.Identity.Account, TargetKey: target.Key, TargetKind: target.Kind(), Now: opts.Now}
	envs := deps.Envs
	if envs == nil {
		envs, err = eval.NewEnv()
		if err != nil {
			return CollectResult{}, err
		}
	}
	copyRule := *r
	copyRule.Collect = nil
	for _, step := range r.Collect {
		if stepID != "" && step.ID != stepID {
			continue
		}
		if step.Gcloud == "" && step.API == nil {
			continue
		}
		copyRule.Collect = append(copyRule.Collect, step)
	}
	outcome, err := eval.RunSteps(ctx, envs, &copyRule, data, c, params, ex.execute, opts.MaxFanout)
	if err != nil {
		return CollectResult{}, err
	}
	if outcome.Aborted != nil && outcome.Aborted.Failure != nil {
		return CollectResult{}, outcome.Aborted.Failure
	}
	if stepID != "" && len(copyRule.Collect) == 0 {
		return CollectResult{}, fmt.Errorf("collect step %q was not found", stepID)
	}
	values := map[string]any{}
	for _, step := range copyRule.Collect {
		if v, ok := data.Get(step.ID); ok {
			values[step.ID] = v
		}
	}
	return CollectResult{Params: params, Data: values, Collectors: ex.records(), Account: client.Identity.Account}, nil
}

type projectMetadata struct {
	number       string
	numberErr    error
	organization string
	folder       string
	ancestorsErr error
}

type clientPlanDeps struct {
	client   *auth.Client
	mu       sync.Mutex
	projects map[string]*projectMetadata
}

func (d *clientPlanDeps) ProjectNumber(ctx context.Context, p string) (string, error) {
	number, err := d.client.ProjectNumber(ctx, p)
	d.mu.Lock()
	meta := d.project(p)
	meta.number = number
	meta.numberErr = err
	d.mu.Unlock()
	return number, err
}
func (d *clientPlanDeps) Ancestors(ctx context.Context, p string) (string, string, error) {
	org, folder, err := d.client.Ancestors(ctx, p)
	d.mu.Lock()
	meta := d.project(p)
	meta.organization = org
	meta.folder = folder
	meta.ancestorsErr = err
	d.mu.Unlock()
	return org, folder, err
}
func (d *clientPlanDeps) Clusters(ctx context.Context, p string) ([]any, error) {
	return d.client.Clusters(ctx, p)
}

func (d *clientPlanDeps) project(p string) *projectMetadata {
	if d.projects[p] == nil {
		d.projects[p] = &projectMetadata{}
	}
	return d.projects[p]
}
func (d *clientPlanDeps) snapshot() map[string]projectMetadata {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]projectMetadata, len(d.projects))
	for p, m := range d.projects {
		out[p] = *m
	}
	return out
}

func checkGcloud(a *rule.Allowlist, argv []string, engine bool) error {
	_, rest, ok := a.MatchGcloud(argv, engine)
	if !ok {
		return fmt.Errorf("gcloud command is not allowed")
	}
	for _, arg := range rest {
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name := strings.SplitN(arg, "=", 2)[0]
		allowed := false
		for _, flag := range a.GcloudFlags {
			if name == flag || strings.TrimSuffix(name, "-") == flag {
				allowed = true
				break
			}
		}
		if !allowed || a.ForbiddenFlag("gcloud", arg) {
			return fmt.Errorf("gcloud flag is not allowed: %s", name)
		}
	}
	return nil
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func hasClusterRules(rules []*rule.Rule) bool {
	for _, current := range rules {
		if current != nil && current.Scope == "cluster" {
			return true
		}
	}
	return false
}

func first(in []string) string {
	if len(in) == 0 {
		return ""
	}
	return in[0]
}
func cloneMap(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

type domainValue struct {
	domain string
	err    error
}
type domainCache struct {
	mu     sync.Mutex
	values map[string]domainValue
}

func (d *domainCache) get(ctx context.Context, c *auth.Client, org string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if v, ok := d.values[org]; ok {
		return v.domain, v.err
	}
	domain, err := c.OrganizationDomain(ctx, org)
	d.values[org] = domainValue{domain, err}
	return domain, err
}

func hasKubectlRules(rules []*rule.Rule) bool {
	for _, currentRule := range rules {
		if currentRule == nil {
			continue
		}
		for _, step := range currentRule.Collect {
			if step.Kubectl != "" {
				return true
			}
		}
	}
	return false
}

func scanTargets(projects []string, metadata map[string]projectMetadata, enumerateClusters bool, units []plan.Unit, issues []plan.TargetIssue) []report.ScanTarget {
	out := make([]report.ScanTarget, 0, len(projects))
	for _, project := range unique(projects) {
		clusterStatus := "NOT_RUN"
		if enumerateClusters {
			clusterStatus = "SUCCEEDED"
		}
		target := report.ScanTarget{Type: "project", ID: project, Clusters: report.ClusterInventory{Status: clusterStatus, Names: []string{}, Unreachable: []string{}}}
		if meta, ok := metadata[project]; ok {
			if meta.numberErr == nil && meta.number != "" {
				n := meta.number
				target.Number = &n
			}
			if meta.ancestorsErr == nil && meta.organization != "" {
				org := meta.organization
				target.Organization = &org
			}
		}
		for _, unit := range units {
			if unit.Target.ProjectID == project && unit.Target.Type == "cluster" {
				target.Clusters.Names = append(target.Clusters.Names, unit.Target.ClusterName)
			}
		}
		sort.Strings(target.Clusters.Names)
		target.Clusters.Names = unique(target.Clusters.Names)
		for _, issue := range issues {
			if enumerateClusters && issue.ProjectID == project && issue.Kind == "clusters_unresolved" {
				target.Clusters.Status = "FAILED"
			}
		}
		out = append(out, target)
	}
	return out
}
