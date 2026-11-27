package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/SummerQXY/gbencher/internal/auth"
	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/failure"
	"github.com/SummerQXY/gbencher/internal/plan"
	"github.com/SummerQXY/gbencher/internal/redact"
	"github.com/SummerQXY/gbencher/internal/report"
	"github.com/SummerQXY/gbencher/internal/rule"
)

type future struct {
	done      chan struct{}
	value     any
	failure   *failure.Failure
	collector report.Collector
}

type executor struct {
	state            *executorState
	client           *auth.Client
	runner           collect.Runner
	rest             *collect.RESTClient
	gcloud           string
	env              []string
	guard            plan.Guard
	target           plan.Target
	scope            string
	timeout          time.Duration
	now              func() time.Time
	workspaceAuth    *workspaceAuthManager
	workspaceEnabled bool
	kubectl          *collect.KubectlCollector
	probe            *clusterProbeFuse
}

type executorState struct {
	mu         sync.Mutex
	flights    map[string]*future
	collectors map[string]report.Collector
}

func newExecutor(ctx context.Context, client *auth.Client, runner collect.Runner, gcloud string, env []string, guard plan.Guard, scope string, _ rule.Step, timeout time.Duration) *executor {
	_ = ctx
	return &executor{state: &executorState{flights: make(map[string]*future), collectors: make(map[string]report.Collector)}, client: client, runner: runner, gcloud: gcloud, env: append([]string(nil), env...), guard: guard, scope: scope, timeout: timeout, now: time.Now}
}

func (e *executor) execute(ctx context.Context, step rule.Step, values map[string]any) (any, *failure.Failure) {
	value, failed, _ := e.executeWithKey(ctx, step, values)
	return value, failed
}

func (e *executor) executeWithKey(ctx context.Context, step rule.Step, values map[string]any) (any, *failure.Failure, string) {
	if step.Kubectl != "" {
		return e.executeKubectlWithKey(ctx, step, values)
	}
	if step.API != nil {
		return e.executeRESTWithKey(ctx, step, values)
	}
	argv, err := collect.RenderArgv(step.Gcloud, values)
	if err != nil {
		return nil, collect.ClassifyParse(err), ""
	}
	if err := checkGcloud(e.guard.Allow, argv, false); err != nil {
		return nil, &failure.Failure{Class: failure.GuardRejected, Summary: err.Error()}, ""
	}
	if err := e.guard.CheckGcloud(argv, e.target, step.CrossProject, step.Foreach != ""); err != nil {
		return nil, &failure.Failure{Class: failure.GuardRejected, Summary: err.Error()}, ""
	}
	encoded, _ := json.Marshal(argv)
	key := "gcloud\x00" + string(encoded) + "\x00" + e.scope

	e.state.mu.Lock()
	if f := e.state.flights[key]; f != nil {
		e.state.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, &failure.Failure{Class: failure.Timeout, Summary: ctx.Err().Error()}, key
		case <-f.done:
			return cloneCollectedValue(f.value), f.failure, key
		}
	}
	f := &future{done: make(chan struct{})}
	e.state.flights[key] = f
	e.state.mu.Unlock()

	started := e.now()
	var out collect.Output
	var runErr error
	limits := collect.Limits{Timeout: e.timeout, MaxOutput: 64 << 20}
	if e.client != nil {
		out, runErr = e.client.Run(ctx, argv, limits)
	} else {
		out, runErr = e.runner.Run(ctx, collect.Exec{Path: e.gcloud, Argv: argv, Env: e.env}, limits)
	}
	fc, _ := failure.As(runErr)
	if runErr != nil && fc == nil {
		fc = &failure.Failure{Class: failure.Unknown, Summary: runErr.Error()}
	}
	if fc == nil {
		fc = collect.ClassifyGcloud(out)
	}
	var value any
	if fc == nil {
		switch step.Parse {
		case "json":
			value, err = collect.DecodeJSON(out.Stdout)
			if err != nil {
				fc = collect.ClassifyParse(err)
			}
		case "text":
			value = strings.TrimSpace(string(out.Stdout))
		case "lines":
			lines := strings.Split(strings.TrimSpace(string(out.Stdout)), "\n")
			if len(lines) == 1 && lines[0] == "" {
				value = []string{}
			} else {
				value = lines
			}
		default:
			value, err = collect.DecodeJSON(out.Stdout)
			if err != nil {
				fc = collect.ClassifyParse(err)
			}
		}
	}
	status := "SUCCEEDED"
	var exit *int
	if out.ExitCode != 0 || fc != nil {
		status = "FAILED"
		code := out.ExitCode
		exit = &code
	}
	var classPtr, errorPtr *string
	if fc != nil {
		c := string(fc.Class)
		classPtr = &c
		s := fc.Summary
		errorPtr = &s
	}
	command := strings.Join(argv, " ")
	c := report.Collector{Key: key, ScopeKey: e.scope, Type: "gcloud", Command: command, StartedAt: started.UTC().Format(time.RFC3339Nano), DurationMS: time.Since(started).Milliseconds(), Status: status, ExitCode: exit, ErrorClass: classPtr, Error: errorPtr}
	f.value, f.failure, f.collector = value, fc, c
	e.state.mu.Lock()
	e.state.collectors[key] = c
	close(f.done)
	e.state.mu.Unlock()
	return cloneCollectedValue(value), fc, key
}

func (e *executor) executeKubectlWithKey(ctx context.Context, step rule.Step, values map[string]any) (any, *failure.Failure, string) {
	if e.target.Type != "cluster" || e.kubectl == nil {
		return nil, &failure.Failure{Class: failure.GuardRejected, Summary: "kubectl collector requires an enabled cluster target"}, ""
	}
	ruleArgv, err := collect.RenderArgv(step.Kubectl, values)
	if err != nil {
		return nil, collect.ClassifyParse(err), ""
	}
	if err := e.guard.CheckKubectl(ruleArgv, e.target); err != nil {
		return nil, &failure.Failure{Class: failure.GuardRejected, Summary: err.Error()}, ""
	}
	encoded, _ := json.Marshal(ruleArgv)
	key := "kubectl\x00" + string(encoded) + "\x00" + e.scope

	e.state.mu.Lock()
	if f := e.state.flights[key]; f != nil {
		e.state.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, &failure.Failure{Class: failure.Timeout, Summary: "kubectl command was canceled or timed out"}, key
		case <-f.done:
			return cloneCollectedValue(f.value), f.failure, key
		}
	}
	f := &future{done: make(chan struct{})}
	e.state.flights[key] = f
	e.state.mu.Unlock()

	started := e.now()
	result := e.kubectl.Collect(ctx, e.target.Cluster, step, values)
	failed := result.Failure
	status := "SUCCEEDED"
	var exit *int
	var classPtr, errorPtr *string
	if failed != nil {
		status = "FAILED"
		code := result.ExitCode
		exit = &code
		class := string(failed.Class)
		summary := failed.Summary
		classPtr, errorPtr = &class, &summary
	}
	command := redact.String(strings.Join(result.Argv, " "))
	collector := report.Collector{Key: key, ScopeKey: e.scope, Type: "kubectl", Command: command, StartedAt: started.UTC().Format(time.RFC3339Nano), DurationMS: result.Duration.Milliseconds(), Status: status, ExitCode: exit, ErrorClass: classPtr, Error: errorPtr}
	f.value, f.failure, f.collector = result.Value, failed, collector
	e.state.mu.Lock()
	e.state.collectors[key] = collector
	close(f.done)
	e.state.mu.Unlock()
	return cloneCollectedValue(result.Value), failed, key
}

func (e *executor) probeCluster(ctx context.Context, target plan.Target) clusterProbeResult {
	if e.probe == nil || target.Type != "cluster" {
		return clusterProbeErrorResult(&failure.Failure{Class: failure.Unknown, Summary: "Kubernetes cluster probe is unavailable"})
	}
	return e.probe.Probe(ctx, target.Key)
}

func (e *executor) executeRESTWithKey(ctx context.Context, step rule.Step, values map[string]any) (any, *failure.Failure, string) {
	api := step.API
	if api == nil || e.rest == nil || e.client == nil {
		return nil, &failure.Failure{Class: failure.Unknown, Summary: "REST collector is unavailable"}, ""
	}
	validate := func(method, rawURL string, body []byte) error {
		return e.guard.CheckAPIRequest(method, rawURL, body, e.target)
	}
	prepared, err := collect.PrepareRESTRequest(api.Method, api.URL, api.Body, values, validate)
	if err != nil {
		failed, _ := failure.As(err)
		if failed == nil {
			failed = &failure.Failure{Class: failure.GuardRejected, Summary: err.Error()}
		}
		return nil, failed, ""
	}
	keyData, err := json.Marshal(struct {
		Method string `json:"method"`
		URL    string `json:"url"`
		Body   []byte `json:"body"`
	}{Method: prepared.Method(), URL: prepared.URL().String(), Body: prepared.Body()})
	if err != nil {
		return nil, &failure.Failure{Class: failure.Parse, Summary: "REST request could not be keyed"}, ""
	}
	key := "api\x00" + string(keyData) + "\x00" + e.scope
	e.state.mu.Lock()
	if f := e.state.flights[key]; f != nil {
		e.state.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, &failure.Failure{Class: failure.Timeout, Summary: "REST request was canceled or timed out"}, key
		case <-f.done:
			return cloneCollectedValue(f.value), f.failure, key
		}
	}
	f := &future{done: make(chan struct{})}
	e.state.flights[key] = f
	e.state.mu.Unlock()

	started := e.now()
	var result *collect.RESTResult
	var requestErr error
	tokenSource := collect.RESTTokenSource(e.client)
	workspace := e.workspaceEnabled
	if workspace {
		if e.workspaceAuth == nil {
			requestErr = &failure.Failure{Class: failure.Permission, Summary: "Workspace application default credentials are unavailable"}
		} else {
			tokenSource, requestErr = e.workspaceAuth.Source(ctx, api.Scopes)
		}
	}
	if requestErr == nil && api.Paginate {
		result, requestErr = e.rest.DoPaginated(ctx, prepared, tokenSource, e.client.Identity.QuotaProject, api.ListField, 100, 100000)
		if requestErr == nil {
			object, ok := result.Value.(map[string]any)
			if !ok {
				requestErr = &failure.Failure{Class: failure.Parse, Summary: "REST paginated response is not an object"}
			} else if items, ok := object[api.ListField].([]any); !ok {
				requestErr = &failure.Failure{Class: failure.Parse, Summary: "REST paginated response has an invalid list field"}
			} else {
				result.Value = items
			}
		}
	} else if requestErr == nil {
		result, requestErr = e.rest.DoAuthenticated(ctx, prepared, tokenSource, e.client.Identity.QuotaProject)
	}
	var failed *failure.Failure
	if requestErr != nil {
		failed, _ = failure.As(requestErr)
		if failed == nil {
			failed = &failure.Failure{Class: failure.Unknown, Summary: "REST request failed"}
		}
		if workspace && (failed.Class == failure.AuthExpired || failed.Class == failure.NotFound) {
			failed = &failure.Failure{Class: failure.Permission, Summary: "Workspace identity or tenant is unavailable"}
		}
	}
	var value any
	if result != nil {
		value = result.Value
	}
	status := "SUCCEEDED"
	var classPtr, errorPtr *string
	if failed != nil {
		status = "FAILED"
		class := string(failed.Class)
		summary := failed.Summary
		classPtr, errorPtr = &class, &summary
	}
	command := redact.String(prepared.URL().String())
	collector := report.Collector{Key: key, ScopeKey: e.scope, Type: "api", Command: command, StartedAt: started.UTC().Format(time.RFC3339Nano), DurationMS: time.Since(started).Milliseconds(), Status: status, ErrorClass: classPtr, Error: errorPtr}
	f.value, f.failure, f.collector = value, failed, collector
	e.state.mu.Lock()
	e.state.collectors[key] = collector
	close(f.done)
	e.state.mu.Unlock()
	return cloneCollectedValue(value), failed, key
}

func cloneCollectedValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		clone := make(map[string]any, len(value))
		for key, item := range value {
			clone[key] = cloneCollectedValue(item)
		}
		return clone
	case []any:
		clone := make([]any, len(value))
		for i, item := range value {
			clone[i] = cloneCollectedValue(item)
		}
		return clone
	case []string:
		return append([]string(nil), value...)
	default:
		return value
	}
}

func (e *executor) records() []report.Collector {
	e.state.mu.Lock()
	defer e.state.mu.Unlock()
	out := make([]report.Collector, 0, len(e.state.collectors))
	for _, c := range e.state.collectors {
		out = append(out, c)
	}
	return out
}

func (e *executor) recordsForScope(scope string) []report.Collector {
	all := e.records()
	out := make([]report.Collector, 0)
	for _, c := range all {
		if c.ScopeKey == scope {
			out = append(out, c)
		}
	}
	return out
}

func (e *executor) useTarget(target plan.Target) { e.target = target; e.scope = target.Key }

func (e *executor) forTarget(target plan.Target) *executor {
	copy := *e
	copy.target = target
	copy.scope = target.Key
	return &copy
}

func (e *executor) runRaw(ctx context.Context, argv []string) (collect.Output, error) {
	if e.client != nil {
		return e.client.Run(ctx, argv, collect.Limits{Timeout: e.timeout, MaxOutput: 64 << 20})
	}
	if e.runner == nil {
		return collect.Output{}, fmt.Errorf("collector runner is required")
	}
	return e.runner.Run(ctx, collect.Exec{Path: e.gcloud, Argv: argv, Env: e.env}, collect.Limits{Timeout: e.timeout, MaxOutput: 64 << 20})
}

var _ = json.Valid
