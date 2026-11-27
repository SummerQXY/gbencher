package collect_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/failure"
	"github.com/SummerQXY/gbencher/internal/rule"
)

type kubectlRunner struct {
	exec   collect.Exec
	limits collect.Limits
	out    collect.Output
	err    error
	calls  int
}

func (r *kubectlRunner) Run(_ context.Context, exec collect.Exec, limits collect.Limits) (collect.Output, error) {
	r.calls++
	r.exec = exec
	r.limits = limits
	return r.out, r.err
}

type kubectlConfig struct {
	cluster any
	path    string
	cache   string
	err     error
}

func (c *kubectlConfig) Create(cluster any) (string, error) {
	c.cluster = cluster
	return c.path, c.err
}

func (c *kubectlConfig) CacheDir() string { return c.cache }

func newKubectlCollector(t *testing.T, runner collect.Runner, config collect.KubectlConfigProvider, env []string) *collect.KubectlCollector {
	t.Helper()
	allow, err := rule.LoadAllowlist()
	if err != nil {
		t.Fatal(err)
	}
	collector, err := collect.NewKubectlCollector(runner, "/usr/bin/kubectl", env, allow, config, 0)
	if err != nil {
		t.Fatal(err)
	}
	return collector
}

func TestKubectlAllowlistRejectsUnlistedCommandAndFlags(t *testing.T) {
	for _, command := range []string{
		"apply pods",
		"delete pods",
		"patch pods",
		"exec pod",
		"get pods --server=https://example.invalid",
		"get pods --token=secret",
		"get pods --kubeconfig=/tmp/user-config",
	} {
		t.Run(strings.ReplaceAll(command, " ", "_"), func(t *testing.T) {
			runner := &kubectlRunner{}
			collector := newKubectlCollector(t, runner, &kubectlConfig{path: "/run/kube/config", cache: "/run/kube/cache"}, nil)
			result := collector.Collect(context.Background(), map[string]any{"name": "cluster-a"}, rule.Step{Kubectl: command, Parse: "json"}, nil)
			if result.Failure == nil || result.Failure.Class != failure.GuardRejected {
				t.Fatalf("Collect(%q) failure = %+v, want guard rejection", command, result.Failure)
			}
			if runner.calls != 0 {
				t.Fatalf("runner called %d times for rejected command", runner.calls)
			}
		})
	}
}

func TestKubectlRuleCorpusPassesRuntimePolicy(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	allow, err := rule.LoadAllowlist()
	if err != nil {
		t.Fatal(err)
	}
	runner := &kubectlRunner{out: collect.Output{Stdout: []byte(`{"items":[]}`)}}
	collector, err := collect.NewKubectlCollector(runner, "/usr/bin/kubectl", nil, allow, &kubectlConfig{path: "/run/config", cache: "/run/cache"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, ruleItem := range set.Rules {
		for _, step := range ruleItem.Collect {
			if step.Kubectl == "" {
				continue
			}
			checked++
			result := collector.Collect(context.Background(), map[string]any{"name": "cluster-a"}, step, map[string]any{"params": ruleItem.Params})
			if result.Failure != nil {
				t.Errorf("%s/%s: runtime policy rejected corpus command %q: %+v", ruleItem.ID, step.ID, step.Kubectl, result.Failure)
			}
		}
	}
	if checked != 56 {
		t.Fatalf("checked %d kubectl steps, want 56", checked)
	}
}

func TestKubectlCollectorInjectsRunConfiguration(t *testing.T) {
	cluster := map[string]any{"name": "cluster-a"}
	runner := &kubectlRunner{out: collect.Output{Stdout: []byte(`{"items":[]}`)}}
	config := &kubectlConfig{path: "/private/run/config.yaml", cache: "/private/run/cache"}
	collector := newKubectlCollector(t, runner, config, []string{
		"PATH=/usr/bin",
		"HOME=/home/tester",
		"KUBECONFIG=/home/tester/.kube/config",
		"KUBECTL_CACHE_DIR=/home/tester/.kube/cache",
	})
	result := collector.Collect(context.Background(), cluster, rule.Step{Kubectl: "get pods -o json", Parse: "json"}, nil)
	if result.Failure != nil {
		t.Fatalf("Collect() failure = %+v", result.Failure)
	}
	wantArgs := []string{
		"get", "pods", "-o", "json",
		"--kubeconfig=/private/run/config.yaml",
		"--cache-dir=/private/run/cache",
		"--request-timeout=2m0s",
	}
	if !reflect.DeepEqual(runner.exec.Argv, wantArgs) {
		t.Fatalf("argv = %#v, want %#v", runner.exec.Argv, wantArgs)
	}
	if !reflect.DeepEqual(config.cluster, cluster) {
		t.Fatal("cluster description was not passed to the run configuration provider")
	}
	for _, env := range runner.exec.Env {
		if strings.HasPrefix(env, "KUBECONFIG=") || strings.HasPrefix(env, "KUBECTL_CACHE_DIR=") {
			t.Fatalf("user Kubernetes environment leaked into child: %q", env)
		}
	}
	if runner.limits.Timeout != 120*time.Second || runner.limits.MaxOutput != 64<<20 {
		t.Fatalf("limits = %+v, want 120s and 64 MiB", runner.limits)
	}
	if !reflect.DeepEqual(result.Value, map[string]any{"items": []any{}}) {
		t.Fatalf("value = %#v", result.Value)
	}
}

func TestKubectlCollectorPreservesSingleArgumentValues(t *testing.T) {
	runner := &kubectlRunner{out: collect.Output{Stdout: []byte(`{"items":[]}`)}}
	collector := newKubectlCollector(t, runner, &kubectlConfig{path: "/run/config", cache: "/run/cache"}, nil)
	result := collector.Collect(context.Background(), map[string]any{"name": "cluster-a"}, rule.Step{
		Kubectl: "get pods --namespace={{ .params.namespace }} -o json",
		Parse:   "json",
	}, map[string]any{"params": map[string]any{"namespace": "team-a=blue"}})
	if result.Failure != nil {
		t.Fatalf("Collect() failure = %+v", result.Failure)
	}
	if !reflect.DeepEqual(runner.exec.Argv[:5], []string{"get", "pods", "--namespace=team-a=blue", "-o", "json"}) {
		t.Fatalf("rule argv was split or changed: %#v", runner.exec.Argv)
	}
}

func TestKubectlCollectorBoundsOutputAndTimeout(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  collect.Output
		want failure.Class
	}{
		{name: "output", out: collect.Output{Truncated: true, ExitCode: 1}, want: failure.OutputTooLarge},
		{name: "timeout", out: collect.Output{TimedOut: true, ExitCode: 1}, want: failure.Timeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &kubectlRunner{out: tc.out}
			collector := newKubectlCollector(t, runner, &kubectlConfig{path: "/run/config", cache: "/run/cache"}, nil)
			result := collector.Collect(context.Background(), map[string]any{"name": "cluster-a"}, rule.Step{Kubectl: "get pods -o json", Parse: "json"}, nil)
			if result.Failure == nil || result.Failure.Class != tc.want {
				t.Fatalf("failure = %+v, want %q", result.Failure, tc.want)
			}
		})
	}
}

func TestKubectlCollectorClassifiesFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  collect.Output
		err  error
		want failure.Class
	}{
		{name: "permission", out: collect.Output{ExitCode: 1, Stderr: []byte("Error from server (Forbidden): access denied")}, want: failure.Permission},
		{name: "not found", out: collect.Output{ExitCode: 1, Stderr: []byte("Error from server (NotFound): resource type missing")}, want: failure.NotFound},
		{name: "unknown", out: collect.Output{ExitCode: 1, Stderr: []byte("unexpected failure")}, want: failure.Unknown},
		{name: "runner error", err: errors.New("sensitive runner error"), want: failure.Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &kubectlRunner{out: tc.out, err: tc.err}
			collector := newKubectlCollector(t, runner, &kubectlConfig{path: "/run/config", cache: "/run/cache"}, nil)
			result := collector.Collect(context.Background(), map[string]any{"name": "cluster-a"}, rule.Step{Kubectl: "get pods -o json", Parse: "json"}, nil)
			if result.Failure == nil || result.Failure.Class != tc.want {
				t.Fatalf("failure = %+v, want %q", result.Failure, tc.want)
			}
			if strings.Contains(result.Failure.Error(), "sensitive runner error") {
				t.Fatal("runner error leaked into failure summary")
			}
		})
	}
	parseRunner := &kubectlRunner{out: collect.Output{Stdout: []byte("not json")}}
	collector := newKubectlCollector(t, parseRunner, &kubectlConfig{path: "/run/config", cache: "/run/cache"}, nil)
	result := collector.Collect(context.Background(), map[string]any{"name": "cluster-a"}, rule.Step{Kubectl: "get pods -o json", Parse: "json"}, nil)
	if result.Failure == nil || result.Failure.Class != failure.Parse {
		t.Fatalf("malformed JSON failure = %+v, want parse_error", result.Failure)
	}
}
