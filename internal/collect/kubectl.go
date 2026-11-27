package collect

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/SummerQXY/gbencher/internal/failure"
	"github.com/SummerQXY/gbencher/internal/rule"
)

const (
	kubectlDefaultTimeout = 120 * time.Second
	kubectlMaxOutput      = 64 << 20
)

// KubectlConfigProvider supplies a kubeconfig and cache directory owned by one scan.
type KubectlConfigProvider interface {
	Create(cluster any) (string, error)
	CacheDir() string
}

// KubectlResult contains the decoded response and safe metadata for one command.
type KubectlResult struct {
	Value    any
	Failure  *failure.Failure
	Argv     []string
	ExitCode int
	Duration time.Duration
}

// KubectlCollector runs read-only rule commands with scan-specific configuration.
type KubectlCollector struct {
	runner  Runner
	path    string
	env     []string
	allow   *rule.Allowlist
	config  KubectlConfigProvider
	timeout time.Duration
}

// NewKubectlCollector creates a collector whose rule commands are checked against the embedded
// command allowlist before the scan-specific flags are added.
func NewKubectlCollector(runner Runner, path string, env []string, allow *rule.Allowlist, config KubectlConfigProvider, timeout time.Duration) (*KubectlCollector, error) {
	if runner == nil {
		return nil, fmt.Errorf("kubectl runner is required")
	}
	if path == "" {
		return nil, fmt.Errorf("kubectl executable is required")
	}
	if allow == nil {
		return nil, fmt.Errorf("kubectl allowlist is required")
	}
	if config == nil {
		return nil, fmt.Errorf("Kubernetes run configuration is required")
	}
	if timeout <= 0 {
		timeout = kubectlDefaultTimeout
	}
	return &KubectlCollector{
		runner: runner, path: path, env: append([]string(nil), env...), allow: allow,
		config: config, timeout: timeout,
	}, nil
}

// Collect renders, validates and runs one kubectl rule step. Rejected commands never reach Runner.
func (c *KubectlCollector) Collect(ctx context.Context, cluster any, step rule.Step, values map[string]any) KubectlResult {
	result := KubectlResult{}
	if c == nil || ctx == nil {
		result.Failure = newFailure(failure.GuardRejected, "kubectl collector and context are required", 0)
		return result
	}
	if ctx.Err() != nil {
		result.Failure = newFailure(failure.Timeout, "kubectl command was canceled", 0)
		return result
	}
	if step.Kubectl == "" {
		result.Failure = newFailure(failure.GuardRejected, "kubectl rule command is required", 0)
		return result
	}

	ruleArgv, err := RenderArgv(step.Kubectl, values)
	if err != nil {
		result.Failure = ClassifyParse(err)
		return result
	}
	if err := validateKubectlRuleArgv(c.allow, ruleArgv); err != nil {
		result.Failure = newFailure(failure.GuardRejected, err.Error(), 0)
		return result
	}

	kubeconfig, err := c.config.Create(cluster)
	if err != nil {
		result.Failure = newFailure(failure.GuardRejected, "scan-specific Kubernetes configuration is unavailable", 0)
		return result
	}
	cacheDir := c.config.CacheDir()
	if kubeconfig == "" || cacheDir == "" {
		result.Failure = newFailure(failure.GuardRejected, "scan-specific Kubernetes configuration is incomplete", 0)
		return result
	}

	argv := make([]string, 0, len(ruleArgv)+3)
	argv = append(argv, ruleArgv...)
	argv = append(argv,
		"--kubeconfig="+kubeconfig,
		"--cache-dir="+cacheDir,
		"--request-timeout="+c.timeout.String(),
	)
	result.Argv = append([]string(nil), argv...)

	started := time.Now()
	out, runErr := c.runner.Run(ctx, Exec{
		Path: c.path,
		Argv: argv,
		Env:  ChildEnv(c.env, nil),
	}, Limits{Timeout: c.timeout, MaxOutput: kubectlMaxOutput})
	result.Duration = time.Since(started)
	result.ExitCode = out.ExitCode
	if out.TimedOut || out.Truncated {
		result.Failure = ClassifyKubectl(out)
		return result
	}
	if runErr != nil {
		if ctx.Err() != nil {
			result.Failure = newFailure(failure.Timeout, "kubectl command was canceled", out.ExitCode)
		} else {
			result.Failure = newFailure(failure.Unknown, "kubectl command could not be started", out.ExitCode)
		}
		return result
	}
	if ctx.Err() != nil {
		result.Failure = newFailure(failure.Timeout, "kubectl command was canceled", out.ExitCode)
		return result
	}
	if failed := ClassifyKubectl(out); failed != nil {
		result.Failure = failed
		return result
	}

	switch step.Parse {
	case "", "json":
		result.Value, err = DecodeJSON(out.Stdout)
	case "text":
		result.Value = strings.TrimSpace(string(out.Stdout))
	case "lines":
		lines := strings.Split(strings.TrimSpace(string(out.Stdout)), "\n")
		if len(lines) == 1 && lines[0] == "" {
			result.Value = []string{}
		} else {
			result.Value = lines
		}
	default:
		err = fmt.Errorf("unsupported kubectl output parser")
	}
	if err != nil {
		result.Value = nil
		result.Failure = ClassifyParse(err)
	}
	return result
}

func validateKubectlRuleArgv(allow *rule.Allowlist, argv []string) error {
	if allow == nil || len(argv) == 0 {
		return fmt.Errorf("kubectl command is empty")
	}
	verb := argv[0]
	if !slices.Contains(allow.KubectlVerbs, verb) {
		return fmt.Errorf("kubectl verb %q is not in the allowlist", verb)
	}
	index := 1
	if verb != "api-resources" && verb != "version" {
		if index >= len(argv) || strings.HasPrefix(argv[index], "-") {
			return fmt.Errorf("kubectl resource is required")
		}
		resource := argv[index]
		if !allow.KubectlAllowed(verb, resource) {
			return fmt.Errorf("kubectl resource %q is not in the allowlist", resource)
		}
		index++
	}

	for index < len(argv) {
		arg := argv[index]
		if !strings.HasPrefix(arg, "-") {
			return fmt.Errorf("unexpected positional kubectl argument")
		}
		if allow.ForbiddenFlag("kubectl", arg) {
			return fmt.Errorf("kubectl flag %q is not in the allowlist", arg)
		}
		name, value, attached := strings.Cut(arg, "=")
		switch name {
		case "-o", "--namespace":
			if attached {
				if value == "" {
					return fmt.Errorf("kubectl flag %q requires a value", name)
				}
				index++
				continue
			}
			if index+1 >= len(argv) || strings.HasPrefix(argv[index+1], "-") {
				return fmt.Errorf("kubectl flag %q requires a value", name)
			}
			index += 2
		case "--all-namespaces":
			if attached {
				return fmt.Errorf("kubectl flag %q does not accept a value", name)
			}
			index++
		default:
			return fmt.Errorf("kubectl flag %q is not supported", name)
		}
	}
	return nil
}

// ClassifyKubectl maps a kubectl process result to the shared collection failure classes.
func ClassifyKubectl(out Output) *failure.Failure {
	if out.TimedOut {
		return newFailure(failure.Timeout, string(out.Stderr), out.ExitCode)
	}
	if out.Truncated {
		return newFailure(failure.OutputTooLarge, string(out.Stderr), out.ExitCode)
	}
	if out.ExitCode == 0 {
		return nil
	}

	text := string(out.Stderr)
	lower := strings.ToLower(text)
	class := failure.Unknown
	switch {
	case strings.Contains(lower, "(unauthorized)"), strings.Contains(lower, "(forbidden)"),
		strings.Contains(lower, "you must be logged in"), strings.Contains(lower, "forbidden"),
		http401Pattern.MatchString(text), http403Pattern.MatchString(text):
		class = failure.Permission
	case strings.Contains(lower, "(notfound)"), strings.Contains(lower, "not found"),
		strings.Contains(lower, "doesn't have a resource type"), strings.Contains(lower, "does not have a resource type"),
		http404Pattern.MatchString(text):
		class = failure.NotFound
	case strings.Contains(lower, "too many requests"), http429Pattern.MatchString(text):
		class = failure.RateLimited
	case strings.Contains(lower, "internal error"), strings.Contains(lower, "service unavailable"),
		http5xxPattern.MatchString(text):
		class = failure.ServerError
	}
	return newFailure(class, text, out.ExitCode)
}
