package engine

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/failure"
)

const clusterProbeRequestTimeout = 15 * time.Second

type clusterProbeOutcome string

const (
	clusterProbeReachable clusterProbeOutcome = "reachable"
	clusterProbeSkipped   clusterProbeOutcome = "skipped"
	clusterProbeError     clusterProbeOutcome = "error"
	clusterProbeCanceled  clusterProbeOutcome = "canceled"
)

type clusterProbeRequest struct {
	ClusterKey     string
	Argv           []string
	RequestTimeout time.Duration
}

type ClusterProbeCheck struct {
	Outcome string
	Reason  string
	Error   string
}

type clusterProbeResult struct {
	Outcome clusterProbeOutcome
	Reason  string
	Failure *failure.Failure
}

type clusterProbeExecutor func(context.Context, clusterProbeRequest) (collect.Output, error)

type clusterProbeFlight struct {
	done   chan struct{}
	result clusterProbeResult
}

type clusterProbeFuse struct {
	execute clusterProbeExecutor
	mu      sync.Mutex
	flights map[string]*clusterProbeFlight
}

func (p *clusterProbeFuse) Results() map[string]clusterProbeResult {
	if p == nil {
		return map[string]clusterProbeResult{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]clusterProbeResult, len(p.flights))
	for key, flight := range p.flights {
		select {
		case <-flight.done:
			out[key] = flight.result
		default:
		}
	}
	return out
}

func newClusterProbeFuse(execute clusterProbeExecutor) *clusterProbeFuse {
	return &clusterProbeFuse{execute: execute, flights: make(map[string]*clusterProbeFlight)}
}

func ProbeCluster(ctx context.Context, runner collect.Runner, path string, env []string, config collect.KubectlConfigProvider, clusterKey string, cluster any) ClusterProbeCheck {
	probe := newClusterProbeFuse(func(ctx context.Context, request clusterProbeRequest) (collect.Output, error) {
		return runClusterProbe(ctx, runner, path, env, config, cluster, request)
	})
	result := probe.Probe(ctx, clusterKey)
	check := ClusterProbeCheck{Outcome: string(result.Outcome), Reason: result.Reason}
	if result.Failure != nil {
		check.Error = "Kubernetes API server probe failed"
	}
	return check
}

func runClusterProbe(ctx context.Context, runner collect.Runner, path string, env []string, config collect.KubectlConfigProvider, cluster any, request clusterProbeRequest) (collect.Output, error) {
	if runner == nil || path == "" || config == nil {
		return collect.Output{}, errors.New("Kubernetes probe dependencies are unavailable")
	}
	kubeconfig, err := config.Create(cluster)
	if err != nil {
		return collect.Output{}, err
	}
	argv := append([]string(nil), request.Argv...)
	argv = append(argv, "--kubeconfig="+kubeconfig, "--cache-dir="+config.CacheDir())
	limitCtx, cancel := context.WithTimeout(ctx, request.RequestTimeout)
	defer cancel()
	return runner.Run(limitCtx, collect.Exec{Path: path, Argv: argv, Env: collect.ChildEnv(env, nil)}, collect.Limits{Timeout: request.RequestTimeout, MaxOutput: 1 << 20})
}

func (p *clusterProbeFuse) Probe(ctx context.Context, clusterKey string) clusterProbeResult {
	if ctx == nil {
		return clusterProbeErrorResult(&failure.Failure{Class: failure.Unknown, Summary: "cluster probe context is required"})
	}
	if ctx.Err() != nil {
		return clusterProbeResult{Outcome: clusterProbeCanceled}
	}
	if p == nil || p.execute == nil {
		return clusterProbeErrorResult(&failure.Failure{Class: failure.Unknown, Summary: "cluster probe executor is unavailable"})
	}
	if clusterKey == "" {
		return clusterProbeErrorResult(&failure.Failure{Class: failure.Unknown, Summary: "cluster key is required"})
	}

	p.mu.Lock()
	if flight := p.flights[clusterKey]; flight != nil {
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return clusterProbeResult{Outcome: clusterProbeCanceled}
		case <-flight.done:
			return flight.result
		}
	}
	flight := &clusterProbeFlight{done: make(chan struct{})}
	p.flights[clusterKey] = flight
	p.mu.Unlock()

	request := clusterProbeRequest{
		ClusterKey:     clusterKey,
		Argv:           []string{"version", "-o", "json", "--request-timeout=" + clusterProbeRequestTimeout.String()},
		RequestTimeout: clusterProbeRequestTimeout,
	}
	out, runErr := p.execute(ctx, request)
	result := classifyClusterProbe(ctx, out, runErr)

	p.mu.Lock()
	flight.result = result
	if result.Outcome == clusterProbeCanceled && p.flights[clusterKey] == flight {
		delete(p.flights, clusterKey)
	}
	close(flight.done)
	p.mu.Unlock()
	return result
}

func classifyClusterProbe(ctx context.Context, out collect.Output, runErr error) clusterProbeResult {
	if ctx.Err() != nil || errors.Is(runErr, context.Canceled) {
		return clusterProbeResult{Outcome: clusterProbeCanceled}
	}
	if errors.Is(runErr, context.DeadlineExceeded) {
		return clusterProbeResult{
			Outcome: clusterProbeSkipped,
			Reason:  "cluster_unreachable",
			Failure: &failure.Failure{Class: failure.Timeout, Summary: "Kubernetes API server probe timed out", ExitCode: out.ExitCode},
		}
	}
	if out.TimedOut || isClusterNetworkFailure(runErr, string(out.Stderr)) {
		return clusterProbeResult{
			Outcome: clusterProbeSkipped,
			Reason:  "cluster_unreachable",
			Failure: &failure.Failure{Class: failure.Timeout, Summary: "Kubernetes API server probe timed out", ExitCode: out.ExitCode},
		}
	}
	if runErr != nil {
		return clusterProbeErrorResult(&failure.Failure{Class: failure.Unknown, Summary: "Kubernetes API server probe could not run", ExitCode: out.ExitCode})
	}
	if out.Truncated {
		return clusterProbeErrorResult(&failure.Failure{Class: failure.OutputTooLarge, Summary: "Kubernetes API server probe output exceeded the limit", ExitCode: out.ExitCode})
	}
	if out.ExitCode != 0 {
		failed := collect.ClassifyKubectl(out)
		if isPermissionProbeFailure(out.Stderr, failed) {
			return clusterProbeResult{
				Outcome: clusterProbeSkipped,
				Reason:  "permission_denied",
				Failure: failed,
			}
		}
		if isClusterNetworkFailure(nil, string(out.Stderr)) {
			return clusterProbeResult{
				Outcome: clusterProbeSkipped,
				Reason:  "cluster_unreachable",
				Failure: failed,
			}
		}
		if failed == nil {
			failed = &failure.Failure{Class: failure.Unknown, Summary: "Kubernetes API server probe failed", ExitCode: out.ExitCode}
		}
		return clusterProbeErrorResult(failed)
	}
	if failed := validateClusterProbeOutput(out.Stdout); failed != nil {
		return clusterProbeErrorResult(failed)
	}
	return clusterProbeResult{Outcome: clusterProbeReachable}
}

func validateClusterProbeOutput(stdout []byte) *failure.Failure {
	value, err := collect.DecodeJSON(stdout)
	if err != nil {
		return collect.ClassifyParse(err)
	}
	document, ok := value.(map[string]any)
	if !ok {
		return &failure.Failure{Class: failure.Parse, Summary: "kubectl version response must be a JSON object"}
	}
	serverVersion, ok := document["serverVersion"].(map[string]any)
	if !ok {
		return &failure.Failure{Class: failure.Parse, Summary: "kubectl version response is missing serverVersion"}
	}
	gitVersion, ok := serverVersion["gitVersion"].(string)
	if !ok || strings.TrimSpace(gitVersion) == "" {
		return &failure.Failure{Class: failure.Parse, Summary: "kubectl version response has an invalid serverVersion"}
	}
	return nil
}

func isPermissionProbeFailure(stderr []byte, failed *failure.Failure) bool {
	if failed != nil && failed.Class == failure.Permission {
		return true
	}
	text := strings.ToLower(string(stderr))
	return strings.Contains(text, "unauthorized") || strings.Contains(text, "forbidden") ||
		strings.Contains(text, "http 401") || strings.Contains(text, "http error 401") ||
		strings.Contains(text, "http 403") || strings.Contains(text, "http error 403") ||
		strings.Contains(text, "status code 401") || strings.Contains(text, "status code 403")
}

func isClusterNetworkFailure(runErr error, stderr string) bool {
	if runErr != nil {
		var networkError net.Error
		if errors.As(runErr, &networkError) && networkError.Timeout() {
			return true
		}
		if errors.Is(runErr, syscall.ECONNREFUSED) || errors.Is(runErr, syscall.EHOSTUNREACH) ||
			errors.Is(runErr, syscall.ENETUNREACH) || errors.Is(runErr, syscall.ETIMEDOUT) {
			return true
		}
		stderr += "\n" + runErr.Error()
	}
	text := strings.ToLower(stderr)
	for _, signal := range []string{
		"i/o timeout",
		"context deadline exceeded",
		"request timed out",
		"client.timeout exceeded",
		"connection timed out",
		"operation timed out",
		"tls handshake timeout",
		"tls handshake failure",
		"tls: handshake failure",
		"tls: failed to verify certificate",
		"x509: certificate signed by unknown authority",
		"x509: certificate is valid for",
		"x509: certificate has expired or is not yet valid",
		"certificate verification failed",
		"connection refused",
		"no route to host",
		"network is unreachable",
	} {
		if strings.Contains(text, signal) {
			return true
		}
	}
	return false
}

func clusterProbeErrorResult(failed *failure.Failure) clusterProbeResult {
	if failed == nil {
		failed = &failure.Failure{Class: failure.Unknown, Summary: "Kubernetes API server probe failed"}
	}
	return clusterProbeResult{Outcome: clusterProbeError, Failure: failed}
}
