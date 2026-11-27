package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/failure"
)

func TestClusterProbe_RunsOnceForConcurrentCalls(t *testing.T) {
	const callers = 24
	attempted := make(chan struct{}, callers)
	var calls atomic.Int32
	probe := newClusterProbeFuse(func(ctx context.Context, request clusterProbeRequest) (collect.Output, error) {
		if got, want := request.ClusterKey, "cluster-a"; got != want {
			t.Errorf("cluster key = %q, want %q", got, want)
		}
		calls.Add(1)
		for range callers {
			<-attempted
		}
		return successfulProbeOutput(), nil
	})

	results := make([]clusterProbeResult, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			attempted <- struct{}{}
			results[i] = probe.Probe(context.Background(), "cluster-a")
		}()
	}
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("probe calls = %d, want 1", got)
	}
	for i, result := range results {
		if result.Outcome != clusterProbeReachable || result.Failure != nil {
			t.Errorf("result %d = %+v, want reachable", i, result)
		}
	}
}

func TestClusterProbe_ClassifiesNetworkAndTLSFailures(t *testing.T) {
	cases := []struct {
		name string
		text string
		err  error
	}{
		{name: "network timeout", text: "Error from server: net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers)"},
		{name: "request deadline", text: "Unable to connect to the server: context deadline exceeded"},
		{name: "connection refused", text: "Unable to connect to the server: dial tcp 192.0.2.1:443: connect: connection refused"},
		{name: "no route", text: "Unable to connect to the server: dial tcp 192.0.2.1:443: connect: no route to host"},
		{name: "TLS handshake", text: "Unable to connect to the server: net/http: TLS handshake timeout"},
		{name: "TLS certificate verification", text: "Unable to connect to the server: tls: failed to verify certificate: x509: certificate signed by unknown authority"},
		{name: "runner network error", err: errors.New("dial tcp: connection refused")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := newClusterProbeFuse(func(context.Context, clusterProbeRequest) (collect.Output, error) {
				return collect.Output{ExitCode: 1, Stderr: []byte(tc.text)}, tc.err
			})
			result := probe.Probe(context.Background(), "cluster-a")
			if result.Outcome != clusterProbeSkipped || result.Reason != "cluster_unreachable" {
				t.Fatalf("result = %+v, want cluster_unreachable skip", result)
			}
		})
	}
}

func TestClusterProbe_ClassifiesUnauthorizedAndForbidden(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{name: "unauthorized", text: "Error from server (Unauthorized): the server has asked for the client to provide credentials"},
		{name: "forbidden", text: "Error from server (Forbidden): user cannot get version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := newClusterProbeFuse(func(context.Context, clusterProbeRequest) (collect.Output, error) {
				return collect.Output{ExitCode: 1, Stderr: []byte(tc.text)}, nil
			})
			result := probe.Probe(context.Background(), "cluster-a")
			if result.Outcome != clusterProbeSkipped || result.Reason != "permission_denied" {
				t.Fatalf("result = %+v, want permission_denied skip", result)
			}
		})
	}
}

func TestClusterProbe_ClassifiesUnexpectedFailures(t *testing.T) {
	cases := []struct {
		name string
		run  func(context.Context, clusterProbeRequest) (collect.Output, error)
	}{
		{
			name: "server error",
			run: func(context.Context, clusterProbeRequest) (collect.Output, error) {
				return collect.Output{ExitCode: 1, Stderr: []byte("Internal error occurred: backend unavailable")}, nil
			},
		},
		{
			name: "invalid output",
			run: func(context.Context, clusterProbeRequest) (collect.Output, error) {
				return collect.Output{Stdout: []byte("not json")}, nil
			},
		},
		{
			name: "missing server version",
			run: func(context.Context, clusterProbeRequest) (collect.Output, error) {
				return collect.Output{Stdout: []byte(`{"clientVersion":{"gitVersion":"v1.33.0"}}`)}, nil
			},
		},
		{
			name: "runner error",
			run: func(context.Context, clusterProbeRequest) (collect.Output, error) {
				return collect.Output{}, errors.New("runner failed")
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := newClusterProbeFuse(tc.run)
			result := probe.Probe(context.Background(), "cluster-a")
			if result.Outcome != clusterProbeError || result.Failure == nil {
				t.Fatalf("result = %+v, want error with failure", result)
			}
		})
	}
}

func TestClusterProbe_IsolatesClusterStates(t *testing.T) {
	var calls atomic.Int32
	probe := newClusterProbeFuse(func(_ context.Context, request clusterProbeRequest) (collect.Output, error) {
		calls.Add(1)
		if request.ClusterKey == "cluster-b" {
			return collect.Output{ExitCode: 1, Stderr: []byte("connection refused")}, nil
		}
		return successfulProbeOutput(), nil
	})

	bad := probe.Probe(context.Background(), "cluster-b")
	good := probe.Probe(context.Background(), "cluster-a")
	badAgain := probe.Probe(context.Background(), "cluster-b")
	if bad.Outcome != clusterProbeSkipped || bad.Reason != "cluster_unreachable" {
		t.Fatalf("bad cluster = %+v", bad)
	}
	if good.Outcome != clusterProbeReachable || good.Failure != nil {
		t.Fatalf("healthy cluster = %+v", good)
	}
	if badAgain.Outcome != bad.Outcome || badAgain.Reason != bad.Reason {
		t.Fatalf("cached bad cluster = %+v, want %+v", badAgain, bad)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("probe calls = %d, want one per cluster", got)
	}
}

func TestClusterProbe_HonorsTimeoutAndCancellation(t *testing.T) {
	t.Run("request timeout", func(t *testing.T) {
		var got clusterProbeRequest
		probe := newClusterProbeFuse(func(_ context.Context, request clusterProbeRequest) (collect.Output, error) {
			got = request
			return collect.Output{TimedOut: true, ExitCode: 1}, nil
		})
		result := probe.Probe(context.Background(), "cluster-a")
		if got.RequestTimeout != 15*time.Second {
			t.Fatalf("request timeout = %s, want 15s", got.RequestTimeout)
		}
		if want := []string{"version", "-o", "json", "--request-timeout=15s"}; !slices.Equal(got.Argv, want) {
			t.Fatalf("probe argv = %q, want %q", got.Argv, want)
		}
		if result.Outcome != clusterProbeSkipped || result.Reason != "cluster_unreachable" {
			t.Fatalf("result = %+v, want cluster_unreachable skip", result)
		}
	})

	t.Run("executor deadline is fused", func(t *testing.T) {
		var calls atomic.Int32
		probe := newClusterProbeFuse(func(context.Context, clusterProbeRequest) (collect.Output, error) {
			calls.Add(1)
			return collect.Output{}, context.DeadlineExceeded
		})
		ctx := context.Background()
		first := probe.Probe(ctx, "cluster-a")
		second := probe.Probe(ctx, "cluster-a")
		for _, result := range []clusterProbeResult{first, second} {
			if result.Outcome != clusterProbeSkipped || result.Reason != "cluster_unreachable" {
				t.Fatalf("result = %+v, want cached cluster_unreachable skip", result)
			}
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("executor calls = %d, want 1 cached deadline result", got)
		}
	})

	t.Run("cancellation is not fused", func(t *testing.T) {
		var calls atomic.Int32
		started := make(chan struct{})
		probe := newClusterProbeFuse(func(ctx context.Context, _ clusterProbeRequest) (collect.Output, error) {
			if calls.Add(1) == 1 {
				close(started)
				select {
				case <-ctx.Done():
					return collect.Output{}, ctx.Err()
				case <-time.After(time.Second):
					return successfulProbeOutput(), nil
				}
			}
			return successfulProbeOutput(), nil
		})
		ctx, cancel := context.WithCancel(context.Background())
		resultChan := make(chan clusterProbeResult, 1)
		go func() {
			resultChan <- probe.Probe(ctx, "cluster-a")
		}()
		<-started
		cancel()
		result := <-resultChan
		if result.Outcome != clusterProbeCanceled {
			t.Fatalf("canceled result = %+v, want canceled", result)
		}
		retry := probe.Probe(context.Background(), "cluster-a")
		if retry.Outcome != clusterProbeReachable {
			t.Fatalf("retry result = %+v, want reachable", retry)
		}
		if got := calls.Load(); got != 2 {
			t.Fatalf("executor calls = %d, want canceled attempt plus retry", got)
		}
	})
}

func successfulProbeOutput() collect.Output {
	return collect.Output{Stdout: []byte(`{"clientVersion":{"gitVersion":"v1.33.0"},"serverVersion":{"gitVersion":"v1.33.0"}}`)}
}

func TestClusterProbe_ResultReasonUsesStableFailureClass(t *testing.T) {
	probe := newClusterProbeFuse(func(context.Context, clusterProbeRequest) (collect.Output, error) {
		return collect.Output{ExitCode: 1, Stderr: []byte("Error from server (Forbidden): denied")}, nil
	})
	result := probe.Probe(context.Background(), "cluster-a")
	if result.Failure == nil || result.Failure.Class != failure.Permission {
		t.Fatalf("failure = %+v, want permission class", result.Failure)
	}
	if result.Reason != "permission_denied" {
		t.Fatalf("reason = %q, want permission_denied", result.Reason)
	}
	if result.Failure.Summary == "" {
		t.Fatal(fmt.Sprintf("failure summary is empty: %+v", result.Failure))
	}
}
