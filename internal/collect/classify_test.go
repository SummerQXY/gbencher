package collect_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/failure"
)

func TestClassifyGcloud_OneSamplePerClass(t *testing.T) {
	for class, file := range map[failure.Class]string{
		failure.ServiceDisabled:    "service_disabled",
		failure.Permission:         "permission_denied",
		failure.NotFound:           "not_found",
		failure.FailedPrecondition: "failed_precondition",
		failure.RateLimited:        "rate_limited",
		failure.ServerError:        "server_error",
		failure.AuthExpired:        "reauthentication",
		failure.Unknown:            "unknown",
	} {
		t.Run(string(class), func(t *testing.T) {
			stderr, err := os.ReadFile(filepath.Join("..", "..", "testdata", "errors", file+".stderr"))
			if err != nil {
				t.Fatal(err)
			}
			got := collect.ClassifyGcloud(collect.Output{ExitCode: 1, Stderr: stderr})
			if got == nil || got.Class != class {
				t.Fatalf("ClassifyGcloud() = %+v, want class %q", got, class)
			}
		})
	}
}

func TestClassifyGcloud_ServiceDisabledBeforePermission(t *testing.T) {
	got := collect.ClassifyGcloud(collect.Output{ExitCode: 1, Stderr: []byte("PERMISSION_DENIED: SERVICE_DISABLED")})
	if got == nil || got.Class != failure.ServiceDisabled {
		t.Fatalf("ClassifyGcloud() = %+v, want service_disabled", got)
	}
}

func TestClassifyGcloud_TimeoutAndTruncationWin(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  collect.Output
		want failure.Class
	}{
		{name: "timeout", out: collect.Output{ExitCode: 1, TimedOut: true, Stderr: []byte("PERMISSION_DENIED")}, want: failure.Timeout},
		{name: "truncation", out: collect.Output{ExitCode: 1, Truncated: true, Stderr: []byte("PERMISSION_DENIED")}, want: failure.OutputTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := collect.ClassifyGcloud(tc.out)
			if got == nil || got.Class != tc.want {
				t.Fatalf("ClassifyGcloud() = %+v, want %q", got, tc.want)
			}
		})
	}
}

func TestClassifyGcloud_SuccessIsNil(t *testing.T) {
	if got := collect.ClassifyGcloud(collect.Output{ExitCode: 0}); got != nil {
		t.Fatalf("ClassifyGcloud() = %+v, want nil", got)
	}
}

func TestClassifyGcloud_BareNumbersInNamesAreNotStatusCodes(t *testing.T) {
	got := collect.ClassifyGcloud(collect.Output{ExitCode: 1, Stderr: []byte("ERROR: (gcloud.foo) odd failure in zone-500")})
	if got == nil || got.Class != failure.Unknown {
		t.Fatalf("ClassifyGcloud() = %+v, want unknown", got)
	}
}

func TestClassifyGcloud_HTTPStatusCodes(t *testing.T) {
	for _, tc := range []struct {
		stderr string
		want   failure.Class
	}{
		{stderr: "HTTPError 403", want: failure.Permission},
		{stderr: "HTTP 404", want: failure.NotFound},
		{stderr: "HTTPError 429", want: failure.RateLimited},
		{stderr: "HTTP 503", want: failure.ServerError},
	} {
		got := collect.ClassifyGcloud(collect.Output{ExitCode: 1, Stderr: []byte(tc.stderr)})
		if got == nil || got.Class != tc.want {
			t.Errorf("ClassifyGcloud(%q) = %+v, want %q", tc.stderr, got, tc.want)
		}
	}
}

func TestClassifyGcloud_SummaryIsRedactedAndShort(t *testing.T) {
	stderr := []byte("ERROR: token ya29.access-token " + strings.Repeat("x", 2048))
	got := collect.ClassifyGcloud(collect.Output{ExitCode: 1, Stderr: stderr})
	if got == nil {
		t.Fatal("ClassifyGcloud() = nil")
	}
	if strings.Contains(got.Summary, "ya29.access-token") {
		t.Fatalf("summary contains a token: %q", got.Summary)
	}
	if len([]rune(got.Summary)) > 500 {
		t.Fatalf("summary has %d characters", len([]rune(got.Summary)))
	}
}

func TestClassifyGcloud_ExtractsMissingPermission(t *testing.T) {
	for _, stderr := range []string{"Permission 'compute.instances.get' denied.", "request requires permission compute.instances.list"} {
		got := collect.ClassifyGcloud(collect.Output{ExitCode: 1, Stderr: []byte(stderr)})
		if got == nil || got.MissingPermission == "" {
			t.Errorf("ClassifyGcloud(%q) = %+v, missing permission", stderr, got)
		}
	}
}

func TestClassifyGcloud_MissingPermissionIsRedacted(t *testing.T) {
	got := collect.ClassifyGcloud(collect.Output{
		ExitCode: 1,
		Stderr:   []byte("Permission 'ya29.synthetic-secret' denied."),
	})
	if got == nil || got.MissingPermission != "[REDACTED]" {
		t.Fatalf("ClassifyGcloud() = %+v, want redacted MissingPermission", got)
	}
	if strings.Contains(got.MissingPermission, "synthetic-secret") {
		t.Fatalf("MissingPermission contains sensitive text: %q", got.MissingPermission)
	}
}

func TestClassifyParse_ReturnsParseFailure(t *testing.T) {
	got := collect.ClassifyParse(errors.New("invalid JSON"))
	if got == nil || got.Class != failure.Parse || got.Summary != "invalid JSON" {
		t.Fatalf("ClassifyParse() = %+v, want parse_error with summary", got)
	}
}
