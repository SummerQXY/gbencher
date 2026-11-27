package eval_test

import (
	"reflect"
	"testing"

	"github.com/SummerQXY/gbencher/internal/eval"
	"github.com/SummerQXY/gbencher/internal/failure"
)

func TestDecide_FailureClasses(t *testing.T) {
	tests := []struct {
		name    string
		class   failure.Class
		onError string
		want    eval.Decision
	}{
		{name: "permission_error", class: failure.Permission, onError: "error", want: eval.Decision{Action: eval.ActionAbort, Status: "SKIPPED", Reason: string(failure.Permission)}},
		{name: "permission_empty", class: failure.Permission, onError: "empty", want: eval.Decision{Action: eval.ActionAbort, Status: "SKIPPED", Reason: string(failure.Permission)}},
		{name: "permission_skip", class: failure.Permission, onError: "skip", want: eval.Decision{Action: eval.ActionAbort, Status: "SKIPPED", Reason: string(failure.Permission)}},
		{name: "permission_ignore", class: failure.Permission, onError: "ignore", want: eval.Decision{Action: eval.ActionAbort, Status: "SKIPPED", Reason: string(failure.Permission)}},
		{name: "service_disabled_error", class: failure.ServiceDisabled, onError: "error", want: eval.Decision{Action: eval.ActionAbort, Status: "NOT_APPLICABLE", Reason: string(failure.ServiceDisabled)}},
		{name: "service_disabled_empty", class: failure.ServiceDisabled, onError: "empty", want: eval.Decision{Action: eval.ActionEmpty, Reason: string(failure.ServiceDisabled)}},
		{name: "service_disabled_skip", class: failure.ServiceDisabled, onError: "skip", want: eval.Decision{Action: eval.ActionAbort, Status: "SKIPPED", Reason: string(failure.ServiceDisabled)}},
		{name: "service_disabled_ignore", class: failure.ServiceDisabled, onError: "ignore", want: eval.Decision{Action: eval.ActionContinue, Reason: string(failure.ServiceDisabled)}},
		{name: "not_found_error", class: failure.NotFound, onError: "error", want: eval.Decision{Action: eval.ActionAbort, Status: "ERROR", Reason: string(failure.NotFound)}},
		{name: "not_found_empty", class: failure.NotFound, onError: "empty", want: eval.Decision{Action: eval.ActionEmpty, Reason: string(failure.NotFound)}},
		{name: "not_found_skip", class: failure.NotFound, onError: "skip", want: eval.Decision{Action: eval.ActionAbort, Status: "SKIPPED", Reason: string(failure.NotFound)}},
		{name: "not_found_ignore", class: failure.NotFound, onError: "ignore", want: eval.Decision{Action: eval.ActionContinue, Reason: string(failure.NotFound)}},
		{name: "failed_precondition_error", class: failure.FailedPrecondition, onError: "error", want: eval.Decision{Action: eval.ActionAbort, Status: "ERROR", Reason: string(failure.FailedPrecondition)}},
		{name: "failed_precondition_empty", class: failure.FailedPrecondition, onError: "empty", want: eval.Decision{Action: eval.ActionEmpty, Reason: string(failure.FailedPrecondition)}},
		{name: "failed_precondition_skip", class: failure.FailedPrecondition, onError: "skip", want: eval.Decision{Action: eval.ActionAbort, Status: "SKIPPED", Reason: string(failure.FailedPrecondition)}},
		{name: "failed_precondition_ignore", class: failure.FailedPrecondition, onError: "ignore", want: eval.Decision{Action: eval.ActionContinue, Reason: string(failure.FailedPrecondition)}},
		{name: "timeout_error", class: failure.Timeout, onError: "error", want: eval.Decision{Action: eval.ActionAbort, Status: "ERROR", Reason: string(failure.Timeout)}},
		{name: "timeout_empty", class: failure.Timeout, onError: "empty", want: eval.Decision{Action: eval.ActionAbort, Status: "ERROR", Reason: string(failure.Timeout)}},
		{name: "timeout_skip", class: failure.Timeout, onError: "skip", want: eval.Decision{Action: eval.ActionAbort, Status: "SKIPPED", Reason: string(failure.Timeout)}},
		{name: "timeout_ignore", class: failure.Timeout, onError: "ignore", want: eval.Decision{Action: eval.ActionContinue, Reason: string(failure.Timeout)}},
		{name: "output_too_large_empty", class: failure.OutputTooLarge, onError: "empty", want: eval.Decision{Action: eval.ActionAbort, Status: "ERROR", Reason: string(failure.OutputTooLarge)}},
		{name: "rate_limited_empty", class: failure.RateLimited, onError: "empty", want: eval.Decision{Action: eval.ActionAbort, Status: "ERROR", Reason: string(failure.RateLimited)}},
		{name: "server_error_empty", class: failure.ServerError, onError: "empty", want: eval.Decision{Action: eval.ActionAbort, Status: "ERROR", Reason: string(failure.ServerError)}},
		{name: "parse_empty", class: failure.Parse, onError: "empty", want: eval.Decision{Action: eval.ActionAbort, Status: "ERROR", Reason: string(failure.Parse)}},
		{name: "unknown_empty", class: failure.Unknown, onError: "empty", want: eval.Decision{Action: eval.ActionAbort, Status: "ERROR", Reason: string(failure.Unknown)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := eval.Decide(&failure.Failure{Class: tt.class}, tt.onError)
			if got != tt.want {
				t.Fatalf("Decide() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDecide_DefaultFailureClassesRespectOnError(t *testing.T) {
	classes := []failure.Class{
		failure.Timeout,
		failure.OutputTooLarge,
		failure.RateLimited,
		failure.ServerError,
		failure.Parse,
		failure.Unknown,
	}
	for _, class := range classes {
		for _, onError := range []string{"error", "empty", "skip", "ignore"} {
			t.Run(string(class)+"/"+onError, func(t *testing.T) {
				want := eval.Decision{Reason: string(class)}
				switch onError {
				case "skip":
					want.Action = eval.ActionAbort
					want.Status = "SKIPPED"
				case "ignore":
					want.Action = eval.ActionContinue
				default:
					want.Action = eval.ActionAbort
					want.Status = "ERROR"
				}
				if got := eval.Decide(&failure.Failure{Class: class}, onError); got != want {
					t.Fatalf("Decide() = %+v, want %+v", got, want)
				}
			})
		}
	}
}

func TestDecide_DefaultsAndSpecialFailures(t *testing.T) {
	t.Run("empty on_error defaults to error", func(t *testing.T) {
		got := eval.Decide(&failure.Failure{Class: failure.NotFound}, "")
		want := eval.Decision{Action: eval.ActionAbort, Status: "ERROR", Reason: string(failure.NotFound)}
		if got != want {
			t.Fatalf("Decide() = %+v, want %+v", got, want)
		}
	})
	t.Run("unknown on_error defaults to error", func(t *testing.T) {
		got := eval.Decide(&failure.Failure{Class: failure.NotFound}, "invalid")
		want := eval.Decision{Action: eval.ActionAbort, Status: "ERROR", Reason: string(failure.NotFound)}
		if got != want {
			t.Fatalf("Decide() = %+v, want %+v", got, want)
		}
	})
	t.Run("nil failure", func(t *testing.T) {
		got := eval.Decide(nil, "empty")
		want := eval.Decision{Action: eval.ActionAbort, Status: "ERROR"}
		if got != want {
			t.Fatalf("Decide() = %+v, want %+v", got, want)
		}
	})
}

func TestDecide_GuardRejectedIsAlwaysError(t *testing.T) {
	for _, onError := range []string{"", "error", "empty", "skip", "ignore"} {
		t.Run(onError, func(t *testing.T) {
			got := eval.Decide(&failure.Failure{Class: failure.GuardRejected}, onError)
			want := eval.Decision{Action: eval.ActionAbort, Status: "ERROR", Reason: string(failure.GuardRejected)}
			if got != want {
				t.Fatalf("Decide() = %+v, want %+v", got, want)
			}
		})
	}
}

func TestDecide_AuthExpiredIsFatal(t *testing.T) {
	for _, onError := range []string{"", "error", "empty", "skip", "ignore"} {
		t.Run(onError, func(t *testing.T) {
			got := eval.Decide(&failure.Failure{Class: failure.AuthExpired}, onError)
			want := eval.Decision{Action: eval.ActionAbort, Status: "ERROR", Reason: string(failure.AuthExpired), Fatal: true}
			if got != want {
				t.Fatalf("Decide() = %+v, want %+v", got, want)
			}
		})
	}
}

func TestServicesMissing_NilEnabledMeansUnknown(t *testing.T) {
	if got := eval.ServicesMissing([]string{"compute", "logging"}, nil); got != nil {
		t.Fatalf("ServicesMissing() = %#v, want nil", got)
	}
}

func TestServicesMissing_ReturnsDisabledInDeclarationOrder(t *testing.T) {
	got := eval.ServicesMissing([]string{"compute", "logging", "storage", "logging"}, map[string]bool{"compute": true, "storage": false})
	want := []string{"logging", "storage", "logging"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ServicesMissing() = %#v, want %#v", got, want)
	}
}

func TestEmptyValue_Shapes(t *testing.T) {
	tests := []struct {
		name  string
		shape eval.EmptyShape
		want  any
	}{
		{name: "list", shape: eval.EmptyList, want: []any{}},
		{name: "object", shape: eval.EmptyObject, want: map[string]any{}},
		{name: "string", shape: eval.EmptyString, want: ""},
		{name: "lines", shape: eval.EmptyLines, want: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := eval.EmptyValue(tt.shape); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("EmptyValue(%d) = %#v, want %#v", tt.shape, got, tt.want)
			}
		})
	}
}
