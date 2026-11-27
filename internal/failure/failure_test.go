package failure

import (
	"errors"
	"testing"
)

func TestFailure_FatalOnlyForAuthExpired(t *testing.T) {
	if !(&Failure{Class: AuthExpired}).Fatal() {
		t.Fatal("AuthExpired must be fatal")
	}
	if (&Failure{Class: Permission}).Fatal() {
		t.Fatal("Permission must not be fatal")
	}
}

func TestAs_FindsFailureInWrappedError(t *testing.T) {
	want := &Failure{Class: Permission, Summary: "denied"}
	got, ok := As(errors.Join(errors.New("outer"), want))
	if !ok || got != want {
		t.Fatalf("As() = (%+v, %v), want (%+v, true)", got, ok, want)
	}
}

func TestFailure_ErrorIncludesClassAndSummary(t *testing.T) {
	got := (&Failure{Class: NotFound, Summary: "missing"}).Error()
	if got != "not_found: missing" {
		t.Fatalf("Error() = %q", got)
	}
}
