package failure

import "errors"

// Class identifies a collection failure category.
type Class string

const (
	Permission         Class = "permission_denied"
	ServiceDisabled    Class = "service_disabled"
	NotFound           Class = "not_found"
	FailedPrecondition Class = "failed_precondition"
	RateLimited        Class = "rate_limited"
	ServerError        Class = "server_error"
	Timeout            Class = "timeout"
	OutputTooLarge     Class = "output_too_large"
	Parse              Class = "parse_error"
	AuthExpired        Class = "auth_expired"
	GuardRejected      Class = "guard_rejected"
	FanoutExceeded     Class = "fanout_exceeded"
	Unknown            Class = "unknown"
)

// Failure is a classified collection failure.
type Failure struct {
	Class                      Class
	Summary, MissingPermission string
	ExitCode                   int
}

// Error returns a concise diagnostic containing the category and summary.
func (f *Failure) Error() string {
	if f == nil {
		return "<nil>"
	}
	return string(f.Class) + ": " + f.Summary
}

// Fatal reports whether the failure invalidates the fixed gcloud identity.
func (f *Failure) Fatal() bool {
	return f != nil && f.Class == AuthExpired
}

// As finds a Failure in err or any wrapped error.
func As(err error) (*Failure, bool) {
	var f *Failure
	if !errors.As(err, &f) || f == nil {
		return nil, false
	}
	return f, true
}
