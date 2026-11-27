package eval

import "github.com/SummerQXY/gbencher/internal/failure"

// Action describes how evaluation handles a collection failure.
type Action int

const (
	ActionContinue Action = iota
	ActionEmpty
	ActionAbort
)

// Decision is the assessment outcome for a collection failure.
type Decision struct {
	Action Action
	Status string
	Reason string
	Fatal  bool
}

// Decide maps a classified collection failure to an assessment outcome.
func Decide(f *failure.Failure, onError string) Decision {
	if f == nil {
		return Decision{Action: ActionAbort, Status: "ERROR"}
	}

	decision := Decision{Action: ActionAbort, Status: "ERROR", Reason: string(f.Class)}
	if f.Class == failure.AuthExpired {
		decision.Fatal = true
		return decision
	}
	if f.Class == failure.GuardRejected {
		return decision
	}

	if onError == "" {
		onError = "error"
	}

	switch f.Class {
	case failure.Permission:
		decision.Status = "SKIPPED"
		return decision
	case failure.ServiceDisabled:
		switch onError {
		case "empty":
			return Decision{Action: ActionEmpty, Reason: decision.Reason}
		case "skip":
			decision.Status = "SKIPPED"
		case "ignore":
			return Decision{Action: ActionContinue, Reason: decision.Reason}
		default:
			decision.Status = "NOT_APPLICABLE"
		}
		return decision
	case failure.NotFound, failure.FailedPrecondition:
		return applyOnError(decision, onError)
	case failure.Timeout, failure.OutputTooLarge, failure.RateLimited, failure.ServerError, failure.Parse, failure.Unknown:
		if onError == "skip" || onError == "ignore" {
			return applyOnError(decision, onError)
		}
		return decision
	default:
		return decision
	}
}

func applyOnError(decision Decision, onError string) Decision {
	switch onError {
	case "empty":
		return Decision{Action: ActionEmpty, Reason: decision.Reason}
	case "skip":
		decision.Status = "SKIPPED"
	case "ignore":
		return Decision{Action: ActionContinue, Reason: decision.Reason}
	}
	return decision
}

// EmptyShape identifies the empty value used after a tolerated collection failure.
type EmptyShape int

const (
	EmptyList EmptyShape = iota
	EmptyObject
	EmptyString
	EmptyLines
)

// EmptyValue returns an empty value matching the requested parsed shape.
func EmptyValue(shape EmptyShape) any {
	switch shape {
	case EmptyList:
		return []any{}
	case EmptyObject:
		return map[string]any{}
	case EmptyString:
		return ""
	case EmptyLines:
		return []string{}
	default:
		return nil
	}
}

// ServicesMissing returns declared services that are not enabled.
func ServicesMissing(declared []string, enabled map[string]bool) []string {
	if enabled == nil {
		return nil
	}

	missing := make([]string, 0)
	for _, service := range declared {
		if !enabled[service] {
			missing = append(missing, service)
		}
	}
	return missing
}
