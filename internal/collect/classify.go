package collect

import (
	"regexp"
	"strings"

	"github.com/SummerQXY/gbencher/internal/failure"
	"github.com/SummerQXY/gbencher/internal/redact"
)

var (
	http403Pattern            = regexp.MustCompile(`\bHTTP(?:Error)?\s+403\b`)
	http401Pattern            = regexp.MustCompile(`\bHTTP(?:Error)?\s+401\b`)
	http404Pattern            = regexp.MustCompile(`\bHTTP(?:Error)?\s+404\b`)
	http429Pattern            = regexp.MustCompile(`\bHTTP(?:Error)?\s+429\b`)
	http5xxPattern            = regexp.MustCompile(`\bHTTP(?:Error)?\s+5[0-9]{2}\b`)
	permissionPattern         = regexp.MustCompile(`(?i)Permission\s+'([^']+)'\s+denied`)
	requiresPermissionPattern = regexp.MustCompile(`(?i)requires permission\s+([A-Za-z0-9._:-]+)`)
)

// ClassifyGcloud maps a gcloud command result to its stable failure class.
func ClassifyGcloud(o Output) *failure.Failure {
	if o.TimedOut {
		return newFailure(failure.Timeout, string(o.Stderr), o.ExitCode)
	}
	if o.Truncated {
		return newFailure(failure.OutputTooLarge, string(o.Stderr), o.ExitCode)
	}
	if o.ExitCode == 0 {
		return nil
	}

	text := string(o.Stderr)
	lower := strings.ToLower(text)
	class := failure.Unknown
	switch {
	case strings.Contains(lower, "reauthentication failed"), strings.Contains(lower, "refreshing your current auth tokens"):
		class = failure.AuthExpired
	case strings.Contains(lower, "service_disabled"), strings.Contains(lower, "api has not been used"), strings.Contains(lower, "is disabled. enable it by visiting"):
		class = failure.ServiceDisabled
	case strings.Contains(lower, "permission_denied"), strings.Contains(lower, "does not have permission"), strings.Contains(lower, "requires permission"), strings.Contains(lower, "required '") && strings.Contains(lower, "' permission"), strings.Contains(lower, "permission '") && strings.Contains(lower, "' denied"), strings.Contains(lower, "forbidden"), http403Pattern.MatchString(text):
		class = failure.Permission
	case strings.Contains(lower, "not_found"), strings.Contains(lower, "was not found"), strings.Contains(lower, "could not be found"), http404Pattern.MatchString(text):
		class = failure.NotFound
	case strings.Contains(lower, "failed_precondition"), strings.Contains(lower, "user project not found"):
		class = failure.FailedPrecondition
	case strings.Contains(lower, "resource_exhausted"), strings.Contains(lower, "quota exceeded"), http429Pattern.MatchString(text):
		class = failure.RateLimited
	case strings.Contains(lower, "internal"), strings.Contains(lower, "unavailable"), strings.Contains(lower, "backend error"), http5xxPattern.MatchString(text):
		class = failure.ServerError
	}

	f := newFailure(class, summary(text), o.ExitCode)
	if class == failure.Permission {
		if match := permissionPattern.FindStringSubmatch(text); len(match) > 1 {
			f.MissingPermission = redact.StripControl(redact.String(match[1]))
		} else if match := requiresPermissionPattern.FindStringSubmatch(text); len(match) > 1 {
			f.MissingPermission = redact.StripControl(redact.String(match[1]))
		}
	}
	return f
}

// ClassifyParse wraps a JSON decoding failure in the parse_error category.
func ClassifyParse(err error) *failure.Failure {
	if err == nil {
		return nil
	}
	return newFailure(failure.Parse, err.Error(), 0)
}

func newFailure(class failure.Class, message string, exitCode int) *failure.Failure {
	return &failure.Failure{Class: class, Summary: summary(message), ExitCode: exitCode}
}

func summary(message string) string {
	line := message
	if index := strings.IndexByte(line, '\n'); index >= 0 {
		line = line[:index]
	}
	line = redact.StripControl(redact.String(line))
	runes := []rune(line)
	if len(runes) > 500 {
		line = string(runes[:500])
	}
	return line
}
