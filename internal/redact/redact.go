package redact

import (
	"regexp"
	"strings"
)

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`ya29\.[A-Za-z0-9._~+/-]+`),
	regexp.MustCompile(`AIza[A-Za-z0-9_-]+`),
	regexp.MustCompile(`(?is)-----BEGIN [^-]+-----.*?-----END [^-]+-----`),
	regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*`),
}

var terminalEscapePattern = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|[@-_])`)

// String replaces recognizable credential values with a stable marker.
func String(s string) string {
	for _, pattern := range secretPatterns {
		s = pattern.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}

// StripControl removes C0 and C1 controls while preserving line and tab layout.
func StripControl(s string) string {
	s = terminalEscapePattern.ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
}
