// Package sanitize replaces known environment identifiers with stable synthetic values.
package sanitize

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/SummerQXY/gbencher/internal/redact"
)

type Scrubber struct {
	known    []string
	metadata map[string]string
	roles    map[string]string
}

var (
	emailPattern   = regexp.MustCompile(`(?i)[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}`)
	ipv4Pattern    = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	ipv6Pattern    = regexp.MustCompile(`(?i)(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}`)
	bucketPattern  = regexp.MustCompile(`gs://[a-z0-9][a-z0-9._-]{1,220}`)
	projectPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
)

// New creates a scrubber for identifiers that should be replaced in every value.
func New(known []string) *Scrubber {
	values := compact(known)
	sort.Strings(values)
	return &Scrubber{known: values}
}

// DefaultKnown returns the environment identifiers collected from project metadata and identity.
func DefaultKnown(projects []string, projectNumber, orgID, orgDomain, account string) []string {
	known := append([]string(nil), projects...)
	known = append(known, projectNumber, orgID, orgDomain, account)
	return compact(known)
}

// NewWithMetadata preserves the semantic replacements for project metadata identifiers.
func NewWithMetadata(projects, projectNumbers, orgIDs, orgDomains []string, account string) *Scrubber {
	known := append([]string(nil), projects...)
	known = append(known, projectNumbers...)
	known = append(known, orgIDs...)
	known = append(known, orgDomains...)
	if account != "" {
		known = append(known, account)
	}
	s := New(known)
	s.metadata = make(map[string]string)
	s.roles = make(map[string]string)
	for _, value := range projectNumbers {
		s.setMetadata(value, "projectNumber", "123456789012")
	}
	for _, value := range orgIDs {
		s.setMetadata(value, "orgID", "111111111111")
	}
	for _, value := range orgDomains {
		s.setMetadata(value, "orgDomain", "example.com")
	}
	if account != "" {
		s.setMetadata(account, "account", "scanner@example-sec.iam.gserviceaccount.com")
	}
	return s
}

func (s *Scrubber) setMetadata(value, role, preferred string) {
	if value == "" {
		return
	}
	if _, exists := s.roles[value]; exists {
		return
	}
	s.roles[value] = role
	s.metadata[value] = preferred
}

// Scrub recursively sanitizes supported JSON-shaped values and returns the original-to-replacement map.
func (s *Scrubber) Scrub(v any) (any, map[string]string) {
	if encoded, err := json.Marshal(v); err == nil {
		var normalized any
		if json.Unmarshal(encoded, &normalized) == nil {
			v = normalized
		}
	}
	visible := make(map[string]struct{})
	collectVisible(v, false, visible)
	mapping := buildMapping(visible, s.known, s.metadata, s.roles)
	state := scrubState{mapping: mapping, replacer: makeReplacer(mapping)}
	return state.value(v, "", false), mapping
}

type scrubState struct {
	mapping  map[string]string
	replacer *strings.Replacer
}

func (s *scrubState) value(v any, field string, forceSecret bool) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		keys := make([]string, 0, len(x))
		for key := range x {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := x[key]
			if isMetadataKey(key) {
				if text, ok := scalarText(child); ok {
					if replacement, exists := s.mapping[text]; exists {
						out[key] = replacement
						continue
					}
				}
			}
			secret := forceSecret || secretField(key)
			if strings.EqualFold(key, "items") {
				out[key] = s.metadataItems(child)
				continue
			}
			if strings.EqualFold(key, "environmentVariables") || strings.EqualFold(key, "secretEnvironmentVariables") {
				out[key] = s.environmentVariables(child)
				continue
			}
			out[key] = s.value(child, key, secret)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, child := range x {
			out[i] = s.value(child, field, forceSecret)
		}
		return out
	case string:
		if forceSecret {
			return "[REDACTED]"
		}
		return s.replacer.Replace(redact.String(x))
	default:
		return v
	}
}

func (s *scrubState) environmentVariables(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		_, hasValue := x["value"]
		if !hasValue {
			_, hasValue = x["Value"]
		}
		for key, child := range x {
			if strings.EqualFold(key, "value") || !hasValue && isString(child) {
				out[key] = "[REDACTED]"
			} else if hasValue {
				out[key] = s.value(child, key, false)
			} else {
				out[key] = s.environmentVariables(child)
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, child := range x {
			out[i] = s.environmentVariables(child)
		}
		return out
	default:
		if isString(v) {
			return "[REDACTED]"
		}
		return s.value(v, "", false)
	}
}

func isString(value any) bool { _, ok := value.(string); return ok }

func (s *scrubState) metadataItems(v any) any {
	items, ok := v.([]any)
	if !ok {
		return s.value(v, "items", false)
	}
	out := make([]any, len(items))
	for i, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			out[i] = s.value(item, "items", false)
			continue
		}
		key, _ := m["key"].(string)
		secret := secretMetadataKey(key)
		copy := make(map[string]any, len(m))
		for k, value := range m {
			copy[k] = s.value(value, k, secret && strings.EqualFold(k, "value"))
		}
		out[i] = copy
	}
	return out
}

func collectVisible(v any, secret bool, out map[string]struct{}) {
	if secret {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		for key, child := range x {
			if isMetadataKey(key) {
				if text, ok := scalarText(child); ok {
					out[text] = struct{}{}
				}
			}
			if strings.EqualFold(key, "items") {
				collectMetadataItems(child, out)
				continue
			}
			if strings.EqualFold(key, "environmentVariables") || strings.EqualFold(key, "secretEnvironmentVariables") {
				collectEnvironmentVariables(child, out)
				continue
			}
			collectVisible(child, secretField(key), out)
		}
	case []any:
		for _, child := range x {
			collectVisible(child, false, out)
		}
	case string:
		out[x] = struct{}{}
	}
}

func collectMetadataItems(v any, out map[string]struct{}) {
	items, ok := v.([]any)
	if !ok {
		collectVisible(v, false, out)
		return
	}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			collectVisible(item, false, out)
			continue
		}
		key, _ := m["key"].(string)
		for field, value := range m {
			collectVisible(value, secretMetadataKey(key) && strings.EqualFold(field, "value"), out)
		}
	}
}

func collectEnvironmentVariables(v any, out map[string]struct{}) {
	switch x := v.(type) {
	case map[string]any:
		_, hasValue := x["value"]
		if !hasValue {
			_, hasValue = x["Value"]
		}
		for key, child := range x {
			if strings.EqualFold(key, "value") || !hasValue && isString(child) {
				continue
			}
			collectVisible(child, false, out)
		}
	case []any:
		for _, child := range x {
			collectEnvironmentVariables(child, out)
		}
	}
}

func buildMapping(visible map[string]struct{}, known []string, metadata, roles map[string]string) map[string]string {
	candidates := make(map[string]string)
	texts := make([]string, 0, len(visible))
	for text := range visible {
		texts = append(texts, text)
	}
	sort.Strings(texts)
	for _, value := range known {
		for _, text := range texts {
			if strings.Contains(text, value) {
				candidates[value] = roleForKnown(value)
				break
			}
		}
	}
	for _, text := range texts {
		for _, value := range emailPattern.FindAllString(text, -1) {
			addCandidate(candidates, value, "email")
		}
		for _, value := range ipv4Pattern.FindAllString(text, -1) {
			if net.ParseIP(value) != nil {
				addCandidate(candidates, value, "ipv4")
			}
		}
		for _, value := range ipv6Pattern.FindAllString(text, -1) {
			if net.ParseIP(value) != nil {
				addCandidate(candidates, value, "ipv6")
			}
		}
		for _, value := range bucketPattern.FindAllString(text, -1) {
			addCandidate(candidates, value, "bucket")
		}
	}
	for value, role := range roles {
		if _, exists := candidates[value]; exists {
			candidates[value] = role
		}
	}

	originals := make([]string, 0, len(candidates))
	for value := range candidates {
		originals = append(originals, value)
	}
	sort.Strings(originals)
	usedRaw := make(map[string]struct{}, len(candidates))
	for value := range candidates {
		usedRaw[value] = struct{}{}
	}
	usedReplacements := map[string]struct{}{}
	result := make(map[string]string, len(candidates))
	byRole := make(map[string][]string)
	for _, value := range originals {
		byRole[candidates[value]] = append(byRole[candidates[value]], value)
	}
	for _, role := range []string{"project", "projectNumber", "orgID", "orgDomain", "account", "email", "ipv4", "ipv6", "bucket", "generic"} {
		values := byRole[role]
		for index, value := range values {
			preferred := metadata[value]
			if preferred == "" {
				preferred = preferredReplacement(role, index+1, len(values), value)
			}
			replacement := allocateReplacement(preferred, role, index+1, usedRaw, usedReplacements)
			result[value] = replacement
			usedReplacements[replacement] = struct{}{}
		}
	}
	return result
}

func isMetadataKey(key string) bool {
	switch strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key)) {
	case "projectnumber", "organization", "organizationid", "orgid", "organizationdomain", "orgdomain":
		return true
	default:
		return false
	}
}

func scalarText(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, v != ""
	case float64:
		return fmt.Sprintf("%.0f", v), v >= 0 && v == float64(uint64(v))
	case int, int32, int64, uint, uint32, uint64:
		return fmt.Sprint(v), true
	default:
		return "", false
	}
}

func addCandidate(candidates map[string]string, value, role string) {
	if _, exists := candidates[value]; !exists {
		candidates[value] = role
	}
}

func roleForKnown(value string) string {
	switch {
	case projectPattern.MatchString(value):
		return "project"
	case strings.Contains(value, "@"):
		return "account"
	case strings.HasPrefix(value, "gs://"):
		return "bucket"
	case net.ParseIP(value) != nil && strings.Contains(value, "."):
		return "ipv4"
	case net.ParseIP(value) != nil:
		return "ipv6"
	case allDigits(value):
		if len(value) == 12 && value != "111111111111" {
			return "projectNumber"
		}
		return "orgID"
	case strings.Contains(value, "."):
		return "orgDomain"
	default:
		return "generic"
	}
}

func preferredReplacement(role string, index, total int, original string) string {
	switch role {
	case "project":
		if total == 1 {
			return "example-prod"
		}
		return fmt.Sprintf("example-prod-%d", index)
	case "projectNumber":
		return "123456789012"
	case "orgID":
		return "111111111111"
	case "orgDomain":
		return "example.com"
	case "account":
		return "scanner@example-sec.iam.gserviceaccount.com"
	case "email":
		if strings.HasSuffix(strings.ToLower(original), ".iam.gserviceaccount.com") {
			return "scanner@example-sec.iam.gserviceaccount.com"
		}
		return fmt.Sprintf("user-%d@example.com", index)
	case "ipv4":
		return fmt.Sprintf("203.0.113.%d", index)
	case "ipv6":
		return fmt.Sprintf("2001:db8::%x", index)
	case "bucket":
		return fmt.Sprintf("gs://example-bucket-%d", index)
	default:
		return fmt.Sprintf("value-%d", index)
	}
}

func allocateReplacement(preferred, role string, index int, originals, used map[string]struct{}) string {
	if safeReplacement(preferred, originals, used) {
		return preferred
	}
	limit := len(originals) + len(used) + 64
	if limit < 64 {
		limit = 64
	}
	for attempt := 1; attempt <= limit; attempt++ {
		candidate := fallbackReplacement(role, index, attempt)
		if safeReplacement(candidate, originals, used) {
			return candidate
		}
	}
	return terminalReplacement(role, originals, used)
}

func safeReplacement(candidate string, originals, used map[string]struct{}) bool {
	if candidate == "" {
		return false
	}
	if _, exists := used[candidate]; exists {
		return false
	}
	for original := range originals {
		if strings.Contains(candidate, original) {
			return false
		}
	}
	return true
}

// terminalReplacement uses a private-use marker after bounded named fallbacks are exhausted.
func terminalReplacement(role string, originals, used map[string]struct{}) string {
	maxLength := 1
	for value := range originals {
		if len(value) > maxLength {
			maxLength = len(value)
		}
	}
	for value := range used {
		if len(value) > maxLength {
			maxLength = len(value)
		}
	}
	for codepoint := rune(0xF0000); codepoint <= 0xFFFFD; codepoint++ {
		marker := string(codepoint)
		occupied := false
		for value := range originals {
			if strings.Contains(value, marker) {
				occupied = true
				break
			}
		}
		if occupied {
			continue
		}
		for value := range used {
			if strings.Contains(value, marker) {
				occupied = true
				break
			}
		}
		if occupied {
			continue
		}
		terminal := strings.Repeat(marker, maxLength+1)
		visible := fmt.Sprintf("[SANITIZED-%s]%s", role, terminal)
		if safeReplacement(visible, originals, used) {
			return visible
		}
		return terminal
	}
	return strings.Repeat("\uFDD0", maxLength+1)
}

func fallbackReplacement(role string, index, attempt int) string {
	sequence := index + attempt - 1
	switch role {
	case "project":
		return fmt.Sprintf("sanitized-project-%d", sequence)
	case "projectNumber", "orgID":
		return fmt.Sprintf("%012d", 900000000000+sequence)
	case "orgDomain":
		return fmt.Sprintf("sanitized-domain-%d.invalid", sequence)
	case "account":
		return fmt.Sprintf("scanner-sanitized-%d@example.net", sequence)
	case "email":
		return fmt.Sprintf("user-%d@example.net", sequence)
	case "ipv4":
		return fmt.Sprintf("198.51.100.%d", sequence)
	case "ipv6":
		return fmt.Sprintf("2001:0db8:0001:0000:0000:0000:0000:%04x", sequence)
	case "bucket":
		return fmt.Sprintf("gs://sanitized-bucket-%d", sequence)
	default:
		return fmt.Sprintf("sanitized-value-%d", sequence)
	}
}

func knownReplacement(value string) string {
	return preferredReplacement(roleForKnown(value), 1, 1, value)
}

func makeReplacer(mapping map[string]string) *strings.Replacer {
	keys := make([]string, 0, len(mapping))
	for key := range mapping {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	pairs := make([]string, 0, len(keys)*2)
	for _, key := range keys {
		pairs = append(pairs, key, mapping[key])
	}
	return strings.NewReplacer(pairs...)
}

func secretField(key string) bool {
	switch strings.ToLower(key) {
	case "clientkey", "password", "username", "environmentvariables", "secretenvironmentvariables":
		return true
	}
	return false
}

func secretMetadataKey(key string) bool {
	switch strings.ToLower(strings.ReplaceAll(key, "_", "-")) {
	case "startup-script", "ssh-keys", "sshkeys", "user-data", "userdata", "cloud-config":
		return true
	default:
		return strings.Contains(strings.ToLower(key), "secret")
	}
}

func compact(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
