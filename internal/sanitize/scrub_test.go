package sanitize_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/sanitize"
)

func TestScrub_StableAndDeterministic(t *testing.T) {
	s := sanitize.New([]string{"sample-project", "111", "scanner@example.com"})
	a, m1 := s.Scrub(map[string]any{"a": "sample-project", "b": "projects/sample-project/zones"})
	b, m2 := s.Scrub(map[string]any{"a": "sample-project", "b": "projects/sample-project/zones"})
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(m1, m2) {
		t.Fatal("unstable")
	}
	if strings.Contains(fmt.Sprint(a), "sample-project/") {
		t.Fatal("id left in nested path")
	}
}

func TestScrub_EmailsAndIPsAndBuckets(t *testing.T) {
	s := sanitize.New(nil)
	got, _ := s.Scrub([]any{"alice@private.example", "192.0.2.10", "2001:db8::1", "gs://private-bucket/path"})
	text := fmt.Sprint(got)
	for _, want := range []string{"user-1@example.com", "203.0.113.1", "2001:0db8:0001:0000:0000:0000:0000:0001", "gs://example-bucket-1"} {
		if !strings.Contains(text, want) {
			t.Errorf("output %q missing %q", text, want)
		}
	}
}

func TestScrub_ReplacesKnownSecretFieldsAndTokens(t *testing.T) {
	input := map[string]any{
		"masterAuth": map[string]any{"clientKey": "private-key-value"},
		"metadata":   map[string]any{"items": []any{map[string]any{"key": "startup-script", "value": "echo private"}}},
		"token":      "ya29.synthetic-token",
	}
	got, _ := sanitize.New(nil).Scrub(input)
	text := fmt.Sprint(got)
	for _, secret := range []string{"private-key-value", "echo private", "ya29.synthetic-token"} {
		if strings.Contains(text, secret) {
			t.Errorf("secret %q remains in %q", secret, text)
		}
	}
	if strings.Count(text, "[REDACTED]") < 3 {
		t.Fatalf("not all secret values were redacted: %q", text)
	}
}

func TestDefaultKnown_ReplacesProjectMetadata(t *testing.T) {
	known := sanitize.DefaultKnown([]string{"sample-project"}, "123456789012", "111111111111", "org.internal.example", "scanner@private.example")
	got, mapping := sanitize.New(known).Scrub(map[string]any{"path": "projects/sample-project/zones/a", "number": "123456789012", "organization": "111111111111", "domain": "org.internal.example", "account": "scanner@private.example"})
	text := fmt.Sprint(got)
	for _, want := range []string{"example-prod", "900000000001", "900000000002", "example.com", "scanner@example-sec.iam.gserviceaccount.com"} {
		if !strings.Contains(text, want) {
			t.Errorf("output %q missing %q", text, want)
		}
	}
	if mapping["sample-project"] != "example-prod" || mapping["org.internal.example"] != "example.com" || mapping["123456789012"] == "123456789012" || mapping["111111111111"] == "111111111111" {
		t.Fatalf("unexpected mapping: %v", mapping)
	}
}

func TestScrub_EnvironmentVariableValuesOnly(t *testing.T) {
	got, _ := sanitize.New(nil).Scrub(map[string]any{"environmentVariables": []any{map[string]any{"name": "MODE", "value": "private-value"}}})
	text := fmt.Sprint(got)
	if !strings.Contains(text, "MODE") || strings.Contains(text, "private-value") || !strings.Contains(text, "[REDACTED]") {
		t.Fatalf("unexpected output: %q", text)
	}
}

func TestScrub_OverlappingKnownValuesDoNotRewriteReplacements(t *testing.T) {
	got, mapping := sanitize.New([]string{"example-prod", "example-prod-2"}).Scrub("projects/example-prod-2/zones/a")
	text := fmt.Sprint(got)
	if mapping["example-prod"] == "example-prod" || mapping["example-prod-2"] == "example-prod-2" {
		t.Fatalf("replacement collides with original values: %v", mapping)
	}
	if strings.Contains(text, "example-prod") {
		t.Fatalf("original project token remains after one-pass replacement: %q", text)
	}
}

func TestScrub_NumberingUsesSortedOriginalValues(t *testing.T) {
	first, firstMap := sanitize.New(nil).Scrub([]any{"zeta@private.example", "alpha@private.example"})
	second, secondMap := sanitize.New(nil).Scrub([]any{"alpha@private.example", "zeta@private.example"})
	if firstMap["alpha@private.example"] != "user-1@example.com" || firstMap["zeta@private.example"] != "user-2@example.com" {
		t.Fatalf("numbering is not sorted: %v", firstMap)
	}
	if secondMap["alpha@private.example"] != "user-1@example.com" || secondMap["zeta@private.example"] != "user-2@example.com" {
		t.Fatalf("numbering changed with traversal order: %v", secondMap)
	}
	_ = first
	_ = second
}

func TestScrub_BucketReplacementHasSingleScheme(t *testing.T) {
	got, mapping := sanitize.New(nil).Scrub("gs://private-bucket/path")
	if got != "gs://example-bucket-1/path" || mapping["gs://private-bucket"] != "gs://example-bucket-1" {
		t.Fatalf("got %v mapping %v", got, mapping)
	}
}

func TestScrub_CollidingNumberedPlaceholdersUseFallbacks(t *testing.T) {
	input := []any{"user-1@example.com", "203.0.113.1", "2001:db8::1", "gs://example-bucket-1"}
	got, mapping := sanitize.New(nil).Scrub(input)
	text := fmt.Sprint(got)
	for _, original := range []string{"user-1@example.com", "203.0.113.1", "2001:db8::1", "gs://example-bucket-1"} {
		if strings.Contains(text, original) || mapping[original] == original {
			t.Errorf("original token %q collided with replacement: output=%q mapping=%v", original, text, mapping)
		}
	}
}

func TestScrub_NumberMetadataPlaceholderAvoidsAllRawNumberTokens(t *testing.T) {
	s := sanitize.NewWithMetadata(nil, []string{"123456789012", "987654321098"}, []string{"111111111111"}, nil, "")
	got, mapping := s.Scrub(map[string]any{"projectNumbers": []any{"123456789012", "987654321098"}, "organizationId": "111111111111"})
	text := fmt.Sprint(got)
	for _, original := range []string{"123456789012", "987654321098", "111111111111"} {
		if strings.Contains(text, original) || mapping[original] == original {
			t.Errorf("original number %q remains: output=%q mapping=%v", original, text, mapping)
		}
	}
}

func TestScrub_ExhaustedNamedFallbackUsesCollisionFreeTerminal(t *testing.T) {
	got, mapping := sanitize.New([]string{"example-prod", "sanitized-project"}).Scrub("example-prod sanitized-project")
	text := fmt.Sprint(got)
	if strings.Contains(text, "example-prod") || strings.Contains(text, "sanitized-project") {
		t.Fatalf("terminal fallback leaked an original: output=%q mapping=%v", text, mapping)
	}
	if !strings.Contains(mapping["example-prod"], "[SANITIZED-project]") || !strings.Contains(mapping["sanitized-project"], "[SANITIZED-project]") {
		t.Fatalf("terminal fallback is not explicit in mapping: %v", mapping)
	}
}
