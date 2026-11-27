package rule_test

import (
	"os"
	"testing"

	"github.com/SummerQXY/gbencher/profiles"
	"github.com/SummerQXY/gbencher/schemas"
)

func TestProfilesValidate(t *testing.T) {
	// Default profile embedded in the binary.
	if err := schemas.ValidateYAML("profile", profiles.Default); err != nil {
		t.Errorf("profiles/default.yaml: %v", err)
	}

	// Example profile.
	example, err := os.ReadFile("../../profiles/examples/acme-prod.yaml")
	if err != nil {
		t.Fatalf("read acme-prod.yaml: %v", err)
	}
	if err := schemas.ValidateYAML("profile", example); err != nil {
		t.Errorf("profiles/examples/acme-prod.yaml: %v", err)
	}
}
