package rule_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/rule"
)

func TestParseProfile_ForbiddenKeyFromSchema(t *testing.T) {
	_, violations, err := rule.ParseProfile([]byte("dsl_version: 1\nexemptions: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) == 0 || !strings.Contains(violations[0].Message, "exemptions") {
		t.Fatalf("violations = %+v, want schema violation for exemptions", violations)
	}
}

func TestParseProfile_RejectsOversizedInput(t *testing.T) {
	data := []byte(strings.Repeat(" ", (1<<20)+1))
	_, _, err := rule.ParseProfile(data)
	if err == nil || !strings.Contains(err.Error(), "yaml-too-large") {
		t.Fatalf("error = %v, want yaml-too-large", err)
	}
}

func TestParseProfile_InvalidYAMLIsError(t *testing.T) {
	_, _, err := rule.ParseProfile([]byte("dsl_version: [1\n"))
	if err == nil || !strings.Contains(err.Error(), "yaml-syntax") {
		t.Fatalf("error = %v, want yaml-syntax", err)
	}
}

func TestParseProfile_UsesRuleYAMLShapeChecks(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{"anchor", "dsl_version: 1\nname: &n sample\n", "yaml-alias"},
		{"alias", "dsl_version: 1\nname: &n sample\ninclude: *n\n", "yaml-alias"},
		{"duplicate key", "dsl_version: 1\nname: a\nname: b\n", "yaml-duplicate-key"},
		{"oversized mapping", "dsl_version: 1\noverrides: {" + strings.Repeat("x: {},", 1000) + "last: {}}\n", "yaml-too-large"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := rule.ParseProfile([]byte(tc.data))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %s", err, tc.want)
			}
		})
	}
}

func TestLoadProfile_ReadsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.yaml")
	if err := os.WriteFile(path, []byte("dsl_version: 1\nname: local\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p, violations, err := rule.LoadProfile(path)
	if err != nil || len(violations) != 0 || p == nil || p.Name != "local" {
		t.Fatalf("profile=%+v violations=%+v err=%v", p, violations, err)
	}
}

func TestLoadProfile_ReadsStdin(t *testing.T) {
	old := os.Stdin
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("dsl_version: 1\nname: stdin\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdin = reader
	t.Cleanup(func() {
		os.Stdin = old
		_ = reader.Close()
	})
	p, violations, err := rule.LoadProfile("-")
	if err != nil || len(violations) != 0 || p == nil || p.Name != "stdin" {
		t.Fatalf("profile=%+v violations=%+v err=%v", p, violations, err)
	}
}
