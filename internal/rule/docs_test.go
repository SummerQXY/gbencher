package rule_test

import (
	"os"
	"strings"
	"testing"
)

func TestDSLDocHasNoDrift(t *testing.T) {
	data, err := os.ReadFile("../../docs/rule-dsl.md")
	if err != nil {
		t.Fatalf("read docs/rule-dsl.md: %v", err)
	}
	text := string(data)
	lines := strings.Split(text, "\n")

	// No node_exec collector table rows, examples, or sections.
	for i, line := range lines {
		if strings.Contains(line, "node_exec") {
			t.Errorf("line %d: contains node_exec: %q", i+1, line)
		}
	}

	// The old collector sentence ("gcloud, api, kubectl, node_exec, shell") is gone.
	if strings.Contains(text, "gcloud, api, kubectl, node_exec, shell") {
		t.Error("the old collector sentence with node_exec and shell is still present")
	}
	// The old collector list "gcloud、api、kubectl、node_exec、shell" is gone.
	if strings.Contains(text, "gcloud、api、kubectl、node_exec、shell") {
		t.Error("the old collector list with node_exec and shell is still present")
	}
	// The requires capability list must not contain node-exec or shell.
	for _, cap := range []string{"node-exec", "shell"} {
		if strings.Contains(text, cap) && strings.Contains(text, "能力：") {
			// Only flag if it appears near the capability list context.
			t.Errorf("the doc still mentions %q as a capability", cap)
		}
	}
	// The shell and node_exec collector sections are gone.
	for _, heading := range []string{"### `node_exec`", "### `shell`"} {
		if strings.Contains(text, heading) {
			t.Errorf("the doc still has a %s collector section", heading)
		}
	}

	// The numerical comparison statement includes dyn and no matching overload.
	if !strings.Contains(text, "no matching overload") {
		t.Error("the doc must mention 'no matching overload' for the == cross-type numeric comparison")
	}
	if !strings.Contains(text, "map(string, dyn)") {
		t.Error("the doc variable table must mention map(string, dyn) for data and params")
	}
	// The old wrong sentence ("params、data、r 都是 dyn") is gone.
	if strings.Contains(text, "都是 dyn") {
		t.Error("the old statement that params, data, r are all dyn must be removed")
	}

	// Scarce new terms exist.
	for _, term := range []string{"evaluate_per", "params_constraints", "resource.key", "cross_project", "dsl_version"} {
		if !strings.Contains(text, term) {
			t.Errorf("the doc must mention %q", term)
		}
	}
	if !strings.Contains(text, "ctx.folder") {
		t.Error("the variable table must include ctx.folder")
	}

	// No line claims monitoring policies is alpha.
	for i, line := range lines {
		if strings.Contains(line, "monitoring policies") && strings.Contains(line, "alpha") {
			t.Errorf("line %d: claims monitoring policies is alpha: %q", i+1, line)
		}
	}

	// No reference to docs/rules-catalog.md.
	if strings.Contains(text, "rules-catalog.md") {
		t.Error("the doc must not reference rules-catalog.md")
	}

	// No reference to the old schema path rules/schema/.
	if strings.Contains(text, "rules/schema/") {
		t.Error("the doc must not reference the old rules/schema/ path")
	}
	// Must reference the new schema path schemas/rule.schema.json.
	if !strings.Contains(text, "schemas/rule.schema.json") {
		t.Error("the doc must reference schemas/rule.schema.json")
	}

	// The gcloud verb list points to rules/allowlist.yaml.
	if !strings.Contains(text, "rules/allowlist.yaml") {
		t.Error("the doc must reference rules/allowlist.yaml for the gcloud verb list")
	}
}
