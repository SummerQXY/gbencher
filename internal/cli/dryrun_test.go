package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/rule"
)

func TestDryRunREST_RendersMethodAndURLWithoutCountingTemplates(t *testing.T) {
	step := rule.Step{ID: "datasets", API: &rule.APIStep{Method: "GET", URL: "https://bigquery.googleapis.com/bigquery/v2/projects/{{ .project }}/datasets"}}
	command, rendered := makeDryRunCommand(step, map[string]any{"project": "example-prod"})
	if !rendered {
		t.Fatal("static REST request was not rendered")
	}
	if command.Method != "GET" || command.URL != "https://bigquery.googleapis.com/bigquery/v2/projects/example-prod/datasets" {
		t.Fatalf("command = %+v", command)
	}
	if command.Template != "" {
		t.Fatalf("static request still has template: %+v", command)
	}

	step.API.URL = "https://bigquery.googleapis.com/bigquery/v2/projects/{{ .data.project }}/datasets"
	command, rendered = makeDryRunCommand(step, map[string]any{"project": "example-prod"})
	if rendered {
		t.Fatal("data-dependent REST request was marked rendered")
	}
	if !strings.Contains(command.Template, "{{ .data.project }}") {
		t.Fatalf("template = %q", command.Template)
	}
}

func TestDryRunREST_CommandLowerBoundCountsOnlyRenderedCalls(t *testing.T) {
	current := &rule.Rule{ID: "example-rule", Scope: "project", Collect: []rule.Step{{ID: "datasets", API: &rule.APIStep{Method: "GET", URL: "https://bigquery.googleapis.com/bigquery/v2/projects/{{ .project }}/datasets"}}}}
	set := &rule.Set{Hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	for _, tc := range []struct {
		url  string
		want int
	}{
		{url: "https://bigquery.googleapis.com/bigquery/v2/projects/{{ .project }}/datasets", want: 1},
		{url: "https://bigquery.googleapis.com/bigquery/v2/projects/{{ .data.project }}/datasets", want: 0},
	} {
		current.Collect[0].API.URL = tc.url
		var out, stderr bytes.Buffer
		if code := writeDryRun(set, []*rule.Rule{current}, []string{"example-prod"}, nil, "json", &out, &stderr); code != 0 {
			t.Fatalf("code=%d stderr=%q", code, stderr.String())
		}
		var got struct {
			Units []struct {
				Commands []dryRunCommand `json:"commands"`
				Count    int             `json:"command_count_lower_bound"`
				Basis    string          `json:"command_count_basis"`
			} `json:"units"`
		}
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Units[0].Count != tc.want {
			t.Errorf("URL %q lower bound = %d, want %d", tc.url, got.Units[0].Count, tc.want)
		}
		if got.Units[0].Commands[0].Template != "" && tc.want == 1 {
			t.Errorf("static REST command retained a template: %+v", got.Units[0].Commands[0])
		}
	}
}

func TestDryRun_LowerBoundIsZeroForUnknownServicesAndTargets(t *testing.T) {
	set := &rule.Set{Hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	cases := []*rule.Rule{
		{ID: "service-checked", Scope: "project", Services: []string{"compute.googleapis.com"}, Collect: []rule.Step{{ID: "instances", Gcloud: "compute instances list"}}},
		{ID: "cluster-target", Scope: "cluster", Collect: []rule.Step{{ID: "pods", Kubectl: "get pods -o json"}}},
	}
	for _, current := range cases {
		var out, stderr bytes.Buffer
		if code := writeDryRun(set, []*rule.Rule{current}, []string{"example-prod"}, []string{"kubectl"}, "json", &out, &stderr); code != 0 {
			t.Fatalf("%s: code=%d stderr=%q", current.ID, code, stderr.String())
		}
		var got struct {
			Units []struct {
				Commands []dryRunCommand `json:"commands"`
				Count    int             `json:"command_count_lower_bound"`
				Basis    string          `json:"command_count_basis"`
			} `json:"units"`
		}
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Units[0].Count != 0 {
			t.Errorf("%s lower bound=%d", current.ID, got.Units[0].Count)
		}
		wantBasis := "service_precheck_unknown"
		if current.Scope == "cluster" {
			wantBasis = "target_unresolved"
		}
		if got.Units[0].Basis != wantBasis {
			t.Errorf("%s count basis=%q, want %q", current.ID, got.Units[0].Basis, wantBasis)
		}
		if len(got.Units[0].Commands) != 1 {
			t.Errorf("%s lost command plan: %+v", current.ID, got.Units[0].Commands)
		}
	}
}
