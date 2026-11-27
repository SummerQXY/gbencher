package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/rule"
)

type dryRunPlan struct {
	SchemaVersion string       `json:"schema_version"`
	RulesetHash   string       `json:"ruleset_hash"`
	Units         []dryRunUnit `json:"units"`
}

type dryRunUnit struct {
	RuleID                 string          `json:"rule_id"`
	Target                 string          `json:"target"`
	TargetStatus           string          `json:"target_status"`
	Requires               []string        `json:"requires"`
	CapabilitySatisfied    bool            `json:"capability_satisfied"`
	MissingCapabilities    []string        `json:"missing_capabilities"`
	Commands               []dryRunCommand `json:"commands"`
	CommandCountLowerBound int             `json:"command_count_lower_bound"`
	CommandCountBasis      string          `json:"command_count_basis"`
}

type dryRunCommand struct {
	StepID   string   `json:"step_id"`
	Type     string   `json:"type"`
	Argv     []string `json:"argv,omitempty"`
	Method   string   `json:"method,omitempty"`
	URL      string   `json:"url,omitempty"`
	Template string   `json:"template,omitempty"`
}

func writeDryRun(set *rule.Set, selected []*rule.Rule, projects, enables []string, format string, stdout, stderr io.Writer) int {
	if format != "json" && format != "table" {
		return scanError(stderr, 2, "--format must be table or json", false)
	}
	capabilities := make(map[string]bool, len(enables))
	for _, capability := range enables {
		capabilities[capability] = true
	}
	plan := dryRunPlan{SchemaVersion: "1.0", RulesetHash: set.Hash, Units: make([]dryRunUnit, 0)}
	seen := make(map[string]bool)
	for _, current := range selected {
		for _, project := range projects {
			target := "projects/" + project
			targetStatus := "known"
			if current.Scope == "organization" && current.EvaluatePer != "project" {
				target = "organizations/unresolved-for-projects/" + project
				targetStatus = "requires_organization_lookup"
			} else if current.Scope == "cluster" {
				targetStatus = "requires_cluster_enumeration"
			}
			key := current.ID + "\x00" + target
			if seen[key] {
				continue
			}
			seen[key] = true
			unit := dryRunUnit{RuleID: current.ID, Target: target, TargetStatus: targetStatus, Requires: append([]string{}, current.Requires...), MissingCapabilities: []string{}, CapabilitySatisfied: true, Commands: []dryRunCommand{}}
			staticCommandCount := 0
			for _, required := range current.Requires {
				if !capabilities[required] || required == "org-access" {
					unit.CapabilitySatisfied = false
					unit.MissingCapabilities = append(unit.MissingCapabilities, required)
				}
			}
			values := map[string]any{"project": project, "project_id": project, "params": current.Params, "ctx": map[string]any{"project": project, "project_id": project}}
			for _, step := range current.Collect {
				if step.Gcloud == "" && step.Kubectl == "" && step.API == nil {
					continue
				}
				for _, required := range step.Requires {
					if !capabilities[required] {
						unit.CapabilitySatisfied = false
						unit.MissingCapabilities = appendUnique(unit.MissingCapabilities, required)
					}
				}
				command, rendered := makeDryRunCommand(step, values)
				command.StepID = step.ID
				unit.Commands = append(unit.Commands, command)
				if rendered {
					staticCommandCount++
				}
			}
			switch {
			case !unit.CapabilitySatisfied:
				unit.CommandCountBasis = "capability_gap"
			case targetStatus != "known":
				unit.CommandCountBasis = "target_unresolved"
			case len(current.Services) != 0:
				unit.CommandCountBasis = "service_precheck_unknown"
			default:
				unit.CommandCountLowerBound = staticCommandCount
				unit.CommandCountBasis = "assuming_scan_preflight_succeeds"
			}
			sort.Strings(unit.MissingCapabilities)
			plan.Units = append(plan.Units, unit)
		}
	}
	if format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(plan); err != nil {
			return scanError(stderr, 3, "write dry-run plan: "+err.Error(), false)
		}
		return 0
	}
	for _, unit := range plan.Units {
		status := "satisfied"
		if !unit.CapabilitySatisfied {
			status = "missing: " + strings.Join(unit.MissingCapabilities, ",")
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%d command(s) minimum (%s)\n", unit.RuleID, unit.Target, status, unit.CommandCountLowerBound, unit.CommandCountBasis)
		for _, command := range unit.Commands {
			if command.Method != "" {
				if command.URL != "" {
					fmt.Fprintf(stdout, "  %s %s %s\n", command.Type, command.Method, command.URL)
				} else {
					fmt.Fprintf(stdout, "  %s template: %s\n", command.Type, command.Template)
				}
				continue
			}
			if len(command.Argv) > 0 {
				fmt.Fprintf(stdout, "  %s %s\n", command.Type, strings.Join(command.Argv, " "))
			} else {
				fmt.Fprintf(stdout, "  %s template: %s\n", command.Type, command.Template)
			}
		}
	}
	return 0
}

func makeDryRunCommand(step rule.Step, values map[string]any) (dryRunCommand, bool) {
	switch {
	case step.API != nil:
		template := step.API.Method + " " + step.API.URL
		command := dryRunCommand{Type: "rest", Method: step.API.Method}
		if step.Foreach != "" || strings.Contains(step.API.URL, "data.") {
			command.Template = template
			return command, false
		}
		url, err := collect.RenderURL(step.API.URL, values)
		if err != nil {
			command.Template = template
			return command, false
		}
		command.URL = url
		return command, true
	case step.Kubectl != "":
		return makeArgvDryRunCommand("kubectl", step, step.Kubectl, values)
	case step.Gcloud != "":
		return makeArgvDryRunCommand("gcloud", step, step.Gcloud, values)
	default:
		return dryRunCommand{}, false
	}
}

func makeArgvDryRunCommand(kind string, step rule.Step, template string, values map[string]any) (dryRunCommand, bool) {
	if step.Foreach != "" || strings.Contains(template, "data.") {
		return dryRunCommand{Type: kind, Template: template}, false
	}
	argv, err := collect.RenderArgv(template, values)
	if err != nil {
		return dryRunCommand{Type: kind, Template: template}, false
	}
	return dryRunCommand{Type: kind, Argv: argv}, true
}

func appendUnique(values []string, value string) []string {
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}
