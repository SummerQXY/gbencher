package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"slices"
	"text/tabwriter"

	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/spf13/cobra"
)

type catalog struct {
	SchemaVersion string        `json:"schema_version"`
	RulesetHash   string        `json:"ruleset_hash"`
	Rules         []catalogRule `json:"rules"`
}

type catalogSection struct {
	ID    string `json:"id,omitempty"`
	Title string `json:"title,omitempty"`
}

type catalogParam struct {
	Default any    `json:"default"`
	Type    string `json:"type"`
}

type catalogConstraint struct {
	Pattern   string   `json:"pattern,omitempty"`
	Minimum   *float64 `json:"minimum,omitempty"`
	Maximum   *float64 `json:"maximum,omitempty"`
	Enum      []any    `json:"enum,omitempty"`
	MaxLength *int     `json:"max_length,omitempty"`
}

type catalogBenchmark struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type catalogRule struct {
	ID                string                       `json:"id"`
	Ref               string                       `json:"ref"`
	Title             string                       `json:"title"`
	Benchmark         catalogBenchmark             `json:"benchmark"`
	Section           *catalogSection              `json:"section,omitempty"`
	Profile           string                       `json:"profile"`
	CISAssessment     string                       `json:"cis_assessment"`
	Mode              string                       `json:"mode"`
	Severity          string                       `json:"severity"`
	Scope             string                       `json:"scope"`
	EvaluatePer       string                       `json:"evaluate_per,omitempty"`
	Services          []string                     `json:"services"`
	Requires          []string                     `json:"requires"`
	Params            map[string]catalogParam      `json:"params"`
	ParamsConstraints map[string]catalogConstraint `json:"params_constraints,omitempty"`
	Verification      rule.VerificationLevel       `json:"verification"`
	Remediation       string                       `json:"remediation"`
	References        []string                     `json:"references"`
	Notes             string                       `json:"notes"`
}

func rulesListCmd(stdout, stderr io.Writer) *cobra.Command {
	format := "table"
	var benchmarks, levels, modes, scopes, verifications []string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List rules in the embedded catalog",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "table" && format != "json" {
				return fmt.Errorf("--format must be table or json")
			}
			set, err := rule.LoadEmbedded()
			if err != nil {
				return err
			}
			verification, err := rule.LoadVerification()
			if err != nil {
				return err
			}
			cat := makeCatalog(set, verification)
			cat, err = filterCatalog(cat, benchmarks, levels, modes, scopes, verifications)
			if err != nil {
				return err
			}
			if format == "json" {
				encoder := json.NewEncoder(stdout)
				encoder.SetEscapeHTML(false)
				return encoder.Encode(cat)
			}
			w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tREF\tSCOPE\tLEVEL\tVERIFICATION\tTITLE")
			for _, current := range cat.Rules {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", current.ID, current.Ref, current.Scope, current.Profile, current.Verification, current.Title)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table or json")
	cmd.Flags().StringArrayVar(&benchmarks, "benchmark", nil, "Filter by benchmark ID or ID@version; repeat to include multiple benchmarks")
	cmd.Flags().StringArrayVar(&levels, "level", nil, "Filter by rule level: L1 or L2")
	cmd.Flags().StringArrayVar(&modes, "mode", nil, "Filter by mode: deterministic or contextual")
	cmd.Flags().StringArrayVar(&scopes, "scope", nil, "Filter by scope: project, organization or cluster")
	cmd.Flags().StringArrayVar(&verifications, "verification", nil, "Filter by verification: none, static, fixture or live")
	return cmd
}

func filterCatalog(cat catalog, benchmarks, levels, modes, scopes, verifications []string) (catalog, error) {
	for _, level := range levels {
		if level != "L1" && level != "L2" {
			return catalog{}, fmt.Errorf("--level must be L1 or L2")
		}
	}
	for _, mode := range modes {
		if mode != "deterministic" && mode != "contextual" {
			return catalog{}, fmt.Errorf("--mode must be deterministic or contextual")
		}
	}
	for _, scope := range scopes {
		if scope != "project" && scope != "organization" && scope != "cluster" {
			return catalog{}, fmt.Errorf("--scope must be project, organization or cluster")
		}
	}
	for _, verification := range verifications {
		if verification != "none" && verification != "static" && verification != "fixture" && verification != "live" {
			return catalog{}, fmt.Errorf("--verification must be none, static, fixture or live")
		}
	}
	knownBenchmarks := make(map[string]bool)
	for _, current := range cat.Rules {
		knownBenchmarks[current.Benchmark.ID] = true
		knownBenchmarks[current.Benchmark.ID+"@"+current.Benchmark.Version] = true
	}
	for _, benchmark := range benchmarks {
		if !knownBenchmarks[benchmark] {
			return catalog{}, fmt.Errorf("unknown benchmark %q", benchmark)
		}
	}
	filtered := make([]catalogRule, 0, len(cat.Rules))
	for _, current := range cat.Rules {
		benchmark := current.Benchmark.ID + "@" + current.Benchmark.Version
		if len(benchmarks) != 0 && !containsAny(benchmarks, current.Benchmark.ID, benchmark) {
			continue
		}
		if len(levels) != 0 && !slices.Contains(levels, current.Profile) {
			continue
		}
		if len(modes) != 0 && !slices.Contains(modes, current.Mode) {
			continue
		}
		if len(scopes) != 0 && !slices.Contains(scopes, current.Scope) {
			continue
		}
		if len(verifications) != 0 && !containsAny(verifications, string(current.Verification)) {
			continue
		}
		filtered = append(filtered, current)
	}
	cat.Rules = filtered
	return cat, nil
}

func containsAny(options []string, values ...string) bool {
	for _, option := range options {
		for _, value := range values {
			if option == value {
				return true
			}
		}
	}
	return false
}

func makeCatalog(set *rule.Set, verification *rule.Verification) catalog {
	out := catalog{SchemaVersion: "1.0", RulesetHash: set.Hash, Rules: make([]catalogRule, 0, len(set.Rules))}
	for _, r := range set.Rules {
		if r == nil {
			continue
		}
		params := make(map[string]catalogParam, len(r.Params))
		for name, value := range r.Params {
			params[name] = catalogParam{Default: value, Type: catalogParamType(value)}
		}
		level := rule.VerificationNone
		if verification != nil {
			if stored, ok := verification.Rules[r.ID]; ok {
				level = stored
			}
		}
		constraints := make(map[string]catalogConstraint, len(r.ParamsConstraints))
		for name, constraint := range r.ParamsConstraints {
			constraints[name] = catalogConstraint{Pattern: constraint.Pattern, Minimum: constraint.Minimum, Maximum: constraint.Maximum, Enum: constraint.Enum, MaxLength: constraint.MaxLength}
		}
		current := catalogRule{ID: r.ID, Ref: r.Ref, Title: r.Title, Benchmark: catalogBenchmark{ID: r.Benchmark.ID, Version: r.Benchmark.Version}, Profile: r.Profile, CISAssessment: r.CISAssessment, Mode: r.Mode, Severity: r.Severity, Scope: r.Scope, EvaluatePer: r.EvaluatePer, Services: nonNil(r.Services), Requires: nonNil(r.Requires), Params: params, ParamsConstraints: constraints, Verification: level, Remediation: r.Remediation, References: nonNil(r.References), Notes: r.Notes}
		if r.Benchmark.Section != "" || r.Benchmark.Title != "" {
			current.Section = &catalogSection{ID: r.Benchmark.Section, Title: r.Benchmark.Title}
		}
		out.Rules = append(out.Rules, current)
	}
	return out
}

func nonNil[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

func catalogParamType(value any) string {
	switch value.(type) {
	case string:
		return "string"
	case bool:
		return "boolean"
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return "integer"
	case float32, float64:
		return "number"
	default:
		kind := reflect.TypeOf(value)
		if kind != nil && kind.Kind() == reflect.Slice {
			return "array"
		}
		return "object"
	}
}
