// Package fixture loads offline rule inputs and evaluates their expected outcomes.
package fixture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/eval"
	"github.com/SummerQXY/gbencher/internal/failure"
	"github.com/SummerQXY/gbencher/internal/plan"
	"github.com/SummerQXY/gbencher/internal/rule"
)

type Target struct {
	Type               string `json:"type"`
	ProjectID          string `json:"project_id"`
	ProjectNumber      string `json:"project_number"`
	Organization       string `json:"organization"`
	OrganizationDomain string `json:"organization_domain"`
	Folder             string `json:"folder"`
	ClusterName        string `json:"cluster_name"`
	ClusterLocation    string `json:"cluster_location"`
}

type Case struct {
	Target           Target
	Cluster          map[string]any
	Params           map[string]any
	Data             map[string]any
	Now              time.Time
	Expect           []Expect
	Meta             Meta
	DisabledServices []string
	CollectionErrors map[string]string
}

type Expect struct {
	RuleID      string `json:"rule_id"`
	ResourceKey string `json:"resource_key"`
	Status      string `json:"status"`
}

type Meta struct {
	Provenance map[string]string `json:"provenance"`
}

// LoadDir loads all JSON cases in a directory in filename order.
func LoadDir(dir string) ([]Case, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read fixture directory %s: %w", dir, err)
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		paths = append(paths, filepath.Join(dir, entry.Name()))
	}
	sort.Strings(paths)
	cases := make([]Case, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read fixture %s: %w", path, err)
		}
		current, err := decodeCase(data)
		if err != nil {
			return nil, fmt.Errorf("fixture %s: %w", path, err)
		}
		cases = append(cases, current)
	}
	return cases, nil
}

func decodeCase(raw []byte) (Case, error) {
	decoded, err := collect.DecodeJSON(raw)
	if err != nil {
		return Case{}, fmt.Errorf("decode JSON: %w", err)
	}
	top, ok := decoded.(map[string]any)
	if !ok {
		return Case{}, fmt.Errorf("fixture must be a JSON object")
	}
	if err := rejectKeys(top, "target", "cluster", "params", "data", "now", "expect", "meta", "disabled_services", "collection_errors"); err != nil {
		return Case{}, err
	}
	for _, key := range []string{"target", "data", "expect", "meta"} {
		if _, ok := top[key]; !ok {
			return Case{}, fmt.Errorf("missing required key %q", key)
		}
	}
	var result Case
	{
		value := top["target"]
		m, ok := value.(map[string]any)
		if !ok {
			return Case{}, fmt.Errorf("target must be an object")
		}
		if err := rejectKeys(m, "type", "project_id", "project_number", "organization", "organization_domain", "folder", "cluster_name", "cluster_location"); err != nil {
			return Case{}, fmt.Errorf("target: %w", err)
		}
		if result.Target, err = decodeTarget(m); err != nil {
			return Case{}, err
		}
		if result.Target.Type == "" {
			return Case{}, fmt.Errorf("target.type is required")
		}
	}
	if result.Cluster, err = optionalMap(top, "cluster"); err != nil {
		return Case{}, err
	}
	if result.Params, err = optionalMap(top, "params"); err != nil {
		return Case{}, err
	}
	if result.Data, err = optionalMap(top, "data"); err != nil {
		return Case{}, err
	}
	if value, exists := top["now"]; exists {
		text, ok := value.(string)
		if !ok {
			return Case{}, fmt.Errorf("now must be an RFC 3339 timestamp string")
		}
		result.Now, err = time.Parse(time.RFC3339Nano, text)
		if err != nil {
			return Case{}, fmt.Errorf("now must be an RFC 3339 timestamp string: %w", err)
		}
	}
	if result.DisabledServices, err = optionalStringSlice(top, "disabled_services"); err != nil {
		return Case{}, err
	}
	if result.CollectionErrors, err = optionalStringMap(top, "collection_errors"); err != nil {
		return Case{}, err
	}
	{
		value := top["expect"]
		items, ok := value.([]any)
		if !ok {
			return Case{}, fmt.Errorf("expect must be an array")
		}
		if len(items) == 0 {
			return Case{}, fmt.Errorf("expect must not be empty")
		}
		for i, item := range items {
			m, ok := item.(map[string]any)
			if !ok {
				return Case{}, fmt.Errorf("expect[%d] must be an object", i)
			}
			if err := rejectKeys(m, "rule_id", "resource_key", "status"); err != nil {
				return Case{}, fmt.Errorf("expect[%d]: %w", i, err)
			}
			expect, err := decodeExpect(m)
			if err != nil {
				return Case{}, fmt.Errorf("expect[%d]: %w", i, err)
			}
			if expect.RuleID == "" || expect.ResourceKey == "" || expect.Status == "" {
				return Case{}, fmt.Errorf("expect[%d] requires rule_id, resource_key, and status", i)
			}
			switch expect.Status {
			case "PASS", "FAIL", "REVIEW", "NOT_APPLICABLE", "SKIPPED", "ERROR":
			default:
				return Case{}, fmt.Errorf("expect[%d].status has invalid value %q", i, expect.Status)
			}
			result.Expect = append(result.Expect, expect)
		}
	}
	{
		value := top["meta"]
		m, ok := value.(map[string]any)
		if !ok {
			return Case{}, fmt.Errorf("meta must be an object")
		}
		if err := rejectKeys(m, "provenance"); err != nil {
			return Case{}, fmt.Errorf("meta: %w", err)
		}
		provenance, ok := m["provenance"].(map[string]any)
		if !ok {
			return Case{}, fmt.Errorf("meta.provenance must be an object")
		}
		result.Meta.Provenance = make(map[string]string, len(provenance))
		steps := make([]string, 0, len(provenance))
		for step := range provenance {
			steps = append(steps, step)
		}
		sort.Strings(steps)
		for _, step := range steps {
			source := provenance[step]
			text, ok := source.(string)
			if !ok {
				return Case{}, fmt.Errorf("meta.provenance.%s must be a string", step)
			}
			switch text {
			case "captured", "captured+mutated", "schema", "handwritten":
			default:
				return Case{}, fmt.Errorf("meta.provenance.%s has invalid value %q", step, text)
			}
			result.Meta.Provenance[step] = text
		}
	}
	return result, nil
}

func decodeTarget(value map[string]any) (Target, error) {
	var result Target
	fields := []struct {
		name        string
		destination *string
	}{
		{"type", &result.Type}, {"project_id", &result.ProjectID}, {"project_number", &result.ProjectNumber},
		{"organization", &result.Organization}, {"organization_domain", &result.OrganizationDomain},
		{"folder", &result.Folder}, {"cluster_name", &result.ClusterName}, {"cluster_location", &result.ClusterLocation},
	}
	for _, field := range fields {
		if item, exists := value[field.name]; exists {
			text, ok := item.(string)
			if !ok {
				return Target{}, fmt.Errorf("target.%s must be a string", field.name)
			}
			*field.destination = text
		}
	}
	return result, nil
}

func decodeExpect(value map[string]any) (Expect, error) {
	var result Expect
	fields := []struct {
		name        string
		destination *string
	}{{"rule_id", &result.RuleID}, {"resource_key", &result.ResourceKey}, {"status", &result.Status}}
	for _, field := range fields {
		if item, exists := value[field.name]; exists {
			text, ok := item.(string)
			if !ok {
				return Expect{}, fmt.Errorf("%s must be a string", field.name)
			}
			*field.destination = text
		}
	}
	return result, nil
}

func optionalMap(values map[string]any, key string) (map[string]any, error) {
	value, ok := values[key]
	if !ok || value == nil {
		return map[string]any{}, nil
	}
	result, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", key)
	}
	return result, nil
}

func optionalStringSlice(values map[string]any, key string) ([]string, error) {
	value, exists := values[key]
	if !exists || value == nil {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", key)
	}
	result := make([]string, 0, len(items))
	for i, item := range items {
		text, ok := item.(string)
		if !ok || text == "" {
			return nil, fmt.Errorf("%s[%d] must be a non-empty string", key, i)
		}
		result = append(result, text)
	}
	return result, nil
}

func optionalStringMap(values map[string]any, key string) (map[string]string, error) {
	value, exists := values[key]
	if !exists || value == nil {
		return nil, nil
	}
	items, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", key)
	}
	result := make(map[string]string, len(items))
	for step, item := range items {
		text, ok := item.(string)
		if !ok || text == "" {
			return nil, fmt.Errorf("%s.%s must be a non-empty string", key, step)
		}
		result[step] = text
	}
	return result, nil
}

func rejectKeys(values map[string]any, allowed ...string) error {
	known := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		known[key] = struct{}{}
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, ok := known[key]; !ok {
			return fmt.Errorf("unknown key %q", key)
		}
	}
	return nil
}

// Evaluate applies a rule to the fixture's already-collected data without running collectors.
func Evaluate(c Case, r *rule.Rule) ([]Expect, error) {
	env, err := eval.NewEnv()
	if err != nil {
		return nil, fmt.Errorf("create evaluation environment: %w", err)
	}
	return EvaluateWithEnv(c, r, env)
}

// EvaluateWithEnv applies a rule to fixture data using the supplied environment.
func EvaluateWithEnv(c Case, r *rule.Rule, env *eval.Env) ([]Expect, error) {
	if r == nil {
		return nil, fmt.Errorf("rule is nil")
	}
	if env == nil {
		return nil, fmt.Errorf("evaluation environment is nil")
	}
	if len(c.DisabledServices) > 0 {
		declared := make(map[string]bool, len(r.Services))
		enabled := make(map[string]bool, len(r.Services))
		for _, service := range r.Services {
			declared[service] = true
			enabled[service] = true
		}
		for _, service := range c.DisabledServices {
			if !declared[service] {
				return nil, fmt.Errorf("disabled service %q is not declared by rule %s", service, r.ID)
			}
			enabled[service] = false
		}
		missing := eval.ServicesMissing(r.Services, enabled)
		if len(missing) == 0 {
			return nil, fmt.Errorf("disabled_services does not disable a declared service for rule %s", r.ID)
		}
		if len(c.Data) > 0 || len(c.CollectionErrors) > 0 {
			return nil, fmt.Errorf("service-disabled fixture for %s must not include collected data", r.ID)
		}
		key := fixtureTargetKey(c.Target)
		return []Expect{{RuleID: r.ID, ResourceKey: key, Status: "NOT_APPLICABLE"}}, nil
	}
	data := eval.NewData()
	for step, value := range c.Data {
		data.Set(step, value)
	}
	for stepID, class := range c.CollectionErrors {
		step, ok := fixtureStep(r, stepID)
		if !ok {
			return nil, fmt.Errorf("collection error references unknown step %q", stepID)
		}
		if class != "service_disabled" {
			return nil, fmt.Errorf("collection error for %s.%s has unsupported class %q", r.ID, stepID, class)
		}
		if step.Foreach != "" {
			return nil, fmt.Errorf("collection error for %s.%s cannot simulate a foreach step", r.ID, stepID)
		}
		if eval.Decide(&failure.Failure{Class: failure.ServiceDisabled}, step.OnError).Action != eval.ActionEmpty {
			return nil, fmt.Errorf("collection error for %s.%s does not produce an empty result", r.ID, stepID)
		}
		if _, exists := c.Data[stepID]; exists {
			return nil, fmt.Errorf("collection error for %s.%s cannot include collected data", r.ID, stepID)
		}
		data.Set(stepID, eval.EmptyValueForStep(step))
	}
	params, err := rule.ApplyParams(r, c.Params)
	if err != nil {
		return nil, fmt.Errorf("apply fixture params: %w", err)
	}
	key := ""
	switch c.Target.Type {
	case "project":
		key = "projects/" + c.Target.ProjectID
	case "organization":
		key = "organizations/" + c.Target.Organization
	case "cluster":
		key = fmt.Sprintf("projects/%s/locations/%s/clusters/%s", c.Target.ProjectID, c.Target.ClusterLocation, c.Target.ClusterName)
	}
	target := plan.Target{Type: c.Target.Type, Key: key, ProjectID: c.Target.ProjectID, Organization: c.Target.Organization, Folder: c.Target.Folder, ClusterName: c.Target.ClusterName, ClusterLocation: c.Target.ClusterLocation, Cluster: c.Cluster}
	contextValue := eval.Context{Project: c.Target.ProjectID, ProjectNumber: c.Target.ProjectNumber, Organization: c.Target.Organization, OrganizationDomain: c.Target.OrganizationDomain, Cluster: c.Cluster, Now: c.Now, TargetKey: target.Key, TargetKind: target.Kind()}
	expanded, err := eval.ExpandResources(context.Background(), env, r, data, contextValue, params)
	if err != nil {
		return nil, fmt.Errorf("expand resources: %w", err)
	}
	if expanded.Empty {
		status := "NOT_APPLICABLE"
		if r.Resource != nil && r.Resource.Empty == "pass" {
			status = "PASS"
		}
		return []Expect{{RuleID: r.ID, ResourceKey: target.Key, Status: status}}, nil
	}
	results := make([]Expect, 0, len(expanded.Instances))
	for _, instance := range expanded.Instances {
		assessment, _, err := eval.Assess(context.Background(), env, r, &instance, data, contextValue, params)
		if err != nil {
			return nil, fmt.Errorf("evaluate resource %s: %w", instance.Key, err)
		}
		results = append(results, Expect{RuleID: r.ID, ResourceKey: instance.Key, Status: assessment.Status})
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].ResourceKey != results[j].ResourceKey {
			return results[i].ResourceKey < results[j].ResourceKey
		}
		if results[i].RuleID != results[j].RuleID {
			return results[i].RuleID < results[j].RuleID
		}
		return results[i].Status < results[j].Status
	})
	return results, nil
}

func fixtureTargetKey(target Target) string {
	switch target.Type {
	case "project":
		return "projects/" + target.ProjectID
	case "organization":
		return "organizations/" + target.Organization
	case "cluster":
		return fmt.Sprintf("projects/%s/locations/%s/clusters/%s", target.ProjectID, target.ClusterLocation, target.ClusterName)
	default:
		return ""
	}
}

func fixtureStep(r *rule.Rule, id string) (rule.Step, bool) {
	for _, step := range r.Collect {
		if step.ID == id {
			return step, true
		}
	}
	return rule.Step{}, false
}
