package rule

import (
	"fmt"
	"io"
	"os"

	"github.com/SummerQXY/gbencher/schemas"
)

// Profile selects rules and supplies parameter overrides.
type Profile struct {
	DSLVersion int                 `yaml:"dsl_version"`
	Name       string              `yaml:"name"`
	Benchmarks []string            `yaml:"benchmarks"`
	Levels     []string            `yaml:"levels"`
	Include    []string            `yaml:"include"`
	Exclude    []string            `yaml:"exclude"`
	Overrides  map[string]Override `yaml:"overrides"`
}

// Override contains profile values for one rule.
type Override struct {
	Params map[string]any `yaml:"params"`
}

// ParseProfile parses one JSON or YAML profile and reports schema violations separately from
// syntax and resource-limit errors.
func ParseProfile(data []byte) (*Profile, []Violation, error) {
	doc, err := parseChecked(data)
	if err != nil {
		return nil, nil, err
	}

	var generic any
	if doc.Kind != 0 {
		if err := doc.Decode(&generic); err != nil {
			return nil, nil, fmt.Errorf("yaml-syntax: %s", err)
		}
	}
	violations := profileSchemaViolations(data, generic)
	profile := &Profile{}
	if doc.Kind != 0 {
		_ = doc.Decode(profile)
	}
	return profile, violations, nil
}

func profileSchemaViolations(data []byte, generic any) []Violation {
	if _, ok := generic.(map[string]any); !ok && len(data) > 0 {
		return []Violation{{File: "profile", Message: "profile must be a mapping"}}
	}
	err := schemas.ValidateYAML("profile", data)
	if err == nil {
		return nil
	}
	issues := schemas.Issues(err)
	if len(issues) == 0 {
		return []Violation{{File: "profile", Message: err.Error()}}
	}
	out := make([]Violation, len(issues))
	for i, issue := range issues {
		out[i] = Violation{File: "profile", Path: issue.Path, Message: issue.Message}
	}
	return out
}

// LoadProfile reads and parses a profile, stopping one byte past the size limit.
func LoadProfile(path string) (*Profile, []Violation, error) {
	var reader io.Reader
	if path == "-" {
		reader = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, fmt.Errorf("open profile: %w", err)
		}
		defer f.Close()
		reader = f
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxFileBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read profile: %w", err)
	}
	return ParseProfile(data)
}
