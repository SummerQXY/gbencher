// Package rule defines the rule model and loads rule files: it parses the YAML, checks it
// against the rule schema, and assembles the rules into a hashed set.
package rule

// Benchmark identifies the baseline a rule file belongs to. It comes from the file header.
type Benchmark struct {
	ID      string `yaml:"id"`
	Version string `yaml:"version"`
	Section string `yaml:"section"`
	Title   string `yaml:"title"`
}

// Rule is one check: what to collect, what to evaluate, and the text that explains it. Its
// fields mirror the rule schema; docs/rule-dsl.md describes their meaning. Values in Params
// are as YAML decodes them: int, float64, bool, string, []any and map[string]any.
type Rule struct {
	ID            string `yaml:"id"`
	Ref           string `yaml:"ref"`
	Title         string `yaml:"title"`
	Profile       string `yaml:"profile"`
	CISAssessment string `yaml:"cis_assessment"`
	Mode          string `yaml:"mode"`
	Severity      string `yaml:"severity"`
	Scope         string `yaml:"scope"`
	EvaluatePer   string `yaml:"evaluate_per"`

	Services   []string `yaml:"services"`
	Requires   []string `yaml:"requires"`
	References []string `yaml:"references"`
	Tags       []string `yaml:"tags"`

	Collect           []Step                     `yaml:"collect"`
	Resource          *Resource                  `yaml:"resource"` // nil for an aggregate rule
	Params            map[string]any             `yaml:"params"`
	ParamsConstraints map[string]ParamConstraint `yaml:"params_constraints"`
	Check             Check                      `yaml:"check"`
	Evidence          []string                   `yaml:"evidence"`
	Remediation       string                     `yaml:"remediation"`
	Notes             string                     `yaml:"notes"`

	// The loader fills these in. They are never read from the file itself.
	Benchmark  Benchmark `yaml:"-"`
	SourceFile string    `yaml:"-"` // path relative to the loaded root, with forward slashes
	Hash       string    `yaml:"-"` // "sha256:" and 64 hex digits over the rule's content, see ParseFile
}

// Step is one entry of a rule's collect list. Exactly one of Gcloud, API and Kubectl is set
// in a valid rule.
type Step struct {
	ID      string `yaml:"id"`
	Gcloud  string `yaml:"gcloud"`
	Kubectl string `yaml:"kubectl"`
	Foreach string `yaml:"foreach"`
	As      string `yaml:"as"`
	Attach  string `yaml:"attach"`
	Parse   string `yaml:"parse"`
	OnError string `yaml:"on_error"`

	API          *APIStep `yaml:"api"`
	Requires     []string `yaml:"requires"`
	CrossProject bool     `yaml:"cross_project"`
}

// APIStep is the REST form of a collect step.
type APIStep struct {
	Method    string         `yaml:"method"`
	URL       string         `yaml:"url"`
	ListField string         `yaml:"list_field"`
	Paginate  bool           `yaml:"paginate"`
	Scopes    []string       `yaml:"scopes"`
	Body      map[string]any `yaml:"body"`
}

// Resource says how a rule expands into the resources it checks.
type Resource struct {
	From   string `yaml:"from"`
	Filter string `yaml:"filter"`
	Name   string `yaml:"name"`
	Key    string `yaml:"key"`
	Kind   string `yaml:"kind"`
	Empty  string `yaml:"empty"`
}

// Check holds the CEL expressions that decide a status and the messages that explain it.
type Check struct {
	Assert        string `yaml:"assert"`
	ReviewWhen    string `yaml:"review_when"`
	Message       string `yaml:"message"`
	ReviewMessage string `yaml:"review_message"`
}

// ParamConstraint limits the values a parameter may take. A field left nil or empty places
// no limit.
type ParamConstraint struct {
	Pattern   string   `yaml:"pattern"`
	Minimum   *float64 `yaml:"minimum"`
	Maximum   *float64 `yaml:"maximum"`
	Enum      []any    `yaml:"enum"`
	MaxLength *int     `yaml:"max_length"`
}

// File is one parsed rule file.
type File struct {
	Name       string // path relative to the loaded root, with forward slashes
	DSLVersion int
	Benchmark  Benchmark
	Rules      []*Rule
}

// Violation is one problem found in a rule file: a schema violation, a file that cannot be
// parsed, or a rule id that is already taken.
type Violation struct {
	File string
	// Path is a JSON Pointer to the offending value, such as /rules/0/ref, and is empty when
	// the problem concerns the whole file.
	Path    string
	Message string
}

// Set is the complete collection of loaded rules.
type Set struct {
	Rules  []*Rule // ordered by ID, compared as plain strings
	Hash   string  // sha256 over the ids and content hashes of all rules, independent of file layout
	Source string  // "embedded" or "external"
}

// Get returns the rule with the given id. The set is small, and a Set can be built by hand,
// so this is a plain scan rather than a lookup that relies on how Rules is ordered.
func (s *Set) Get(id string) (*Rule, bool) {
	for _, r := range s.Rules {
		if r.ID == id {
			return r, true
		}
	}
	return nil, false
}
