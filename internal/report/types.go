package report

import "github.com/SummerQXY/gbencher/internal/rule"

type Report struct {
	SchemaVersion string        `json:"schema_version"`
	Scan          Scan          `json:"scan"`
	Summary       Summary       `json:"summary"`
	RuleSummaries []RuleSummary `json:"rule_summaries"`
	Results       []Result      `json:"results"`
	Collectors    []Collector   `json:"collectors"`
	unitsForExit  []UnitRef     `json:"-"`
}

type Scan struct {
	ID          string       `json:"id"`
	StartedAt   string       `json:"started_at"`
	FinishedAt  string       `json:"finished_at"`
	Status      string       `json:"status"`
	Tool        Tool         `json:"tool"`
	Environment Environment  `json:"environment"`
	Identity    Identity     `json:"identity"`
	Targets     []ScanTarget `json:"targets"`
	Selection   Selection    `json:"selection"`
	Coverage    Coverage     `json:"coverage"`
}

type Tool struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	RulesetHash   string `json:"ruleset_hash"`
	RulesetSource string `json:"ruleset_source"`
}
type Environment struct {
	GcloudVersion  string  `json:"gcloud_version"`
	KubectlVersion *string `json:"kubectl_version"`
	OS             string  `json:"os"`
	Arch           string  `json:"arch"`
}
type Identity struct {
	Account      string  `json:"account"`
	ADCAccount   *string `json:"adc_account"`
	Impersonated *string `json:"impersonated"`
	QuotaProject *string `json:"quota_project"`
}
type ScanTarget struct {
	Type         string           `json:"type"`
	ID           string           `json:"id"`
	Number       *string          `json:"number"`
	Organization *string          `json:"organization"`
	Clusters     ClusterInventory `json:"clusters"`
}
type ClusterInventory struct {
	Status      string   `json:"status"`
	Names       []string `json:"names"`
	Unreachable []string `json:"unreachable"`
}
type Selection struct {
	ProfileHash   string   `json:"profile_hash"`
	Benchmarks    []string `json:"benchmarks"`
	Levels        []string `json:"levels"`
	Capabilities  []string `json:"capabilities"`
	RulesSelected int      `json:"rules_selected"`
}
type Coverage struct {
	Units         int `json:"units"`
	Evaluated     int `json:"evaluated"`
	NotApplicable int `json:"not_applicable"`
	Skipped       int `json:"skipped"`
	Error         int `json:"error"`
}
type Summary struct {
	ResultsTotal int            `json:"results_total"`
	StatusCounts map[string]int `json:"status_counts"`
}
type RuleSummary struct {
	RuleID          string         `json:"rule_id"`
	RuleHash        string         `json:"rule_hash"`
	Ref             string         `json:"ref"`
	Title           string         `json:"title"`
	Profile         string         `json:"profile"`
	Severity        string         `json:"severity"`
	Mode            string         `json:"mode"`
	Verification    string         `json:"verification"`
	EffectiveParams map[string]any `json:"effective_params"`
	Status          string         `json:"status"`
	StatusCounts    map[string]int `json:"status_counts"`
}

type RuleRef struct {
	ID       string `json:"id"`
	Ref      string `json:"ref"`
	Title    string `json:"title"`
	Profile  string `json:"profile"`
	Severity string `json:"severity"`
	Mode     string `json:"mode"`
}
type TargetRef struct {
	Type      string `json:"type"`
	Key       string `json:"key"`
	ProjectID string `json:"project_id,omitempty"`
	Cluster   string `json:"cluster,omitempty"`
}
type ResourceRef struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Key     string `json:"key"`
	Members int    `json:"members,omitempty"`
}
type Collection struct {
	Status       string           `json:"status"`
	CollectorIDs []string         `json:"collector_ids"`
	Error        *CollectionError `json:"error"`
}
type CollectionError struct {
	Class   string `json:"class"`
	Summary string `json:"summary"`
}
type Assessment struct {
	Status       string  `json:"status"`
	Message      string  `json:"message"`
	ReviewReason *string `json:"review_reason"`
}
type Evidence struct {
	Expr         string `json:"expr"`
	Value        any    `json:"value"`
	CollectorID  string `json:"collector_id"`
	Truncated    bool   `json:"truncated,omitempty"`
	CollectorKey string `json:"-"`
}

type Collector struct {
	Key        string  `json:"-"`
	ScopeKey   string  `json:"-"`
	ID         string  `json:"id"`
	Type       string  `json:"type"`
	Command    string  `json:"command"`
	StartedAt  string  `json:"started_at"`
	DurationMS int64   `json:"duration_ms"`
	Status     string  `json:"status"`
	ExitCode   *int    `json:"exit_code"`
	ErrorClass *string `json:"error_class"`
	Error      *string `json:"error"`
}

type Result struct {
	ID            string      `json:"id"`
	FindingKey    string      `json:"finding_key"`
	Rule          RuleRef     `json:"rule"`
	Target        TargetRef   `json:"target"`
	Resource      ResourceRef `json:"resource"`
	CollectorKeys []string    `json:"-"`
	Collection    Collection  `json:"collection"`
	Assessment    Assessment  `json:"assessment"`
	Evidence      []Evidence  `json:"evidence"`
}

type UnitRef struct {
	RuleID    string
	TargetKey string
	Outcome   string
}
type Input struct {
	Scan       Scan
	Rules      []*rule.Rule
	Units      []UnitRef
	Results    []Result
	Collectors []Collector
}
