package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/engine"
	"github.com/SummerQXY/gbencher/internal/redact"
	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/internal/sanitize"
	"github.com/spf13/cobra"
)

type collectFlags struct {
	ruleID, project, step, format, account, impersonate, quotaProject string
	sanitize                                                          bool
}

func collectCmd(stdout, stderr io.Writer, env []string) *cobra.Command {
	f := collectFlags{}
	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Collect one rule's data",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			code := runCollect(cmd.Context(), f, stdout, stderr, env)
			if code != 0 {
				return &exitError{code: code}
			}
			return nil
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&f.ruleID, "rule", "", "Rule ID to collect")
	flags.StringVar(&f.project, "project", "", "Project ID to collect")
	flags.StringVar(&f.step, "step", "", "Collect step ID")
	flags.BoolVar(&f.sanitize, "sanitize", false, "Replace known identifiers and redact secrets")
	flags.StringVar(&f.format, "format", "json", "Output format: json")
	flags.StringVar(&f.account, "account", "", "gcloud account")
	flags.StringVar(&f.impersonate, "impersonate-service-account", "", "Service account to impersonate")
	flags.StringVar(&f.quotaProject, "quota-project", "", "Quota project")
	return cmd
}

func runCollect(parent context.Context, f collectFlags, stdout, stderr io.Writer, env []string) int {
	if f.ruleID == "" || f.project == "" {
		return scanError(stderr, 2, "--rule and --project are required", false)
	}
	if !projectIDPattern.MatchString(f.project) {
		return scanError(stderr, 2, fmt.Sprintf("invalid project ID %q", f.project), false)
	}
	if f.format != "json" {
		return scanError(stderr, 2, "--format must be json", false)
	}
	set, err := rule.LoadEmbedded()
	if err != nil {
		return scanError(stderr, 3, "load embedded rules: "+err.Error(), false)
	}
	r, ok := set.Get(f.ruleID)
	if !ok {
		return scanError(stderr, 2, fmt.Sprintf("unknown rule %q", f.ruleID), false)
	}
	selected := make([]rule.Step, 0, len(r.Collect))
	found := f.step == ""
	hasREST := false
	for _, step := range r.Collect {
		if f.step != "" && step.ID != f.step {
			continue
		}
		if step.Kubectl != "" || (step.Gcloud == "" && step.API == nil) {
			return scanError(stderr, 2, "collect supports gcloud and REST steps only", false)
		}
		found = true
		hasREST = hasREST || step.API != nil
		selected = append(selected, step)
	}
	if !found || len(selected) == 0 {
		return scanError(stderr, 2, fmt.Sprintf("collect step %q was not found", f.step), false)
	}
	if r.Scope != "project" {
		return scanError(stderr, 2, "collect supports project scope only", false)
	}
	copyRule := *r
	copyRule.Collect = selected
	baseEnv := env
	if baseEnv == nil {
		baseEnv = os.Environ()
	}
	gcloud, err := lookPath("gcloud", baseEnv)
	if err != nil {
		return scanError(stderr, 3, "gcloud executable not found", false)
	}
	allow, err := rule.LoadAllowlist()
	if err != nil {
		return scanError(stderr, 3, "load command allowlist: "+err.Error(), false)
	}
	ctx := parent
	if ctx == nil {
		ctx = context.Background()
	}
	result, err := engine.CollectRule(ctx, engine.Options{
		Projects: []string{f.project}, Rules: []*rule.Rule{&copyRule}, CommandTimeout: 120 * time.Second,
		Account: f.account, Impersonate: f.impersonate, QuotaProject: f.quotaProject,
	}, engine.Deps{Runner: collect.OSRunner{}, Gcloud: gcloud, Env: collect.ChildEnv(baseEnv, engine.GcloudEnvOverrides()), Allow: allow}, &copyRule, f.step)
	if err != nil {
		return scanError(stderr, 3, redact.String(err.Error()), false)
	}
	payload := map[string]any{"params": result.Params, "data": result.Data, "collectors": result.Collectors}
	if f.sanitize {
		projectNumbers, orgIDs, orgDomains := collectedMetadata(result.Data)
		scrubber := sanitize.NewWithMetadata([]string{f.project}, projectNumbers, orgIDs, orgDomains, result.Account)
		_, _ = io.WriteString(stderr, "collect: sanitization is best-effort only; manually review output")
		missing := make([]string, 0, 3)
		if len(projectNumbers) == 0 {
			missing = append(missing, "project number")
		}
		if len(orgIDs) == 0 {
			missing = append(missing, "organization ID")
		}
		if len(orgDomains) == 0 {
			missing = append(missing, "organization domain")
		}
		if len(missing) > 0 {
			_, _ = fmt.Fprintf(stderr, "; not identified in collected data: %s", strings.Join(missing, ", "))
		}
		multiple := make([]string, 0, 3)
		if len(projectNumbers) > 1 {
			multiple = append(multiple, "project numbers")
		}
		if len(orgIDs) > 1 {
			multiple = append(multiple, "organization IDs")
		}
		if len(orgDomains) > 1 {
			multiple = append(multiple, "organization domains")
		}
		if len(multiple) > 0 {
			_, _ = fmt.Fprintf(stderr, "; multiple values found and included: %s", strings.Join(multiple, ", "))
		}
		_, _ = io.WriteString(stderr, "\n")
		scrubbed, mapping := scrubber.Scrub(payload)
		payload = scrubbed.(map[string]any)
		keys := make([]string, 0, len(mapping))
		for original := range mapping {
			keys = append(keys, original)
		}
		sort.Strings(keys)
		if !hasREST {
			for _, original := range keys {
				_, _ = fmt.Fprintf(stderr, "%s → %s\n", original, mapping[original])
			}
		}
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return scanError(stderr, 3, "write collect output: "+err.Error(), false)
	}
	return 0
}

func collectedMetadata(data map[string]any) ([]string, []string, []string) {
	projects := map[string]bool{}
	organizations := map[string]bool{}
	domains := map[string]bool{}
	collectMetadataValues(data, projects, organizations, domains)
	return sortedValues(projects), sortedValues(organizations), sortedValues(domains)
}

func collectMetadataValues(value any, projects, organizations, domains map[string]bool) {
	switch current := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(current))
		for key := range current {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		typeName, _ := current["type"].(string)
		for _, key := range keys {
			child := current[key]
			if text, ok := metadataScalar(child); ok {
				switch normalizeMetadataKey(key) {
				case "projectnumber":
					projects[text] = true
				case "organization", "organizationid", "orgid":
					organizations[text] = true
				case "organizationdomain", "orgdomain":
					domains[text] = true
				case "id":
					if strings.EqualFold(typeName, "organization") {
						organizations[text] = true
					}
				}
			}
			collectMetadataValues(child, projects, organizations, domains)
		}
	case []any:
		for _, child := range current {
			collectMetadataValues(child, projects, organizations, domains)
		}
	}
}

func metadataScalar(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, v != ""
	case json.Number:
		return v.String(), v.String() != ""
	case float64:
		return fmt.Sprintf("%.0f", v), v == float64(uint64(v))
	case int, int32, int64, uint, uint32, uint64:
		return fmt.Sprint(v), true
	default:
		return "", false
	}
}

func normalizeMetadataKey(key string) string {
	key = strings.ToLower(key)
	return strings.NewReplacer("_", "", "-", "").Replace(key)
}

func sortedValues(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
