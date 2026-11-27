package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/SummerQXY/gbencher/internal/redact"
	"github.com/SummerQXY/gbencher/internal/rule"
)

func FindingKey(ruleID, targetKey, resourceKey string) string {
	sum := sha256.Sum256([]byte(ruleID + "\n" + targetKey + "\n" + resourceKey))
	return "fk1:" + hex.EncodeToString(sum[:])[:32]
}

func unitKey(ruleID, targetKey string) string {
	return ruleID + "\x00" + targetKey
}

func resultOutcome(status string) (string, bool) {
	switch status {
	case "ERROR":
		return "error", true
	case "SKIPPED":
		return "skipped", true
	case "PASS", "FAIL", "REVIEW":
		return "evaluated", true
	case "NOT_APPLICABLE":
		return "not_applicable", true
	default:
		return "", false
	}
}

func outcomeRank(outcome string) (int, bool) {
	switch outcome {
	case "not_applicable":
		return 1, true
	case "evaluated":
		return 2, true
	case "skipped":
		return 3, true
	case "error":
		return 4, true
	default:
		return 0, false
	}
}

func outcomeRankValue(outcome string) int {
	rank, _ := outcomeRank(outcome)
	return rank
}

func Assemble(in Input) (*Report, error) {
	rules := make(map[string]*rule.Rule, len(in.Rules))
	for _, r := range in.Rules {
		if r != nil {
			rules[r.ID] = r
		}
	}
	results := append([]Result(nil), in.Results...)
	unitOutcomes := make(map[string]string, len(in.Units))
	for _, u := range in.Units {
		key := unitKey(u.RuleID, u.TargetKey)
		if _, exists := unitOutcomes[key]; exists {
			return nil, fmt.Errorf("duplicate unit for rule %q and target %q", u.RuleID, u.TargetKey)
		}
		if _, ok := outcomeRank(u.Outcome); !ok {
			return nil, fmt.Errorf("unknown unit outcome %q", u.Outcome)
		}
		unitOutcomes[key] = u.Outcome
	}
	worstOutcomes := make(map[string]string, len(unitOutcomes))
	for _, result := range results {
		key := unitKey(result.Rule.ID, result.Target.Key)
		if _, exists := unitOutcomes[key]; !exists {
			return nil, fmt.Errorf("result for rule %q and target %q has no unit", result.Rule.ID, result.Target.Key)
		}
		outcome, ok := resultOutcome(result.Assessment.Status)
		if !ok {
			return nil, fmt.Errorf("unknown assessment status %q for rule %q and target %q", result.Assessment.Status, result.Rule.ID, result.Target.Key)
		}
		if current := worstOutcomes[key]; current == "" || outcomeRankValue(outcome) > outcomeRankValue(current) {
			worstOutcomes[key] = outcome
		}
	}
	for _, u := range in.Units {
		key := unitKey(u.RuleID, u.TargetKey)
		worstOutcome := worstOutcomes[key]
		if worstOutcome == "" {
			return nil, fmt.Errorf("unit %q for target %q has no result", u.RuleID, u.TargetKey)
		}
		if worstOutcome != u.Outcome {
			return nil, fmt.Errorf("unit %q for target %q has outcome %q, but its results require %q", u.RuleID, u.TargetKey, u.Outcome, worstOutcome)
		}
	}
	results, err := mergeResults(results)
	if err != nil {
		return nil, err
	}
	coverage := Coverage{Units: len(in.Units)}
	for _, u := range in.Units {
		switch u.Outcome {
		case "evaluated":
			coverage.Evaluated++
		case "not_applicable":
			coverage.NotApplicable++
		case "skipped":
			coverage.Skipped++
		case "error":
			coverage.Error++
		}
	}
	in.Scan.Coverage = coverage
	in.Scan.Status = "completed"
	if coverage.Skipped > 0 || coverage.Error > 0 {
		in.Scan.Status = "completed_with_gaps"
	}

	collectors := append([]Collector(nil), in.Collectors...)
	sort.SliceStable(collectors, func(i, j int) bool {
		a, b := collectors[i], collectors[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Command != b.Command {
			return a.Command < b.Command
		}
		if a.ScopeKey != b.ScopeKey {
			return a.ScopeKey < b.ScopeKey
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		if a.StartedAt != b.StartedAt {
			return a.StartedAt < b.StartedAt
		}
		if a.Status != b.Status {
			return a.Status < b.Status
		}
		if a.DurationMS != b.DurationMS {
			return a.DurationMS < b.DurationMS
		}
		if pointerString(a.ErrorClass) != pointerString(b.ErrorClass) {
			return pointerString(a.ErrorClass) < pointerString(b.ErrorClass)
		}
		if pointerString(a.Error) != pointerString(b.Error) {
			return pointerString(a.Error) < pointerString(b.Error)
		}
		if pointerInt(a.ExitCode) != pointerInt(b.ExitCode) {
			return pointerInt(a.ExitCode) < pointerInt(b.ExitCode)
		}
		return false
	})
	type scopedKey struct{ key, scope string }
	collectorIDs := make(map[scopedKey]string, len(collectors))
	for i := range collectors {
		c := &collectors[i]
		c.ID = fmt.Sprintf("collect-%d", i+1)
		c.Command = redact.String(c.Command)
		if c.Error != nil {
			s := redact.String(*c.Error)
			c.Error = &s
		}
		key := scopedKey{key: c.Key, scope: c.ScopeKey}
		if _, exists := collectorIDs[key]; exists {
			return nil, fmt.Errorf("duplicate collector key %q for scope %q", c.Key, c.ScopeKey)
		}
		collectorIDs[key] = c.ID
	}
	for i := range results {
		r := &results[i]
		if r.Assessment.Status == "FAIL" && r.Collection.Status != "SUCCEEDED" && r.Collection.Status != "PARTIAL" {
			return nil, fmt.Errorf("FAIL result %q has collection status %q", r.Rule.ID, r.Collection.Status)
		}
		if r.Rule.ID == "" {
			if rr := rules[r.Rule.ID]; rr != nil {
				r.Rule = ruleRef(rr)
			}
		}
		if rr := rules[r.Rule.ID]; rr != nil {
			r.Rule = ruleRef(rr)
		}
		r.Collection.CollectorIDs = []string{}
		for _, key := range r.CollectorKeys {
			id, ok := collectorIDs[scopedKey{key: key, scope: r.Target.Key}]
			if !ok {
				return nil, fmt.Errorf("unknown collector key %q for scope %q", key, r.Target.Key)
			}
			r.Collection.CollectorIDs = append(r.Collection.CollectorIDs, id)
		}
		r.Collection.CollectorIDs = sortedUnique(r.Collection.CollectorIDs)
		if r.Collection.Error != nil {
			r.Collection.Error.Summary = redact.String(r.Collection.Error.Summary)
		}
		r.Assessment.Message = redact.String(r.Assessment.Message)
		if r.Assessment.ReviewReason != nil {
			s := redact.String(*r.Assessment.ReviewReason)
			r.Assessment.ReviewReason = &s
		}
		if r.Evidence == nil {
			r.Evidence = []Evidence{}
		}
		if len(r.Evidence) > 50 {
			r.Evidence = r.Evidence[:50]
		}
		for ei := range r.Evidence {
			e := &r.Evidence[ei]
			e.CollectorID = ""
			if e.CollectorKey != "" {
				id, ok := collectorIDs[scopedKey{key: e.CollectorKey, scope: r.Target.Key}]
				if !ok {
					return nil, fmt.Errorf("unknown evidence collector key %q for scope %q", e.CollectorKey, r.Target.Key)
				}
				e.CollectorID = id
			}
			value, truncated, err := sanitizeEvidence(e.Value)
			if err != nil {
				return nil, fmt.Errorf("marshal evidence: %w", err)
			}
			e.Value = value
			e.Truncated = e.Truncated || truncated
		}
		r.FindingKey = FindingKey(r.Rule.ID, r.Target.Key, r.Resource.Key)
	}
	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.Rule.ID != b.Rule.ID {
			return a.Rule.ID < b.Rule.ID
		}
		if a.Target.Key != b.Target.Key {
			return a.Target.Key < b.Target.Key
		}
		return a.Resource.Key < b.Resource.Key
	})
	for i := 1; i < len(results); i++ {
		previous, current := results[i-1], results[i]
		if previous.Rule.ID == current.Rule.ID && previous.Target.Key == current.Target.Key && previous.Resource.Key == current.Resource.Key {
			return nil, fmt.Errorf("duplicate result for rule %q, target %q, resource %q", current.Rule.ID, current.Target.Key, current.Resource.Key)
		}
	}
	for i := range results {
		results[i].ID = fmt.Sprintf("result-%d", i+1)
	}

	summaryCounts := map[string]int{}
	byRule := map[string]map[string]int{}
	for _, r := range results {
		summaryCounts[r.Assessment.Status]++
		if byRule[r.Rule.ID] == nil {
			byRule[r.Rule.ID] = map[string]int{}
		}
		byRule[r.Rule.ID][r.Assessment.Status]++
	}
	summaries := make([]RuleSummary, 0, len(byRule))
	for id, counts := range byRule {
		rr := rules[id]
		rs := RuleSummary{RuleID: id, StatusCounts: counts, Status: "", Verification: "none", EffectiveParams: map[string]any{}}
		if rr != nil {
			rs.RuleHash = rr.Hash
			rs.Ref = rr.Ref
			rs.Title = rr.Title
			rs.Profile = rr.Profile
			rs.Severity = rr.Severity
			rs.Mode = rr.Mode
			if rr.Params != nil {
				rs.EffectiveParams = rr.Params
			}
		}
		statuses := make([]string, 0, len(counts))
		for status := range counts {
			statuses = append(statuses, status)
		}
		sort.Strings(statuses)
		if len(statuses) == 1 {
			rs.Status = statuses[0]
		} else {
			rs.Status = "MIXED"
		}
		summaries = append(summaries, rs)
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].RuleID < summaries[j].RuleID })
	if in.Scan.Selection.Benchmarks == nil {
		in.Scan.Selection.Benchmarks = []string{}
	}
	if in.Scan.Selection.Levels == nil {
		in.Scan.Selection.Levels = []string{}
	}
	if in.Scan.Selection.Capabilities == nil {
		in.Scan.Selection.Capabilities = []string{}
	}
	if in.Scan.Targets == nil {
		in.Scan.Targets = []ScanTarget{}
	}
	for i := range in.Scan.Targets {
		t := &in.Scan.Targets[i]
		if t.Clusters.Names == nil {
			t.Clusters.Names = []string{}
		}
		if t.Clusters.Unreachable == nil {
			t.Clusters.Unreachable = []string{}
		}
	}
	if results == nil {
		results = []Result{}
	}
	if collectors == nil {
		collectors = []Collector{}
	}
	return &Report{SchemaVersion: "1.1", Scan: in.Scan, Summary: Summary{ResultsTotal: len(results), StatusCounts: summaryCounts}, RuleSummaries: summaries, Results: results, Collectors: collectors, unitsForExit: append([]UnitRef(nil), in.Units...)}, nil
}

const (
	maxMergedMembers  = 20
	maxResultEvidence = 50
)

type resultGroupKey struct {
	ruleID      string
	targetKey   string
	resourceKey string
}

func mergeResults(results []Result) ([]Result, error) {
	groups := make(map[resultGroupKey][]Result, len(results))
	for _, result := range results {
		key := resultGroupKey{ruleID: result.Rule.ID, targetKey: result.Target.Key, resourceKey: result.Resource.Key}
		groups[key] = append(groups[key], result)
	}

	keys := make([]resultGroupKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ruleID != keys[j].ruleID {
			return keys[i].ruleID < keys[j].ruleID
		}
		if keys[i].targetKey != keys[j].targetKey {
			return keys[i].targetKey < keys[j].targetKey
		}
		return keys[i].resourceKey < keys[j].resourceKey
	})

	merged := make([]Result, 0, len(groups))
	for _, key := range keys {
		members := groups[key]
		if len(members) == 1 {
			merged = append(merged, members[0])
			continue
		}
		for _, member := range members[1:] {
			if member.Target != members[0].Target {
				return nil, fmt.Errorf("results for rule %q and resource %q have inconsistent target identity", key.ruleID, key.resourceKey)
			}
			if member.Resource.Kind != members[0].Resource.Kind {
				return nil, fmt.Errorf("results for rule %q, target %q, and resource %q have inconsistent resource kind", key.ruleID, key.targetKey, key.resourceKey)
			}
		}

		type orderedResult struct {
			result Result
			status int
			order  string
		}
		ordered := make([]orderedResult, len(members))
		for i, member := range members {
			status, ok := assessmentRank(member.Assessment.Status)
			if !ok {
				return nil, fmt.Errorf("unknown assessment status %q for rule %q and target %q", member.Assessment.Status, key.ruleID, key.targetKey)
			}
			order, err := resultOrderKey(member)
			if err != nil {
				return nil, fmt.Errorf("marshal result for rule %q and target %q: %w", key.ruleID, key.targetKey, err)
			}
			ordered[i] = orderedResult{result: member, status: status, order: order}
		}
		sort.Slice(ordered, func(i, j int) bool {
			if ordered[i].status != ordered[j].status {
				return ordered[i].status > ordered[j].status
			}
			return ordered[i].order < ordered[j].order
		})
		result := ordered[0].result
		collectorKeys := make([]string, 0)
		evidence := make([]orderedEvidence, 0)
		memberCount := 0
		for _, item := range ordered {
			member := item.result
			count := member.Resource.Members
			if count < 1 {
				count = 1
			}
			memberCount += count
			collectorKeys = append(collectorKeys, member.CollectorKeys...)
			for index, entry := range member.Evidence {
				evidence = append(evidence, orderedEvidence{entry: entry, source: item.order, index: index})
			}
			if member.Resource.Name < result.Resource.Name {
				result.Resource.Name = member.Resource.Name
			}
		}
		if memberCount > maxMergedMembers {
			memberCount = maxMergedMembers
		}
		result.Resource.Members = memberCount
		result.CollectorKeys = sortedUnique(collectorKeys)
		sort.SliceStable(evidence, func(i, j int) bool {
			if evidence[i].source != evidence[j].source {
				return evidence[i].source < evidence[j].source
			}
			return evidence[i].index < evidence[j].index
		})
		result.Evidence = make([]Evidence, 0, min(len(evidence), maxResultEvidence))
		for _, entry := range evidence[:min(len(evidence), maxResultEvidence)] {
			result.Evidence = append(result.Evidence, entry.entry)
		}
		merged = append(merged, result)
	}
	return merged, nil
}

type orderedEvidence struct {
	entry  Evidence
	source string
	index  int
}

func assessmentRank(status string) (int, bool) {
	switch status {
	case "FAIL":
		return 5, true
	case "ERROR":
		return 4, true
	case "REVIEW":
		return 3, true
	case "SKIPPED":
		return 2, true
	case "PASS":
		return 1, true
	default:
		return 0, false
	}
}

func resultOrderKey(result Result) (string, error) {
	evidenceCollectorKeys := make([]string, len(result.Evidence))
	for i, evidence := range result.Evidence {
		evidenceCollectorKeys[i] = evidence.CollectorKey
	}
	return marshalOrderKey(struct {
		Result                Result     `json:"result"`
		CollectorKeys         []string   `json:"collector_keys"`
		Evidence              []Evidence `json:"evidence"`
		EvidenceCollectorKeys []string   `json:"evidence_collector_keys"`
	}{Result: result, CollectorKeys: result.CollectorKeys, Evidence: result.Evidence, EvidenceCollectorKeys: evidenceCollectorKeys})
}

func marshalOrderKey(value any) (string, error) {
	data, err := json.Marshal(value)
	return string(data), err
}

func ruleRef(r *rule.Rule) RuleRef {
	return RuleRef{ID: r.ID, Ref: r.Ref, Title: r.Title, Profile: r.Profile, Severity: r.Severity, Mode: r.Mode}
}

func pointerString(p *string) string {
	if p == nil {
		return "\x00"
	}
	return "\x01" + *p
}

func pointerInt(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}
func sortedUnique(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for _, s := range in {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}
func sanitizeEvidence(v any) (any, bool, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, false, err
	}
	clean := redact.String(string(b))
	if len(clean) > 4096 {
		return "[TRUNCATED]", true, nil
	}
	var out any
	if err := json.Unmarshal([]byte(clean), &out); err != nil {
		return nil, false, err
	}
	return out, false, nil
}
