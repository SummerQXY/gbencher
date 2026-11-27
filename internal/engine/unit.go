package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/SummerQXY/gbencher/internal/auth"
	"github.com/SummerQXY/gbencher/internal/eval"
	"github.com/SummerQXY/gbencher/internal/failure"
	"github.com/SummerQXY/gbencher/internal/plan"
	"github.com/SummerQXY/gbencher/internal/report"
	"github.com/SummerQXY/gbencher/internal/rule"
)

func runUnit(ctx context.Context, opts Options, deps Deps, client *auth.Client, shared *executor, guard plan.Guard, env *eval.Env, unit plan.Unit, projectNumber string, enabled map[string]bool, domains *domainCache) (out struct {
	results []report.Result
	unit    report.UnitRef
	err     error
	fatal   bool
}) {
	r, target := unit.Rule, unit.Target
	out.unit = report.UnitRef{RuleID: r.ID, TargetKey: target.Key, Outcome: "evaluated"}
	baseCtx := eval.Context{Project: target.ProjectID, ProjectNumber: projectNumber, Organization: target.Organization, Folder: target.Folder, Cluster: target.Cluster, Account: client.Identity.Account, TargetKey: target.Key, TargetKind: target.Kind(), Now: opts.Now}
	if target.Type == "organization" {
		baseCtx.Organization = trimPrefix(target.Key, "organizations/")
	}
	params := cloneMap(r.Params)
	if r.Scope == "cluster" && target.Type != "cluster" {
		out.unit.Outcome = "not_applicable"
		out.results = []report.Result{unitResult(r, target, nil, "NOT_APPLICABLE", "no_clusters", report.Collection{Status: "NOT_RUN", CollectorIDs: []string{}})}
		return
	}
	if reason := missingCapability(r.Requires, opts.Enable, target); reason != "" {
		out.unit.Outcome = "skipped"
		out.results = []report.Result{unitResult(r, target, nil, "SKIPPED", reason, report.Collection{Status: "NOT_RUN", CollectorIDs: []string{}})}
		return
	}
	if ruleRequiresWorkspace(r) && !contains(opts.Enable, "workspace-admin") {
		out.unit.Outcome = "skipped"
		out.results = []report.Result{unitResult(r, target, nil, "SKIPPED", "workspace-admin", report.Collection{Status: "NOT_RUN", CollectorIDs: []string{}})}
		return
	}
	if missing := eval.ServicesMissing(r.Services, enabled); len(missing) > 0 {
		out.unit.Outcome = "not_applicable"
		out.results = []report.Result{unitResult(r, target, nil, "NOT_APPLICABLE", "service_disabled: "+strings.Join(missing, ", "), report.Collection{Status: "NOT_RUN", CollectorIDs: []string{}})}
		return
	}
	if baseCtx.Organization == "" && r.Scope == "organization" {
		out.unit.Outcome = "skipped"
		out.results = []report.Result{unitResult(r, target, nil, "SKIPPED", "organization_unresolved", report.Collection{Status: "NOT_RUN", CollectorIDs: []string{}})}
		return
	}
	stepCopy := *r
	stepCopy.Collect = nil
	partialReasons := []string{}
	missingCapabilitySteps := []rule.Step{}
	for _, step := range r.Collect {
		if missingCapability(step.Requires, opts.Enable, target) != "" {
			partialReasons = append(partialReasons, step.ID+": capability_missing")
			missingCapabilitySteps = append(missingCapabilitySteps, step)
			continue
		}
		stepCopy.Collect = append(stepCopy.Collect, step)
	}
	for _, step := range stepCopy.Collect {
		if step.Kubectl != "" {
			if target.Type != "cluster" {
				out.unit.Outcome = "error"
				out.results = []report.Result{unitResult(r, target, nil, "ERROR", "kubectl collection requires a cluster target", report.Collection{Status: "NOT_RUN", CollectorIDs: []string{}})}
				return
			}
			probe := shared.probeCluster(ctx, target)
			switch probe.Outcome {
			case clusterProbeReachable:
			case clusterProbeSkipped:
				out.unit.Outcome = "skipped"
				class := failure.Timeout
				if probe.Failure != nil {
					class = probe.Failure.Class
				}
				collection := report.Collection{Status: "FAILED", CollectorIDs: []string{}, Error: &report.CollectionError{Class: string(class), Summary: probe.Reason}}
				out.results = []report.Result{unitResult(r, target, nil, "SKIPPED", probe.Reason, collection)}
				return
			case clusterProbeCanceled:
				out.err = ErrCanceled
				return
			default:
				out.unit.Outcome = "error"
				failed := probe.Failure
				if failed == nil {
					failed = &failure.Failure{Class: failure.Unknown, Summary: "Kubernetes API server probe failed"}
				}
				collection := report.Collection{Status: "FAILED", CollectorIDs: []string{}, Error: &report.CollectionError{Class: string(failed.Class), Summary: failed.Summary}}
				out.results = []report.Result{unitResult(r, target, nil, "ERROR", failed.Summary, collection)}
				return
			}
		}
	}
	if needsOrganizationDomain(r, stepCopy.Collect) {
		if baseCtx.Organization == "" {
			out.unit.Outcome = "skipped"
			out.results = []report.Result{unitResult(r, target, nil, "SKIPPED", "organization_unresolved", report.Collection{Status: "NOT_RUN", CollectorIDs: []string{}})}
			return
		}
		domain, err := domains.get(ctx, client, baseCtx.Organization)
		if err != nil {
			if f, ok := failure.As(err); ok && f.Fatal() {
				out.fatal = true
				out.err = f
				return
			}
			out.unit.Outcome = "error"
			status := "ERROR"
			if f, ok := failure.As(err); ok && f.Class == failure.Permission {
				status = "SKIPPED"
				out.unit.Outcome = "skipped"
			}
			out.results = []report.Result{unitResult(r, target, nil, status, err.Error(), report.Collection{Status: "FAILED", CollectorIDs: []string{}, Error: &report.CollectionError{Class: failureClass(err), Summary: err.Error()}})}
			return
		}
		baseCtx.OrganizationDomain = domain
	}
	if target.Type == "cluster" {
		baseCtx.Cluster = target.Cluster
	}
	data := eval.NewData()
	if target.Type == "cluster" {
		data.Set("cluster", target.Cluster)
	}
	ex := shared.forTarget(target)
	ex.workspaceEnabled = ruleRequiresWorkspace(r)
	stepFailures := map[string]*failure.Failure{}
	usedCollectorKeys := map[string]bool{}
	stepOutcome, err := eval.RunSteps(ctx, env, &stepCopy, data, baseCtx, params, func(c context.Context, s rule.Step, values map[string]any) (any, *failure.Failure) {
		values["organization_domain"] = baseCtx.OrganizationDomain
		value, f, key := ex.executeWithKey(c, s, values)
		if key != "" {
			usedCollectorKeys[key] = true
		}
		if f != nil {
			stepFailures[s.ID] = f
			if f.Fatal() {
				out.fatal = true
				out.err = f
			}
		}
		return value, f
	}, opts.MaxFanout)
	if err != nil {
		out.unit.Outcome = "error"
		out.results = []report.Result{unitResult(r, target, nil, "ERROR", err.Error(), report.Collection{Status: "FAILED", CollectorIDs: []string{}})}
		return
	}
	if out.fatal {
		return
	}
	collectorKeys := make([]string, 0, len(usedCollectorKeys))
	for key := range usedCollectorKeys {
		collectorKeys = append(collectorKeys, key)
	}
	collection := report.Collection{Status: "SUCCEEDED", CollectorIDs: []string{}}
	if len(partialReasons) > 0 || len(stepOutcome.EmptySteps) > 0 || len(stepOutcome.IgnoredSteps) > 0 {
		collection.Status = "PARTIAL"
		class := "step_unavailable"
		summary := strings.Join(partialReasons, ", ")
		if len(stepOutcome.EmptySteps) > 0 {
			for _, id := range stepOutcome.EmptySteps {
				f := stepFailures[id]
				if f != nil {
					class = string(f.Class)
					summary = appendReason(summary, id+": "+string(f.Class))
				}
			}
		}
		if len(stepOutcome.IgnoredSteps) > 0 {
			for _, item := range stepOutcome.IgnoredSteps {
				summary = appendReason(summary, item.Step+": "+item.Reason)
			}
		}
		collection.Error = &report.CollectionError{Class: class, Summary: summary}
	}
	if stepOutcome.Aborted != nil {
		status := stepOutcome.Aborted.Status
		outcome := statusOutcome(status)
		out.unit.Outcome = outcome
		collection.Status = "FAILED"
		collection.Error = &report.CollectionError{Class: string(stepOutcome.Aborted.Failure.Class), Summary: stepOutcome.Aborted.Reason}
		result := unitResult(r, target, nil, status, stepOutcome.Aborted.Reason, collection)
		result.CollectorKeys = append([]string(nil), collectorKeys...)
		out.results = []report.Result{result}
		return
	}
	expanded, err := eval.ExpandResources(ctx, env, r, data, baseCtx, params)
	if err != nil {
		out.unit.Outcome = "error"
		collection.Status = "FAILED"
		collection.Error = &report.CollectionError{Class: "evaluation_error", Summary: err.Error()}
		out.results = []report.Result{unitResult(r, target, nil, "ERROR", err.Error(), collection)}
		return
	}
	instances := expanded.Instances
	if failures := collectionFailures(data, instances); len(failures) > 0 {
		collection.Status = "PARTIAL"
		class, summary := failureSummary(failures)
		if collection.Error != nil {
			summary = appendReason(collection.Error.Summary, summary)
		}
		collection.Error = &report.CollectionError{Class: class, Summary: summary}
	}
	if expanded.Empty {
		var dataDependencies eval.DataDependencies
		var dependencyErr error
		if r.Resource != nil {
			dataDependencies, dependencyErr = env.DataDependencies(r.Resource.From)
		}
		for _, step := range missingCapabilitySteps {
			if r.Resource == nil {
				continue
			}
			if dependencyErr == nil && !dataDependencies.Unknown && !contains(dataDependencies.Fields, step.ID) {
				continue
			}
			reason := step.ID + ": capability_missing"
			out.unit.Outcome = "skipped"
			collection.Status = "FAILED"
			summary := reason
			if collection.Error != nil && collection.Error.Summary != "" {
				summary = collection.Error.Summary
			}
			collection.Error = &report.CollectionError{Class: "capability_missing", Summary: summary}
			result := unitResult(r, target, nil, "SKIPPED", reason, collection)
			result.CollectorKeys = append([]string(nil), collectorKeys...)
			out.results = []report.Result{result}
			return
		}
		status := "NOT_APPLICABLE"
		if r.Resource != nil && r.Resource.Empty == "pass" {
			status = "PASS"
			out.unit.Outcome = "evaluated"
		} else {
			out.unit.Outcome = "not_applicable"
		}
		result := unitResult(r, target, nil, status, expanded.EmptyReason, collection)
		result.CollectorKeys = append([]string(nil), collectorKeys...)
		out.results = []report.Result{result}
		return
	}
	for i := range instances {
		assessment, evidence, assessErr := eval.Assess(ctx, env, r, &instances[i], data, baseCtx, params)
		if assessErr != nil {
			assessment = eval.Assessment{Status: "ERROR", Message: assessErr.Error()}
		}
		converted := convertEvidence(evidence, collectorKeys)
		out.results = append(out.results, unitResult(r, target, &instances[i], assessment.Status, assessment.Message, collection))
		out.results[len(out.results)-1].CollectorKeys = append([]string(nil), collectorKeys...)
		out.results[len(out.results)-1].Evidence = converted
		_ = i
	}
	if r.Resource != nil {
		if partial, ok := eval.PartialData(data, instances); ok {
			resource := planResource(target)
			assessment := partial
			out.results = append(out.results, report.Result{Rule: ruleRef(r), Target: targetRef(target), Resource: resource, CollectorKeys: append([]string(nil), collectorKeys...), Collection: collection, Assessment: report.Assessment{Status: assessment.Status, Message: assessment.Message}, Evidence: []report.Evidence{}})
		}
	}
	for _, tr := range stepOutcome.Truncated {
		assessment := fmt.Sprintf("evaluated %d of %d", tr.Evaluated, tr.Total)
		failedCollection := collection
		failedCollection.Status = "PARTIAL"
		failedCollection.Error = &report.CollectionError{Class: string(failure.FanoutExceeded), Summary: assessment}
		if r.Resource == nil && len(out.results) > 0 {
			last := len(out.results) - 1
			out.results[last].Assessment = report.Assessment{Status: "ERROR", Message: assessment}
			out.results[last].Collection = failedCollection
		} else {
			result := unitResult(r, target, nil, "ERROR", assessment, failedCollection)
			result.CollectorKeys = append([]string(nil), collectorKeys...)
			out.results = append(out.results, result)
		}
	}
	if len(out.results) == 0 {
		out.unit.Outcome = "not_applicable"
		out.results = []report.Result{unitResult(r, target, nil, "NOT_APPLICABLE", "no_resources", collection)}
	}
	out.unit.Outcome = worstOutcome(out.results)
	return
}

func missingCapability(required, enabled []string, target plan.Target) string {
	for _, cap := range required {
		switch cap {
		case "kubectl", "workspace-admin":
			if !contains(enabled, cap) {
				return cap
			}
		case "org-access":
			if target.Organization == "" {
				return cap
			}
		}
	}
	return ""
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func needsOrganizationDomain(r *rule.Rule, steps []rule.Step) bool {
	parts := []string{r.Check.Assert, r.Check.ReviewWhen, r.Check.Message, r.Check.ReviewMessage}
	parts = append(parts, r.Evidence...)
	if r.Resource != nil {
		parts = append(parts, r.Resource.From, r.Resource.Filter, r.Resource.Name, r.Resource.Key)
	}
	for _, s := range steps {
		parts = append(parts, s.Gcloud, s.Kubectl, s.Foreach)
		if s.API != nil {
			parts = append(parts, s.API.URL)
		}
	}
	for _, p := range parts {
		if strings.Contains(p, "organization_domain") {
			return true
		}
	}
	return false
}

func collectionFailures(data *eval.Data, instances []eval.ResourceInstance) []eval.Failed {
	known := make([]any, 0, len(instances))
	for _, instance := range instances {
		known = append(known, instance.Elem)
	}
	failed := data.Unattributed(known)
	for _, instance := range instances {
		failed = append(failed, data.Failures(instance.Elem)...)
	}
	sort.SliceStable(failed, func(i, j int) bool {
		if failed[i].Step != failed[j].Step {
			return failed[i].Step < failed[j].Step
		}
		if failed[i].Reason != failed[j].Reason {
			return failed[i].Reason < failed[j].Reason
		}
		return failed[i].Status < failed[j].Status
	})
	return failed
}

func failureSummary(failed []eval.Failed) (string, string) {
	class := "unknown"
	summaries := make([]string, 0, len(failed))
	seen := map[string]bool{}
	for _, item := range failed {
		if item.Failure != nil && class == "unknown" {
			class = string(item.Failure.Class)
		}
		reason := item.Reason
		if reason == "" && item.Failure != nil {
			reason = string(item.Failure.Class)
		}
		summary := item.Step + ": " + reason
		if !seen[summary] {
			seen[summary] = true
			summaries = append(summaries, summary)
		}
	}
	return class, strings.Join(summaries, "; ")
}
func needsProjectNumber(r *rule.Rule) bool { return strings.Contains(fmt.Sprint(r), "project_number") }
func failureClass(err error) string {
	if f, ok := failure.As(err); ok {
		return string(f.Class)
	}
	return "unknown"
}
func statusOutcome(status string) string {
	switch status {
	case "SKIPPED":
		return "skipped"
	case "NOT_APPLICABLE":
		return "not_applicable"
	case "ERROR":
		return "error"
	default:
		return "evaluated"
	}
}
func worstOutcome(results []report.Result) string {
	rank := map[string]int{"not_applicable": 1, "evaluated": 2, "skipped": 3, "error": 4}
	worst := "not_applicable"
	for _, r := range results {
		o := statusOutcome(r.Assessment.Status)
		if rank[o] > rank[worst] {
			worst = o
		}
	}
	return worst
}
func appendReason(current, next string) string {
	if current == "" {
		return next
	}
	return current + "; " + next
}
func trimPrefix(s, p string) string { return strings.TrimPrefix(s, p) }

func unitResult(r *rule.Rule, t plan.Target, inst *eval.ResourceInstance, status, message string, collection report.Collection) report.Result {
	resource := planResource(t)
	if inst != nil {
		resource = report.ResourceRef{Kind: inst.Kind, Name: inst.Name, Key: inst.Key}
	}
	return report.Result{Rule: ruleRef(r), Target: targetRef(t), Resource: resource, Collection: collection, Assessment: report.Assessment{Status: status, Message: message}, Evidence: []report.Evidence{}}
}
func planResource(t plan.Target) report.ResourceRef {
	return report.ResourceRef{Kind: t.Kind(), Name: t.Key, Key: t.Key}
}
func targetRef(t plan.Target) report.TargetRef {
	return report.TargetRef{Type: t.Type, Key: t.Key, ProjectID: t.ProjectID, Cluster: t.ClusterName}
}
func ruleRef(r *rule.Rule) report.RuleRef {
	return report.RuleRef{ID: r.ID, Ref: r.Ref, Title: r.Title, Profile: r.Profile, Severity: r.Severity, Mode: r.Mode}
}
func convertEvidence(in []eval.Evidence, keys []string) []report.Evidence {
	out := make([]report.Evidence, 0, len(in))
	for i, e := range in {
		key := ""
		if len(keys) > 0 {
			key = keys[min(i, len(keys)-1)]
		}
		out = append(out, report.Evidence{Expr: e.Expr, Value: e.Value, CollectorKey: key, Truncated: e.Truncated})
	}
	return out
}
