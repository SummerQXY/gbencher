package eval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
	"unicode/utf8"

	"github.com/SummerQXY/gbencher/internal/rule"
)

const (
	maxEvidenceBytes = 4 * 1024
	maxEvidenceItems = 50
)

// Assessment is the status and user-facing explanation for one resource.
type Assessment struct {
	Status, Message, ReviewReason string
}

// Evidence records the value of one rule-declared expression.
type Evidence struct {
	Expr      string
	Value     any
	Truncated bool
}

// Assess evaluates one resource instance, returning collection failures before CEL checks.
func Assess(ctx context.Context, env *Env, r *rule.Rule, inst *ResourceInstance, d *Data, c Context, params map[string]any) (Assessment, []Evidence, error) {
	if r == nil {
		return Assessment{}, nil, fmt.Errorf("rule is nil")
	}
	if env == nil {
		return Assessment{}, nil, fmt.Errorf("evaluation environment is nil")
	}
	if d == nil {
		d = NewData()
	}
	if inst == nil {
		inst = &ResourceInstance{}
	}
	resource := any(nil)
	if r.Resource != nil {
		resource = inst.Elem
	}
	failed := d.Failures(inst.Elem)
	if r.Resource == nil {
		failed = d.Unattributed(nil)
	}
	if len(failed) != 0 {
		return assessmentForFailures(failed, ""), nil, nil
	}
	asserted, err := env.Bool(ctx, r.Check.Assert, d, resource, c, params)
	if err != nil {
		return Assessment{Status: "ERROR", Message: err.Error()}, nil, nil
	}
	status := "PASS"
	messageText := ""
	if !asserted {
		status = "FAIL"
		messageText = r.Check.Message
	} else if r.Check.ReviewWhen != "" {
		review, err := env.Bool(ctx, r.Check.ReviewWhen, d, resource, c, params)
		if err != nil {
			return Assessment{Status: "ERROR", Message: err.Error()}, nil, nil
		}
		if review {
			status = "REVIEW"
			messageText = r.Check.ReviewMessage
			if messageText == "" {
				messageText = r.Check.Message
			}
		}
	}
	message, messageErr := renderMessage(messageText, messageVars(c, params, resource))
	if messageErr != nil {
		message = defaultMessage(status) + " (message render error: " + messageErr.Error() + ")"
	}
	evidence := make([]Evidence, 0, min(len(r.Evidence), maxEvidenceItems))
	for _, expr := range r.Evidence {
		if len(evidence) >= maxEvidenceItems {
			break
		}
		value, err := env.Value(ctx, expr, d, resource, c, params)
		if err != nil {
			evidence = append(evidence, Evidence{Expr: expr})
			continue
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			evidence = append(evidence, Evidence{Expr: expr})
			continue
		}
		if len(encoded) > maxEvidenceBytes {
			value = truncateEvidence(encoded)
			evidence = append(evidence, Evidence{Expr: expr, Value: value, Truncated: true})
			continue
		}
		evidence = append(evidence, Evidence{Expr: expr, Value: value})
	}
	return Assessment{Status: status, Message: message}, evidence, nil
}

// PartialData creates a resource-level aggregate result for failures without a matching instance.
func PartialData(d *Data, instances []ResourceInstance) (Assessment, bool) {
	if d == nil {
		return Assessment{}, false
	}
	known := make([]any, 0, len(instances))
	for _, instance := range instances {
		known = append(known, instance.Elem)
	}
	failed := d.Unattributed(known)
	if len(failed) == 0 {
		return Assessment{}, false
	}
	return assessmentForFailures(failed, "partial data"), true
}

func assessmentForFailures(failures []Failed, prefix string) Assessment {
	status := "SKIPPED"
	var reasons []string
	for _, item := range failures {
		if item.Status == "ERROR" {
			status = "ERROR"
		}
		if item.Reason != "" {
			reasons = append(reasons, item.Reason)
		}
	}
	message := strings.Join(reasons, "; ")
	if prefix != "" {
		if message == "" {
			message = prefix
		} else {
			message = prefix + ": " + message
		}
	}
	return Assessment{Status: status, Message: message}
}

func renderMessage(source string, vars map[string]any) (string, error) {
	if source == "" {
		return "", nil
	}
	t, err := template.New("message").Option("missingkey=zero").Parse(source)
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	if err := t.Execute(&out, vars); err != nil {
		return "", err
	}
	return out.String(), nil
}

func messageVars(c Context, params map[string]any, resource any) map[string]any {
	vars := c.Vars(params, nil)
	vars["r"] = resource
	return vars
}

func defaultMessage(status string) string {
	switch status {
	case "FAIL":
		return "Rule assertion failed"
	case "REVIEW":
		return "Manual review required"
	default:
		return ""
	}
}

func truncateEvidence(encoded []byte) string {
	text := strings.ToValidUTF8(string(encoded), "�")
	if len(text) > maxEvidenceBytes {
		text = text[:maxEvidenceBytes]
		text = strings.ToValidUTF8(text, "�")
	}
	for {
		serialized, err := json.Marshal(text)
		if err == nil && len(serialized) <= maxEvidenceBytes {
			return text
		}
		_, size := utf8.DecodeLastRuneInString(text)
		if size == 0 {
			return ""
		}
		text = text[:len(text)-size]
	}
}
