package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"unicode"
	"unicode/utf8"

	"github.com/SummerQXY/gbencher/internal/redact"
)

// TableOptions controls the plain-text report rendering.
type TableOptions struct {
	ShowPass   bool
	MaxMessage int
	Out        io.Writer
}

// WriteTable writes a deterministic, control-character-free summary and result table.
func (r *Report) WriteTable(o TableOptions) error {
	if o.Out == nil {
		return fmt.Errorf("table output writer is nil")
	}
	maxMessage := o.MaxMessage
	if maxMessage <= 0 {
		maxMessage = 120
	}
	w := tabwriter.NewWriter(o.Out, 0, 4, 2, ' ', 0)

	statuses := make([]string, 0, len(r.Summary.StatusCounts))
	for status := range r.Summary.StatusCounts {
		statuses = append(statuses, status)
	}
	sort.Strings(statuses)
	if _, err := fmt.Fprintln(w, "summary\tcount"); err != nil {
		return err
	}
	for _, status := range statuses {
		if _, err := fmt.Fprintf(w, "%s\t%d\n", tableText(status), r.Summary.StatusCounts[status]); err != nil {
			return err
		}
	}
	coverage := r.Scan.Coverage
	if _, err := fmt.Fprintf(w, "coverage\tunits=%d evaluated=%d not_applicable=%d skipped=%d error=%d\n", coverage.Units, coverage.Evaluated, coverage.NotApplicable, coverage.Skipped, coverage.Error); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "scan_status\t%s\n", tableText(r.Scan.Status)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "status\tseverity\trule_id\tresource\tmessage"); err != nil {
		return err
	}

	results := append([]Result(nil), r.Results...)
	sort.Slice(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.Rule.ID != b.Rule.ID {
			return a.Rule.ID < b.Rule.ID
		}
		if a.Target.Key != b.Target.Key {
			return a.Target.Key < b.Target.Key
		}
		if a.Resource.Key != b.Resource.Key {
			return a.Resource.Key < b.Resource.Key
		}
		if a.Assessment.Status != b.Assessment.Status {
			return a.Assessment.Status < b.Assessment.Status
		}
		if a.Resource.Name != b.Resource.Name {
			return a.Resource.Name < b.Resource.Name
		}
		if a.Rule.Severity != b.Rule.Severity {
			return a.Rule.Severity < b.Rule.Severity
		}
		return a.Assessment.Message < b.Assessment.Message
	})
	for _, result := range results {
		if !o.ShowPass && result.Assessment.Status == "PASS" {
			continue
		}
		message := truncateRunes(tableText(result.Assessment.Message), maxMessage)
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			tableText(result.Assessment.Status),
			tableText(result.Rule.Severity),
			tableText(result.Rule.ID),
			tableText(result.Resource.Name),
			message,
		); err != nil {
			return err
		}
	}
	return w.Flush()
}

func tableText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r == '\v' || r == '\f' || r == '\u0085' || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return ' '
		}
		return r
	}, s)
	return redact.StripControl(s)
}

func truncateRunes(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	if limit == 1 {
		return "…"
	}
	runes := []rune(s)
	return string(runes[:limit-1]) + "…"
}
