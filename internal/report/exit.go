package report

import "slices"

func (r *Report) ExitCode(failOn []string) int {
	if r == nil || r.Scan.Coverage.Evaluated == 0 {
		return 4
	}
	if len(failOn) == 0 {
		failOn = []string{"fail", "error"}
	}
	if slices.Contains(failOn, "none") {
		return 0
	}
	for _, result := range r.Results {
		if result.Assessment.Status == "FAIL" && slices.Contains(failOn, "fail") {
			return 1
		}
		if result.Assessment.Status == "REVIEW" && slices.Contains(failOn, "review") {
			return 1
		}
	}
	for _, u := range r.unitsForExit {
		if u.Outcome == "skipped" && slices.Contains(failOn, "skipped") {
			return 1
		}
		if u.Outcome == "error" && slices.Contains(failOn, "error") {
			return 1
		}
	}
	return 0
}
