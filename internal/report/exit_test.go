package report

import (
	"os"
	"testing"
)

func TestExitCode_Table(t *testing.T) {
	cases := []struct {
		name   string
		units  []string
		status string
		failOn []string
		want   int
	}{
		{"clean", []string{"evaluated"}, "PASS", nil, 0},
		{"fail", []string{"evaluated"}, "FAIL", []string{"fail"}, 1},
		{"review", []string{"evaluated"}, "REVIEW", []string{"review"}, 1},
		{"skipped", []string{"evaluated", "skipped"}, "SKIPPED", []string{"skipped"}, 1},
		{"error", []string{"evaluated", "error"}, "ERROR", []string{"error"}, 1},
		{"none", []string{"evaluated"}, "FAIL", []string{"none"}, 0},
		{"empty", nil, "FAIL", []string{"fail"}, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := sampleInput(t)
			base := in.Results[0]
			in.Units = nil
			in.Results = nil
			for i, outcome := range tc.units {
				target := "projects/example-prod"
				if i > 0 {
					target = "projects/example-prod/target-" + string(rune('0'+i))
				}
				unit := UnitRef{RuleID: base.Rule.ID, TargetKey: target, Outcome: outcome}
				in.Units = append(in.Units, unit)
				result := base
				result.Target.Key = target
				result.Assessment.Status = tc.status
				if outcome == "evaluated" && (tc.status == "SKIPPED" || tc.status == "ERROR") {
					result.Assessment.Status = "PASS"
				}
				if outcome == "skipped" || outcome == "error" {
					result.Collection.Status = "FAILED"
				}
				in.Results = append(in.Results, result)
			}
			r, err := Assemble(in)
			if err != nil {
				t.Fatal(err)
			}
			if got := r.ExitCode(tc.failOn); got != tc.want {
				t.Fatalf("ExitCode() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestWriteFile_RefusesExistingWithoutForce(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/report.json"
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Assemble(sampleInput(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.WriteFile(path, false); err == nil {
		t.Fatal("expected existing file error")
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "keep" {
		t.Fatalf("existing file changed: %q, %v", b, err)
	}
}

func TestWriteFile_RefusesSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	target := dir + "/target"
	link := dir + "/link"
	if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	r, err := Assemble(sampleInput(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.WriteFile(link, true); err == nil {
		t.Fatal("expected symlink error")
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "keep" {
		t.Fatalf("symlink target changed: %q, %v", got, err)
	}
}

func TestWriteFile_WritesMode0600(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/report.json"
	r, err := Assemble(sampleInput(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.WriteFile(path, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestWriteFile_NoTempLeftOnFailure(t *testing.T) {
	dir := t.TempDir()
	destination := dir + "/destination"
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	r, err := Assemble(sampleInput(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.WriteFile(destination, true); err == nil {
		t.Fatal("expected rename failure")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "destination" {
		t.Fatalf("temporary files remain: %v", entries)
	}
}
