package rule

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"

	"github.com/SummerQXY/gbencher/rules"
)

// maxListedViolations bounds how many violations ViolationsError.Error spells out.
const maxListedViolations = 20

// ViolationsError is the error LoadFS returns when the rule files do not load cleanly. It
// carries every violation; its message lists the first few.
type ViolationsError struct {
	Violations []Violation
}

func (e *ViolationsError) Error() string {
	n := len(e.Violations)
	noun := "violations"
	if n == 1 {
		noun = "violation"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "invalid rule files: %d %s", n, noun)
	for _, v := range e.Violations[:min(n, maxListedViolations)] {
		b.WriteString("\n  ")
		b.WriteString(v.File)
		b.WriteString(": ")
		if v.Path != "" {
			b.WriteString(v.Path)
			b.WriteString(": ")
		}
		b.WriteString(v.Message)
	}
	if n > maxListedViolations {
		fmt.Fprintf(&b, "\n  ... and %d more omitted", n-maxListedViolations)
	}
	return b.String()
}

// LoadFiles parses every rule file under fsys, however deeply nested, and returns them in
// path order. A rule file is a *.yaml file; the root also holds data files in YAML that
// follow other schemas (allowlist.yaml, verification.yaml), and those are skipped. Only the
// names at the root are reserved: a file of the same name in a subdirectory is a rule file.
//
// A file that parses is returned even when it has violations. A file whose YAML cannot be
// parsed is reported as a violation and the walk goes on, so that one load finds every
// problem. The error is for a file system that cannot be read.
func LoadFiles(fsys fs.FS) ([]*File, []Violation, error) {
	paths, err := ruleFilePaths(fsys)
	if err != nil {
		return nil, nil, err
	}

	var (
		files      []*File
		violations []Violation
	)
	for _, p := range paths {
		data, err := readRuleFile(fsys, p)
		if err != nil {
			return nil, nil, err
		}
		f, vs, err := ParseFile(p, data)
		if err != nil {
			violations = append(violations, Violation{File: p, Message: "unreadable yaml: " + err.Error()})
			continue
		}
		files = append(files, f)
		violations = append(violations, vs...)
	}
	return files, violations, nil
}

// ruleFilePaths lists the rule files under fsys in plain string order of their paths.
func ruleFilePaths(fsys fs.FS) ([]string, error) {
	var paths []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && isRuleFile(p) {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list rule files: %w", err)
	}
	// WalkDir orders the entries of one directory by name, which is not the order of the full
	// paths when a file name is a prefix of a directory name (a.yaml and a/).
	slices.Sort(paths)
	return paths, nil
}

// isRuleFile reports whether p, a slash-separated path relative to the loaded root, is a rule
// file.
func isRuleFile(p string) bool {
	if !strings.HasSuffix(p, ".yaml") {
		return false
	}
	return p != "allowlist.yaml" && p != "verification.yaml"
}

// readRuleFile reads a rule file but stops one byte past the size limit: ParseFile only has to
// see that the file is too large, so a huge file is never held in memory.
func readRuleFile(fsys fs.FS, p string) ([]byte, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p, err)
	}
	return data, nil
}

// LoadFS loads every rule file under fsys into one Set and records source in Set.Source.
//
// It is all or nothing, because a partial rule set must never be used for a scan: a
// violation in any file, a file that cannot be parsed, or a rule id used twice fails the load
// with a *ViolationsError that lists everything found. Any other error means the file system
// itself could not be read.
func LoadFS(fsys fs.FS, source string) (*Set, error) {
	files, violations, err := LoadFiles(fsys)
	if err != nil {
		return nil, err
	}

	var all []*Rule
	firstSeen := make(map[string]*Rule)
	for _, f := range files {
		for i, r := range f.Rules {
			if r.ID == "" {
				continue // the schema check has already reported the missing id
			}
			if first, dup := firstSeen[r.ID]; dup {
				violations = append(violations, Violation{
					File:    f.Name,
					Path:    fmt.Sprintf("/rules/%d/id", i),
					Message: duplicateIDMessage(r.ID, first.SourceFile, f.Name),
				})
				continue
			}
			firstSeen[r.ID] = r
			all = append(all, r)
		}
	}
	if len(violations) > 0 {
		return nil, &ViolationsError{Violations: violations}
	}

	slices.SortFunc(all, func(a, b *Rule) int { return strings.Compare(a.ID, b.ID) })
	return &Set{Rules: all, Hash: hashSet(all), Source: source}, nil
}

func duplicateIDMessage(id, firstFile, file string) string {
	if firstFile == file {
		return fmt.Sprintf("rule id %q is defined more than once in %s", id, file)
	}
	return fmt.Sprintf("rule id %q is defined in both %s and %s", id, firstFile, file)
}

// LoadDir loads the rule files under dir. The set's Source is "external".
func LoadDir(dir string) (*Set, error) {
	return LoadFS(os.DirFS(dir), "external")
}

// LoadEmbedded loads the rules compiled into the binary. The set's Source is "embedded".
func LoadEmbedded() (*Set, error) {
	return LoadFS(rules.FS, "embedded")
}
