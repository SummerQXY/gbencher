package cli

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/internal/rule/kubeschema"
	"github.com/SummerQXY/gbencher/internal/rule/lint"
	"github.com/SummerQXY/gbencher/internal/rule/restschema"
	"github.com/SummerQXY/gbencher/rules"
)

// rulesLintCmd builds the "rules lint" subcommand.
func rulesLintCmd(stdout, stderr io.Writer) *cobra.Command {
	writeVerification := false
	fixtures := "testdata/rules"
	cmd := &cobra.Command{
		Use:   "lint [path]",
		Short: "Check rule files for correctness",
		Long: `Lint reads rule files from path and reports every violation of the rule
schema and every finding the static checker produces. When no path is
given it lints the rule corpus that is embedded in the binary.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRulesLint(stdout, stderr, args, writeVerification, fixtures)
		},
	}
	cmd.Flags().BoolVar(&writeVerification, "write-verification", false, "Write computed verification levels")
	cmd.Flags().StringVar(&fixtures, "fixtures", "testdata/rules", "Fixture directory used to compute verification levels")
	return cmd
}

// runRulesLint runs the lint logic: load rules, run the checks, print the result.
func runRulesLint(stdout, stderr io.Writer, args []string, writeVerification bool, fixtures string) error {
	var (
		source string
		fsys   fs.FS
	)

	if len(args) == 1 {
		path := args[0]
		source = path

		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			return fmt.Errorf("%s: no such file or directory", path)
		}
		if err != nil {
			return fmt.Errorf("%s: %v", path, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s: not a directory", path)
		}
		fsys = os.DirFS(path)
	} else {
		source = "embedded rules"
		fsys = rules.FS
	}

	files, violations, err := rule.LoadFiles(fsys)
	if err != nil {
		return fmt.Errorf("%s: %v", source, err)
	}

	allow, err := rule.LoadAllowlist()
	if err != nil {
		return fmt.Errorf("allowlist: %v", err)
	}

	findings := lint.Run(files, violations, lint.Options{Allow: allow})
	allRules := make([]*rule.Rule, 0)
	for _, file := range files {
		allRules = append(allRules, file.Rules...)
	}
	set := &rule.Set{Rules: allRules}
	schemaResult := restschema.Check(set)
	for _, message := range schemaResult.Errors {
		findings = append(findings, lint.Finding{Code: "rest-schema", Message: message})
	}
	for _, message := range schemaResult.Warnings {
		fmt.Fprintf(stdout, "warning: %s\n", message)
	}
	kubeResult := kubeschema.Check(set)
	for _, message := range kubeResult.Errors {
		findings = append(findings, lint.Finding{Code: "kubectl-schema", Message: message})
	}
	for _, message := range kubeResult.Warnings {
		fmt.Fprintf(stdout, "warning: %s\n", message)
	}
	staticOK := make(map[string]bool, len(schemaResult.StaticOK)+len(kubeResult.StaticOK))
	for id, ok := range schemaResult.StaticOK {
		staticOK[id] = ok
	}
	for id, ok := range kubeResult.StaticOK {
		staticOK[id] = ok
	}
	computed, err := rule.ComputeVerification(set, fixtures, staticOK)
	if err != nil {
		return fmt.Errorf("compute verification: %w", err)
	}
	verificationPath := "rules/verification.yaml"
	if len(args) == 1 {
		verificationPath = filepath.Join(args[0], "verification.yaml")
	}
	if writeVerification {
		if len(findings) == 0 {
			if err := rule.WriteVerification(verificationPath, computed); err != nil {
				return fmt.Errorf("write verification: %w", err)
			}
		}
	} else {
		stored, loadErr := rule.LoadVerificationFS(fsys)
		if loadErr == nil && !rule.VerificationEqual(*stored, computed) {
			findings = append(findings, lint.Finding{File: "verification.yaml", Code: "verification-stale", Message: "stored verification levels do not match computed levels"})
		} else if loadErr != nil && source == "embedded rules" {
			return fmt.Errorf("load verification: %w", loadErr)
		} else if loadErr != nil {
			if _, statErr := fs.Stat(fsys, "verification.yaml"); statErr == nil {
				return fmt.Errorf("load verification: %w", loadErr)
			}
		}
	}
	n := len(findings)

	if n == 1 && findings[0].Code == "no-rule-files" {
		fmt.Fprintf(stdout, "lint: no-rule-files: no rule files found in %s\n", source)
	} else {
		fmt.Fprint(stdout, lint.FormatText(findings))
	}

	fmt.Fprintf(stderr, "lint: %d finding(s) in %s\n", n, source)

	if n > 0 {
		return &exitError{code: 1}
	}
	return nil
}
