package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/engine"
	"github.com/SummerQXY/gbencher/internal/redact"
	"github.com/SummerQXY/gbencher/internal/report"
	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/internal/rule/lint"
	"github.com/SummerQXY/gbencher/profiles"
	"github.com/spf13/cobra"
)

const maxProfileSize = 1 << 20

var projectIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

type scanFlags struct {
	projects, rulePatterns, excludes, benchmarks, levels, sets, enables, failOn []string
	profile, format, output, rulesDir, account, impersonate, quotaProject       string
	parallel, maxFanout                                                         int
	commandTimeout, timeout                                                     time.Duration
	profileSet, force, dryRun, verbose, showPass                                bool
}

func scanCmd(stdin io.Reader, stdout, stderr io.Writer, env []string) *cobra.Command {
	f := scanFlags{}
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan one or more GCP projects",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			f.profileSet = cmd.Flags().Changed("profile")
			code := runScan(cmd.Context(), f, stdin, stdout, stderr, env)
			if code != 0 {
				return &exitError{code: code}
			}
			return nil
		},
	}
	flags := cmd.Flags()
	flags.StringArrayVar(&f.projects, "project", nil, "Project ID to scan (repeatable)")
	flags.StringVar(&f.profile, "profile", "", "Profile path or - for stdin")
	flags.StringArrayVar(&f.rulePatterns, "rule", nil, "Rule ID or glob to include (repeatable)")
	flags.StringArrayVar(&f.excludes, "exclude", nil, "Rule ID or glob to exclude (repeatable)")
	flags.StringArrayVar(&f.benchmarks, "benchmark", nil, "Benchmark ID@version to include (repeatable)")
	flags.StringArrayVar(&f.levels, "level", nil, "Rule level to include (repeatable)")
	flags.StringArrayVar(&f.sets, "set", nil, "Rule parameter assignment (repeatable)")
	flags.StringSliceVar(&f.enables, "enable", nil, "Enable comma-separated capabilities")
	flags.IntVar(&f.parallel, "parallel", 8, "Maximum parallel rule units")
	flags.IntVar(&f.maxFanout, "max-fanout", 500, "Maximum foreach fanout")
	flags.DurationVar(&f.commandTimeout, "command-timeout", 120*time.Second, "Maximum duration of one command")
	flags.DurationVar(&f.timeout, "timeout", 0, "Maximum scan duration")
	flags.StringVar(&f.format, "format", "table", "Output format: table or json")
	flags.StringVar(&f.output, "output", "", "Write the JSON report to this path")
	flags.BoolVar(&f.force, "force", false, "Replace an existing output file")
	flags.StringSliceVar(&f.failOn, "fail-on", []string{"fail", "error"}, "Conditions that cause exit code 1")
	flags.StringVar(&f.account, "account", "", "gcloud account")
	flags.StringVar(&f.impersonate, "impersonate-service-account", "", "Service account to impersonate")
	flags.StringVar(&f.quotaProject, "quota-project", "", "Quota project")
	flags.BoolVar(&f.dryRun, "dry-run", false, "Show the planned scan without running commands")
	flags.StringVar(&f.rulesDir, "rules-dir", "", "Load and lint an external rule directory")
	flags.BoolVarP(&f.verbose, "verbose", "v", false, "Write diagnostics to stderr")
	flags.BoolVar(&f.showPass, "show-pass", false, "Show PASS results in table output")
	return cmd
}

func runScan(parent context.Context, f scanFlags, stdin io.Reader, stdout, stderr io.Writer, env []string) int {
	set, err := rule.LoadEmbedded()
	if err != nil {
		return scanError(stderr, 3, "load embedded rules: "+err.Error(), f.verbose)
	}
	allow, err := rule.LoadAllowlist()
	if err != nil {
		return scanError(stderr, 3, "load command allowlist: "+err.Error(), f.verbose)
	}
	if f.rulesDir != "" {
		files, violations, loadErr := rule.LoadFiles(os.DirFS(f.rulesDir))
		if loadErr != nil {
			return scanError(stderr, 2, "load external rules: "+loadErr.Error(), f.verbose)
		}
		findings := lint.Run(files, violations, lint.Options{Allow: allow})
		if len(findings) != 0 {
			_, _ = io.WriteString(stderr, "scan: external rules failed lint\n")
			return 2
		}
		external, loadErr := rule.LoadDir(f.rulesDir)
		if loadErr != nil {
			return scanError(stderr, 2, "load external rules: "+loadErr.Error(), f.verbose)
		}
		set = rule.Merge(set, external)
	}
	if len(f.projects) == 0 {
		return scanError(stderr, 2, "at least one --project is required", f.verbose)
	}
	for _, project := range f.projects {
		if !projectIDPattern.MatchString(project) {
			return scanError(stderr, 2, fmt.Sprintf("invalid project ID %q", project), f.verbose)
		}
	}
	profileData := profiles.Default
	if f.profileSet {
		if f.profile == "-" {
			profileData, err = io.ReadAll(io.LimitReader(stdin, maxProfileSize+1))
		} else {
			var file *os.File
			file, err = os.Open(f.profile)
			if err == nil {
				profileData, err = io.ReadAll(io.LimitReader(file, maxProfileSize+1))
				_ = file.Close()
			}
		}
		if err != nil {
			return scanError(stderr, 2, "read profile: "+err.Error(), f.verbose)
		}
	}
	if len(profileData) > maxProfileSize {
		return scanError(stderr, 2, "profile exceeds 1 MiB", f.verbose)
	}
	profile, violations, err := rule.ParseProfile(profileData)
	if err != nil || len(violations) > 0 {
		message := "invalid profile"
		if err != nil {
			message += ": " + err.Error()
		} else {
			message += ": " + violations[0].Message
		}
		return scanError(stderr, 2, message, f.verbose)
	}
	if f.parallel <= 0 || f.maxFanout <= 0 || f.commandTimeout <= 0 || f.timeout < 0 {
		return scanError(stderr, 2, "scan limits must be positive", f.verbose)
	}
	if f.format != "json" && f.format != "table" {
		return scanError(stderr, 2, "--format must be table or json", f.verbose)
	}
	if err := validateList("--level", f.levels, map[string]bool{"L1": true, "L2": true}); err != nil {
		return scanError(stderr, 2, err.Error(), f.verbose)
	}
	if err := validateList("--enable", f.enables, map[string]bool{"kubectl": true, "workspace-admin": true}); err != nil {
		return scanError(stderr, 2, err.Error(), f.verbose)
	}
	if err := validateList("--fail-on", f.failOn, map[string]bool{"fail": true, "review": true, "skipped": true, "error": true, "none": true}); err != nil {
		return scanError(stderr, 2, err.Error(), f.verbose)
	}
	paramSets, err := parseParamSets(f.sets)
	if err != nil {
		return scanError(stderr, 2, err.Error(), f.verbose)
	}
	selected, err := rule.Select(set, profile, rule.Selection{Benchmarks: f.benchmarks, Levels: f.levels, Include: f.rulePatterns, Exclude: f.excludes, Set: paramSets})
	if err != nil {
		return scanError(stderr, 2, err.Error(), f.verbose)
	}
	if f.dryRun {
		return writeDryRun(set, selected, f.projects, f.enables, f.format, stdout, stderr)
	}
	if f.output != "" {
		if code, err := preflightOutput(f.output, f.force); err != nil {
			return scanError(stderr, code, err.Error(), f.verbose)
		}
	}
	baseEnv := env
	if baseEnv == nil {
		baseEnv = os.Environ()
	}
	gcloud, err := lookPath("gcloud", baseEnv)
	if err != nil {
		return scanError(stderr, 3, "gcloud executable not found", f.verbose)
	}
	childEnv := collect.ChildEnv(baseEnv, engine.GcloudEnvOverrides())
	kubectl := ""
	if stringListContains(f.enables, "kubectl") && rulesUseKubectl(selected) {
		kubectl, err = lookPath("kubectl", baseEnv)
		if err != nil {
			return scanError(stderr, 3, "kubectl executable not found", f.verbose)
		}
	}
	if f.verbose {
		_, _ = fmt.Fprintf(stderr, "scan: starting scan for %d project(s) and %d rule(s)\n", len(f.projects), len(selected))
	}
	signals := newScanSignals(parent)
	defer signals.close()
	ctx := signals.ctx
	profileHash := sha256.Sum256(profileData)
	profileHashString := "sha256:" + hex.EncodeToString(profileHash[:])
	benchmarks, levels := selectedMetadata(selected)
	rep, err := engine.Run(ctx, engine.Options{Projects: f.projects, Rules: selected, Enable: f.enables, Parallel: f.parallel, MaxFanout: f.maxFanout, CommandTimeout: f.commandTimeout, Timeout: f.timeout, Account: f.account, Impersonate: f.impersonate, QuotaProject: f.quotaProject, RulesetHash: set.Hash, RulesetSource: set.Source, ProfileHash: profileHashString, Benchmarks: benchmarks, Levels: levels}, engine.Deps{Runner: collect.OSRunner{}, Gcloud: gcloud, Kubectl: kubectl, Env: childEnv, Allow: allow})
	if err != nil {
		if code, interrupted := signals.exitCode(); interrupted {
			return code
		}
		if errors.Is(err, engine.ErrCanceled) {
			return scanError(stderr, 3, "scan canceled by timeout", f.verbose)
		}
		var runErr *engine.RunError
		if errors.As(err, &runErr) {
			return scanError(stderr, runErr.Code, err.Error(), f.verbose)
		}
		return scanError(stderr, 3, err.Error(), f.verbose)
	}
	code := rep.ExitCode(f.failOn)
	if f.verbose {
		_, _ = fmt.Fprintf(stderr, "scan: completed with exit code %d\n", code)
	}
	if f.output != "" && (code == 0 || code == 1 || code == 4) {
		if err := rep.WriteFileContextGuarded(ctx, f.output, f.force, signals.publish); err != nil {
			if code, interrupted := signals.exitCode(); interrupted {
				return code
			}
			return scanError(stderr, 3, "write report: "+err.Error(), f.verbose)
		}
		if cleanupErr := signals.cleanupWarning(); cleanupErr != nil {
			_, _ = fmt.Fprintln(stderr, "scan: report was published, but temporary file cleanup failed:", redact.String(cleanupErr.Error()))
		}
	}
	if code, interrupted := signals.exitCode(); interrupted {
		return code
	}
	if f.format == "json" {
		if err := rep.WriteJSON(stdout); err != nil {
			return scanError(stderr, 3, "write report: "+err.Error(), f.verbose)
		}
	} else if err := rep.WriteTable(report.TableOptions{ShowPass: f.showPass, Out: stdout}); err != nil {
		return scanError(stderr, 3, "write report: "+err.Error(), f.verbose)
	}
	return code
}

func rulesUseKubectl(rules []*rule.Rule) bool {
	for _, current := range rules {
		if current == nil {
			continue
		}
		for _, step := range current.Collect {
			if step.Kubectl != "" {
				return true
			}
		}
	}
	return false
}

func stringListContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type scanSignals struct {
	ctx        context.Context
	cancel     context.CancelFunc
	channel    chan os.Signal
	mu         sync.Mutex
	received   os.Signal
	committed  bool
	cleanupErr error
}

func newScanSignals(parent context.Context) *scanSignals {
	ctx, cancel := context.WithCancel(parent)
	s := &scanSignals{ctx: ctx, cancel: cancel, channel: make(chan os.Signal, 1)}
	signal.Notify(s.channel, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-s.channel:
			s.accept(sig)
		case <-ctx.Done():
		}
	}()
	return s
}

func (s *scanSignals) close() {
	signal.Stop(s.channel)
	s.cancel()
}

func (s *scanSignals) accept(sig os.Signal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.committed && s.received == nil {
		s.received = sig
		s.cancel()
	}
}

func (s *scanSignals) exitCode() (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.received == nil {
		return 0, false
	}
	if s.received == syscall.SIGTERM {
		return 143, true
	}
	return 130, true
}

func (s *scanSignals) publish(commit func() (report.PublishResult, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ctx.Err(); err != nil {
		return err
	}
	result, err := commit()
	if result.Published {
		s.committed = true
	}
	if result.CleanupError != nil {
		s.cleanupErr = result.CleanupError
	}
	return err
}

func (s *scanSignals) cleanupWarning() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleanupErr
}

func scanError(stderr io.Writer, code int, message string, verbose bool) int {
	_ = verbose
	message = redact.String(message)
	_, _ = fmt.Fprintln(stderr, "scan:", message)
	return code
}

func validateList(name string, values []string, allowed map[string]bool) error {
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if !allowed[part] {
				return fmt.Errorf("invalid %s value %q", name, part)
			}
		}
	}
	return nil
}

func parseParamSets(values []string) ([]rule.ParamSet, error) {
	out := make([]rule.ParamSet, 0, len(values))
	for _, assignment := range values {
		left, raw, ok := strings.Cut(assignment, "=")
		index := strings.LastIndexByte(left, '.')
		if !ok || index <= 0 || index == len(left)-1 || raw == "" {
			return nil, fmt.Errorf("invalid --set assignment %q", assignment)
		}
		var value any
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("invalid --set JSON value %q: %w", assignment, err)
		}
		if decoder.Decode(new(any)) != io.EOF {
			return nil, fmt.Errorf("invalid trailing JSON in --set assignment %q", assignment)
		}
		out = append(out, rule.ParamSet{RuleID: left[:index], Param: left[index+1:], Value: value})
	}
	return out, nil
}

func selectedMetadata(selected []*rule.Rule) (benchmarks, levels []string) {
	benchmarkSet := make(map[string]bool)
	levelSet := make(map[string]bool)
	for _, r := range selected {
		if r == nil {
			continue
		}
		benchmarkSet[r.Benchmark.ID+"@"+r.Benchmark.Version] = true
		levelSet[r.Profile] = true
	}
	for benchmark := range benchmarkSet {
		benchmarks = append(benchmarks, benchmark)
	}
	for level := range levelSet {
		levels = append(levels, level)
	}
	sort.Strings(benchmarks)
	sort.Strings(levels)
	return benchmarks, levels
}

func preflightOutput(path string, force bool) (int, error) {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return 2, fmt.Errorf("refusing symlink output %q", path)
		}
		if !force {
			return 2, fmt.Errorf("output %q already exists", path)
		}
	} else if !os.IsNotExist(err) {
		return 3, err
	}
	if err := syscall.Access(filepath.Dir(path), 2); err != nil {
		return 3, fmt.Errorf("output directory is not writable: %w", err)
	}
	return 0, nil
}

func lookPath(name string, env []string) (string, error) {
	pathValue := ""
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if ok && key == "PATH" {
			pathValue = value
			break
		}
	}
	if pathValue == "" {
		return "", exec.ErrNotFound
	}
	for _, dir := range filepath.SplitList(pathValue) {
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() && info.Mode().Perm()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", exec.ErrNotFound
}
