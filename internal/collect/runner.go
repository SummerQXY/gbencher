package collect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Exec describes a command to run.
type Exec struct {
	Path  string
	Argv  []string
	Stdin []byte
	Env   []string
	Dir   string
}

// Limits controls resource bounds for a subprocess.
// A Timeout <= 0 means no runner-level timeout — only the caller's context
// bounds the run.
type Limits struct {
	Timeout   time.Duration
	MaxOutput int64
}

// Output holds the result of a subprocess run.
type Output struct {
	Stdout, Stderr []byte
	ExitCode       int
	Duration       time.Duration
	TimedOut       bool
	Truncated      bool // true when stdout exceeded MaxOutput
}

// Runner executes a command described by Exec.
type Runner interface {
	Run(ctx context.Context, e Exec, l Limits) (Output, error)
}

// OSRunner implements Runner via os/exec, with process-group cleanup on
// timeout or cancellation.
type OSRunner struct{}

// Run starts the command, captures its stdout and stderr, and waits for it to
// complete. Stdout is capped at l.MaxOutput; stderr keeps its first 64 KiB.
// Only stdout truncation sets Truncated. If the command does not finish within
// l.Timeout the entire process group receives SIGKILL and TimedOut is set. If
// the parent context is cancelled before l.Timeout the process group is killed
// but TimedOut stays false. nil Env means an empty environment, not inherit.
func (OSRunner) Run(ctx context.Context, e Exec, l Limits) (Output, error) {
	var cmdCtx context.Context
	if l.Timeout > 0 {
		var cancel context.CancelFunc
		cmdCtx, cancel = context.WithTimeout(ctx, l.Timeout)
		defer cancel()
	} else {
		cmdCtx = ctx
	}

	cmd := exec.CommandContext(cmdCtx, e.Path, e.Argv...)
	cmd.Env = e.Env
	if cmd.Env == nil {
		cmd.Env = []string{}
	}
	cmd.Dir = e.Dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 200 * time.Millisecond

	// Cancel kills the entire process group, not just the direct child.
	// exec.CommandContext sets a nil Cancel; we override it here so that
	// grandchildren are killed together with the direct child.
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}

	if len(e.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(e.Stdin)
	}

	var stdoutW, stderrW cappedWriter
	stdoutW.limit = l.MaxOutput
	stderrW.limit = 64 * 1024
	cmd.Stdout = &stdoutW
	cmd.Stderr = &stderrW

	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start)

	// If ProcessState is nil the command never started (missing executable,
	// permission denied, etc.).
	if cmd.ProcessState == nil {
		return Output{}, err
	}

	exitCode := cmd.ProcessState.ExitCode()

	// Our own deadline expires -> TimedOut. Parent cancellation -> TimedOut
	// stays false.
	timedOut := l.Timeout > 0 && ctx.Err() == nil && cmdCtx.Err() != nil

	out := Output{
		Stdout:    stdoutW.bytes(),
		Stderr:    stderrW.bytes(),
		ExitCode:  exitCode,
		Duration:  elapsed,
		TimedOut:  timedOut,
		Truncated: stdoutW.truncated(),
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		waitDelayErr := fmt.Errorf("subprocess output may be incomplete: %w", err)
		if killErr := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); killErr != nil && !errors.Is(killErr, syscall.ESRCH) {
			waitDelayErr = errors.Join(waitDelayErr, fmt.Errorf("kill process group after wait delay: %w", killErr))
		}
		return out, waitDelayErr
	}
	return out, nil
}

// cappedWriter is a goroutine-safe io.Writer that keeps at most limit bytes
// and reports whether data beyond the limit was discarded.
type cappedWriter struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	limit    int64
	hitLimit bool
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.hitLimit {
		return len(p), nil
	}

	remain := w.limit - int64(w.buf.Len())
	if remain <= 0 {
		w.hitLimit = true
		return len(p), nil
	}

	n := len(p)
	if int64(n) > remain {
		n = int(remain)
		w.hitLimit = true
	}
	w.buf.Write(p[:n])
	return len(p), nil
}

func (w *cappedWriter) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Bytes()
}

func (w *cappedWriter) truncated() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.hitLimit
}
