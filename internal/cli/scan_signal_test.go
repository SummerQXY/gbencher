package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SummerQXY/gbencher/internal/report"
)

func TestScanSignals_PublishWinsConcurrentInterrupt(t *testing.T) {
	for _, force := range []bool{false, true} {
		name := "without force"
		if force {
			name = "with force"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.json")
			old := []byte("old report")
			if force {
				if err := os.WriteFile(path, old, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			signals := newScanSignals(context.Background())
			defer signals.close()
			started := make(chan struct{})
			release := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				reportValue := &report.Report{}
				done <- reportValue.WriteFileContextGuarded(signals.ctx, path, force, func(commit func() (report.PublishResult, error)) error {
					return signals.publish(func() (report.PublishResult, error) {
						close(started)
						<-release
						return commit()
					})
				})
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("publication did not reach the guarded boundary")
			}
			accepted := make(chan struct{})
			go func() {
				signals.accept(os.Interrupt)
				close(accepted)
			}()
			close(release)
			if err := <-done; err != nil {
				t.Fatalf("write failed: %v", err)
			}
			select {
			case <-accepted:
			case <-time.After(5 * time.Second):
				t.Fatal("interrupt handler did not leave publication boundary")
			}
			if code, interrupted := signals.exitCode(); interrupted {
				t.Fatalf("published report returned interrupt code %d", code)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) == string(old) {
				t.Fatal("force publication did not replace the old report")
			}
		})
	}
}

func TestScanSignals_InterruptBeforePublishPreservesTarget(t *testing.T) {
	for _, force := range []bool{false, true} {
		name := "without force"
		if force {
			name = "with force"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.json")
			old := []byte("old report")
			if force {
				if err := os.WriteFile(path, old, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			signals := newScanSignals(context.Background())
			defer signals.close()
			signals.accept(os.Interrupt)
			writeErr := (&report.Report{}).WriteFileContextGuarded(signals.ctx, path, force, signals.publish)
			if writeErr == nil {
				t.Fatal("canceled write unexpectedly succeeded")
			}
			if code, interrupted := signals.exitCode(); !interrupted || code != 130 {
				t.Fatalf("exit code=%d interrupted=%v, want 130", code, interrupted)
			}
			data, err := os.ReadFile(path)
			if force {
				if err != nil || string(data) != string(old) {
					t.Fatalf("old report changed: data=%q err=%v", data, err)
				}
			} else if !os.IsNotExist(err) {
				t.Fatalf("new report exists after interruption: data=%q err=%v", data, err)
			}
		})
	}
}

func TestScanSignals_PostPublishErrorCannotBecomeInterrupt(t *testing.T) {
	signals := newScanSignals(context.Background())
	defer signals.close()
	cleanupErr := errors.New("post-publish cleanup failed")
	err := signals.publish(func() (report.PublishResult, error) {
		return report.PublishResult{Published: true, CleanupError: cleanupErr}, nil
	})
	if err != nil {
		t.Fatalf("published operation returned error: %v", err)
	}
	signals.accept(os.Interrupt)
	if code, interrupted := signals.exitCode(); interrupted {
		t.Fatalf("published operation returned interrupt code %d", code)
	}
	if got := signals.cleanupWarning(); !errors.Is(got, cleanupErr) {
		t.Fatalf("cleanup warning=%v, want %v", got, cleanupErr)
	}
}
