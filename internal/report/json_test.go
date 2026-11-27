package report

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type cancelWriter struct{ cancel context.CancelFunc }

func (w cancelWriter) Write(p []byte) (int, error) {
	w.cancel()
	return len(p), nil
}

func TestWriteFileContext_CancellationDuringWriteStopsBeforePublish(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	err := writeContext(ctx, cancelWriter{cancel: cancel}, bytes.Repeat([]byte("x"), 64<<10))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context canceled", err)
	}

	path := filepath.Join(t.TempDir(), "report.json")
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if err := sampleReport(t).WriteFileContext(ctx, path, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context canceled", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("target exists after cancellation: %v", err)
	}
}

func sampleReport(t *testing.T) *Report {
	t.Helper()
	r, err := Assemble(sampleInput(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestNewScanID_UsesUTCAndReaderBytes(t *testing.T) {
	id := NewScanID(time.Date(2026, 11, 16, 8, 9, 10, 0, time.FixedZone("test", 8*60*60)), strings.NewReader("abcdef"))
	if id != "scan-20261116T000910Z-616263646566" {
		t.Fatalf("NewScanID() = %q", id)
	}
}

func TestWriteJSON_ControlCharactersAndInvalidUTF8StayValidJSON(t *testing.T) {
	in := sampleInput(t)
	in.Results[0].Resource.Name = string([]byte{'a', 0, 0x1b, 0xff})
	r, err := Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := r.WriteJSON(&b); err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(b.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestPublishNoClobber_LeavesTargetCreatedBeforePublish(t *testing.T) {
	dir := t.TempDir()
	temp := dir + "/temp"
	target := dir + "/report.json"
	if err := os.WriteFile(temp, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishNoClobber(temp, target); err == nil {
		t.Fatal("expected publish to refuse existing target")
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "existing" {
		t.Fatalf("existing target changed: %q, %v", got, err)
	}
}

func TestWriteFileContext_CleanupFailureAfterLinkRemainsCommitted(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "report.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	removeCalls := 0
	var tempPath string
	ops := reportFileOps{
		link: os.Link,
		remove: func(path string) error {
			removeCalls++
			if removeCalls == 1 {
				tempPath = path
				cancel()
				return errors.New("injected cleanup failure")
			}
			return os.Remove(path)
		},
		rename: os.Rename,
	}
	committed := false
	var cleanupErr error
	guard := func(publish func() (PublishResult, error)) error {
		result, err := publish()
		committed = result.Published
		cleanupErr = result.CleanupError
		return err
	}
	if err := (&Report{}).writeFileContextGuarded(ctx, target, false, guard, ops); err != nil {
		t.Fatalf("write returned error after publication: %v", err)
	}
	if !committed {
		t.Fatal("publication was not reported as committed")
	}
	if removeCalls != 2 {
		t.Fatalf("remove calls=%d, want two cleanup attempts", removeCalls)
	}
	if cleanupErr != nil {
		t.Fatalf("cleanup retry succeeded but warning remained: %v", cleanupErr)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("published target missing: %v", err)
	}
	if _, err := os.Lstat(tempPath); !os.IsNotExist(err) {
		t.Fatalf("temporary file remained after successful retry: %v", err)
	}
}

func TestWriteFileContext_PersistentTempCleanupFailureLeavesCommittedTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "report.json")
	removeCalls := 0
	var tempPath string
	ops := reportFileOps{
		link: os.Link,
		remove: func(path string) error {
			removeCalls++
			tempPath = path
			return errors.New("injected persistent cleanup failure")
		},
		rename: os.Rename,
	}
	committed := false
	var cleanupErr error
	guard := func(publish func() (PublishResult, error)) error {
		result, err := publish()
		committed = result.Published
		cleanupErr = result.CleanupError
		return err
	}
	if err := (&Report{}).writeFileContextGuarded(context.Background(), target, false, guard, ops); err != nil {
		t.Fatalf("write returned error after publication: %v", err)
	}
	if !committed {
		t.Fatal("publication was not reported as committed")
	}
	if removeCalls != 2 {
		t.Fatalf("remove calls=%d, want two cleanup attempts", removeCalls)
	}
	if cleanupErr == nil {
		t.Fatal("persistent cleanup failure was not reported")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("published target missing: %v", err)
	}
	if _, err := os.Stat(tempPath); err != nil {
		t.Fatalf("expected leftover temporary file after persistent cleanup failure: %v", err)
	}
}
