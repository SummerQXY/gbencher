package report

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func NewScanID(now time.Time, random io.Reader) string {
	if random == nil {
		random = rand.Reader
	}
	var token [6]byte
	if _, err := io.ReadFull(random, token[:]); err != nil {
		token = [6]byte{}
	}
	return "scan-" + now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(token[:])
}

func (r *Report) WriteJSON(w io.Writer) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	n, err := w.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}

func (r *Report) WriteFile(path string, force bool) error {
	return r.WriteFileContext(context.Background(), path, force)
}

// WriteFileContext writes a report atomically and discards its temporary file when ctx is canceled.
func (r *Report) WriteFileContext(ctx context.Context, path string, force bool) error {
	return r.WriteFileContextGuarded(ctx, path, force, nil)
}

// PublishResult reports whether the target was published, even if later cleanup failed.
type PublishResult struct {
	Published    bool
	CleanupError error
}

// PublishGuard serializes the final context check and atomic publication with cancellation.
type PublishGuard func(publish func() (PublishResult, error)) error

// WriteFileContextGuarded writes a report while letting the caller serialize cancellation with publication.
func (r *Report) WriteFileContextGuarded(ctx context.Context, path string, force bool, guard PublishGuard) error {
	return r.writeFileContextGuarded(ctx, path, force, guard, reportFileOps{link: os.Link, remove: os.Remove, rename: os.Rename})
}

type reportFileOps struct {
	link   func(string, string) error
	remove func(string) error
	rename func(string, string) error
}

func (r *Report) writeFileContextGuarded(ctx context.Context, path string, force bool, guard PublishGuard, ops reportFileOps) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink output %q", path)
		}
		if !force {
			return fmt.Errorf("output %q already exists", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".gbench-report-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	transferred := false
	defer func() {
		if !transferred {
			_ = ops.remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		tmp.Close()
		return err
	}
	data = append(data, '\n')
	if err := writeContext(ctx, tmp, data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	publish := func() (PublishResult, error) {
		if err := ctx.Err(); err != nil {
			return PublishResult{}, err
		}
		if !force {
			result, err := publishNoClobberWithOps(tmpName, path, ops)
			if result.Published {
				transferred = true
			}
			return result, err
		}
		if err := ops.rename(tmpName, path); err != nil {
			return PublishResult{}, err
		}
		return PublishResult{Published: true}, nil
	}
	if guard != nil {
		return guard(publish)
	}
	result, err := publish()
	if err != nil {
		return err
	}
	if result.CleanupError != nil {
		return fmt.Errorf("report was published but temporary file cleanup failed: %w", result.CleanupError)
	}
	return nil
}

func writeContext(ctx context.Context, w io.Writer, data []byte) error {
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := min(len(data), 32<<10)
		written, err := w.Write(data[:n])
		if err != nil {
			return err
		}
		if written != n {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return ctx.Err()
}

func publishNoClobber(tempPath, targetPath string) error {
	_, err := publishNoClobberWithOps(tempPath, targetPath, reportFileOps{link: os.Link, remove: os.Remove})
	return err
}

func publishNoClobberWithOps(tempPath, targetPath string, ops reportFileOps) (PublishResult, error) {
	if err := ops.link(tempPath, targetPath); err != nil {
		return PublishResult{}, err
	}
	result := PublishResult{Published: true}
	// Once the link succeeds the target is committed; temporary-file removal is best effort.
	if err := ops.remove(tempPath); err != nil {
		if retryErr := ops.remove(tempPath); retryErr != nil {
			result.CleanupError = retryErr
		}
	}
	return result, nil
}
