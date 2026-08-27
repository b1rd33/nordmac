package state

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b1rd33/nordmac/internal/tunnel"
)

func TestFileLockerIsExclusiveAndReusable(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "runtime")
	locker := FileLocker{Directory: directory}
	sessionID := strings.Repeat("a", 32)
	firstRelease, err := locker.Acquire(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	if _, err := locker.Acquire(context.Background(), sessionID); !errors.Is(err, tunnel.ErrLockHeld) {
		t.Fatalf("second Acquire error = %v, want ErrLockHeld", err)
	}
	if err := firstRelease(); err != nil {
		t.Fatalf("first release: %v", err)
	}
	if err := firstRelease(); err != nil {
		t.Fatalf("idempotent release: %v", err)
	}
	secondRelease, err := locker.Acquire(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("Acquire after release: %v", err)
	}
	if err := secondRelease(); err != nil {
		t.Fatalf("second release: %v", err)
	}

	info, err := os.Stat(filepath.Join(directory, lockFilename))
	if err != nil {
		t.Fatalf("Stat lock: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("lock mode = %04o, want 0600", got)
	}
}

func TestFileLockerRejectsSymlinkAndInvalidIdentity(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(directory, lockFilename)); err != nil {
		t.Fatal(err)
	}
	locker := FileLocker{Directory: directory}
	if _, err := locker.Acquire(context.Background(), strings.Repeat("a", 32)); err == nil {
		t.Fatal("Acquire unexpectedly followed a lock symlink")
	}
	if _, err := locker.Acquire(context.Background(), "../outside"); err == nil {
		t.Fatal("Acquire unexpectedly accepted an invalid session id")
	}
}
