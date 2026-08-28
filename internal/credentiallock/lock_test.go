package credentiallock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileLockerIsExclusivePrivateAndReusable(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "credentials")
	locker := FileLocker{Directory: directory}
	release, err := locker.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := locker.Lock(context.Background()); !errors.Is(err, ErrHeld) {
		t.Fatalf("second lock error = %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	release, err = locker.Lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(directory, filename))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("info=%v err=%v", info, err)
	}
}

func TestFileLockerRejectsSymlinkAndBroadDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "credentials")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(directory, filename)); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileLocker{Directory: directory}).Lock(context.Background()); err == nil {
		t.Fatal("lock symlink unexpectedly accepted")
	}
	if err := os.Remove(filepath.Join(directory, filename)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileLocker{Directory: directory}).Lock(context.Background()); err == nil {
		t.Fatal("broad lock directory unexpectedly accepted")
	}
}
