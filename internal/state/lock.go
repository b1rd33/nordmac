package state

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/b1rd33/nordmac/internal/tunnel"
)

const lockFilename = "nordmac.lock"

// FileLocker serializes all tunnel transactions using one lock in the injected
// secure journal directory. It never waits: contention fails closed.
type FileLocker struct {
	Directory string
}

func (locker FileLocker) Acquire(ctx context.Context, sessionID string) (func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !tunnel.ValidSessionID(sessionID) {
		return nil, errors.New("invalid tunnel session id")
	}
	if locker.Directory == "" || !filepath.IsAbs(locker.Directory) {
		return nil, errors.New("lock directory must be an absolute path")
	}
	if err := ensureDirectory(locker.Directory); err != nil {
		return nil, err
	}
	path := filepath.Join(locker.Directory, lockFilename)
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open tunnel lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return nil, errors.New("open tunnel lock: invalid file descriptor")
	}
	closeOnError := func(err error) (func() error, error) {
		return nil, errors.Join(err, file.Close())
	}
	info, err := file.Stat()
	if err != nil {
		return closeOnError(fmt.Errorf("inspect tunnel lock: %w", err))
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return closeOnError(errors.New("tunnel lock must be a private regular file"))
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return closeOnError(errors.New("tunnel lock is not owned by the current process uid"))
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return closeOnError(tunnel.ErrLockHeld)
		}
		return closeOnError(fmt.Errorf("acquire tunnel lock: %w", err))
	}

	var once sync.Once
	var releaseErr error
	release := func() error {
		once.Do(func() {
			releaseErr = errors.Join(
				wrapIfError("unlock tunnel lock", syscall.Flock(fd, syscall.LOCK_UN)),
				wrapIfError("close tunnel lock", file.Close()),
			)
		})
		return releaseErr
	}
	return release, nil
}

func wrapIfError(action string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", action, err)
}

var _ tunnel.Locker = FileLocker{}
