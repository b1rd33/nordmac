// Package credentiallock serializes credential replacement transactions.
package credentiallock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

var ErrHeld = errors.New("another credential transaction is active")

const filename = "credentials.lock"

type FileLocker struct {
	Directory string
}

func (locker FileLocker) Lock(ctx context.Context) (func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if locker.Directory == "" || !filepath.IsAbs(locker.Directory) || filepath.Clean(locker.Directory) != locker.Directory {
		return nil, errors.New("credential lock directory must be absolute and canonical")
	}
	if err := ensureDirectory(locker.Directory); err != nil {
		return nil, err
	}
	path := filepath.Join(locker.Directory, filename)
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("open credential lock")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return nil, errors.New("open credential lock")
	}
	closeOnError := func(lockErr error) (func() error, error) {
		return nil, errors.Join(lockErr, file.Close())
	}
	info, err := file.Stat()
	if err != nil {
		return closeOnError(errors.New("inspect credential lock"))
	}
	if err := validatePrivate("credential lock", info, false); err != nil {
		return closeOnError(err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return closeOnError(ErrHeld)
		}
		return closeOnError(errors.New("acquire credential lock"))
	}
	var once sync.Once
	var releaseErr error
	return func() error {
		once.Do(func() {
			releaseErr = errors.Join(
				wrap("unlock credential lock", syscall.Flock(fd, syscall.LOCK_UN)),
				wrap("close credential lock", file.Close()),
			)
		})
		return releaseErr
	}, nil
}

func ensureDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("create credential lock directory")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return errors.New("inspect credential lock directory")
	}
	return validatePrivate("credential lock directory", info, true)
}

func validatePrivate(kind string, info os.FileInfo, directory bool) error {
	if directory != info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s has the wrong file type", kind)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s permissions are too broad", kind)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%s is not owned by the current uid", kind)
	}
	return nil
}

func wrap(action string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", action, err)
}
