// Package state persists non-secret tunnel recovery journals. It does not
// choose the production root-owned directory; callers must inject that path.
package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/b1rd33/nordmac/internal/tunnel"
)

const maxJournalBytes = 1 << 20

type JournalStore struct {
	Directory string
}

func (store JournalStore) Create(ctx context.Context, journal tunnel.Journal) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := store.path(journal.SessionID)
	if err != nil {
		return err
	}
	data, err := encodeJournal(journal)
	if err != nil {
		return err
	}
	defer wipe(data)
	temporary, err := store.writeTemporary(data)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := os.Link(temporary, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("tunnel journal already exists")
		}
		return fmt.Errorf("publish tunnel journal: %w", err)
	}
	return syncDirectory(store.Directory)
}

func (store JournalStore) Update(ctx context.Context, journal tunnel.Journal) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := store.path(journal.SessionID)
	if err != nil {
		return err
	}
	if err := validateExisting(path); err != nil {
		return err
	}
	data, err := encodeJournal(journal)
	if err != nil {
		return err
	}
	defer wipe(data)
	temporary, err := store.writeTemporary(data)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("replace tunnel journal: %w", err)
	}
	return syncDirectory(store.Directory)
}

func (store JournalStore) Load(ctx context.Context, sessionID string) (tunnel.Journal, error) {
	if err := ctx.Err(); err != nil {
		return tunnel.Journal{}, err
	}
	path, err := store.path(sessionID)
	if err != nil {
		return tunnel.Journal{}, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return tunnel.Journal{}, tunnel.ErrJournalNotFound
	}
	if err != nil {
		return tunnel.Journal{}, fmt.Errorf("open tunnel journal: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return tunnel.Journal{}, errors.New("open tunnel journal: invalid file descriptor")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return tunnel.Journal{}, fmt.Errorf("inspect open tunnel journal: %w", err)
	}
	if err := validatePrivateInfo("tunnel journal", info, false); err != nil {
		return tunnel.Journal{}, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxJournalBytes+1))
	if err != nil {
		return tunnel.Journal{}, fmt.Errorf("read tunnel journal: %w", err)
	}
	defer wipe(data)
	if len(data) > maxJournalBytes {
		return tunnel.Journal{}, errors.New("tunnel journal exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var journal tunnel.Journal
	if err := decoder.Decode(&journal); err != nil {
		return tunnel.Journal{}, fmt.Errorf("decode tunnel journal: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return tunnel.Journal{}, errors.New("tunnel journal contains trailing data")
	}
	if err := journal.Validate(); err != nil {
		return tunnel.Journal{}, fmt.Errorf("validate tunnel journal: %w", err)
	}
	return journal, nil
}

func (store JournalStore) Delete(ctx context.Context, sessionID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := store.path(sessionID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); errors.Is(err, os.ErrNotExist) {
		return tunnel.ErrJournalNotFound
	} else if err != nil {
		return fmt.Errorf("delete tunnel journal: %w", err)
	}
	return syncDirectory(store.Directory)
}

func (store JournalStore) path(sessionID string) (string, error) {
	if !tunnel.ValidSessionID(sessionID) {
		return "", errors.New("invalid tunnel session id")
	}
	if store.Directory == "" || !filepath.IsAbs(store.Directory) {
		return "", errors.New("journal directory must be an absolute path")
	}
	if err := ensureDirectory(store.Directory); err != nil {
		return "", err
	}
	return filepath.Join(store.Directory, sessionID+".json"), nil
}

func (store JournalStore) writeTemporary(data []byte) (path string, retErr error) {
	file, err := os.CreateTemp(store.Directory, ".nordmac-journal-*")
	if err != nil {
		return "", fmt.Errorf("create temporary tunnel journal: %w", err)
	}
	path = file.Name()
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close temporary tunnel journal: %w", closeErr))
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return path, fmt.Errorf("secure temporary tunnel journal: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return path, fmt.Errorf("write temporary tunnel journal: %w", err)
	}
	if err := file.Sync(); err != nil {
		return path, fmt.Errorf("sync temporary tunnel journal: %w", err)
	}
	return path, nil
}

func encodeJournal(journal tunnel.Journal) ([]byte, error) {
	if err := journal.Validate(); err != nil {
		return nil, fmt.Errorf("refuse invalid tunnel journal: %w", err)
	}
	data, err := json.Marshal(journal)
	if err != nil {
		return nil, fmt.Errorf("encode tunnel journal: %w", err)
	}
	if len(data)+1 > maxJournalBytes {
		return nil, errors.New("tunnel journal exceeds size limit")
	}
	return append(data, '\n'), nil
}

func ensureDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create journal directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect journal directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("journal path is not a real directory")
	}
	return validatePrivateInfo("journal directory", info, true)
}

func validateExisting(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return tunnel.ErrJournalNotFound
	}
	if err != nil {
		return fmt.Errorf("inspect tunnel journal: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("tunnel journal is not a regular file")
	}
	return validatePrivateInfo("tunnel journal", info, false)
}

func validatePrivateInfo(kind string, info os.FileInfo, directory bool) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s permissions %04o are too broad", kind, info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%s is not owned by the current process uid", kind)
	}
	if directory != info.IsDir() {
		return fmt.Errorf("%s has the wrong file type", kind)
	}
	return nil
}

func syncDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open journal directory for sync: %w", err)
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync journal directory: %w", err)
	}
	return nil
}

func wipe(data []byte) {
	for index := range data {
		data[index] = 0
	}
}

var _ tunnel.JournalStore = JournalStore{}
