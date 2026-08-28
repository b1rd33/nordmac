// Package nativekeychain is the Go boundary for the native macOS Keychain
// helper. Only the isolated validation target is enabled in this phase.
package nativekeychain

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"regexp"

	"github.com/b1rd33/nordmac/internal/credentials"
)

var validationDirectoryPattern = regexp.MustCompile(`^nordmac-keychain-native-validation-[a-f0-9]{32}$`)

type Runner interface {
	Run(context.Context, []byte, string, ...string) ([]byte, []byte, error)
}

type commandRunner struct{}

func (commandRunner) Run(ctx context.Context, stdin []byte, binary string, args ...string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, binary, args...)
	command.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

type Store struct {
	Runner   Runner
	Helper   string
	Keychain string
}

func NewValidation(helper, keychainPath string) (Store, error) {
	if !filepath.IsAbs(helper) || filepath.Clean(helper) != helper {
		return Store{}, errors.New("native Keychain helper path must be absolute and canonical")
	}
	clean := filepath.Clean(keychainPath)
	if !filepath.IsAbs(clean) || filepath.Base(clean) != "validation.keychain-db" ||
		filepath.Dir(filepath.Dir(clean)) != "/private/tmp" ||
		!validationDirectoryPattern.MatchString(filepath.Base(filepath.Dir(clean))) {
		return Store{}, errors.New("invalid native validation Keychain path")
	}
	return Store{Runner: commandRunner{}, Helper: helper, Keychain: clean}, nil
}

func (store Store) Put(ctx context.Context, kind credentials.Kind, secret []byte) error {
	if err := store.validate(kind); err != nil {
		return err
	}
	if len(secret) == 0 || len(secret) > 4096 {
		return errors.New("invalid credential length")
	}
	copy := bytes.Clone(secret)
	defer credentials.Wipe(copy)
	_, stderr, err := store.runner().Run(ctx, copy, store.Helper, store.arguments("put", kind)...)
	credentials.Wipe(stderr)
	if err != nil {
		return errors.New("native Keychain write failed")
	}
	return nil
}

func (store Store) Get(ctx context.Context, kind credentials.Kind) ([]byte, error) {
	if err := store.validate(kind); err != nil {
		return nil, err
	}
	stdout, stderr, err := store.runner().Run(ctx, nil, store.Helper, store.arguments("get", kind)...)
	credentials.Wipe(stderr)
	if err != nil {
		credentials.Wipe(stdout)
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 44 {
			return nil, credentials.ErrNotFound
		}
		return nil, errors.New("native Keychain read failed")
	}
	if len(stdout) == 0 || len(stdout) > 4096 {
		credentials.Wipe(stdout)
		return nil, errors.New("native Keychain returned invalid credential data")
	}
	return stdout, nil
}

func (store Store) Delete(ctx context.Context, kind credentials.Kind) error {
	if err := store.validate(kind); err != nil {
		return err
	}
	stdout, stderr, err := store.runner().Run(ctx, nil, store.Helper, store.arguments("delete", kind)...)
	credentials.Wipe(stdout)
	credentials.Wipe(stderr)
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 44 {
			return credentials.ErrNotFound
		}
		return errors.New("native Keychain delete failed")
	}
	return nil
}

func (store Store) validate(kind credentials.Kind) error {
	if err := kind.Validate(); err != nil {
		return err
	}
	if store.Runner == nil || store.Helper == "" || store.Keychain == "" {
		return errors.New("native Keychain validation store is incomplete")
	}
	return nil
}

func (store Store) arguments(operation string, kind credentials.Kind) []string {
	return []string{operation, string(kind), "--validation-keychain", store.Keychain}
}

func (store Store) runner() Runner { return store.Runner }

var _ credentials.Store = Store{}
