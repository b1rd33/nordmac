// Package keychain stores nordmac secrets as generic-password items in the
// current user's default macOS Keychain.
package keychain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/b1rd33/nordmac/internal/credentials"
)

const (
	defaultBinary  = "/usr/bin/security"
	defaultService = "com.github.b1rd33.nordmac"
)

// ErrWriteUnavailable keeps credential writes disabled until a native secret
// boundary passes isolated and login-Keychain validation.
var ErrWriteUnavailable = errors.New("Keychain writes require a validated native secret boundary")

// Runner isolates the security(1) read/delete adapter for deterministic tests.
// Writes are disabled because prompted stdin proved unreliable live.
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

// Store is a fail-closed macOS Keychain credentials.Store. Get and Delete use
// security(1); Put remains disabled pending a native validated boundary.
type Store struct {
	Runner   Runner
	Binary   string
	Service  string
	platform string
}

func New() Store {
	return Store{Runner: commandRunner{}, Binary: defaultBinary, Service: defaultService}
}

func (store Store) Put(_ context.Context, kind credentials.Kind, _ []byte) error {
	if err := store.validate(kind); err != nil {
		return err
	}
	return ErrWriteUnavailable
}

func (store Store) Get(ctx context.Context, kind credentials.Kind) ([]byte, error) {
	if err := store.validate(kind); err != nil {
		return nil, err
	}
	stdout, stderr, err := store.runner().Run(ctx, nil, store.binary(),
		"find-generic-password", "-a", string(kind), "-s", store.service(), "-w")
	defer credentials.Wipe(stdout)
	if err != nil {
		if isNotFound(stderr) {
			return nil, credentials.ErrNotFound
		}
		return nil, commandError("read credential", stderr, err)
	}
	secret := bytes.TrimSuffix(stdout, []byte("\n"))
	secret = bytes.TrimSuffix(secret, []byte("\r"))
	if len(secret) == 0 {
		return nil, errors.New("Keychain returned an empty credential")
	}
	return bytes.Clone(secret), nil
}

func (store Store) Delete(ctx context.Context, kind credentials.Kind) error {
	if err := store.validate(kind); err != nil {
		return err
	}
	_, stderr, err := store.runner().Run(ctx, nil, store.binary(),
		"delete-generic-password", "-a", string(kind), "-s", store.service())
	if err != nil {
		if isNotFound(stderr) {
			return credentials.ErrNotFound
		}
		return commandError("delete credential", stderr, err)
	}
	return nil
}

func (store Store) validate(kind credentials.Kind) error {
	if store.platformName() != "darwin" {
		return errors.New("macOS Keychain is unavailable on this platform")
	}
	if err := kind.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(store.service()) == "" {
		return errors.New("Keychain service name is empty")
	}
	return nil
}

func (store Store) platformName() string {
	if store.platform != "" {
		return store.platform
	}
	return runtime.GOOS
}

func (store Store) runner() Runner {
	if store.Runner != nil {
		return store.Runner
	}
	return commandRunner{}
}

func (store Store) binary() string {
	if store.Binary != "" {
		return store.Binary
	}
	return defaultBinary
}

func (store Store) service() string {
	if store.Service != "" {
		return store.Service
	}
	return defaultService
}

func isNotFound(stderr []byte) bool {
	message := strings.ToLower(string(stderr))
	return strings.Contains(message, "could not be found") || strings.Contains(message, "errsecitemnotfound")
}

func commandError(action string, stderr []byte, err error) error {
	// Do not propagate external stderr. A secret should never be written there,
	// but treating the external process as untrusted prevents an accidental echo
	// from entering nordmac errors or logs.
	_ = stderr
	return fmt.Errorf("%s: %w", action, err)
}

var _ credentials.Store = Store{}
