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

// Runner exists so tests can verify that secrets are sent on stdin and never
// placed in argv without touching the user's Keychain.
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

// Store is a macOS Keychain-backed credentials.Store. Constructing it does not
// read or modify the Keychain.
type Store struct {
	Runner   Runner
	Binary   string
	Service  string
	platform string
}

func New() Store {
	return Store{Runner: commandRunner{}, Binary: defaultBinary, Service: defaultService}
}

func (store Store) Put(ctx context.Context, kind credentials.Kind, secret []byte) error {
	if err := store.validate(kind); err != nil {
		return err
	}
	if len(secret) == 0 {
		return errors.New("refusing to store an empty credential")
	}
	if bytes.ContainsAny(secret, "\r\n\x00") {
		return errors.New("credential contains unsupported control characters")
	}

	// With -w last, security reads the password from its prompt. Supplying the
	// prompt input over stdin keeps the secret out of argv and process listings.
	stdin := make([]byte, len(secret)+1)
	copy(stdin, secret)
	stdin[len(secret)] = '\n'
	defer credentials.Wipe(stdin)

	_, stderr, err := store.runner().Run(ctx, stdin, store.binary(),
		"add-generic-password", "-U", "-a", string(kind), "-s", store.service(), "-w")
	if err != nil {
		return commandError("store credential", stderr, err)
	}
	return nil
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
