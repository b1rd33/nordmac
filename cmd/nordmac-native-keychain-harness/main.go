// nordmac-native-keychain-harness validates the native helper against one
// explicitly owned temporary Keychain using random synthetic data only.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/b1rd33/nordmac/internal/credentials"
	"github.com/b1rd33/nordmac/internal/nativekeychain"
	"github.com/b1rd33/nordmac/internal/tunnel"
)

const helperPath = "/private/tmp/nordmac-keychain-native-helper"

type result struct {
	SchemaVersion int    `json:"schema_version"`
	OK            bool   `json:"ok"`
	Operations    int    `json:"operations,omitempty"`
	Error         string `json:"error,omitempty"`
}

func main() {
	if err := run(); err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(result{SchemaVersion: 1, OK: false, Error: err.Error()})
		os.Exit(1)
	}
}

func run() (retErr error) {
	var session string
	var acknowledged bool
	flag.StringVar(&session, "session", "", "32-character lowercase hex validation session")
	flag.BoolVar(&acknowledged, "ack-native-keychain", false, "confirm isolated native Keychain validation")
	flag.Parse()
	if runtime.GOOS != "darwin" || os.Geteuid() == 0 || !acknowledged || !tunnel.ValidSessionID(session) {
		return errors.New("native Keychain validation requires an unprivileged macOS user, acknowledgement, and valid session")
	}
	directory := filepath.Join("/private/tmp", "nordmac-keychain-native-validation-"+session)
	if err := os.Mkdir(directory, 0o700); err != nil {
		return fmt.Errorf("create validation directory: %w", err)
	}
	keychainPath := filepath.Join(directory, "validation.keychain-db")
	created := false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if created {
			retErr = errors.Join(retErr, security(cleanupCtx, "delete-keychain", keychainPath))
		}
		retErr = errors.Join(retErr, os.RemoveAll(directory))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := security(ctx, "create-keychain", "-p", "", keychainPath); err != nil {
		return err
	}
	created = true
	if err := security(ctx, "unlock-keychain", "-p", "", keychainPath); err != nil {
		return err
	}
	store, err := nativekeychain.NewValidation(helperPath, keychainPath)
	if err != nil {
		return err
	}
	first, err := secret()
	if err != nil {
		return err
	}
	defer credentials.Wipe(first)
	second, err := secret()
	if err != nil {
		return err
	}
	defer credentials.Wipe(second)
	if err := store.CreateValidation(ctx, credentials.AccessToken, first); err != nil {
		return err
	}
	if err := verify(ctx, store, first); err != nil {
		return err
	}
	if err := store.ReplaceValidation(ctx, credentials.AccessToken, second); err != nil {
		return err
	}
	if err := verify(ctx, store, second); err != nil {
		return err
	}
	if err := store.Delete(ctx, credentials.AccessToken); err != nil {
		return err
	}
	if remaining, err := store.Get(ctx, credentials.AccessToken); err == nil {
		credentials.Wipe(remaining)
		return errors.New("native validation item remained after deletion")
	} else if !errors.Is(err, credentials.ErrNotFound) {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result{SchemaVersion: 1, OK: true, Operations: 7})
}

func verify(ctx context.Context, store nativekeychain.Store, expected []byte) error {
	actual, err := store.Get(ctx, credentials.AccessToken)
	if err != nil {
		return err
	}
	defer credentials.Wipe(actual)
	if !bytes.Equal(actual, expected) {
		return errors.New("native Keychain returned different data")
	}
	return nil
}

func secret() ([]byte, error) {
	raw := make([]byte, 32)
	defer credentials.Wipe(raw)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	encoded := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(encoded, raw)
	return encoded, nil
}

func security(ctx context.Context, args ...string) error {
	command := exec.CommandContext(ctx, "/usr/bin/security", args...)
	if err := command.Run(); err != nil {
		return errors.New("temporary Keychain lifecycle command failed")
	}
	return nil
}
