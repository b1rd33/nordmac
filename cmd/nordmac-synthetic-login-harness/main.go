// nordmac-synthetic-login-harness exercises the complete candidate login flow
// against loopback and an explicitly owned temporary Keychain only.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/b1rd33/nordmac/internal/credentials"
	"github.com/b1rd33/nordmac/internal/loginflow"
	"github.com/b1rd33/nordmac/internal/nativekeychain"
	"github.com/b1rd33/nordmac/internal/nordauth"
	"github.com/b1rd33/nordmac/internal/tunnel"
)

const (
	helperPath          = "/private/tmp/nordmac-synthetic-login-helper"
	syntheticToken      = "0123456789abcdef0123456789abcdef"
	syntheticPrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

type result struct {
	SchemaVersion int    `json:"schema_version"`
	OK            bool   `json:"ok"`
	Operations    int    `json:"operations,omitempty"`
	Requests      int32  `json:"requests,omitempty"`
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
	flag.BoolVar(&acknowledged, "ack-synthetic-login", false, "confirm loopback and isolated-Keychain login simulation")
	flag.Parse()
	if runtime.GOOS != "darwin" || os.Geteuid() == 0 || !acknowledged || !tunnel.ValidSessionID(session) {
		return errors.New("synthetic login requires an unprivileged macOS user, acknowledgement, and valid session")
	}

	directory := filepath.Join("/private/tmp", "nordmac-keychain-native-validation-"+session)
	if err := os.Mkdir(directory, 0o700); err != nil {
		return errors.New("create synthetic login directory")
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

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method != http.MethodGet || request.URL.Path != "/v1/users/services/credentials" || request.Header.Get("Authorization") != "Bearer "+syntheticToken {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"id":42,"created_at":"synthetic","updated_at":"synthetic","username":"synthetic","password":"synthetic","nordlynx_private_key":"`+syntheticPrivateKey+`"}`)
	}))
	defer server.Close()

	token := []byte(syntheticToken)
	defer credentials.Wipe(token)
	login := loginflow.Service{
		Provisioner: nordauth.Client{BaseURL: server.URL, HTTP: server.Client()},
		Store:       store,
	}
	loginResult, err := login.Login(ctx, token)
	if err != nil || loginResult.AccountID != 42 {
		return errors.New("synthetic login transaction failed")
	}
	if err := verify(ctx, store, credentials.AccessToken, []byte(syntheticToken)); err != nil {
		return err
	}
	if err := verify(ctx, store, credentials.NordLynxPrivateKey, []byte(syntheticPrivateKey)); err != nil {
		return err
	}
	if err := store.Delete(ctx, credentials.AccessToken); err != nil {
		return err
	}
	if err := store.Delete(ctx, credentials.NordLynxPrivateKey); err != nil {
		return err
	}
	if err := absent(ctx, store, credentials.AccessToken); err != nil {
		return err
	}
	if err := absent(ctx, store, credentials.NordLynxPrivateKey); err != nil {
		return err
	}
	if requests.Load() != 1 {
		return fmt.Errorf("synthetic login made %d requests", requests.Load())
	}
	return json.NewEncoder(os.Stdout).Encode(result{SchemaVersion: 1, OK: true, Operations: 9, Requests: requests.Load()})
}

func verify(ctx context.Context, store nativekeychain.Store, kind credentials.Kind, expected []byte) error {
	actual, err := store.Get(ctx, kind)
	if err != nil {
		return err
	}
	defer credentials.Wipe(actual)
	if !bytes.Equal(actual, expected) {
		return errors.New("synthetic stored credential mismatch")
	}
	return nil
}

func absent(ctx context.Context, store nativekeychain.Store, kind credentials.Kind) error {
	value, err := store.Get(ctx, kind)
	credentials.Wipe(value)
	if !errors.Is(err, credentials.ErrNotFound) {
		return errors.New("synthetic credential remained after deletion")
	}
	return nil
}

func security(ctx context.Context, arguments ...string) error {
	command := exec.CommandContext(ctx, "/usr/bin/security", arguments...)
	if err := command.Run(); err != nil {
		return errors.New("temporary Keychain lifecycle command failed")
	}
	return nil
}
