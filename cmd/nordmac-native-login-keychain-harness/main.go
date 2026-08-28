// nordmac-native-login-keychain-harness validates one fixed synthetic item in
// the current unprivileged user's login Keychain. It cannot accept a service,
// account, Keychain path, or secret from the caller.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"
	"time"

	"github.com/b1rd33/nordmac/internal/credentials"
	"github.com/b1rd33/nordmac/internal/nativekeychain"
)

const validationService = "com.github.b1rd33.nordmac.validation.native"

var packageDirectoryPattern = regexp.MustCompile(`^nordmac-login-keychain-validation-[a-f0-9]{32}$`)

type result struct {
	SchemaVersion int    `json:"schema_version"`
	OK            bool   `json:"ok"`
	Operations    int    `json:"operations,omitempty"`
	ItemAbsent    bool   `json:"item_absent,omitempty"`
	Error         string `json:"error,omitempty"`
}

func main() {
	if err := run(); err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(result{SchemaVersion: 1, OK: false, Error: err.Error()})
		os.Exit(1)
	}
}

func run() (retErr error) {
	var helper string
	var helperSHA256 string
	var acknowledged bool
	flag.StringVar(&helper, "helper", "", "absolute path to the locally built validation helper")
	flag.StringVar(&helperSHA256, "helper-sha256", "", "expected SHA-256 of the validation helper")
	flag.BoolVar(&acknowledged, "ack-login-keychain-validation", false, "confirm the approved synthetic login Keychain lifecycle")
	flag.Parse()
	if runtime.GOOS != "darwin" || os.Geteuid() == 0 || !acknowledged {
		return errors.New("login Keychain validation requires an unprivileged macOS user and acknowledgement")
	}
	if err := verifyHelper(helper, helperSHA256); err != nil {
		return err
	}
	store, err := nativekeychain.NewLoginValidation(helper)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if existing, err := store.Get(ctx, credentials.AccessToken); err == nil {
		credentials.Wipe(existing)
		return errors.New("validation item already exists; refusing to overwrite or delete it")
	} else if !errors.Is(err, credentials.ErrNotFound) {
		return err
	}

	created := false
	defer func() {
		if !created {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		err := store.Delete(cleanupCtx, credentials.AccessToken)
		if err != nil && !errors.Is(err, credentials.ErrNotFound) {
			retErr = errors.Join(retErr, errors.New("deferred validation item cleanup failed"))
		}
	}()

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
	created = true
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
	created = false
	if remaining, err := store.Get(ctx, credentials.AccessToken); err == nil {
		credentials.Wipe(remaining)
		return errors.New("validation item remained after deletion")
	} else if !errors.Is(err, credentials.ErrNotFound) {
		return err
	}
	if err := independentAbsent(ctx); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result{SchemaVersion: 1, OK: true, Operations: 8, ItemAbsent: true})
}

func verifyHelper(path, expectedHex string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "nordmac-keychain-helper" {
		return errors.New("invalid packaged helper path")
	}
	directory := filepath.Dir(path)
	if filepath.Dir(directory) != "/private/tmp" || !packageDirectoryPattern.MatchString(filepath.Base(directory)) {
		return errors.New("invalid packaged helper directory")
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode().Perm() != 0o700 || !ownedByCurrentUser(directoryInfo) {
		return errors.New("packaged helper directory ownership or mode is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o500 || !ownedByCurrentUser(info) {
		return errors.New("packaged helper ownership or mode is invalid")
	}
	want, err := hex.DecodeString(expectedHex)
	if err != nil || len(want) != sha256.Size {
		return errors.New("invalid packaged helper SHA-256")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("open packaged helper")
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return errors.New("hash packaged helper")
	}
	if !bytes.Equal(digest.Sum(nil), want) {
		return errors.New("packaged helper SHA-256 mismatch")
	}
	return nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
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

func independentAbsent(ctx context.Context) error {
	command := exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password", "-s", validationService, "-a", string(credentials.AccessToken))
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	credentials.Wipe(stdout.Bytes())
	credentials.Wipe(stderr.Bytes())
	if err == nil {
		return errors.New("independent lookup found the validation item after deletion")
	}
	if exitError, ok := err.(*exec.ExitError); !ok || exitError.ExitCode() != 44 {
		return fmt.Errorf("independent deletion verification failed")
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
