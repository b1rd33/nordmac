package keychain

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/b1rd33/nordmac/internal/credentials"
)

type call struct {
	stdin  []byte
	binary string
	args   []string
}

type fakeRunner struct {
	stdout []byte
	stderr []byte
	err    error
	calls  []call
}

func (runner *fakeRunner) Run(_ context.Context, stdin []byte, binary string, args ...string) ([]byte, []byte, error) {
	runner.calls = append(runner.calls, call{stdin: bytes.Clone(stdin), binary: binary, args: append([]string(nil), args...)})
	return bytes.Clone(runner.stdout), bytes.Clone(runner.stderr), runner.err
}

func TestPutKeepsSecretOutOfArguments(t *testing.T) {
	runner := &fakeRunner{}
	store := Store{Runner: runner, platform: "darwin"}
	secret := []byte("synthetic-token-123")

	if err := store.Put(context.Background(), credentials.AccessToken, secret); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(runner.calls))
	}
	got := runner.calls[0]
	if strings.Contains(strings.Join(got.args, " "), string(secret)) {
		t.Fatal("secret appeared in command arguments")
	}
	if !bytes.Equal(got.stdin, append(bytes.Clone(secret), '\n')) {
		t.Fatalf("stdin was not the expected prompted secret")
	}
	wantArgs := []string{"add-generic-password", "-U", "-a", "access-token", "-s", defaultService, "-w"}
	if !reflect.DeepEqual(got.args, wantArgs) {
		t.Fatalf("args = %#v, want %#v", got.args, wantArgs)
	}
	if !bytes.Equal(secret, []byte("synthetic-token-123")) {
		t.Fatal("Put modified the caller-owned secret")
	}
}

func TestPutRejectsUnsafeValuesBeforeRunner(t *testing.T) {
	runner := &fakeRunner{}
	store := Store{Runner: runner, platform: "darwin"}
	for _, secret := range [][]byte{nil, {}, []byte("line\nbreak"), []byte{'a', 0, 'b'}} {
		if err := store.Put(context.Background(), credentials.AccessToken, secret); err == nil {
			t.Fatalf("Put(%q) unexpectedly succeeded", secret)
		}
	}
	if len(runner.calls) != 0 {
		t.Fatal("runner was called for an invalid secret")
	}
}

func TestPutErrorCannotEchoSecret(t *testing.T) {
	secret := []byte("synthetic-token-123")
	runner := &fakeRunner{stderr: append([]byte("unexpected echo: "), secret...), err: errors.New("exit status 1")}
	store := Store{Runner: runner, platform: "darwin"}
	err := store.Put(context.Background(), credentials.AccessToken, secret)
	if err == nil {
		t.Fatal("Put unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), string(secret)) {
		t.Fatal("secret appeared in the returned error")
	}
}

func TestGetReturnsSecretWithoutSecurityNewline(t *testing.T) {
	runner := &fakeRunner{stdout: []byte("synthetic-private-key=\n")}
	store := Store{Runner: runner, platform: "darwin"}
	secret, err := store.Get(context.Background(), credentials.NordLynxPrivateKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(secret) != "synthetic-private-key=" {
		t.Fatalf("secret = %q", secret)
	}
	wantArgs := []string{"find-generic-password", "-a", "nordlynx-private-key", "-s", defaultService, "-w"}
	if !reflect.DeepEqual(runner.calls[0].args, wantArgs) {
		t.Fatalf("args = %#v, want %#v", runner.calls[0].args, wantArgs)
	}
}

func TestGetAndDeleteMapNotFound(t *testing.T) {
	for _, operation := range []string{"get", "delete"} {
		t.Run(operation, func(t *testing.T) {
			runner := &fakeRunner{stderr: []byte("security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain."), err: errors.New("exit status 44")}
			store := Store{Runner: runner, platform: "darwin"}
			var err error
			if operation == "get" {
				_, err = store.Get(context.Background(), credentials.AccessToken)
			} else {
				err = store.Delete(context.Background(), credentials.AccessToken)
			}
			if !errors.Is(err, credentials.ErrNotFound) {
				t.Fatalf("error = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestRejectsArbitraryCredentialKind(t *testing.T) {
	runner := &fakeRunner{}
	store := Store{Runner: runner, platform: "darwin"}
	if _, err := store.Get(context.Background(), credentials.Kind("other")); err == nil {
		t.Fatal("Get unexpectedly accepted an arbitrary kind")
	}
	if len(runner.calls) != 0 {
		t.Fatal("runner was called for an invalid kind")
	}
}
