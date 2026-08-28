package keychain

import (
	"bytes"
	"context"
	"errors"
	"reflect"
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

func TestPutFailsClosedBeforeRunner(t *testing.T) {
	runner := &fakeRunner{}
	store := Store{Runner: runner, platform: "darwin"}
	secret := []byte("synthetic-token-123")

	if err := store.Put(context.Background(), credentials.AccessToken, secret); !errors.Is(err, ErrWriteUnavailable) {
		t.Fatalf("Put error = %v, want ErrWriteUnavailable", err)
	}
	if len(runner.calls) != 0 {
		t.Fatal("runner was called for a disabled write")
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
