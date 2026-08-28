package nativekeychain

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/b1rd33/nordmac/internal/credentials"
)

type call struct {
	stdin []byte
	path  string
	args  []string
}

type fakeRunner struct {
	stdout []byte
	calls  []call
}

func (runner *fakeRunner) Run(_ context.Context, stdin []byte, path string, args ...string) ([]byte, []byte, error) {
	runner.calls = append(runner.calls, call{stdin: bytes.Clone(stdin), path: path, args: append([]string(nil), args...)})
	return bytes.Clone(runner.stdout), nil, nil
}

func TestPutKeepsSecretOutOfArguments(t *testing.T) {
	runner := &fakeRunner{}
	store := Store{
		Runner: runner, Helper: "/private/tmp/nordmac-keychain-native-helper",
		Keychain: "/private/tmp/nordmac-keychain-native-validation-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/validation.keychain-db",
		Target:   "isolated",
	}
	secret := []byte("synthetic-secret")
	if err := store.Put(context.Background(), credentials.AccessToken, secret); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 || !bytes.Equal(runner.calls[0].stdin, secret) {
		t.Fatalf("unexpected call: %#v", runner.calls)
	}
	if strings.Contains(strings.Join(runner.calls[0].args, " "), string(secret)) {
		t.Fatal("secret appeared in helper arguments")
	}
	want := []string{"put", "access-token", "--validation-keychain", store.Keychain}
	if !reflect.DeepEqual(runner.calls[0].args, want) {
		t.Fatalf("args = %#v, want %#v", runner.calls[0].args, want)
	}
}

func TestLoginValidationUsesFixedTarget(t *testing.T) {
	store, err := NewLoginValidation("/private/tmp/nordmac-keychain-native-helper")
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	store.Runner = runner
	if err := store.Put(context.Background(), credentials.AccessToken, []byte("synthetic-secret")); err != nil {
		t.Fatal(err)
	}
	want := []string{"put", "access-token", "--login-keychain-validation"}
	if !reflect.DeepEqual(runner.calls[0].args, want) {
		t.Fatalf("args = %#v, want %#v", runner.calls[0].args, want)
	}
}

func TestCreateValidationUsesCreateOnlyOperation(t *testing.T) {
	store, err := NewLoginValidation("/private/tmp/nordmac-keychain-native-helper")
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	store.Runner = runner
	if err := store.CreateValidation(context.Background(), credentials.AccessToken, []byte("synthetic-secret")); err != nil {
		t.Fatal(err)
	}
	want := []string{"create", "access-token", "--login-keychain-validation"}
	if !reflect.DeepEqual(runner.calls[0].args, want) {
		t.Fatalf("args = %#v, want %#v", runner.calls[0].args, want)
	}
}

func TestReplaceValidationUsesUpdateOnlyOperation(t *testing.T) {
	store, err := NewLoginValidation("/private/tmp/nordmac-keychain-native-helper")
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	store.Runner = runner
	if err := store.ReplaceValidation(context.Background(), credentials.AccessToken, []byte("synthetic-secret")); err != nil {
		t.Fatal(err)
	}
	want := []string{"replace", "access-token", "--login-keychain-validation"}
	if !reflect.DeepEqual(runner.calls[0].args, want) {
		t.Fatalf("args = %#v, want %#v", runner.calls[0].args, want)
	}
}

func TestValidationConstructorRejectsArbitraryTargets(t *testing.T) {
	valid := "/private/tmp/nordmac-keychain-native-validation-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/validation.keychain-db"
	if _, err := NewValidation("/private/tmp/nordmac-keychain-native-helper", valid); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative", "/Users/example/Library/Keychains/login.keychain-db", "/private/tmp/other/validation.keychain-db"} {
		if _, err := NewValidation("/private/tmp/nordmac-keychain-native-helper", path); err == nil {
			t.Fatalf("path %q unexpectedly accepted", path)
		}
	}
}
