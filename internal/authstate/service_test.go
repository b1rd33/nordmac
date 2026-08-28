package authstate

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/b1rd33/nordmac/internal/credentials"
)

type memoryStore struct {
	values        map[credentials.Kind][]byte
	failDeleteFor credentials.Kind
	failPutFor    credentials.Kind
}

func newMemoryStore() *memoryStore { return &memoryStore{values: make(map[credentials.Kind][]byte)} }

func (store *memoryStore) Put(_ context.Context, kind credentials.Kind, value []byte) error {
	if store.failPutFor == kind {
		return errors.New("synthetic put failure")
	}
	credentials.Wipe(store.values[kind])
	store.values[kind] = bytes.Clone(value)
	return nil
}

func (store *memoryStore) Get(_ context.Context, kind credentials.Kind) ([]byte, error) {
	value, ok := store.values[kind]
	if !ok {
		return nil, credentials.ErrNotFound
	}
	return bytes.Clone(value), nil
}

func (store *memoryStore) Delete(_ context.Context, kind credentials.Kind) error {
	if store.failDeleteFor == kind {
		return errors.New("synthetic delete failure")
	}
	value, ok := store.values[kind]
	if !ok {
		return credentials.ErrNotFound
	}
	credentials.Wipe(value)
	delete(store.values, kind)
	return nil
}

type fakeLocker struct {
	err        error
	releaseErr error
}

func (locker fakeLocker) Lock(context.Context) (func() error, error) {
	if locker.err != nil {
		return nil, locker.err
	}
	return func() error { return locker.releaseErr }, nil
}

func TestInspectReportsAllCredentialStates(t *testing.T) {
	for name, values := range map[string]map[credentials.Kind][]byte{
		"logged out": {},
		"logged in": {
			credentials.AccessToken: []byte("token"), credentials.NordLynxPrivateKey: []byte("key"),
		},
		"inconsistent token": {credentials.AccessToken: []byte("token")},
		"inconsistent key":   {credentials.NordLynxPrivateKey: []byte("key")},
	} {
		t.Run(name, func(t *testing.T) {
			store := newMemoryStore()
			store.values = values
			got, err := (Service{Store: store, Locker: fakeLocker{}}).Inspect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			wantState := Inconsistent
			if len(values) == 0 {
				wantState = LoggedOut
			} else if len(values) == 2 {
				wantState = LoggedIn
			}
			if got.State != wantState || got.RepairNeeded != (wantState == Inconsistent) {
				t.Fatalf("status = %#v, want state %q", got, wantState)
			}
		})
	}
}

func TestLogoutLocalRemovesCompleteAndPartialState(t *testing.T) {
	for name, values := range map[string]map[credentials.Kind][]byte{
		"complete": {
			credentials.AccessToken: []byte("token"), credentials.NordLynxPrivateKey: []byte("key"),
		},
		"partial": {credentials.AccessToken: []byte("token")},
	} {
		t.Run(name, func(t *testing.T) {
			store := newMemoryStore()
			store.values = values
			result, err := (Service{Store: store, Locker: fakeLocker{}}).LogoutLocal(context.Background())
			if err != nil || !result.LocalCredentialsRemoved || result.RemoteTokenRevoked || len(store.values) != 0 {
				t.Fatalf("result=%#v error=%v values=%#v", result, err, store.values)
			}
		})
	}
}

func TestLogoutLocalRestoresPairAfterPartialDeleteFailure(t *testing.T) {
	store := newMemoryStore()
	store.values[credentials.AccessToken] = []byte("old-token")
	store.values[credentials.NordLynxPrivateKey] = []byte("old-key")
	store.failDeleteFor = credentials.NordLynxPrivateKey
	_, err := (Service{Store: store, Locker: fakeLocker{}}).LogoutLocal(context.Background())
	if !errors.Is(err, ErrCredentialTransaction) || !bytes.Equal(store.values[credentials.AccessToken], []byte("old-token")) || !bytes.Equal(store.values[credentials.NordLynxPrivateKey], []byte("old-key")) {
		t.Fatalf("error=%v values=%#v", err, store.values)
	}
}

func TestServiceFailsClosedWhenLockIsHeld(t *testing.T) {
	service := Service{Store: newMemoryStore(), Locker: fakeLocker{err: errors.New("held")}}
	if _, err := service.Inspect(context.Background()); !errors.Is(err, ErrCredentialLock) {
		t.Fatalf("inspect error = %v", err)
	}
	if _, err := service.LogoutLocal(context.Background()); !errors.Is(err, ErrCredentialLock) {
		t.Fatalf("logout error = %v", err)
	}
}

func TestLogoutReportsIncompleteRollback(t *testing.T) {
	store := newMemoryStore()
	store.values[credentials.AccessToken] = []byte("old-token")
	store.values[credentials.NordLynxPrivateKey] = []byte("old-key")
	store.failDeleteFor = credentials.NordLynxPrivateKey
	store.failPutFor = credentials.AccessToken
	_, err := (Service{Store: store, Locker: fakeLocker{}}).LogoutLocal(context.Background())
	if !errors.Is(err, ErrCredentialTransaction) || !errors.Is(err, ErrRollbackIncomplete) {
		t.Fatalf("error = %v", err)
	}
}

func TestInspectReportsReleaseFailure(t *testing.T) {
	service := Service{Store: newMemoryStore(), Locker: fakeLocker{releaseErr: errors.New("synthetic release failure")}}
	result, err := service.Inspect(context.Background())
	if !errors.Is(err, ErrCredentialLock) || result.State != "" {
		t.Fatalf("result=%#v error=%v", result, err)
	}
}
