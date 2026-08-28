package loginflow

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/b1rd33/nordmac/internal/credentials"
	"github.com/b1rd33/nordmac/internal/nordauth"
)

type fakeProvisioner struct {
	result nordauth.Provisioning
	err    error
	seen   []byte
}

func (provider *fakeProvisioner) Provision(_ context.Context, token []byte) (nordauth.Provisioning, error) {
	provider.seen = bytes.Clone(token)
	return nordauth.Provisioning{AccountID: provider.result.AccountID, PrivateKey: bytes.Clone(provider.result.PrivateKey)}, provider.err
}

type memoryStore struct {
	values     map[credentials.Kind][]byte
	failPutFor credentials.Kind
}

func newMemoryStore() *memoryStore { return &memoryStore{values: make(map[credentials.Kind][]byte)} }

func (store *memoryStore) Put(_ context.Context, kind credentials.Kind, value []byte) error {
	if store.failPutFor == kind {
		return errors.New("synthetic write failure containing no secret")
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
	value, ok := store.values[kind]
	if !ok {
		return credentials.ErrNotFound
	}
	credentials.Wipe(value)
	delete(store.values, kind)
	return nil
}

func TestLoginStoresProvisionedPair(t *testing.T) {
	provider := &fakeProvisioner{result: nordauth.Provisioning{AccountID: 42, PrivateKey: []byte("synthetic-private-key")}}
	store := newMemoryStore()
	token := []byte("0123456789abcdef")
	result, err := (Service{Provisioner: provider, Store: store}).Login(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if result.AccountID != 42 || !bytes.Equal(store.values[credentials.AccessToken], token) || !bytes.Equal(store.values[credentials.NordLynxPrivateKey], []byte("synthetic-private-key")) {
		t.Fatalf("result=%#v values=%#v", result, store.values)
	}
	if !bytes.Equal(provider.seen, token) || !bytes.Equal(token, []byte("0123456789abcdef")) {
		t.Fatal("caller token was modified")
	}
}

func TestLoginDoesNotWriteWhenProvisioningFails(t *testing.T) {
	store := newMemoryStore()
	_, err := (Service{Provisioner: &fakeProvisioner{err: nordauth.ErrUnauthorized}, Store: store}).Login(context.Background(), []byte("0123456789abcdef"))
	if !errors.Is(err, nordauth.ErrUnauthorized) || len(store.values) != 0 {
		t.Fatalf("error=%v values=%#v", err, store.values)
	}
}

func TestLoginRollsBackNewTokenWhenPrivateKeyWriteFails(t *testing.T) {
	store := newMemoryStore()
	store.failPutFor = credentials.NordLynxPrivateKey
	provider := &fakeProvisioner{result: nordauth.Provisioning{AccountID: 42, PrivateKey: []byte("synthetic-private-key")}}
	_, err := (Service{Provisioner: provider, Store: store}).Login(context.Background(), []byte("0123456789abcdef"))
	if !errors.Is(err, ErrCredentialTransaction) || len(store.values) != 0 {
		t.Fatalf("error=%v values=%#v", err, store.values)
	}
}

func TestLoginRestoresExistingPairWhenReplacementFails(t *testing.T) {
	store := newMemoryStore()
	store.values[credentials.AccessToken] = []byte("old-token")
	store.values[credentials.NordLynxPrivateKey] = []byte("old-private-key")
	store.failPutFor = credentials.NordLynxPrivateKey
	provider := &fakeProvisioner{result: nordauth.Provisioning{AccountID: 42, PrivateKey: []byte("new-private-key")}}
	_, err := (Service{Provisioner: provider, Store: store}).Login(context.Background(), []byte("new-token-abcdef"))
	if !errors.Is(err, ErrCredentialTransaction) || !errors.Is(err, ErrRollbackIncomplete) || !bytes.Equal(store.values[credentials.AccessToken], []byte("old-token")) || !bytes.Equal(store.values[credentials.NordLynxPrivateKey], []byte("old-private-key")) {
		t.Fatalf("error=%v values=%#v", err, store.values)
	}
}
