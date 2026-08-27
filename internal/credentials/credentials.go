// Package credentials defines the secret-storage boundary used by nordmac.
//
// Implementations must not persist secrets outside an operating-system secret
// store or expose them through logs, command arguments, JSON, or error text.
package credentials

import (
	"context"
	"errors"
	"fmt"
)

var ErrNotFound = errors.New("credential not found")

// Kind is the stable Keychain account name for one nordmac secret.
type Kind string

const (
	AccessToken        Kind = "access-token"
	NordLynxPrivateKey Kind = "nordlynx-private-key"
)

// Valid reports whether kind is a credential nordmac is allowed to store.
func (kind Kind) Valid() bool {
	switch kind {
	case AccessToken, NordLynxPrivateKey:
		return true
	default:
		return false
	}
}

// Validate rejects arbitrary account names at the secret-store boundary.
func (kind Kind) Validate() error {
	if !kind.Valid() {
		return fmt.Errorf("invalid credential kind %q", kind)
	}
	return nil
}

// Store persists secrets by a fixed Kind. Callers own returned byte slices and
// should wipe them as soon as they are no longer needed.
type Store interface {
	Put(context.Context, Kind, []byte) error
	Get(context.Context, Kind) ([]byte, error)
	Delete(context.Context, Kind) error
}

// Wipe overwrites a transient secret buffer. Go may retain other copies made by
// runtimes or dependencies, so callers should also avoid converting secrets to
// strings unless an operating-system API requires it.
func Wipe(secret []byte) {
	for index := range secret {
		secret[index] = 0
	}
}
