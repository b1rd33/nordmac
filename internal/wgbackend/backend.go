// Package wgbackend owns the approval-gated WireGuard userspace device.
// It deliberately does not configure addresses, routes, DNS, or PF.
package wgbackend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/b1rd33/nordmac/internal/helperproto"
	"github.com/b1rd33/nordmac/internal/tunnel"
)

var (
	ErrSessionExists     = errors.New("WireGuard session already exists")
	ErrSessionNotFound   = errors.New("WireGuard session not found")
	ErrOwnershipMismatch = errors.New("WireGuard device ownership mismatch")
)

// SecretSource lends a session's keys exactly once and wipes its owned copy
// after consume returns. Implementations must not persist or log the keys.
type SecretSource interface {
	Consume(context.Context, string, func(*helperproto.DeviceSecrets) error) error
}

type RuntimeFactory interface {
	Create(int) (Runtime, error)
}

type AddressConfigurer interface {
	Apply(context.Context, tunnel.InterfaceAddress) error
}

type Runtime interface {
	Name() string
	Configure(tunnel.DeviceSpec, *helperproto.DeviceSecrets) error
	Up() error
	Snapshot() (Snapshot, error)
	Close() error
}

type Snapshot struct {
	LastHandshake time.Time `json:"last_handshake"`
	Transmitted   uint64    `json:"transmitted_bytes"`
	Received      uint64    `json:"received_bytes"`
}

// Manager implements tunnel.DeviceManager while retaining exact in-process
// ownership. If the process dies, the utun file descriptor closes and macOS
// removes the interface.
type Manager struct {
	Secrets    SecretSource
	Factory    RuntimeFactory
	Addresses  AddressConfigurer
	DeviceOnly bool
	PID        int

	mu       sync.Mutex
	sessions map[string]ownedRuntime
}

type ownedRuntime struct {
	handle  tunnel.DeviceHandle
	runtime Runtime
}

func (manager *Manager) Create(ctx context.Context, spec tunnel.DeviceSpec) (tunnel.DeviceHandle, error) {
	if err := validateSpec(spec); err != nil {
		return tunnel.DeviceHandle{}, err
	}
	if manager.Secrets == nil || manager.Factory == nil {
		return tunnel.DeviceHandle{}, errors.New("WireGuard backend is incomplete")
	}
	if manager.Addresses == nil && !manager.DeviceOnly {
		return tunnel.DeviceHandle{}, errors.New("WireGuard address configurer is missing")
	}
	pid := manager.PID
	if pid == 0 {
		pid = os.Getpid()
	}
	if pid <= 0 {
		return tunnel.DeviceHandle{}, errors.New("invalid WireGuard owner process")
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.sessions == nil {
		manager.sessions = make(map[string]ownedRuntime)
	}
	if _, exists := manager.sessions[spec.SessionID]; exists {
		return tunnel.DeviceHandle{}, ErrSessionExists
	}

	var created Runtime
	err := manager.Secrets.Consume(ctx, spec.SessionID, func(secrets *helperproto.DeviceSecrets) error {
		if err := verifyPeerFingerprint(spec.PeerFingerprint, secrets); err != nil {
			return err
		}
		var err error
		created, err = manager.Factory.Create(spec.MTU)
		if err != nil {
			return fmt.Errorf("create userspace WireGuard runtime: %w", err)
		}
		if err := created.Configure(spec, secrets); err != nil {
			return fmt.Errorf("configure userspace WireGuard runtime: %w", err)
		}
		if err := created.Up(); err != nil {
			return fmt.Errorf("bring userspace WireGuard runtime up: %w", err)
		}
		if manager.Addresses != nil {
			if err := manager.Addresses.Apply(ctx, tunnel.InterfaceAddress{Interface: created.Name(), Prefix: spec.Address}); err != nil {
				return fmt.Errorf("configure userspace WireGuard address: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		if created != nil {
			_ = created.Close()
		}
		return tunnel.DeviceHandle{}, err
	}

	handle := tunnel.DeviceHandle{Interface: created.Name(), OwnerPID: pid}
	if err := handle.Validate(); err != nil {
		_ = created.Close()
		return tunnel.DeviceHandle{}, fmt.Errorf("invalid userspace WireGuard handle: %w", err)
	}
	manager.sessions[spec.SessionID] = ownedRuntime{handle: handle, runtime: created}
	return handle, nil
}

func (manager *Manager) DeleteOwned(_ context.Context, sessionID string, handle *tunnel.DeviceHandle) error {
	if !tunnel.ValidSessionID(sessionID) {
		return errors.New("invalid WireGuard session id")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	owned, exists := manager.sessions[sessionID]
	if !exists {
		return nil
	}
	if handle != nil && *handle != owned.handle {
		return ErrOwnershipMismatch
	}
	if err := owned.runtime.Close(); err != nil {
		return fmt.Errorf("close userspace WireGuard runtime: %w", err)
	}
	delete(manager.sessions, sessionID)
	return nil
}

func (manager *Manager) Snapshot(sessionID string) (Snapshot, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	owned, exists := manager.sessions[sessionID]
	if !exists {
		return Snapshot{}, ErrSessionNotFound
	}
	return owned.runtime.Snapshot()
}

func verifyPeerFingerprint(want string, secrets *helperproto.DeviceSecrets) error {
	if err := secrets.Validate(); err != nil {
		return err
	}
	digest := sha256.Sum256(secrets.PeerPublicKey[:])
	if hex.EncodeToString(digest[:]) != want {
		return errors.New("peer public key does not match the approved fingerprint")
	}
	return nil
}

func validateSpec(spec tunnel.DeviceSpec) error {
	if !tunnel.ValidSessionID(spec.SessionID) || !spec.Address.IsValid() || !spec.Address.Addr().Is4() ||
		spec.MTU < 1280 || spec.MTU > 9000 || !spec.Endpoint.IsValid() || !spec.Endpoint.Addr().Is4() ||
		spec.Endpoint.Port() == 0 || len(spec.PeerFingerprint) != sha256.Size*2 {
		return errors.New("invalid WireGuard device specification")
	}
	if _, err := hex.DecodeString(spec.PeerFingerprint); err != nil {
		return errors.New("invalid WireGuard peer fingerprint")
	}
	return nil
}
