package wgbackend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/b1rd33/nordmac/internal/helperproto"
	"github.com/b1rd33/nordmac/internal/tunnel"
)

const testSession = "0123456789abcdef0123456789abcdef"

type fakeRuntime struct {
	name          string
	configured    bool
	up            bool
	closed        int
	configureErr  error
	upErr         error
	snapshot      Snapshot
	privateAtCall [32]byte
}

func (runtime *fakeRuntime) Name() string { return runtime.name }
func (runtime *fakeRuntime) Configure(_ tunnel.DeviceSpec, secrets *helperproto.DeviceSecrets) error {
	runtime.configured = true
	runtime.privateAtCall = secrets.ClientPrivateKey
	return runtime.configureErr
}
func (runtime *fakeRuntime) Up() error                   { runtime.up = true; return runtime.upErr }
func (runtime *fakeRuntime) Snapshot() (Snapshot, error) { return runtime.snapshot, nil }
func (runtime *fakeRuntime) Close() error                { runtime.closed++; return nil }

type fakeFactory struct {
	runtime Runtime
	err     error
}

func (factory fakeFactory) Create(int) (Runtime, error) { return factory.runtime, factory.err }

type fakeAddressConfigurer struct {
	addresses []tunnel.InterfaceAddress
	err       error
}

func (configurer *fakeAddressConfigurer) Apply(_ context.Context, address tunnel.InterfaceAddress) error {
	configurer.addresses = append(configurer.addresses, address)
	return configurer.err
}

func TestManagerOwnsCreatesSnapshotsAndDeletesExactSession(t *testing.T) {
	secrets := testSecrets()
	peerDigest := sha256.Sum256(secrets.PeerPublicKey[:])
	source, err := NewOneShotSecrets(testSession, &secrets)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{name: "utun9", snapshot: Snapshot{LastHandshake: time.Unix(100, 0), Transmitted: 92, Received: 148}}
	manager := &Manager{Secrets: source, Factory: fakeFactory{runtime: runtime}, DeviceOnly: true, PID: 4321}

	handle, err := manager.Create(context.Background(), testSpec(hex.EncodeToString(peerDigest[:])))
	if err != nil {
		t.Fatal(err)
	}
	if handle.Interface != "utun9" || handle.OwnerPID != 4321 || !runtime.configured || !runtime.up {
		t.Fatalf("unexpected created device: %#v runtime=%#v", handle, runtime)
	}
	snapshot, err := manager.Snapshot(testSession)
	if err != nil || snapshot.Received != 148 {
		t.Fatalf("unexpected snapshot %#v: %v", snapshot, err)
	}
	wrong := handle
	wrong.Interface = "utun8"
	if !errors.Is(manager.DeleteOwned(context.Background(), testSession, &wrong), ErrOwnershipMismatch) {
		t.Fatal("expected ownership mismatch")
	}
	if runtime.closed != 0 {
		t.Fatal("ownership mismatch closed runtime")
	}
	if err := manager.DeleteOwned(context.Background(), testSession, &handle); err != nil {
		t.Fatal(err)
	}
	if runtime.closed != 1 {
		t.Fatalf("close count = %d", runtime.closed)
	}
	if err := manager.DeleteOwned(context.Background(), testSession, &handle); err != nil {
		t.Fatalf("idempotent delete failed: %v", err)
	}
}

func TestManagerRejectsFingerprintBeforeCreatingRuntime(t *testing.T) {
	secrets := testSecrets()
	source, err := NewOneShotSecrets(testSession, &secrets)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{name: "utun9"}
	manager := &Manager{Secrets: source, Factory: fakeFactory{runtime: runtime}, DeviceOnly: true}
	_, err = manager.Create(context.Background(), testSpec(string(make([]byte, 64))))
	if err == nil {
		t.Fatal("expected fingerprint rejection")
	}
	if runtime.configured || runtime.closed != 0 {
		t.Fatal("runtime was touched before fingerprint validation")
	}
}

func TestManagerClosesPartiallyConfiguredRuntime(t *testing.T) {
	secrets := testSecrets()
	peerDigest := sha256.Sum256(secrets.PeerPublicKey[:])
	source, err := NewOneShotSecrets(testSession, &secrets)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{name: "utun9", configureErr: errors.New("injected")}
	manager := &Manager{Secrets: source, Factory: fakeFactory{runtime: runtime}, DeviceOnly: true}
	_, err = manager.Create(context.Background(), testSpec(hex.EncodeToString(peerDigest[:])))
	if err == nil || runtime.closed != 1 {
		t.Fatalf("partial runtime was not closed: err=%v closes=%d", err, runtime.closed)
	}
}

func TestManagerConfiguresAddressAndClosesOnAddressFailure(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[failure], func(t *testing.T) {
			secrets := testSecrets()
			peerDigest := sha256.Sum256(secrets.PeerPublicKey[:])
			source, err := NewOneShotSecrets(testSession, &secrets)
			if err != nil {
				t.Fatal(err)
			}
			runtime := &fakeRuntime{name: "utun9"}
			addresses := &fakeAddressConfigurer{}
			if failure {
				addresses.err = errors.New("injected address failure")
			}
			manager := &Manager{Secrets: source, Factory: fakeFactory{runtime: runtime}, Addresses: addresses}
			handle, createErr := manager.Create(context.Background(), testSpec(hex.EncodeToString(peerDigest[:])))
			if len(addresses.addresses) != 1 || addresses.addresses[0].Interface != "utun9" || addresses.addresses[0].Prefix.String() != "10.5.0.2/32" {
				t.Fatalf("address calls = %#v", addresses.addresses)
			}
			if failure {
				if createErr == nil || runtime.closed != 1 {
					t.Fatalf("address failure was not closed: err=%v closes=%d", createErr, runtime.closed)
				}
				return
			}
			if createErr != nil {
				t.Fatal(createErr)
			}
			if err := manager.DeleteOwned(context.Background(), testSession, &handle); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOneShotSecretsTransfersAndWipesOwnership(t *testing.T) {
	input := testSecrets()
	want := input.ClientPrivateKey
	source, err := NewOneShotSecrets(testSession, &input)
	if err != nil {
		t.Fatal(err)
	}
	if input.ClientPrivateKey != [32]byte{} || input.PeerPublicKey != [32]byte{} {
		t.Fatal("constructor did not wipe caller-owned keys")
	}
	err = source.Consume(context.Background(), testSession, func(secrets *helperproto.DeviceSecrets) error {
		if secrets.ClientPrivateKey != want {
			t.Fatal("consumer did not receive keys")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if source.secrets.ClientPrivateKey != [32]byte{} || source.secrets.PeerPublicKey != [32]byte{} {
		t.Fatal("source did not wipe consumed keys")
	}
	if err := source.Consume(context.Background(), testSession, func(*helperproto.DeviceSecrets) error { return nil }); err == nil {
		t.Fatal("one-shot source was reused")
	}
}

func TestParseSnapshot(t *testing.T) {
	snapshot, err := parseSnapshot([]byte("private_key=redacted-by-test\npublic_key=peer\nlast_handshake_time_sec=20\nlast_handshake_time_nsec=3\ntx_bytes=4\nrx_bytes=5\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.LastHandshake.Equal(time.Unix(20, 3)) || snapshot.Transmitted != 4 || snapshot.Received != 5 {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
}

func testSecrets() helperproto.DeviceSecrets {
	var secrets helperproto.DeviceSecrets
	for index := range secrets.ClientPrivateKey {
		secrets.ClientPrivateKey[index] = byte(index + 1)
		secrets.PeerPublicKey[index] = byte(index + 33)
	}
	return secrets
}

func testSpec(fingerprint string) tunnel.DeviceSpec {
	return tunnel.DeviceSpec{
		SessionID:       testSession,
		Address:         netip.MustParsePrefix("10.5.0.2/32"),
		MTU:             1280,
		Endpoint:        netip.MustParseAddrPort("192.0.2.1:51820"),
		PeerFingerprint: fingerprint,
	}
}
