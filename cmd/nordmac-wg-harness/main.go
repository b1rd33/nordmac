// nordmac-wg-harness is an intentionally separate, device-only validation
// binary. It creates no routes, DNS settings, PF rules, credentials, or state.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/b1rd33/nordmac/internal/helperproto"
	"github.com/b1rd33/nordmac/internal/tunnel"
	"github.com/b1rd33/nordmac/internal/wgbackend"
)

type result struct {
	SchemaVersion int                 `json:"schema_version"`
	OK            bool                `json:"ok"`
	Interface     string              `json:"interface,omitempty"`
	Snapshot      *wgbackend.Snapshot `json:"snapshot,omitempty"`
	Error         string              `json:"error,omitempty"`
}

func main() {
	if err := run(); err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(result{SchemaVersion: 1, OK: false, Error: err.Error()})
		os.Exit(1)
	}
}

func run() (retErr error) {
	var sessionID, endpointText string
	var duration time.Duration
	var acknowledged bool
	flag.StringVar(&sessionID, "session", "", "32-character lowercase hex test session")
	flag.StringVar(&endpointText, "endpoint", "", "controlled peer IPv4 endpoint as IP:port")
	flag.DurationVar(&duration, "duration", 0, "bounded observation window (1s to 60s)")
	flag.BoolVar(&acknowledged, "ack-device-only", false, "confirm the endpoint is controlled and no host networking will be changed")
	flag.Parse()

	endpoint, err := validateGate(sessionID, endpointText, duration, acknowledged)
	if err != nil {
		return err
	}
	secrets, err := helperproto.ReadSecrets(os.Stdin)
	if err != nil {
		return fmt.Errorf("read fixed binary secret frame from stdin: %w", err)
	}
	peerDigest := sha256.Sum256(secrets.PeerPublicKey[:])
	source, err := wgbackend.NewOneShotSecrets(sessionID, &secrets)
	if err != nil {
		secrets.Wipe()
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	manager := &wgbackend.Manager{Secrets: source, Factory: wgbackend.UserspaceFactory{}}
	spec := tunnel.DeviceSpec{
		SessionID:       sessionID,
		Address:         netip.MustParsePrefix("10.255.255.254/32"),
		MTU:             1280,
		Endpoint:        endpoint,
		PeerFingerprint: hex.EncodeToString(peerDigest[:]),
	}
	startedAt := time.Now()
	handle, err := manager.Create(ctx, spec)
	if err != nil {
		return err
	}
	cleaned := false
	defer func() {
		if !cleaned {
			retErr = errors.Join(retErr, manager.DeleteOwned(context.Background(), sessionID, &handle))
		}
	}()

	deadline := time.NewTimer(duration)
	defer deadline.Stop()
	poll := time.NewTicker(200 * time.Millisecond)
	defer poll.Stop()
	var snapshot wgbackend.Snapshot
	for {
		snapshot, err = manager.Snapshot(sessionID)
		if err != nil {
			return err
		}
		if !snapshot.LastHandshake.Before(startedAt.Add(-time.Second)) && snapshot.Transmitted > 0 && snapshot.Received > 0 {
			if err := manager.DeleteOwned(context.Background(), sessionID, &handle); err != nil {
				return err
			}
			cleaned = true
			return json.NewEncoder(os.Stdout).Encode(result{SchemaVersion: 1, OK: true, Interface: handle.Interface, Snapshot: &snapshot})
		}
		select {
		case <-ctx.Done():
			return errors.New("device-only test cancelled")
		case <-deadline.C:
			return errors.New("controlled peer produced no fresh bidirectional WireGuard handshake before the deadline")
		case <-poll.C:
		}
	}
}

func validateGate(sessionID, endpointText string, duration time.Duration, acknowledged bool) (netip.AddrPort, error) {
	if !acknowledged {
		return netip.AddrPort{}, errors.New("refusing device creation without --ack-device-only")
	}
	if !tunnel.ValidSessionID(sessionID) {
		return netip.AddrPort{}, errors.New("invalid test session")
	}
	if duration < time.Second || duration > time.Minute {
		return netip.AddrPort{}, errors.New("duration must be between 1s and 60s")
	}
	endpoint, err := netip.ParseAddrPort(endpointText)
	if err != nil || !endpoint.Addr().Is4() ||
		(!endpoint.Addr().IsGlobalUnicast() && !endpoint.Addr().IsLoopback()) || endpoint.Port() == 0 {
		return netip.AddrPort{}, errors.New("endpoint must be a literal usable IPv4 address and nonzero port")
	}
	return endpoint, nil
}
