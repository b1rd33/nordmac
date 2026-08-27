// nordmac-scoped-harness is an unreleased Gate 3 executable. It can add only
// one private scoped route and never configures default routes, DNS, or PF.
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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/b1rd33/nordmac/internal/darwinnet"
	"github.com/b1rd33/nordmac/internal/helperproto"
	"github.com/b1rd33/nordmac/internal/state"
	"github.com/b1rd33/nordmac/internal/tunnel"
	"github.com/b1rd33/nordmac/internal/wgbackend"
)

type inputs struct {
	Endpoint      netip.AddrPort
	TunnelAddress netip.Prefix
	PeerAddress   netip.Addr
	ScopedRoute   netip.Prefix
	Duration      time.Duration
}

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
	var sessionID, recoverSession, endpointText, tunnelAddressText, peerAddressText, scopedRouteText string
	var duration time.Duration
	var acknowledged bool
	flag.StringVar(&sessionID, "session", "", "32-character lowercase hex Gate 3 session")
	flag.StringVar(&recoverSession, "recover-session", "", "roll back a retained Gate 3 session without reading keys")
	flag.StringVar(&endpointText, "endpoint", "", "controlled peer endpoint as literal public-or-LAN IPv4:port")
	flag.StringVar(&tunnelAddressText, "tunnel-address", "", "owned utun IPv4 /32")
	flag.StringVar(&peerAddressText, "peer-address", "", "private IPv4 address to ping through the tunnel")
	flag.StringVar(&scopedRouteText, "scoped-route", "", "single private IPv4 /16 to /32 containing the peer")
	flag.DurationVar(&duration, "duration", 0, "bounded complete test window (1s to 30s)")
	flag.BoolVar(&acknowledged, "ack-scoped-route", false, "confirm Gate 3 authorization")
	flag.Parse()
	if recoverSession != "" {
		if !acknowledged || !tunnel.ValidSessionID(recoverSession) {
			return errors.New("recovery requires --ack-scoped-route and a valid --recover-session")
		}
		return recover(recoverSession)
	}
	if !tunnel.ValidSessionID(sessionID) {
		return errors.New("invalid Gate 3 session")
	}

	input, err := validateInputs(endpointText, tunnelAddressText, peerAddressText, scopedRouteText, duration, acknowledged)
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

	runner := darwinnet.CommandRunner{}
	routes := darwinnet.RouteManager{Runner: runner}
	physical, err := routes.Snapshot(context.Background())
	if err != nil {
		return err
	}
	plan := tunnel.Plan{
		SessionID:         sessionID,
		OwnerUID:          os.Getuid(),
		Endpoint:          input.Endpoint,
		PhysicalGateway:   physical.Default.Gateway,
		PhysicalInterface: physical.Default.Interface,
		TunnelAddress:     input.TunnelAddress,
		TunnelMTU:         1280,
		RoutePolicy:       tunnel.RoutePolicyScopedIPv4,
		ScopedRoutes:      []netip.Prefix{input.ScopedRoute},
		PeerFingerprint:   hex.EncodeToString(peerDigest[:]),
	}
	if err := plan.Validate(); err != nil {
		return err
	}

	journalDirectory := stateDirectory(sessionID)
	if err := os.Mkdir(journalDirectory, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("Gate 3 state already exists; recover that session before retrying")
		}
		return fmt.Errorf("create private Gate 3 journal directory: %w", err)
	}
	defer func() {
		retErr = errors.Join(retErr, removeStateIfClean(journalDirectory))
	}()

	manager := &wgbackend.Manager{
		Secrets:   source,
		Factory:   wgbackend.UserspaceFactory{},
		Addresses: darwinnet.AddressManager{Runner: runner},
	}
	verifier := scopedVerifier{
		Devices:     manager,
		Routes:      routes,
		Pinger:      darwinnet.Pinger{Runner: runner},
		PeerAddress: input.PeerAddress,
	}
	controller := tunnel.Controller{
		Journals:  state.JournalStore{Directory: journalDirectory},
		Locks:     state.FileLocker{Directory: journalDirectory},
		Conflicts: darwinnet.ConflictChecker{Routes: routes},
		Devices:   manager,
		Routes:    routes,
		Verifier:  verifier,
	}

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, input.Duration)
	defer cancel()
	journal, err := controller.Connect(ctx, plan)
	if err != nil {
		return err
	}
	snapshot, err := manager.Snapshot(sessionID)
	if err != nil {
		return cleanupConnected(controller, journal, err)
	}
	output := result{SchemaVersion: 1, OK: true, Interface: journal.Device.Interface, Snapshot: &snapshot}
	if err := cleanupConnected(controller, journal, nil); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(output)
}

type scopedVerifier struct {
	Devices     *wgbackend.Manager
	Routes      darwinnet.RouteManager
	Pinger      darwinnet.Pinger
	PeerAddress netip.Addr
}

func (verifier scopedVerifier) Verify(ctx context.Context, journal tunnel.Journal) error {
	endpoint, found, err := verifier.Routes.LookupExact(ctx, journal.Plan.EndpointRoute().Destination)
	if err != nil {
		return fmt.Errorf("inspect endpoint pin: %w", err)
	}
	if !found || endpoint.Gateway != journal.Plan.PhysicalGateway || endpoint.Interface != journal.Plan.PhysicalInterface {
		return errors.New("endpoint pin is not owned through the captured physical route")
	}
	scoped := journal.Plan.TunnelRoutes()[0]
	scoped.Interface = journal.Device.Interface
	current, found, err := verifier.Routes.LookupExact(ctx, scoped.Destination)
	if err != nil {
		return fmt.Errorf("inspect scoped route: %w", err)
	}
	if !found || current.Interface != scoped.Interface {
		return errors.New("scoped route is not owned by the tunnel interface")
	}
	var lastErr error
	for {
		pingErr := verifier.Pinger.Ping(ctx, verifier.PeerAddress)
		snapshot, snapshotErr := verifier.Devices.Snapshot(journal.SessionID)
		if pingErr == nil && snapshotErr == nil && !snapshot.LastHandshake.Before(journal.CreatedAt.Add(-time.Second)) &&
			snapshot.Transmitted > 0 && snapshot.Received > 0 {
			return nil
		}
		lastErr = errors.Join(pingErr, snapshotErr)
		select {
		case <-ctx.Done():
			return errors.Join(errors.New("scoped traffic produced no fresh bidirectional WireGuard handshake"), ctx.Err(), lastErr)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func cleanupConnected(controller tunnel.Controller, journal tunnel.Journal, primary error) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return errors.Join(primary, controller.Disconnect(cleanupCtx, journal.SessionID, journal.OwnerUID))
}

func recover(sessionID string) error {
	directory := stateDirectory(sessionID)
	routes := darwinnet.RouteManager{Runner: darwinnet.CommandRunner{}}
	controller := tunnel.Controller{
		Journals: state.JournalStore{Directory: directory},
		Locks:    state.FileLocker{Directory: directory},
		Devices:  &wgbackend.Manager{},
		Routes:   routes,
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := controller.Disconnect(cleanupCtx, sessionID, os.Getuid()); err != nil {
		return err
	}
	return removeStateIfClean(directory)
}

func stateDirectory(sessionID string) string {
	return filepath.Join("/private/tmp", "nordmac-gate3-"+sessionID)
}

func removeStateIfClean(directory string) error {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect Gate 3 state: %w", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			return errors.New("Gate 3 rollback evidence retained for explicit recovery")
		}
	}
	if err := os.RemoveAll(directory); err != nil {
		return fmt.Errorf("remove clean Gate 3 state: %w", err)
	}
	return nil
}

func validateInputs(endpointText, tunnelAddressText, peerAddressText, scopedRouteText string, duration time.Duration, acknowledged bool) (inputs, error) {
	if !acknowledged {
		return inputs{}, errors.New("refusing scoped routing without --ack-scoped-route")
	}
	if duration < time.Second || duration > 30*time.Second {
		return inputs{}, errors.New("duration must be between 1s and 30s")
	}
	endpoint, err := netip.ParseAddrPort(endpointText)
	if err != nil || !endpoint.Addr().Is4() || !endpoint.Addr().IsGlobalUnicast() || endpoint.Addr().IsLoopback() || endpoint.Port() == 0 {
		return inputs{}, errors.New("endpoint must be a literal non-loopback unicast IPv4 address and nonzero port")
	}
	tunnelAddress, err := netip.ParsePrefix(tunnelAddressText)
	if err != nil || !tunnelAddress.Addr().Is4() || tunnelAddress.Bits() != 32 {
		return inputs{}, errors.New("tunnel address must be an IPv4 /32")
	}
	peerAddress, err := netip.ParseAddr(peerAddressText)
	if err != nil || !peerAddress.Is4() || !peerAddress.IsPrivate() {
		return inputs{}, errors.New("peer address must be private IPv4")
	}
	scopedRoute, err := netip.ParsePrefix(scopedRouteText)
	if err != nil || !scopedRoute.Addr().Is4() || scopedRoute != scopedRoute.Masked() ||
		!scopedRoute.Addr().IsPrivate() || scopedRoute.Bits() < 16 || scopedRoute.Bits() > 32 || !scopedRoute.Contains(peerAddress) {
		return inputs{}, errors.New("scoped route must be canonical IPv4 and contain the peer address")
	}
	return inputs{Endpoint: endpoint, TunnelAddress: tunnelAddress, PeerAddress: peerAddress, ScopedRoute: scopedRoute, Duration: duration}, nil
}
