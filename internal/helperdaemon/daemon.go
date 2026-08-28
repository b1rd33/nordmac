// Package helperdaemon runs the narrow privileged half of nordmac. It never
// reads Keychain credentials, calls Nord APIs, accepts executable paths, or
// interprets shell text.
package helperdaemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/b1rd33/nordmac/internal/darwinnet"
	"github.com/b1rd33/nordmac/internal/helperproto"
	"github.com/b1rd33/nordmac/internal/state"
	"github.com/b1rd33/nordmac/internal/tunnel"
	"github.com/b1rd33/nordmac/internal/wgbackend"
)

const (
	runtimeRoot = "/var/run/nordmac"
	stateRoot   = "/var/db/nordmac"
)

// Run reads exactly one bootstrap frame. Connect remains alive as the device
// owner; recovery operations exit after replying.
func Run(ctx context.Context, input io.Reader, output io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("privileged helper must run as root")
	}
	request, secrets, err := helperproto.DecodeFrame(input)
	if err != nil {
		return err
	}
	defer secrets.Wipe()
	if err := authorizeBootstrap(request.OwnerUID); err != nil {
		return err
	}
	switch request.Operation {
	case helperproto.OperationConnect:
		return connectAndServe(ctx, output, request, &secrets)
	case helperproto.OperationDisconnect, helperproto.OperationRecover:
		return recoverSession(ctx, output, request)
	default:
		return errors.New("unsupported bootstrap helper operation")
	}
}

func authorizeBootstrap(ownerUID int) error {
	value := os.Getenv("SUDO_UID")
	uid, err := strconv.Atoi(value)
	if err != nil || uid < 0 || uid != ownerUID {
		return errors.New("helper caller does not match SUDO_UID")
	}
	return nil
}

func connectAndServe(ctx context.Context, output io.Writer, request helperproto.Request, secrets *helperproto.DeviceSecrets) (retErr error) {
	if request.Plan == nil {
		return errors.New("connect request is missing its plan")
	}
	stateDirectory, err := prepareStateDirectory(request.OwnerUID)
	if err != nil {
		return err
	}
	runner := darwinnet.CommandRunner{}
	routes := darwinnet.RouteManager{Runner: runner}
	source, err := wgbackend.NewOneShotSecrets(request.SessionID, secrets)
	if err != nil {
		return err
	}
	manager := &wgbackend.Manager{
		Secrets: source, Factory: wgbackend.UserspaceFactory{},
		Addresses: darwinnet.AddressManager{Runner: runner, PeerAddress: netip.MustParseAddr("10.5.0.1")},
	}
	dns := darwinnet.DNSManager{Runner: runner}
	verifier := fullVerifier{Devices: manager, Routes: routes, DNS: dns, Pinger: darwinnet.Pinger{Runner: runner}}
	controller := tunnel.Controller{
		Journals: state.JournalStore{Directory: stateDirectory}, Locks: state.FileLocker{Directory: stateDirectory},
		Conflicts: darwinnet.ConflictChecker{Routes: routes}, Devices: manager, Routes: routes, DNS: dns,
		Verifier: verifier,
	}
	connectCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	journal, err := controller.Connect(connectCtx, *request.Plan)
	cancel()
	if err != nil {
		_ = helperproto.EncodeResponse(output, responseFor(request, false, phaseFromJournal(journal), err))
		return err
	}
	listener, socketPath, err := listenForOwner(request.OwnerUID)
	if err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		return errors.Join(err, controller.Disconnect(cleanupCtx, request.SessionID, request.OwnerUID))
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		retErr = errors.Join(retErr, controller.Disconnect(cleanupCtx, request.SessionID, request.OwnerUID))
	}()
	if err := helperproto.EncodeResponse(output, responseFor(request, true, tunnel.PhaseConnected, nil)); err != nil {
		return err
	}
	return serve(ctx, listener, controller, manager, verifier, request, journal)
}

func serve(ctx context.Context, listener *net.UnixListener, controller tunnel.Controller, devices *wgbackend.Manager, verifier fullVerifier, initial helperproto.Request, journal tunnel.Journal) error {
	if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	nextHealthCheck := time.Now().Add(10 * time.Second)
	healthFailures := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		connection, err := listener.AcceptUnix()
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			if !time.Now().Before(nextHealthCheck) {
				healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				healthErr := verifier.verifyOwnership(healthCtx, journal)
				cancel()
				if healthErr == nil {
					healthFailures = 0
				} else {
					healthFailures++
					if healthFailures >= 3 {
						return errors.New("tunnel ownership health check repeatedly failed")
					}
				}
				nextHealthCheck = time.Now().Add(10 * time.Second)
			}
			_ = listener.SetDeadline(time.Now().Add(time.Second))
			continue
		}
		if err != nil {
			return err
		}
		stop, handleErr := handle(connection, controller, devices, verifier, initial, journal)
		_ = connection.Close()
		if stop {
			// The deferred cleanup is the single rollback owner.
			return handleErr
		}
	}
}

func handle(connection *net.UnixConn, controller tunnel.Controller, devices *wgbackend.Manager, verifier fullVerifier, initial helperproto.Request, journal tunnel.Journal) (bool, error) {
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	if err := authorizePeer(connection, initial.OwnerUID); err != nil {
		return false, err
	}
	request, secrets, err := helperproto.DecodeFrame(connection)
	secrets.Wipe()
	if err != nil {
		return false, err
	}
	if request.OwnerUID != initial.OwnerUID || request.SessionID != initial.SessionID || request.Operation == helperproto.OperationConnect {
		err = errors.New("helper request does not own the active session")
		_ = helperproto.EncodeResponse(connection, responseFor(request, false, tunnel.PhaseForeignConflict, err))
		return false, err
	}
	switch request.Operation {
	case helperproto.OperationStatus:
		statusCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = verifier.verifyOwnership(statusCtx, journal)
		cancel()
		if err == nil {
			_, err = devices.Snapshot(initial.SessionID)
		}
		response := responseFor(request, err == nil, tunnel.PhaseConnected, err)
		if err != nil {
			response.State = tunnel.PhaseDegraded
		}
		return false, helperproto.EncodeResponse(connection, response)
	case helperproto.OperationDisconnect, helperproto.OperationRecover:
		// Acknowledge only after rollback. The outer deferred retry is idempotent.
		disconnectCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = controller.Disconnect(disconnectCtx, initial.SessionID, initial.OwnerUID)
		cancel()
		encodeErr := helperproto.EncodeResponse(connection, responseFor(request, err == nil, tunnel.PhaseDisconnected, err))
		return err == nil, errors.Join(err, encodeErr)
	default:
		return false, errors.New("unsupported active helper operation")
	}
}

func recoverSession(ctx context.Context, output io.Writer, request helperproto.Request) error {
	stateDirectory := filepath.Join(stateRoot, strconv.Itoa(request.OwnerUID))
	runner := darwinnet.CommandRunner{}
	controller := tunnel.Controller{
		Journals: state.JournalStore{Directory: stateDirectory}, Locks: state.FileLocker{Directory: stateDirectory},
		Devices: &wgbackend.Manager{}, Routes: darwinnet.RouteManager{Runner: runner}, DNS: darwinnet.DNSManager{Runner: runner},
	}
	rollbackCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err := controller.Disconnect(rollbackCtx, request.SessionID, request.OwnerUID)
	if err == nil {
		err = removeStaleSocket(request.OwnerUID)
	}
	encodeErr := helperproto.EncodeResponse(output, responseFor(request, err == nil, tunnel.PhaseDisconnected, err))
	return errors.Join(err, encodeErr)
}

type fullVerifier struct {
	Devices *wgbackend.Manager
	Routes  darwinnet.RouteManager
	DNS     darwinnet.DNSManager
	Pinger  darwinnet.Pinger
}

func (verifier fullVerifier) Verify(ctx context.Context, journal tunnel.Journal) error {
	if err := verifier.verifyOwnership(ctx, journal); err != nil {
		return err
	}
	for {
		_ = verifier.Pinger.Ping(ctx, netip.MustParseAddr("10.5.0.1"))
		snapshot, snapshotErr := verifier.Devices.Snapshot(journal.SessionID)
		if snapshotErr == nil && !snapshot.LastHandshake.Before(journal.CreatedAt.Add(-time.Second)) && snapshot.Transmitted > 0 && snapshot.Received > 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(errors.New("no fresh bidirectional WireGuard handshake"), ctx.Err(), snapshotErr)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (verifier fullVerifier) verifyOwnership(ctx context.Context, journal tunnel.Journal) error {
	physical, err := verifier.Routes.Snapshot(ctx)
	if err != nil || physical.Default.Gateway != journal.Plan.PhysicalGateway || physical.Default.Interface != journal.Plan.PhysicalInterface {
		return errors.Join(errors.New("physical default route changed"), err)
	}
	for _, expected := range append([]tunnel.Route{journal.Plan.EndpointRoute()}, journal.Plan.TunnelRoutes()...) {
		if !expected.Reject && expected.Gateway == (netip.Addr{}) {
			expected.Interface = journal.Device.Interface
		}
		current, found, err := verifier.Routes.LookupExact(ctx, expected.Destination)
		if err != nil || !found || current.Interface != expected.Interface || current.Reject != expected.Reject || expected.Gateway.IsValid() && current.Gateway != expected.Gateway {
			return errors.Join(errors.New("planned route ownership verification failed"), err)
		}
	}
	dns, err := verifier.DNS.Snapshot(ctx, journal.Plan.DNSConfig())
	if err != nil || len(dns.Services) != 1 || !slices.Equal(dns.Services[0].Servers, journal.Plan.TunnelDNS) {
		return errors.Join(errors.New("tunnel DNS verification failed"), err)
	}
	return nil
}

func prepareStateDirectory(ownerUID int) (string, error) {
	if err := ensureRootDirectory(stateRoot, 0o700); err != nil {
		return "", fmt.Errorf("create state root: %w", err)
	}
	directory := filepath.Join(stateRoot, strconv.Itoa(ownerUID))
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("create state directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return "", errors.New("state directory is not a private directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return "", errors.New("state directory is not root-owned")
	}
	return directory, nil
}

func listenForOwner(ownerUID int) (*net.UnixListener, string, error) {
	if err := ensureRootDirectory(runtimeRoot, 0o755); err != nil {
		return nil, "", err
	}
	path := filepath.Join(runtimeRoot, strconv.Itoa(ownerUID)+".sock")
	if _, err := os.Lstat(path); err == nil {
		return nil, "", errors.New("active helper socket already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, "", err
	}
	if err := os.Chown(path, ownerUID, -1); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, "", err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, "", err
	}
	return listener, path, nil
}

func ensureRootDirectory(path string, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != mode {
		return errors.New("privileged helper directory has unsafe type or mode")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("privileged helper directory is not root-owned")
	}
	return nil
}

func removeStaleSocket(ownerUID int) error {
	path := filepath.Join(runtimeRoot, strconv.Itoa(ownerUID)+".sock")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != uint32(ownerUID) {
		return errors.New("refuse to remove unowned helper socket")
	}
	return os.Remove(path)
}

func responseFor(request helperproto.Request, ok bool, phase tunnel.Phase, err error) helperproto.Response {
	response := helperproto.Response{SchemaVersion: helperproto.SchemaVersion, RequestID: request.RequestID, OK: ok, State: phase}
	if !ok {
		response.ErrorCode = helperproto.ErrorInternal
		switch {
		case errors.Is(err, tunnel.ErrConflict):
			response.ErrorCode = helperproto.ErrorConflict
		case errors.Is(err, tunnel.ErrRollback):
			response.ErrorCode = helperproto.ErrorRollback
		}
	}
	return response
}

func phaseFromJournal(journal tunnel.Journal) tunnel.Phase {
	if journal.Phase == "" {
		return tunnel.PhaseDisconnected
	}
	return journal.Phase
}
