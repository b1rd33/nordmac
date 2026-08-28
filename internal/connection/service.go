package connection

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/b1rd33/nordmac/internal/catalog"
	"github.com/b1rd33/nordmac/internal/connectplan"
	"github.com/b1rd33/nordmac/internal/credentials"
	"github.com/b1rd33/nordmac/internal/darwinnet"
	"github.com/b1rd33/nordmac/internal/helperproto"
	"github.com/b1rd33/nordmac/internal/recommend"
	"github.com/b1rd33/nordmac/internal/tunnel"
)

var (
	ErrNotAuthenticated = errors.New("Nord credentials are not available")
	ErrAlreadyConnected = errors.New("a nordmac connection is already recorded")
	ErrHelper           = errors.New("privileged helper operation failed")
	ErrBusy             = errors.New("another nordmac operation is active")
)

type Recommender interface {
	RecommendConnection(context.Context, recommend.Query) (catalog.Server, error)
}

type Helper interface {
	Exchange(context.Context, helperproto.Request, *helperproto.DeviceSecrets) (helperproto.Response, error)
}

type Locker interface {
	Lock(context.Context) (func() error, error)
}

type Service struct {
	Recommender Recommender
	Credentials credentials.Store
	Routes      darwinnet.RouteManager
	Runner      darwinnet.Runner
	Helper      Helper
	Locker      Locker
	Metadata    MetadataStore
	OwnerUID    int
	Now         func() time.Time
}

type Result struct {
	State     string `json:"state"`
	SessionID string `json:"session_id,omitempty"`
	Server    string `json:"server,omitempty"`
	Country   string `json:"country,omitempty"`
	City      string `json:"city,omitempty"`
}

func (service Service) Connect(ctx context.Context, query recommend.Query) (result Result, retErr error) {
	release, err := service.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer func() { retErr = errors.Join(retErr, release()) }()
	return service.connectLocked(ctx, query)
}

func (service Service) connectLocked(ctx context.Context, query recommend.Query) (Result, error) {
	if _, err := service.Metadata.Load(); err == nil {
		return Result{}, ErrAlreadyConnected
	} else if !errors.Is(err, os.ErrNotExist) {
		return Result{}, err
	}
	server, err := service.Recommender.RecommendConnection(ctx, query)
	if err != nil {
		return Result{}, err
	}
	manifest, err := connectplan.Build(server)
	if err != nil {
		return Result{}, err
	}
	privateText, err := service.Credentials.Get(ctx, credentials.NordLynxPrivateKey)
	if errors.Is(err, credentials.ErrNotFound) {
		return Result{}, ErrNotAuthenticated
	}
	if err != nil {
		return Result{}, err
	}
	defer credentials.Wipe(privateText)
	secrets, err := decodeSecrets(privateText, server)
	if err != nil {
		return Result{}, err
	}
	defer secrets.Wipe()
	physical, err := service.Routes.Snapshot(ctx)
	if err != nil {
		return Result{}, err
	}
	dnsService, err := darwinnet.NetworkService(ctx, service.Runner, physical.Default.Interface)
	if err != nil {
		return Result{}, err
	}
	sessionID, err := randomID()
	if err != nil {
		return Result{}, err
	}
	endpoint, err := netip.ParseAddrPort(manifest.Endpoint.IPv4 + ":51820")
	if err != nil {
		return Result{}, errors.New("recommended server has an invalid endpoint")
	}
	peerDigest := sha256.Sum256(secrets.PeerPublicKey[:])
	if hex.EncodeToString(peerDigest[:]) != manifest.WireGuard.PeerPublicKeyFingerprint {
		return Result{}, errors.New("recommended peer key changed while planning")
	}
	plan := tunnel.Plan{
		SessionID: sessionID, OwnerUID: service.uid(), Endpoint: endpoint,
		PhysicalGateway: physical.Default.Gateway, PhysicalInterface: physical.Default.Interface,
		TunnelAddress: netip.MustParsePrefix("10.5.0.2/32"), TunnelMTU: 1280,
		TunnelDNS:  []netip.Addr{netip.MustParseAddr("103.86.96.100"), netip.MustParseAddr("103.86.99.100")},
		DNSService: dnsService, RoutePolicy: tunnel.RoutePolicyFullIPv4, PeerFingerprint: hex.EncodeToString(peerDigest[:]),
	}
	if err := plan.Validate(); err != nil {
		return Result{}, err
	}
	metadata := Metadata{SchemaVersion: 1, SessionID: sessionID, Server: server.Hostname,
		Country: server.CountryName, City: server.CityName, Phase: "connecting", CreatedAt: service.now()}
	if err := service.Metadata.Save(metadata); err != nil {
		return Result{}, err
	}
	request := helperproto.Request{SchemaVersion: helperproto.SchemaVersion, RequestID: mustRandomID(), Operation: helperproto.OperationConnect,
		SessionID: sessionID, OwnerUID: service.uid(), SecretChannelVersion: helperproto.SecretChannelVersion, Plan: &plan}
	response, err := service.Helper.Exchange(ctx, request, &secrets)
	if err != nil || !response.OK {
		// Retain connecting metadata when rollback evidence may exist.
		return Result{}, errors.Join(ErrHelper, err)
	}
	metadata.Phase = "connected"
	if err := service.Metadata.Save(metadata); err != nil {
		cleanupRequest := helperproto.Request{SchemaVersion: helperproto.SchemaVersion, RequestID: mustRandomID(), Operation: helperproto.OperationDisconnect, SessionID: sessionID, OwnerUID: service.uid()}
		_, cleanupErr := service.Helper.Exchange(context.Background(), cleanupRequest, nil)
		return Result{}, errors.Join(err, cleanupErr)
	}
	return resultFromMetadata(metadata, "connected"), nil
}

func (service Service) Disconnect(ctx context.Context) (result Result, retErr error) {
	release, err := service.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer func() { retErr = errors.Join(retErr, release()) }()
	return service.disconnectLocked(ctx)
}

func (service Service) disconnectLocked(ctx context.Context) (Result, error) {
	metadata, err := service.Metadata.Load()
	if errors.Is(err, os.ErrNotExist) {
		return Result{State: "disconnected"}, nil
	}
	if err != nil {
		return Result{}, err
	}
	request := helperproto.Request{SchemaVersion: helperproto.SchemaVersion, RequestID: mustRandomID(), Operation: helperproto.OperationDisconnect,
		SessionID: metadata.SessionID, OwnerUID: service.uid()}
	response, err := service.Helper.Exchange(ctx, request, nil)
	if err != nil || !response.OK {
		return resultFromMetadata(metadata, "rollback_required"), errors.Join(ErrHelper, err)
	}
	if err := service.Metadata.Delete(); err != nil {
		return Result{}, err
	}
	return Result{State: "disconnected"}, nil
}

func (service Service) Status(ctx context.Context) (result Result, retErr error) {
	release, err := service.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer func() { retErr = errors.Join(retErr, release()) }()
	return service.statusLocked(ctx)
}

func (service Service) statusLocked(ctx context.Context) (Result, error) {
	metadata, err := service.Metadata.Load()
	if errors.Is(err, os.ErrNotExist) {
		return Result{State: "disconnected"}, nil
	}
	if err != nil {
		return Result{}, err
	}
	request := helperproto.Request{SchemaVersion: helperproto.SchemaVersion, RequestID: mustRandomID(), Operation: helperproto.OperationStatus,
		SessionID: metadata.SessionID, OwnerUID: service.uid()}
	response, err := service.Helper.Exchange(ctx, request, nil)
	if err != nil {
		return resultFromMetadata(metadata, "degraded"), nil
	}
	state := string(response.State)
	if state == "" {
		state = "degraded"
	}
	return resultFromMetadata(metadata, state), nil
}

func (service Service) Reconnect(ctx context.Context, fresh bool) (result Result, retErr error) {
	if !fresh {
		return Result{}, errors.New("reconnect requires fresh server selection")
	}
	release, err := service.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer func() { retErr = errors.Join(retErr, release()) }()
	metadata, err := service.Metadata.Load()
	if err != nil {
		return Result{}, err
	}
	query := recommend.Query{Country: metadata.Country, City: metadata.City}
	if _, err := service.disconnectLocked(ctx); err != nil {
		return Result{}, err
	}
	return service.connectLocked(ctx, query)
}

func (service Service) lock(ctx context.Context) (func() error, error) {
	if service.Locker == nil {
		return nil, errors.New("connection lock is unavailable")
	}
	release, err := service.Locker.Lock(ctx)
	if err != nil {
		return nil, errors.Join(ErrBusy, err)
	}
	return release, nil
}

func decodeSecrets(privateText []byte, server catalog.Server) (helperproto.DeviceSecrets, error) {
	var secrets helperproto.DeviceSecrets
	private := make([]byte, base64.StdEncoding.DecodedLen(len(privateText)))
	count, err := base64.StdEncoding.Decode(private, privateText)
	if err != nil || count != 32 {
		credentials.Wipe(private)
		return secrets, errors.New("stored NordLynx private key is invalid")
	}
	private = private[:count]
	defer credentials.Wipe(private)
	peer, err := base64.StdEncoding.DecodeString(server.WireGuardPubKey)
	if err != nil || len(peer) != 32 {
		return secrets, errors.New("recommended server public key is invalid")
	}
	defer credentials.Wipe(peer)
	copy(secrets.ClientPrivateKey[:], private)
	copy(secrets.PeerPublicKey[:], peer)
	if err := secrets.Validate(); err != nil {
		secrets.Wipe()
		return helperproto.DeviceSecrets{}, err
	}
	return secrets, nil
}

func randomID() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", fmt.Errorf("generate session identity: %w", err)
	}
	return hex.EncodeToString(data[:]), nil
}

func mustRandomID() string {
	value, err := randomID()
	if err != nil {
		panic(err)
	}
	return value
}

func (service Service) uid() int {
	if service.OwnerUID > 0 {
		return service.OwnerUID
	}
	return os.Getuid()
}

func (service Service) now() time.Time {
	if service.Now != nil {
		return service.Now().UTC()
	}
	return time.Now().UTC()
}

func resultFromMetadata(metadata Metadata, state string) Result {
	return Result{State: state, SessionID: metadata.SessionID, Server: metadata.Server, Country: metadata.Country, City: metadata.City}
}
