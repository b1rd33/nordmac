package connection

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b1rd33/nordmac/internal/catalog"
	"github.com/b1rd33/nordmac/internal/credentials"
	"github.com/b1rd33/nordmac/internal/darwinnet"
	"github.com/b1rd33/nordmac/internal/helperproto"
	"github.com/b1rd33/nordmac/internal/recommend"
	"github.com/b1rd33/nordmac/internal/tunnel"
)

type fakeRecommender struct{ server catalog.Server }

func (fake fakeRecommender) RecommendConnection(context.Context, recommend.Query) (catalog.Server, error) {
	return fake.server, nil
}

type fakeCredentials struct{ private []byte }

func (fake fakeCredentials) Put(context.Context, credentials.Kind, []byte) error { return nil }
func (fake fakeCredentials) Delete(context.Context, credentials.Kind) error      { return nil }
func (fake fakeCredentials) Get(_ context.Context, kind credentials.Kind) ([]byte, error) {
	if kind != credentials.NordLynxPrivateKey {
		return nil, credentials.ErrNotFound
	}
	return append([]byte(nil), fake.private...), nil
}

type helperCall struct {
	request helperproto.Request
	secret  helperproto.DeviceSecrets
}

type fakeHelper struct{ calls []helperCall }

func (fake *fakeHelper) Exchange(_ context.Context, request helperproto.Request, secrets *helperproto.DeviceSecrets) (helperproto.Response, error) {
	call := helperCall{request: request}
	if secrets != nil {
		call.secret = *secrets
	}
	fake.calls = append(fake.calls, call)
	state := tunnel.PhaseConnected
	if request.Operation == helperproto.OperationDisconnect {
		state = tunnel.PhaseDisconnected
	}
	return helperproto.Response{SchemaVersion: helperproto.SchemaVersion, RequestID: request.RequestID, OK: true, State: state}, nil
}

type networkRunner struct{}

type noOpLocker struct{}

func (noOpLocker) Lock(context.Context) (func() error, error) {
	return func() error { return nil }, nil
}

func (networkRunner) Run(_ context.Context, path string, arguments ...string) ([]byte, error) {
	if path == "/sbin/route" {
		return []byte("destination: default\nmask: default\ngateway: 192.0.2.1\ninterface: en0\nflags: <UP,GATEWAY>\n"), nil
	}
	return []byte("(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n"), nil
}

func TestConnectStatusDisconnectComposition(t *testing.T) {
	private := make([]byte, 32)
	peer := make([]byte, 32)
	private[0], peer[0] = 1, 2
	helper := &fakeHelper{}
	runner := networkRunner{}
	service := Service{
		Recommender: fakeRecommender{server: catalog.Server{
			Hostname: "de1234.nordvpn.com", Station: "203.0.113.11", WireGuardPubKey: base64.StdEncoding.EncodeToString(peer),
			CountryName: "Germany", CityName: "Berlin",
		}},
		Credentials: fakeCredentials{private: []byte(base64.StdEncoding.EncodeToString(private))},
		Routes:      darwinnet.RouteManager{Runner: runner}, Runner: runner, Helper: helper, Locker: noOpLocker{},
		Metadata: MetadataStore{Path: filepath.Join(t.TempDir(), "connection-v1.json")}, OwnerUID: 501,
		Now: func() time.Time { return time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC) },
	}
	result, err := service.Connect(context.Background(), recommend.Query{Country: "de", City: "berlin"})
	if err != nil || result.State != "connected" || len(helper.calls) != 1 {
		t.Fatalf("Connect = %#v, %v calls=%d", result, err, len(helper.calls))
	}
	plan := helper.calls[0].request.Plan
	if plan == nil || plan.DNSService != "Wi-Fi" || len(plan.TunnelRoutes()) != 4 || helper.calls[0].secret.ClientPrivateKey[0] != 1 {
		t.Fatalf("helper call = %#v", helper.calls[0])
	}
	status, err := service.Status(context.Background())
	if err != nil || status.State != "connected" {
		t.Fatalf("Status = %#v, %v", status, err)
	}
	disconnected, err := service.Disconnect(context.Background())
	if err != nil || disconnected.State != "disconnected" {
		t.Fatalf("Disconnect = %#v, %v", disconnected, err)
	}
	if _, err := os.Stat(service.Metadata.Path); !os.IsNotExist(err) {
		t.Fatalf("metadata remained: %v", err)
	}
}

func TestMetadataRejectsTrailingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connection-v1.json")
	data := `{"schema_version":1,"session_id":"` + strings.Repeat("a", 32) + `","server":"de1.nordvpn.com","phase":"connected","created_at":"2026-08-28T12:00:00Z"}` + "\n{}"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (MetadataStore{Path: path}).Load(); err == nil {
		t.Fatal("trailing metadata accepted")
	}
}
