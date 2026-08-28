// Package connectplan builds a non-secret, non-mutating candidate manifest for
// a future one-server Nord live-tunnel gate.
package connectplan

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"regexp"
	"strings"

	"github.com/b1rd33/nordmac/internal/catalog"
)

var nordHostnamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.nordvpn\.com$`)

const (
	ReferenceCommit = "d49b7d14715a80e320bae55944727612cac98c9f"
	CredentialPath  = "/v1/users/services/credentials"
)

type Endpoint struct {
	Hostname string `json:"hostname"`
	IPv4     string `json:"ipv4"`
	Port     uint16 `json:"port"`
}

type WireGuard struct {
	TunnelAddress            string   `json:"tunnel_address"`
	PeerAddress              string   `json:"peer_address"`
	MTU                      int      `json:"mtu"`
	AllowedIPs               []string `json:"allowed_ips"`
	RouteMutations           []string `json:"route_mutations"`
	PeerPublicKeyFingerprint string   `json:"peer_public_key_sha256"`
}

type CredentialContract struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	Authorization string `json:"authorization"`
	Status        string `json:"status"`
}

type Manifest struct {
	ReadyForLiveTest    bool               `json:"ready_for_live_test"`
	Endpoint            Endpoint           `json:"endpoint"`
	WireGuard           WireGuard          `json:"wireguard"`
	DNS                 []string           `json:"dns"`
	IPv6Policy          string             `json:"ipv6_policy"`
	Credential          CredentialContract `json:"credential_contract"`
	ReferenceRepository string             `json:"reference_repository"`
	ReferenceCommit     string             `json:"reference_commit"`
	Blockers            []string           `json:"blockers"`
}

func Build(server catalog.Server) (Manifest, error) {
	station, err := netip.ParseAddr(server.Station)
	if err != nil || !station.Is4() || !station.IsGlobalUnicast() || station.IsPrivate() {
		return Manifest{}, errors.New("server station must be a public IPv4 address")
	}
	hostname := strings.ToLower(strings.TrimSpace(server.Hostname))
	if !nordHostnamePattern.MatchString(hostname) {
		return Manifest{}, errors.New("server hostname is outside the Nord domain")
	}
	publicKey, err := base64.StdEncoding.DecodeString(server.WireGuardPubKey)
	if err != nil || len(publicKey) != 32 {
		return Manifest{}, errors.New("server WireGuard public key is invalid")
	}
	digest := sha256.Sum256(publicKey)
	return Manifest{
		ReadyForLiveTest: false,
		Endpoint:         Endpoint{Hostname: hostname, IPv4: station.String(), Port: 51820},
		WireGuard: WireGuard{
			TunnelAddress: "10.5.0.2/32", PeerAddress: "10.5.0.1", MTU: 1280,
			AllowedIPs: []string{"0.0.0.0/0"},
			RouteMutations: []string{
				"endpoint IPv4 /32 via captured physical gateway",
				"0.0.0.0/1 via owned utun",
				"128.0.0.0/1 via owned utun",
			},
			PeerPublicKeyFingerprint: hex.EncodeToString(digest[:]),
		},
		DNS:        []string{"103.86.96.100", "103.86.99.100"},
		IPv6Policy: "unresolved: live test forbidden until IPv6 is tunneled or explicitly blocked and restored",
		Credential: CredentialContract{
			Method: "GET", Path: CredentialPath, Authorization: "Bearer token read from an approved secret channel",
			Status: "undocumented internal Nord contract; no request made by this plan",
		},
		ReferenceRepository: "https://github.com/NordSecurity/nordvpn-linux",
		ReferenceCommit:     ReferenceCommit,
		Blockers: []string{
			"replace the unvalidated security(1) write path with a native or signed Keychain boundary",
			"implement compare-before-restore DNS mutation for the active macOS service",
			"choose and validate an explicit IPv6 leak policy",
			"freeze a fresh server recommendation immediately before an approved bounded test",
		},
	}, nil
}
