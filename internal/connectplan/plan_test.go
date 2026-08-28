package connectplan

import (
	"strings"
	"testing"

	"github.com/b1rd33/nordmac/internal/catalog"
)

func TestBuildProducesFailClosedCandidate(t *testing.T) {
	manifest, err := Build(catalog.Server{
		Hostname: "DE1234.NORDVPN.COM", Station: "203.0.113.11",
		WireGuardPubKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ReadyForLiveTest || manifest.Endpoint.Port != 51820 || manifest.Endpoint.Hostname != "de1234.nordvpn.com" {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	if len(manifest.WireGuard.RouteMutations) != 3 || len(manifest.DNS) != 2 || len(manifest.Blockers) == 0 {
		t.Fatalf("incomplete manifest: %#v", manifest)
	}
	if len(manifest.WireGuard.PeerPublicKeyFingerprint) != 64 || strings.Contains(manifest.WireGuard.PeerPublicKeyFingerprint, "=") {
		t.Fatalf("invalid fingerprint: %q", manifest.WireGuard.PeerPublicKeyFingerprint)
	}
}

func TestBuildRejectsUntrustedPeerInputs(t *testing.T) {
	valid := catalog.Server{Hostname: "de1.nordvpn.com", Station: "203.0.113.11", WireGuardPubKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	for name, mutate := range map[string]func(*catalog.Server){
		"hostname": func(server *catalog.Server) { server.Hostname = "attacker.example" },
		"station":  func(server *catalog.Server) { server.Station = "127.0.0.1" },
		"private":  func(server *catalog.Server) { server.Station = "10.0.0.1" },
		"key":      func(server *catalog.Server) { server.WireGuardPubKey = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			server := valid
			mutate(&server)
			if _, err := Build(server); err == nil {
				t.Fatal("invalid server unexpectedly accepted")
			}
		})
	}
}
