package tunnel

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestPlanValidationAndDerivedOrder(t *testing.T) {
	plan := testPlan()
	if err := plan.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if route := plan.EndpointRoute(); route.Destination.String() != "203.0.113.10/32" || route.Gateway != plan.PhysicalGateway || route.Interface != "en0" {
		t.Fatalf("endpoint route = %#v", route)
	}
	routes := plan.TunnelRoutes()
	if len(routes) != 2 || routes[0].Destination.String() != "0.0.0.0/1" || routes[1].Destination.String() != "128.0.0.0/1" {
		t.Fatalf("tunnel routes = %#v", routes)
	}
}

func TestPlanRejectsUnsafeValues(t *testing.T) {
	tests := map[string]func(*Plan){
		"session":    func(plan *Plan) { plan.SessionID = "../outside" },
		"owner":      func(plan *Plan) { plan.OwnerUID = -1 },
		"endpoint":   func(plan *Plan) { plan.Endpoint = netip.MustParseAddrPort("0.0.0.0:51820") },
		"port":       func(plan *Plan) { plan.Endpoint = netip.MustParseAddrPort("203.0.113.10:0") },
		"interface":  func(plan *Plan) { plan.PhysicalInterface = "en0;command" },
		"address":    func(plan *Plan) { plan.TunnelAddress = netip.MustParsePrefix("10.5.0.2/24") },
		"MTU":        func(plan *Plan) { plan.TunnelMTU = 1000 },
		"DNS family": func(plan *Plan) { plan.TunnelDNS = []netip.Addr{netip.MustParseAddr("2001:db8::53")} },
		"DNS duplicate": func(plan *Plan) {
			plan.TunnelDNS = []netip.Addr{netip.MustParseAddr("10.5.0.1"), netip.MustParseAddr("10.5.0.1")}
		},
		"fingerprint": func(plan *Plan) { plan.PeerFingerprint = strings.Repeat("z", 64) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			plan := testPlan()
			mutate(&plan)
			if err := plan.Validate(); err == nil {
				t.Fatal("Validate unexpectedly succeeded")
			}
		})
	}
}

func TestJournalValidationRejectsIdentityAndEntryCorruption(t *testing.T) {
	plan := testPlan()
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	journal := Journal{
		SchemaVersion: JournalSchemaVersion,
		SessionID:     plan.SessionID,
		OwnerUID:      plan.OwnerUID,
		Phase:         PhaseConnecting,
		Plan:          plan,
		RouteBefore: RouteSnapshot{Default: Route{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Gateway:     netip.MustParseAddr("192.0.2.1"),
			Interface:   "en0",
		}},
		DNSBefore: DNSSnapshot{
			Revision: "synthetic",
			Services: []ServiceDNS{{ServiceID: "synthetic-wifi", Servers: []netip.Addr{netip.MustParseAddr("192.0.2.53")}}},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := journal.Validate(); err != nil {
		t.Fatalf("valid journal: %v", err)
	}

	badIdentity := journal
	badIdentity.OwnerUID++
	if err := badIdentity.Validate(); err == nil {
		t.Fatal("journal accepted mismatched identity")
	}
	badEntry := journal
	badEntry.Entries = []Entry{{Kind: StepTunnelRoute, Status: StepApplied}}
	if err := badEntry.Validate(); err == nil {
		t.Fatal("journal accepted a route step without a route")
	}
}
