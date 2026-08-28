package darwinnet

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/b1rd33/nordmac/internal/tunnel"
)

const defaultRouteOutput = `route to: default
destination: default
       mask: default
    gateway: 192.0.2.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC>
`

func TestConflictCheckerRejectsExistingVPNRoutes(t *testing.T) {
	plan := tunnel.Plan{
		SessionID:         strings.Repeat("a", 32),
		OwnerUID:          501,
		Endpoint:          netip.MustParseAddrPort("203.0.113.10:51820"),
		PhysicalGateway:   netip.MustParseAddr("192.0.2.1"),
		PhysicalInterface: "en0",
		TunnelAddress:     netip.MustParsePrefix("10.250.0.2/32"),
		TunnelMTU:         1280,
		RoutePolicy:       tunnel.RoutePolicyScopedIPv4,
		ScopedRoutes:      []netip.Prefix{netip.MustParsePrefix("10.250.0.0/24")},
		PeerFingerprint:   strings.Repeat("b", 64),
	}
	t.Run("clean", func(t *testing.T) {
		runner := &fakeRunner{results: []runnerResult{
			{output: defaultRouteOutput},
			{output: defaultRouteOutput},
			{output: defaultRouteOutput},
		}}
		checker := ConflictChecker{Routes: RouteManager{Runner: runner}}
		if err := checker.Check(context.Background(), plan); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("split default", func(t *testing.T) {
		runner := &fakeRunner{results: []runnerResult{
			{output: defaultRouteOutput},
			{output: "destination: 0.0.0.0\nmask: 128.0.0.0\ngateway: 192.0.2.1\ninterface: en0\nflags: <UP,GATEWAY>\n"},
		}}
		checker := ConflictChecker{Routes: RouteManager{Runner: runner}}
		if err := checker.Check(context.Background(), plan); err == nil {
			t.Fatal("existing split default accepted")
		}
	})
	t.Run("utun default", func(t *testing.T) {
		runner := &fakeRunner{results: []runnerResult{{output: strings.Replace(defaultRouteOutput, "en0", "utun8", 1)}}}
		checker := ConflictChecker{Routes: RouteManager{Runner: runner}}
		if err := checker.Check(context.Background(), plan); err == nil {
			t.Fatal("utun default accepted")
		}
	})
	t.Run("IPv6 reject collision in full policy", func(t *testing.T) {
		fullPlan := plan
		fullPlan.RoutePolicy = tunnel.RoutePolicyFullIPv4
		runner := &fakeRunner{results: []runnerResult{
			{output: defaultRouteOutput}, {output: defaultRouteOutput}, {output: defaultRouteOutput},
			{output: "destination: ::\nmask: 8000::\ninterface: lo0\nflags: <UP,REJECT>\n"},
		}}
		checker := ConflictChecker{Routes: RouteManager{Runner: runner}}
		if err := checker.Check(context.Background(), fullPlan); err == nil {
			t.Fatal("existing IPv6 reject route accepted")
		}
	})
}

func TestPingerUsesBoundedNumericCommand(t *testing.T) {
	runner := &fakeRunner{}
	pinger := Pinger{Runner: runner}
	if err := pinger.Ping(context.Background(), netip.MustParseAddr("10.250.0.1")); err != nil {
		t.Fatal(err)
	}
	want := []invocation{{name: "/sbin/ping", args: []string{"-n", "-c", "1", "-W", "1000", "10.250.0.1"}}}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, want)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	if err := pinger.Ping(ctx, netip.MustParseAddr("10.250.0.1")); err == nil {
		t.Fatal("cancelled ping succeeded")
	}
}
