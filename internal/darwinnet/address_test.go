package darwinnet

import (
	"context"
	"net/netip"
	"reflect"
	"testing"

	"github.com/b1rd33/nordmac/internal/tunnel"
)

func TestAddressApplyUsesFixedIfconfigArguments(t *testing.T) {
	runner := &fakeRunner{}
	manager := AddressManager{Runner: runner, PeerAddress: netip.MustParseAddr("10.250.0.1")}
	address := tunnel.InterfaceAddress{Interface: "utun11", Prefix: netip.MustParsePrefix("10.250.0.2/32")}
	if err := manager.Apply(context.Background(), address); err != nil {
		t.Fatal(err)
	}
	want := []invocation{{name: "/sbin/ifconfig", args: []string{"utun11", "inet", "10.250.0.2", "10.250.0.1", "netmask", "255.255.255.255", "alias"}}}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, want)
	}
}

func TestAddressApplyRejectsInjectionAndCancellation(t *testing.T) {
	runner := &fakeRunner{}
	manager := AddressManager{Runner: runner, PeerAddress: netip.MustParseAddr("10.250.0.1")}
	bad := tunnel.InterfaceAddress{Interface: "utun11;touch", Prefix: netip.MustParsePrefix("10.250.0.2/32")}
	if err := manager.Apply(context.Background(), bad); err == nil || len(runner.calls) != 0 {
		t.Fatal("invalid interface reached runner")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	valid := tunnel.InterfaceAddress{Interface: "utun11", Prefix: netip.MustParsePrefix("10.250.0.2/32")}
	if err := manager.Apply(ctx, valid); err == nil {
		t.Fatal("cancelled address operation succeeded")
	}
}
