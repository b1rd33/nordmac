package darwinnet

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/b1rd33/nordmac/internal/tunnel"
)

func dnsConfig() tunnel.DNSConfig {
	return tunnel.DNSConfig{ServiceID: "Wi-Fi", Servers: []netip.Addr{netip.MustParseAddr("10.5.0.1")}}
}

func TestDNSSnapshotCapturesOnlyFixedService(t *testing.T) {
	runner := &fakeRunner{results: []runnerResult{
		{output: "192.0.2.53\n2001:db8::53\n"},
		{output: "example.test\n"},
	}}
	snapshot, err := (DNSManager{Runner: runner}).Snapshot(context.Background(), dnsConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Revision) != 64 || len(snapshot.Services) != 1 || snapshot.Services[0].ServiceID != "Wi-Fi" {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	want := []invocation{
		{name: "/usr/sbin/networksetup", args: []string{"-getdnsservers", "Wi-Fi"}},
		{name: "/usr/sbin/networksetup", args: []string{"-getsearchdomains", "Wi-Fi"}},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, want)
	}
}

func TestDNSApplyUsesArgumentVectorsAndPreservesSearchDomains(t *testing.T) {
	runner := &fakeRunner{}
	if err := (DNSManager{Runner: runner}).Apply(context.Background(), dnsConfig()); err != nil {
		t.Fatal(err)
	}
	want := []invocation{
		{name: "/usr/sbin/networksetup", args: []string{"-setdnsservers", "Wi-Fi", "10.5.0.1"}},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, want)
	}
}

func TestDNSRestoreComparesOwnershipAndSupportsPartialApply(t *testing.T) {
	before := tunnel.DNSSnapshot{Revision: "synthetic", Services: []tunnel.ServiceDNS{{
		ServiceID: "Wi-Fi", Servers: []netip.Addr{netip.MustParseAddr("192.0.2.53")}, SearchDomains: []string{"home.test"},
	}}}
	t.Run("fully owned", func(t *testing.T) {
		runner := &fakeRunner{results: []runnerResult{{output: "10.5.0.1\n"}, {output: "home.test\n"}, {}}}
		if err := (DNSManager{Runner: runner}).RestoreIfOwned(context.Background(), before, dnsConfig()); err != nil {
			t.Fatal(err)
		}
		wantTail := []invocation{{name: "/usr/sbin/networksetup", args: []string{"-setdnsservers", "Wi-Fi", "192.0.2.53"}}}
		if !reflect.DeepEqual(runner.calls[2:], wantTail) {
			t.Fatalf("restore calls = %#v", runner.calls)
		}
	})
	t.Run("servers applied but domains original", func(t *testing.T) {
		runner := &fakeRunner{results: []runnerResult{{output: "10.5.0.1\n"}, {output: "home.test\n"}, {}}}
		if err := (DNSManager{Runner: runner}).RestoreIfOwned(context.Background(), before, dnsConfig()); err != nil {
			t.Fatal(err)
		}
		if len(runner.calls) != 3 || runner.calls[2].args[0] != "-setdnsservers" {
			t.Fatalf("partial restore calls = %#v", runner.calls)
		}
	})
}

func TestDNSRestoreRefusesForeignChangeWithoutMutation(t *testing.T) {
	before := tunnel.DNSSnapshot{Revision: "synthetic", Services: []tunnel.ServiceDNS{{ServiceID: "Wi-Fi"}}}
	runner := &fakeRunner{results: []runnerResult{{output: "203.0.113.53\n"}, {output: "There aren't any Search Domains set on Wi-Fi.\n"}}}
	err := (DNSManager{Runner: runner}).RestoreIfOwned(context.Background(), before, dnsConfig())
	if !errors.Is(err, ErrDNSConflict) {
		t.Fatalf("error = %v, want ErrDNSConflict", err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("foreign change caused mutation: %#v", runner.calls)
	}
}
