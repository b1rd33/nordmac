package darwinnet

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/b1rd33/nordmac/internal/tunnel"
)

type invocation struct {
	name string
	args []string
}

type runnerResult struct {
	output string
	err    error
}

type fakeRunner struct {
	calls   []invocation
	results []runnerResult
}

func (runner *fakeRunner) Run(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	runner.calls = append(runner.calls, invocation{name: name, args: append([]string(nil), arguments...)})
	if len(runner.results) == 0 {
		return nil, nil
	}
	result := runner.results[0]
	runner.results = runner.results[1:]
	return []byte(result.output), result.err
}

func TestRouteSnapshotParsesNumericDefault(t *testing.T) {
	runner := &fakeRunner{results: []runnerResult{{output: `route to: default
destination: default
       mask: default
    gateway: 192.0.2.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC>
`}}}
	snapshot, err := (RouteManager{Runner: runner}).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Default.Gateway.String() != "192.0.2.1" || snapshot.Default.Interface != "en0" {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
	want := invocation{name: "/sbin/route", args: []string{"-n", "get", "-inet", "default"}}
	if !reflect.DeepEqual(runner.calls, []invocation{want}) {
		t.Fatalf("calls = %#v", runner.calls)
	}
}

func TestRouteAddUsesExactArgumentsAfterNoExactConflict(t *testing.T) {
	runner := &fakeRunner{results: []runnerResult{
		{output: "destination: default\nmask: default\ninterface: en0\nflags: <UP,GATEWAY>\n"},
		{},
	}}
	route := tunnel.Route{Destination: netip.MustParsePrefix("10.250.0.0/24"), Interface: "utun11"}
	if err := (RouteManager{Runner: runner}).Add(context.Background(), route); err != nil {
		t.Fatal(err)
	}
	want := []invocation{
		{name: "/sbin/route", args: []string{"-n", "get", "-inet", "-net", "10.250.0.0/24"}},
		{name: "/sbin/route", args: []string{"-n", "add", "-inet", "-net", "10.250.0.0/24", "-interface", "utun11"}},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, want)
	}
}

func TestRouteAddRefusesExistingExactRoute(t *testing.T) {
	runner := &fakeRunner{results: []runnerResult{{output: `destination: 10.250.0
       mask: 255.255.255.0
    gateway: link#21
  interface: utun4
      flags: <UP,DONE,STATIC>
`}}}
	route := tunnel.Route{Destination: netip.MustParsePrefix("10.250.0.0/24"), Interface: "utun11"}
	if err := (RouteManager{Runner: runner}).Add(context.Background(), route); !errors.Is(err, ErrRouteConflict) {
		t.Fatalf("Add error = %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("conflict performed mutation: %#v", runner.calls)
	}
}

func TestRouteRemoveComparesOwnershipAndIsIdempotent(t *testing.T) {
	route := tunnel.Route{Destination: netip.MustParsePrefix("10.250.0.0/24"), Interface: "utun11"}
	t.Run("owned", func(t *testing.T) {
		runner := &fakeRunner{results: []runnerResult{
			{output: "destination: 10.250.0\nmask: 0xffffff00\ngateway: link#21\ninterface: utun11\nflags: <UP,DONE,STATIC>\n"},
			{},
		}}
		if err := (RouteManager{Runner: runner}).Remove(context.Background(), route); err != nil {
			t.Fatal(err)
		}
		if got := runner.calls[1].args; !reflect.DeepEqual(got, []string{"-n", "delete", "-inet", "-net", "10.250.0.0/24", "-interface", "utun11"}) {
			t.Fatalf("delete args = %#v", got)
		}
	})
	t.Run("changed", func(t *testing.T) {
		runner := &fakeRunner{results: []runnerResult{{output: "destination: 10.250.0\nmask: 255.255.255.0\ninterface: utun4\nflags: <UP>\n"}}}
		if err := (RouteManager{Runner: runner}).Remove(context.Background(), route); !errors.Is(err, ErrRouteConflict) {
			t.Fatalf("Remove error = %v", err)
		}
		if len(runner.calls) != 1 {
			t.Fatal("changed route was deleted")
		}
	})
	t.Run("absent", func(t *testing.T) {
		runner := &fakeRunner{results: []runnerResult{{err: errors.New("route: not in table")}}}
		if err := (RouteManager{Runner: runner}).Remove(context.Background(), route); err != nil {
			t.Fatal(err)
		}
		if len(runner.calls) != 1 {
			t.Fatal("absent route triggered delete")
		}
	})
}

func TestEndpointRoutePinsGatewayAndScope(t *testing.T) {
	route := tunnel.Route{
		Destination: netip.MustParsePrefix("203.0.113.10/32"),
		Gateway:     netip.MustParseAddr("192.0.2.1"),
		Interface:   "en0",
	}
	arguments, err := routeArguments("add", route)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"add", "-inet", "-host", "203.0.113.10", "192.0.2.1"}
	if !reflect.DeepEqual(arguments, want) {
		t.Fatalf("arguments = %#v, want %#v", arguments, want)
	}
}

func TestParseRoutePrefixRejectsNonContiguousMask(t *testing.T) {
	_, err := parseRoutePrefix(map[string]string{"destination": "10.250", "mask": "255.0.255.0"})
	if err == nil {
		t.Fatal("non-contiguous mask accepted")
	}
}
