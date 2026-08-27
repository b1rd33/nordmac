package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

type fakeEnvironment struct {
	events           []string
	failAction       string
	failUpdateNumber int
	updateCount      int
	journal          *Journal
	deviceBySession  map[string]DeviceHandle
	routes           map[string]Route
	dnsApplied       bool
	conflict         bool
	physicalRoute    Route
}

func newFakeEnvironment() *fakeEnvironment {
	return &fakeEnvironment{
		deviceBySession: map[string]DeviceHandle{},
		routes:          map[string]Route{},
		physicalRoute: Route{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Gateway:     netip.MustParseAddr("192.0.2.1"),
			Interface:   "en0",
		},
	}
}

func (environment *fakeEnvironment) controller() Controller {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	return Controller{
		Journals:  fakeJournalStore{environment},
		Locks:     environment,
		Conflicts: environment,
		Devices:   fakeDeviceManager{environment},
		Routes:    fakeRouteManager{environment},
		DNS:       fakeDNSManager{environment},
		Verifier:  environment,
		Now: func() time.Time {
			now = now.Add(time.Millisecond)
			return now
		},
	}
}

func testPlan() Plan {
	return Plan{
		SessionID:         strings.Repeat("a", 32),
		OwnerUID:          501,
		Endpoint:          netip.MustParseAddrPort("203.0.113.10:51820"),
		PhysicalGateway:   netip.MustParseAddr("192.0.2.1"),
		PhysicalInterface: "en0",
		TunnelAddress:     netip.MustParsePrefix("10.5.0.2/32"),
		TunnelMTU:         1420,
		TunnelDNS:         []netip.Addr{netip.MustParseAddr("10.5.0.1")},
		RoutePolicy:       RoutePolicyFullIPv4,
		PeerFingerprint:   strings.Repeat("b", 64),
	}
}

func scopedTestPlan() Plan {
	plan := testPlan()
	plan.RoutePolicy = RoutePolicyScopedIPv4
	plan.TunnelDNS = nil
	plan.ScopedRoutes = []netip.Prefix{netip.MustParsePrefix("10.250.0.0/24")}
	return plan
}

func (environment *fakeEnvironment) action(name string, mutation func()) error {
	environment.events = append(environment.events, name)
	if mutation != nil {
		mutation()
	}
	if environment.failAction == name {
		return errors.New("injected " + name + " failure")
	}
	return nil
}

func (environment *fakeEnvironment) createJournal(journal Journal) error {
	if err := journal.Validate(); err != nil {
		return err
	}
	if environment.journal != nil {
		return errors.New("journal already exists")
	}
	copy := cloneJournal(journal)
	environment.journal = &copy
	return environment.action("journal.create", nil)
}

func (environment *fakeEnvironment) updateJournal(journal Journal) error {
	if err := journal.Validate(); err != nil {
		return err
	}
	environment.updateCount++
	copy := cloneJournal(journal)
	environment.journal = &copy
	if environment.failUpdateNumber == environment.updateCount {
		return fmt.Errorf("injected journal update %d failure", environment.updateCount)
	}
	return nil
}

func (environment *fakeEnvironment) loadJournal(sessionID string) (Journal, error) {
	if environment.journal == nil || environment.journal.SessionID != sessionID {
		return Journal{}, ErrJournalNotFound
	}
	return cloneJournal(*environment.journal), nil
}

func (environment *fakeEnvironment) deleteJournal(sessionID string) error {
	if environment.journal == nil || environment.journal.SessionID != sessionID {
		return ErrJournalNotFound
	}
	return environment.action("journal.delete", func() { environment.journal = nil })
}

func (environment *fakeEnvironment) Acquire(_ context.Context, _ string) (func() error, error) {
	if err := environment.action("lock.acquire", nil); err != nil {
		return nil, err
	}
	return func() error { return environment.action("lock.release", nil) }, nil
}

func (environment *fakeEnvironment) Check(_ context.Context, _ Plan) error {
	if environment.conflict {
		return errors.New("another default-route VPN is active")
	}
	return environment.action("conflict.check", nil)
}

func (environment *fakeEnvironment) createDevice(spec DeviceSpec) (DeviceHandle, error) {
	handle := DeviceHandle{Interface: "utun9", OwnerPID: 4242}
	err := environment.action("device.create", func() { environment.deviceBySession[spec.SessionID] = handle })
	return handle, err
}

func (environment *fakeEnvironment) DeleteOwned(_ context.Context, sessionID string, handle *DeviceHandle) error {
	return environment.action("device.delete", func() {
		owned, exists := environment.deviceBySession[sessionID]
		if !exists {
			return
		}
		if handle == nil || *handle == owned {
			delete(environment.deviceBySession, sessionID)
		}
	})
}

func (environment *fakeEnvironment) Snapshot(_ context.Context) (RouteSnapshot, error) {
	if err := environment.action("route.snapshot", nil); err != nil {
		return RouteSnapshot{}, err
	}
	return RouteSnapshot{Default: environment.physicalRoute}, nil
}

func routeKey(route Route) string {
	return route.Destination.String() + "@" + route.Interface
}

func (environment *fakeEnvironment) Add(_ context.Context, route Route) error {
	name := "route.add:" + route.Destination.String()
	return environment.action(name, func() { environment.routes[routeKey(route)] = route })
}

func (environment *fakeEnvironment) Remove(_ context.Context, route Route) error {
	name := "route.remove:" + route.Destination.String()
	return environment.action(name, func() { delete(environment.routes, routeKey(route)) })
}

func (environment *fakeEnvironment) Apply(_ context.Context, _ DNSConfig) error {
	return environment.action("dns.apply", func() { environment.dnsApplied = true })
}

func (environment *fakeEnvironment) RestoreIfOwned(_ context.Context, _ DNSSnapshot, _ DNSConfig) error {
	return environment.action("dns.restore", func() { environment.dnsApplied = false })
}

func (environment *fakeEnvironment) Verify(_ context.Context, _ Journal) error {
	return environment.action("verify", nil)
}

// fakeRouteManager and fakeDNSManager disambiguate the two Snapshot methods in
// the controller's route and DNS interfaces.
type fakeRouteManager struct{ environment *fakeEnvironment }
type fakeDNSManager struct{ environment *fakeEnvironment }
type fakeDeviceManager struct{ environment *fakeEnvironment }
type fakeJournalStore struct{ environment *fakeEnvironment }

func (store fakeJournalStore) Create(_ context.Context, journal Journal) error {
	return store.environment.createJournal(journal)
}
func (store fakeJournalStore) Update(_ context.Context, journal Journal) error {
	return store.environment.updateJournal(journal)
}
func (store fakeJournalStore) Load(_ context.Context, sessionID string) (Journal, error) {
	return store.environment.loadJournal(sessionID)
}
func (store fakeJournalStore) Delete(_ context.Context, sessionID string) error {
	return store.environment.deleteJournal(sessionID)
}

func (manager fakeRouteManager) Snapshot(ctx context.Context) (RouteSnapshot, error) {
	return manager.environment.Snapshot(ctx)
}
func (manager fakeRouteManager) Add(ctx context.Context, route Route) error {
	return manager.environment.Add(ctx, route)
}
func (manager fakeRouteManager) Remove(ctx context.Context, route Route) error {
	return manager.environment.Remove(ctx, route)
}
func (manager fakeDNSManager) Snapshot(_ context.Context) (DNSSnapshot, error) {
	if err := manager.environment.action("dns.snapshot", nil); err != nil {
		return DNSSnapshot{}, err
	}
	return DNSSnapshot{
		Revision: "synthetic-before",
		Services: []ServiceDNS{{ServiceID: "synthetic-wifi", Servers: []netip.Addr{netip.MustParseAddr("192.0.2.53")}}},
	}, nil
}
func (manager fakeDNSManager) Apply(ctx context.Context, config DNSConfig) error {
	return manager.environment.Apply(ctx, config)
}
func (manager fakeDNSManager) RestoreIfOwned(ctx context.Context, before DNSSnapshot, applied DNSConfig) error {
	return manager.environment.RestoreIfOwned(ctx, before, applied)
}
func (manager fakeDeviceManager) Create(_ context.Context, spec DeviceSpec) (DeviceHandle, error) {
	return manager.environment.createDevice(spec)
}
func (manager fakeDeviceManager) DeleteOwned(ctx context.Context, sessionID string, handle *DeviceHandle) error {
	return manager.environment.DeleteOwned(ctx, sessionID, handle)
}

func withManagers(controller Controller, environment *fakeEnvironment) Controller {
	controller.Routes = fakeRouteManager{environment}
	controller.DNS = fakeDNSManager{environment}
	controller.Devices = fakeDeviceManager{environment}
	return controller
}

func TestConnectAndDisconnectTransactionOrder(t *testing.T) {
	environment := newFakeEnvironment()
	controller := withManagers(environment.controller(), environment)
	journal, err := controller.Connect(context.Background(), testPlan())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if journal.Phase != PhaseConnected || environment.journal == nil || len(environment.routes) != 3 || !environment.dnsApplied || len(environment.deviceBySession) != 1 {
		t.Fatalf("unexpected connected state: phase=%s journal=%v routes=%d dns=%v devices=%d", journal.Phase, environment.journal != nil, len(environment.routes), environment.dnsApplied, len(environment.deviceBySession))
	}

	wantApplyOrder := []string{
		"route.add:203.0.113.10/32",
		"device.create",
		"route.add:0.0.0.0/1",
		"route.add:128.0.0.0/1",
		"dns.apply",
		"verify",
	}
	if got := selectedEvents(environment.events, "device.create", "route.add:", "dns.apply", "verify"); !reflect.DeepEqual(got, wantApplyOrder) {
		t.Fatalf("apply order = %#v, want %#v", got, wantApplyOrder)
	}

	environment.events = nil
	if err := controller.Disconnect(context.Background(), testPlan().SessionID, testPlan().OwnerUID); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	wantRollbackOrder := []string{
		"dns.restore",
		"route.remove:128.0.0.0/1",
		"route.remove:0.0.0.0/1",
		"device.delete",
		"route.remove:203.0.113.10/32",
	}
	if got := selectedEvents(environment.events, "dns.restore", "route.remove:", "device.delete"); !reflect.DeepEqual(got, wantRollbackOrder) {
		t.Fatalf("rollback order = %#v, want %#v", got, wantRollbackOrder)
	}
	assertClean(t, environment)
	if err := controller.Disconnect(context.Background(), testPlan().SessionID, testPlan().OwnerUID); err != nil {
		t.Fatalf("idempotent Disconnect: %v", err)
	}
}

func TestScopedConnectNeverTouchesDNSOrDefaultRoutes(t *testing.T) {
	environment := newFakeEnvironment()
	controller := withManagers(environment.controller(), environment)
	controller.DNS = nil
	plan := scopedTestPlan()
	journal, err := controller.Connect(context.Background(), plan)
	if err != nil {
		t.Fatalf("Connect scoped: %v", err)
	}
	if journal.Phase != PhaseConnected || len(environment.routes) != 2 || environment.dnsApplied {
		t.Fatalf("unexpected scoped state: phase=%s routes=%#v dns=%v", journal.Phase, environment.routes, environment.dnsApplied)
	}
	wantApplyOrder := []string{
		"route.add:203.0.113.10/32",
		"device.create",
		"route.add:10.250.0.0/24",
		"verify",
	}
	if got := selectedEvents(environment.events, "device.create", "route.add:", "dns.", "verify"); !reflect.DeepEqual(got, wantApplyOrder) {
		t.Fatalf("scoped apply order = %#v, want %#v", got, wantApplyOrder)
	}

	environment.events = nil
	if err := controller.Disconnect(context.Background(), plan.SessionID, plan.OwnerUID); err != nil {
		t.Fatalf("Disconnect scoped: %v", err)
	}
	wantRollbackOrder := []string{
		"route.remove:10.250.0.0/24",
		"device.delete",
		"route.remove:203.0.113.10/32",
	}
	if got := selectedEvents(environment.events, "dns.", "route.remove:", "device.delete"); !reflect.DeepEqual(got, wantRollbackOrder) {
		t.Fatalf("scoped rollback order = %#v, want %#v", got, wantRollbackOrder)
	}
	assertClean(t, environment)
}

func TestScopedConnectRollsBackEveryMutationAndJournalBoundary(t *testing.T) {
	for _, action := range []string{
		"device.create",
		"route.add:203.0.113.10/32",
		"route.add:10.250.0.0/24",
		"verify",
	} {
		t.Run(action, func(t *testing.T) {
			environment := newFakeEnvironment()
			environment.failAction = action
			controller := withManagers(environment.controller(), environment)
			controller.DNS = nil
			if _, err := controller.Connect(context.Background(), scopedTestPlan()); err == nil {
				t.Fatal("scoped Connect unexpectedly succeeded")
			}
			assertClean(t, environment)
		})
	}
	for failure := 1; failure <= 7; failure++ {
		t.Run(fmt.Sprintf("update_%02d", failure), func(t *testing.T) {
			environment := newFakeEnvironment()
			environment.failUpdateNumber = failure
			controller := withManagers(environment.controller(), environment)
			controller.DNS = nil
			if _, err := controller.Connect(context.Background(), scopedTestPlan()); err == nil {
				t.Fatal("scoped Connect unexpectedly succeeded")
			}
			assertClean(t, environment)
		})
	}
}

type cancellingVerifier struct{ cancel context.CancelFunc }

func (verifier cancellingVerifier) Verify(ctx context.Context, _ Journal) error {
	verifier.cancel()
	<-ctx.Done()
	return ctx.Err()
}

func TestCancelledVerificationUsesIndependentRollbackContext(t *testing.T) {
	environment := newFakeEnvironment()
	controller := withManagers(environment.controller(), environment)
	controller.DNS = nil
	ctx, cancel := context.WithCancel(context.Background())
	controller.Verifier = cancellingVerifier{cancel: cancel}
	if _, err := controller.Connect(ctx, scopedTestPlan()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Connect error = %v, want cancellation", err)
	}
	assertClean(t, environment)
}

func TestConnectRollsBackAfterEveryMutationFailure(t *testing.T) {
	actions := []string{
		"device.create",
		"route.add:203.0.113.10/32",
		"route.add:0.0.0.0/1",
		"route.add:128.0.0.0/1",
		"dns.apply",
		"verify",
	}
	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			environment := newFakeEnvironment()
			environment.failAction = action
			controller := withManagers(environment.controller(), environment)
			if _, err := controller.Connect(context.Background(), testPlan()); err == nil {
				t.Fatal("Connect unexpectedly succeeded")
			}
			assertClean(t, environment)
		})
	}
}

func TestConnectRollsBackAfterEveryJournalBoundaryFailure(t *testing.T) {
	for failure := 1; failure <= 11; failure++ {
		t.Run(fmt.Sprintf("update_%02d", failure), func(t *testing.T) {
			environment := newFakeEnvironment()
			environment.failUpdateNumber = failure
			controller := withManagers(environment.controller(), environment)
			if _, err := controller.Connect(context.Background(), testPlan()); err == nil {
				t.Fatal("Connect unexpectedly succeeded")
			}
			assertClean(t, environment)
		})
	}
}

func TestConnectFailsClosedBeforeFirstMutation(t *testing.T) {
	for _, action := range []string{"lock.acquire", "conflict.check", "route.snapshot", "dns.snapshot", "journal.create"} {
		t.Run(action, func(t *testing.T) {
			environment := newFakeEnvironment()
			environment.failAction = action
			controller := withManagers(environment.controller(), environment)
			if _, err := controller.Connect(context.Background(), testPlan()); err == nil {
				t.Fatal("Connect unexpectedly succeeded")
			}
			if len(environment.routes) != 0 || environment.dnsApplied || len(environment.deviceBySession) != 0 {
				t.Fatalf("pre-mutation failure changed resources: routes=%d dns=%v devices=%d", len(environment.routes), environment.dnsApplied, len(environment.deviceBySession))
			}
			if action == "journal.create" {
				if environment.journal == nil {
					t.Fatal("ambiguous journal create did not retain recovery evidence")
				}
				environment.failAction = ""
				if err := controller.Disconnect(context.Background(), testPlan().SessionID, testPlan().OwnerUID); err != nil {
					t.Fatalf("recover ambiguous journal create: %v", err)
				}
			} else if environment.journal != nil {
				t.Fatal("failure before journal creation left a journal")
			}
		})
	}
}

func TestIncompleteRollbackIsRetainedAndRecoverable(t *testing.T) {
	environment := newFakeEnvironment()
	controller := withManagers(environment.controller(), environment)
	if _, err := controller.Connect(context.Background(), testPlan()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	environment.failAction = "route.remove:0.0.0.0/1"
	err := controller.Disconnect(context.Background(), testPlan().SessionID, testPlan().OwnerUID)
	if !errors.Is(err, ErrRollback) {
		t.Fatalf("Disconnect error = %v, want ErrRollback", err)
	}
	if environment.journal == nil || environment.journal.Phase != PhaseRollbackRequired {
		t.Fatalf("rollback evidence not retained: journal=%v phase=%v routes=%d", environment.journal != nil, environment.journal.Phase, len(environment.routes))
	}

	environment.failAction = ""
	if err := controller.Disconnect(context.Background(), testPlan().SessionID, testPlan().OwnerUID); err != nil {
		t.Fatalf("recovery Disconnect: %v", err)
	}
	assertClean(t, environment)
}

func TestEveryRollbackOperationCanBeRetried(t *testing.T) {
	actions := []string{
		"dns.restore",
		"route.remove:128.0.0.0/1",
		"route.remove:0.0.0.0/1",
		"route.remove:203.0.113.10/32",
		"device.delete",
	}
	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			environment := newFakeEnvironment()
			controller := withManagers(environment.controller(), environment)
			if _, err := controller.Connect(context.Background(), testPlan()); err != nil {
				t.Fatalf("Connect: %v", err)
			}
			environment.failAction = action
			if err := controller.Disconnect(context.Background(), testPlan().SessionID, testPlan().OwnerUID); !errors.Is(err, ErrRollback) {
				t.Fatalf("Disconnect error = %v, want ErrRollback", err)
			}
			if environment.journal == nil || environment.journal.Phase != PhaseRollbackRequired {
				t.Fatal("failed rollback did not retain rollback_required journal")
			}
			environment.failAction = ""
			if err := controller.Disconnect(context.Background(), testPlan().SessionID, testPlan().OwnerUID); err != nil {
				t.Fatalf("retry Disconnect: %v", err)
			}
			assertClean(t, environment)
		})
	}
}

func TestConnectRefusesStalePhysicalRouteAndConflict(t *testing.T) {
	t.Run("stale route", func(t *testing.T) {
		environment := newFakeEnvironment()
		environment.physicalRoute.Gateway = netip.MustParseAddr("192.0.2.254")
		controller := withManagers(environment.controller(), environment)
		if _, err := controller.Connect(context.Background(), testPlan()); err == nil || !strings.Contains(err.Error(), "stale endpoint pin") {
			t.Fatalf("Connect error = %v", err)
		}
		assertClean(t, environment)
	})
	t.Run("foreign conflict", func(t *testing.T) {
		environment := newFakeEnvironment()
		environment.conflict = true
		controller := withManagers(environment.controller(), environment)
		if _, err := controller.Connect(context.Background(), testPlan()); !errors.Is(err, ErrConflict) {
			t.Fatalf("Connect error = %v, want ErrConflict", err)
		}
		assertClean(t, environment)
	})
}

func TestDisconnectRefusesWrongOwner(t *testing.T) {
	environment := newFakeEnvironment()
	controller := withManagers(environment.controller(), environment)
	if _, err := controller.Connect(context.Background(), testPlan()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := controller.Disconnect(context.Background(), testPlan().SessionID, 502); err == nil {
		t.Fatal("Disconnect unexpectedly accepted the wrong owner")
	}
	if environment.journal == nil || len(environment.routes) != 3 {
		t.Fatal("wrong-owner request changed tunnel state")
	}
}

func selectedEvents(events []string, exactOrPrefixes ...string) []string {
	var selected []string
	for _, event := range events {
		for _, candidate := range exactOrPrefixes {
			if event == candidate || strings.HasSuffix(candidate, ":") && strings.HasPrefix(event, candidate) {
				selected = append(selected, event)
				break
			}
		}
	}
	return selected
}

func assertClean(t *testing.T, environment *fakeEnvironment) {
	t.Helper()
	if environment.journal != nil || len(environment.routes) != 0 || environment.dnsApplied || len(environment.deviceBySession) != 0 {
		t.Fatalf("resources not clean: journal=%v routes=%d dns=%v devices=%d events=%v", environment.journal != nil, len(environment.routes), environment.dnsApplied, len(environment.deviceBySession), environment.events)
	}
}

func cloneJournal(journal Journal) Journal {
	copy := journal
	copy.Plan.TunnelDNS = slices.Clone(journal.Plan.TunnelDNS)
	copy.Plan.ScopedRoutes = slices.Clone(journal.Plan.ScopedRoutes)
	copy.DNSBefore.Services = slices.Clone(journal.DNSBefore.Services)
	for index := range copy.DNSBefore.Services {
		copy.DNSBefore.Services[index].Servers = slices.Clone(journal.DNSBefore.Services[index].Servers)
		copy.DNSBefore.Services[index].SearchDomains = slices.Clone(journal.DNSBefore.Services[index].SearchDomains)
	}
	copy.Entries = make([]Entry, len(journal.Entries))
	for index, entry := range journal.Entries {
		copy.Entries[index] = entry
		if entry.Route != nil {
			route := *entry.Route
			copy.Entries[index].Route = &route
		}
	}
	if journal.Device != nil {
		device := *journal.Device
		copy.Device = &device
	}
	return copy
}
