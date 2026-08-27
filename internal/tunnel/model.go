// Package tunnel defines nordmac's privileged tunnel transaction without
// implementing any platform mutation. Concrete device, route, DNS, journal,
// and lock adapters are deliberately separate approval-gated work.
package tunnel

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
)

const JournalSchemaVersion = 2

var (
	sessionIDPattern   = regexp.MustCompile(`^[a-f0-9]{32}$`)
	interfacePattern   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]{0,15}$`)
	fingerprintPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Phase string

const (
	PhaseDisconnected     Phase = "disconnected"
	PhaseConnecting       Phase = "connecting"
	PhaseConnected        Phase = "connected"
	PhaseDegraded         Phase = "degraded"
	PhaseDisconnecting    Phase = "disconnecting"
	PhaseRollbackRequired Phase = "rollback_required"
	PhaseForeignConflict  Phase = "foreign_conflict"
)

type StepKind string

const (
	StepDevice        StepKind = "device"
	StepEndpointRoute StepKind = "endpoint_route"
	StepTunnelRoute   StepKind = "tunnel_route"
	StepDNS           StepKind = "dns"
)

type RoutePolicy string

const (
	RoutePolicyScopedIPv4 RoutePolicy = "scoped_ipv4"
	RoutePolicyFullIPv4   RoutePolicy = "full_ipv4"
)

type StepStatus string

const (
	StepPlanned    StepStatus = "planned"
	StepApplied    StepStatus = "applied"
	StepRolledBack StepStatus = "rolled_back"
)

// Plan is the non-secret, fully validated input accepted by the future helper.
// IPv6 remains deliberately unsupported. ScopedIPv4 is the only policy allowed
// by the Gate 3 harness; FullIPv4 remains approval-gated future work.
type Plan struct {
	SessionID         string         `json:"session_id"`
	OwnerUID          int            `json:"owner_uid"`
	Endpoint          netip.AddrPort `json:"endpoint"`
	PhysicalGateway   netip.Addr     `json:"physical_gateway"`
	PhysicalInterface string         `json:"physical_interface"`
	TunnelAddress     netip.Prefix   `json:"tunnel_address"`
	TunnelMTU         int            `json:"tunnel_mtu"`
	TunnelDNS         []netip.Addr   `json:"tunnel_dns"`
	RoutePolicy       RoutePolicy    `json:"route_policy"`
	ScopedRoutes      []netip.Prefix `json:"scoped_routes,omitempty"`
	PeerFingerprint   string         `json:"peer_public_key_fingerprint"`
}

func (plan Plan) Validate() error {
	if !ValidSessionID(plan.SessionID) {
		return errors.New("session id must be 32 lowercase hexadecimal characters")
	}
	if plan.OwnerUID < 0 {
		return errors.New("owner uid must not be negative")
	}
	if !plan.Endpoint.IsValid() || !plan.Endpoint.Addr().Is4() || plan.Endpoint.Port() == 0 || !plan.Endpoint.Addr().IsGlobalUnicast() {
		return errors.New("endpoint must be a unicast IPv4 address and nonzero port")
	}
	if !plan.PhysicalGateway.IsValid() || !plan.PhysicalGateway.Is4() || plan.PhysicalGateway.IsUnspecified() {
		return errors.New("physical gateway must be an IPv4 address")
	}
	if !interfacePattern.MatchString(plan.PhysicalInterface) {
		return errors.New("physical interface is invalid")
	}
	if !plan.TunnelAddress.IsValid() || !plan.TunnelAddress.Addr().Is4() || plan.TunnelAddress != plan.TunnelAddress.Masked() {
		return errors.New("tunnel address must be a canonical IPv4 prefix")
	}
	if plan.TunnelAddress.Bits() != 32 {
		return errors.New("tunnel address must be an IPv4 /32")
	}
	if plan.TunnelMTU < 1280 || plan.TunnelMTU > 9000 {
		return errors.New("tunnel MTU must be between 1280 and 9000")
	}
	if err := plan.validatePolicy(); err != nil {
		return err
	}
	seenDNS := map[netip.Addr]struct{}{}
	for _, server := range plan.TunnelDNS {
		if !server.IsValid() || !server.Is4() || server.IsUnspecified() || server.IsMulticast() {
			return errors.New("tunnel DNS servers must be usable IPv4 addresses")
		}
		if _, exists := seenDNS[server]; exists {
			return errors.New("tunnel DNS servers must be unique")
		}
		seenDNS[server] = struct{}{}
	}
	if !fingerprintPattern.MatchString(plan.PeerFingerprint) {
		return errors.New("peer public-key fingerprint must be lowercase SHA-256 hex")
	}
	return nil
}

func ValidSessionID(sessionID string) bool {
	return sessionIDPattern.MatchString(sessionID)
}

func (plan Plan) EndpointRoute() Route {
	return Route{
		Destination: netip.PrefixFrom(plan.Endpoint.Addr(), 32),
		Gateway:     plan.PhysicalGateway,
		Interface:   plan.PhysicalInterface,
	}
}

func (plan Plan) TunnelRoutes() []Route {
	if plan.RoutePolicy == RoutePolicyScopedIPv4 {
		routes := make([]Route, len(plan.ScopedRoutes))
		for index, prefix := range plan.ScopedRoutes {
			routes[index] = Route{Destination: prefix}
		}
		return routes
	}
	return []Route{
		{Destination: netip.MustParsePrefix("0.0.0.0/1")},
		{Destination: netip.MustParsePrefix("128.0.0.0/1")},
	}
}

func (plan Plan) UsesDNS() bool { return plan.RoutePolicy == RoutePolicyFullIPv4 }

func (plan Plan) validatePolicy() error {
	switch plan.RoutePolicy {
	case RoutePolicyFullIPv4:
		if len(plan.ScopedRoutes) != 0 {
			return errors.New("full IPv4 policy must not contain scoped routes")
		}
		if len(plan.TunnelDNS) == 0 || len(plan.TunnelDNS) > 4 {
			return errors.New("full IPv4 policy requires one to four DNS servers")
		}
	case RoutePolicyScopedIPv4:
		if len(plan.TunnelDNS) != 0 {
			return errors.New("scoped IPv4 policy must not change DNS")
		}
		if len(plan.ScopedRoutes) == 0 || len(plan.ScopedRoutes) > 4 {
			return errors.New("scoped IPv4 policy requires one to four routes")
		}
		seen := map[netip.Prefix]struct{}{}
		for _, prefix := range plan.ScopedRoutes {
			if !prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked() ||
				!prefix.Addr().IsPrivate() || prefix.Bits() < 16 || prefix.Bits() > 32 {
				return errors.New("scoped routes must be canonical private IPv4 prefixes between /16 and /32")
			}
			if prefix.Contains(plan.Endpoint.Addr()) || prefix.Contains(plan.PhysicalGateway) {
				return errors.New("scoped routes must not contain the endpoint or physical gateway")
			}
			if _, exists := seen[prefix]; exists {
				return errors.New("scoped routes must be unique")
			}
			seen[prefix] = struct{}{}
		}
	default:
		return fmt.Errorf("unsupported route policy %q", plan.RoutePolicy)
	}
	return nil
}

func (plan Plan) DNSConfig() DNSConfig {
	return DNSConfig{Servers: slices.Clone(plan.TunnelDNS)}
}

type Route struct {
	Destination netip.Prefix `json:"destination"`
	Gateway     netip.Addr   `json:"gateway,omitempty"`
	Interface   string       `json:"interface,omitempty"`
}

func (route Route) Validate() error {
	if !route.Destination.IsValid() || !route.Destination.Addr().Is4() || route.Destination != route.Destination.Masked() {
		return errors.New("route destination must be a canonical IPv4 prefix")
	}
	if route.Gateway.IsValid() && (!route.Gateway.Is4() || route.Gateway.IsUnspecified()) {
		return errors.New("route gateway must be a usable IPv4 address")
	}
	if route.Interface != "" && !interfacePattern.MatchString(route.Interface) {
		return errors.New("route interface is invalid")
	}
	return nil
}

type RouteSnapshot struct {
	Default Route `json:"default"`
}

type ServiceDNS struct {
	ServiceID     string       `json:"service_id"`
	Servers       []netip.Addr `json:"servers"`
	SearchDomains []string     `json:"search_domains,omitempty"`
}

type DNSSnapshot struct {
	Revision string       `json:"revision"`
	Services []ServiceDNS `json:"services"`
}

type DNSConfig struct {
	Servers       []netip.Addr `json:"servers"`
	SearchDomains []string     `json:"search_domains,omitempty"`
}

type DeviceSpec struct {
	SessionID       string         `json:"session_id"`
	Address         netip.Prefix   `json:"address"`
	MTU             int            `json:"mtu"`
	Endpoint        netip.AddrPort `json:"endpoint"`
	PeerFingerprint string         `json:"peer_public_key_fingerprint"`
}

type DeviceHandle struct {
	Interface string `json:"interface"`
	OwnerPID  int    `json:"owner_pid"`
}

type InterfaceAddress struct {
	Interface string       `json:"interface"`
	Prefix    netip.Prefix `json:"prefix"`
}

func (address InterfaceAddress) Validate() error {
	if !interfacePattern.MatchString(address.Interface) {
		return errors.New("interface address has an invalid interface")
	}
	if !address.Prefix.IsValid() || !address.Prefix.Addr().Is4() || address.Prefix.Bits() != 32 {
		return errors.New("interface address must be an IPv4 /32")
	}
	return nil
}

func (handle DeviceHandle) Validate() error {
	if !interfacePattern.MatchString(handle.Interface) || handle.OwnerPID <= 0 {
		return errors.New("device handle is invalid")
	}
	return nil
}

type Entry struct {
	Kind   StepKind   `json:"kind"`
	Status StepStatus `json:"status"`
	Route  *Route     `json:"route,omitempty"`
}

type Journal struct {
	SchemaVersion int           `json:"schema_version"`
	SessionID     string        `json:"session_id"`
	OwnerUID      int           `json:"owner_uid"`
	Phase         Phase         `json:"phase"`
	Plan          Plan          `json:"plan"`
	RouteBefore   RouteSnapshot `json:"route_before"`
	DNSBefore     DNSSnapshot   `json:"dns_before"`
	Device        *DeviceHandle `json:"device,omitempty"`
	Entries       []Entry       `json:"entries"`
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
}

func (journal Journal) Validate() error {
	if journal.SchemaVersion != JournalSchemaVersion {
		return fmt.Errorf("unsupported journal schema %d", journal.SchemaVersion)
	}
	if err := journal.Plan.Validate(); err != nil {
		return fmt.Errorf("invalid journal plan: %w", err)
	}
	if journal.SessionID != journal.Plan.SessionID || journal.OwnerUID != journal.Plan.OwnerUID {
		return errors.New("journal identity does not match its plan")
	}
	if !validPhase(journal.Phase) {
		return fmt.Errorf("invalid journal phase %q", journal.Phase)
	}
	if journal.CreatedAt.IsZero() || journal.UpdatedAt.Before(journal.CreatedAt) {
		return errors.New("journal timestamps are invalid")
	}
	if err := validatePreimages(journal); err != nil {
		return err
	}
	if journal.Device != nil {
		if err := journal.Device.Validate(); err != nil {
			return fmt.Errorf("invalid journal device: %w", err)
		}
	}
	expectedKinds := journal.expectedKinds()
	if len(journal.Entries) > len(expectedKinds) {
		return errors.New("journal contains too many transaction entries")
	}
	for index, entry := range journal.Entries {
		if !validStep(entry.Kind) || !validStepStatus(entry.Status) {
			return fmt.Errorf("invalid journal entry %d", index)
		}
		if entry.Kind != expectedKinds[index] {
			return fmt.Errorf("journal entry %d is out of transaction order", index)
		}
		if entry.Kind == StepEndpointRoute || entry.Kind == StepTunnelRoute {
			if entry.Route == nil {
				return fmt.Errorf("journal route entry %d is missing its route", index)
			}
			if err := entry.Route.Validate(); err != nil {
				return fmt.Errorf("invalid journal route entry %d: %w", index, err)
			}
		} else if entry.Route != nil {
			return fmt.Errorf("non-route journal entry %d contains a route", index)
		}
		if journal.Phase == PhaseConnecting && entry.Status == StepRolledBack {
			return errors.New("connecting journal contains a rolled-back entry")
		}
	}
	if len(journal.Entries) > 1 && journal.Entries[1].Status == StepApplied && journal.Device == nil {
		return errors.New("applied device entry is missing its handle")
	}
	if journal.Device != nil && len(journal.Entries) < 2 {
		return errors.New("journal device has no ownership entry")
	}
	if len(journal.Entries) > 0 && *journal.Entries[0].Route != journal.Plan.EndpointRoute() {
		return errors.New("journal endpoint route does not match its plan")
	}
	if len(journal.Entries) > 2 {
		if journal.Device == nil {
			return errors.New("journal tunnel routes are missing their device handle")
		}
		expectedRoutes := journal.Plan.TunnelRoutes()
		for index := 2; index < min(len(journal.Entries), 2+len(expectedRoutes)); index++ {
			expected := expectedRoutes[index-2]
			expected.Interface = journal.Device.Interface
			if *journal.Entries[index].Route != expected {
				return fmt.Errorf("journal tunnel route %d does not match its plan", index-2)
			}
		}
	}
	if journal.Phase == PhaseConnected || journal.Phase == PhaseDegraded {
		if len(journal.Entries) != len(expectedKinds) || journal.Device == nil {
			return errors.New("connected journal is missing transaction entries")
		}
		for _, entry := range journal.Entries {
			if entry.Status != StepApplied {
				return errors.New("connected journal contains a non-applied entry")
			}
		}
	}
	if journal.Phase == PhaseDisconnected {
		for _, entry := range journal.Entries {
			if entry.Status != StepRolledBack {
				return errors.New("disconnected journal contains an owned entry")
			}
		}
	}
	return nil
}

func (journal Journal) expectedKinds() []StepKind {
	kinds := []StepKind{StepEndpointRoute, StepDevice}
	for range journal.Plan.TunnelRoutes() {
		kinds = append(kinds, StepTunnelRoute)
	}
	if journal.Plan.UsesDNS() {
		kinds = append(kinds, StepDNS)
	}
	return kinds
}

func validatePreimages(journal Journal) error {
	if err := journal.RouteBefore.Default.Validate(); err != nil {
		return fmt.Errorf("invalid route pre-image: %w", err)
	}
	if journal.RouteBefore.Default.Destination != netip.MustParsePrefix("0.0.0.0/0") ||
		journal.RouteBefore.Default.Gateway != journal.Plan.PhysicalGateway ||
		journal.RouteBefore.Default.Interface != journal.Plan.PhysicalInterface {
		return errors.New("route pre-image does not match the planned physical route")
	}
	if !journal.Plan.UsesDNS() {
		if journal.DNSBefore.Revision != "" || len(journal.DNSBefore.Services) != 0 {
			return errors.New("scoped journal contains a DNS pre-image")
		}
		return nil
	}
	if len(journal.DNSBefore.Revision) == 0 || len(journal.DNSBefore.Revision) > 128 || hasControl(journal.DNSBefore.Revision) {
		return errors.New("DNS pre-image revision is invalid")
	}
	if len(journal.DNSBefore.Services) == 0 || len(journal.DNSBefore.Services) > 32 {
		return errors.New("DNS pre-image service count is invalid")
	}
	seenServices := map[string]struct{}{}
	for _, service := range journal.DNSBefore.Services {
		if len(service.ServiceID) == 0 || len(service.ServiceID) > 256 || hasControl(service.ServiceID) {
			return errors.New("DNS pre-image service id is invalid")
		}
		if _, exists := seenServices[service.ServiceID]; exists {
			return errors.New("DNS pre-image service ids must be unique")
		}
		seenServices[service.ServiceID] = struct{}{}
		if len(service.Servers) > 8 || len(service.SearchDomains) > 32 {
			return errors.New("DNS pre-image service data exceeds limits")
		}
		for _, server := range service.Servers {
			if !server.IsValid() || server.IsUnspecified() || server.IsMulticast() {
				return errors.New("DNS pre-image contains an invalid server")
			}
		}
		for _, domain := range service.SearchDomains {
			if len(domain) == 0 || len(domain) > 253 || hasControl(domain) {
				return errors.New("DNS pre-image contains an invalid search domain")
			}
		}
	}
	return nil
}

func hasControl(value string) bool {
	return strings.ContainsFunc(value, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	})
}

func validPhase(phase Phase) bool {
	switch phase {
	case PhaseDisconnected, PhaseConnecting, PhaseConnected, PhaseDegraded, PhaseDisconnecting, PhaseRollbackRequired, PhaseForeignConflict:
		return true
	default:
		return false
	}
}

func validStep(step StepKind) bool {
	switch step {
	case StepDevice, StepEndpointRoute, StepTunnelRoute, StepDNS:
		return true
	default:
		return false
	}
}

func validStepStatus(status StepStatus) bool {
	switch status {
	case StepPlanned, StepApplied, StepRolledBack:
		return true
	default:
		return false
	}
}
