package darwinnet

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"strconv"
	"strings"

	"github.com/b1rd33/nordmac/internal/tunnel"
)

const defaultRoutePath = "/sbin/route"

var ErrRouteConflict = errors.New("route conflicts with existing host state")

type RouteManager struct {
	Runner    Runner
	RoutePath string
}

func (manager RouteManager) Snapshot(ctx context.Context) (tunnel.RouteSnapshot, error) {
	output, err := manager.run(ctx, "get", "-inet", "default")
	if err != nil {
		return tunnel.RouteSnapshot{}, fmt.Errorf("inspect IPv4 default route: %w", err)
	}
	fields := parseRouteFields(output)
	gateway, err := netip.ParseAddr(fields["gateway"])
	if err != nil || !gateway.Is4() {
		return tunnel.RouteSnapshot{}, errors.New("IPv4 default route has no numeric gateway")
	}
	result := tunnel.RouteSnapshot{Default: tunnel.Route{
		Destination: netip.MustParsePrefix("0.0.0.0/0"),
		Gateway:     gateway,
		Interface:   fields["interface"],
	}}
	if err := result.Default.Validate(); err != nil {
		return tunnel.RouteSnapshot{}, fmt.Errorf("invalid IPv4 default route: %w", err)
	}
	return result, nil
}

func (manager RouteManager) Add(ctx context.Context, route tunnel.Route) error {
	if err := route.Validate(); err != nil {
		return err
	}
	owned, found, err := manager.inspectExact(ctx, route.Destination)
	if err != nil {
		return err
	}
	if found {
		return fmt.Errorf("%w: %s already resolves through %s", ErrRouteConflict, route.Destination, owned.Interface)
	}
	arguments, err := routeArguments("add", route)
	if err != nil {
		return err
	}
	if _, err := manager.run(ctx, arguments...); err != nil {
		return fmt.Errorf("add route %s: %w", route.Destination, err)
	}
	current, found, err := manager.inspectExact(ctx, route.Destination)
	if err != nil {
		return fmt.Errorf("verify added route %s: %w", route.Destination, err)
	}
	if !found || current.Interface != route.Interface || current.Reject != route.Reject || route.Gateway.IsValid() && current.Gateway != route.Gateway {
		return fmt.Errorf("%w: added route %s is not owned as planned", ErrRouteConflict, route.Destination)
	}
	return nil
}

func (manager RouteManager) Remove(ctx context.Context, route tunnel.Route) error {
	if err := route.Validate(); err != nil {
		return err
	}
	current, found, err := manager.inspectExact(ctx, route.Destination)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if current.Interface != route.Interface || current.Reject != route.Reject || route.Gateway.IsValid() && current.Gateway != route.Gateway {
		return fmt.Errorf("%w: refuse to remove changed route %s", ErrRouteConflict, route.Destination)
	}
	arguments, err := routeArguments("delete", route)
	if err != nil {
		return err
	}
	if _, err := manager.run(ctx, arguments...); err != nil {
		return fmt.Errorf("delete route %s: %w", route.Destination, err)
	}
	return nil
}

func (manager RouteManager) LookupExact(ctx context.Context, destination netip.Prefix) (tunnel.Route, bool, error) {
	if !destination.IsValid() || destination != destination.Masked() {
		return tunnel.Route{}, false, errors.New("invalid exact route lookup")
	}
	return manager.inspectExact(ctx, destination)
}

func (manager RouteManager) inspectExact(ctx context.Context, destination netip.Prefix) (tunnel.Route, bool, error) {
	family := "-inet"
	if destination.Addr().Is6() {
		family = "-inet6"
	}
	kind := "-net"
	destinationArgument := destination.String()
	if destination.Bits() == destination.Addr().BitLen() {
		kind = "-host"
		destinationArgument = destination.Addr().String()
	}
	output, err := manager.run(ctx, "get", family, kind, destinationArgument)
	if err != nil {
		if routeMissing(err.Error()) {
			return tunnel.Route{}, false, nil
		}
		return tunnel.Route{}, false, fmt.Errorf("inspect route %s: %w", destination, err)
	}
	fields := parseRouteFields(output)
	prefix, err := parseRoutePrefix(fields, destination.Addr().BitLen())
	if err != nil {
		return tunnel.Route{}, false, fmt.Errorf("parse route %s: %w", destination, err)
	}
	if prefix != destination {
		return tunnel.Route{}, false, nil
	}
	current := tunnel.Route{
		Destination: prefix, Interface: fields["interface"], Reject: strings.Contains(fields["flags"], "REJECT"),
	}
	if gateway, parseErr := netip.ParseAddr(fields["gateway"]); parseErr == nil {
		current.Gateway = gateway
	}
	if err := current.Validate(); err != nil {
		return tunnel.Route{}, false, err
	}
	return current, true, nil
}

func (manager RouteManager) run(ctx context.Context, arguments ...string) ([]byte, error) {
	if manager.Runner == nil {
		return nil, errors.New("Darwin route runner is missing")
	}
	path := manager.RoutePath
	if path == "" {
		path = defaultRoutePath
	}
	return manager.Runner.Run(ctx, path, append([]string{"-n"}, arguments...)...)
}

func routeArguments(operation string, route tunnel.Route) ([]string, error) {
	if operation != "add" && operation != "delete" {
		return nil, errors.New("unsupported route operation")
	}
	family := "-inet"
	if route.Destination.Addr().Is6() {
		family = "-inet6"
	}
	kind := "-net"
	if route.Destination.Bits() == route.Destination.Addr().BitLen() {
		kind = "-host"
	}
	arguments := []string{operation, family, kind}
	destination := route.Destination.String()
	if route.Destination.Bits() == route.Destination.Addr().BitLen() {
		destination = route.Destination.Addr().String()
	}
	if route.Gateway.IsValid() {
		if route.Interface == "" {
			return nil, errors.New("gateway route is missing its expected interface")
		}
		// Keep the endpoint route unscoped so wireguard-go's unbound Darwin UDP
		// socket can select it. The captured interface is verified after add and
		// before delete; the gateway constrains the mutation itself.
		arguments = append(arguments, destination, route.Gateway.String())
		return arguments, nil
	}
	if route.Interface == "" {
		return nil, errors.New("direct route is missing its interface")
	}
	arguments = append(arguments, destination, "-interface", route.Interface)
	if route.Reject {
		arguments = append(arguments, "-reject")
	}
	return arguments, nil
}

func parseRouteFields(output []byte) map[string]string {
	fields := make(map[string]string)
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return fields
}

func parseRoutePrefix(fields map[string]string, bitLength int) (netip.Prefix, error) {
	destination := fields["destination"]
	if destination == "default" && bitLength == 32 {
		return netip.MustParsePrefix("0.0.0.0/0"), nil
	}
	var address netip.Addr
	var err error
	if bitLength == 128 {
		address, err = netip.ParseAddr(destination)
	} else {
		address, err = parseBSDAddress(destination)
	}
	if err != nil {
		return netip.Prefix{}, err
	}
	if strings.Contains(fields["flags"], "HOST") {
		return netip.PrefixFrom(address, bitLength), nil
	}
	if prefixLength, parseErr := strconv.Atoi(fields["prefixlen"]); parseErr == nil && prefixLength >= 0 && prefixLength <= bitLength {
		return netip.PrefixFrom(address, prefixLength).Masked(), nil
	}
	if fields["mask"] == "" {
		return netip.Prefix{}, errors.New("non-host route is missing its mask")
	}
	bits, err := parseMaskBits(fields["mask"], bitLength)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(address, bits).Masked(), nil
}

func parseBSDAddress(value string) (netip.Addr, error) {
	parts := strings.Split(value, ".")
	if len(parts) > 4 {
		return netip.Addr{}, errors.New("invalid route destination")
	}
	for len(parts) < 4 {
		parts = append(parts, "0")
	}
	return netip.ParseAddr(strings.Join(parts, "."))
}

func parseMaskBits(value string, bitLength int) (int, error) {
	if value == "default" {
		return 0, nil
	}
	if bitLength == 32 && strings.HasPrefix(value, "0x") {
		mask, err := strconv.ParseUint(strings.TrimPrefix(value, "0x"), 16, 32)
		if err != nil {
			return 0, err
		}
		return maskBits(uint32(mask))
	}
	mask, err := netip.ParseAddr(value)
	if err != nil || mask.BitLen() != bitLength {
		return 0, errors.New("invalid route mask")
	}
	if bitLength == 32 {
		bytes := mask.As4()
		value32 := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
		return maskBits(value32)
	}
	bytes := mask.As16()
	ones := 0
	zeroSeen := false
	for _, item := range bytes {
		for bit := 7; bit >= 0; bit-- {
			set := item&(1<<bit) != 0
			if zeroSeen && set {
				return 0, errors.New("non-contiguous route mask")
			}
			if set {
				ones++
			} else {
				zeroSeen = true
			}
		}
	}
	return ones, nil
}

func maskBits(mask uint32) (int, error) {
	ones := bits.OnesCount32(mask)
	var canonical uint32
	if ones > 0 {
		canonical = ^uint32(0) << (32 - ones)
	}
	if mask != canonical {
		return 0, errors.New("non-contiguous IPv4 route mask")
	}
	return ones, nil
}

func routeMissing(message string) bool {
	lower := strings.ToLower(message)
	return strings.Contains(lower, "not in table") || strings.Contains(lower, "not found") || strings.Contains(lower, "no such process")
}

var _ tunnel.RouteManager = RouteManager{}
