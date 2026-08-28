package darwinnet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/b1rd33/nordmac/internal/tunnel"
)

const defaultNetworkSetupPath = "/usr/sbin/networksetup"

var ErrDNSConflict = errors.New("DNS configuration changed after nordmac applied it")

// DNSManager owns only the static DNS and search-domain settings of one fixed
// macOS network service. It never edits the dynamic SystemConfiguration store
// directly and refuses rollback when either owned component changed.
type DNSManager struct {
	Runner           Runner
	NetworkSetupPath string
}

func (manager DNSManager) Snapshot(ctx context.Context, config tunnel.DNSConfig) (tunnel.DNSSnapshot, error) {
	if err := config.Validate(); err != nil {
		return tunnel.DNSSnapshot{}, err
	}
	service, err := manager.snapshotService(ctx, config.ServiceID)
	if err != nil {
		return tunnel.DNSSnapshot{}, err
	}
	return snapshotForService(service), nil
}

func (manager DNSManager) Apply(ctx context.Context, config tunnel.DNSConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if err := manager.set(ctx, "-setdnsservers", config.ServiceID, addresses(config.Servers)); err != nil {
		return fmt.Errorf("set DNS servers for %q: %w", config.ServiceID, err)
	}
	if config.SearchDomains != nil {
		if err := manager.set(ctx, "-setsearchdomains", config.ServiceID, config.SearchDomains); err != nil {
			return fmt.Errorf("set DNS search domains for %q: %w", config.ServiceID, err)
		}
	}
	return nil
}

func (manager DNSManager) RestoreIfOwned(ctx context.Context, before tunnel.DNSSnapshot, applied tunnel.DNSConfig) error {
	if err := applied.Validate(); err != nil {
		return err
	}
	if len(before.Services) != 1 || before.Services[0].ServiceID != applied.ServiceID {
		return errors.New("DNS pre-image does not match the applied service")
	}
	current, err := manager.snapshotService(ctx, applied.ServiceID)
	if err != nil {
		return err
	}
	original := before.Services[0]
	serversOwned := slices.Equal(current.Servers, applied.Servers)
	serversOriginal := slices.Equal(current.Servers, original.Servers)
	domainsOwned, domainsOriginal := true, true
	if applied.SearchDomains != nil {
		domainsOwned = slices.Equal(current.SearchDomains, applied.SearchDomains)
		domainsOriginal = slices.Equal(current.SearchDomains, original.SearchDomains)
	}
	if (!serversOwned && !serversOriginal) || (!domainsOwned && !domainsOriginal) {
		return ErrDNSConflict
	}

	// Restore in reverse apply order. A component already matching the pre-image
	// is a valid partial-apply recovery and is left untouched.
	if domainsOwned && !domainsOriginal {
		if err := manager.set(ctx, "-setsearchdomains", applied.ServiceID, original.SearchDomains); err != nil {
			return fmt.Errorf("restore DNS search domains for %q: %w", applied.ServiceID, err)
		}
	}
	if serversOwned && !serversOriginal {
		if err := manager.set(ctx, "-setdnsservers", applied.ServiceID, addresses(original.Servers)); err != nil {
			return fmt.Errorf("restore DNS servers for %q: %w", applied.ServiceID, err)
		}
	}
	return nil
}

func (manager DNSManager) snapshotService(ctx context.Context, serviceID string) (tunnel.ServiceDNS, error) {
	serversOutput, err := manager.run(ctx, "-getdnsservers", serviceID)
	if err != nil {
		return tunnel.ServiceDNS{}, fmt.Errorf("read DNS servers for %q: %w", serviceID, err)
	}
	serverLines := settingLines(serversOutput)
	servers := make([]netip.Addr, 0, len(serverLines))
	for _, line := range serverLines {
		server, parseErr := netip.ParseAddr(line)
		if parseErr != nil || server.IsUnspecified() || server.IsMulticast() {
			return tunnel.ServiceDNS{}, fmt.Errorf("invalid DNS server %q for %q", line, serviceID)
		}
		servers = append(servers, server)
	}
	domainsOutput, err := manager.run(ctx, "-getsearchdomains", serviceID)
	if err != nil {
		return tunnel.ServiceDNS{}, fmt.Errorf("read DNS search domains for %q: %w", serviceID, err)
	}
	domains := settingLines(domainsOutput)
	for _, domain := range domains {
		if len(domain) > 253 || strings.ContainsAny(domain, " \t") {
			return tunnel.ServiceDNS{}, fmt.Errorf("invalid DNS search domain %q for %q", domain, serviceID)
		}
	}
	return tunnel.ServiceDNS{ServiceID: serviceID, Servers: servers, SearchDomains: domains}, nil
}

func (manager DNSManager) set(ctx context.Context, operation, serviceID string, values []string) error {
	arguments := []string{operation, serviceID}
	if len(values) == 0 {
		values = []string{"empty"}
	}
	_, err := manager.run(ctx, append(arguments, values...)...)
	return err
}

func (manager DNSManager) run(ctx context.Context, arguments ...string) ([]byte, error) {
	if manager.Runner == nil {
		return nil, errors.New("Darwin DNS runner is missing")
	}
	path := manager.NetworkSetupPath
	if path == "" {
		path = defaultNetworkSetupPath
	}
	return manager.Runner.Run(ctx, path, arguments...)
}

func settingLines(output []byte) []string {
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" || strings.HasPrefix(trimmed, "There aren't any ") {
		return nil
	}
	lines := strings.Split(trimmed, "\n")
	for index := range lines {
		lines[index] = strings.TrimSpace(lines[index])
	}
	return lines
}

func addresses(values []netip.Addr) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}

func snapshotForService(service tunnel.ServiceDNS) tunnel.DNSSnapshot {
	canonical := service.ServiceID + "\x00" + strings.Join(addresses(service.Servers), "\x00") + "\x01" + strings.Join(service.SearchDomains, "\x00")
	digest := sha256.Sum256([]byte(canonical))
	return tunnel.DNSSnapshot{Revision: hex.EncodeToString(digest[:]), Services: []tunnel.ServiceDNS{service}}
}

var _ tunnel.DNSManager = DNSManager{}
