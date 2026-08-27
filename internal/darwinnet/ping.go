package darwinnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
)

const defaultPingPath = "/sbin/ping"

type Pinger struct {
	Runner   Runner
	PingPath string
}

func (pinger Pinger) Ping(ctx context.Context, address netip.Addr) error {
	if !address.IsValid() || !address.Is4() || !address.IsPrivate() {
		return errors.New("scoped ping target must be a private IPv4 address")
	}
	if pinger.Runner == nil {
		return errors.New("Darwin ping runner is missing")
	}
	path := pinger.PingPath
	if path == "" {
		path = defaultPingPath
	}
	if _, err := pinger.Runner.Run(ctx, path, "-n", "-c", "1", "-W", "1000", address.String()); err != nil {
		return fmt.Errorf("ping scoped peer %s: %w", address, err)
	}
	return nil
}
