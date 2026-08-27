package darwinnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/b1rd33/nordmac/internal/tunnel"
)

const defaultIfconfigPath = "/sbin/ifconfig"

type AddressManager struct {
	Runner       Runner
	IfconfigPath string
	PeerAddress  netip.Addr
}

func (manager AddressManager) Apply(ctx context.Context, address tunnel.InterfaceAddress) error {
	if err := address.Validate(); err != nil {
		return err
	}
	if manager.Runner == nil {
		return errors.New("Darwin address runner is missing")
	}
	if !manager.PeerAddress.IsValid() || !manager.PeerAddress.Is4() || !manager.PeerAddress.IsPrivate() {
		return errors.New("Darwin peer address must be a private IPv4 address")
	}
	path := manager.IfconfigPath
	if path == "" {
		path = defaultIfconfigPath
	}
	local := address.Prefix.Addr().String()
	peer := manager.PeerAddress.String()
	if _, err := manager.Runner.Run(ctx, path, address.Interface, "inet", local, peer, "netmask", "255.255.255.255", "alias"); err != nil {
		return fmt.Errorf("add owned point-to-point address %s with peer %s to %s: %w", address.Prefix, peer, address.Interface, err)
	}
	return nil
}

var _ interface {
	Apply(context.Context, tunnel.InterfaceAddress) error
} = AddressManager{}
