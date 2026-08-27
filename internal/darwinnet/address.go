package darwinnet

import (
	"context"
	"errors"
	"fmt"

	"github.com/b1rd33/nordmac/internal/tunnel"
)

const defaultIfconfigPath = "/sbin/ifconfig"

type AddressManager struct {
	Runner       Runner
	IfconfigPath string
}

func (manager AddressManager) Apply(ctx context.Context, address tunnel.InterfaceAddress) error {
	if err := address.Validate(); err != nil {
		return err
	}
	if manager.Runner == nil {
		return errors.New("Darwin address runner is missing")
	}
	path := manager.IfconfigPath
	if path == "" {
		path = defaultIfconfigPath
	}
	value := address.Prefix.String()
	if _, err := manager.Runner.Run(ctx, path, address.Interface, "inet", value, "alias"); err != nil {
		return fmt.Errorf("add owned address %s to %s: %w", value, address.Interface, err)
	}
	return nil
}

var _ interface {
	Apply(context.Context, tunnel.InterfaceAddress) error
} = AddressManager{}
