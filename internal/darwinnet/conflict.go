package darwinnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/b1rd33/nordmac/internal/tunnel"
)

type ConflictChecker struct {
	Routes RouteManager
}

func (checker ConflictChecker) Check(ctx context.Context, plan tunnel.Plan) error {
	snapshot, err := checker.Routes.Snapshot(ctx)
	if err != nil {
		return err
	}
	if strings.HasPrefix(snapshot.Default.Interface, "utun") {
		return errors.New("default route is already owned by a utun interface")
	}
	if snapshot.Default.Gateway != plan.PhysicalGateway || snapshot.Default.Interface != plan.PhysicalInterface {
		return errors.New("physical default route changed before conflict check")
	}
	for _, prefix := range []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	} {
		if route, found, err := checker.Routes.LookupExact(ctx, prefix); err != nil {
			return err
		} else if found {
			return fmt.Errorf("split default %s already exists on %s", prefix, route.Interface)
		}
	}
	return nil
}

var _ tunnel.ConflictChecker = ConflictChecker{}
