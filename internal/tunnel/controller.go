package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

var (
	ErrJournalNotFound = errors.New("tunnel journal not found")
	ErrLockHeld        = errors.New("another tunnel transaction holds the lock")
	ErrConflict        = errors.New("foreign network conflict")
	ErrRollback        = errors.New("tunnel rollback incomplete")
)

const rollbackTimeout = 10 * time.Second

type JournalStore interface {
	Create(context.Context, Journal) error
	Update(context.Context, Journal) error
	Load(context.Context, string) (Journal, error)
	Delete(context.Context, string) error
}

type Locker interface {
	Acquire(context.Context, string) (release func() error, err error)
}

type ConflictChecker interface {
	Check(context.Context, Plan) error
}

// DeviceManager must scope cleanup to the exact session id. DeleteOwned must
// reconcile a nil handle after an interrupted or partially failed Create, be
// idempotent, and never delete an unowned interface.
type DeviceManager interface {
	Create(context.Context, DeviceSpec) (DeviceHandle, error)
	DeleteOwned(context.Context, string, *DeviceHandle) error
}

type RouteManager interface {
	Snapshot(context.Context) (RouteSnapshot, error)
	Add(context.Context, Route) error
	Remove(context.Context, Route) error
}

// RestoreIfOwned must compare the current DNS state with applied before
// restoring before. A mismatch is an error, not permission to overwrite a
// user's newer DNS configuration.
type DNSManager interface {
	Snapshot(context.Context) (DNSSnapshot, error)
	Apply(context.Context, DNSConfig) error
	RestoreIfOwned(context.Context, DNSSnapshot, DNSConfig) error
}

type Verifier interface {
	Verify(context.Context, Journal) error
}

type Controller struct {
	Journals  JournalStore
	Locks     Locker
	Conflicts ConflictChecker
	Devices   DeviceManager
	Routes    RouteManager
	DNS       DNSManager
	Verifier  Verifier
	Now       func() time.Time
}

func (controller Controller) Connect(ctx context.Context, plan Plan) (journal Journal, retErr error) {
	if err := plan.Validate(); err != nil {
		return Journal{}, fmt.Errorf("invalid tunnel plan: %w", err)
	}
	if err := controller.validate(plan); err != nil {
		return Journal{}, err
	}
	plan.TunnelDNS = slices.Clone(plan.TunnelDNS)
	plan.ScopedRoutes = slices.Clone(plan.ScopedRoutes)

	release, err := controller.Locks.Acquire(ctx, plan.SessionID)
	if err != nil {
		return Journal{}, fmt.Errorf("acquire tunnel lock: %w", err)
	}
	defer func() {
		if releaseErr := release(); releaseErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("release tunnel lock: %w", releaseErr))
		}
	}()

	if err := controller.Conflicts.Check(ctx, plan); err != nil {
		return Journal{}, fmt.Errorf("%w: %v", ErrConflict, err)
	}
	routeBefore, err := controller.Routes.Snapshot(ctx)
	if err != nil {
		return Journal{}, fmt.Errorf("capture route pre-image: %w", err)
	}
	if err := validatePhysicalPreimage(plan, routeBefore); err != nil {
		return Journal{}, err
	}
	var dnsBefore DNSSnapshot
	if plan.UsesDNS() {
		dnsBefore, err = controller.DNS.Snapshot(ctx)
		if err != nil {
			return Journal{}, fmt.Errorf("capture DNS pre-image: %w", err)
		}
	}

	now := controller.now()
	journal = Journal{
		SchemaVersion: JournalSchemaVersion,
		SessionID:     plan.SessionID,
		OwnerUID:      plan.OwnerUID,
		Phase:         PhaseConnecting,
		Plan:          plan,
		RouteBefore:   routeBefore,
		DNSBefore:     dnsBefore,
		Entries:       []Entry{},
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := journal.Validate(); err != nil {
		return Journal{}, fmt.Errorf("construct tunnel journal: %w", err)
	}
	if err := controller.Journals.Create(ctx, journal); err != nil {
		return Journal{}, fmt.Errorf("create tunnel journal: %w", err)
	}

	fail := func(connectErr error) (Journal, error) {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
		defer cancel()
		rollbackErr := controller.rollback(rollbackCtx, &journal)
		if rollbackErr != nil {
			return journal, errors.Join(connectErr, rollbackErr)
		}
		return journal, connectErr
	}

	deviceEntry := Entry{Kind: StepDevice, Status: StepPlanned}
	deviceIndex, err := controller.recordIntent(ctx, &journal, deviceEntry)
	if err != nil {
		return fail(err)
	}
	device, err := controller.Devices.Create(ctx, DeviceSpec{
		SessionID:       plan.SessionID,
		Address:         plan.TunnelAddress,
		MTU:             plan.TunnelMTU,
		Endpoint:        plan.Endpoint,
		PeerFingerprint: plan.PeerFingerprint,
	})
	if err != nil {
		return fail(fmt.Errorf("create tunnel device: %w", err))
	}
	if err := device.Validate(); err != nil {
		return fail(fmt.Errorf("create tunnel device: %w", err))
	}
	journal.Device = &device
	if err := controller.markApplied(ctx, &journal, deviceIndex); err != nil {
		return fail(err)
	}

	endpointRoute := plan.EndpointRoute()
	if err := controller.applyRoute(ctx, &journal, StepEndpointRoute, endpointRoute); err != nil {
		return fail(err)
	}
	for _, route := range plan.TunnelRoutes() {
		route.Interface = device.Interface
		if err := controller.applyRoute(ctx, &journal, StepTunnelRoute, route); err != nil {
			return fail(err)
		}
	}

	if plan.UsesDNS() {
		dnsIndex, err := controller.recordIntent(ctx, &journal, Entry{Kind: StepDNS, Status: StepPlanned})
		if err != nil {
			return fail(err)
		}
		if err := controller.DNS.Apply(ctx, plan.DNSConfig()); err != nil {
			return fail(fmt.Errorf("apply tunnel DNS: %w", err))
		}
		if err := controller.markApplied(ctx, &journal, dnsIndex); err != nil {
			return fail(err)
		}
	}

	if err := controller.Verifier.Verify(ctx, journal); err != nil {
		return fail(fmt.Errorf("verify tunnel: %w", err))
	}
	if err := controller.setPhase(ctx, &journal, PhaseConnected); err != nil {
		return fail(err)
	}
	return journal, nil
}

func (controller Controller) Disconnect(ctx context.Context, sessionID string, ownerUID int) (retErr error) {
	if !ValidSessionID(sessionID) || ownerUID < 0 {
		return errors.New("invalid tunnel session identity")
	}
	// A recovered journal determines whether DNS is required. Validate the
	// common dependencies now and the policy-specific dependency after load.
	if err := controller.validateDisconnect(); err != nil {
		return err
	}
	release, err := controller.Locks.Acquire(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("acquire tunnel lock: %w", err)
	}
	defer func() {
		if releaseErr := release(); releaseErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("release tunnel lock: %w", releaseErr))
		}
	}()

	journal, err := controller.Journals.Load(ctx, sessionID)
	if errors.Is(err, ErrJournalNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load tunnel journal: %w", err)
	}
	if err := journal.Validate(); err != nil {
		return fmt.Errorf("refuse invalid tunnel journal: %w", err)
	}
	if journal.OwnerUID != ownerUID {
		return errors.New("tunnel journal owner does not match requester")
	}
	if journal.Plan.UsesDNS() && controller.DNS == nil {
		return errors.New("tunnel controller DNS dependency is incomplete")
	}
	if journal.Phase == PhaseDisconnected {
		return controller.Journals.Delete(ctx, sessionID)
	}
	return controller.rollback(ctx, &journal)
}

func (controller Controller) applyRoute(ctx context.Context, journal *Journal, kind StepKind, route Route) error {
	if err := route.Validate(); err != nil {
		return fmt.Errorf("invalid planned route: %w", err)
	}
	copy := route
	index, err := controller.recordIntent(ctx, journal, Entry{Kind: kind, Status: StepPlanned, Route: &copy})
	if err != nil {
		return err
	}
	if err := controller.Routes.Add(ctx, route); err != nil {
		return fmt.Errorf("add %s: %w", kind, err)
	}
	return controller.markApplied(ctx, journal, index)
}

func (controller Controller) recordIntent(ctx context.Context, journal *Journal, entry Entry) (int, error) {
	journal.Entries = append(journal.Entries, entry)
	journal.UpdatedAt = controller.nextTime(journal.UpdatedAt)
	if err := controller.Journals.Update(ctx, *journal); err != nil {
		return 0, fmt.Errorf("persist %s intent: %w", entry.Kind, err)
	}
	return len(journal.Entries) - 1, nil
}

func (controller Controller) markApplied(ctx context.Context, journal *Journal, index int) error {
	journal.Entries[index].Status = StepApplied
	journal.UpdatedAt = controller.nextTime(journal.UpdatedAt)
	if err := controller.Journals.Update(ctx, *journal); err != nil {
		return fmt.Errorf("persist applied %s: %w", journal.Entries[index].Kind, err)
	}
	return nil
}

func (controller Controller) setPhase(ctx context.Context, journal *Journal, phase Phase) error {
	if !allowedTransition(journal.Phase, phase) {
		return fmt.Errorf("invalid tunnel transition %s -> %s", journal.Phase, phase)
	}
	journal.Phase = phase
	journal.UpdatedAt = controller.nextTime(journal.UpdatedAt)
	if err := controller.Journals.Update(ctx, *journal); err != nil {
		return fmt.Errorf("persist tunnel phase %s: %w", phase, err)
	}
	return nil
}

func (controller Controller) rollback(ctx context.Context, journal *Journal) error {
	var rollbackErrors []error
	if journal.Phase != PhaseDisconnecting {
		if allowedTransition(journal.Phase, PhaseDisconnecting) {
			journal.Phase = PhaseDisconnecting
			journal.UpdatedAt = controller.nextTime(journal.UpdatedAt)
			if err := controller.Journals.Update(ctx, *journal); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("persist disconnecting phase: %w", err))
			}
		} else {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("cannot roll back phase %s", journal.Phase))
		}
	}

	for index := len(journal.Entries) - 1; index >= 0; index-- {
		entry := &journal.Entries[index]
		if entry.Status == StepRolledBack {
			continue
		}
		var err error
		switch entry.Kind {
		case StepDNS:
			err = controller.DNS.RestoreIfOwned(ctx, journal.DNSBefore, journal.Plan.DNSConfig())
		case StepEndpointRoute, StepTunnelRoute:
			if entry.Route == nil {
				err = errors.New("route rollback entry is missing its route")
			} else {
				err = controller.Routes.Remove(ctx, *entry.Route)
			}
		case StepDevice:
			err = controller.Devices.DeleteOwned(ctx, journal.SessionID, journal.Device)
		default:
			err = fmt.Errorf("unknown rollback step %q", entry.Kind)
		}
		if err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("roll back %s: %w", entry.Kind, err))
			continue
		}
		entry.Status = StepRolledBack
		journal.UpdatedAt = controller.nextTime(journal.UpdatedAt)
		if err := controller.Journals.Update(ctx, *journal); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("persist rolled-back %s: %w", entry.Kind, err))
		}
	}

	if len(rollbackErrors) > 0 {
		journal.Phase = PhaseRollbackRequired
		journal.UpdatedAt = controller.nextTime(journal.UpdatedAt)
		if err := controller.Journals.Update(ctx, *journal); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("persist rollback-required phase: %w", err))
		}
		return errors.Join(append([]error{ErrRollback}, rollbackErrors...)...)
	}

	journal.Phase = PhaseDisconnected
	journal.UpdatedAt = controller.nextTime(journal.UpdatedAt)
	if err := controller.Journals.Update(ctx, *journal); err != nil {
		return errors.Join(ErrRollback, fmt.Errorf("persist disconnected phase: %w", err))
	}
	if err := controller.Journals.Delete(ctx, journal.SessionID); err != nil {
		return errors.Join(ErrRollback, fmt.Errorf("delete completed journal: %w", err))
	}
	return nil
}

func (controller Controller) validate(plan Plan) error {
	if err := controller.validateCommon(); err != nil {
		return err
	}
	if plan.UsesDNS() && controller.DNS == nil {
		return errors.New("tunnel controller DNS dependency is incomplete")
	}
	return nil
}

func (controller Controller) validateCommon() error {
	if controller.Journals == nil || controller.Locks == nil || controller.Conflicts == nil ||
		controller.Devices == nil || controller.Routes == nil || controller.Verifier == nil {
		return errors.New("tunnel controller dependencies are incomplete")
	}
	return nil
}

func (controller Controller) validateDisconnect() error {
	if controller.Journals == nil || controller.Locks == nil || controller.Devices == nil || controller.Routes == nil {
		return errors.New("tunnel rollback dependencies are incomplete")
	}
	return nil
}

func validatePhysicalPreimage(plan Plan, snapshot RouteSnapshot) error {
	defaultRoute := snapshot.Default
	if err := defaultRoute.Validate(); err != nil {
		return fmt.Errorf("invalid physical route pre-image: %w", err)
	}
	if defaultRoute.Destination != netip.MustParsePrefix("0.0.0.0/0") {
		return errors.New("physical route pre-image does not contain the IPv4 default route")
	}
	if defaultRoute.Gateway != plan.PhysicalGateway || defaultRoute.Interface != plan.PhysicalInterface {
		return errors.New("physical route changed after planning; refusing stale endpoint pin")
	}
	return nil
}

func allowedTransition(from, to Phase) bool {
	allowed := map[Phase][]Phase{
		PhaseConnecting:       {PhaseConnected, PhaseDisconnecting, PhaseRollbackRequired},
		PhaseConnected:        {PhaseDegraded, PhaseDisconnecting, PhaseRollbackRequired},
		PhaseDegraded:         {PhaseDisconnecting, PhaseRollbackRequired},
		PhaseDisconnecting:    {PhaseDisconnected, PhaseRollbackRequired},
		PhaseRollbackRequired: {PhaseDisconnecting},
		PhaseForeignConflict:  {PhaseDisconnected},
	}
	return slices.Contains(allowed[from], to)
}

func (controller Controller) now() time.Time {
	if controller.Now != nil {
		return controller.Now().UTC()
	}
	return time.Now().UTC()
}

func (controller Controller) nextTime(previous time.Time) time.Time {
	now := controller.now()
	if !now.After(previous) {
		return previous.Add(time.Nanosecond)
	}
	return now
}
