package state

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/b1rd33/nordmac/internal/tunnel"
)

func validJournal() tunnel.Journal {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	plan := tunnel.Plan{
		SessionID:         strings.Repeat("a", 32),
		OwnerUID:          501,
		Endpoint:          netip.MustParseAddrPort("203.0.113.10:51820"),
		PhysicalGateway:   netip.MustParseAddr("192.0.2.1"),
		PhysicalInterface: "en0",
		TunnelAddress:     netip.MustParsePrefix("10.5.0.2/32"),
		TunnelMTU:         1420,
		TunnelDNS:         []netip.Addr{netip.MustParseAddr("10.5.0.1")},
		RoutePolicy:       tunnel.RoutePolicyFullIPv4,
		PeerFingerprint:   strings.Repeat("b", 64),
	}
	return tunnel.Journal{
		SchemaVersion: tunnel.JournalSchemaVersion,
		SessionID:     plan.SessionID,
		OwnerUID:      plan.OwnerUID,
		Phase:         tunnel.PhaseConnecting,
		Plan:          plan,
		RouteBefore: tunnel.RouteSnapshot{Default: tunnel.Route{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			Gateway:     netip.MustParseAddr("192.0.2.1"),
			Interface:   "en0",
		}},
		DNSBefore: tunnel.DNSSnapshot{
			Revision: "synthetic",
			Services: []tunnel.ServiceDNS{{ServiceID: "synthetic-wifi", Servers: []netip.Addr{netip.MustParseAddr("192.0.2.53")}}},
		},
		Entries:   []tunnel.Entry{},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func TestJournalStoreRoundTripAndModes(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "journals")
	store := JournalStore{Directory: directory}
	journal := validJournal()
	if err := store.Create(context.Background(), journal); err != nil {
		t.Fatalf("Create: %v", err)
	}
	path := filepath.Join(directory, journal.SessionID+".json")
	for name, wantMode := range map[string]os.FileMode{directory: 0o700, path: 0o600} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatalf("Stat(%s): %v", name, err)
		}
		if got := info.Mode().Perm(); got != wantMode {
			t.Fatalf("mode(%s) = %04o, want %04o", name, got, wantMode)
		}
	}
	loaded, err := store.Load(context.Background(), journal.SessionID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Phase != tunnel.PhaseConnecting || loaded.SessionID != journal.SessionID {
		t.Fatalf("loaded journal = %#v", loaded)
	}

	journal.DNSBefore.Revision = "synthetic-updated"
	journal.UpdatedAt = journal.UpdatedAt.Add(time.Second)
	if err := store.Update(context.Background(), journal); err != nil {
		t.Fatalf("Update: %v", err)
	}
	loaded, err = store.Load(context.Background(), journal.SessionID)
	if err != nil || loaded.DNSBefore.Revision != "synthetic-updated" {
		t.Fatalf("updated Load = revision %s, error %v", loaded.DNSBefore.Revision, err)
	}
	if err := store.Delete(context.Background(), journal.SessionID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Load(context.Background(), journal.SessionID); !errors.Is(err, tunnel.ErrJournalNotFound) {
		t.Fatalf("Load after Delete = %v, want ErrJournalNotFound", err)
	}
}

func TestJournalCreateIsExclusive(t *testing.T) {
	store := JournalStore{Directory: filepath.Join(t.TempDir(), "journals")}
	journal := validJournal()
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsSeen <- store.Create(context.Background(), journal)
		}()
	}
	wait.Wait()
	close(errorsSeen)
	var successes, failures int
	for err := range errorsSeen {
		if err == nil {
			successes++
		} else {
			failures++
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("successes=%d failures=%d, want one each", successes, failures)
	}
}

func TestInvalidUpdatePreservesExistingJournal(t *testing.T) {
	store := JournalStore{Directory: filepath.Join(t.TempDir(), "journals")}
	journal := validJournal()
	if err := store.Create(context.Background(), journal); err != nil {
		t.Fatalf("Create: %v", err)
	}
	invalid := journal
	invalid.Phase = tunnel.Phase("invented")
	if err := store.Update(context.Background(), invalid); err == nil {
		t.Fatal("Update unexpectedly accepted invalid journal")
	}
	loaded, err := store.Load(context.Background(), journal.SessionID)
	if err != nil || loaded.Phase != tunnel.PhaseConnecting {
		t.Fatalf("original journal was not preserved: phase=%s error=%v", loaded.Phase, err)
	}
}

func TestJournalStoreRejectsTraversalSymlinksAndBroadPermissions(t *testing.T) {
	t.Run("session traversal", func(t *testing.T) {
		store := JournalStore{Directory: filepath.Join(t.TempDir(), "journals")}
		if _, err := store.Load(context.Background(), "../outside"); err == nil {
			t.Fatal("Load unexpectedly accepted traversal")
		}
	})

	t.Run("symlink journal", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "journals")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		journal := validJournal()
		path := filepath.Join(directory, journal.SessionID+".json")
		if err := os.Symlink("/dev/null", path); err != nil {
			t.Fatal(err)
		}
		if _, err := (JournalStore{Directory: directory}).Load(context.Background(), journal.SessionID); err == nil {
			t.Fatal("Load unexpectedly followed symlink")
		}
	})

	t.Run("broad directory", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "journals")
		if err := os.Mkdir(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		store := JournalStore{Directory: directory}
		if err := store.Create(context.Background(), validJournal()); err == nil {
			t.Fatal("Create unexpectedly accepted broad directory permissions")
		}
	})
}

func TestJournalLoadRejectsUnknownAndTrailingData(t *testing.T) {
	for name, data := range map[string]string{
		"unknown":  `{"unknown":true}`,
		"trailing": `{}` + "\n{}",
	} {
		t.Run(name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "journals")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			journal := validJournal()
			path := filepath.Join(directory, journal.SessionID+".json")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := (JournalStore{Directory: directory}).Load(context.Background(), journal.SessionID); err == nil {
				t.Fatal("Load unexpectedly accepted malformed journal")
			}
		})
	}
}
