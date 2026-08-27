package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"nordmac/internal/catalog"
)

func TestCountriesRoundTripAndFreshness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "countries.json")
	store := Countries{Path: path, TTL: time.Hour}
	fetched := time.Date(2026, 8, 27, 8, 0, 0, 0, time.UTC)
	want := catalog.CountriesResult{Countries: []catalog.Country{{ID: 81, Name: "Germany", Code: "DE"}}, FetchedAt: fetched}
	if err := store.Write(want); err != nil {
		t.Fatal(err)
	}
	got, fresh, err := store.Read(fetched.Add(30 * time.Minute))
	if err != nil || !fresh || got.Countries[0].Code != "DE" {
		t.Fatalf("Read = %#v, %v, %v", got, fresh, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("cache permissions = %v, %v", info, err)
	}
	_, fresh, err = store.Read(fetched.Add(2 * time.Hour))
	if err != nil || fresh {
		t.Fatalf("stale Read fresh=%v err=%v", fresh, err)
	}
}

func TestCountriesMissingCache(t *testing.T) {
	store := Countries{Path: filepath.Join(t.TempDir(), "missing.json"), TTL: time.Hour}
	result, fresh, err := store.Read(time.Now())
	if err != nil || fresh || len(result.Countries) != 0 {
		t.Fatalf("Read = %#v, %v, %v", result, fresh, err)
	}
}
