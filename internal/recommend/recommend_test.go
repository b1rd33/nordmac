package recommend

import (
	"errors"
	"testing"

	"github.com/b1rd33/nordmac/internal/catalog"
)

var germany = catalog.Country{
	ID: 81, Name: "Germany", Code: "DE",
	Cities: []catalog.City{{ID: 1, Name: "Berlin", Slug: "berlin"}, {ID: 2, Name: "Frankfurt", Slug: "frankfurt"}},
}

func TestResolveCountryCodeAndName(t *testing.T) {
	countries := []catalog.Country{germany, {ID: 228, Name: "United States", Code: "US"}}
	for _, input := range []string{"de", "DE", " Germany "} {
		got, err := ResolveCountry(countries, input)
		if err != nil || got.ID != germany.ID {
			t.Fatalf("ResolveCountry(%q) = %#v, %v", input, got, err)
		}
	}
}

func TestResolveCountryNoMatchAndAmbiguous(t *testing.T) {
	if _, err := ResolveCountry([]catalog.Country{germany}, "zz"); !errors.Is(err, catalog.ErrNoMatch) {
		t.Fatalf("expected no match, got %v", err)
	}
	duplicate := germany
	duplicate.ID = 82
	duplicate.Code = "DX"
	if _, err := ResolveCountry([]catalog.Country{germany, duplicate}, "germany"); !errors.Is(err, catalog.ErrAmbiguous) {
		t.Fatalf("expected ambiguous, got %v", err)
	}
}

func TestResolveCityBySlug(t *testing.T) {
	city, err := ResolveCity(germany, "BERLIN")
	if err != nil || city.ID != 1 {
		t.Fatalf("ResolveCity = %#v, %v", city, err)
	}
}

func TestSelectPreservesOrderAndFilters(t *testing.T) {
	validKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	servers := []catalog.Server{
		{ID: 1, Hostname: "de1.nordvpn.com", Status: "offline", CountryID: 81, CountryCode: "DE", CityID: 1, WireGuardPubKey: validKey},
		{ID: 2, Hostname: "de2.nordvpn.com", Status: "online", CountryID: 81, CountryCode: "DE", CityID: 2, WireGuardPubKey: validKey},
		{ID: 3, Hostname: "de3.nordvpn.com", Status: "online", CountryID: 81, CountryCode: "DE", CityID: 1, WireGuardPubKey: validKey},
	}
	got, err := Select(servers, germany, 1, "")
	if err != nil || got.ID != 3 {
		t.Fatalf("Select = %#v, %v", got, err)
	}
	exact, err := Select(servers, germany, 0, "de2")
	if err != nil || exact.ID != 2 {
		t.Fatalf("exact Select = %#v, %v", exact, err)
	}
}

func TestSelectRejectsMalformedKey(t *testing.T) {
	servers := []catalog.Server{{ID: 1, Hostname: "de1.nordvpn.com", Status: "online", CountryID: 81, CountryCode: "DE", WireGuardPubKey: "not-a-key"}}
	if _, err := Select(servers, germany, 0, ""); !errors.Is(err, catalog.ErrNoMatch) {
		t.Fatalf("expected no match, got %v", err)
	}
}

func FuzzResolveCountry(f *testing.F) {
	f.Add("de")
	f.Add("Germany")
	f.Add("\x00--")
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = ResolveCountry([]catalog.Country{germany}, input)
	})
}
