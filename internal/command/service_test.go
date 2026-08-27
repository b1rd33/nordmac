package command

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"nordmac/internal/cache"
	"nordmac/internal/catalog"
	"nordmac/internal/recommend"
)

type fakeAPI struct {
	countries      []catalog.Country
	recommendation []catalog.Server
	servers        []catalog.Server
	err            error
	countryCalls   int
	recommendCalls int
	serverCalls    int
	cityID         int64
}

func (f *fakeAPI) Countries(context.Context) ([]catalog.Country, error) {
	f.countryCalls++
	return f.countries, f.err
}

func (f *fakeAPI) Recommendations(_ context.Context, _ int64, cityID int64, _ int) ([]catalog.Server, error) {
	f.recommendCalls++
	f.cityID = cityID
	return f.recommendation, f.err
}

func (f *fakeAPI) Servers(context.Context, int64, int) ([]catalog.Server, error) {
	f.serverCalls++
	return f.servers, f.err
}

func TestServiceCountriesUsesFreshCache(t *testing.T) {
	now := time.Date(2026, 8, 27, 8, 0, 0, 0, time.UTC)
	store := cache.Countries{Path: filepath.Join(t.TempDir(), "countries.json"), TTL: time.Hour}
	if err := store.Write(catalog.CountriesResult{Countries: []catalog.Country{germanyCountry()}, FetchedAt: now}); err != nil {
		t.Fatal(err)
	}
	api := &fakeAPI{err: errors.New("API must not be called")}
	service := Service{API: api, Cache: store, Now: func() time.Time { return now.Add(30 * time.Minute) }}
	result, err := service.Countries(context.Background(), false)
	if err != nil || result.Source != catalog.SourceCache || api.countryCalls != 0 {
		t.Fatalf("result=%#v err=%v calls=%d", result, err, api.countryCalls)
	}
}

func TestServiceCountriesFallsBackToStaleCache(t *testing.T) {
	now := time.Date(2026, 8, 27, 8, 0, 0, 0, time.UTC)
	store := cache.Countries{Path: filepath.Join(t.TempDir(), "countries.json"), TTL: time.Hour}
	if err := store.Write(catalog.CountriesResult{Countries: []catalog.Country{germanyCountry()}, FetchedAt: now.Add(-2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	api := &fakeAPI{err: errors.New("offline")}
	service := Service{API: api, Cache: store, Now: func() time.Time { return now }}
	result, err := service.Countries(context.Background(), false)
	if err != nil || result.Source != catalog.SourceStaleCache || len(result.Warnings) != 1 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestServiceRecommendCityAndExactServerPaths(t *testing.T) {
	now := time.Date(2026, 8, 27, 8, 0, 0, 0, time.UTC)
	validKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	server := catalog.Server{ID: 1, Hostname: "de1.nordvpn.com", Status: "online", CountryID: 81, CountryCode: "DE", CityID: 2181458, WireGuardPubKey: validKey}
	api := &fakeAPI{countries: []catalog.Country{germanyCountry()}, recommendation: []catalog.Server{server}, servers: []catalog.Server{server}}
	service := Service{API: api, Cache: cache.Countries{Path: filepath.Join(t.TempDir(), "countries.json"), TTL: time.Hour}, Now: func() time.Time { return now }}

	result, err := service.Recommend(context.Background(), recommend.Query{Country: "de", City: "berlin"})
	if err != nil || result.Server.ID != 1 || api.recommendCalls != 1 || api.cityID != 2181458 {
		t.Fatalf("result=%#v err=%v api=%#v", result, err, api)
	}
	result, err = service.Recommend(context.Background(), recommend.Query{Country: "de", Server: "de1"})
	if err != nil || result.Server.ID != 1 || api.serverCalls != 1 {
		t.Fatalf("exact result=%#v err=%v api=%#v", result, err, api)
	}
}

func germanyCountry() catalog.Country {
	return catalog.Country{ID: 81, Name: "Germany", Code: "DE", Cities: []catalog.City{{ID: 2181458, Name: "Berlin", Slug: "berlin"}}}
}
