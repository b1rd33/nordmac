package catalog

import (
	"context"
	"time"
)

// Country is a normalized country returned by the public server catalog.
type Country struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Code   string `json:"code"`
	Cities []City `json:"cities"`
}

// City is a normalized location within a country.
type City struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// Server contains only the public fields required to recommend a WireGuard peer.
type Server struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	Hostname        string `json:"hostname"`
	Load            int    `json:"load"`
	Status          string `json:"status"`
	CountryID       int64  `json:"country_id"`
	CountryName     string `json:"country_name"`
	CountryCode     string `json:"country_code"`
	CityID          int64  `json:"city_id"`
	CityName        string `json:"city_name"`
	CitySlug        string `json:"city_slug"`
	WireGuardPubKey string `json:"wireguard_public_key"`
}

// Source is the backing source used for a countries result.
type Source string

const (
	SourceNetwork    Source = "network"
	SourceCache      Source = "cache"
	SourceStaleCache Source = "stale_cache"
)

// CountriesResult includes cache metadata without exposing an API response body.
type CountriesResult struct {
	Countries []Country `json:"countries"`
	Source    Source    `json:"source"`
	FetchedAt time.Time `json:"fetched_at"`
	Warnings  []string  `json:"warnings,omitempty"`
}

// PublicAPI is the read-only Nord catalog boundary.
type PublicAPI interface {
	Countries(context.Context) ([]Country, error)
	Recommendations(context.Context, int64, int64, int) ([]Server, error)
	Servers(context.Context, int64, int) ([]Server, error)
}
