package command

import (
	"context"
	"errors"
	"fmt"
	"time"

	"nordmac/internal/cache"
	"nordmac/internal/catalog"
	"nordmac/internal/recommend"
)

const (
	recommendationLimit = 20
	exactServerLimit    = 1000
)

// Service implements Phase 1 using only the public catalog API and a non-secret cache.
type Service struct {
	API   catalog.PublicAPI
	Cache cache.Countries
	Now   func() time.Time
}

type RecommendationResult struct {
	Query   recommend.Query `json:"query"`
	Country catalog.Country `json:"country"`
	Server  catalog.Server  `json:"server"`
	Source  catalog.Source  `json:"countries_source"`
	Fetched time.Time       `json:"countries_fetched_at"`
	Warning []string        `json:"warnings,omitempty"`
}

func (s Service) Countries(ctx context.Context, refresh bool) (catalog.CountriesResult, error) {
	now := s.now()
	cached, fresh, cacheErr := s.Cache.Read(now)
	if !refresh && cacheErr == nil && fresh {
		return cached, nil
	}

	countries, apiErr := s.API.Countries(ctx)
	if apiErr != nil {
		if cacheErr == nil && len(cached.Countries) > 0 {
			cached.Source = catalog.SourceStaleCache
			cached.Warnings = append(cached.Warnings, "public API unavailable; using stale countries cache")
			return cached, nil
		}
		if cacheErr != nil {
			return catalog.CountriesResult{}, fmt.Errorf("fetch countries: %w (cache unavailable: %v)", apiErr, cacheErr)
		}
		return catalog.CountriesResult{}, fmt.Errorf("fetch countries: %w", apiErr)
	}

	result := catalog.CountriesResult{Countries: countries, Source: catalog.SourceNetwork, FetchedAt: now.UTC()}
	if cacheErr != nil {
		result.Warnings = append(result.Warnings, "ignored unreadable countries cache")
	}
	if err := s.Cache.Write(result); err != nil {
		result.Warnings = append(result.Warnings, "could not update countries cache")
	}
	return result, nil
}

func (s Service) Recommend(ctx context.Context, query recommend.Query) (RecommendationResult, error) {
	countries, err := s.Countries(ctx, false)
	if err != nil {
		return RecommendationResult{}, err
	}
	country, err := recommend.ResolveCountry(countries.Countries, query.Country)
	if err != nil {
		return RecommendationResult{}, err
	}

	var cityID int64
	if query.City != "" {
		city, cityErr := recommend.ResolveCity(country, query.City)
		if cityErr != nil {
			return RecommendationResult{}, cityErr
		}
		cityID = city.ID
	}

	var servers []catalog.Server
	if query.Server == "" {
		servers, err = s.API.Recommendations(ctx, country.ID, cityID, recommendationLimit)
	} else {
		servers, err = s.API.Servers(ctx, country.ID, exactServerLimit)
	}
	if err != nil {
		if errors.Is(err, catalog.ErrNoMatch) {
			return RecommendationResult{}, err
		}
		return RecommendationResult{}, fmt.Errorf("fetch server recommendations: %w", err)
	}
	server, err := recommend.Select(servers, country, cityID, query.Server)
	if err != nil {
		return RecommendationResult{}, err
	}
	return RecommendationResult{
		Query: query, Country: country, Server: server, Source: countries.Source,
		Fetched: countries.FetchedAt, Warning: countries.Warnings,
	}, nil
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
