package nordapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/b1rd33/nordmac/internal/catalog"
)

const (
	DefaultBaseURL = "https://api.nordvpn.com/v1"
	maxBodyBytes   = 8 << 20
)

// Client reads the public, unauthenticated server catalog only.
type Client struct {
	baseURL *url.URL
	http    *http.Client
}

func New(baseURL string, httpClient *http.Client) (*Client, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse API base URL: %w", err)
	}
	if base.Scheme != "https" && base.Hostname() != "127.0.0.1" && base.Hostname() != "localhost" {
		return nil, errors.New("API base URL must use HTTPS")
	}
	if httpClient == nil {
		return nil, errors.New("HTTP client is required")
	}
	return &Client{baseURL: base, http: httpClient}, nil
}

func (c *Client) Countries(ctx context.Context) ([]catalog.Country, error) {
	var response []countryDTO
	if err := c.getJSON(ctx, "/servers/countries", nil, &response); err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, fmt.Errorf("%w: countries response is empty", catalog.ErrInvalid)
	}

	countries := make([]catalog.Country, 0, len(response))
	seenCodes := make(map[string]struct{}, len(response))
	for index, item := range response {
		country, err := item.convert()
		if err != nil {
			return nil, fmt.Errorf("%w: country %d: %v", catalog.ErrInvalid, index, err)
		}
		if _, duplicate := seenCodes[country.Code]; duplicate {
			return nil, fmt.Errorf("%w: duplicate country code %s", catalog.ErrInvalid, country.Code)
		}
		seenCodes[country.Code] = struct{}{}
		countries = append(countries, country)
	}
	sort.Slice(countries, func(i, j int) bool { return countries[i].Code < countries[j].Code })
	return countries, nil
}

func (c *Client) Recommendations(ctx context.Context, countryID, cityID int64, limit int) ([]catalog.Server, error) {
	query, err := serverQuery(countryID, cityID, limit)
	if err != nil {
		return nil, err
	}
	return c.servers(ctx, "/servers/recommendations", query)
}

func (c *Client) Servers(ctx context.Context, countryID int64, limit int) ([]catalog.Server, error) {
	query, err := serverQuery(countryID, 0, limit)
	if err != nil {
		return nil, err
	}
	return c.servers(ctx, "/servers", query)
}

func (c *Client) servers(ctx context.Context, path string, query url.Values) ([]catalog.Server, error) {
	var response []serverDTO
	if err := c.getJSON(ctx, path, query, &response); err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, catalog.ErrNoMatch
	}

	servers := make([]catalog.Server, 0, len(response))
	for index, item := range response {
		server, err := item.convert()
		if err != nil {
			return nil, fmt.Errorf("%w: server %d: %v", catalog.ErrInvalid, index, err)
		}
		servers = append(servers, server)
	}
	return servers, nil
}

func serverQuery(countryID, cityID int64, limit int) (url.Values, error) {
	if countryID <= 0 {
		return nil, errors.New("country id must be positive")
	}
	if limit < 1 || limit > 1000 {
		return nil, errors.New("server limit must be between 1 and 1000")
	}
	query := make(url.Values)
	query.Set("filters[country_id]", fmt.Sprint(countryID))
	query.Set("filters[servers_technologies][identifier]", "wireguard_udp")
	query.Set("limit", fmt.Sprint(limit))
	if cityID > 0 {
		query.Set("filters[city_id]", fmt.Sprint(cityID))
	}
	return query, nil
}

func (c *Client) getJSON(ctx context.Context, path string, query url.Values, destination any) error {
	endpoint := c.baseURL.ResolveReference(&url.URL{Path: strings.TrimRight(c.baseURL.Path, "/") + path})
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return fmt.Errorf("build public API request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "nordmac/dev")

	response, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("public API request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("public API returned HTTP %d", response.StatusCode)
	}
	if mediaType := strings.ToLower(response.Header.Get("Content-Type")); !strings.HasPrefix(mediaType, "application/json") {
		return fmt.Errorf("public API returned unexpected content type %q", mediaType)
	}

	limited := http.MaxBytesReader(nil, response.Body, maxBodyBytes)
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode public API response: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("decode public API response: trailing JSON value")
		}
		return fmt.Errorf("decode public API response trailer: %w", err)
	}
	return nil
}

type countryDTO struct {
	ID     int64     `json:"id"`
	Name   string    `json:"name"`
	Code   string    `json:"code"`
	Cities []cityDTO `json:"cities"`
}

type cityDTO struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	DNSName string `json:"dns_name"`
}

func (d countryDTO) convert() (catalog.Country, error) {
	code := strings.ToUpper(strings.TrimSpace(d.Code))
	name := strings.TrimSpace(d.Name)
	if d.ID <= 0 || len(code) != 2 || name == "" {
		return catalog.Country{}, errors.New("missing or invalid id, name, or ISO code")
	}
	country := catalog.Country{ID: d.ID, Name: name, Code: code, Cities: make([]catalog.City, 0, len(d.Cities))}
	seen := make(map[string]struct{}, len(d.Cities))
	for _, rawCity := range d.Cities {
		city := catalog.City{ID: rawCity.ID, Name: strings.TrimSpace(rawCity.Name), Slug: strings.ToLower(strings.TrimSpace(rawCity.DNSName))}
		if city.ID <= 0 || city.Name == "" || city.Slug == "" {
			return catalog.Country{}, errors.New("city has missing or invalid id, name, or slug")
		}
		if _, duplicate := seen[city.Slug]; duplicate {
			return catalog.Country{}, fmt.Errorf("duplicate city slug %s", city.Slug)
		}
		seen[city.Slug] = struct{}{}
		country.Cities = append(country.Cities, city)
	}
	sort.Slice(country.Cities, func(i, j int) bool { return country.Cities[i].Slug < country.Cities[j].Slug })
	return country, nil
}

type serverDTO struct {
	ID           int64           `json:"id"`
	Name         string          `json:"name"`
	Hostname     string          `json:"hostname"`
	Load         int             `json:"load"`
	Status       string          `json:"status"`
	Locations    []locationDTO   `json:"locations"`
	Technologies []technologyDTO `json:"technologies"`
}

type locationDTO struct {
	Country locationCountryDTO `json:"country"`
}

type locationCountryDTO struct {
	ID   int64   `json:"id"`
	Name string  `json:"name"`
	Code string  `json:"code"`
	City cityDTO `json:"city"`
}

type technologyDTO struct {
	Identifier string        `json:"identifier"`
	Metadata   []metadataDTO `json:"metadata"`
}

type metadataDTO struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (d serverDTO) convert() (catalog.Server, error) {
	if d.ID <= 0 || strings.TrimSpace(d.Name) == "" || strings.TrimSpace(d.Hostname) == "" || strings.TrimSpace(d.Status) == "" {
		return catalog.Server{}, errors.New("missing server identity or status")
	}
	if d.Load < 0 || d.Load > 100 {
		return catalog.Server{}, errors.New("load is outside 0..100")
	}
	if len(d.Locations) == 0 {
		return catalog.Server{}, errors.New("server has no location")
	}
	location := d.Locations[0].Country
	if location.ID <= 0 || len(strings.TrimSpace(location.Code)) != 2 || location.City.ID <= 0 {
		return catalog.Server{}, errors.New("server location is incomplete")
	}

	var publicKey string
	for _, technology := range d.Technologies {
		if technology.Identifier != "wireguard_udp" {
			continue
		}
		for _, metadata := range technology.Metadata {
			if metadata.Name == "public_key" {
				publicKey = strings.TrimSpace(metadata.Value)
			}
		}
	}
	return catalog.Server{
		ID:              d.ID,
		Name:            strings.TrimSpace(d.Name),
		Hostname:        strings.ToLower(strings.TrimSpace(d.Hostname)),
		Load:            d.Load,
		Status:          strings.ToLower(strings.TrimSpace(d.Status)),
		CountryID:       location.ID,
		CountryName:     strings.TrimSpace(location.Name),
		CountryCode:     strings.ToUpper(strings.TrimSpace(location.Code)),
		CityID:          location.City.ID,
		CityName:        strings.TrimSpace(location.City.Name),
		CitySlug:        strings.ToLower(strings.TrimSpace(location.City.DNSName)),
		WireGuardPubKey: publicKey,
	}, nil
}
