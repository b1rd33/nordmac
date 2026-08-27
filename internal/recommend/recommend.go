package recommend

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode"

	"github.com/b1rd33/nordmac/internal/catalog"
)

// Query describes a deterministic recommendation request.
type Query struct {
	Country string `json:"country"`
	City    string `json:"city,omitempty"`
	Server  string `json:"server,omitempty"`
}

// ResolveCountry accepts an ISO code or an unambiguous country name.
func ResolveCountry(countries []catalog.Country, input string) (catalog.Country, error) {
	want := normalize(input)
	if want == "" {
		return catalog.Country{}, fmt.Errorf("%w: country is required", catalog.ErrInvalid)
	}

	var matches []catalog.Country
	for _, country := range countries {
		if normalize(country.Code) == want || normalize(country.Name) == want {
			matches = append(matches, country)
		}
	}
	if len(matches) == 0 {
		return catalog.Country{}, fmt.Errorf("%w: country %q", catalog.ErrNoMatch, input)
	}
	if len(matches) > 1 {
		return catalog.Country{}, fmt.Errorf("%w: country %q", catalog.ErrAmbiguous, input)
	}
	return matches[0], nil
}

// ResolveCity accepts a city name or slug within an already resolved country.
func ResolveCity(country catalog.Country, input string) (catalog.City, error) {
	want := normalize(input)
	if want == "" {
		return catalog.City{}, fmt.Errorf("%w: city is required", catalog.ErrInvalid)
	}

	var matches []catalog.City
	for _, city := range country.Cities {
		if normalize(city.Name) == want || normalize(city.Slug) == want {
			matches = append(matches, city)
		}
	}
	if len(matches) == 0 {
		return catalog.City{}, fmt.Errorf("%w: city %q in %s", catalog.ErrNoMatch, input, country.Code)
	}
	if len(matches) > 1 {
		return catalog.City{}, fmt.Errorf("%w: city %q in %s", catalog.ErrAmbiguous, input, country.Code)
	}
	return matches[0], nil
}

// Select returns the first eligible server, preserving the API's ordering.
func Select(servers []catalog.Server, country catalog.Country, cityID int64, exactServer string) (catalog.Server, error) {
	wantHost := normalizeServer(exactServer)
	seen := make(map[string]struct{}, len(servers))
	for _, server := range servers {
		host := strings.ToLower(strings.TrimSpace(server.Hostname))
		if _, duplicate := seen[host]; duplicate {
			continue
		}
		seen[host] = struct{}{}

		if server.CountryID != country.ID || !strings.EqualFold(server.CountryCode, country.Code) {
			continue
		}
		if cityID != 0 && server.CityID != cityID {
			continue
		}
		if wantHost != "" && host != wantHost {
			continue
		}
		if !strings.EqualFold(server.Status, "online") || !validWireGuardKey(server.WireGuardPubKey) {
			continue
		}
		return server, nil
	}

	detail := country.Code
	if exactServer != "" {
		detail += " server " + exactServer
	}
	return catalog.Server{}, fmt.Errorf("%w: %s", catalog.ErrNoMatch, detail)
}

func normalizeServer(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if !strings.Contains(value, ".") {
		value += ".nordvpn.com"
	}
	return value
}

func normalize(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return -1
	}, value)
}

func validWireGuardKey(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}
