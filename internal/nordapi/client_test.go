package nordapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCountriesConvertsAndSorts(t *testing.T) {
	fixture := readFixture(t, "countries.json")
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/servers/countries" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	})

	countries, err := client.Countries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(countries) != 2 || countries[0].Code != "DE" || countries[0].Cities[0].Slug != "berlin" {
		t.Fatalf("unexpected countries: %#v", countries)
	}
}

func TestRecommendationsSendsValidatedFilters(t *testing.T) {
	fixture := readFixture(t, "recommendations.json")
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("filters[country_id]") != "81" || query.Get("filters[city_id]") != "2181458" || query.Get("filters[servers_technologies][identifier]") != "wireguard_udp" || query.Get("limit") != "20" {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(fixture)
	})

	servers, err := client.Recommendations(context.Background(), 81, 2181458, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 3 || servers[1].Hostname != "de1001.nordvpn.com" || servers[1].WireGuardPubKey == "" {
		t.Fatalf("unexpected servers: %#v", servers)
	}
}

func TestClientRejectsBadResponses(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		status      int
	}{
		{name: "status", contentType: "application/json", body: `{}`, status: http.StatusServiceUnavailable},
		{name: "content type", contentType: "text/html", body: `[]`, status: http.StatusOK},
		{name: "invalid json", contentType: "application/json", body: `[`, status: http.StatusOK},
		{name: "trailing value", contentType: "application/json", body: `[] {}`, status: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			})
			if _, err := client.Countries(context.Background()); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestRecommendationsRejectsUnboundedLimit(t *testing.T) {
	client := testClient(t, func(http.ResponseWriter, *http.Request) {})
	if _, err := client.Recommendations(context.Background(), 81, 0, 1001); err == nil {
		t.Fatal("expected limit validation error")
	}
}

func testClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder.Result(), nil
	})}
	client, err := New("http://localhost/v1", httpClient)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func FuzzCountriesDecoder(f *testing.F) {
	f.Add(`[{"id":81,"name":"Germany","code":"DE","cities":[]}]`)
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 1<<16 || strings.ContainsRune(body, '\x00') {
			t.Skip()
		}
		client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		})
		_, _ = client.Countries(context.Background())
	})
}
