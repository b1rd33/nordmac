package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b1rd33/nordmac/internal/buildinfo"
	"github.com/b1rd33/nordmac/internal/catalog"
	"github.com/b1rd33/nordmac/internal/recommend"
)

type fakeBackend struct {
	countries catalog.CountriesResult
	result    RecommendationResult
	err       error
	query     recommend.Query
}

func (f *fakeBackend) Countries(context.Context, bool) (catalog.CountriesResult, error) {
	return f.countries, f.err
}

func (f *fakeBackend) Recommend(_ context.Context, query recommend.Query) (RecommendationResult, error) {
	f.query = query
	return f.result, f.err
}

func TestRunRecommendFlagsAfterCountryJSON(t *testing.T) {
	fetched := time.Date(2026, 8, 27, 8, 0, 0, 0, time.UTC)
	backend := &fakeBackend{result: RecommendationResult{
		Query:   recommend.Query{Country: "de", City: "berlin"},
		Country: catalog.Country{ID: 81, Name: "Germany", Code: "DE", Cities: []catalog.City{{ID: 2181458, Name: "Berlin", Slug: "berlin"}}},
		Server: catalog.Server{
			ID: 1001, Name: "Germany #1001", Hostname: "de1001.nordvpn.com", Station: "203.0.113.11", Load: 6, Status: "online",
			CountryID: 81, CountryName: "Germany", CountryCode: "DE", CityID: 2181458, CityName: "Berlin", CitySlug: "berlin",
			WireGuardPubKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		},
		Source: catalog.SourceCache, Fetched: fetched,
	}}
	var stdout, stderr bytes.Buffer
	exit := Run(context.Background(), []string{"recommend", "de", "--city", "berlin", "--json"}, &stdout, &stderr, backend)
	if exit != ExitOK || backend.query.Country != "de" || backend.query.City != "berlin" || stderr.Len() != 0 {
		t.Fatalf("exit=%d query=%#v stderr=%q", exit, backend.query, stderr.String())
	}
	var envelope struct {
		SchemaVersion int  `json:"schema_version"`
		OK            bool `json:"ok"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil || !envelope.OK || envelope.SchemaVersion != 1 {
		t.Fatalf("output=%q err=%v envelope=%#v", stdout.String(), err, envelope)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "testdata", "recommend.json.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if stdout.String() != string(want) {
		t.Fatalf("JSON output changed\nwant: %s\n got: %s", want, stdout.String())
	}
}

func TestRunPlanIsExplicitlyNotLiveReady(t *testing.T) {
	backend := &fakeBackend{result: RecommendationResult{
		Query:   recommend.Query{Country: "de"},
		Country: catalog.Country{ID: 81, Name: "Germany", Code: "DE"},
		Server: catalog.Server{
			ID: 1001, Name: "Germany #1001", Hostname: "de1001.nordvpn.com", Station: "203.0.113.11",
			Load: 6, Status: "online", CountryID: 81, CountryName: "Germany", CountryCode: "DE",
			CityID: 2181458, CityName: "Berlin", CitySlug: "berlin",
			WireGuardPubKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		},
		Source: catalog.SourceNetwork, Fetched: time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC),
	}}
	var stdout, stderr bytes.Buffer
	exit := Run(context.Background(), []string{"plan", "de", "--json"}, &stdout, &stderr, backend)
	if exit != ExitOK || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%q", exit, stderr.String())
	}
	var envelope struct {
		OK   bool `json:"ok"`
		Data struct {
			Manifest struct {
				Ready    bool     `json:"ready_for_live_test"`
				Blockers []string `json:"blockers"`
			} `json:"manifest"`
		} `json:"data"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil || !envelope.OK || envelope.Data.Manifest.Ready || len(envelope.Data.Manifest.Blockers) != 4 {
		t.Fatalf("output=%q err=%v envelope=%#v", stdout.String(), err, envelope)
	}
}

func TestRunCountriesText(t *testing.T) {
	backend := &fakeBackend{countries: catalog.CountriesResult{Countries: []catalog.Country{{Code: "DE", Name: "Germany", Cities: []catalog.City{{Name: "Berlin", Slug: "berlin"}}}}, FetchedAt: time.Now()}}
	var stdout, stderr bytes.Buffer
	if exit := Run(context.Background(), []string{"countries"}, &stdout, &stderr, backend); exit != ExitOK {
		t.Fatalf("exit=%d stderr=%q", exit, stderr.String())
	}
	if !strings.Contains(stdout.String(), "DE  Germany") || !strings.Contains(stdout.String(), "berlin") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestRunVersionNeedsNoBackend(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exit := Run(context.Background(), []string{"--version"}, &stdout, &stderr, nil)
	if exit != ExitOK || !strings.HasPrefix(stdout.String(), "nordmac ") || stderr.Len() != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
}

func TestRunVersionJSONIncludesPackagedHelperDigest(t *testing.T) {
	previous := buildinfo.HelperSHA256
	buildinfo.HelperSHA256 = strings.Repeat("a", 64)
	t.Cleanup(func() { buildinfo.HelperSHA256 = previous })
	var stdout, stderr bytes.Buffer
	exit := Run(context.Background(), []string{"version", "--json"}, &stdout, &stderr, nil)
	if exit != ExitOK || !strings.Contains(stdout.String(), `"helper_sha256":"`+strings.Repeat("a", 64)+`"`) || stderr.Len() != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
}

func TestRunNoMatchJSON(t *testing.T) {
	backend := &fakeBackend{err: catalog.ErrNoMatch}
	var stdout, stderr bytes.Buffer
	exit := Run(context.Background(), []string{"recommend", "zz", "--json"}, &stdout, &stderr, backend)
	if exit != ExitNoMatch || !strings.Contains(stdout.String(), `"code":"no_match"`) || stderr.Len() != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
}

func TestRunUnavailableNeverCallsBackend(t *testing.T) {
	backend := &fakeBackend{err: errors.New("must not be called")}
	var stdout, stderr bytes.Buffer
	exit := Run(context.Background(), []string{"connect", "de", "--json"}, &stdout, &stderr, backend)
	if exit != ExitUsage || !strings.Contains(stdout.String(), "no system changes were made") {
		t.Fatalf("exit=%d stdout=%q", exit, stdout.String())
	}
}

func TestParseRecommendRejectsDuplicates(t *testing.T) {
	_, _, err := parseRecommend([]string{"de", "--city", "berlin", "--city=frankfurt"})
	if err == nil {
		t.Fatal("expected duplicate flag error")
	}
}
