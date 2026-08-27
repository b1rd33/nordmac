package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/b1rd33/nordmac/internal/catalog"
)

const cacheSchemaVersion = 1

// Countries stores normalized, non-secret catalog data.
type Countries struct {
	Path string
	TTL  time.Duration
}

type countriesFile struct {
	SchemaVersion int               `json:"schema_version"`
	FetchedAt     time.Time         `json:"fetched_at"`
	Countries     []catalog.Country `json:"countries"`
}

func (c Countries) Read(now time.Time) (catalog.CountriesResult, bool, error) {
	file, err := os.Open(c.Path)
	if errors.Is(err, os.ErrNotExist) {
		return catalog.CountriesResult{}, false, nil
	}
	if err != nil {
		return catalog.CountriesResult{}, false, fmt.Errorf("open countries cache: %w", err)
	}
	defer file.Close()

	var stored countriesFile
	decoder := json.NewDecoder(io.LimitReader(file, 4<<20))
	if err := decoder.Decode(&stored); err != nil {
		return catalog.CountriesResult{}, false, fmt.Errorf("decode countries cache: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return catalog.CountriesResult{}, false, errors.New("decode countries cache: trailing JSON value")
		}
		return catalog.CountriesResult{}, false, fmt.Errorf("decode countries cache trailer: %w", err)
	}
	if stored.SchemaVersion != cacheSchemaVersion || stored.FetchedAt.IsZero() || len(stored.Countries) == 0 {
		return catalog.CountriesResult{}, false, errors.New("countries cache has invalid metadata")
	}
	fresh := now.Sub(stored.FetchedAt) >= 0 && now.Sub(stored.FetchedAt) <= c.TTL
	return catalog.CountriesResult{Countries: stored.Countries, Source: catalog.SourceCache, FetchedAt: stored.FetchedAt}, fresh, nil
}

func (c Countries) Write(result catalog.CountriesResult) error {
	if result.FetchedAt.IsZero() || len(result.Countries) == 0 {
		return errors.New("refusing to cache empty countries result")
	}
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o700); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}

	file, err := os.CreateTemp(filepath.Dir(c.Path), ".countries-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary countries cache: %w", err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("protect countries cache: %w", err)
	}

	stored := countriesFile{SchemaVersion: cacheSchemaVersion, FetchedAt: result.FetchedAt, Countries: result.Countries}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(stored); err != nil {
		file.Close()
		return fmt.Errorf("encode countries cache: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync countries cache: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close countries cache: %w", err)
	}
	if err := os.Rename(temporaryPath, c.Path); err != nil {
		return fmt.Errorf("replace countries cache: %w", err)
	}
	return nil
}
