package connection

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/b1rd33/nordmac/internal/tunnel"
)

type Metadata struct {
	SchemaVersion int       `json:"schema_version"`
	SessionID     string    `json:"session_id"`
	Server        string    `json:"server"`
	Country       string    `json:"country"`
	City          string    `json:"city"`
	Phase         string    `json:"phase"`
	CreatedAt     time.Time `json:"created_at"`
}

func (metadata Metadata) validate() error {
	if metadata.SchemaVersion != 1 || !tunnel.ValidSessionID(metadata.SessionID) || metadata.Server == "" || metadata.CreatedAt.IsZero() {
		return errors.New("invalid local connection metadata")
	}
	if metadata.Phase != "connecting" && metadata.Phase != "connected" {
		return errors.New("invalid local connection phase")
	}
	return nil
}

type MetadataStore struct{ Path string }

func (store MetadataStore) Load() (Metadata, error) {
	data, err := os.ReadFile(store.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Metadata{}, os.ErrNotExist
	}
	if err != nil {
		return Metadata{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var metadata Metadata
	if err := decoder.Decode(&metadata); err != nil {
		return Metadata{}, errors.New("decode local connection metadata")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Metadata{}, errors.New("trailing local connection metadata")
	}
	if err := metadata.validate(); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func (store MetadataStore) Save(metadata Metadata) error {
	if err := metadata.validate(); err != nil {
		return err
	}
	directory := filepath.Dir(store.Path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(directory, ".connection-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, store.Path); err != nil {
		return fmt.Errorf("replace local connection metadata: %w", err)
	}
	return nil
}

func (store MetadataStore) Delete() error {
	err := os.Remove(store.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
