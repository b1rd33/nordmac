package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateInputsFailsClosed(t *testing.T) {
	valid := func(ack bool, endpoint, route string, duration time.Duration) error {
		_, err := validateInputs(endpoint, "10.250.0.2/32", "10.250.0.1", route, duration, ack)
		return err
	}
	if err := valid(true, "192.0.2.10:51820", "10.250.0.0/24", 20*time.Second); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
	for name, err := range map[string]error{
		"ack":       valid(false, "192.0.2.10:51820", "10.250.0.0/24", 20*time.Second),
		"loopback":  valid(true, "127.0.0.1:51820", "10.250.0.0/24", 20*time.Second),
		"default":   valid(true, "192.0.2.10:51820", "0.0.0.0/0", 20*time.Second),
		"unbounded": valid(true, "192.0.2.10:51820", "10.250.0.0/24", 31*time.Second),
	} {
		if err == nil {
			t.Fatalf("%s gate unexpectedly accepted", name)
		}
	}
}

func TestRemoveStateIfCleanRetainsJournalEvidence(t *testing.T) {
	directory := t.TempDir()
	journal := filepath.Join(directory, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json")
	if err := os.WriteFile(journal, []byte("evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeStateIfClean(directory); err == nil {
		t.Fatal("journal evidence was treated as clean")
	}
	if _, err := os.Stat(journal); err != nil {
		t.Fatalf("journal evidence was removed: %v", err)
	}
	if err := os.Remove(journal); err != nil {
		t.Fatal(err)
	}
	if err := removeStateIfClean(directory); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("clean state directory remains: %v", err)
	}
}
