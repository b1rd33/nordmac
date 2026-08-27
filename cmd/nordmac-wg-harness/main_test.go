package main

import (
	"testing"
	"time"
)

func TestValidateGate(t *testing.T) {
	const session = "0123456789abcdef0123456789abcdef"
	if _, err := validateGate(session, "192.0.2.1:51820", time.Second, false); err == nil {
		t.Fatal("missing acknowledgement accepted")
	}
	if _, err := validateGate(session, "vpn.example:51820", time.Second, true); err == nil {
		t.Fatal("hostname endpoint accepted")
	}
	if _, err := validateGate(session, "192.0.2.1:51820", 61*time.Second, true); err == nil {
		t.Fatal("unbounded duration accepted")
	}
	if _, err := validateGate(session, "192.0.2.1:51820", 10*time.Second, true); err != nil {
		t.Fatalf("valid gate rejected: %v", err)
	}
	if _, err := validateGate(session, "127.0.0.1:51820", 10*time.Second, true); err != nil {
		t.Fatalf("loopback controlled peer rejected: %v", err)
	}
}
