package helperproto

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/b1rd33/nordmac/internal/tunnel"
)

func protocolPlan() tunnel.Plan {
	return tunnel.Plan{
		SessionID:         strings.Repeat("a", 32),
		OwnerUID:          501,
		Endpoint:          netip.MustParseAddrPort("203.0.113.10:51820"),
		PhysicalGateway:   netip.MustParseAddr("192.0.2.1"),
		PhysicalInterface: "en0",
		TunnelAddress:     netip.MustParsePrefix("10.5.0.2/32"),
		TunnelMTU:         1420,
		TunnelDNS:         []netip.Addr{netip.MustParseAddr("10.5.0.1")},
		RoutePolicy:       tunnel.RoutePolicyFullIPv4,
		PeerFingerprint:   strings.Repeat("b", 64),
	}
}

func TestRequestValidation(t *testing.T) {
	plan := protocolPlan()
	valid := Request{
		SchemaVersion:        SchemaVersion,
		RequestID:            strings.Repeat("c", 32),
		Operation:            OperationConnect,
		SessionID:            plan.SessionID,
		OwnerUID:             plan.OwnerUID,
		SecretChannelVersion: SecretChannelVersion,
		Plan:                 &plan,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid connect request: %v", err)
	}

	tests := map[string]Request{
		"unknown schema":         func() Request { value := valid; value.SchemaVersion++; return value }(),
		"unknown operation":      func() Request { value := valid; value.Operation = "shell"; return value }(),
		"missing secret channel": func() Request { value := valid; value.SecretChannelVersion = 0; return value }(),
		"owner mismatch":         func() Request { value := valid; value.OwnerUID++; return value }(),
		"arbitrary session":      func() Request { value := valid; value.SessionID = "../outside"; return value }(),
	}
	for name, request := range tests {
		t.Run(name, func(t *testing.T) {
			if err := request.Validate(); err == nil {
				t.Fatal("request unexpectedly accepted")
			}
		})
	}

	disconnect := Request{
		SchemaVersion: SchemaVersion,
		RequestID:     strings.Repeat("d", 32),
		Operation:     OperationDisconnect,
		SessionID:     plan.SessionID,
		OwnerUID:      plan.OwnerUID,
	}
	if err := disconnect.Validate(); err != nil {
		t.Fatalf("valid disconnect request: %v", err)
	}
	disconnect.Plan = &plan
	if err := disconnect.Validate(); err == nil {
		t.Fatal("disconnect unexpectedly accepted a connect plan")
	}
}

func TestRequestCodecIsBoundedAndStrict(t *testing.T) {
	plan := protocolPlan()
	request := Request{
		SchemaVersion:        SchemaVersion,
		RequestID:            strings.Repeat("c", 32),
		Operation:            OperationConnect,
		SessionID:            plan.SessionID,
		OwnerUID:             plan.OwnerUID,
		SecretChannelVersion: SecretChannelVersion,
		Plan:                 &plan,
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRequest(bytes.NewReader(data))
	if err != nil || decoded.Operation != OperationConnect {
		t.Fatalf("DecodeRequest = operation %s, error %v", decoded.Operation, err)
	}
	for name, input := range map[string][]byte{
		"unknown":  append(data[:len(data)-1], []byte(`,"shell":"value"}`)...),
		"trailing": append(append([]byte(nil), data...), []byte(`{}`)...),
		"oversize": bytes.Repeat([]byte{'x'}, maxRequestBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequest(bytes.NewReader(input)); err == nil {
				t.Fatal("DecodeRequest unexpectedly accepted invalid data")
			}
		})
	}
}

func TestResponseHasOnlyStableCodes(t *testing.T) {
	response := Response{
		SchemaVersion: SchemaVersion,
		RequestID:     strings.Repeat("d", 32),
		OK:            false,
		State:         tunnel.PhaseRollbackRequired,
		ErrorCode:     ErrorRollback,
	}
	var output bytes.Buffer
	if err := EncodeResponse(&output, response); err != nil {
		t.Fatalf("EncodeResponse: %v", err)
	}
	if bytes.Contains(output.Bytes(), []byte("message")) {
		t.Fatal("response unexpectedly contains free-form error text")
	}
	response.ErrorCode = "external-error-text"
	if err := EncodeResponse(&bytes.Buffer{}, response); err == nil {
		t.Fatal("EncodeResponse unexpectedly accepted an arbitrary error code")
	}
}

func TestSecretFrameRoundTripAndWipe(t *testing.T) {
	var input DeviceSecrets
	for index := range input.ClientPrivateKey {
		input.ClientPrivateKey[index] = byte(index + 1)
		input.PeerPublicKey[index] = byte(index + 33)
	}
	var buffer bytes.Buffer
	if err := WriteSecrets(&buffer, &input); err != nil {
		t.Fatalf("WriteSecrets: %v", err)
	}
	if buffer.Len() != SecretFrameBytes {
		t.Fatalf("frame length = %d, want %d", buffer.Len(), SecretFrameBytes)
	}
	output, err := ReadSecrets(&buffer)
	if err != nil {
		t.Fatalf("ReadSecrets: %v", err)
	}
	if output != input {
		t.Fatal("secret frame did not round trip")
	}
	output.Wipe()
	if !allZero(output.ClientPrivateKey[:]) || !allZero(output.PeerPublicKey[:]) {
		t.Fatal("Wipe did not clear the keys")
	}
}

func TestSecretFrameRejectsInvalidInput(t *testing.T) {
	var zero DeviceSecrets
	if err := WriteSecrets(&bytes.Buffer{}, &zero); err == nil {
		t.Fatal("WriteSecrets unexpectedly accepted zero keys")
	}

	short := bytes.NewReader(make([]byte, SecretFrameBytes-1))
	if _, err := ReadSecrets(short); err == nil {
		t.Fatal("ReadSecrets unexpectedly accepted a short frame")
	}

	trailing := make([]byte, SecretFrameBytes+1)
	copy(trailing[:4], secretMagic[:])
	trailing[4] = 1
	trailing[36] = 2
	if _, err := ReadSecrets(bytes.NewReader(trailing)); err == nil {
		t.Fatal("ReadSecrets unexpectedly accepted trailing data")
	}
}
