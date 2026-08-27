package nordauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/b1rd33/nordmac/internal/credentials"
)

const syntheticToken = "0123456789abcdef"

func TestProvisionUsesBoundedObservedContract(t *testing.T) {
	var requestSeen bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestSeen = true
		if request.Method != http.MethodGet || request.URL.Path != provisionPath {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer "+syntheticToken {
			t.Error("missing bearer authorization")
		}
		writer.Header().Set("Content-Type", "application/json")
		io.WriteString(writer, `{"id":42,"created_at":"synthetic","updated_at":"synthetic","username":"synthetic-user","password":"synthetic-password","nordlynx_private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`)
	}))
	defer server.Close()

	token := []byte(syntheticToken)
	result, err := (Client{BaseURL: server.URL, HTTP: server.Client()}).Provision(context.Background(), token)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	defer credentials.Wipe(result.PrivateKey)
	if !requestSeen || result.AccountID != 42 || string(result.PrivateKey) != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		t.Fatalf("result = %#v, requestSeen = %v", result, requestSeen)
	}
	if string(token) != syntheticToken {
		t.Fatal("Provision modified the caller-owned token")
	}
}

func TestProvisionRejectsRedirectWithoutForwardingToken(t *testing.T) {
	var destinationAuthorization string
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		destinationAuthorization = request.Header.Get("Authorization")
		writer.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()

	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Redirect(writer, &http.Request{}, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	_, err := (Client{BaseURL: source.URL, HTTP: source.Client()}).Provision(context.Background(), []byte(syntheticToken))
	if err == nil {
		t.Fatal("Provision unexpectedly followed a redirect")
	}
	if destinationAuthorization != "" {
		t.Fatal("authorization reached redirect destination")
	}
}

func TestProvisionMapsStatusWithoutReturningBody(t *testing.T) {
	for status, want := range map[int]error{
		http.StatusUnauthorized:    ErrUnauthorized,
		http.StatusForbidden:       ErrForbidden,
		http.StatusTooManyRequests: ErrRateLimited,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(status)
				io.WriteString(writer, `{"secret":"must-not-escape"}`)
			}))
			defer server.Close()
			_, err := (Client{BaseURL: server.URL, HTTP: server.Client()}).Provision(context.Background(), []byte(syntheticToken))
			if !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
			if strings.Contains(err.Error(), "must-not-escape") {
				t.Fatal("response body appeared in error")
			}
		})
	}
}

func TestProvisionRejectsInvalidInputBeforeNetwork(t *testing.T) {
	for _, token := range [][]byte{nil, []byte("UPPERCASE"), []byte("contains-dash")} {
		_, err := (Client{BaseURL: "https://example.invalid"}).Provision(context.Background(), token)
		if err == nil {
			t.Fatalf("token %q unexpectedly accepted", token)
		}
	}
	for _, base := range []string{"http://api.nordvpn.com", "https://api.nordvpn.com:444", "https://example.com", "https://user@example.com", "://bad"} {
		_, err := (Client{BaseURL: base}).Provision(context.Background(), []byte(syntheticToken))
		if err == nil {
			t.Fatalf("base URL %q unexpectedly accepted", base)
		}
	}
}

func TestProvisionRejectsOversizeAndSchemaDrift(t *testing.T) {
	tests := map[string]string{
		"oversize":      strings.Repeat("x", maxBodyBytes+1),
		"unknown field": `{"id":42,"created_at":"x","updated_at":"x","username":"x","password":"x","nordlynx_private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","surprise":true}`,
		"bad key":       `{"id":42,"created_at":"x","updated_at":"x","username":"x","password":"x","nordlynx_private_key":"not-a-key"}`,
		"trailing JSON": `{"id":42,"created_at":"x","updated_at":"x","username":"x","password":"x","nordlynx_private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}{}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				io.WriteString(writer, body)
			}))
			defer server.Close()
			_, err := (Client{BaseURL: server.URL, HTTP: server.Client()}).Provision(context.Background(), []byte(syntheticToken))
			if !errors.Is(err, ErrInvalidData) {
				t.Fatalf("error = %v, want ErrInvalidData", err)
			}
		})
	}
}
