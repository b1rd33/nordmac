// Package nordauth contains the bounded client for Nord's undocumented
// credential-provisioning contract. The packaged CLI invokes it only from an
// explicit login command; tests use loopback and synthetic credentials.
package nordauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/b1rd33/nordmac/internal/credentials"
)

const (
	defaultBaseURL = "https://api.nordvpn.com"
	provisionPath  = "/v1/users/services/credentials"
	maxBodyBytes   = 64 << 10
	requestTimeout = 10 * time.Second
)

var (
	ErrUnauthorized = errors.New("Nord access token was rejected")
	ErrForbidden    = errors.New("Nord account is not authorized for VPN credentials")
	ErrRateLimited  = errors.New("Nord credential service rate limit reached")
	ErrInvalidData  = errors.New("Nord credential response is invalid")
)

// Provisioning contains only the fields nordmac would need from the candidate
// endpoint. PrivateKey is base64 text and must be wiped by the caller.
type Provisioning struct {
	AccountID  int64
	PrivateKey []byte
}

// BaseURL exists for local httptest servers; production callers leave it empty.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// Provision performs the observed credential exchange. It does not mutate the
// Nord account, but its response contains a private key.
func (client Client) Provision(ctx context.Context, token []byte) (Provisioning, error) {
	if err := validateToken(token); err != nil {
		return Provisioning{}, err
	}
	endpoint, err := client.endpoint()
	if err != nil {
		return Provisioning{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Provisioning{}, errors.New("construct Nord credential request")
	}
	// net/http requires header values to be strings. This creates an unavoidable
	// transient copy, but the value is never logged, returned, or placed in argv.
	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "nordmac/credential-contract-probe")

	httpClient := client.httpClient()
	resp, err := httpClient.Do(req)
	if err != nil {
		return Provisioning{}, fmt.Errorf("request Nord credentials: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return Provisioning{}, ErrUnauthorized
	case http.StatusForbidden:
		return Provisioning{}, ErrForbidden
	case http.StatusTooManyRequests:
		return Provisioning{}, ErrRateLimited
	default:
		return Provisioning{}, fmt.Errorf("Nord credential service returned HTTP %d", resp.StatusCode)
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
	if mediaType != "application/json" {
		return Provisioning{}, fmt.Errorf("%w: unexpected content type", ErrInvalidData)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return Provisioning{}, errors.New("read Nord credential response")
	}
	defer credentials.Wipe(body)
	if len(body) > maxBodyBytes {
		return Provisioning{}, fmt.Errorf("%w: response exceeds %d bytes", ErrInvalidData, maxBodyBytes)
	}
	return decodeProvisioning(body)
}

type wireResponse struct {
	ID                 int64           `json:"id"`
	CreatedAt          json.RawMessage `json:"created_at"`
	UpdatedAt          json.RawMessage `json:"updated_at"`
	Username           json.RawMessage `json:"username"`
	Password           json.RawMessage `json:"password"`
	NordLynxPrivateKey json.RawMessage `json:"nordlynx_private_key"`
}

func decodeProvisioning(body []byte) (Provisioning, error) {
	var response wireResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return Provisioning{}, fmt.Errorf("%w: malformed schema", ErrInvalidData)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return Provisioning{}, err
	}
	defer wipeRawFields(&response)
	if response.ID <= 0 {
		return Provisioning{}, fmt.Errorf("%w: invalid account id", ErrInvalidData)
	}

	encoded := response.NordLynxPrivateKey
	if len(encoded) != 46 || encoded[0] != '"' || encoded[len(encoded)-1] != '"' {
		return Provisioning{}, fmt.Errorf("%w: invalid NordLynx private key", ErrInvalidData)
	}
	encoded = encoded[1 : len(encoded)-1]
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	defer credentials.Wipe(decoded)
	count, err := base64.StdEncoding.Decode(decoded, encoded)
	if err != nil || count != 32 {
		return Provisioning{}, fmt.Errorf("%w: invalid NordLynx private key", ErrInvalidData)
	}
	return Provisioning{AccountID: response.ID, PrivateKey: bytes.Clone(encoded)}, nil
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing response data", ErrInvalidData)
	}
	return nil
}

func wipeRawFields(response *wireResponse) {
	credentials.Wipe(response.CreatedAt)
	credentials.Wipe(response.UpdatedAt)
	credentials.Wipe(response.Username)
	credentials.Wipe(response.Password)
	credentials.Wipe(response.NordLynxPrivateKey)
}

func validateToken(token []byte) error {
	if len(token) == 0 || len(token) > 4096 {
		return errors.New("invalid Nord access token format")
	}
	for _, value := range token {
		if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
			return errors.New("invalid Nord access token format")
		}
	}
	return nil
}

func (client Client) endpoint() (string, error) {
	base := client.BaseURL
	if base == "" {
		base = defaultBaseURL
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("invalid Nord API base URL")
	}
	loopback := isLoopbackHost(parsed.Hostname())
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback) {
		return "", errors.New("Nord API base URL must use HTTPS")
	}
	if !loopback && (!strings.EqualFold(parsed.Hostname(), "api.nordvpn.com") || (parsed.Port() != "" && parsed.Port() != "443")) {
		return "", errors.New("Nord API base URL host is not allowed")
	}
	parsed.Path = provisionPath
	parsed.RawPath = ""
	return parsed.String(), nil
}

func isLoopbackHost(host string) bool {
	return host == "127.0.0.1" || host == "::1" || strings.EqualFold(host, "localhost")
}

func (client Client) httpClient() *http.Client {
	configured := client.HTTP
	if configured == nil {
		configured = &http.Client{}
	}
	copy := *configured
	if copy.Timeout == 0 || copy.Timeout > requestTimeout {
		copy.Timeout = requestTimeout
	}
	copy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("redirect refused for credential request")
	}
	return &copy
}
