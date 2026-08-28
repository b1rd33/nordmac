// Package tokeninput reads a Nord access token without accepting it through
// process arguments or environment variables.
package tokeninput

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/b1rd33/nordmac/internal/credentials"
	"golang.org/x/term"
)

const maxTokenBytes = 4096

type Terminal struct {
	IsTerminal   func(int) bool
	ReadPassword func(int) ([]byte, error)
}

func ReadHidden(fd int, prompt io.Writer, terminal Terminal) ([]byte, error) {
	if prompt == nil {
		return nil, errors.New("token prompt is unavailable")
	}
	if terminal.IsTerminal == nil {
		terminal.IsTerminal = term.IsTerminal
	}
	if terminal.ReadPassword == nil {
		terminal.ReadPassword = term.ReadPassword
	}
	if !terminal.IsTerminal(fd) {
		return nil, errors.New("hidden token input requires a terminal; use --token-stdin")
	}
	if _, err := fmt.Fprint(prompt, "Nord access token: "); err != nil {
		return nil, errors.New("write token prompt")
	}
	raw, err := terminal.ReadPassword(fd)
	_, newlineErr := fmt.Fprintln(prompt)
	if err != nil {
		credentials.Wipe(raw)
		return nil, errors.New("read hidden token")
	}
	if newlineErr != nil {
		credentials.Wipe(raw)
		return nil, errors.New("finish token prompt")
	}
	return normalize(raw, false)
}

func ReadStdin(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("token stdin is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, maxTokenBytes+3))
	if err != nil {
		credentials.Wipe(raw)
		return nil, errors.New("read token from stdin")
	}
	return normalize(raw, true)
}

func normalize(raw []byte, allowLineEnding bool) ([]byte, error) {
	if allowLineEnding {
		raw = bytes.TrimSuffix(raw, []byte("\n"))
		raw = bytes.TrimSuffix(raw, []byte("\r"))
	}
	if len(raw) == 0 || len(raw) > maxTokenBytes {
		credentials.Wipe(raw)
		return nil, errors.New("invalid Nord access token format")
	}
	for _, value := range raw {
		if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
			credentials.Wipe(raw)
			return nil, errors.New("invalid Nord access token format")
		}
	}
	return raw, nil
}
