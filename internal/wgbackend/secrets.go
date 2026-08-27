package wgbackend

import (
	"context"
	"errors"
	"sync"

	"github.com/b1rd33/nordmac/internal/helperproto"
	"github.com/b1rd33/nordmac/internal/tunnel"
)

// OneShotSecrets is a small in-memory bridge for the future helper's fixed
// binary secret channel. It is intentionally neither serializable nor reusable.
type OneShotSecrets struct {
	mu        sync.Mutex
	sessionID string
	secrets   helperproto.DeviceSecrets
	consumed  bool
}

func NewOneShotSecrets(sessionID string, secrets *helperproto.DeviceSecrets) (*OneShotSecrets, error) {
	if !validSecretSession(sessionID) || secrets == nil {
		return nil, errors.New("invalid one-shot WireGuard secrets")
	}
	if err := secrets.Validate(); err != nil {
		return nil, err
	}
	source := &OneShotSecrets{sessionID: sessionID, secrets: *secrets}
	secrets.Wipe()
	return source, nil
}

func (source *OneShotSecrets) Consume(ctx context.Context, sessionID string, consume func(*helperproto.DeviceSecrets) error) error {
	if consume == nil {
		return errors.New("missing WireGuard secret consumer")
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if source.consumed || sessionID != source.sessionID {
		return errors.New("WireGuard secrets unavailable for session")
	}
	source.consumed = true
	defer source.secrets.Wipe()
	return consume(&source.secrets)
}

func validSecretSession(sessionID string) bool {
	return tunnel.ValidSessionID(sessionID)
}
