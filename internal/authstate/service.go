// Package authstate inspects and removes the fixed local credential pair.
package authstate

import (
	"context"
	"errors"
	"time"

	"github.com/b1rd33/nordmac/internal/credentials"
)

var (
	ErrCredentialLock        = errors.New("credential state lock failed")
	ErrCredentialRead        = errors.New("credential state read failed")
	ErrCredentialTransaction = errors.New("credential removal transaction failed")
	ErrRollbackIncomplete    = errors.New("credential removal rollback incomplete")
)

type State string

const (
	LoggedOut    State = "logged_out"
	LoggedIn     State = "logged_in"
	Inconsistent State = "inconsistent"
)

type Locker interface {
	Lock(context.Context) (func() error, error)
}

type Service struct {
	Store  credentials.Store
	Locker Locker
}

type Status struct {
	State         State `json:"state"`
	HasToken      bool  `json:"has_access_token"`
	HasPrivateKey bool  `json:"has_nordlynx_private_key"`
	RepairNeeded  bool  `json:"repair_needed"`
}

type LogoutResult struct {
	LocalCredentialsRemoved bool `json:"local_credentials_removed"`
	RemoteTokenRevoked      bool `json:"remote_token_revoked"`
}

type snapshot struct {
	value  []byte
	exists bool
}

func (service Service) Inspect(ctx context.Context) (result Status, retErr error) {
	release, err := service.acquire(ctx)
	if err != nil {
		return Status{}, err
	}
	defer func() {
		if err := release(); err != nil {
			result = Status{}
			retErr = errors.Join(retErr, ErrCredentialLock)
		}
	}()

	token, err := capture(ctx, service.Store, credentials.AccessToken)
	if err != nil {
		return Status{}, ErrCredentialRead
	}
	defer credentials.Wipe(token.value)
	key, err := capture(ctx, service.Store, credentials.NordLynxPrivateKey)
	if err != nil {
		return Status{}, ErrCredentialRead
	}
	defer credentials.Wipe(key.value)
	return status(token.exists, key.exists), nil
}

func (service Service) LogoutLocal(ctx context.Context) (result LogoutResult, retErr error) {
	release, err := service.acquire(ctx)
	if err != nil {
		return LogoutResult{}, err
	}
	defer func() {
		if err := release(); err != nil {
			result = LogoutResult{}
			retErr = errors.Join(retErr, ErrCredentialLock)
		}
	}()

	token, err := capture(ctx, service.Store, credentials.AccessToken)
	if err != nil {
		return LogoutResult{}, ErrCredentialRead
	}
	defer credentials.Wipe(token.value)
	key, err := capture(ctx, service.Store, credentials.NordLynxPrivateKey)
	if err != nil {
		return LogoutResult{}, ErrCredentialRead
	}
	defer credentials.Wipe(key.value)
	if !token.exists && !key.exists {
		return LogoutResult{}, nil
	}

	if err := deleteIfPresent(ctx, service.Store, credentials.AccessToken, token.exists); err != nil {
		return LogoutResult{}, service.failedRemoval(ctx, token, key)
	}
	if err := deleteIfPresent(ctx, service.Store, credentials.NordLynxPrivateKey, key.exists); err != nil {
		return LogoutResult{}, service.failedRemoval(ctx, token, key)
	}
	return LogoutResult{LocalCredentialsRemoved: true, RemoteTokenRevoked: false}, nil
}

func (service Service) acquire(ctx context.Context) (func() error, error) {
	if service.Store == nil || service.Locker == nil {
		return nil, errors.New("credential state service is incomplete")
	}
	release, err := service.Locker.Lock(ctx)
	if err != nil {
		return nil, ErrCredentialLock
	}
	return release, nil
}

func (service Service) failedRemoval(ctx context.Context, token, key snapshot) error {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := errors.Join(
		restore(rollbackCtx, service.Store, credentials.AccessToken, token),
		restore(rollbackCtx, service.Store, credentials.NordLynxPrivateKey, key),
	); err != nil {
		return errors.Join(ErrCredentialTransaction, ErrRollbackIncomplete)
	}
	return ErrCredentialTransaction
}

func capture(ctx context.Context, store credentials.Store, kind credentials.Kind) (snapshot, error) {
	value, err := store.Get(ctx, kind)
	if errors.Is(err, credentials.ErrNotFound) {
		credentials.Wipe(value)
		return snapshot{}, nil
	}
	if err != nil {
		credentials.Wipe(value)
		return snapshot{}, err
	}
	return snapshot{value: value, exists: true}, nil
}

func deleteIfPresent(ctx context.Context, store credentials.Store, kind credentials.Kind, exists bool) error {
	if !exists {
		return nil
	}
	return store.Delete(ctx, kind)
}

func restore(ctx context.Context, store credentials.Store, kind credentials.Kind, before snapshot) error {
	if before.exists {
		return store.Put(ctx, kind, before.value)
	}
	err := store.Delete(ctx, kind)
	if errors.Is(err, credentials.ErrNotFound) {
		return nil
	}
	return err
}

func status(hasToken, hasKey bool) Status {
	state := Inconsistent
	if hasToken && hasKey {
		state = LoggedIn
	} else if !hasToken && !hasKey {
		state = LoggedOut
	}
	return Status{
		State: state, HasToken: hasToken, HasPrivateKey: hasKey,
		RepairNeeded: state == Inconsistent,
	}
}
