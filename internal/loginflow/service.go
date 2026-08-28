// Package loginflow coordinates credential provisioning and transactional
// secret storage without deciding how a token is collected from a user.
package loginflow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/b1rd33/nordmac/internal/credentials"
	"github.com/b1rd33/nordmac/internal/nordauth"
)

var (
	ErrCredentialTransaction = errors.New("credential transaction failed")
	ErrRollbackIncomplete    = errors.New("credential rollback incomplete")
)

type Provisioner interface {
	Provision(context.Context, []byte) (nordauth.Provisioning, error)
}

type Service struct {
	Provisioner Provisioner
	Store       credentials.Store
}

type Result struct {
	AccountID int64 `json:"account_id"`
}

type snapshot struct {
	value  []byte
	exists bool
}

func (service Service) Login(ctx context.Context, token []byte) (Result, error) {
	if service.Provisioner == nil || service.Store == nil {
		return Result{}, errors.New("login service is incomplete")
	}
	provisioning, err := service.Provisioner.Provision(ctx, token)
	defer credentials.Wipe(provisioning.PrivateKey)
	if err != nil {
		return Result{}, fmt.Errorf("provision VPN credentials: %w", err)
	}

	accessBefore, err := capture(ctx, service.Store, credentials.AccessToken)
	if err != nil {
		return Result{}, ErrCredentialTransaction
	}
	defer credentials.Wipe(accessBefore.value)
	keyBefore, err := capture(ctx, service.Store, credentials.NordLynxPrivateKey)
	if err != nil {
		return Result{}, ErrCredentialTransaction
	}
	defer credentials.Wipe(keyBefore.value)

	if err := service.Store.Put(ctx, credentials.AccessToken, token); err != nil {
		if service.rollback(ctx, accessBefore, keyBefore) != nil {
			return Result{}, errors.Join(ErrCredentialTransaction, ErrRollbackIncomplete)
		}
		return Result{}, ErrCredentialTransaction
	}
	if err := service.Store.Put(ctx, credentials.NordLynxPrivateKey, provisioning.PrivateKey); err != nil {
		if service.rollback(ctx, accessBefore, keyBefore) != nil {
			return Result{}, errors.Join(ErrCredentialTransaction, ErrRollbackIncomplete)
		}
		return Result{}, ErrCredentialTransaction
	}
	return Result{AccountID: provisioning.AccountID}, nil
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

func (service Service) rollback(ctx context.Context, accessBefore, keyBefore snapshot) error {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return errors.Join(
		restore(rollbackCtx, service.Store, credentials.AccessToken, accessBefore),
		restore(rollbackCtx, service.Store, credentials.NordLynxPrivateKey, keyBefore),
	)
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
