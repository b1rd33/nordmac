package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/b1rd33/nordmac/internal/authstate"
	"github.com/b1rd33/nordmac/internal/cache"
	"github.com/b1rd33/nordmac/internal/command"
	"github.com/b1rd33/nordmac/internal/credentiallock"
	"github.com/b1rd33/nordmac/internal/loginflow"
	"github.com/b1rd33/nordmac/internal/nativekeychain"
	"github.com/b1rd33/nordmac/internal/nordapi"
	"github.com/b1rd33/nordmac/internal/nordauth"
)

type authenticatedBackend struct {
	command.Backend
	command.Authentication
}

type productionAuthentication struct {
	login loginflow.Service
	state authstate.Service
}

func (authentication productionAuthentication) Login(ctx context.Context, token []byte) (loginflow.Result, error) {
	return authentication.login.Login(ctx, token)
}

func (authentication productionAuthentication) CredentialStatus(ctx context.Context) (authstate.Status, error) {
	return authentication.state.Inspect(ctx)
}

func (authentication productionAuthentication) LogoutLocal(ctx context.Context) (authstate.LogoutResult, error) {
	return authentication.state.LogoutLocal(ctx)
}

func main() {
	os.Exit(run())
}

func run() int {
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nordmac: locate user cache: %v\n", err)
		return command.ExitNetwork
	}
	if override := os.Getenv("NORDMAC_CACHE_DIR"); override != "" {
		cacheRoot = override
	}
	client, err := nordapi.New(nordapi.DefaultBaseURL, &http.Client{Timeout: 15 * time.Second})
	if err != nil {
		fmt.Fprintf(os.Stderr, "nordmac: configure public API: %v\n", err)
		return command.ExitNetwork
	}
	service := command.Service{
		API: client,
		Cache: cache.Countries{
			Path: filepath.Join(cacheRoot, "nordmac", "countries-v1.json"),
			TTL:  24 * time.Hour,
		},
	}
	var backend command.Backend = service
	if authentication, authErr := configureAuthentication(); authErr == nil {
		backend = authenticatedBackend{Backend: service, Authentication: authentication}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return command.RunWithInput(ctx, os.Args[1:], command.Input{Reader: os.Stdin, FD: int(os.Stdin.Fd())}, os.Stdout, os.Stderr, backend)
}

func configureAuthentication() (command.Authentication, error) {
	helper, err := nativekeychain.LocatePackagedHelper()
	if err != nil {
		return nil, err
	}
	store, err := nativekeychain.NewLogin(helper)
	if err != nil {
		return nil, err
	}
	configRoot, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	locker := credentiallock.FileLocker{Directory: filepath.Join(configRoot, "nordmac")}
	return productionAuthentication{
		login: loginflow.Service{Provisioner: nordauth.Client{}, Store: store, Locker: locker},
		state: authstate.Service{Store: store, Locker: locker},
	}, nil
}
