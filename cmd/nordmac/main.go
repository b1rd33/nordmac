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
	"github.com/b1rd33/nordmac/internal/connection"
	"github.com/b1rd33/nordmac/internal/credentiallock"
	"github.com/b1rd33/nordmac/internal/credentials"
	"github.com/b1rd33/nordmac/internal/darwinnet"
	"github.com/b1rd33/nordmac/internal/helperclient"
	"github.com/b1rd33/nordmac/internal/helperdaemon"
	"github.com/b1rd33/nordmac/internal/loginflow"
	"github.com/b1rd33/nordmac/internal/nativekeychain"
	"github.com/b1rd33/nordmac/internal/nordapi"
	"github.com/b1rd33/nordmac/internal/nordauth"
)

type authenticatedBackend struct {
	command.Backend
	command.Authentication
}

type connectedBackend struct {
	authenticatedBackend
	command.Connection
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
	if len(os.Args) == 2 && os.Args[1] == "__helper" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := helperdaemon.Run(ctx, os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "nordmac: privileged helper failed")
			return command.ExitPrivilege
		}
		return command.ExitOK
	}
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
	if authentication, store, authErr := configureAuthentication(); authErr == nil {
		configRoot, configErr := os.UserConfigDir()
		if configErr == nil {
			runner := darwinnet.CommandRunner{}
			connections := connection.Service{
				Recommender: service, Credentials: store, Routes: darwinnet.RouteManager{Runner: runner}, Runner: runner,
				Helper: helperclient.Client{Stderr: os.Stderr}, Metadata: connection.MetadataStore{Path: filepath.Join(configRoot, "nordmac", "connection-v1.json")},
				Locker: credentiallock.FileLocker{Directory: filepath.Join(configRoot, "nordmac")}, OwnerUID: os.Getuid(),
			}
			backend = connectedBackend{authenticatedBackend: authenticatedBackend{Backend: service, Authentication: authentication}, Connection: connections}
		} else {
			backend = authenticatedBackend{Backend: service, Authentication: authentication}
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return command.RunWithInput(ctx, os.Args[1:], command.Input{Reader: os.Stdin, FD: int(os.Stdin.Fd())}, os.Stdout, os.Stderr, backend)
}

func configureAuthentication() (command.Authentication, credentials.Store, error) {
	helper, err := nativekeychain.LocatePackagedHelper()
	if err != nil {
		return nil, nil, err
	}
	store, err := nativekeychain.NewLogin(helper)
	if err != nil {
		return nil, nil, err
	}
	configRoot, err := os.UserConfigDir()
	if err != nil {
		return nil, nil, err
	}
	locker := credentiallock.FileLocker{Directory: filepath.Join(configRoot, "nordmac")}
	return productionAuthentication{
		login: loginflow.Service{Provisioner: nordauth.Client{}, Store: store, Locker: locker},
		state: authstate.Service{Store: store, Locker: locker},
	}, store, nil
}
