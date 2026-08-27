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

	"github.com/b1rd33/nordmac/internal/cache"
	"github.com/b1rd33/nordmac/internal/command"
	"github.com/b1rd33/nordmac/internal/nordapi"
)

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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return command.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, service)
}
