package command

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/b1rd33/nordmac/internal/buildinfo"
	"github.com/b1rd33/nordmac/internal/catalog"
	"github.com/b1rd33/nordmac/internal/connectplan"
	"github.com/b1rd33/nordmac/internal/output"
	"github.com/b1rd33/nordmac/internal/recommend"
)

const (
	ExitOK        = 0
	ExitUsage     = 2
	ExitNoMatch   = 4
	ExitNetwork   = 5
	ExitPrivilege = 6
)

type Backend interface {
	Countries(context.Context, bool) (catalog.CountriesResult, error)
	Recommend(context.Context, recommend.Query) (RecommendationResult, error)
}

func Run(ctx context.Context, args []string, stdout, stderr io.Writer, backend Backend) int {
	if len(args) == 0 {
		writeUsage(stderr)
		return ExitUsage
	}

	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(stdout, buildinfo.String())
		return ExitOK
	case "help", "--help", "-h":
		writeUsage(stdout)
		return ExitOK
	case "countries":
		return runCountries(ctx, args[1:], stdout, stderr, backend)
	case "recommend":
		return runRecommend(ctx, args[1:], stdout, stderr, backend)
	case "plan":
		return runPlan(ctx, args[1:], stdout, stderr, backend)
	case "login", "status", "connect", "disconnect", "reconnect":
		return unavailable(args[0], hasJSON(args[1:]), stdout, stderr)
	default:
		return fail(hasJSON(args[1:]), stdout, stderr, ExitUsage, "usage", fmt.Sprintf("unknown command %q", args[0]))
	}
}

type PlanResult struct {
	Query    recommend.Query      `json:"query"`
	Country  catalog.Country      `json:"country"`
	Server   catalog.Server       `json:"server"`
	Manifest connectplan.Manifest `json:"manifest"`
	Source   catalog.Source       `json:"countries_source"`
	Fetched  time.Time            `json:"countries_fetched_at"`
	Warning  []string             `json:"warnings,omitempty"`
}

func runCountries(ctx context.Context, args []string, stdout, stderr io.Writer, backend Backend) int {
	jsonMode := hasJSON(args)
	refresh := false
	for _, arg := range args {
		switch arg {
		case "--json":
		case "--refresh":
			refresh = true
		case "--help", "-h":
			fmt.Fprintln(stdout, "usage: nordmac countries [--json] [--refresh]")
			return ExitOK
		default:
			return fail(jsonMode, stdout, stderr, ExitUsage, "usage", fmt.Sprintf("unknown countries argument %q", arg))
		}
	}

	result, err := backend.Countries(ctx, refresh)
	if err != nil {
		return fail(jsonMode, stdout, stderr, classify(err), errorCode(err), err.Error())
	}
	if jsonMode {
		if err := output.JSONSuccess(stdout, result); err != nil {
			fmt.Fprintf(stderr, "nordmac: write output: %v\n", err)
			return ExitNetwork
		}
		return ExitOK
	}
	for _, warning := range result.Warnings {
		fmt.Fprintf(stderr, "nordmac: warning: %s\n", warning)
	}
	for _, country := range result.Countries {
		fmt.Fprintf(stdout, "%s  %s\n", country.Code, country.Name)
		for _, city := range country.Cities {
			fmt.Fprintf(stdout, "    %-20s %s\n", city.Slug, city.Name)
		}
	}
	return ExitOK
}

func runRecommend(ctx context.Context, args []string, stdout, stderr io.Writer, backend Backend) int {
	jsonMode := hasJSON(args)
	query, help, err := parseRecommend(args)
	if help {
		fmt.Fprintln(stdout, "usage: nordmac recommend <country> [--city <city>] [--server <server>] [--json]")
		return ExitOK
	}
	if err != nil {
		return fail(jsonMode, stdout, stderr, ExitUsage, "usage", err.Error())
	}

	result, err := backend.Recommend(ctx, query)
	if err != nil {
		return fail(jsonMode, stdout, stderr, classify(err), errorCode(err), err.Error())
	}
	if jsonMode {
		if err := output.JSONSuccess(stdout, result); err != nil {
			fmt.Fprintf(stderr, "nordmac: write output: %v\n", err)
			return ExitNetwork
		}
		return ExitOK
	}
	for _, warning := range result.Warning {
		fmt.Fprintf(stderr, "nordmac: warning: %s\n", warning)
	}
	fmt.Fprintf(stdout, "%s  %s / %s  load %d%%\n", result.Server.Hostname, result.Server.CountryName, result.Server.CityName, result.Server.Load)
	return ExitOK
}

func runPlan(ctx context.Context, args []string, stdout, stderr io.Writer, backend Backend) int {
	jsonMode := hasJSON(args)
	query, help, err := parseRecommend(args)
	if help {
		fmt.Fprintln(stdout, "usage: nordmac plan <country> [--city <city>] [--server <server>] [--json]")
		return ExitOK
	}
	if err != nil {
		return fail(jsonMode, stdout, stderr, ExitUsage, "usage", err.Error())
	}

	recommendation, err := backend.Recommend(ctx, query)
	if err != nil {
		return fail(jsonMode, stdout, stderr, classify(err), errorCode(err), err.Error())
	}
	manifest, err := connectplan.Build(recommendation.Server)
	if err != nil {
		return fail(jsonMode, stdout, stderr, ExitNetwork, "invalid_data", err.Error())
	}
	result := PlanResult{
		Query: query, Country: recommendation.Country, Server: recommendation.Server, Manifest: manifest,
		Source: recommendation.Source, Fetched: recommendation.Fetched, Warning: recommendation.Warning,
	}
	if jsonMode {
		if err := output.JSONSuccess(stdout, result); err != nil {
			fmt.Fprintf(stderr, "nordmac: write output: %v\n", err)
			return ExitNetwork
		}
		return ExitOK
	}
	for _, warning := range result.Warning {
		fmt.Fprintf(stderr, "nordmac: warning: %s\n", warning)
	}
	fmt.Fprintf(stdout, "candidate only — live test blocked\n%s (%s:%d)\n", result.Server.Hostname, result.Manifest.Endpoint.IPv4, result.Manifest.Endpoint.Port)
	for _, blocker := range result.Manifest.Blockers {
		fmt.Fprintf(stdout, "  blocked: %s\n", blocker)
	}
	return ExitOK
}

func parseRecommend(args []string) (recommend.Query, bool, error) {
	var query recommend.Query
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch {
		case arg == "--json":
		case arg == "--help" || arg == "-h":
			return recommend.Query{}, true, nil
		case arg == "--city" || arg == "--server":
			if index+1 >= len(args) || strings.HasPrefix(args[index+1], "-") {
				return recommend.Query{}, false, fmt.Errorf("%s requires a value", arg)
			}
			index++
			if arg == "--city" {
				if query.City != "" {
					return recommend.Query{}, false, errors.New("--city may be specified only once")
				}
				query.City = args[index]
			} else {
				if query.Server != "" {
					return recommend.Query{}, false, errors.New("--server may be specified only once")
				}
				query.Server = args[index]
			}
		case strings.HasPrefix(arg, "--city="):
			if query.City != "" || strings.TrimPrefix(arg, "--city=") == "" {
				return recommend.Query{}, false, errors.New("invalid or duplicate --city")
			}
			query.City = strings.TrimPrefix(arg, "--city=")
		case strings.HasPrefix(arg, "--server="):
			if query.Server != "" || strings.TrimPrefix(arg, "--server=") == "" {
				return recommend.Query{}, false, errors.New("invalid or duplicate --server")
			}
			query.Server = strings.TrimPrefix(arg, "--server=")
		case strings.HasPrefix(arg, "-"):
			return recommend.Query{}, false, fmt.Errorf("unknown recommend flag %q", arg)
		default:
			if query.Country != "" {
				return recommend.Query{}, false, fmt.Errorf("unexpected argument %q", arg)
			}
			query.Country = arg
		}
	}
	if query.Country == "" {
		return recommend.Query{}, false, errors.New("country is required")
	}
	return query, false, nil
}

func unavailable(command string, jsonMode bool, stdout, stderr io.Writer) int {
	message := fmt.Sprintf("%s is not implemented in Phase 1 and no system changes were made", command)
	return fail(jsonMode, stdout, stderr, ExitUsage, "unavailable", message)
}

func classify(err error) int {
	if errors.Is(err, catalog.ErrNoMatch) || errors.Is(err, catalog.ErrAmbiguous) {
		return ExitNoMatch
	}
	if errors.Is(err, catalog.ErrInvalid) {
		return ExitNetwork
	}
	return ExitNetwork
}

func errorCode(err error) string {
	if errors.Is(err, catalog.ErrNoMatch) {
		return "no_match"
	}
	if errors.Is(err, catalog.ErrAmbiguous) {
		return "ambiguous"
	}
	if errors.Is(err, catalog.ErrInvalid) {
		return "invalid_data"
	}
	return "network"
}

func fail(jsonMode bool, stdout, stderr io.Writer, exit int, code, message string) int {
	if jsonMode {
		if err := output.JSONError(stdout, code, message); err != nil {
			fmt.Fprintf(stderr, "nordmac: write error output: %v\n", err)
			return ExitNetwork
		}
		return exit
	}
	fmt.Fprintf(stderr, "nordmac: %s\n", message)
	return exit
}

func hasJSON(args []string) bool {
	for _, arg := range args {
		if arg == "--json" {
			return true
		}
	}
	return false
}

func writeUsage(writer io.Writer) {
	fmt.Fprintln(writer, `usage: nordmac <command> [options]

Read-only commands:
  countries [--json] [--refresh]
  recommend <country> [--city <city>] [--server <server>] [--json]
  plan <country> [--city <city>] [--server <server>] [--json]

Planned but unavailable: login, status, connect, disconnect, reconnect`)
}
