package command

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/b1rd33/nordmac/internal/authstate"
	"github.com/b1rd33/nordmac/internal/buildinfo"
	"github.com/b1rd33/nordmac/internal/catalog"
	"github.com/b1rd33/nordmac/internal/connectplan"
	"github.com/b1rd33/nordmac/internal/credentials"
	"github.com/b1rd33/nordmac/internal/loginflow"
	"github.com/b1rd33/nordmac/internal/nordauth"
	"github.com/b1rd33/nordmac/internal/output"
	"github.com/b1rd33/nordmac/internal/recommend"
	"github.com/b1rd33/nordmac/internal/tokeninput"
)

const (
	ExitOK        = 0
	ExitUsage     = 2
	ExitNoMatch   = 4
	ExitNetwork   = 5
	ExitPrivilege = 6
	ExitAuth      = 7
	ExitBusy      = 8
)

type Backend interface {
	Countries(context.Context, bool) (catalog.CountriesResult, error)
	Recommend(context.Context, recommend.Query) (RecommendationResult, error)
}

type Authentication interface {
	Login(context.Context, []byte) (loginflow.Result, error)
	CredentialStatus(context.Context) (authstate.Status, error)
	LogoutLocal(context.Context) (authstate.LogoutResult, error)
}

type Input struct {
	Reader   io.Reader
	FD       int
	Terminal tokeninput.Terminal
}

func Run(ctx context.Context, args []string, stdout, stderr io.Writer, backend Backend) int {
	return RunWithInput(ctx, args, Input{}, stdout, stderr, backend)
}

func RunWithInput(ctx context.Context, args []string, input Input, stdout, stderr io.Writer, backend Backend) int {
	if len(args) == 0 {
		writeUsage(stderr)
		return ExitUsage
	}

	switch args[0] {
	case "version", "--version":
		return runVersion(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		writeUsage(stdout)
		return ExitOK
	case "countries":
		return runCountries(ctx, args[1:], stdout, stderr, backend)
	case "recommend":
		return runRecommend(ctx, args[1:], stdout, stderr, backend)
	case "plan":
		return runPlan(ctx, args[1:], stdout, stderr, backend)
	case "login":
		return runLogin(ctx, args[1:], input, stdout, stderr, backend)
	case "status":
		return runStatus(ctx, args[1:], stdout, stderr, backend)
	case "logout":
		return runLogout(ctx, args[1:], stdout, stderr, backend)
	case "connect", "disconnect", "reconnect":
		return unavailable(args[0], hasJSON(args[1:]), stdout, stderr)
	default:
		return fail(hasJSON(args[1:]), stdout, stderr, ExitUsage, "usage", fmt.Sprintf("unknown command %q", args[0]))
	}
}

type StatusResult struct {
	Authentication authstate.Status `json:"authentication"`
	Connection     ConnectionStatus `json:"connection"`
}

type ConnectionStatus struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
}

func runLogin(ctx context.Context, args []string, input Input, stdout, stderr io.Writer, backend Backend) int {
	jsonMode := hasJSON(args)
	stdinMode := false
	for _, arg := range args {
		switch arg {
		case "--json":
		case "--token-stdin":
			if stdinMode {
				return fail(jsonMode, stdout, stderr, ExitUsage, "usage", "--token-stdin may be specified only once")
			}
			stdinMode = true
		case "--help", "-h":
			fmt.Fprintln(stdout, "usage: nordmac login [--token-stdin] [--json]")
			return ExitOK
		default:
			return fail(jsonMode, stdout, stderr, ExitUsage, "usage", fmt.Sprintf("unknown login argument %q", arg))
		}
	}
	authentication, ok := backend.(Authentication)
	if !ok {
		return unavailable("login", jsonMode, stdout, stderr)
	}

	var token []byte
	var err error
	if stdinMode {
		token, err = tokeninput.ReadStdin(input.Reader)
	} else {
		token, err = tokeninput.ReadHidden(input.FD, stderr, input.Terminal)
	}
	if err != nil {
		return fail(jsonMode, stdout, stderr, ExitUsage, "invalid_token_input", err.Error())
	}
	defer credentials.Wipe(token)
	result, err := authentication.Login(ctx, token)
	if err != nil {
		return failAuthentication(jsonMode, stdout, stderr, err)
	}
	if jsonMode {
		if err := output.JSONSuccess(stdout, result); err != nil {
			fmt.Fprintf(stderr, "nordmac: write output: %v\n", err)
			return ExitNetwork
		}
		return ExitOK
	}
	fmt.Fprintf(stdout, "Nord credentials stored for account %d\n", result.AccountID)
	return ExitOK
}

func runStatus(ctx context.Context, args []string, stdout, stderr io.Writer, backend Backend) int {
	jsonMode := hasJSON(args)
	for _, arg := range args {
		switch arg {
		case "--json":
		case "--help", "-h":
			fmt.Fprintln(stdout, "usage: nordmac status [--json]")
			return ExitOK
		default:
			return fail(jsonMode, stdout, stderr, ExitUsage, "usage", fmt.Sprintf("unknown status argument %q", arg))
		}
	}
	authentication, ok := backend.(Authentication)
	if !ok {
		return unavailable("status", jsonMode, stdout, stderr)
	}
	status, err := authentication.CredentialStatus(ctx)
	if err != nil {
		return failAuthentication(jsonMode, stdout, stderr, err)
	}
	result := StatusResult{
		Authentication: status,
		Connection: ConnectionStatus{
			State: "unavailable", Reason: "tunnel commands are not enabled",
		},
	}
	if jsonMode {
		if err := output.JSONSuccess(stdout, result); err != nil {
			fmt.Fprintf(stderr, "nordmac: write output: %v\n", err)
			return ExitNetwork
		}
		return ExitOK
	}
	fmt.Fprintf(stdout, "authentication: %s\nconnection: unavailable\n", status.State)
	if status.RepairNeeded {
		fmt.Fprintln(stderr, "nordmac: warning: local credentials are incomplete; run login again or logout --local-only")
	}
	return ExitOK
}

func runLogout(ctx context.Context, args []string, stdout, stderr io.Writer, backend Backend) int {
	jsonMode := hasJSON(args)
	localOnly := false
	for _, arg := range args {
		switch arg {
		case "--json":
		case "--local-only":
			if localOnly {
				return fail(jsonMode, stdout, stderr, ExitUsage, "usage", "--local-only may be specified only once")
			}
			localOnly = true
		case "--help", "-h":
			fmt.Fprintln(stdout, "usage: nordmac logout --local-only [--json]")
			return ExitOK
		default:
			return fail(jsonMode, stdout, stderr, ExitUsage, "usage", fmt.Sprintf("unknown logout argument %q", arg))
		}
	}
	if !localOnly {
		return fail(jsonMode, stdout, stderr, ExitUsage, "local_only_required", "remote token revocation is not implemented; use --local-only to delete only nordmac's local credentials")
	}
	authentication, ok := backend.(Authentication)
	if !ok {
		return unavailable("logout", jsonMode, stdout, stderr)
	}
	result, err := authentication.LogoutLocal(ctx)
	if err != nil {
		return failAuthentication(jsonMode, stdout, stderr, err)
	}
	if jsonMode {
		if err := output.JSONSuccess(stdout, result); err != nil {
			fmt.Fprintf(stderr, "nordmac: write output: %v\n", err)
			return ExitNetwork
		}
		return ExitOK
	}
	if result.LocalCredentialsRemoved {
		fmt.Fprintln(stdout, "local nordmac credentials deleted; the Nord token was not remotely revoked")
	} else {
		fmt.Fprintln(stdout, "no local nordmac credentials were present; no remote request was made")
	}
	return ExitOK
}

func failAuthentication(jsonMode bool, stdout, stderr io.Writer, err error) int {
	switch {
	case errors.Is(err, nordauth.ErrUnauthorized):
		return fail(jsonMode, stdout, stderr, ExitAuth, "unauthorized", "Nord access token was rejected")
	case errors.Is(err, nordauth.ErrForbidden):
		return fail(jsonMode, stdout, stderr, ExitAuth, "forbidden", "Nord account is not authorized for VPN credentials")
	case errors.Is(err, nordauth.ErrRateLimited):
		return fail(jsonMode, stdout, stderr, ExitNetwork, "rate_limited", "Nord credential service rate limit reached")
	case errors.Is(err, loginflow.ErrCredentialLock), errors.Is(err, authstate.ErrCredentialLock):
		return fail(jsonMode, stdout, stderr, ExitBusy, "busy", "another credential transaction is active")
	case errors.Is(err, loginflow.ErrRollbackIncomplete), errors.Is(err, authstate.ErrRollbackIncomplete):
		return fail(jsonMode, stdout, stderr, ExitNetwork, "credential_recovery_required", "credential rollback was incomplete; inspect status before retrying")
	case errors.Is(err, loginflow.ErrCredentialTransaction), errors.Is(err, authstate.ErrCredentialTransaction):
		return fail(jsonMode, stdout, stderr, ExitNetwork, "credential_transaction", "credential transaction failed without exposing secret data")
	case errors.Is(err, authstate.ErrCredentialRead):
		return fail(jsonMode, stdout, stderr, ExitNetwork, "credential_read", "could not inspect local credentials")
	default:
		return fail(jsonMode, stdout, stderr, ExitNetwork, "authentication", "authentication operation failed")
	}
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stdout, buildinfo.String())
		return ExitOK
	}
	if len(args) == 1 && args[0] == "--json" {
		if err := output.JSONSuccess(stdout, buildinfo.Current()); err != nil {
			fmt.Fprintf(stderr, "nordmac: write output: %v\n", err)
			return ExitNetwork
		}
		return ExitOK
	}
	return fail(hasJSON(args), stdout, stderr, ExitUsage, "usage", "usage: nordmac version [--json]")
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
  version [--json]
  countries [--json] [--refresh]
  recommend <country> [--city <city>] [--server <server>] [--json]
  plan <country> [--city <city>] [--server <server>] [--json]

Authentication commands (require an authenticated packaged helper):
  login [--token-stdin] [--json]
  status [--json]
  logout --local-only [--json]

Planned but unavailable: connect, disconnect, reconnect`)
}
