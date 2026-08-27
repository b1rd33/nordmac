# nordmac

Open-source, macOS-first CLI for selecting NordVPN locations and, only after an explicit validation gate, managing a NordLynx/WireGuard tunnel without GUI automation.

Phase 1 is implemented. The available commands are read-only and use Nord's public, unauthenticated server catalog. Phase 2 now includes runner-isolated credential work plus an offline journaled tunnel transaction core, but real login and every privileged adapter remain disabled. No tunnel device, authenticated request, credential creation, privileged helper, route/DNS change, or other network mutation is performed by the CLI.

See [docs/implementation-plan.md](docs/implementation-plan.md) for the architecture, phased delivery plan, safety gates, and Phase 1 scope.

## Intended commands

```bash
nordmac login
nordmac countries --json
nordmac recommend de --json
sudo nordmac connect de --json
sudo nordmac connect de --city berlin
sudo nordmac connect de --server de1234
nordmac status --json
sudo nordmac disconnect
sudo nordmac reconnect --fresh
```

These commands are a target interface, not a statement that Nord's undocumented authentication and NordLynx provisioning APIs are stable or supported.

## Phase 1 commands

```bash
mkdir -p bin
go build -o bin/nordmac ./cmd/nordmac

bin/nordmac countries
bin/nordmac countries --json
bin/nordmac recommend de
bin/nordmac recommend de --city berlin --json
bin/nordmac recommend de --server de1234 --json
```

`countries` uses a 24-hour non-secret cache at the platform user cache location. Set `NORDMAC_CACHE_DIR` to override its parent directory for development or tests. `--refresh` requests a new country catalog; if the public API is unavailable and stale cache data exists, the command succeeds with an explicit warning.

The `login`, `status`, `connect`, `disconnect`, and `reconnect` command names currently return an `unavailable` error and perform no system changes.

The Phase 2 credential foundation uses fixed Keychain account names and keeps secrets out of process arguments. Its tests use synthetic values, a fake runner, and local HTTP servers; they do not touch the user's Keychain or Nord's authenticated API. See [ADR 0002](docs/adr/0002-authentication-contract.md) for the current authentication evidence and the gate that keeps real token exchange disabled.

The Phase 2 tunnel core records intent before each planned mutation, pins the endpoint before split IPv4 defaults, restores in reverse order, and retains incomplete rollback evidence. All current adapters are fakes or temporary-directory state stores; the code is not connected to a command. See [ADR 0003](docs/adr/0003-tunnel-transaction-core.md) for the local-peer harness gates and helper boundary.

The current `/v1/servers` endpoints are the replacement family Nord pointed users to after deprecating older endpoints; nevertheless, they remain undocumented and are treated as unstable. See [ADR 0001](docs/adr/0001-public-api.md).

## Homebrew release

Install the latest release from the public tap:

```bash
brew install --cask b1rd33/tap/nordmac
```

Release archives include Apple Silicon and Intel macOS binaries plus SHA-256 checksums. See the [v0.1.0 release](https://github.com/b1rd33/nordmac/releases/tag/v0.1.0) or [docs/releasing.md](docs/releasing.md) for the release pipeline.

## License and affiliation

`nordmac` is independently authored and released under the [MIT License](LICENSE). See [source provenance](docs/source-provenance.md) for the pre-publication comparison with Nord's GPL Linux client.

This is an unofficial project and is not affiliated with or endorsed by Nord Security. NordVPN and NordLynx are referenced only to describe interoperability targets.
