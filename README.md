# nordmac

Open-source, macOS-first CLI for selecting NordVPN locations and, only after an explicit validation gate, managing a NordLynx/WireGuard tunnel without GUI automation.

Phase 1 is implemented. The available commands are read-only and use Nord's public, unauthenticated server catalog. No tunnel implementation, authentication flow, credentials, installer, privileged helper, or network mutation exists.

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

The current `/v1/servers` endpoints are the replacement family Nord pointed users to after deprecating older endpoints; nevertheless, they remain undocumented and are treated as unstable. See [ADR 0001](docs/adr/0001-public-api.md).

## Homebrew release

Once `v0.1.0` is published, install from the existing personal tap:

```bash
brew install --cask b1rd33/tap/nordmac
```

Release archives include Apple Silicon and Intel macOS binaries plus SHA-256 checksums. See [docs/releasing.md](docs/releasing.md) for the release pipeline and its remaining publication gates.

## License and affiliation

`nordmac` is independently authored and released under the [MIT License](LICENSE). See [source provenance](docs/source-provenance.md) for the pre-publication comparison with Nord's GPL Linux client.

This is an unofficial project and is not affiliated with or endorsed by Nord Security. NordVPN and NordLynx are referenced only to describe interoperability targets.
