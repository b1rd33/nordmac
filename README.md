# nordmac

Open-source, macOS-first CLI for selecting NordVPN locations and, only after an explicit validation gate, managing a NordLynx/WireGuard tunnel without GUI automation.

The shipped CLI remains read-only and uses Nord's public, unauthenticated server catalog. The controlled WireGuard device and scoped-route gates have passed on macOS, but real login and full-tunnel commands remain disabled. No tunnel device, authenticated request, credential creation, privileged helper, route/DNS change, or other network mutation is performed by the shipped CLI.

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

## Available read-only commands

```bash
mkdir -p bin
go build -o bin/nordmac ./cmd/nordmac

bin/nordmac countries
bin/nordmac countries --json
bin/nordmac recommend de
bin/nordmac recommend de --city berlin --json
bin/nordmac recommend de --server de1234 --json
bin/nordmac plan de --city berlin --json
```

`countries` uses a 24-hour non-secret cache at the platform user cache location. Set `NORDMAC_CACHE_DIR` to override its parent directory for development or tests. `--refresh` requests a new country catalog; if the public API is unavailable and stale cache data exists, the command succeeds with an explicit warning.

`plan` freezes a candidate server IPv4, peer-key fingerprint, WireGuard parameters, split-route mutations, DNS resolvers, current upstream reference commit, and remaining safety blockers. It always reports `ready_for_live_test: false`; it does not read credentials or change the network.

The `login`, `status`, `connect`, `disconnect`, and `reconnect` command names currently return an `unavailable` error and perform no system changes.

The credential foundation uses fixed Keychain account names and keeps secrets out of process arguments. Its automated tests use synthetic values, a fake runner, and local HTTP servers; they do not touch the user's Keychain or Nord's authenticated API. Live synthetic validation found that Apple's `security(1)` stdin write can return success while storing an empty value, so `Store.Put` now fails closed until it is replaced by a native or signed boundary. See [ADR 0002](docs/adr/0002-authentication-contract.md) and the [Keychain validation record](docs/validation/keychain-2026-08-28.md).

An unreleased native Security framework helper has passed create/read/replace/read/delete validation against both an explicit temporary Keychain and one approved synthetic item in the user's login Keychain. The login test used a fixed validation-only service and left no item behind. Real Nord credentials, authenticated requests, and the production CLI path remain disabled. The next signed release is designed to include the validation-only helper beside the CLI with its SHA-256 embedded in that architecture's CLI; the existing v0.1.0 release does not contain it. See the [isolated](docs/validation/native-keychain-2026-08-28.md) and [login Keychain](docs/validation/native-login-keychain-2026-08-28.md) validation records.

The tunnel core records intent before each planned mutation, pins the endpoint before tunnel routes, restores in reverse order, and retains incomplete rollback evidence. Unreleased approval-gated harnesses validated userspace WireGuard and one scoped route against controlled peers; the adapters remain disconnected from shipped commands. See [ADR 0003](docs/adr/0003-tunnel-transaction-core.md), [ADR 0005](docs/adr/0005-scoped-route-gate.md), and the [Gate 3 evidence](docs/validation/scoped-route-2026-08-27.md).

The current `/v1/servers` endpoints are the replacement family Nord pointed users to after deprecating older endpoints; nevertheless, they remain undocumented and are treated as unstable. See [ADR 0001](docs/adr/0001-public-api.md).

## Homebrew release

Install the latest release from the public tap:

```bash
brew install --cask b1rd33/tap/nordmac
```

The existing v0.1.0 release contains unsigned Apple Silicon and Intel binaries. Future releases are gated on Developer ID signing and Apple notarization and use architecture-specific ZIP archives containing the CLI and its fixed validation-only Keychain helper. See the [v0.1.0 release](https://github.com/b1rd33/nordmac/releases/tag/v0.1.0) or [docs/releasing.md](docs/releasing.md) for the release pipeline.

## License and affiliation

`nordmac` is independently authored and released under the [MIT License](LICENSE). See [source provenance](docs/source-provenance.md) for the pre-publication comparison with Nord's GPL Linux client.

This is an unofficial project and is not affiliated with or endorsed by Nord Security. NordVPN and NordLynx are referenced only to describe interoperability targets.
