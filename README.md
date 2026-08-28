# nordmac

Open-source, macOS-first CLI for selecting NordVPN locations and, only after an explicit validation gate, managing a NordLynx/WireGuard tunnel without GUI automation.

The currently published v0.1.0 CLI remains read-only and uses Nord's public, unauthenticated server catalog. The controlled WireGuard device and scoped-route gates have passed on macOS, but real login and full-tunnel validation remain incomplete. No tunnel device, authenticated request, credential creation, privileged helper, route/DNS change, or other network mutation is performed by v0.1.0.

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

`connect`, `disconnect`, and `reconnect` still return an `unavailable` error and perform no system changes. The source tree now wires `login`, credential-aware `status`, and explicit `logout --local-only` only when the running CLI authenticates its packaged native helper by resolved location, SHA-256, type, mode, and ownership. Development builds without an embedded helper digest and the published v0.1.0 release remain unavailable before reading token input or accessing Keychain.

The credential foundation uses fixed Keychain account names and keeps secrets out of process arguments. Its automated tests use synthetic values, a fake runner, and local HTTP servers; they do not touch the user's Keychain or Nord's authenticated API. Live synthetic validation found that Apple's `security(1)` stdin write can return success while storing an empty value, so `Store.Put` now fails closed until it is replaced by a native or signed boundary. See [ADR 0002](docs/adr/0002-authentication-contract.md) and the [Keychain validation record](docs/validation/keychain-2026-08-28.md).

An unreleased native Security framework helper has passed create/read/replace/read/delete validation against both an explicit temporary Keychain and one approved synthetic item in the user's login Keychain. The login test used a fixed validation-only service and left no item behind. The helper now also contains a separate fixed production service, but the public CLI does not invoke it and it has never been used with a production item. Real Nord credentials and authenticated requests remain disabled. The release pipeline can package the helper beside the CLI with its SHA-256 embedded in that architecture's CLI; the existing v0.1.0 release does not contain it. See the [isolated](docs/validation/native-keychain-2026-08-28.md), [login Keychain](docs/validation/native-login-keychain-2026-08-28.md), and [login-boundary](docs/validation/login-boundary-2026-08-28.md) validation records.

The candidate login transaction has also passed end-to-end simulation against one loopback request and an isolated temporary Keychain. It provisioned a synthetic response, stored and verified the token/key pair, deleted both, and removed the Keychain. Bounded hidden/stdin token parsing, a private single-writer credential lock, status consistency detection, and transactional local removal are implemented and tested. `logout` requires `--local-only` because it does not revoke the token remotely. This does not validate Nord's live undocumented endpoint or authorize a production login test. See the [synthetic login](docs/validation/synthetic-login-2026-08-28.md) and [authentication-command](docs/validation/auth-commands-2026-08-28.md) records.

The tunnel core records intent before each planned mutation, pins the endpoint before tunnel routes, restores in reverse order, and retains incomplete rollback evidence. Unreleased approval-gated harnesses validated userspace WireGuard and one scoped route against controlled peers; the adapters remain disconnected from shipped commands. See [ADR 0003](docs/adr/0003-tunnel-transaction-core.md), [ADR 0005](docs/adr/0005-scoped-route-gate.md), and the [Gate 3 evidence](docs/validation/scoped-route-2026-08-27.md).

The current `/v1/servers` endpoints are the replacement family Nord pointed users to after deprecating older endpoints; nevertheless, they remain undocumented and are treated as unstable. See [ADR 0001](docs/adr/0001-public-api.md).

## Homebrew release

Install the latest release from the public tap:

```bash
brew install --cask b1rd33/tap/nordmac
```

The existing v0.1.0 release contains unsigned Apple Silicon and Intel binaries. The repository can build ad-hoc local snapshots without an Apple Developer membership. Public releases from the current pipeline are gated on Developer ID signing and Apple notarization and use architecture-specific ZIP archives containing the CLI and its fixed-target Keychain helper. See the [v0.1.0 release](https://github.com/b1rd33/nordmac/releases/tag/v0.1.0) or [docs/releasing.md](docs/releasing.md) for the release pipeline.

## License and affiliation

`nordmac` is independently authored and released under the [MIT License](LICENSE). See [source provenance](docs/source-provenance.md) for the pre-publication comparison with Nord's GPL Linux client.

This is an unofficial project and is not affiliated with or endorsed by Nord Security. NordVPN and NordLynx are referenced only to describe interoperability targets.
