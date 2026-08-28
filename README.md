# nordmac

Open-source, macOS-first CLI for selecting NordVPN locations and, only after an explicit validation gate, managing a NordLynx/WireGuard tunnel without GUI automation.

The currently published v0.1.0 CLI remains read-only and uses Nord's public, unauthenticated server catalog. The controlled WireGuard device and scoped-route gates have passed on macOS, but real login and full-tunnel validation remain incomplete. No tunnel device, authenticated request, credential creation, privileged helper, route/DNS change, or other network mutation is performed by v0.1.0.

See [docs/implementation-plan.md](docs/implementation-plan.md) for the architecture, phased delivery plan, safety gates, and Phase 1 scope.

## Intended commands

```bash
nordmac login
nordmac countries --json
nordmac recommend de --json
nordmac connect de --json
nordmac connect de --city berlin
nordmac connect de --server de1234
nordmac status --json
nordmac disconnect
nordmac reconnect --fresh
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

The unreleased source tree implements `connect`, `disconnect`, and `reconnect --fresh`. Run the CLI as the ordinary logged-in user: it reads the fixed Keychain items before asking `sudo` to launch a narrow internal helper. That root helper never reads the login Keychain or calls Nord APIs; it owns the userspace `utun`, exact route/DNS transaction, private journal, and per-user status socket. The published v0.1.0 release remains read-only, and the new full-tunnel path remains unvalidated against Nord until a separately approved live test.

The credential foundation uses fixed Keychain account names and keeps secrets out of process arguments. Its automated tests use synthetic values, a fake runner, and local HTTP servers; they do not touch the user's Keychain or Nord's authenticated API. Live synthetic validation found that Apple's `security(1)` stdin write can return success while storing an empty value, so `Store.Put` now fails closed until it is replaced by a native or signed boundary. See [ADR 0002](docs/adr/0002-authentication-contract.md) and the [Keychain validation record](docs/validation/keychain-2026-08-28.md).

An unreleased native Security framework helper has passed create/read/replace/read/delete validation against both an explicit temporary Keychain and one approved synthetic item in the user's login Keychain. The login test used a fixed validation-only service and left no item behind. The source CLI now composes its separate fixed production service, but no production item or real Nord credential has been used. The release pipeline packages the helper beside the CLI with its SHA-256 embedded in that architecture's CLI; the existing v0.1.0 release does not contain it. See the [isolated](docs/validation/native-keychain-2026-08-28.md), [login Keychain](docs/validation/native-login-keychain-2026-08-28.md), and [login-boundary](docs/validation/login-boundary-2026-08-28.md) validation records.

The candidate login transaction has also passed end-to-end simulation against one loopback request and an isolated temporary Keychain. It provisioned a synthetic response, stored and verified the token/key pair, deleted both, and removed the Keychain. Bounded hidden/stdin token parsing, a private single-writer credential lock, status consistency detection, and transactional local removal are implemented and tested. `logout` requires `--local-only` because it does not revoke the token remotely. This does not validate Nord's live undocumented endpoint or authorize a production login test. See the [synthetic login](docs/validation/synthetic-login-2026-08-28.md) and [authentication-command](docs/validation/auth-commands-2026-08-28.md) records.

The tunnel core records intent before every mutation, pins the endpoint before tunnel routes, rejects IPv6 with two owned routes, applies DNS only to the captured physical network service, restores in reverse order, and refuses to overwrite route or DNS state that changed after application. Unreleased controlled harnesses validated userspace WireGuard and one scoped route; full default routing and DNS still require the separately approved Nord live gate. See [ADR 0003](docs/adr/0003-tunnel-transaction-core.md), [ADR 0005](docs/adr/0005-scoped-route-gate.md), the [Gate 3 evidence](docs/validation/scoped-route-2026-08-27.md), and the [offline full-tunnel checkpoint](docs/validation/full-tunnel-implementation-2026-08-28.md).

The current `/v1/servers` endpoints are the replacement family Nord pointed users to after deprecating older endpoints; nevertheless, they remain undocumented and are treated as unstable. See [ADR 0001](docs/adr/0001-public-api.md).

## Homebrew release

Install the latest release from the public tap:

```bash
brew install --cask b1rd33/tap/nordmac
```

The existing v0.1.0 release contains unsigned Apple Silicon and Intel binaries. Future releases use architecture-specific ZIP archives with ad-hoc signatures, the fixed-target Keychain helper, and third-party notices. This costs nothing but is not Apple-notarized, so Gatekeeper may require explicit user approval. See the [v0.1.0 release](https://github.com/b1rd33/nordmac/releases/tag/v0.1.0) or [docs/releasing.md](docs/releasing.md).

## License and affiliation

`nordmac` is independently authored and released under the [MIT License](LICENSE). See [source provenance](docs/source-provenance.md) for the comparison with Nord's GPL Linux client and [third-party notices](THIRD_PARTY_NOTICES.md) for linked WireGuard/Go modules.

This is an unofficial project and is not affiliated with or endorsed by Nord Security. NordVPN and NordLynx are referenced only to describe interoperability targets.
