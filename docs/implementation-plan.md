# nordmac implementation plan

Status: Phase 1 implemented and verified
Date: 2026-08-27  
Scope: open-source, personal macOS tool

## 1. Outcome and non-goals

`nordmac` should be a real CLI that discovers NordVPN locations, makes deterministic server recommendations, and—only if a separately approved proof of concept validates the necessary contract—creates and manages a NordLynx/WireGuard tunnel on macOS.

Non-goals:

- no GUI automation or control of NordVPN.app;
- no `scutil`-only wrapper (it cannot discover or select Nord servers);
- no Docker-based host VPN design;
- no copying or adapting Nord's GPL-3.0 Linux client code;
- no App Store/commercial packaging requirement;
- no kill switch in the first tunnel milestone;
- no claim that an undocumented Nord API is stable or supported.

Nord's Linux repository is reference material for observable concepts and behavior only. Original implementation, tests, names, and control flow must be independently authored. Maintain a short provenance note for any behavior learned from it.

## 2. Read-only baseline observed on this Mac

- Apple Silicon (`arm64`), macOS 27.0 build 26A5421a.
- Go 1.27.0, Git 2.55.0, Xcode 27 beta 5 toolchain, `jq`, `curl`, and Homebrew are present.
- `wg`, `wg-quick`, and `wireguard-go` are not installed.
- `/bin/bash` is 3.2.57. Current Darwin `wg-quick` requires Bash 4+.
- NordVPN.app 10.9.1 (build 373) is installed.
- During inspection, NordVPN's own `SingleTunnelExtension` was active: default route `utun8`, MTU 1420, DNS `100.64.0.2`. Tailscale's network extension is also enabled. These are coexistence hazards, not configuration to reuse.
- The public endpoint `/v1/servers/countries` returned 149 countries and Germany id 81 with Berlin, Frankfurt, and Hamburg.
- The public recommendation endpoint accepted a Germany plus `wireguard_udp` filter and returned online servers with hostname, load, location, and WireGuard `public_key` metadata. This proves Phase 1 discovery is feasible; it does not prove a client private key, tunnel address, DNS contract, endpoint port, or successful handshake.

No software was installed, no credentials were accessed or created, and no network state was changed during inspection.

## 3. Architecture

Use a Go module with a thin command layer and explicit ports around every unstable or privileged boundary.

```text
user CLI
  -> command/application services
      -> Nord catalog client (public HTTPS, read-only)
      -> recommender (pure deterministic logic)
      -> credential store interface (macOS Keychain implementation later)
      -> tunnel controller interface
          -> privileged helper / local IPC
              -> userspace WireGuard device on utun
              -> transactional route manager
              -> transactional DNS manager
              -> later PF policy manager
```

Security boundary: parsing arguments, fetching catalogs, recommendation, and JSON rendering run unprivileged. Only interface creation, route/DNS changes, and future PF rules cross into a minimal privileged helper. The helper accepts a narrow, versioned request, validates every IP/prefix/interface/hostname, never runs a shell, uses absolute executable paths if a subprocess is temporarily required, and refuses arbitrary hooks or commands.

The literal `sudo nordmac connect ...` target is acceptable for the first controlled PoC, but it conflicts with clean access to a user's login Keychain. Before production connection work, choose one:

1. Preferred: user-facing `nordmac connect` reads the user's Keychain, then calls a signed/root-owned helper over authenticated local IPC and passes only an ephemeral tunnel configuration.
2. Transitional PoC: a root-only helper consumes an already prepared, short-lived configuration over an inherited pipe; never command-line arguments, environment variables, or a world-readable file.
3. Rejected as a steady state: have a process running under `sudo` scrape another user's login Keychain or store reusable secrets in plaintext under `/var`.

Longer term, a Network Extension packet-tunnel system extension gives macOS-native route/DNS lifecycle and crash cleanup, but it requires a signed containing app, Network Extension entitlement, provisioning, and Swift/Xcode glue even if the product UX remains CLI-only. Treat that as a decision after the userspace PoC, not a Phase 1 dependency.

## 4. Proposed package layout

```text
cmd/nordmac/                 CLI entry point
internal/command/            command handlers and exit-code mapping
internal/catalog/            domain models and repository interfaces
internal/nordapi/            public catalog HTTP client and strict DTO decoding
internal/recommend/          country/city/server resolution and ranking
internal/output/             stable text and JSON envelopes
internal/config/             non-secret user preferences
internal/credentials/        secret-store interface; no network policy
internal/keychain/           macOS Keychain adapter (later)
internal/tunnel/             lifecycle interface and state machine
internal/helperproto/        versioned privileged IPC messages
internal/wgbackend/          userspace WireGuard adapter (later)
internal/darwinroute/        route snapshot/apply/restore (later)
internal/darwindns/          DNS snapshot/apply/restore (later)
internal/pf/                 optional kill switch, separate phase
internal/state/              validated non-secret runtime journal
testdata/                    redacted API fixtures and failure cases
docs/adr/                    decision records and API evidence
```

Keep Nord DTOs out of domain packages. The API client converts untrusted/optional fields into validated domain values so schema drift fails closed with a clear diagnostic.

## 5. Command contract

All commands support `--json` where useful. JSON goes to stdout; diagnostics go to stderr. JSON uses a versioned envelope such as `{"schema_version":1,"ok":true,"data":...}`. Secret values, authorization headers, private keys, and full raw API bodies never appear in either stream or logs. Stable exit classes: `0` success, `2` usage, `3` auth, `4` discovery/no match, `5` network/API, `6` privilege, `7` tunnel transition/rollback, `8` conflict.

- `login`: later accepts a token from a hidden prompt or stdin/FD, validates it with the minimum safe request, saves it to Keychain, zeroes transient buffers where practical, and never accepts a token as a positional flag. Exact Nord endpoint/semantics are gated on evidence.
- `countries`: fetches or reads a bounded cache of country/city catalog data; output includes normalized ISO code and city slugs. Cache is non-secret, atomic, and records fetch time/schema version.
- `recommend <country>`: validates an ISO code or unambiguous country name, optionally filters `--city` or exact `--server`, requests `wireguard_udp`, rejects offline/malformed entries, preserves Nord's returned recommendation order, and applies only documented local tie-breakers. `--server de1234` is exact and must still be online, in scope, and WireGuard-capable.
- `connect`: refuses if another default-route VPN is active unless an explicit future coexistence policy allows it; resolves and pins the endpoint before installing default-tunnel routes; executes a journaled transaction; reports connected only after a recent handshake and controlled reachability/DNS checks.
- `status`: combines owned state journal, live interface/device statistics, route ownership, DNS ownership, handshake age, and endpoint. It must distinguish `disconnected`, `connecting`, `connected`, `degraded`, `disconnecting`, `rollback_required`, and `foreign_conflict`.
- `disconnect`: removes only resources whose identity and pre-image are recorded as owned by this session, restores DNS/routes, stops the device, and preserves a failure journal if rollback is incomplete. Idempotent when already disconnected.
- `reconnect`: uses the current selection policy; `--fresh` discards the selected server and refetches recommendations but never discards rollback evidence.

## 6. State model and transactional lifecycle

Persistent non-secret state belongs under the user's Application Support directory. Privileged runtime/journal data belongs in a root-owned directory with mode 0700 and files 0600. Secrets remain in Keychain; state stores only opaque Keychain references/fingerprints.

Session state records: schema version, random session id, owner UID, PID/helper identity, selected server id/hostname/IP/public-key fingerprint, resolved endpoint and physical interface/gateway, allocated `utun`, intended routes, route/DNS pre-images, applied steps, timestamps, and last handshake counters. Atomic write plus `fsync` before each mutation that needs recovery.

Connection transaction:

1. acquire an exclusive lock and detect foreign VPN/default-route conflicts;
2. capture physical IPv4/IPv6 routes and DNS state;
3. resolve endpoint A/AAAA records before DNS/default-route changes;
4. create/configure the WireGuard `utun` without a default route;
5. add endpoint host route(s) pinned to the physical gateway/interface;
6. add split default routes (`0/1`, `128/1`; IPv6 only if supported and validated);
7. apply tunnel DNS with a captured pre-image;
8. require handshake plus bounded probes; otherwise reverse every applied step;
9. mark connected only after verification.

Rollback runs in strict reverse order and is idempotent. On startup and before connect, detect stale journals and offer/perform only evidence-backed cleanup. Never restore a stale DNS snapshot over user changes made after connection; compare current values to the values nordmac applied first.

## 7. Dependencies and WireGuard decision

Phase 1 should use the Go standard library plus a small CLI parser only if it materially improves command help. Prefer `net/http`, `encoding/json`, `net/netip`, and injected clock/resolver/client interfaces. Pin modules and review licenses/checksums.

Do not make `wg-quick` the product architecture:

- it is an orchestration shell script, so using it would outsource precisely the route/DNS ownership and rollback behavior nordmac must control;
- its Darwin script mutates DNS across network services and monitors routes in a background process, which complicates precise ownership and coexistence;
- it requires Bash 4+, absent on this Mac, and `wg`/`wireguard-go` are absent;
- wireguard-tools is GPL-2.0, while `wireguard-go` is MIT-licensed. Shelling out to a separately installed GPL tool is legally different from copying it, but it adds an unnecessary runtime/install dependency.

Recommended tunnel sequence:

- For the first live PoC, build a narrowly pinned, separately reviewed `wireguard-go` userspace backend (or a tiny original adapter using its MIT-licensed Go packages) and let nordmac own route/DNS transactions. A temporary `wg` subprocess may be acceptable only if separately approved and used through a typed config pipe, never a generated shell command.
- After the PoC, embed the WireGuard Go device/control primitives directly so the CLI/helper has one typed lifecycle and no `wg-quick` dependency.
- Evaluate a signed Network Extension system extension if crash recovery, sleep/wake, network roaming, and coexistence prove unreliable with a root helper plus raw `utun`.

This is a decision gate, not permission to download or install anything.

## 8. Required evidence before attempting `connect de`

Discovery evidence already demonstrated:

- current country/city schema, country id mapping, recommendation filters, online status, hostname/load/location, and `wireguard_udp` public-key metadata;
- recorded HTTP status, content type, cache behavior/ETag if any, timeouts, rate-limit behavior, malformed/empty response behavior, and redacted fixtures;
- DNS resolution yields usable endpoint IPs and selection is stable enough to pin for one transaction.

Still required, using a disposable/short-lived credential and read-only or provider-sanctioned requests first:

1. An official or directly observed authentication contract: token format/transport, endpoint, scopes, expiry, revocation, MFA implications, and whether validation itself rotates/revokes anything.
2. A reproducible, authorized way to obtain or register the NordLynx client private/public key pair without copying Nord GPL code; determine whether the private key is account-issued, device-bound, generated locally, or rotated by the service.
3. Confirm the complete peer contract: endpoint UDP port, server public key per selected server/cluster, client tunnel IPv4 address/prefix, supported IPv6 behavior/address, allowed IPs, keepalive, MTU, and DNS servers.
4. Confirm whether the same advertised public key across multiple recommended hostnames is expected (the inspected German sample did this) and what identity should be pinned.
5. Prove that the selected account/subscription permits manual NordLynx use and that this use does not conflict with Nord's current terms or simultaneous-device rules.
6. Produce a fully redacted configuration manifest and validate all key lengths/base64, IPs, prefixes, port, and hostname/IP bindings offline.
7. Define success: WireGuard handshake timestamp advances, RX/TX counters move, egress IP is the selected Nord location, DNS uses the intended resolver without leaks, endpoint route remains on the physical interface, and rollback restores the exact pre-test state.

If any of items 1-5 cannot be established, stop at the recommendation CLI. A public server key plus an account token is not enough evidence to attempt a tunnel.

## 9. Network and security risks

- **Endpoint routing loop:** install endpoint `/32` or `/128` route through the captured physical gateway before default routes; monitor physical route changes and fail closed/rollback if it cannot be safely repinned.
- **DNS rollback/leak:** snapshot per-service and scoped resolver state, apply transactionally, verify with both system resolver state and queries, compare-before-restore, and test DHCP/Wi-Fi changes. Avoid assuming `/etc/resolv.conf` is authoritative on macOS.
- **IPv6 leak:** until Nord IPv6 tunnel support is proven, either leave IPv6 untouched and clearly label the tunnel non-leak-safe, or explicitly block non-tunnel IPv6 as a separately approved safety policy. Never silently route IPv4 only while claiming full protection.
- **Partial route failure:** journal before mutation, use split defaults so the physical default remains discoverable, validate route ownership, and make every removal exact/idempotent.
- **Existing VPNs:** the observed NordVPN and Tailscale interfaces mean route/DNS assumptions can be false. Default behavior is refuse on active foreign default-route VPN; define explicit Tailscale coexistence tests later.
- **Sleep/wake and network roaming:** endpoint gateway and DNS can change. Initially mark degraded and disconnect/rollback; do not attempt clever automatic repair until tested.
- **Privilege injection:** privileged code accepts no shell fragments, hooks, arbitrary file paths, or environment-controlled executables; clear/sanitize environment and use peer credential checks on IPC.
- **Credentials:** Keychain entries use a dedicated service/account and restrictive access control; tokens and private keys never enter argv, environment, JSON, logs, state files, crash reports, or test fixtures. Redact public-key fingerprints consistently even though public keys are not secret.
- **Undocumented API drift:** strict validation, short timeouts, bounded responses, no blind retries on auth/provisioning calls, fixture contract tests, and a server-side feature kill switch/config version if needed.
- **Kill switch:** PF comes only after base lifecycle reliability. Use a private anchor, preserve existing PF state, scope rules to owned interfaces/endpoints, and prove recovery after process crash/reboot before enabling by default.

## 10. Testing plan

### Phase 1 tests

- unit tests for ISO/name normalization, ambiguous inputs, city/server constraints, stable ordering/tie-breaking, invalid public keys, offline servers, duplicate servers, and empty results;
- HTTP contract tests with `httptest.Server`: timeouts, non-2xx, oversized body, invalid JSON, missing/null/unknown fields, schema drift, retry/backoff, caching, and deterministic JSON output;
- golden fixtures captured from public endpoints and aggressively minimized/redacted;
- race detector, fuzz tests for API decoding and selectors, `go vet`, static analysis, dependency/license review, and secret-scanning fixtures;
- no root, Keychain, or network mutations in the default test suite.

### Tunnel tests (later, approval-gated)

- pure planner tests with fake route/DNS/device adapters and failure injected after every transaction step;
- integration tests against an isolated test peer not Nord, proving utun, handshake, routing, DNS, rollback, signals, crash recovery, and repeated idempotent disconnect;
- macOS VM or sacrificial test account/device matrix: Wi-Fi/USB, IPv4-only/dual-stack, sleep/wake, gateway/DHCP change, DNS changes during tunnel, active Tailscale, active NordVPN refusal, endpoint DNS rotation, helper crash, and reboot;
- live Nord test only after all offline/local-peer tests pass, with an out-of-band recovery path and captured before/after route/DNS/PF snapshots.

## 11. Phases and decision points

### Phase 1 — read-only catalog and recommendation

Implement `countries` and `recommend`, typed public API client, deterministic selection, stable JSON, cache, fixtures, tests, documentation, and provenance notes. No login command behavior beyond a clear `not implemented`; no sudo/root code.

Decision gate A: Is the public API sufficiently reliable and its use acceptable for this personal tool? If not, keep cached/manual catalogs or stop.

Result on 2026-08-27: accepted for bounded, read-only personal use. The client has strict validation, timeouts, bounded responses, a non-secret country cache, and explicit failure behavior. This does not imply acceptance of any authentication or tunnel endpoint.

### Phase 2 — credential-contract research and local-peer tunnel harness

Design Keychain records and secret input, but use only disposable test material. Independently bring up the backend against a controlled WireGuard peer, implement the privileged boundary and full transaction/rollback with no Nord credentials.

Possible deliverables:

- an ADR documenting the observed Nord authentication/provisioning contract, confidence level, expiry/revocation behavior, and unresolved assumptions;
- a Keychain storage prototype using synthetic secrets only, including hidden input, lookup, replacement, deletion, and redaction tests;
- a versioned CLI-to-helper protocol with peer identity checks, strict request validation, timeouts, and no general-purpose command execution;
- a userspace WireGuard backend connected only to a controlled test peer;
- route and DNS planners with fake adapters, failure injection after every mutation, and deterministic rollback tests;
- a macOS integration harness that exercises `utun` creation and cleanup against the controlled peer under a separately approved test plan;
- an ADR comparing a raw `utun` helper with a signed Network Extension on security, lifecycle, development cost, sleep/wake, roaming, and recovery.

Phase 2 remains Nord-network-free: no Nord credential use and no Nord tunnel attempt. It is complete only when the controlled peer can connect, verify, disconnect, and restore the recorded route/DNS pre-image repeatedly, including injected failure cases.

Progress on 2026-08-27: [ADR 0002](adr/0002-authentication-contract.md) records that Nord officially supports account-generated tokens for its own headless Linux client, while the credential exchange used by that client remains an undocumented internal contract for nordmac. A narrow macOS Keychain adapter, secret-store interface, and quarantined candidate provisioning client were added with synthetic runner and local-server tests. Real `login`, authenticated Nord requests, and live Keychain access remain disabled pending the ADR's approval gate.

[ADR 0003](adr/0003-tunnel-transaction-core.md) adds the next offline slice: a validated IPv4-only plan, journaled transaction controller, strict atomic journal store, exclusive file lock, narrow helper protocol, separate ephemeral key frame, and failure injection around every planned mutation and persistence boundary. It contains no WireGuard dependency or platform mutation adapter and remains unreachable from CLI commands.

Decision gate B: root helper/raw `utun` versus signed Network Extension, based on crash, roaming, DNS, and coexistence evidence.

### Phase 3 — minimal Nord live tunnel PoC

Only after the evidence checklist and explicit approval: one server, one short-lived session, IPv4 policy stated in advance, no kill switch, no auto-reconnect. Verify handshake/egress/DNS and immediately disconnect/restore.

Possible deliverables:

- a frozen, reviewed manifest containing the one server hostname/IP, UDP port, server public-key fingerprint, client address, allowed IPs, MTU, DNS, dependency versions, and exact mutations;
- before/after snapshots of physical routes, scoped DNS, active VPN interfaces, and nordmac-owned state;
- a single bounded `connect` experiment with a maximum duration and an out-of-band recovery procedure;
- evidence of a fresh WireGuard handshake, RX/TX movement, selected-country egress, intended DNS behavior, physical endpoint-route pinning, and clean rollback;
- a redacted test report recording failures and API/schema observations without tokens, private keys, or reusable raw configurations.

Do not add retries, failover, daemonization, auto-start, a kill switch, or persistent installation in this phase. A successful single handshake validates feasibility; it does not yet establish production reliability.

Decision gate C: if the API/credential contract is unstable, unsupported, or cannot be safely obtained, do not productize connect.

### Phase 4 — production lifecycle for personal use

Add `login`, generalized selectors, `status`, `disconnect`, `reconnect --fresh`, stale-state recovery, sleep/wake behavior, packaging/signing/helper installation, diagnostics/redaction, and coexistence policy.

Possible deliverables:

- safe `login`, credential replacement, credential status, and logout/revocation semantics backed by Keychain;
- all target commands with stable human and versioned JSON output;
- city and exact-server selection, server revalidation immediately before connection, and clear offline/no-match behavior;
- an explicit lifecycle state machine with exclusive locking, idempotent disconnect, stale-journal recovery, signal handling, and bounded retries;
- tested handling for sleep/wake, Wi-Fi or gateway changes, DNS changes, endpoint address rotation, helper/CLI crash, and reboot;
- a documented default refusal policy for active foreign default-route VPNs, plus tested Tailscale coexistence only if it can be made predictable;
- signed or checksum-verifiable local packaging, a narrowly scoped helper installation/removal flow, and an uninstall/recovery command;
- redacted diagnostics that report ownership and health without exposing credentials or browsing/network history.

Phase 4 is complete when the full lifecycle passes repeated local integration tests and a small number of explicitly approved Nord sessions without manual route/DNS repair. Keep it experimental and manually invoked at this stage.

Decision gate D: is the selected helper/Network Extension architecture reliable enough for unattended personal use? If not, keep nordmac interactive and fail closed.

### Phase 5 — optional hardening

PF kill switch, IPv6 support or explicit block, endpoint failover, health monitoring, structured audit log, and Network Extension migration if selected.

Possible deliverables:

- a private PF anchor with exact ownership, atomic apply/remove, preservation of pre-existing PF state, and boot/crash recovery tests;
- a proven IPv6 tunnel configuration, or a clearly surfaced and separately approved IPv6 block policy;
- constrained endpoint failover that repins routes before changing peers and has retry/time budgets;
- continuous handshake, route, and DNS health checks that transition to `degraded` and disconnect or fail closed according to policy;
- structured, locally retained audit events with explicit retention and aggressive secret/privacy redaction;
- migration to a signed Network Extension if raw `utun` lifecycle evidence remains inadequate;
- a recovery utility and written manual recovery procedure that work even when the main CLI cannot start.

Every hardening feature is independently opt-in until its rollback and crash behavior is proven. In particular, PF is never enabled merely because a tunnel can connect.

Decision gate E: enable each hardening feature by default only after failure-injection and reboot testing show that it cannot strand the Mac offline.

### Phase 6 — agent and workflow integration

Expose the stable CLI safely to local agents and scripts only after Phase 4, with mutating capabilities disabled by default.

Possible deliverables:

- machine-readable command schemas and a documented JSON compatibility policy;
- `--dry-run` plans showing the selected server and intended privileged mutations without credentials or changes;
- non-interactive read-only `countries`, `recommend`, and `status` workflows with bounded timeouts;
- an explicit policy file restricting agents to allowed countries, cities, servers, command classes, and maximum session duration;
- human confirmation or a short-lived authorization grant for `connect`, `disconnect`, credential operations, and policy changes;
- stable error categories, correlation IDs, cancellation support, and redacted audit events for agent debugging;
- concurrency tests so two agents cannot race connection, rollback, or credential state.

Do not expose arbitrary helper IPC, raw WireGuard configuration, Keychain contents, PF controls, or shell hooks as agent tools. Agents invoke the same validated application layer as a human CLI.

Decision gate F: permit unattended connection only if an explicit user policy defines destinations, duration, conflict behavior, and recovery; otherwise agents may recommend and report status but not mutate the network.

## 12. Concise Phase 1 task list

1. Create the Go module and command skeleton for `countries` and `recommend` only.
2. Capture minimized public API fixtures and write a provenance/API-contract note.
3. Implement a bounded, timeout-aware public catalog client with strict DTO conversion and cache metadata.
4. Implement country/city/exact-server resolution and preserve the API's recommendation order.
5. Define schema-versioned JSON and human output plus stable exit codes.
6. Add unit, contract, fuzz, golden-output, race, static, license, and secret-scan checks.
7. Document that `login`, `connect`, `disconnect`, and `reconnect` are unavailable and perform no mutation.
8. Review Phase 1 evidence and make decision gate A.

## Exact approval required before any live tunnel test

Require a new, explicit instruction naming all of the following: permission to use a specified disposable/short-lived Nord token or test account; permission to access/store the resulting credential and private key in the macOS Keychain; permission to download/build the specifically pinned WireGuard dependency if it is not already vendored; permission to run the reviewed privileged helper with `sudo`; permission to create a `utun`, add/remove the enumerated IPv4/IPv6 routes, change/restore the enumerated DNS settings, and send test traffic to one named Nord endpoint; acknowledgement that the existing NordVPN/Tailscale tunnel must first be disconnected or an approved coexistence procedure must be followed; and acceptance of the prewritten rollback/recovery procedure and test window.

An acceptable approval would be: “Run the reviewed one-server Nord live-tunnel test plan in ADR-NNN using disposable credential `<Keychain reference>`, pinned dependency versions `<versions>`, endpoint `<hostname:port>`, and the recorded route/DNS mutations. I approve Keychain access, `sudo`, utun creation, those exact route/DNS changes, validation traffic, and immediate rollback. Do not alter PF or install persistent services.”

Anything less remains approval for research or Phase 1 only, not for a live tunnel.

## References

- Nord public country catalog: https://api.nordvpn.com/v1/servers/countries
- Nord public recommendations: https://api.nordvpn.com/v1/servers/recommendations
- Nord's statement on current public server endpoints: https://github.com/NordSecurity/nordvpn-linux/issues/294
- Nord Linux client (GPL-3.0; reference only): https://github.com/NordSecurity/nordvpn-linux
- WireGuard userspace implementation and macOS utun notes (MIT): https://github.com/WireGuard/wireguard-go
- Darwin `wg-quick` behavior (GPL-2.0): https://git.zx2c4.com/wireguard-tools/tree/src/wg-quick/darwin.bash
- Apple Packet Tunnel Provider: https://developer.apple.com/documentation/networkextension/packet-tunnel-provider
- Apple Network Extension entitlement: https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension
- Apple Network Extension deployment: https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment
