# ADR 0003: journaled IPv4 transaction core before any `utun` test

- Status: accepted for the Phase 2 offline core
- Date: 2026-08-27

## Context

A WireGuard handshake alone is not a safe macOS VPN lifecycle. The client must pin the peer endpoint outside the tunnel, install and remove routes in a deterministic order, change DNS without overwriting later user or DHCP changes, survive partial failure, and identify exactly which resources it owns.

The official [`wireguard-go` documentation](https://github.com/WireGuard/wireguard-go/blob/master/README.md) confirms macOS `utun` support, but also notes that Darwin lacks Linux-style fwmarks and sticky sockets. The current Darwin [`wg-quick` implementation](https://git.zx2c4.com/wireguard-tools/tree/src/wg-quick/darwin.bash) manages routes, changes DNS across network services, and runs a background route monitor. That behavior conflicts with nordmac's requirement for typed ownership and explicit recovery. Apple's [Packet Tunnel Provider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider) can apply virtual addresses, routes, DNS, and MTU as one system-managed settings object, but requires a signed app extension and entitlement.

## Decision

Build and validate the transaction core before selecting or activating a concrete tunnel backend.

The offline core now has:

- a non-secret, IPv4-only plan that validates session identity, owner UID, endpoint, captured physical gateway/interface, tunnel address, MTU, DNS servers, and peer-key fingerprint;
- a versioned lifecycle journal with `planned`, `applied`, and `rolled_back` entries;
- intent persistence before every device, endpoint-route, split-default-route, and DNS mutation;
- endpoint `/32` pinning through the captured physical gateway/interface before `0.0.0.0/1` and `128.0.0.0/1` routes;
- DNS applied last and restored only through an adapter contract that compares current state with what nordmac applied;
- reverse, idempotent rollback that continues after individual cleanup failures and retains `rollback_required` evidence;
- an exclusive fail-closed file lock and a strict journal store using private modes, bounded JSON, atomic replacement, file and directory syncing, no path-derived input, and no secret fields;
- a versioned helper request with only `connect`, `disconnect`, and `recover`, plus a separate fixed-size binary frame for ephemeral WireGuard keys.

The code contains no Darwin route, DNS, process, `utun`, or WireGuard implementation and is not wired to the CLI. Its tests use fake adapters and temporary directories only.

IPv6 is intentionally rejected in this slice. This is not leak protection and must never be presented as a complete VPN. A future live plan must either prove IPv6 tunneling or separately approve an explicit block policy.

## Local-peer harness plan

Use four gates, each requiring the previous gate to pass:

1. **Dependency freeze:** completed offline in ADR 0004. `wireguard-go` is pinned to source commit `ecfc5a8d54462e18e13c72173e2623d16d8e25a0` through immutable pseudo-version `v0.0.0-20260522210424-ecfc5a8d5446`; the module graph, checksums, and licenses are recorded in `docs/wireguard-dependencies.md`.
2. **Device-only harness:** passed on 2026-08-27. A root-owned `utun11` completed a fresh handshake with an ephemeral controlled peer bound to loopback, then disappeared during exact-owner cleanup. See `docs/validation/device-only-2026-08-27.md`. Signal/process-death fault injection remains a required gate-3 regression check.
3. **Scoped-route harness:** add only a synthetic peer subnet and endpoint pin. Inject failures before and after each real mutation and compare the observed system state with the journal. Do not add default routes yet.
4. **Full transaction harness:** with an out-of-band recovery path, exercise split IPv4 defaults and synthetic DNS, then verify compare-before-restore, signals, helper crash, stale journal recovery, repeated disconnect, and restoration of the exact pre-image.

Docker may host a controlled peer if already available, but it is only test infrastructure inside Docker Desktop's VM; it is not the host-wide macOS tunnel solution.

Before running gate 2, require a new approval naming the controlled peer endpoint, test environment, maximum duration, and cleanup procedure. An acceptable approval is: “Run the reviewed `nordmac-wg-harness` pinned to `wireguard-go` commit `ecfc5a8d54462e18e13c72173e2623d16d8e25a0`. I confirm `<IPv4:port>` is my controlled WireGuard peer. I approve `sudo` if required, creation and deletion of the resulting test `utun` interface, and traffic only to that endpoint for at most `<1–60 seconds>`. Do not install persistent software, use Nord credentials, configure interface addresses, add routes, change DNS or PF, or leave the interface running after the test.”

## Helper boundary requirements

The unprivileged process selects and validates the plan, reads Keychain, and sends an authenticated request to a root-owned helper. The helper must independently verify the caller UID, current physical route, request schema, fixed operation, endpoint, prefixes, interface names, and journal ownership. It accepts no executable path, shell text, hook, environment override, PF rule, or arbitrary file path.

For the transitional PoC, ephemeral raw WireGuard keys use a dedicated inherited pipe with a fixed 68-byte frame and must be wiped after configuration. The request and persistent journal contain only the public-key fingerprint. The sender closes the secret pipe after one frame; trailing or short data fails closed.

## Consequences and next decision

The same controller can be tested against fakes now and either a raw `utun` helper or Network Extension later. `wg-quick` is not part of the architecture.

Decision gate B remains open. Choose the raw helper only if the local-peer harness proves reliable ownership and recovery. Choose a Network Extension if system-managed route/DNS lifecycle materially reduces crash, sleep/wake, or roaming risk enough to justify signing and entitlement complexity.
