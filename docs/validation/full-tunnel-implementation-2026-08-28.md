# Full-tunnel implementation checkpoint — 2026-08-28

## Scope

This checkpoint completed the unreleased production command path without
performing a production login or live full-tunnel test. It added:

- ordinary-user `connect`, `disconnect`, `reconnect --fresh`, and connection-aware `status` commands;
- a length-prefixed, bounded helper protocol with a fixed 68-byte key frame;
- a sudo-launched long-lived root helper with kernel peer-UID authentication;
- root-private journals and a root-owned per-user Unix socket;
- endpoint pinning, IPv4 split defaults, and owned IPv6 reject routes;
- fixed-network-service DNS server snapshot, apply, ownership comparison, and rollback while preserving search domains;
- local connection metadata, shared credential/connection locking, stale-helper recovery, signal cleanup, and repeated ownership monitoring;
- ad-hoc zero-fee arm64/x86_64 release archives with the native Keychain helper and third-party notices.

## Offline verification

The complete Go suite and race-enabled suite passed on macOS. `go vet ./...`,
format checks, shell syntax checks, YAML parsing, secret-pattern scanning, and
Darwin arm64 plus Linux amd64 builds passed. The release script produced both
macOS architectures, both checksums verified, both code objects passed strict
ad-hoc signature validation, and both archives contained
`THIRD_PARTY_NOTICES.md`.

The 241 unique non-comment implementation lines of at least 60 characters in
the new connection/helper/DNS files had zero exact matches against either
retained Nord Linux checkout used for provenance review.

## Explicitly not validated

No real Nord token or private key was read or created. No authenticated Nord
request, production Keychain item, `utun`, default route, IPv6 route, DNS
setting, PF rule, tag, GitHub release, Homebrew update, or persistent service
was created by this checkpoint.

The code must remain described as experimental until one separately approved
bounded live gate proves Nord authentication, handshake, IPv4 egress, DNS,
IPv6 rejection, graceful rollback, forced-helper crash recovery, and exact
host-state restoration.
