# Source provenance

`nordmac` is an independently authored implementation distributed under the MIT License. It is not a fork, port, translation, or derivative copy of NordSecurity's GPL-3.0 Linux client.

## Inputs used for Phase 1

Phase 1 was built from:

- observed responses from Nord's unauthenticated public country and server endpoints;
- factual endpoint guidance posted by a Nord contributor in the public `NordSecurity/nordvpn-linux` issue tracker;
- public WireGuard and Apple platform documentation used only for future architectural planning;
- independently designed Go packages, command behavior, validation, caching, JSON output, and tests.

No authentication, private-key provisioning, Linux daemon, firewall, routing, DNS, tunnel, or NordLynx implementation was copied or adapted. Phase 1 does not contain those features.

## Pre-publication comparison

On 2026-08-27, the nordmac Go source was compared with a shallow checkout of:

```text
Repository: https://github.com/NordSecurity/nordvpn-linux
Commit:     01a73607bd831541175a636e9c20ccbb944acc85
License:    GPL-3.0
```

The comparison checked 229 unique, non-comment nordmac source lines of at least 60 characters against all Go files in that checkout. It found zero exact matches. Distinctive nordmac identifiers—including `CountriesResult`, `RecommendationResult`, `ResolveCountry`, `ResolveCity`, `validWireGuardKey`, `normalizeServer`, `SourceStaleCache`, `recommendationLimit`, `exactServerLimit`, `JSONSuccess`, and `JSONError`—also had zero matches.

At the time of the Phase 1 comparison, its Go dependency graph contained only the standard library and nordmac's own packages. Later approval-gated harness work added the MIT-licensed `wireguard-go` dependency; no Nord source or GPL WireGuard tools were added.

## Phase 2 authentication-boundary audit

On 2026-08-27, the independently written files under `internal/credentials`, `internal/keychain`, and `internal/nordauth` were compared with all Go files in NordSecurity/nordvpn-linux at commit `b20a74cd61f030dc160a251755bdfe30a2a2f2c4`. The comparison checked 101 unique, non-comment nordmac lines of at least 60 characters and found zero exact matches. Distinctive new identifiers—including `Provisioning`, `decodeProvisioning`, `wipeRawFields`, and `credential-contract-probe`—also had zero upstream matches.

The candidate endpoint path, bearer-token transport, and response field names are interoperability facts observed during read-only review, not copied implementation. Phase 2 still imports only the Go standard library and nordmac's own packages.

## Phase 2 transaction-core audit

On 2026-08-27, the independently written files under `internal/tunnel`, `internal/state`, and `internal/helperproto` were compared with both NordSecurity/nordvpn-linux at commit `b20a74cd61f030dc160a251755bdfe30a2a2f2c4` and WireGuard/wireguard-go at commit `ecfc5a8d54462e18e13c72173e2623d16d8e25a0`. The comparison checked 386 unique, non-comment nordmac lines of at least 60 characters and found zero exact matches against either codebase. Distinctive identifiers—including `JournalSchemaVersion`, `RestoreIfOwned`, `SecretChannelVersion`, `DecodeRequest`, and `PeerFingerprint`—also had zero matches.

The transaction order, route prefixes, WireGuard key sizes, and `utun` constraints are interoperability and operating-system facts. No Nord or WireGuard implementation was copied. `wireguard-go` remains a reviewed future MIT-licensed dependency candidate; it has not been added to nordmac's module graph.

This comparison is evidence of independent authorship, not a legal opinion. Future phases must repeat provenance and license review before adding any tunnel implementation or third-party dependency.

## 2026-08-28 current-contract review

The official Linux client was reviewed read-only at commit `d49b7d14715a80e320bae55944727612cac98c9f` to confirm factual interoperability parameters for `nordmac plan`: the credential endpoint path and bearer transport, response field name, tunnel address, WireGuard port and allowed IP, and default DNS addresses. `internal/connectplan` was independently written from those facts and contains no copied Nord control flow, implementation, or test data. The generated manifest identifies the pinned reference and remains explicitly blocked from live use.

## Native Keychain boundary

The Swift helper under `native/keychain-helper` was independently written from Apple Security framework documentation for generic-password items, `SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, `SecItemDelete`, `kSecUseKeychain`, and `kSecMatchSearchList`. It contains no Nord or third-party implementation. The helper is validation-only, is not present in release archives, and has no enabled login-Keychain target.

## Names and affiliation

NordVPN and NordLynx are names associated with Nord Security. This project is unofficial, is not endorsed by or affiliated with Nord Security, and makes no claim to those marks. References are descriptive of interoperability targets.
