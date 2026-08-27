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

Phase 1's Go dependency graph contains only the standard library and nordmac's own packages. It does not import Nord code, WireGuard code, `wireguard-go`, or `wireguard-tools`.

This comparison is evidence of independent authorship, not a legal opinion. Future phases must repeat provenance and license review before adding any tunnel implementation or third-party dependency.

## Names and affiliation

NordVPN and NordLynx are names associated with Nord Security. This project is unofficial, is not endorsed by or affiliated with Nord Security, and makes no claim to those marks. References are descriptive of interoperability targets.

