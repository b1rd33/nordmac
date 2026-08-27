# ADR 0001: bounded use of Nord's public server API

Status: accepted for Phase 1 only  
Date observed: 2026-08-27

## Decision

Phase 1 may use the unauthenticated endpoints below through the isolated `internal/nordapi` adapter:

- `GET https://api.nordvpn.com/v1/servers/countries`
- `GET https://api.nordvpn.com/v1/servers/recommendations`
- `GET https://api.nordvpn.com/v1/servers` only for bounded, country-filtered exact-server lookup

This does not authorize use of authentication, user, credential, key-provisioning, or connection endpoints.

## Why this is not the deprecated endpoint family

In NordSecurity's public Linux-client issue tracker, a Nord contributor directed users away from older legacy endpoints and toward `/v1/servers/recommendations` and `/v1/servers` as the replacements. The `v1` component is a version label; it is not evidence that the endpoint is legacy.

These replacements are still not a documented public contract. The client therefore assumes drift is possible, validates required fields, bounds response sizes and result limits, uses timeouts, and keeps DTOs out of domain packages. Failure is explicit rather than silently fabricating a recommendation.

Reference: https://github.com/NordSecurity/nordvpn-linux/issues/294

## Observed contract

The country endpoint returned country id, name, two-letter code, and city id/name/`dns_name`. On the observation date it returned 149 countries; Germany was id 81, with Berlin, Frankfurt, and Hamburg.

The recommendation endpoint accepted:

```text
filters[country_id]=81
filters[city_id]=2181458
filters[servers_technologies][identifier]=wireguard_udp
limit=5
```

It returned an ordered array with server id/name/hostname/load/status, nested country/city location, and `wireguard_udp` metadata containing a base64 WireGuard `public_key`. The implementation preserves this order and locally rejects offline entries, country/city mismatches, duplicate hostnames, and keys that do not decode to 32 bytes.

The full `/servers` endpoint accepted the country and technology filters. Trial query keys named `hostname`, `id`, and `search` were silently ignored and returned unrelated initial results. Exact-server selection must therefore request at most 1,000 entries from a country-filtered WireGuard set and match the normalized hostname locally. If a country ever exceeds that bound and the target is absent, the command returns no match rather than issuing an unbounded request.

The country endpoint's observed response was `application/json` with `Cache-Control: public, max-age=30` and integrity-related `X-Digest`/`X-Signature` headers. The recommendation endpoint rejected `HEAD` with HTTP 405, so availability checks must use bounded `GET` requests. Phase 1 does not yet verify Nord's nonstandard signature headers because no public verification contract or key has been established.

## Cache policy

Countries and cities are cached locally for 24 hours because they are relatively stable and non-secret. Recommendations are never cached. The cache records a schema version and fetch time, is written atomically with mode 0600 beneath a mode-0700 directory, and may be used stale only with an explicit warning if the public country request fails.

The 24-hour local TTL is an application availability choice, not derived from the HTTP `max-age=30` freshness directive. `--refresh` bypasses a fresh local cache.

## Reconsideration triggers

Stop or revise Phase 1 if Nord withdraws the endpoints, documents a different supported source, materially changes the schema/filter behavior, adds terms that disallow this personal use, or if routine requests prove unreliable. No behavior observed here is evidence for the separate NordLynx authentication or tunnel contract.

## Phase 1 verification

The implementation was verified with unit and integration-style tests using an in-memory HTTP transport, so the default test suite opens no network sockets. Coverage includes country/city resolution, ambiguous and missing locations, offline/malformed/duplicate servers, exact-server selection, HTTP status/content-type/JSON failures, query bounds, cache freshness and permissions, stale fallback, CLI parsing, stable JSON golden output, and unavailable-command behavior.

`go test ./...`, `go test -race ./...`, `go vet ./...`, selector fuzzing, API decoder fuzzing, and a trimmed production build passed on the observed macOS environment. A separately authorized read-only smoke test returned 149 countries, resolved Germany and Berlin, recommended an online Berlin server, reused the local country cache, and matched that exact server through the bounded full-server path. It did not authenticate, access credentials, create a tunnel, or change routes/DNS/PF.
