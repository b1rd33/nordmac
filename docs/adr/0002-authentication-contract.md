# ADR 0002: keep Nord authentication disabled pending contract validation

- Status: accepted for the Phase 2 foundation
- Date: 2026-08-27

## Context

Nord officially documents access tokens generated in Nord Account for headless login to its Linux application. The documentation says temporary tokens expire after 30 days, non-expiring tokens are available, tokens are displayed once, and ordinary logout revokes the token. It does not document a third-party API for exchanging that token for NordLynx configuration.

Read-only review of NordSecurity's GPL-3.0 Linux client at commit [`b20a74cd61f030dc160a251755bdfe30a2a2f2c4`](https://github.com/NordSecurity/nordvpn-linux/tree/b20a74cd61f030dc160a251755bdfe30a2a2f2c4) shows that its token-login path sends a bearer token to an internal service-credentials endpoint and expects an account identifier, OpenVPN credentials, and a NordLynx private key. This is technical evidence about Nord's current client, not a supported interoperability contract. No upstream implementation or test fixture is copied into nordmac.

The candidate request observed in that client is `GET https://api.nordvpn.com/v1/users/services/credentials` with an access token in the `Authorization: Bearer` header and no request body. The candidate nordmac client caps the response at 64 KiB, refuses redirects, requires HTTPS, uses a ten-second maximum timeout, rejects unknown response fields, and returns only the account identifier and a validated 32-byte base64 NordLynx private key. It is not reachable from a CLI command and is tested only with synthetic local HTTP servers.

The public server catalog supplies a server public key, but a working tunnel additionally needs at least a client private key, assigned tunnel address, endpoint IP and port, DNS policy, allowed IPs, MTU, subscription authorization, and understood expiry/revocation behavior. The reviewed source alone does not establish all of those as a stable macOS contract.

Sources:

- [NordVPN: token login without a GUI on Linux](https://support.nordvpn.com/hc/en-us/articles/20286980309265-How-to-use-a-token-with-NordVPN-and-log-in-without-a-GUI-on-Linux)
- [NordSecurity/nordvpn-linux at the reviewed commit](https://github.com/NordSecurity/nordvpn-linux/tree/b20a74cd61f030dc160a251755bdfe30a2a2f2c4)
- the `security(1)` manual included with the inspected macOS host.

## Decision

Do not enable real `nordmac login` or call Nord's authenticated endpoints in this milestone.

Add a narrow credential-store abstraction and a macOS Keychain adapter with fixed account names. The adapter invokes `/usr/bin/security` without putting secrets in process arguments; writes provide the prompted password on stdin. Add a quarantined candidate provisioning client with the bounds above, but do not connect it to `command.Service`. Automated tests use only synthetic values, fake command runners, and local HTTP servers, so they never touch the user's Keychain or Nord's authenticated API.

Before enabling login, require all of the following:

1. explicit approval to use one named temporary Nord token;
2. a reviewed, bounded request manifest for the exact host, path, HTTP method, headers, response size, and accepted fields;
3. confirmation of token validation, expiry, and revocation semantics without assuming Linux-client behavior applies to nordmac;
4. a decision on whether storing both the access token and returned private key is necessary, including replacement and deletion semantics;
5. tests proving secrets cannot appear in argv, environment, JSON, errors, logs, caches, fixtures, or crash diagnostics.

## Consequences

The credential boundary can be reviewed and tested now without authenticating or making network changes. `nordmac login` remains unavailable in the shipped CLI. This postpones convenience, but avoids presenting an undocumented internal endpoint as a supported public API.

The `/usr/bin/security` adapter has not yet been exercised against any Keychain. Before activation, verify its prompted-stdin behavior using an isolated temporary Keychain and synthetic data on the supported macOS versions; do not use the login Keychain for that validation.
