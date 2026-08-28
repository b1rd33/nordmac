# ADR 0002: bounded Nord authentication behind explicit login

- Status: implemented in unreleased builds; production validation pending
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

On 2026-08-28, an isolated synthetic experiment created an explicit temporary Keychain successfully, without selecting or modifying the login Keychain. Apple’s `security add-generic-password` command then rejected the only argument order that keeps the password on prompted stdin while naming that Keychain. The temporary Keychain and directory were deleted. The experiment used no Nord token and made no authenticated request.

This invalidates the proposed `security(1)` write path as a production boundary: its secret-safe behavior cannot be integration-tested in isolation without temporarily changing the user's default-Keychain preference. Do not do that. Before enabling login, replace the write path with a narrowly scoped native Security framework implementation or a signed helper that accepts secret bytes over an authenticated channel and can target an explicit validation Keychain. The current adapter remains unreachable from the CLI.

A separately approved login-Keychain validation then tested the proposed stdin write with one random synthetic item under the validation-only service `com.github.b1rd33.nordmac.validation`. The write process returned success, but the immediate read returned an empty value. Deferred cleanup and an independent lookup proved the item was deleted. Replacement was not attempted after the failed read. The concrete Go adapter now returns `ErrWriteUnavailable` before any write command; see [the validation record](../validation/keychain-2026-08-28.md).

The replacement native boundary passed its isolated gate on 2026-08-28. A Swift Security framework helper and Go adapter completed create/read/replace/read/delete/not-found against an explicitly owned temporary Keychain, with secret bytes confined to stdin/stdout. The helper has no production target and is not packaged or reachable from `nordmac login`; see [the native validation record](../validation/native-keychain-2026-08-28.md).

A separately approved native login-Keychain gate then passed with one random synthetic item under the fixed validation-only service `com.github.b1rd33.nordmac.validation.native`. The packaged harness refused pre-existing items, authenticated the helper by owner, mode, path and SHA-256, completed create/read/replace/read/delete, and independently confirmed item-not-found afterward. Temporary artifacts were removed. This enables evidence for the boundary only: real Nord services, credentials, requests, release packaging, and `nordmac login` remain disabled; see [the login Keychain validation record](../validation/native-login-keychain-2026-08-28.md).

The next implementation step added a separate compile-time production service, bounded hidden/stdin token readers, and a private nonblocking file lock around the full credential transaction. The public command remains unavailable, the production target has not been invoked, and no Nord credential or authenticated request was used. See [the login-boundary validation record](../validation/login-boundary-2026-08-28.md).

Read-only review on 2026-08-28 pinned the current official Linux client at `d49b7d14715a80e320bae55944727612cac98c9f`. It still defines `GET /v1/users/services/credentials` with bearer authorization, a `nordlynx_private_key` response field, `10.5.0.2`, UDP 51820, IPv4 allowed IP `0.0.0.0/0`, and DNS resolvers `103.86.96.100` and `103.86.99.100`. These remain undocumented interoperability observations, not a supported third-party API.

The composed login path passed a synthetic end-to-end gate on 2026-08-28. An unreleased harness made exactly one request to a loopback server, decoded a bounded synthetic response, transactionally stored the synthetic access token and NordLynx private key in an explicit temporary Keychain, verified both, deleted both, and removed the Keychain. Unit tests cover partial-write rollback and replacement restoration. The public command remains disconnected; see [the synthetic login validation record](../validation/synthetic-login-2026-08-28.md).

The command layer was subsequently wired behind authenticated packaged-helper discovery. Helper-less builds reject authentication commands before reading stdin or prompting. Packaged builds accept hidden input or explicit `--token-stdin`, serialize the complete transaction, report complete/absent/inconsistent local credential state, and require `logout --local-only` before deleting the local pair. Local logout does not claim to revoke a Nord token. A crash between Keychain mutations can leave an inconsistent pair; `status` detects it, and either a successful replacement login or transactional local logout repairs it. No production command was invoked during this implementation; see [the authentication-command validation record](../validation/auth-commands-2026-08-28.md).

The current unreleased packaged CLI now exposes that guarded login composition and uses the stored private key only in memory when building a connect request. This changes code reachability, not validation evidence: no real token has been submitted, no production Keychain item has been created, and the authenticated endpoint remains undocumented. Invoking `login` is therefore an explicit user-authorized production action, not an automatic setup step or release test.
