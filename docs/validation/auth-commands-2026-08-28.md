# Authentication command wiring validation — 2026-08-28

## Scope

This gate wired the reviewed login components into the CLI without invoking a production command. All command tests used injected synthetic authentication backends. No Nord endpoint or production Keychain target was contacted.

## Command contract

- `nordmac login` reads a lowercase hexadecimal token with terminal echo disabled. `--token-stdin` is the only noninteractive input mode; tokens are rejected in argv and ordinary environment variables. The command wipes its transient input buffer after the backend returns.
- Authentication commands are exposed only when the running CLI locates the exact `libexec/nordmac-keychain-helper` sibling of its resolved executable. The helper must match the SHA-256 embedded in that architecture's CLI, be a regular executable file, share safe ownership with its parent, and neither object may be group- or world-writable.
- Development binaries without an embedded digest and the published v0.1.0 binary reject login before reading stdin or displaying a secret prompt.
- `nordmac status` reports authentication state as `logged_out`, `logged_in`, or `inconsistent`, with non-secret presence booleans. Connection state remains explicitly `unavailable` until tunnel commands are enabled.
- `nordmac logout` refuses to act unless `--local-only` is supplied. The result always reports `remote_token_revoked: false`; nordmac does not pretend that deleting a Keychain item revokes a Nord token.

## Recovery semantics

Login, status, and local logout share one private nonblocking credential lock. Local logout snapshots both fixed credential items, removes present items, and restores the prior pair under a fresh five-second context if a deletion fails. An incomplete rollback is returned as `credential_recovery_required`.

An uncatchable process crash between two Keychain writes can still leave one item. The lock is released automatically when the process exits. The next `status` reports `inconsistent`; a successful replacement login overwrites both fixed items, while `logout --local-only` transactionally clears either a complete or partial pair.

## Evidence

Unit tests cover hidden and stdin input, post-call token wiping, helper-less refusal without consuming stdin, login JSON, complete and partial status, explicit local-only logout, complete and partial removal, rollback after a second-delete failure, lock contention, helper digest mismatch, non-executable helpers, writable helper files, and writable helper directories.

The full Go suite, race detector, and vet passed locally. Native isolated-Keychain validation passed with seven operations. Synthetic login passed with nine operations and exactly one loopback request. Ad-hoc arm64 and Intel release archives built successfully and both code objects passed local signature verification. All test Keychains and temporary artifacts were then removed.

## Safety result

No real token, Nord credential, authenticated request, production Keychain item, route, DNS setting, PF rule, tunnel, release, or Homebrew installation was touched. The next live step requires explicit approval to send one specified token to the exact Nord credential endpoint and store the returned fixed credential pair in the production Keychain service.
