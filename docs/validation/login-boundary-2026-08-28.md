# Login input and transaction-boundary validation — 2026-08-28

## Scope

This gate prepared the remaining local pieces of the login boundary without enabling `nordmac login`. It added bounded token readers, a single-writer credential lock, and a fixed production service in the native Keychain helper. No production Keychain operation or Nord request was performed.

## Evidence

- Hidden input requires a terminal, uses `term.ReadPassword`, and refuses a redirected descriptor with guidance to use `--token-stdin`. Tests inject a no-echo reader; no live terminal secret was collected.
- Standard-input mode accepts one lowercase hexadecimal token with at most one trailing LF or CRLF, caps input at 4096 bytes, and rejects empty, uppercase, whitespace-containing, multiline, and oversized input. Rejected byte buffers are wiped.
- The credential transaction acquires a nonblocking file lock before provisioning. The lock directory must be absolute, canonical, owned by the current uid, and inaccessible to group/other users; the lock file is opened with `O_NOFOLLOW` and mode `0600`. Contention fails closed before any request or Keychain operation.
- The native helper now recognizes `--login-keychain` as a distinct production target using only service `com.github.b1rd33.nordmac` and the compiled accounts `access-token` and `nordlynx-private-key`. The caller cannot choose an arbitrary service, account, or Keychain path.
- The synthetic login harness was rerun with the real file lock. It made exactly one bounded loopback request, verified a synthetic token/key pair in an isolated temporary Keychain, deleted both items, and removed its temporary resources.

## Safety result

The public command dispatcher still reports `login` as unavailable. The production Keychain target was reviewed and unit-tested for exact helper arguments but was not invoked. No real token, Nord credential, authenticated Nord request, production Keychain item, route, DNS setting, PF rule, or tunnel was touched.

## Remaining gate

Packaged-helper authentication, command input wiring, and local status/logout recovery were subsequently implemented and are recorded in the [authentication-command validation](auth-commands-2026-08-28.md). The remaining gate is separate approval for the exact live Nord credential-provisioning request and production Keychain write. A real token must never be passed in argv or an ordinary environment variable.
