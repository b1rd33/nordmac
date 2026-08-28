# Synthetic login validation — 2026-08-28

## Scope

This gate simulated the complete candidate login transaction without using Nord credentials or contacting Nord. An unreleased harness used a fixed synthetic hexadecimal token, one loopback-only HTTP server, the bounded candidate provisioning client, the transactional login service, the native Security-framework helper, and one explicit temporary Keychain under `/private/tmp`.

The public `nordmac login` command remained unavailable. The harness accepted no token, endpoint, response body, Keychain path, service name, or account name from the caller. Its only caller inputs were a validation session and an explicit acknowledgement.

## Contract exercised

The loopback server required exactly one `GET /v1/users/services/credentials` request with the expected synthetic bearer token and returned a synthetic account id plus a structurally valid 32-byte base64 NordLynx private key. The client retained its production bounds: loopback was the only permitted plain-HTTP target, redirects were disabled, response size and schema were bounded, and secrets were excluded from output and errors.

The login service provisioned before touching storage, captured any prior token/key pair, wrote both fixed credential kinds, and used a fresh five-second cleanup context to restore both snapshots after a partial write failure. Unit tests cover success, authentication failure with zero writes, rollback of a new partial login, and replacement failure with restoration of the old pair. An incomplete rollback is surfaced distinctly.

## Result

The live synthetic harness completed successfully with nine operations and exactly one loopback request. It stored and compared the synthetic access token and private key, deleted both items, verified both were not found, deleted the temporary Keychain, and removed the helper, harness, module cache, and Go build cache.

No login-Keychain item, Nord credential, Nord endpoint, route, DNS setting, PF rule, tunnel device, release, or Homebrew installation was touched.

## Remaining gate

This result proves composition of the reviewed components, not compatibility with Nord's live undocumented endpoint. Before enabling the public command, add bounded hidden/standard-input token collection, a single-writer credential lock, a fixed production Keychain service in the native helper, status/logout and recovery semantics, and an approval-gated test of the exact production request. A real token must never be supplied in argv or an ordinary environment variable.
