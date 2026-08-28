# Native login Keychain validation — 2026-08-28

## Authorization and scope

The user approved the packaged native helper to create, read, replace, and delete one random synthetic generic-password item under the fixed service `com.github.b1rd33.nordmac.validation.native` in the current user's login Keychain, verify deletion, and leave no item behind. Nord credentials and authenticated requests were forbidden.

The validation account was fixed to `access-token`; neither the service, account, Keychain path, nor secret was accepted from the command line. The first write used create-only semantics and the harness first proved the item absent, so an existing matching item could not be overwritten or deleted.

## Packaged boundary

The Swift helper and Go harness were built into a mode-0700 directory owned by the current user under `/private/tmp`. Both executables were mode 0500. The harness required the helper's canonical fixed filename, validated the package directory name, owner and modes, rejected symlinks/non-regular files, and verified the helper against its expected SHA-256 before execution. The helper was ad-hoc signed for this local validation; this does not replace Developer ID signing or notarization for a release.

The helper's login-validation mode derives the current unprivileged user's fixed `~/Library/Keychains/login.keychain-db`, verifies the home-directory owner, opens that Keychain explicitly, adds through `kSecUseKeychain`, and constrains search/update/delete through `kSecMatchSearchList`. Production service names and arbitrary targets remain unavailable.

## Result

The lifecycle completed successfully with eight checks: absent preflight, create, read/compare, replace, read/compare, delete, native not-found verification, and an independent `security find-generic-password` not-found verification. A second independent lookup after the harness also returned item-not-found (status 44).

The temporary package, build caches, and validation item were deleted. No Nord token or NordLynx private key was read or written, no authenticated API request was made, and `nordmac login` remains disabled.

## Remaining release gate

This validates the fixed login-Keychain API boundary, but does not yet ship it. Before enabling login, package Developer ID-signed and notarized architecture-specific helpers in release assets, authenticate the installed helper identity and digest from the Go caller, define upgrade ownership, and separately authorize any real Nord token storage and authenticated credential-provisioning request.
