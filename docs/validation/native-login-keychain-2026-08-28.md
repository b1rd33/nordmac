# Native login Keychain validation — 2026-08-28

## Authorization and scope

The user approved the packaged native helper to create, read, replace, and delete one random synthetic generic-password item under the fixed service `com.github.b1rd33.nordmac.validation.native` in the current user's login Keychain, verify deletion, and leave no item behind. Nord credentials and authenticated requests were forbidden.

The validation account was fixed to `access-token`; neither the service, account, Keychain path, nor secret was accepted from the command line. The first write used create-only semantics and the harness first proved the item absent, so an existing matching item could not be overwritten or deleted.

## Packaged boundary

The Swift helper and Go harness were built into a mode-0700 directory owned by the current user under `/private/tmp`. Both executables were mode 0500. The harness required the helper's canonical fixed filename, validated the package directory name, owner and modes, rejected symlinks/non-regular files, and verified the helper against its expected SHA-256 before execution. The helper was ad-hoc signed for this local validation; this does not replace Developer ID signing or notarization for a release.

At the time of this gate, the helper's login-validation mode derived the current unprivileged user's fixed `~/Library/Keychains/login.keychain-db`, verified the home-directory owner, opened that Keychain explicitly, added through `kSecUseKeychain`, and constrained search/update/delete through `kSecMatchSearchList`. Production service names and arbitrary targets were unavailable. A later gate added one compile-time production service without invoking it; arbitrary services and targets remain unavailable.

## Result

The lifecycle completed successfully with eight checks: absent preflight, create, read/compare, replace, read/compare, delete, native not-found verification, and an independent `security find-generic-password` not-found verification. A second independent lookup after the harness also returned item-not-found (status 44).

The temporary package, build caches, and validation item were deleted. No Nord token or NordLynx private key was read or written, and no authenticated API request was made. At the conclusion of this gate, `nordmac login` remained disabled; later command wiring is recorded separately in [auth-commands-2026-08-28.md](auth-commands-2026-08-28.md).

## Remaining release gate

This validates the fixed login-Keychain API boundary, but does not enable production use. The release pipeline now builds architecture-specific helpers, requires Developer ID signing/notarization for tagged publication, and embeds the signed helper digest in the matching CLI. No signing identity is currently configured and no such release has been published. Before enabling login, complete a real signed release, verify the Homebrew installation relationship, define upgrade ownership, and separately authorize any real Nord token storage and authenticated credential-provisioning request.
