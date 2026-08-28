# Native Keychain validation — 2026-08-28

## Boundary

At the time of this isolated gate, the replacement boundary consisted of a Swift helper using macOS Security framework item APIs and a Go adapter that exchanged raw secret bytes only through stdin/stdout. The helper accepted fixed credential kinds and the validation-only service `com.github.b1rd33.nordmac.validation`. Its only enabled target was an explicitly named Keychain under `/private/tmp/nordmac-keychain-native-validation-<session>/validation.keychain-db`, in a mode-0700 directory owned by the caller. The later fixed-service login-Keychain gate is recorded separately in [native-login-keychain-2026-08-28.md](native-login-keychain-2026-08-28.md).

The helper uses `kSecUseKeychain` to add to the explicit Keychain and `kSecMatchSearchList` to constrain reads, updates, and deletion to that same Keychain. It never accepts a service name, account name, arbitrary path, secret argument, environment secret, or logging option.

## Result

The isolated macOS 27 run passed seven checks using two independently generated random synthetic values:

1. create the first value;
2. read and compare it;
3. replace it with the second value;
4. read and compare the replacement;
5. delete the item;
6. confirm the item is not found;
7. delete the temporary Keychain and confirm its directory is absent.

The Go unit tests independently verify that the secret is provided to the helper on stdin and never appears in argv. The full Go test, race, and vet suites remain required. A dedicated macOS CI job rebuilds the Swift helper and repeats the isolated lifecycle on every change.

## Remaining gate

This validates the native secret transport and explicit-Keychain lifecycle, not production login. Before enabling `nordmac login`, add and review a fixed login-Keychain target, package and checksum the helper for Apple Silicon and Intel, authenticate the helper path/identity from the Go caller, and obtain separate approval for one synthetic login-Keychain validation. No Nord credential or authenticated API request is authorized by this result.
