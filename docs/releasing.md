# Releasing nordmac

The current signed-release design is macOS-native because every artifact contains both a Go CLI and a Swift Security-framework helper. A tagged release must build, Developer ID-sign, notarize, and verify separate Apple Silicon and Intel ZIP archives. Publication fails closed when any signing or notarization input is missing.

The public v0.1.0 release predates this pipeline: it contains unsigned CLI-only `tar.gz` archives. Do not describe v0.1.0 as signed or notarized.

## Archive contract

Each future `nordmac_<version>_darwin_<architecture>.zip` contains:

- `nordmac`;
- `libexec/nordmac-keychain-helper` for the same architecture;
- `nordmac-helper-manifest.json`;
- `LICENSE` and `README.md`.

The packaging script hashes the already-signed helper and embeds that SHA-256 into the matching CLI at link time. `nordmac version --json` exposes the non-secret digest for installation verification. The future caller also resolves the installed CLI symlink, rejects a group/world-writable helper, and re-hashes the exact `libexec` sibling before use. Development builds have no accepted helper digest.

The packaged helper still exposes only isolated and fixed-service synthetic validation targets. Packaging does not enable `nordmac login`, a production Keychain service, Nord authentication, or tunnel changes.

## Apple prerequisites

Apple requires directly distributed software to use a Developer ID Application certificate, hardened runtime, and secure timestamp before notarization. The repository currently finds no local valid signing identity, so only ad-hoc local snapshots can be produced until the maintainer joins/configures the Apple Developer Program and creates the required credentials.

Configure these GitHub Actions secrets:

- `APPLE_DEVELOPER_ID_P12_BASE64`: base64-encoded Developer ID Application certificate and private key exported as PKCS#12;
- `APPLE_DEVELOPER_ID_P12_PASSWORD`: export password for that PKCS#12 file;
- `APPLE_SIGNING_IDENTITY`: full identity beginning with `Developer ID Application:`;
- `APPLE_API_KEY_P8_BASE64`: base64-encoded App Store Connect API private key;
- `APPLE_API_KEY_ID`: API key identifier;
- `APPLE_API_ISSUER_ID`: App Store Connect issuer identifier.

The release job imports the certificate into an ephemeral runner Keychain, signs both code objects with hardened runtime and timestamping, submits each ZIP using `notarytool --wait`, verifies both extracted signatures with `codesign` and Gatekeeper with `spctl`, publishes only after success, and deletes ephemeral key material in an `always()` step. ZIP files cannot carry stapled tickets; Apple publishes tickets online for the signed binaries contained in the accepted archive.

## Local verification

Run the normal suite, then build an ad-hoc snapshot without contacting Apple:

```bash
make fmt
make vet
make test
make race
make build
make release-check
make snapshot
```

An ad-hoc snapshot tests build shape, architecture, signatures, embedded helper digest, archive contents, and checksums. It is not distributable and must never be published as signed or notarized.

## Publishing

After all six GitHub secrets are configured and the main-branch CI run passes, create a new immutable semantic-version tag. Never reuse or move a published tag. The tag triggers `.github/workflows/release.yml`; the workflow creates the GitHub release only after both archives are accepted by Apple and verified locally on the runner.

Update `Casks/nordmac.rb` in `b1rd33/homebrew-tap` only after checking the published checksums. The new cask URLs must use `.zip`, retain `binary "nordmac"`, and leave `libexec/nordmac-keychain-helper` in the staged archive beside the resolved CLI target. Remove the v0.1.0 quarantine-removal `postflight`; signed and notarized artifacts must not depend on clearing quarantine manually.

Final verification on a clean Mac:

```bash
brew update
brew install --cask b1rd33/tap/nordmac
nordmac --version
nordmac version --json
nordmac recommend de --json
```

Only the last command contacts Nord's public unauthenticated catalog. None of these checks accesses the login Keychain or an authenticated Nord endpoint.
