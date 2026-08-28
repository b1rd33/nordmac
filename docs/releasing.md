# Releasing nordmac

The zero-fee release design builds ad-hoc-signed Apple Silicon and Intel ZIP archives containing the Go CLI and Swift Security-framework helper. It does not require Apple Developer Program membership. These artifacts are not notarized, so macOS may require the user to approve or remove quarantine for the downloaded binary.

The public v0.1.0 release predates this pipeline: it contains unsigned CLI-only `tar.gz` archives. Do not describe v0.1.0 as signed or notarized.

## Archive contract

Each future `nordmac_<version>_darwin_<architecture>.zip` contains:

- `nordmac`;
- `libexec/nordmac-keychain-helper` for the same architecture;
- `nordmac-helper-manifest.json`;
- `LICENSE`, `README.md`, and `THIRD_PARTY_NOTICES.md`.

The packaging script hashes the already-signed helper and embeds that SHA-256 into the matching CLI at link time. `nordmac version --json` exposes the non-secret digest for installation verification. The caller resolves the installed CLI symlink and accepts only the exact `libexec` sibling when its SHA-256 matches, it and its parent have safe type/mode/ownership, neither is group- or world-writable, and the helper is executable. Development builds have no accepted helper digest.

The packaged helper exposes isolated validation, fixed-service login-Keychain validation, and a distinct fixed production service. The production target accepts only the two compiled credential account names and cannot accept an arbitrary service, account, or Keychain path. A correctly packaged CLI can reach the authentication command code, but packaging alone does not invoke it, authenticate with Nord, access Keychain, or change a tunnel.

## Optional future notarization

Developer ID signing and Apple notarization can be added later to eliminate Gatekeeper friction. They are not required by the current GitHub/Homebrew release workflow and no paid Apple membership is assumed.

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

An ad-hoc snapshot tests build shape, architecture, signatures, embedded helper digest, archive contents, notices, and checksums. It may be distributed, but must never be described as Developer ID-signed or notarized.

## Publishing

After the main-branch CI run passes and the separately approved live validation is complete, create a new immutable semantic-version tag. Never reuse or move a published tag. The tag triggers `.github/workflows/release.yml`, verifies both ad-hoc archives, and creates the GitHub release.

Update `Casks/nordmac.rb` in `b1rd33/homebrew-tap` only after checking the published checksums. The new cask URLs must use `.zip`, retain `binary "nordmac"`, leave `libexec/nordmac-keychain-helper` beside the resolved CLI target, and clearly retain the existing quarantine workaround because the artifacts are not notarized.

Final verification on a clean Mac:

```bash
brew update
brew install --cask b1rd33/tap/nordmac
nordmac --version
nordmac version --json
nordmac recommend de --json
```

Only the last command contacts Nord's public unauthenticated catalog. None of these checks accesses the login Keychain or an authenticated Nord endpoint.
