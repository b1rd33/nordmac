# Releasing nordmac

`nordmac` follows the same release shape as the existing `b1rd33` Go CLIs:

- semantic tag such as `v0.1.0`;
- GoReleaser v2 builds unsigned, static macOS binaries for Apple Silicon and Intel;
- release archives are named `nordmac_<version>_darwin_<arch>.tar.gz`;
- GitHub Release contains both archives and `checksums.txt`;
- the maintainer updates `Casks/nordmac.rb` in `b1rd33/homebrew-tap` from the verified release assets and per-architecture SHA-256 values;
- the cask installs the precompiled `nordmac` binary and applies the documented quarantine-removal hook required for an unsigned personal CLI;
- release verification runs `nordmac --version` without making an API request.

## One-time GitHub setup

1. Create `b1rd33/nordmac` and add it as `origin`.
2. Create it as a public repository so Homebrew can download release assets without authentication.
3. For automated future tap publication, add `HOMEBREW_TAP_TOKEN` using a fine-grained token with `Contents: write` only for `b1rd33/homebrew-tap`. The initial release updates the tap locally and does not delegate a broad OAuth token to Actions.
4. Keep the MIT license and source-provenance record in every release archive.
5. Push `main` and confirm the CI workflow passes.

## Local checks

```bash
make fmt
make vet
make test
make race
make build
make release-check
goreleaser release --snapshot --clean
```

Verify both snapshot archives, checksums, embedded versions, and the generated Homebrew formula before tagging.

## Publishing v0.1.0

```bash
git tag -a v0.1.0 -m "nordmac v0.1.0"
git push origin main
git push origin v0.1.0
```

The tag push triggers `.github/workflows/release.yml`. Do not create or push the tag until the public repository and snapshot checks are resolved. A failed tag workflow must be repaired without moving or reusing a published tag.

Use a signed tag when a signing key is configured and its public key is published. The initial `v0.1.0` tag is annotated because this development environment had no configured signing key; do not claim it is cryptographically signed.

After the release workflow and tap commit succeed:

```bash
brew update
brew install --cask b1rd33/tap/nordmac
nordmac --version
nordmac recommend de --json
```

The final command is a live, read-only public API check. The formula's own test uses only `--version` and remains offline.
