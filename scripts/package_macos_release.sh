#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: scripts/package_macos_release.sh <version> <output-directory>" >&2
  exit 2
fi

version=$1
output_directory=$2
case "$version" in
  *[!A-Za-z0-9._+-]*|'') echo "invalid release version" >&2; exit 2 ;;
esac
case "$output_directory" in
  /*) ;;
  *) echo "output directory must be absolute" >&2; exit 2 ;;
esac

signing_mode=${NORDMAC_SIGNING_MODE:-adhoc}
signing_identity=${NORDMAC_SIGNING_IDENTITY:--}
case "$signing_mode" in
  adhoc)
    signing_identity=-
    ;;
  developer-id)
    case "$signing_identity" in
      "Developer ID Application:"*) ;;
      *) echo "a Developer ID Application identity is required" >&2; exit 1 ;;
    esac
    ;;
  *) echo "invalid signing mode" >&2; exit 2 ;;
esac

if [ -e "$output_directory" ] && [ -n "$(/bin/ls -A "$output_directory" 2>/dev/null)" ]; then
  echo "output directory must be empty" >&2
  exit 1
fi
/bin/mkdir -p "$output_directory"
work_directory=$(/usr/bin/mktemp -d /private/tmp/nordmac-release.XXXXXXXX)
cleanup() {
  /usr/bin/find "$work_directory" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT INT TERM

commit=$(/usr/bin/git rev-parse --short=12 HEAD)
build_date=$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ)

for architecture in arm64 amd64; do
  case "$architecture" in
    arm64) swift_target=arm64-apple-macos13 ;;
    amd64) swift_target=x86_64-apple-macos13 ;;
  esac
  stage="$work_directory/stage-$architecture"
  module_cache="$work_directory/module-cache-$architecture"
  go_cache="$work_directory/go-cache-$architecture"
  /bin/mkdir -p "$stage/libexec" "$module_cache" "$go_cache"
  helper="$stage/libexec/nordmac-keychain-helper"
  /usr/bin/swiftc -module-cache-path "$module_cache" -target "$swift_target" \
    -O -whole-module-optimization -framework Security \
    -o "$helper" native/keychain-helper/main.swift

  if [ "$signing_mode" = developer-id ]; then
    /usr/bin/codesign --force --options runtime --timestamp \
      --identifier com.github.b1rd33.nordmac.keychain-helper \
      --sign "$signing_identity" "$helper"
  else
    /usr/bin/codesign --force --options runtime \
      --identifier com.github.b1rd33.nordmac.keychain-helper \
      --sign - "$helper"
  fi
  /usr/bin/codesign --verify --strict --verbose=2 "$helper"
  helper_sha256=$(/usr/bin/shasum -a 256 "$helper" | /usr/bin/awk '{print $1}')

  ldflags="-s -w -X github.com/b1rd33/nordmac/internal/buildinfo.Version=$version -X github.com/b1rd33/nordmac/internal/buildinfo.Commit=$commit -X github.com/b1rd33/nordmac/internal/buildinfo.Date=$build_date -X github.com/b1rd33/nordmac/internal/buildinfo.HelperSHA256=$helper_sha256"
  CGO_ENABLED=0 GOOS=darwin GOARCH=$architecture GOCACHE="$go_cache" \
    go build -trimpath -ldflags "$ldflags" -o "$stage/nordmac" ./cmd/nordmac
  if [ "$signing_mode" = developer-id ]; then
    /usr/bin/codesign --force --options runtime --timestamp \
      --identifier com.github.b1rd33.nordmac \
      --sign "$signing_identity" "$stage/nordmac"
  else
    /usr/bin/codesign --force --options runtime \
      --identifier com.github.b1rd33.nordmac \
      --sign - "$stage/nordmac"
  fi
  /usr/bin/codesign --verify --strict --verbose=2 "$stage/nordmac"

  /bin/cp LICENSE README.md "$stage/"
  /usr/bin/printf '{"schema_version":1,"architecture":"%s","helper_sha256":"%s","signing":"%s"}\n' \
    "$architecture" "$helper_sha256" "$signing_mode" > "$stage/nordmac-helper-manifest.json"
  archive_architecture=$architecture
  if [ "$architecture" = amd64 ]; then archive_architecture=x86_64; fi
  archive="$output_directory/nordmac_${version}_darwin_${archive_architecture}.zip"
  /usr/bin/ditto -c -k --norsrc "$stage" "$archive"
done

(
  cd "$output_directory"
  /usr/bin/shasum -a 256 nordmac_*.zip > checksums.txt
)
