#!/bin/sh
set -eu

module_cache=/private/tmp/nordmac-synthetic-login-module-cache
go_cache=/private/tmp/nordmac-synthetic-login-go-cache
helper=/private/tmp/nordmac-synthetic-login-helper
harness=/private/tmp/nordmac-synthetic-login-harness
session=88888888888888888888888888888888
state=/private/tmp/nordmac-keychain-native-validation-$session

cleanup() {
  /usr/bin/find "$module_cache" -depth -delete 2>/dev/null || true
  /usr/bin/find "$go_cache" -depth -delete 2>/dev/null || true
  /usr/bin/find "$helper" -delete 2>/dev/null || true
  /usr/bin/find "$harness" -delete 2>/dev/null || true
}
trap cleanup EXIT INT TERM

/bin/mkdir -p "$module_cache" "$go_cache"
/usr/bin/swiftc -module-cache-path "$module_cache" -O -whole-module-optimization -framework Security \
  -o "$helper" native/keychain-helper/main.swift
GOCACHE="$go_cache" go build -trimpath -o "$harness" ./cmd/nordmac-synthetic-login-harness
"$harness" --session "$session" --ack-synthetic-login
test ! -e "$state"
