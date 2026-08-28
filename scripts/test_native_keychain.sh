#!/bin/sh
set -eu

module_cache=/private/tmp/nordmac-native-keychain-module-cache
go_cache=/private/tmp/nordmac-native-keychain-go-cache
helper=/private/tmp/nordmac-keychain-native-helper
harness=/private/tmp/nordmac-native-keychain-harness
session=77777777777777777777777777777777
state=/private/tmp/nordmac-keychain-native-validation-$session

cleanup() {
  find "$module_cache" -depth -delete 2>/dev/null || true
  find "$go_cache" -depth -delete 2>/dev/null || true
  find "$helper" -delete 2>/dev/null || true
  find "$harness" -delete 2>/dev/null || true
}
trap cleanup EXIT INT TERM

mkdir -p "$module_cache" "$go_cache"
swiftc -module-cache-path "$module_cache" -O -whole-module-optimization -framework Security \
  -o "$helper" native/keychain-helper/main.swift
GOCACHE="$go_cache" go build -trimpath -o "$harness" ./cmd/nordmac-native-keychain-harness
"$harness" --session "$session" --ack-native-keychain
test ! -e "$state"
