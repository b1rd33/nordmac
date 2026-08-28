# WireGuard dependency freeze

Frozen on 2026-08-27 for the device-only macOS harness. `go.sum` is the machine-verified checksum lock; this document records the review boundary.

## Linked into Darwin harness builds

| Module | Version | Module checksum | `go.mod` checksum | License |
| --- | --- | --- | --- | --- |
| `golang.zx2c4.com/wireguard` | `v0.0.0-20260522210424-ecfc5a8d5446` | `h1:cqHQ3AycTHvM2R7ikgyX57D+XvtcSnGylsLkOVhta/w=` | `h1:rpwXGsirqLqN2L0JDJQlwOboGHmptD5ZD6T2VmcqhTw=` | MIT |
| `golang.org/x/crypto` | `v0.37.0` | `h1:kJNSjF/Xp7kU0iB2Z+9viTPMW4EqqsrywMXLJOOsXSE=` | `h1:vg+k43peMZ0pUMhYmVAWysMK35e6ioLh3wB8ZCAfbVc=` | BSD-3-Clause |
| `golang.org/x/net` | `v0.39.0` | `h1:ZCu7HMWDxpXpaiKdhzIfaltL9Lp31x/3fCP11bc6/fY=` | `h1:X7NRbYVEA+ewNkCNyJ513WmMdQ3BineSwVtN2zD/d+E=` | BSD-3-Clause |
| `golang.org/x/sys` | `v0.32.0` | `h1:s77OFDvIQeibCmezSnk/q6iAfkdiQaJi4VzroCFrN20=` | `h1:BJP2sWEmIv4KK5OTEluFJCKSidICx8ciO85XgH3Ak8k=` | BSD-3-Clause |

The amd64 and arm64 Darwin dependency lists are identical. The WireGuard pseudo-version resolves to upstream VCS URL `https://git.zx2c4.com/wireguard-go` and exact source hash `ecfc5a8d54462e18e13c72173e2623d16d8e25a0`.

## Present only in the upstream module graph

These modules appear in the pinned module graph, but `go list -deps` confirms they are not linked into either Darwin harness binary. Go's pruned `go.sum` may omit graph-only entries, so both observed proxy checksums are recorded here explicitly.

| Module | Version | Module checksum | `go.mod` checksum | License |
| --- | --- | --- | --- | --- |
| `golang.zx2c4.com/wintun` | `v0.0.0-20230126152724-0fa3db229ce2` | `h1:B82qJJgjvYKsXS9jeunTOisW56dUokqW/FOteYJJ/yg=` | `h1:deeaetjYA+DHMHg+sMSMI58GrEteJUUzzw7en6TJQcI=` | MIT |
| `gvisor.dev/gvisor` | `v0.0.0-20250503011706-39ed1f5ac29c` | `h1:m/r7OM+Y2Ty1sgBQ7Qb27VgIMBW8ZZhT4gLnUyDIhzI=` | `h1:3r5CMtNQMKIvBlrmM9xWUNamjKBYPOWyXOjmg5Kts3g=` | Apache-2.0 |
| `github.com/google/btree` | `v1.1.2` | `h1:xf4v41cLI2Z6FxbKm+8Bu+m8ifhj15JuZ9sa0jZCMUU=` | `h1:qOPhT0dTNdNzV6Z/lhRX0YXUafgPLFUh+gZMl761Gm4=` | Apache-2.0 |
| `golang.org/x/term` | `v0.31.0` | `h1:erwDkOK1Msy6offm1mOgvspSkslFnIGsFnxOKoufg3o=` | `h1:R4BeIy7D95HzImkxGkTW1UQTtP54tio2RyHz7PwK0aw=` | BSD-3-Clause |
| `golang.org/x/text` | `v0.24.0` | `h1:dd5Bzh4yt5KYA8f9CJHCP4FB4D51c2c6JvN37xJJkJ0=` | `h1:L8rBsPeo2pSS+xqN0d5u2ikmjtmoJbDBT1b7nHvFCdU=` | BSD-3-Clause |
| `golang.org/x/time` | `v0.7.0` | `h1:ntUhktv3OPE6TgYxXWv9vKvUSJyIFJlyohwbkEwPrKQ=` | `h1:3BpzKBy/shNhVucY/MWOyx10tF3SFh9QdLuxbVysPQM=` | BSD-3-Clause |

## Distribution rule

The current release packaging builds only `cmd/nordmac` plus the independently authored fixed-target Keychain helper; it does not ship the WireGuard harness or link this backend. Before any release begins linking the backend, add the full applicable dependency notices to the release archive and re-run the module, checksum, and license audit. No NordVPN Linux client source is a dependency.
