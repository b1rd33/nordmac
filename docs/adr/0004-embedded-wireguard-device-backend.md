# ADR 0004: embed a pinned WireGuard userspace device behind an unwired adapter

- Status: accepted for the device-only validation gate
- Date: 2026-08-27

## Decision

Use the official MIT-licensed `wireguard-go` packages directly for the first macOS device backend. Pin source commit `ecfc5a8d54462e18e13c72173e2623d16d8e25a0` as Go pseudo-version `v0.0.0-20260522210424-ecfc5a8d5446` and retain module checksums in `go.sum`.

Do not shell out to `wg-quick`. Its Darwin implementation owns routes, DNS, and a background route monitor, which would bypass nordmac's transaction journal and compare-before-restore rules. A standalone `wireguard-go` process would also complicate exact process/interface ownership and secret transport without removing the need for a privileged nordmac helper.

The backend is deliberately unwired from the public CLI. The separate `nordmac-wg-harness` executable is also excluded from GoReleaser. Its only permitted live action is creating one userspace `utun`, configuring one literal IPv4 controlled-peer endpoint, waiting at most 60 seconds for a fresh bidirectional handshake, and closing the device. It cannot configure an interface address, route, DNS, PF, Nord credential, persistence, or arbitrary hook.

## Secret and ownership boundary

The caller transfers a fixed binary key frame into a one-shot in-memory source. Construction wipes the caller's copy; consumption is single-use and wipes the source copy on every return path. Before device creation, the backend hashes the supplied peer key and compares it with the non-secret approved plan fingerprint.

The UAPI configuration is assembled in a mutable byte slice and wiped immediately after `IpcSetOperation` returns. The upstream parser necessarily creates short-lived internal Go strings while parsing the key line; Go cannot guarantee physical memory erasure. Therefore the process must remain short-lived and must never dump core or log UAPI input. Long-term credentials stay outside this package.

The manager records the exact session, actual `utun` name, process ID, and live runtime. Cleanup refuses a mismatched handle and is idempotent. The macOS `utun` file descriptor is owned by the process, so process death closes it; the live gate must still prove this behavior empirically.

## Consequences

This validates only WireGuard device creation and handshake mechanics. It is not a VPN, offers no leak protection, and must not be exposed as `nordmac connect`. Gate 3 remains responsible for interface addressing and one scoped synthetic route. Full IPv4 routes, DNS, IPv6 policy, sleep/wake, roaming, and stale-journal recovery remain later gates.
