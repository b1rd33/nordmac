# ADR 0004: embed a pinned WireGuard userspace device

- Status: wired into the unreleased helper; Nord live validation pending
- Date: 2026-08-27

## Decision

Use the official MIT-licensed `wireguard-go` packages directly for the first macOS device backend. Pin source commit `ecfc5a8d54462e18e13c72173e2623d16d8e25a0` as Go pseudo-version `v0.0.0-20260522210424-ecfc5a8d5446` and retain module checksums in `go.sum`.

Do not shell out to `wg-quick`. Its Darwin implementation owns routes, DNS, and a background route monitor, which would bypass nordmac's transaction journal and compare-before-restore rules. A standalone `wireguard-go` process would also complicate exact process/interface ownership and secret transport without removing the need for a privileged nordmac helper.

The backend is wired into the unreleased CLI through the privileged daemon and journaled controller. The separate `nordmac-wg-harness` remains excluded from release packaging as regression evidence for the device-only gate. The production path is not considered validated until the separately approved full Nord test succeeds and rolls back cleanly.

## Secret and ownership boundary

The caller transfers a fixed binary key frame into a one-shot in-memory source. Construction wipes the caller's copy; consumption is single-use and wipes the source copy on every return path. Before device creation, the backend hashes the supplied peer key and compares it with the non-secret approved plan fingerprint.

The UAPI configuration is assembled in a mutable byte slice and wiped immediately after `IpcSetOperation` returns. The upstream parser necessarily creates short-lived internal Go strings while parsing the key line; Go cannot guarantee physical memory erasure. Therefore the process must remain short-lived and must never dump core or log UAPI input. Long-term credentials stay outside this package.

The manager records the exact session, actual `utun` name, process ID, and live runtime. Cleanup refuses a mismatched handle and is idempotent. The macOS `utun` file descriptor is owned by the process, so process death closes it; the live gate must still prove this behavior empirically.

## Consequences

The backend supplies device creation and handshake mechanics; the tunnel controller now supplies interface addressing, endpoint pinning, IPv4 split defaults, IPv6 rejection, DNS ownership, status, and stale-journal recovery. Sleep/wake, roaming, full DNS/default-route behavior, and real Nord interoperability remain live validation gates.

The first live device-only validation passed on 2026-08-27. The evidence and cleanup record are in `docs/validation/device-only-2026-08-27.md`.
