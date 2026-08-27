# Device-only WireGuard validation — 2026-08-27

## Approved boundary

The approved test could start OrbStack, create one ephemeral controlled WireGuard peer, bind it only to a loopback UDP endpoint, create and delete one temporary macOS `utun`, and exchange handshake traffic for at most 30 seconds. It could not use Nord credentials, configure interface addresses, add routes, change DNS or PF, install software, or persist the peer.

## Fixture

- Host: macOS 27 arm64.
- Backend: `golang.zx2c4.com/wireguard` commit `ecfc5a8d54462e18e13c72173e2623d16d8e25a0`, pinned as `v0.0.0-20260522210424-ecfc5a8d5446`.
- Peer: a temporary static Linux arm64 executable compiled from the already-cached pinned modules. It created a WireGuard device with no interface address or route.
- Container: an existing local image used read-only with no persistent volume and `--rm`; no image was downloaded.
- Host endpoint: `127.0.0.1:51888/udp`, confirmed by `lsof` before the test.
- Keys: generated from the OS CSPRNG, stored only in a mode-`0600` temporary directory for the gate, and deleted afterward. They were unrelated to NordVPN.

## Result

The unprivileged attempt failed before device creation with `operation not permitted`, establishing that the raw macOS backend requires the approved privileged boundary on this host.

The administrator-authorized attempt passed:

```json
{"schema_version":1,"ok":true,"interface":"utun11","snapshot":{"last_handshake":"2026-08-27T15:04:14.969412+03:00","transmitted_bytes":180,"received_bytes":92}}
```

This proves creation of the expected userspace device, a fresh bidirectional WireGuard handshake, observable counters, and normal exact-owner teardown. It does not prove packet routing, DNS behavior, leak protection, sleep/wake behavior, or Nord provisioning.

## Cleanup evidence

After the successful result:

- `utun11` was absent from `ifconfig -l`;
- the `--rm` peer container was absent from `docker ps -a`;
- nothing was listening on UDP port `51888`;
- the temporary directory containing both keys, configuration, sources, and binaries was deleted;
- OrbStack was returned to its original `Stopped` state;
- the repository working tree was unchanged by the live fixture.

## Next gate

Gate 3 may configure one synthetic interface address and one scoped peer-subnet route, never a default route. It must capture the host pre-image, verify endpoint reachability stays outside the tunnel, inject cancellation/process death, repeat teardown, and prove exact restoration before any full-tunnel work is considered.
