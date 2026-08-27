# Scoped-route validation — 2026-08-27

## Approved boundary

The approved Gate 3 test used session `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`, endpoint `87.106.8.110:51820`, host address `10.250.0.2/32`, peer address `10.250.0.1`, and only `10.250.0.0/24`. It permitted one temporary utun, the endpoint host route, the scoped route, administrator execution, cancellation, and crash recovery for at most 30 seconds. Default routes, DNS, PF, Nord credentials, package or image installation, and changes to existing containers remained forbidden.

Separate approvals permitted one ephemeral VPS nftables rule and one temporary IONOS source-filtered UDP rule for `185.99.26.218/32` to port 51820. Both rules had to be removed after the test; neither changed the VPS's persistent firewall configuration.

The VPS fixture was a static Linux amd64 binary backed by wireguard-go's userspace network stack. It assigned only `10.250.0.1` internally and ran in one existing-image Docker container with `--pull never`, `--rm`, `--read-only`, host networking, all capabilities dropped, and `no-new-privileges`. Keys were ephemeral and unrelated to NordVPN.

## Implementation corrections discovered live

Two fail-closed attempts exposed Darwin-specific defects before scoped traffic was possible:

- utun rejected the one-address `ifconfig` form with `SIOCAIFADDR: Destination address required`; the adapter now supplies the private peer destination and a `/32` netmask;
- WireGuard may transmit immediately when brought up, racing endpoint pinning with a cloned route-cache entry; the journaled endpoint `/32` is now installed before device creation and removed after device teardown.

Both attempts rolled back without retaining a utun, route, or journal. The full Go test suite and `go vet` passed after the corrections.

## Results

Before the successful run, a four-byte UDP probe increased the VPS `InDatagrams` counter from `1018152` to `1018153`, independently confirming that the source-filtered ingress path reached the controlled peer. The Mac default route was `172.20.10.1` on `en0`, the endpoint and synthetic peer both resolved outside any utun, and the public source address still matched the temporary firewall rules.

The corrected transaction created `utun12`, verified the endpoint `/32` through the captured physical gateway and `10.250.0.0/24` through the owned utun, reached `10.250.0.1`, and observed a fresh bidirectional WireGuard handshake:

```json
{"schema_version":1,"ok":true,"interface":"utun12","snapshot":{"last_handshake":"2026-08-27T18:12:23.821546+03:00","transmitted_bytes":308,"received_bytes":220}}
```

Gate 3 therefore passed. It proves interface addressing, endpoint pinning, one scoped synthetic route, controlled peer traffic, handshake observation, and transaction rollback. It does not authorize or validate a default route, DNS changes, IPv6 policy, PF, Nord credentials, or a Nord endpoint.

Cancellation and crash recovery passed:

- SIGTERM during verification produced `context canceled`; rollback used its independent cleanup context, removed both routes, closed the utun, and deleted the journal;
- SIGKILL retained the root-owned journal and endpoint `/32`; closing the process file descriptor caused macOS to remove the utun and its scoped route;
- `--recover-session bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --ack-scoped-route` removed the journal-owned endpoint route, treated the already-absent scoped route idempotently, and deleted the state directory.

## Cleanup evidence

After the successful transaction and fixture teardown:

- the IPv4 default remained `172.20.10.1` on `en0`;
- the endpoint `/32` and `10.250.0.0/24` routes were absent;
- `utun12` and the root-owned journal were absent;
- `/private/tmp/nordmac-gate3-run-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb` was absent;
- the named `--rm` container and exact VPS temporary directory were absent;
- nothing listened on VPS UDP 51820;
- the ephemeral host nftables rule was absent;
- the temporary IONOS UDP rule was absent;
- no existing container, DNS setting, PF rule, default route, Nord credential, package, or image was changed.

## Next gate

Any Nord live-tunnel PoC is a separate gate. It requires an approved disposable credential flow, evidence for the current Nord endpoint/configuration contract, explicit IPv4/IPv6 and DNS behavior, rollback and leak-test criteria, and new approval naming the allowed network mutations. Gate 3 alone does not authorize that test.
