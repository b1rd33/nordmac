# Scoped-route validation — 2026-08-27

## Approved boundary

The approved Gate 3 test used session `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`, endpoint `87.106.8.110:51820`, host address `10.250.0.2/32`, peer address `10.250.0.1`, and only `10.250.0.0/24`. It permitted one temporary utun, the endpoint host route, the scoped route, administrator execution, cancellation, and crash recovery for at most 30 seconds. Default routes, DNS, PF, Nord credentials, package or image installation, persistent firewall changes, and changes to existing containers remained forbidden.

The VPS fixture was a static Linux amd64 binary backed by wireguard-go's userspace network stack. It assigned only `10.250.0.1` internally and ran in one existing-image Docker container with `--pull never`, `--rm`, `--read-only`, host networking, all capabilities dropped, and `no-new-privileges`. Keys were ephemeral and unrelated to NordVPN.

## Implementation corrections discovered live

Two fail-closed attempts exposed Darwin-specific defects before scoped traffic was possible:

- utun rejected the one-address `ifconfig` form with `SIOCAIFADDR: Destination address required`; the adapter now supplies the private peer destination and a `/32` netmask;
- WireGuard may transmit immediately when brought up, racing endpoint pinning with a cloned route-cache entry; the journaled endpoint `/32` is now installed before device creation and removed after device teardown.

Both attempts rolled back without retaining a utun, route, or journal. The full Go test suite and `go vet` passed after the corrections.

## Results

The corrected transaction reached its verifier. Reaching that point proves that the verifier found both the endpoint `/32` through the captured `192.168.72.129` gateway on `en0` and `10.250.0.0/24` through the owned utun. The peer ping and fresh bidirectional WireGuard handshake then timed out, and normal rollback restored the pre-image.

The failure was isolated to peer reachability: the VPS `/proc/net/snmp` UDP `InDatagrams` counter was unchanged before and after a dedicated four-byte datagram sent only to `87.106.8.110:51820`. No VPS firewall rule was changed. Gate 3 therefore does not yet prove packet exchange through the scoped route.

Cancellation and crash recovery passed:

- SIGTERM during verification produced `context canceled`; rollback used its independent cleanup context, removed both routes, closed the utun, and deleted the journal;
- SIGKILL retained the root-owned journal and endpoint `/32`; closing the process file descriptor caused macOS to remove the utun and its scoped route;
- `--recover-session bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --ack-scoped-route` removed the journal-owned endpoint route, treated the already-absent scoped route idempotently, and deleted the state directory.

## Cleanup evidence

After recovery and fixture teardown:

- the IPv4 default remained `192.168.72.129` on `en0`;
- both `87.106.8.110` and `10.250.0.1` resolved only through that default route;
- `/private/tmp/nordmac-gate3-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb` was absent;
- the named `--rm` container and exact VPS temporary directory were absent;
- nothing listened on VPS UDP 51820;
- no existing container, DNS setting, PF rule, default route, Nord credential, package, or image was changed.

## Remaining evidence for Gate 3

Repeat the same bounded test with UDP ingress to the controlled peer independently confirmed. A passing gate still requires a successful ping to `10.250.0.1`, a fresh handshake timestamp, nonzero transmitted and received byte counters, and the same post-test restoration evidence. No full-tunnel or Nord live test is authorized by this partial result.
