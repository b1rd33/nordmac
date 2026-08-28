# ADR 0005: require a scoped-route gate before any default route

- Status: accepted; Gate 3 passed live
- Date: 2026-08-27

## Decision

Journal schema 2 records an explicit route policy. `scoped_ipv4` accepts only one to four canonical private IPv4 prefixes between `/16` and `/32`, rejects DNS, rejects public and default routes, and rejects a prefix containing the physical gateway or WireGuard endpoint. `full_ipv4` preserves the future split-default and DNS transaction but remains unreachable from the public CLI.

Schema 1 journals fail closed instead of being guessed or migrated. No live nordmac tunnel existed when schema 2 was introduced, so there is no legitimate schema 1 recovery state to preserve.

The transaction applies resources in this order:

1. pin the WireGuard endpoint through the captured physical gateway and interface;
2. create the owned userspace `utun`, configure WireGuard, bring it up, and assign its owned point-to-point IPv4 `/32`;
3. add only the approved scoped route through the `utun`;
4. verify both exact routes, ping the controlled peer, and require a fresh handshake with bidirectional counters.

Rollback uses the reverse order. Cancellation during verification gets a new bounded cleanup context rather than reusing the cancelled request context. A route is removed only when an exact lookup still matches the journaled interface and, for the endpoint pin, gateway. Missing routes are treated idempotently; changed routes retain `rollback_required` evidence.

## Darwin boundary

The adapters invoke fixed absolute binaries with validated argument arrays and no shell:

- `/sbin/ifconfig <utun> inet <private-address> <private-peer> netmask 255.255.255.255 alias`
- `/sbin/route -n add|delete ...`
- `/sbin/ping -n -c 1 -W 1000 <private-peer>`

The route adapter parses numeric `route get` output, rejects non-contiguous masks, refuses a pre-existing exact destination, and compares current ownership before deletion. The endpoint host route is intentionally unscoped through the captured gateway: `wireguard-go` uses an unbound UDP socket on Darwin, so an interface-scoped route might not be selected. It is installed before WireGuard starts because bringing up the device can emit a handshake immediately and race endpoint pinning with a cloned Darwin route-cache entry. The adapter verifies that macOS resolves the installed host route through the captured physical interface before continuing. macOS routes have no nordmac ownership tag, so a foreign actor replacing a route with byte-for-byte identical fields cannot be distinguished; the short gate window and journal lock reduce but cannot eliminate that platform limitation.

## Harness and crash recovery

`cmd/nordmac-scoped-harness` is excluded from the release pipeline. It requires an explicit acknowledgement, session id, literal non-loopback endpoint, tunnel `/32`, private peer address, one containing private scoped prefix, and a duration of at most 30 seconds. It reads keys only through the fixed binary secret frame.

State is stored at the fixed, validated path `/private/tmp/nordmac-gate3-<session>`. Normal cleanup removes it only after the journal is gone. `--recover-session <session>` needs no keys and replays journaled route cleanup after a crash; incomplete cleanup retains the journal instead of deleting evidence.

## Live gate result

The approved 2026-08-27 run against a temporary userspace peer on `87.106.8.110:51820` proved point-to-point utun addressing, exact endpoint and scoped-route ownership checks, scoped peer traffic, a fresh bidirectional handshake, normal rollback, cancellation rollback, and explicit recovery after SIGKILL. The successful snapshot recorded 308 transmitted bytes, 220 received bytes, and a fresh handshake on `utun12`. Post-test checks found no retained interface, route, journal, peer container, key fixture, host nftables rule, or provider firewall rule. Gate 3 passed. See `docs/validation/scoped-route-2026-08-27.md`.

Any future repetition still requires approval naming:

- the controlled non-loopback peer endpoint;
- `10.250.0.2/32` as the temporary host tunnel address;
- `10.250.0.1` as the temporary peer address;
- `10.250.0.0/24` as the only temporary route;
- one session id, a maximum 30-second window, administrator authorization, and permission for deliberate signal/process-death cleanup tests.

The approval must continue to forbid default routes, DNS, PF, Nord credentials, persistent software, and any traffic outside the controlled endpoint and synthetic subnet.
