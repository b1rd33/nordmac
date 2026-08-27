# nordmac

Private, macOS-first CLI for selecting NordVPN locations and, only after an explicit validation gate, managing a NordLynx/WireGuard tunnel without GUI automation.

The project is currently in planning. No tunnel implementation, authentication flow, credentials, installer, or network mutation exists yet.

See [docs/implementation-plan.md](docs/implementation-plan.md) for the architecture, phased delivery plan, safety gates, and Phase 1 scope.

## Intended commands

```bash
nordmac login
nordmac countries --json
nordmac recommend de --json
sudo nordmac connect de --json
sudo nordmac connect de --city berlin
sudo nordmac connect de --server de1234
nordmac status --json
sudo nordmac disconnect
sudo nordmac reconnect --fresh
```

These commands are a target interface, not a statement that Nord's undocumented authentication and NordLynx provisioning APIs are stable or supported.

