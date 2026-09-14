# Relay Open-Core License Architecture & Repository Audit

**Document ID:** `CR003-LIC-001`  
**Version:** `1.0.0`  
**Date:** 2026-09-14  
**Audit Target:** Relay `v0.1.0` Repository & Dependency Graph  

---

## 1. Repository License Audit

A comprehensive audit of all packages and source trees in the Relay workspace was conducted:

```text
/home/sumeet/relay
├── crates/relay-domain       [Apache-2.0]
├── crates/relay-canonical    [Apache-2.0]
├── crates/relay-policy       [Apache-2.0]
├── crates/relay-credentials  [Apache-2.0]
├── crates/relay-receipts     [Apache-2.0]
├── crates/relay-connectors   [Apache-2.0]
├── crates/relay-ledger       [Apache-2.0]
├── crates/relay-mcp          [Apache-2.0]
└── crates/relay-cli          [Apache-2.0]
```

### Audit Findings:
1. **100% First-Party Apache-2.0:** Every first-party crate in the workspace explicitly specifies `license = "Apache-2.0"` in its `Cargo.toml`.
2. **Zero Proprietary Enclaves:** There are no proprietary, closed-source, or dual-licensed components compiled into the shipped `v0.1.0` release binary.
3. **Root License:** The root repository provides the full Apache License Version 2.0 text in [`LICENSE`](file:///home/sumeet/relay/LICENSE).
4. **Third-Party Dependency Compatibility:** All 120+ direct and transitive dependencies use permissive open-source licenses (MIT, Apache-2.0, BSD-3-Clause, ISC, and MPL-2.0). Full attribution is maintained in [`docs/release/THIRD-PARTY-LICENSES.md`](file:///home/sumeet/relay/docs/release/THIRD-PARTY-LICENSES.md). No copyleft (GPL / AGPL) dependencies are linked into the Relay binary.

---

## 2. Open-Core Boundary & Non-Interference Guarantee

Relay enforces a strict separation between open-core code and commercial extensions:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        Relay Commercial Services                       │
│    (Contractual Support, Enterprise SLAs, Signed Policy Bundles)       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Offline Entitlement Verification
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    Relay Open Core (Apache-2.0)                        │
│                                                                        │
│   CLI Engine ──► Cedar PEP/PDP ──► OS Credential Vault ──► DSSE Ledger │
│         ▲                                                    │         │
│         └──────────────── Local Web UI ──────────────────────┘         │
│                         (127.0.0.1 loopback)                           │
└────────────────────────────────────────────────────────────────────────┘
```

### Architectural Guarantees:
1. **No Proprietary Shims:** The open-core binary does not contain artificial stubs or hidden feature gates that require secret keys to unlock fundamental security invariants.
2. **No Cloud Tether:** Shipped binaries operate completely offline. Open-core users are never blocked by network latency, external server downtime, or authentication failures with Relay-operated servers.
3. **Future Extension Model:** Any future commercial modules (such as centralized multi-tenant management or hosted fleet observability) will be developed either as separate out-of-tree management services or separate packages, without converting the existing Apache-2.0 core to a proprietary license.
