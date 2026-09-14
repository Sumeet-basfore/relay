# Relay v0.1.0 — Golden Reference Deployment Specification

**Version:** `v0.1.0`  
**Commit:** `0360a95f74c33a9fc3d7628876dd9bb7d307e2bb`  
**Classification:** Canonical Golden Reference Architecture  
**Status:** **ACTIVE / CERTIFIED**  

---

## 1. Objective & Philosophy

The **Relay Golden Reference Deployment** provides a minimal, self-contained, and completely reproducible demonstration environment that validates Relay's core security thesis:

> **Authority + Credential Isolation + Evidence**  
> *Under complete prompt-injection compromise of the agent, the agent cannot obtain ambient credentials, bypass Cedar authorization, escape network sandbox boundaries, or mutate state without generating tamper-evident cryptographic evidence.*

The reference deployment proves security properties through live adversarial validation rather than mocked components or theatrical simulations.

---

## 2. Reference Environment Specification

| Component | Canonical Specification | Verification Method |
| :--- | :--- | :--- |
| **Operating System** | Linux (x86_64 / aarch64, kernel ≥ 5.4) | `uname -s -r -m` |
| **Relay Binary** | Relay `v0.1.0` release artifact | `relay --version` |
| **Sandbox Mode (Linux)**| Linux Enforced Network Namespace Sandbox (`CLONE_NEWNET`) | `relay doctor` |
| **Managed Proxy Mode** | Loopback HTTP forward proxy with dynamic credential injection | `127.0.0.1:<ephemeral>` |
| **Authorization Engine**| Embedded Cedar Policy Engine (RFC 8785 JCS canonicalization) | Embedded `cedar-policy` |
| **Evidence / Ledger** | in-toto Statement (RFC 9598 DSSE Envelope) + SQLite Hash-Chain | `relay verify --ledger .relay/ledger.db` |
| **Demo MCP Server** | Python 3 Deterministic JSON-RPC 2.0 stdio MCP Server | `python3 server.py` |
| **Policy Set** | `demo/policies/demo.cedar` + `demo/policies/relay_schema.cedarschema`| Cedar parser & validator |
| **Fixtures & Data** | Disposable filesystem tree (`fixtures/public.txt`, `fixtures/protected.txt`) | SHA-256 pinned |

---

## 3. End-to-End Mediation Topologies

### 3.1 Governed In-Process & Native Execution Pipeline

```text
Untrusted AI Agent (Client Stdio)
       │ (JSON-RPC 2.0 frames ≤ 16MB)
       ▼
┌─────────────────────────────────────────────────────────────┐
│ Relay Core Gateway Boundary                                 │
│  1. Bounded JSON-RPC Framing & Parsing (SI-001)             │
│  2. RFC 8785 JSON Canonicalization Scheme (JCS) (SI-002)     │
│  3. Deterministic ActionHash Computation                    │
│  4. Fail-Closed Cedar Policy Authorization (SI-004)         │
│  5. Interactive Human Approval Step-Up (/dev/tty) (SI-018)  │
│  6. Ephemeral JIT Credential Broker Leasing (SI-006, SI-007)│
└──────┬──────────────────────────────────────────────────────┘
       │ Governed Dispatch
       ▼
┌─────────────────────────────────────────────────────────────┐
│ Execution Target (Native Connector / MCP Server Subprocess) │
└──────┬──────────────────────────────────────────────────────┘
       │ Output Capture & Zeroized Secrets (SI-008, SI-017)
       ▼
┌─────────────────────────────────────────────────────────────┐
│ Cryptographic Evidence & Persistence Engine                 │
│  1. In-Toto Statement Generation (RFC 9598 DSSE Envelope)   │
│  2. Ed25519 Cryptographic Signature (SI-009)                │
│  3. Append-Only SQLite Ledger Hash-Chain (SI-011, SI-012)   │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 External MCP Subprocess & Linux Network Namespace Sandbox

```text
External MCP Subprocess (e.g. Third-Party Tool Server)
       │
       │ [Linux Network Namespace Isolation: CLONE_NEWNET]
       │ [Raw sockets blocked: ENETUNREACH]
       ▼
┌─────────────────────────────────────────────────────────────┐
│ Relay In-Process Loopback HTTP Egress Forward Proxy         │
│  1. Action-Bound Ephemeral Proxy Session Token (SI-023)     │
│  2. Anti-SSRF & Cloud Metadata Filtering (SI-022)           │
│  3. Cedar Destination Allowlisting                          │
│  4. JIT Dynamic Credential Header Injection                 │
└──────┬──────────────────────────────────────────────────────┘
       │ Filtered & Authorized Outbound HTTP/HTTPS Traffic
       ▼
┌─────────────────────────────────────────────────────────────┐
│ Destination Target (e.g. External API https://api.example.com)│
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Demonstration Narrative & Scene Progression

The Golden Reference Deployment exercises seven structured scenes:

```text
Scene 1: Allowed Action        → Agent reads public.txt          → ALLOWED
Scene 2: Unauthorized Action   → Agent attempts protected.txt    → DENIED (Fail-Closed)
Scene 3: Scoped Mutation       → Agent writes to output/         → ALLOWED
Scene 4: Approval Step-Up      → Agent attempts file deletion    → APPROVAL REQUIRED
Scene 5: Adversarial Attacks   → Server probes creds/SSRF/net    → ALL BLOCKED
Scene 6: Evidence Verification → relay verify checks hash chain  → CHAIN VALID
Scene 7: Tamper Detection      → 1-byte mutation on disk/ledger  → CORRUPTION DETECTED
```

---

## 5. Disposable Workspace Directory Layout

The reference deployment runs strictly within an ephemeral directory (`/tmp/relay-golden-demo`):

```text
/tmp/relay-golden-demo/
├── relay.toml                      # Root configuration (0600 permissions)
├── policies/
│   ├── demo.cedar                  # Active Cedar security policies
│   └── relay_schema.cedarschema    # Domain entity schema definition
├── fixtures/
│   ├── public.txt                  # Public test asset (Permitted read)
│   ├── protected.txt               # Confidential asset (Strictly forbidden)
│   ├── schema.sql                  # PostgreSQL demo schema
│   └── output/                     # Scoped write directory
├── server.py                       # Deterministic reference MCP server
├── .relay/
│   ├── ledger.db                   # SQLite hash-chain audit ledger
│   └── signing_key.ed25519         # Ephemeral Ed25519 signing keypair
└── demo-output/
    ├── receipts/                   # Exported DSSE Action Receipts
    ├── ledger/                     # Exported ledger state
    ├── logs/                       # Execution and audit traces
    └── summary.txt                 # Machine-verifiable execution log
```

---

## 6. Security Invariants Demonstration Matrix

| Invariant | Security Guarantee | Demonstrated Mechanism |
| :--- | :--- | :--- |
| **SI-002** | RFC 8785 Canonicalization | Semantic JSON equality produces bit-for-bit identical `ActionHash` |
| **SI-004** | Fail-Closed Cedar PEP | Explicit forbid on `protected.txt` denies read attempt immediately |
| **SI-006 / SI-007** | Credential Isolation | `attack_exfiltrate_credentials` verifies 0 ambient secrets in subprocess |
| **SI-009** | DSSE Envelope Evidence | Ed25519 signature generated and independently verified |
| **SI-011 / SI-012** | Immutable Hash Ledger | Database write-once triggers prevent in-place mutation |
| **SI-013** | Verification Self-Consistency | `relay verify` validates genesis hash, entry linkage, and payloads |
| **SI-021** | Linux NetNS Sandbox | `attack_raw_socket` receives `ENETUNREACH` in network namespace |
| **SI-022** | Anti-SSRF & Metadata Filter | `attack_probe_cloud_metadata` (169.254.169.254) is blocked |
| **SI-023** | Ephemeral Proxy Session | `attack_post_action` fails because session token burned upon action completion |
