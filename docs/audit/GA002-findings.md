# Independent Findings Ledger: Milestone GA002

**Document ID:** `AUD-FND-GA002`  
**Milestone:** `GA002 — Independent Security & Release Audit`  
**Auditor:** Principal External Security Reviewer  
**Release Target:** `v0.1.0`  
**Evaluation Date:** 2026-09-14  

---

## 1. Findings Classification Summary

| Finding ID | Title | Severity | Component | Disposition |
|:---|:---|:---:|:---:|:---:|
| **FINDING-GA002-01** | `Proxy-Connection` hop-by-hop header stripping | `LOW` | `relay-mcp::egress_headers` | **RESOLVED** |
| **FINDING-GA002-02** | Direct Rust Connector API Invocation without Governed Runner | `ACCEPTED RISK` | `relay-connectors` | **ACCEPTED RISK** |
| **FINDING-GA002-03** | macOS & Windows raw socket bypass in cooperative mode | `EXPECTED LIMITATION` | `relay-mcp::egress_sandbox` | **ACCEPTED RISK** |
| **FINDING-GA002-04** | Localhost Ledger File Deletion by Same OS User | `EXPECTED LIMITATION` | `relay-ledger::sqlite` | **ACCEPTED RISK** |

---

## 2. Detailed Findings Evaluation

### Finding GA002-01: `Proxy-Connection` Hop-by-Hop Header Stripping
- **Severity:** `LOW`
- **Component:** `crates/relay-mcp/src/egress_headers.rs`
- **Attack Preconditions:** Adversarial MCP tool sends non-standard `Proxy-Connection: keep-alive` headers through the proxy.
- **Attack:** Attempt to preserve proxy connection state across upstream requests.
- **Observed Result:** Header was forwarded if not in hop-by-hop list.
- **Security Impact:** Potential for connection persistence confusion in certain legacy upstream proxies.
- **Existing Mitigation:** Fixed in M003 by explicitly adding `"proxy-connection"` to `HOP_BY_HOP_HEADERS`.
- **Disposition:** **RESOLVED** (Verified by `test_phase15_header_smuggling_crlf_and_hop_by_hop_stripping`).

---

### Finding GA002-02: Direct Rust Connector API Invocation without Governed Runner
- **Severity:** `ACCEPTED RISK`
- **Component:** `crates/relay-connectors`
- **Attack Preconditions:** A third-party Rust developer links `relay-connectors` as a library and invokes `FilesystemConnector::execute_governed_with_receipt` directly rather than through `GovernedActionRunner`.
- **Attack:** Developer writes custom Rust code that bypasses `GovernedActionRunner::run_action`.
- **Observed Result:** Direct connector invocation still requires passing a valid `&PolicyDecision` and `&Ed25519ReceiptSigner`.
- **Security Impact:** In library mode, a rogue developer writing Rust code within the host binary can construct mock policy decisions. The Relay CLI binary, however, strictly executes all actions through `GovernedActionRunner`.
- **Existing Mitigation:** The Relay binary (`relay run`) enforces `GovernedActionRunner` unconditionally.
- **Recommendation:** In v0.2.0, restrict connector visibility to crate-private or require sealed builder traits.
- **Disposition:** **ACCEPTED RISK** for v0.1.0.

---

### Finding GA002-03: macOS & Windows Raw Socket Bypass in Cooperative Mode
- **Severity:** `EXPECTED LIMITATION`
- **Component:** `crates/relay-mcp/src/egress_sandbox.rs`
- **Attack Preconditions:** MCP subprocess executed on macOS or Windows without kernel sandbox extensions.
- **Attack:** Subprocess ignores `HTTP_PROXY` environment variables and directly calls `socket(AF_INET, SOCK_STREAM)` syscalls.
- **Observed Result:** Direct raw TCP socket connects successfully to external IP without passing through Relay proxy. However, target API credentials remain vaulted inside Relay and are never leaked.
- **Security Impact:** Destination allowlisting is cooperative on macOS/Windows; credential isolation remains 100% hard enforced.
- **Existing Mitigation:** Documented extensively in `docs/security/limitations.md` and flagged by `relay doctor`.
- **Disposition:** **ACCEPTED RISK** for v0.1.0.

---

### Finding GA002-04: Localhost Ledger File Deletion by Same OS User
- **Severity:** `EXPECTED LIMITATION`
- **Component:** `crates/relay-ledger::sqlite`
- **Attack Preconditions:** Attacker has direct shell write access as the same OS user running Relay.
- **Attack:** Attacker executes `rm .relay/ledger.db` or overwrites database file.
- **Observed Result:** Ledger file is deleted or destroyed.
- **Security Impact:** Audit history is lost. However, cryptographic hash-chaining prevents retroactive modification without detection (`relay verify` fails on tampered records).
- **Existing Mitigation:** Restrictive `0600` file permissions; SQLite WAL mode; Merkle hash-chaining.
- **Recommendation:** Document that Relay provides tamper-evidence against retroactive modification, not protection against full host user destruction.
- **Disposition:** **ACCEPTED RISK** (Documented Host Security Boundary).

---

## 3. Severity & Blocker Summary

- **BLOCKER Findings:** 0
- **HIGH Findings:** 0
- **MEDIUM Findings:** 0
- **LOW Findings:** 1 (Resolved)
- **Accepted Risks / Limitations:** 3 (Documented & Qualified)

$$\text{Independent Findings Status: } \mathbf{ZERO\ RELEASE\ BLOCKERS}$$
