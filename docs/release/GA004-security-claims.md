# GA004 — Public Security Claims & Verification Matrix

**Release:** Relay `v0.1.0`  
**Candidate Commit:** `0360a95f74c33a9fc3d7628876dd9bb7d307e2bb`  
**Status:** **FROZEN & CERTIFIED**  

---

## Authoritative Security Claims

Every public security claim made by Relay `v0.1.0` is grounded in concrete implementation, formal invariants, and automated test suites:

### 1. Zero Ambient Agent Credentials
* **Claim:** The agent runtime (e.g. Claude, Cursor, custom loops) and external MCP subprocesses possess zero target credentials in memory, environment, or persistent disk storage.
* **Release Implementation:** `crates/relay-mcp/src/subprocess.rs` (`apply_sanitized_env`), `crates/relay-credentials/src/broker.rs`.
* **Invariant:** `SI-001`, `SI-007`, `SI-015`.
* **Test:** `crates/relay-cli/tests/ga003_golden_demo_tests.rs`, `crates/relay-cli/tests/rc001_hardening_tests.rs`.
* **Evidence:** Process memory and environment inspection confirms 0 leaked secrets.
* **Boundary:** Local process memory and child process tree.
* **Limitation:** Does not protect against host root `/proc` memory scraping if root is compromised.

---

### 2. Deterministic Cedar Policy Authorization
* **Claim:** Tool execution is governed strictly by declarative Cedar security policies evaluated over RFC 8785 canonical actions.
* **Release Implementation:** `crates/relay-policy/src/engine.rs`, `crates/relay-canonical/src/jcs.rs`.
* **Invariant:** `SI-002`, `SI-004`, `SI-010`.
* **Test:** `crates/relay-policy/tests/authorization_tests.rs`, `crates/relay-connectors/tests/golden_path_security_tests.rs`.
* **Evidence:** Unmatched or unauthorized actions evaluate to `DENY` fail-closed with 0 target execution.
* **Boundary:** Relay Cedar PEP boundary.
* **Limitation:** Policy correctness depends on administrator policy authoring.

---

### 3. Complete Mediation of Governed Execution
* **Claim:** All execution paths (Native Filesystem, PostgreSQL, GitHub, and External MCP Subprocess Egress) are completely mediated without unmediated bypass routes.
* **Release Implementation:** `crates/relay-connectors/src/coordinator.rs`, `crates/relay-cli/src/governed_interceptor.rs`.
* **Invariant:** `SI-002`, `SI-003`, `SI-019`.
* **Test:** `crates/relay-cli/tests/ga002_audit_tests.rs`, `crates/relay-connectors/tests/adversarial_campaign_tests.rs`.
* **Evidence:** Complete mediation map validated in `docs/audit/GA002-complete-mediation-map.md`.
* **Boundary:** Relay stdio gateway and proxy socket interface.
* **Limitation:** Direct in-library invocation of connector structs outside the CLI requires embedding the `GovernedActionRunner`.

---

### 4. Cryptographic DSSE Action Receipts & Ledger Chain
* **Claim:** Every executed governed action produces a non-repudiable in-toto Statement wrapped in an RFC 9598 DSSE envelope signed with Ed25519 and chained in an append-only SQLite ledger.
* **Release Implementation:** `crates/relay-receipts/src/dsse.rs`, `crates/relay-ledger/src/storage.rs`.
* **Invariant:** `SI-009`, `SI-011`, `SI-012`, `SI-013`.
* **Test:** `crates/relay-receipts/tests/crypto_tests.rs`, `crates/relay-ledger/tests/tamper_detection_tests.rs`, `crates/relay-cli/tests/ga002_audit_tests.rs`.
* **Evidence:** `relay verify` validates genesis hash, parent links, and signatures, failing closed on single-bit tampering.
* **Boundary:** Local SQLite database file and signing keypair.
* **Limitation:** Receipts prove local execution observation; remote eventual consistency of cloud SaaS state cannot be guaranteed locally.

---

### 5. Linux Network Namespace Isolation & Anti-SSRF
* **Claim:** On Linux, external MCP subprocesses run in isolated network namespaces (`CLONE_NEWNET`) with no direct internet routing; all network traffic is forced through Relay's loopback forward proxy with strict anti-SSRF pre-DNS blocking.
* **Release Implementation:** `crates/relay-mcp/src/egress_sandbox.rs`, `crates/relay-mcp/src/egress_dns.rs`, `crates/relay-mcp/src/egress_proxy.rs`.
* **Invariant:** `SI-019`, `SI-020`, `SI-021`, `SI-022`, `SI-023`, `SI-024`.
* **Test:** `crates/relay-mcp/tests/m003_adversarial_tests.rs`, `crates/relay-cli/tests/ga002_audit_tests.rs`.
* **Evidence:** Direct raw socket attempts return `ENETUNREACH`; cloud metadata (`169.254.169.254`, `fd00:ec2::254`) requests return HTTP 403 Forbidden.
* **Boundary:** Linux network namespace kernel boundary (`CLONE_NEWNET`).
* **Limitation:** macOS and Windows operate in Managed Cooperative Mode (raw socket isolation requires container/VM sandboxes).
