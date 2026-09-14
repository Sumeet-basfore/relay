# Relay Engineering Integration Audit: Milestone M003

**Document ID:** `ENG-AUD-M003`  
**Milestone:** `M003 — External MCP Adversarial Validation & Governed Lifecycle Integration`  
**Date:** 2026-09-14  
**Auditor:** Principal Security Architect & Lead Protocol Engineer  
**Status:** Complete Integration Audit  

---

## 1. Executive Summary

This integration architecture audit maps and evaluates the end-to-end execution path for both native connectors (Filesystem, PostgreSQL, GitHub) and external MCP subprocesses across the 9 crates of the Relay workspace.

The objective of this audit is to rigorously trace authority transitions, session lifecycles, sandbox boundaries, credential injections, and cryptographic receipt generation to confirm that no component permits authority expansion, ambient credential exposure, or ungoverned execution.

---

## 2. End-to-End Execution Path Architecture

The complete governed lifecycle operates across two primary pipelines:

### 2.1. In-Process Native Connector Pipeline
```text
Agent JSON-RPC Frame (`tools/call`)
      ↓
`relay_mcp::gateway::handle_agent_frame` (Strict JSON / duplicate key validation)
      ↓
`relay_canonical::ActionCanonicalizer::canonicalize` (Deterministic JCS canonicalization → `ActionHash`)
      ↓
`relay_policy::engine::DefaultPolicyEngine::evaluate` (AWS Cedar PEP evaluation → `PolicyDecision`)
      ↓
`relay_mcp::approval::TtyApprovalProvider::request_approval` (Step-up human approval on `/dev/tty` if required)
      ↓
`relay_credentials::broker::CredentialBroker::acquire_lease` (Vaulted secret acquisition → `CredentialLease`)
      ↓
`relay_connectors::coordinator::GovernedActionRunner::run_action` (Native connector dispatch)
      ↓
`relay_receipts::signer::Ed25519ReceiptSigner::sign_receipt` (DSSE/in-toto envelope generation with secret scrubbing)
      ↓
`relay_ledger::sqlite::SqliteLedger::append` (Append-only SQLite hash-chain commit)
```

### 2.2. Governed External MCP Subprocess Pipeline
```text
Agent JSON-RPC Frame (`tools/call`)
      ↓
`relay_mcp::gateway::handle_agent_frame`
      ↓
`relay_canonical::ActionCanonicalizer::canonicalize` (`ActionHash`)
      ↓
`relay_policy::engine::DefaultPolicyEngine::evaluate` (Cedar PEP)
      ↓
Step-Up Approval (if required)
      ↓
`relay_mcp::egress_session::ProxySessionManager::create_session` (Generates 256-bit `RELAY_PROXY_AUTH` lease token, 30s TTL, bound to `ActionHash`)
      ↓
`relay_mcp::egress_sandbox::EgressSandboxLauncher::launch`
  ├─ Linux: `pre_exec` unshares `CLONE_NEWUSER | CLONE_NEWNET` (blocks raw sockets, loopback only)
  └─ macOS/Windows: Injects sanitized environment (`HTTP_PROXY`, `HTTPS_PROXY`, `RELAY_PROXY_AUTH`)
      ↓
External MCP Subprocess executes tool logic
      ↓
Subprocess dials `HTTP_PROXY` on `127.0.0.1:<ephemeral_port>`
      ↓
`relay_mcp::egress_proxy::EgressProxy::handle_client`
  ├─ 1. Authenticate `RELAY_PROXY_AUTH` lease token (`ProxySessionManager::validate_lease`)
  ├─ 2. DNS Pre-Resolution Blacklist check (Blocks `169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`)
  ├─ 3. DNS Resolution + RFC 1918 / Loopback filtering + Socket IP Pinning (`DnsResolverWithBlacklist`)
  ├─ 4. Cedar PDP Destination Authorization (`mcp.http_request` on `Relay::NetworkEndpoint`)
  ├─ 5. Hop-by-Hop Header Sanitization & CRLF Injection Check (`HeaderPolicy`)
  ├─ 6. Vaulted JIT Credential Injection into upstream headers (`CredentialInjector`)
  └─ 7. Direct TCP dispatch to pinned IP / Bidirectional Splice
      ↓
Subprocess finishes tool call → `ProxySessionManager::burn_session(action_hash)`
      ↓
Cryptographic Receipt Signing & Append-Only Ledger Commit
```

---

## 3. Authority Transition & Boundary Analysis

| Boundary Transition | Source Authority | Target Authority | Defense & Invariant | Potential Vulnerability Audited |
|:---|:---|:---|:---|:---|
| **Frame → Canonical Action** | Untrusted JSON text | Strongly typed `CanonicalAction` with `ActionHash` | Strict RFC 8785 canonicalization, duplicate key rejection, NaN/Infinity rejection (`SI-009`) | Non-canonical JSON parsing divergence |
| **Canonical Action → Policy** | `CanonicalAction` | `PolicyDecision` (Allow / Deny / ApprovalRequired) | Deterministic Cedar evaluation against compiled schema (`SI-002`, `SI-010`) | Unknown principal / action bypass |
| **Policy → Approval** | `PolicyDecision::ApprovalRequired` | `Approval` record with SHA-256 digest | Interactive `/dev/tty` prompt; fail-closed in headless mode (`SI-011`, `SI-012`, `SI-014`) | TTY hijacking / headless fail-open |
| **Approval → Proxy Session** | Authorized action | Ephemeral `ProxyLease` ($T_{\text{lease}}$) | 256-bit cryptographically secure token, 30s TTL, ActionHash binding (`SI-020`) | Token forgery / cross-action replay |
| **Session → Subprocess Launch** | Relay Host Process | Isolated Child Subprocess | Linux `CLONE_NEWUSER \| CLONE_NEWNET`, `env_clear()`, zero ambient secrets (`SI-001`, `SI-018`, `SI-023`) | Environment variable leakage / raw socket escape |
| **Subprocess → Proxy Request** | Child HTTP / CONNECT | Validated In-Process Proxy Stream | Loopback-only listener (`127.0.0.1`), bounded backlog (`SI-019`) | Non-loopback interface exposure |
| **Proxy Request → DNS / IP** | Hostname string | Pinned `SocketAddr` | Pre-resolution blacklist, private IP rejection, IP pinning (`SI-021`) | SSRF / DNS rebinding TOCTOU |
| **Proxy → Cedar Destination** | Upstream URI | Destination Authorization | Cedar `Relay::NetworkEndpoint` evaluation (`SI-002`) | Host/port confusion |
| **Proxy → Upstream Socket** | Sanitized Headers | Outbound HTTPS request with JIT secrets | JIT Header Injection in Relay memory; hop-by-hop stripping (`SI-001`, `SI-022`) | Secret leakage into subprocess |
| **Response → Receipt** | Execution Outcome | Signed DSSE Envelope | Secret scrubber (regex + zeroize), Ed25519 DSSE signing (`SI-007`, `SI-008`) | Secret leakage in audit trail |
| **Receipt → Ledger** | `ActionReceipt` | Merkle-linked `LedgerEntry` | SQLite append-only hash-chain (`SI-013`, `SI-014`) | Audit log truncation / tampering |

---

## 4. Code Path Audit Findings & Resolution

1. **Authority Reconstruction Check:**
   - *Audit:* Verified whether `ProxySessionManager` permits creating a session without an `ActionHash`.
   - *Result:* `ProxySessionManager::create_session` strictly requires `ActionHash`, `Principal`, and `Option<NetworkEndpoint>`. It is impossible to issue a floating un-governed session lease.

2. **Policy Decision Replay Check:**
   - *Audit:* Verified whether policy decisions can be cached across distinct tool calls.
   - *Result:* Policy evaluation is strictly per-call and re-evaluated using the exact `ActionHash`. No caching layer exists that could allow stale decisions to authorize subsequent actions.

3. **Session Detachment & Token Burning:**
   - *Audit:* Verified what happens when a tool call completes or fails.
   - *Result:* Session tokens are explicitly burned via `burn_session(action_hash)` upon tool call completion, or invalidated automatically when their 30s TTL expires.

4. **Public API Escape Audit:**
   - *Audit:* Verified whether any public function in `relay-connectors` or `relay-mcp` allows executing tool logic without passing through `GovernedActionRunner` or Cedar PEP.
   - *Result:* All connector execution methods (`execute_governed_with_receipt`) require a valid `&PolicyDecision` matching the `ActionHash` and a signer. Direct unguarded execution is impossible.

5. **Asynchronous Tasks Handling:**
   - *Audit:* Evaluated behavior for background MCP Tasks attempting network access after the synchronous tool call completes.
   - *Result:* Relay explicitly unsupports un-bounded asynchronous MCP Tasks that outlive the synchronous action. Because the proxy lease is burned upon tool completion and Linux Network Namespaces block raw sockets, post-action background traffic fails closed (`SI-020`, `SI-023`).

---

## 5. Conclusion

The integration architecture audit confirms that the Relay execution path forms a strictly governed, non-bypassable security boundary. Every authority transition is guarded by explicit invariants, deterministic policy evaluation, vaulted secret isolation, and cryptographic evidence generation.
