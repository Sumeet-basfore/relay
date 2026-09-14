# Independent Security Architecture Model: Milestone GA002

**Document ID:** `AUD-MOD-GA002`  
**Milestone:** `GA002 — Independent Security & Release Audit`  
**Auditor:** Principal External Security Reviewer  
**Date:** 2026-09-14  
**Status:** Independent Security Model  

---

## 1. Executive Summary & Core Thesis

Relay is evaluated as an adversarial execution boundary interposed between an **untrusted AI agent** (potentially subject to prompt injection or model compromise) and **governed target resources** (filesystems, relational databases, cloud APIs, and external third-party MCP servers).

### Core Architectural Principle
$$\text{Authority} + \text{Credential Isolation} + \text{Evidence}$$

---

## 2. Actor Classification & Trust Boundary Matrix

| Actor / Entity | Trust Level | Capabilities & Boundaries |
|:---|:---:|:---|
| **Human Operator** | `FULLY TRUSTED` | Controls configuration files (`relay.toml`), policy files (`policies/*.cedar`), and provides interactive step-up approval over `/dev/tty`. |
| **Relay Host Process** | `TRUSTED COMPUTING BASE (TCB)` | Runs with operator privileges; evaluates Cedar policies; manages vaulted credentials in `SecretBuffer`; signs receipts with Ed25519; appends to SQLite ledger. |
| **AI Agent Process** | `UNTRUSTED / ADVERSARIAL` | Assumed to be under full prompt-injection control. Communicates strictly over JSON-RPC stdio frames with Relay gateway. Receives zero ambient credentials. |
| **External MCP Subprocess** | `UNTRUSTED / HOSTILE` | Launched as a child subprocess. On Linux, strictly isolated within unprivileged User & Network Namespaces (`CLONE_NEWUSER \| CLONE_NEWNET`); on macOS/Windows, governed via cooperative `HTTP_PROXY`. |
| **Remote Target Services** | `AUTHENTICATED TARGETS` | GitHub API, PostgreSQL servers, HTTPS destinations. Authorized via Cedar and reached via vaulted credentials injected JIT by Relay. |
| **Independent Verifier** | `EXTERNAL AUDITOR` | Audits DSSE action receipts and SQLite Merkle hash-chain ledgers using public keys without requiring access to Relay secrets. |

---

## 3. Authority, Credentials, and Evidence Flow

```text
1. Authority Entry:
   Agent sends raw JSON-RPC frame (e.g. tools/call).
   Relay strictly parses JSON and normalizes arguments via RFC 8785 (JCS) -> ActionHash.

2. Authority Verification:
   Relay Policy Engine (Cedar PEP) evaluates authorization against compiled Cedar schema.
   If policy returns ApprovalRequired, Relay prompts Operator on /dev/tty.
   If policy returns Deny, Relay returns JSON-RPC error / HTTP 403 immediately.

3. Credential Isolation:
   Child subprocess environment is wiped via env_clear() (zero ambient secrets).
   Subprocess receives only ephemeral 256-bit proxy lease token ($T_{\text{lease}}$, 30s TTL).
   Vaulted credentials remain inside Relay memory and are injected JIT into upstream headers.

4. Network Mediation:
   Linux: Subprocess placed in isolated NetNS (raw sockets blocked with ENETUNREACH).
   Traffic dials Relay loopback proxy on 127.0.0.1:<ephemeral>.
   Proxy validates lease token, checks pre-DNS blacklist, pins resolved IP, and evaluates Cedar destination policy.

5. Evidence Generation & Persistence:
   Relay captures execution outcome, strips sensitive tokens via secret scrubber,
   signs Ed25519 DSSE / in-toto Action Receipt, and commits entry to SQLite Merkle hash-chain ledger.
```

---

## 4. Discrepancy & Scope Analysis

| Area | Stated Claim in Prior Docs | Independent Audit Verification | Verdict |
|:---|:---|:---|:---:|
| **Ambient Secrets** | Zero ambient credentials in agent/subprocess context. | Verified via `env_clear()`, `/proc` inspection, and sanitized child environment. | **CONFIRMED** |
| **Destination Policy** | Outbound HTTP/HTTPS mediated and authorized by Cedar. | Verified via in-process loopback proxy and Cedar mapping. | **CONFIRMED** |
| **Linux Sandboxing** | 100% of raw sockets blocked on Linux without root. | Verified via unprivileged User & Net Namespaces (`CLONE_NEWUSER \| CLONE_NEWNET`). | **CONFIRMED** |
| **macOS/Windows Sandboxing** | Cooperative environment proxy; raw socket evasion possible. | Confirmed as an explicitly documented platform boundary. | **CONFIRMED** |
| **Ledger Immutability** | Tamper-evident hash chain; host OS user can delete file. | Confirmed: ledger is tamper-evident (detects alterations), not indestructible. | **CONFIRMED** |

---

## 5. Reviewer Conclusion

The mental model confirms that Relay's architecture forms a cohesive, defensible execution boundary. Authority is verified before execution, credentials are never exposed ambiently, and cryptographic evidence is generated deterministically.
