# CR002: Local Security Console Adversarial Security Review

**Document ID:** `CR002-SEC-REVIEW-001`  
**Version:** `1.0.0`  
**Date:** September 2026  
**Status:** Certified Approved Baseline  
**Review Type:** Adversarial Threat Modeling & Vulnerability Assessment  
**Target Milestone:** Relay CR002 (Local Security Console)  
**Corpus Dependencies:** `CR002-UI-ARCH-001`, `CR002-PRIVACY-001`, `A004-security-invariants`

---

## 1. Executive Summary & Assessment Methodology

This review conducts a rigorous adversarial security evaluation of the **Relay Local Security Console** introduced in Milestone CR002. The console was subjected to simulated local web attacks, cross-origin attack vectors, DNS rebinding exploits, CSRF campaigns, content injection attempts, and cryptographic verification integrity probes.

### The Fundamental Security Invariant
> **The UI is a viewing and controlled management surface over Relay's existing security core, NEVER an alternate execution path or an ambient credential store.**

---

## 2. Adversarial Threat Questions & Verified Findings

### Q1: Can a malicious website cause an approval?
**Verdict: NO (PROVEN BY ARCHITECTURAL DESIGN & TESTS)**
- **Mechanics:** The human approval gate is anchored strictly to the controlling terminal (`/dev/tty`). The web UI exposes **zero** endpoints to approve, authorize, or bypass human-in-the-loop decisions.
- **Verification:** Any attempt by browser scripts to submit approvals fails with `404 Not Found`. Authoritative operator confirmation remains strictly out-of-band on `/dev/tty`.

### Q2: Can a local webpage invoke an execution endpoint?
**Verdict: NO (PROVEN BY TESTS)**
- **Mechanics:** The UI API exposes zero tool execution endpoints. Tools can only be invoked by an untrusted agent over the stdio MCP protocol (`tools/call`), which is deterministically intercepted and evaluated by Cedar in `GovernedActionRunner`.
- **Test Evidence:** `test_no_raw_connector_execution_endpoints` confirms `/api/v1/execute`, `/api/v1/connectors/exec`, and direct connector endpoints return `404 Not Found`.

### Q3: Can a browser session steal credentials?
**Verdict: NO (PROVEN BY ARCHITECTURAL INVARIANT SI-001 & TESTS)**
- **Mechanics:** Target API tokens, database connection strings with passwords, and private signing keys are never held in UI memory, serializable models, or browser DOM.
- **Redaction Engine:** All JSON outputs are processed through `crates/relay-cli/src/ui/data_minimization.rs`, which strips sensitive key patterns (`token`, `password`, `secret`, `key`, `auth`) and known credential prefixes (`ghp_`, `BEGIN RSA`, etc.) to `[REDACTED]`.
- **Test Evidence:** `test_data_minimization_redacts_credentials` verifies passwords, GitHub tokens, and private keys are redacted.

### Q4: Can UI state mutation bypass Cedar?
**Verdict: NO (PROVEN BY ARCHITECTURAL INVARIANT SI-004)**
- **Mechanics:** The UI cannot execute actions or modify authorization rules on the fly. When policies are reloaded via `POST /api/v1/policies/reload`, they are compiled, strictly validated against Relay's Cedar schema, and hashed. If validation fails, Relay immediately rolls back to the existing active policy without interruption.

### Q5: Can an XSS payload read sensitive receipts?
**Verdict: NO (PROVEN BY CSP & RESTRICTED CORS)**
- **Mechanics:** Content Security Policy enforces `default-src 'self'; script-src 'self'`. Untrusted inline scripts are blocked. Receipts displayed in the browser are scrubbed of credentials prior to transmission. Furthermore, session tokens are kept in JavaScript memory, preventing persistent exfiltration.

### Q6: Can a malicious tool name execute JavaScript?
**Verdict: NO (PROVEN BY TESTED SAFE DOM RENDERING)**
- **Mechanics:** The UI frontend (`app.js`) renders all dynamic content (tool names, principal strings, resource URIs, ActionHashes, and argument previews) using safe DOM property assignment (`textContent`) and strict HTML character escaping (`escapeHtml`). No `eval()` or unsanitized `innerHTML` is used for untrusted payloads.

### Q7: Can the UI cause Relay to load remote content?
**Verdict: NO (PROVEN BY LOCAL-ONLY GUARANTEE)**
- **Mechanics:** Static assets (`index.html`, `app.css`, `app.js`, `favicon.svg`) are statically compiled into the binary via `include_str!`. The UI makes zero external HTTP, CDN, or font requests.
- **Test Evidence:** `test_static_assets_served_locally` validates all assets are delivered locally from loopback with zero external URLs.

### Q8: Can an attacker change policy without authorization?
**Verdict: NO (PROVEN BY TESTS)**
- **Mechanics:** `POST /api/v1/policies/reload` requires:
  1. A valid active session token (`X-Relay-Session`).
  2. A valid matching CSRF token (`X-Relay-CSRF`).
  3. Strict origin validation (`Origin: http://127.0.0.1:<port>`).
  4. Valid Cedar schema validation of the target policies on disk.
- **Test Evidence:** `test_csrf_protection_on_mutating_endpoint` and `test_cross_origin_mutating_request_blocked` prove forged or cross-origin attempts are rejected with `403 Forbidden`.

### Q9: Can the UI mutate the ledger?
**Verdict: NO (PROVEN BY DATABASE IMMUTABILITY TRIGGERS & API DESIGN)**
- **Mechanics:** The UI API exposes zero ledger mutation endpoints. The only ledger endpoints are `GET /api/v1/ledger/status` and `POST /api/v1/ledger/verify`. The underlying SQLite ledger table enforces immutable hash-chain triggers (`SI-014`).

---

## 3. Local Web Attack Vectors Evaluated

| Vector | Attack Description | Relay Defense | Test Verification |
| :--- | :--- | :--- | :--- |
| **DNS Rebinding** | Attacker maps `evil.com` to `127.0.0.1` and lures user to `evil.com`. | `SecurityValidator::validate_host` rejects any Host header other than `127.0.0.1:<port>` or `localhost:<port>`. | `test_dns_rebinding_rejected` |
| **Cross-Site Request Forgery (CSRF)** | Attacker page executes `POST` to Relay mutating endpoint. | Requires `X-Relay-CSRF` custom header and matching local Origin; blocked by browser CORS preflight. | `test_csrf_protection_on_mutating_endpoint` |
| **Iframe Embedding / Clickjacking** | Attacker embeds Relay UI in an invisible iframe. | `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'`. | `test_security_headers_present` |
| **Denial of Service (Oversized Body)** | Attacker floods UI server with gigabytes of data. | Server enforces hard `MAX_BODY_SIZE` (1 MB) and `MAX_HEADER_SIZE` (16 KB), returning `413 Payload Too Large`. | `test_oversized_payload_rejected` |
| **Session Fixation / Replay** | Attacker attempts to guess or replay session tokens. | Tokens are 256-bit cryptographically secure UUIDv7/hex; compared with constant-time equality; 15-minute idle timeout. | `test_invalid_bootstrap_token_rejected` |

---

## 4. Cryptographic Verification Authenticity

The UI does not implement mock or visual-only verification:
1. **Receipt Verification (`POST /api/v1/receipts/:id/verify`):** Calls `relay_receipts::ReceiptVerifier` directly in Rust, executing real Ed25519 signature verification on the Pre-Authentication Encoding (PAE) and verifying in-toto statement domain hash bindings.
2. **Ledger Verification (`POST /api/v1/ledger/verify`):** Calls `relay_ledger::LedgerVerifier` directly, recalculating SHA-256 block hashes from genesis block sequence #0 through the head sequence.
3. **Binary Outcome:** Results are strictly `VALID` or `INVALID` / `BROKEN`. No ambiguous or estimated security metrics.

---

## 5. Adversarial Review Conclusion

The Relay Local Security Console satisfies all zero-trust criteria for CR002. It provides high-fidelity operational visibility into Relay's security boundary while strictly prohibiting credential exfiltration, unauthorized policy mutations, or bypasses of Cedar authorization and out-of-band human approval gates.
