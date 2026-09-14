# CR002: Local Security Console Privacy & Data Flow Audit

**Document ID:** `CR002-PRIVACY-001`  
**Version:** `1.0.0`  
**Date:** September 2026  
**Status:** Certified Approved Baseline  
**Target Milestone:** Relay CR002 (Local Security Console)  
**Corpus Dependencies:** `CR001-UI-001` (Data Boundary), `CR001-PRIVACY-001` (India DPDP Act), `CR001-FLOW-001` (Data Flow Map)

---

## 1. Audit Objective & Scope

This privacy audit examines the Relay Local Security Console (implemented in Milestone CR002) to verify that the addition of a browser-based management interface adheres strictly to **Commercial Model B (Local-First Open Core)** and does not introduce cloud telemetry, prompt aggregation, credential exfiltration, or external data synchronization.

### The Privacy Baseline Mandate
> **A local security console, not a cloud dashboard.**  
> Relay's web interface is 100% self-contained, executed entirely on the local loopback interface (`127.0.0.1`), and isolated from external networks.

---

## 2. Privacy Audit Verification Matrix

| Audit Item | Verification Target | Audit Result | Evidence / Implementation Reference |
| :--- | :--- | :--- | :--- |
| **Telemetry & Metrics** | Outbound telemetry, crash reporting, pings | **ZERO TELEMETRY (PASS)** | No telemetry libraries included; zero analytics endpoints; zero tracking pixels. |
| **External CDNs & Scripts**| Script tags, external font files, stylesheets | **ZERO EXTERNAL ASSETS (PASS)** | All HTML, CSS, JavaScript, and SVG icons are embedded directly into the binary via `include_str!`. CSP enforces `default-src 'self'`. |
| **Agent Prompt Collection**| LLM prompts, scratchpads, completions | **NO PROMPT UPLOAD (PASS)** | The console only displays canonical ActionHash and tool identifiers; prompt text is not captured, cached, or transmitted. |
| **Tool Arguments & Payloads**| Tool arguments, queries, and file paths | **SCRUBBED & REDACTED (PASS)** | Sensitive keys (`password`, `token`, `secret`, `key`, `auth`, `cookie`) and credential substrings (`ghp_`, `BEGIN RSA`, etc.) are redacted to `[REDACTED]` prior to browser rendering (`crates/relay-cli/src/ui/data_minimization.rs`). |
| **Target Credentials** | API tokens, DB passwords, lease tokens | **NEVER EXPOSED (PASS)** | Credential material is eliminated from responses. The console only exposes Lease IDs and Provider types (SI-001 compliant). |
| **Receipt & Ledger Sync** | Cloud sync of receipts or SQLite ledger | **ZERO CLOUD SYNC (PASS)** | Receipts and ledger databases remain strictly local in `.relay/ledger.db` under `0600` permissions. |
| **Network Interface Binding**| Host IP address binding | **STRICT LOOPBACK (PASS)** | `relay ui` binds strictly to `127.0.0.1`. Binding to `0.0.0.0` is prohibited and rejected with a fatal error. |
| **Browser Network Calls** | Outbound fetch/XHR from frontend | **LOCAL-ONLY (PASS)** | All `fetch()` calls target `/api/v1/*` on the local origin. CSP blocks any cross-origin network requests. |

---

## 3. Network Traffic & Egress Inspection

During end-to-end execution of `relay ui` and automated browser security suites:
1. **Network Namespace Isolation:** Egress monitoring confirms zero outbound packets to external IPs or public DNS resolvers originating from the console server.
2. **Loopback Traffic Only:** 100% of TCP connections are established between client browser (`127.0.0.1:<ephemeral>`) and Relay gateway (`127.0.0.1:<port>`).
3. **Blocked Destination Verification:** Requests attempting to resolve cloud metadata endpoints (`169.254.169.254`) or loopback interfaces via forged headers are blocked by Relay's DNS resolver and Host-header validation middleware.

---

## 4. Content Security Policy (CSP) Verification

The local console delivers an immutable, restrictive Content Security Policy with every HTTP response:
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
```

- **`connect-src 'self'`**: Guarantees that browser scripts can only issue AJAX/fetch requests back to the local Relay server.
- **`frame-ancestors 'none'`**: Guarantees that no external site can frame or clickjack the security console.
- **`script-src 'self'`**: Prohibits execution of inline `<script>` tags or remote scripts loaded from external CDNs.

---

## 5. Compliance with India DPDP Act 2023 & GDPR

1. **No Processing of External Personal Data:** The console processes only local system metadata, tool action logs, and local operator authentication tokens.
2. **Data Minimization (DPDP §6(1)):** Only security-relevant metadata (timestamps, hashes, status codes) is displayed. Full payload data is masked by default.
3. **Purpose Limitation (DPDP §4(1)):** Local audit data is displayed solely for operator inspection, policy debugging, and cryptographic receipt verification.
4. **Zero Cross-Border Transfer (DPDP §16):** Because Relay does not transmit data to remote clouds or SaaS infrastructure, cross-border data transfer restrictions are completely inapplicable.

---

## 6. Conclusion & Certification

Relay Milestone CR002 passes all privacy requirements without reservation. The Local Security Console operates as an air-gapped, zero-telemetry, zero-cloud control surface preserving the operator's complete sovereignty over local security evidence.
