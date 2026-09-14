# CR002: Relay Local Security Console Architecture Specification

**Document ID:** `CR002-UI-ARCH-001`  
**Version:** `1.0.0`  
**Date:** September 2026  
**Status:** Approved Architectural Baseline / Implementation Specification  
**Target Milestone:** Relay CR002 (Local Security Console)  
**Corpus Dependencies:** `A001-system-architecture`, `CR001-UI-001` (Data Boundary), `R009` (Trust Boundaries), `R011` (Action Receipts), `R012` (MCP Boundary)

---

## 1. Executive Summary & Objective

The **Relay Local Security Console** provides security operators, platform engineers, and developers with real-time, comprehensive visibility into Relay's security boundary:
- Real-time security posture and policy decision tracking.
- Governed tool action execution lifecycle (`Action -> Policy -> Approval -> Credential -> Execution -> Evidence -> Ledger`).
- Independent in-browser cryptographic verification of Action Receipts (Ed25519) and ledger integrity (SHA-256 hash chains).
- Active Cedar policy inspection, syntax validation, and atomic reload with fail-closed rollback.
- External MCP network egress sandbox status, session leases, and blocked destination monitoring.
- Connector operational status across Filesystem, PostgreSQL, GitHub, and external MCP subprocesses.
- Shared diagnostic health telemetry aligned with `relay doctor`.

### The Core Architectural Mandate
> **A local security console, not a cloud dashboard.**  
> The console is a viewing and controlled management surface over Relay's existing security model. It is NEVER an alternate execution path or a shortcut around Cedar policies, JIT credentials, or out-of-band approval gates.

---

## 2. Guiding Principles & Core Invariants

1. **Single Security Core, Dual Interface:**  
   The CLI (`relay`) and the Web UI (`relay ui`) share the exact same underlying domain logic, Cedar evaluation engine, cryptographic verifiers, and storage engines. The UI gains no capabilities that the CLI/core cannot justify.
2. **Localhost-Only Loopback Binding:**  
   The web server binds strictly to `127.0.0.1` by default. Binding to `0.0.0.0` is strictly forbidden.
3. **No Ambient Credential Exposure:**  
   Target credentials (GitHub PATs, database passwords, private keys, API secrets) never enter browser DOM, memory, or network responses. Full redaction and scrubbing apply to all payloads.
4. **Out-of-Band Approval Boundary Preserved:**  
   The human-in-the-loop approval gate remains firmly anchored to the controlling terminal (`/dev/tty`). The web UI displays pending approvals, but cannot be manipulated by untrusted browser tabs or automated scripts to approve sensitive operations.
5. **Zero Remote Telemetry or CDN Dependencies:**  
   All HTML, CSS, JavaScript, and SVG assets are statically embedded directly into the Relay binary (`include_str!`). The UI performs zero outbound network requests, loads zero third-party assets, and incorporates zero product analytics or tracking scripts.
6. **Strict Cryptographic Integrity:**  
   Receipt and ledger verification actions in the UI execute the real `relay_receipts::ReceiptVerifier` and `relay_ledger::LedgerVerifier` implementations. Statuses are binary (`VALID` vs `INVALID` / `BROKEN`), not simulated.

---

## 3. System Context & Component Architecture

```text
 ┌──────────────────────────────────────────────────────────────────┐
 │                       LOCAL BROWSER SURFACE                      │
 │  Operators Web Browser (Chrome, Firefox, Safari, Edge)           │
 │  Origin: http://127.0.0.1:<port>                                 │
 └────────────────────────────────┬─────────────────────────────────┘
                                  │ HTTP/1.1 (JSON API + Assets)
                                  │ Loopback Only (127.0.0.1)
                                  │ Headers: X-Relay-Session, X-Relay-CSRF
                                  ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │               RELAY LOCAL SECURITY CONSOLE SERVER                │
 │  ┌────────────────────────────────────────────────────────────┐  │
 │  │ Security Middleware                                        │  │
 │  │ - Host Header Verification (`127.0.0.1:<port>`, `localhost`)│  │
 │  │ - Origin & Referer Verification                            │  │
 │  │ - Ephemeral Session Token & CSRF Validation                │  │
 │  │ - Security Headers (CSP, XFO, nosniff, no-referrer)        │  │
 │  │ - Request Payload Size Limiting (Max 1MB / 64KB JSON)      │  │
 │  └─────────────────────────────┬──────────────────────────────┘  │
 │                                │                                 │
 │  ┌─────────────────────────────┴──────────────────────────────┐  │
 │  │ UI API Dispatcher & Data Minimization Engine               │  │
 │  │ - Secret Scrubber (`relay_receipts::scrub`)                │  │
 │  │ - Paged/Bounded Response Serializer                        │  │
 │  │ - Embedded Asset Server (`index.html`, `app.css`, `app.js`) │  │
 │  └─────────────────────────────┬──────────────────────────────┘  │
 └────────────────────────────────┼─────────────────────────────────┘
                                  │ In-Process Internal Trait Calls
                                  ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │                        RELAY CORE ENGINES                        │
 │  ┌───────────────────────┐           ┌────────────────────────┐  │
 │  │ Cedar Policy Engine   │           │ Sqlite Ledger Engine   │  │
 │  │ (Validation & Reload) │           │ (Recent & Chain Verify)│  │
 │  └───────────────────────┘           └────────────────────────┘  │
 │  ┌───────────────────────┐           ┌────────────────────────┐  │
 │  │ Receipt Verifier      │           │ Diagnostic Engine      │  │
 │  │ (DSSE & in-toto v1.0) │           │ (`DoctorReport` Model) │  │
 │  └───────────────────────┘           └────────────────────────┘  │
 │  ┌───────────────────────┐           ┌────────────────────────┐  │
 │  │ Connector Registry    │           │ Egress Proxy & Sandbox │  │
 │  │ (Status & Health)     │           │ (Sessions & Blocks)    │  │
 │  └───────────────────────┘           └────────────────────────┘  │
 └──────────────────────────────────────────────────────────────────┘
```

---

## 4. Local Web Security Boundary

### 4.1 Binding & Port Selection
- **Default Address:** `127.0.0.1` (IPv4 loopback).
- **Default Port:** `8765`. If specified port is in use, the operator can provide `--port <PORT>`.
- **Prohibited Address:** `0.0.0.0` or any non-loopback network interface.

### 4.2 Host Header Validation (Anti-DNS Rebinding)
To protect against DNS rebinding attacks (where an external site binds `evil.com` to `127.0.0.1` with a short TTL):
- Every incoming HTTP request MUST supply a `Host` header.
- The `Host` header must strictly match `127.0.0.1:<port>` or `localhost:<port>`.
- Any request with a diverging `Host` header (e.g., `evil.com:8765` or `subdomain.attacker.com`) is immediately rejected with `403 Forbidden: Invalid Host Header`.

### 4.3 Origin & Referer Policy
- For all state-changing HTTP methods (`POST`, `PUT`, `DELETE`):
  - If an `Origin` header is present, it must equal `http://127.0.0.1:<port>` or `http://localhost:<port>`.
  - If `Origin` is omitted, the `Referer` header must start with the valid local origin.
  - Cross-origin requests are rejected with `403 Forbidden: Origin Mismatch`.
  - No `Access-Control-Allow-Origin: *` is ever emitted.

### 4.4 CSRF Protection
- All state-changing requests must include a custom header: `X-Relay-CSRF: <csrf_token>`.
- Standard browser cross-origin forms, images, and links cannot set custom HTTP headers without triggering a preflight request, which is strictly blocked.

### 4.5 Request & Response Constraints
- Maximum HTTP request body size: 1,048,576 bytes (1 MB).
- JSON API request body size: 65,536 bytes (64 KB).
- Responses are bounded (e.g., activity queries default to 20-50 recent items).

---

## 5. Local Authentication & Session Lifecycle

### 5.1 CLI-Issued Ephemeral Token
When `relay ui` is launched:
1. Relay generates a 256-bit cryptographically secure random token (encoded as a 64-character hexadecimal string).
2. Relay prints the localized launch URL to `stdout`:
   ```text
   http://127.0.0.1:8765/?token=4f8b2c...a1
   ```
3. When the browser loads the page, `app.js` extracts the `token` parameter from `window.location.search`.
4. `app.js` immediately scrubs the token from the browser address bar and history via `window.history.replaceState({}, document.title, window.location.pathname)`.
5. The frontend submits the token via `POST /api/v1/auth/session`.
6. Relay validates the token using constant-time comparison, creates an active session record, and returns a session token and a CSRF token.
7. Subsequent API calls attach:
   - `X-Relay-Session: <session_token>`
   - `X-Relay-CSRF: <csrf_token>`

### 5.2 Idle Expiration & Session Lock
- Sessions maintain a `last_active_at` timestamp.
- **Idle Timeout:** 15 minutes of inactivity marks the session expired.
- When expired, API endpoints return `401 Unauthorized: Session Expired`. The UI transitions to an accessible locked screen prompting the operator to re-authenticate or restart `relay ui`.

---

## 6. Browser Threat Model & Protections

| Threat Scenario | Vector | Mitigation in Relay Console |
| :--- | :--- | :--- |
| **Malicious Tab / Website** | User visits `attacker.com` in another tab while Relay UI is active. | Origin check rejects cross-origin POSTs; custom `X-Relay-Session` / `X-Relay-CSRF` headers cannot be attached; CORS denies cross-origin reads. |
| **DNS Rebinding** | Malicious DNS server resolves `rebind.com` to `127.0.0.1`. | Host header verification rejects `Host: rebind.com:<port>`. |
| **Iframe Embedding / Clickjacking** | Malicious site embeds Relay UI in an iframe. | `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` prevent embedding in any frame. |
| **Cross-Site Scripting (XSS)** | Attacker injects HTML into tool arguments or resource URIs. | Strict CSP (`script-src 'self'`); all dynamic UI content is rendered via safe DOM APIs (`textContent`); no `eval()` or `innerHTML` on untrusted inputs. |
| **Credential Theft via UI** | Operator views actions; sensitive credentials leaked in UI source/DOM. | Strict Data Minimization & Secret Scrubber strips PATs, passwords, private keys before JSON serialization. |
| **Direct Connector Execution** | Web client attempts to trigger file deletion or database drop. | The UI exposes zero connector execution endpoints. Execution can only be initiated via the MCP stdio protocol governed by Cedar. |
| **Unauthorized Policy Overwrite** | Malicious script overwrites Cedar policies with `permit(principal, action, resource);`. | Policy reload requires authenticated session + CSRF token + strict Cedar schema validation; failed validation rolls back atomically without modifying active policy. |

---

## 7. UI API Design & Specifications

### 7.1 Read Endpoints

| Method & Path | Auth Required | Description |
| :--- | :--- | :--- |
| `GET /api/v1/status` | Yes | High-level system state, version, security posture, active connector count. |
| `GET /api/v1/doctor` | Yes | Comprehensive diagnostic health checks (reusing `relay doctor` logic). |
| `GET /api/v1/activity` | Yes | List recent governed tool actions with filters for status, tool, and connector. |
| `GET /api/v1/activity/:id` | Yes | Complete 7-stage lifecycle detail for an action. |
| `GET /api/v1/receipts` | Yes | List DSSE action receipts stored in the ledger. |
| `GET /api/v1/receipts/:id` | Yes | Complete DSSE envelope and in-toto v1.0 statement for a receipt. |
| `GET /api/v1/receipts/:id/export`| Yes | Export scrubbed, verifiable canonical JSON receipt. |
| `GET /api/v1/ledger/status` | Yes | Ledger entry count, head sequence number, genesis hash, head hash. |
| `GET /api/v1/policies` | Yes | Active Cedar policies, schema version, policy digest (SHA-256). |
| `GET /api/v1/connectors` | Yes | Operational state and security boundaries of all connectors. |
| `GET /api/v1/egress` | Yes | Egress loopback proxy status, sandbox mode, active sessions, blocked targets. |
| `GET /api/v1/security` | Yes | Trust boundary diagrams, platform limitations, and security invariant registry. |

### 7.2 Write Endpoints

| Method & Path | Auth Required | CSRF Required | Description |
| :--- | :--- | :--- | :--- |
| `POST /api/v1/auth/session` | Token | No (Bootstrap) | Exchange initial CLI token for session and CSRF tokens. |
| `POST /api/v1/receipts/:id/verify` | Yes | Yes | Perform independent Ed25519 cryptographic signature verification. |
| `POST /api/v1/ledger/verify` | Yes | Yes | Perform cryptographic SHA-256 hash-chain verification from genesis. |
| `POST /api/v1/policies/validate` | Yes | Yes | Validate proposed Cedar policy syntax against schema without applying. |
| `POST /api/v1/policies/reload` | Yes | Yes | Safely reload active policies from disk with validation & rollback. |

---

## 8. UI Data Minimization & Secret Redaction

The console strictly follows the data categorization established in `CR001-UI-001`:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        DATA EXPOSURE BOUNDARIES                        │
├────────────────────────────────────────────────────────────────────────┤
│ 1. SAFE (Public in UI)                                                 │
│    Action status, ActionHash, Tool name, Principal, Resource URI,      │
│    Policy decision, Determining policies, Timestamps, Hash digests,   │
│    Verification results, Sandbox modes, Ledger sequence numbers.       │
├────────────────────────────────────────────────────────────────────────┤
│ 2. RESTRICTED (Redacted / Sanitized Preview)                           │
│    Tool arguments (scrubbed of secret patterns), SQL queries           │
│    (normalized/sanitized), Filesystem paths (lexically normalized).    │
├────────────────────────────────────────────────────────────────────────┤
│ 3. PROHIBITED (Never Serialized or Sent to Browser)                    │
│    Raw API tokens (GitHub PATs, AWS keys), database passwords,         │
│    Ed25519 private signing keys, OS keyring secret values,             │
│    session proxy lease tokens, Authorization headers.                  │
└────────────────────────────────────────────────────────────────────────┘
```

All payloads undergo rigorous automated scrubbing using `relay_receipts::scrub` regex patterns prior to serialization.

---

## 9. Seven-Stage Action Lifecycle Visualization

The UI renders the exact 7-stage pipeline that governed actions traverse:

```text
┌───────────┐     ┌───────────┐     ┌───────────┐     ┌───────────┐
│ 1. Action │ ──► │ 2. Policy │ ──► │ 3.Approval│ ──► │4.Cred Lease│
│ (Proposal)│     │  (Cedar)  │     │ (/dev/tty)│     │(JIT Vault)│
└───────────┘     └───────────┘     └───────────┘     └───────────┘
                                                            │
┌───────────┐     ┌───────────┐     ┌───────────┐           │
│ 7. Ledger │ ◄── │6. Receipt │ ◄── │5.Execution│ ◄─────────┘
│  (SQLite) │     │  (DSSE)   │     │ (Native)  │
└───────────┘     └───────────┘     └───────────┘
```

Each stage is accompanied by immutable cryptographic evidence:
- **Action:** Proposal canonical ActionHash (RFC 8785 JCS).
- **Policy:** Cedar `ALLOW` or `DENY`, matching policy IDs, policy set digest.
- **Approval:** Mechanism (`NOT_REQUIRED`, `INTERACTIVE_TTY`, `HEADLESS`), Approver, Decision.
- **Credential Lease:** Lease ID, Provider type, Key alias, Scope, Zero secret material.
- **Execution:** Connector, Operation, Duration ms, Execution status.
- **Receipt:** Receipt ID, DSSE envelope, Ed25519 signature status.
- **Ledger:** Sequence number, Current hash, Parent hash.

---

## 10. Embedded Static Asset & Content Security Policy

### 10.1 Asset Packaging
- No external node modules, build steps, or CDNs required at runtime.
- Static assets (`index.html`, `app.css`, `app.js`, `favicon.svg`) are located in `crates/relay-cli/src/ui/assets/` and compiled directly into the binary using `include_str!`.
- Total uncompressed frontend payload is under 60 KB.

### 10.2 Restrictive Security Headers
Every HTTP response emitted by the Relay console includes:
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
```

---

## 11. Acceptance & Verification Criteria

This specification forms the baseline for Milestone CR002. Compliance is verified against:
- `cr002_ui_security_tests.rs`: Comprehensive automated security test suite.
- `cr002-privacy-audit.md`: Verification of zero outbound data transmission.
- `CR002-security-review.md`: Formal adversarial review of browser attack vectors.
- Clean compilation and 100% test pass rate across the workspace.
