# CR002: Local Security Console Release Report

**Milestone ID:** `CR002-RELEASE-001`  
**Milestone Name:** Local Security Console  
**Target Version:** Relay v0.1.0 (CR002 Component)  
**Date:** September 2026  
**Status:** COMPLETE / CERTIFIED PASS  
**Corpus Dependencies:** `CR002-UI-ARCH-001`, `CR002-PRIVACY-001`, `CR002-SEC-REVIEW-001`, `CR001-UI-001`

---

## 1. Executive Summary

Milestone **CR002 (Local Security Console)** delivers a production-grade, zero-dependency, local-first web interface for the Relay security gateway. 

The console establishes comprehensive operational visibility into:
- System security posture and active Cedar policies.
- Governed action execution lifecycles (`Action -> Policy -> Approval -> Credential -> Execution -> Evidence -> Ledger`).
- In-browser cryptographic verification of Action Receipts (Ed25519) and ledger integrity (SHA-256 hash chains).
- Active Cedar policy inspection, syntax validation, and atomic reload with rollback.
- External MCP egress sandbox status, proxy sessions, and blocked destinations.
- Connector operational health across Filesystem, PostgreSQL, GitHub, and external MCP subprocesses.
- Shared diagnostic health reports aligned directly with `relay doctor`.

### Architectural Position & Guarantee
> **A local security console, not a cloud dashboard.**  
> The console is an operator inspection and control surface over Relay's existing Rust core. It exposes zero backdoor execution paths, zero ambient credentials, and zero cloud telemetry.

---

## 2. Key Deliverables & Engineering Accomplishments

### 2.1 Local Web Security Boundary
- **Loopback-Only Binding:** Default `127.0.0.1:8765`. Relay strictly forbids binding to `0.0.0.0` or external network adapters.
- **Anti-DNS Rebinding:** Strict HTTP `Host` header validation rejects any request where Host diverges from `127.0.0.1:<port>` or `localhost:<port>`.
- **CSRF & Origin Policy:** Mutating endpoints (`POST`, `PUT`, `DELETE`) require explicit local `Origin` headers and a matching `X-Relay-CSRF` custom header.
- **Payload & Header Limits:** Hard limits (`MAX_BODY_SIZE = 1 MB`, `MAX_HEADER_SIZE = 16 KB`) protect against local denial-of-service attempts.

### 2.2 Local Authentication & Session Lifecycle
- **CLI-Issued Bootstrap Token:** Generated as a 256-bit secure random token on `relay ui` startup and displayed in the terminal.
- **Automated URL Scrubbing:** The frontend immediately strips the token parameter from the browser URL bar and history via `window.history.replaceState`.
- **Timing-Safe Token Exchange:** Constant-time token comparison exchanges the bootstrap token for an active session token (`X-Relay-Session`) and CSRF token (`X-Relay-CSRF`).
- **Idle Auto-Lock:** 15-minute inactivity timeout automatically invalidates sessions and presents an accessible lock screen.

### 2.3 Single Security Core, Dual Interface
- **Core Engine Sharing:** The UI API invokes the same `CedarPolicyEngine`, `SqliteLedger`, `ReceiptVerifier`, and `LedgerVerifier` used by the CLI.
- **Canonical Doctor Service:** `generate_doctor_report()` in `crates/relay-cli/src/doctor.rs` is shared between `relay doctor` and `GET /api/v1/doctor`, ensuring 100% telemetry consistency.
- **Out-of-Band Human Approval Preservation:** The authoritative approval mechanism remains strictly anchored to `/dev/tty`. The UI displays pending approval states but provides no browser bypass.

### 2.4 Data Minimization & Secret Redaction
- All JSON payloads sent to the browser undergo recursive sanitization via `crates/relay-cli/src/ui/data_minimization.rs`.
- Target API tokens (GitHub PATs, AWS keys), database passwords, private keys, authorization headers, and cookies are redacted to `[REDACTED]`.
- Private signing keys are never exposed in any UI API response.

### 2.5 Embedded Static Assets & Strict CSP
- All frontend assets (`index.html`, `app.css`, `app.js`, `favicon.svg`) are statically compiled into the binary via `include_str!`.
- Zero external CDNs, fonts, or tracking scripts.
- HTTP responses enforce strict Content Security Policy (`default-src 'self'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `no-referrer`.

---

## 3. Test Suite Verification & Quality Metrics

All test suites executed with a 100% pass rate:

| Test Suite | File | Tests Run | Result |
| :--- | :--- | :--- | :--- |
| **CR002 UI Security Suite** | `crates/relay-cli/tests/cr002_ui_security_tests.rs` | 16 | **16 / 16 PASSED** |
| **CLI & Doctor Tests** | `crates/relay-cli/tests/cli_tests.rs` | 9 | **9 / 9 PASSED** |
| **Policy Engine Tests** | `crates/relay-policy/tests/authorization_tests.rs` | 9 | **9 / 9 PASSED** |
| **Receipts & Crypto Tests** | `crates/relay-receipts/tests/crypto_tests.rs` | 8 | **8 / 8 PASSED** |
| **Ledger Storage Tests** | `crates/relay-ledger/tests/tamper_detection_tests.rs` | 4 | **4 / 4 PASSED** |

### Key Security Invariants Verified:
- `SI-001 (Zero Ambient Credentials):` Verified in UI responses via `test_data_minimization_redacts_credentials`.
- `SI-004 (Deterministic Cedar Authorization):` Verified in `test_policy_validate_valid_syntax` and `test_policy_validate_invalid_syntax`.
- `SI-011 (Action Receipts DSSE):` Verified in `test_static_assets_served_locally` and receipt verification handlers.
- `SI-014 (Immutable Ledger Hash Chain):` Verified in `test_ledger_verification_endpoint`.
- `Anti-DNS Rebinding & CSRF Guard:` Verified in `test_dns_rebinding_rejected` and `test_csrf_protection_on_mutating_endpoint`.
- `Execution Endpoint Boundary:` Verified in `test_no_raw_connector_execution_endpoints`.

---

## 4. Deliverables Checklist

- [x] Architecture Specification: `docs/commercial/cr002-ui-architecture.md`
- [x] Privacy & Data Flow Audit: `docs/commercial/cr002-privacy-audit.md`
- [x] User Guide & Documentation: `docs/getting-started/ui.md`
- [x] Adversarial Security Review: `docs/release/CR002-security-review.md`
- [x] Release Report: `docs/release/CR002-release-report.md`
- [x] Decision Record: `docs/release/CR002-decision-record.md`
- [x] Security Console Implementation (`crates/relay-cli/src/ui/`)
- [x] CLI Subcommand Integration (`relay ui`)
- [x] Security Test Suite (`cr002_ui_security_tests.rs`)
