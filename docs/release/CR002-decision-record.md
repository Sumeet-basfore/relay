# CR002: Local Security Console Milestone Decision Record

**Document ID:** `CR002-DECISION-001`  
**Version:** `1.0.0`  
**Date:** September 2026  
**Status:** Certified Approved Baseline  
**Target Milestone:** Relay CR002 (Local Security Console)  
**Corpus Dependencies:** `CR002-UI-ARCH-001`, `CR002-PRIVACY-001`, `CR002-SEC-REVIEW-001`, `CR002-RELEASE-001`

---

## 1. Context & Architectural Assessment

Milestone CR002 implements the Local Security Console for Relay under Commercial Model B (Local-First Open Core). The objective was to provide operators with comprehensive, real-time visibility into the security posture, governed actions, Cedar policy decisions, cryptographic action receipts, ledger hash-chains, and external MCP network egress sandbox states without turning Relay into a cloud telemetry or SaaS analytics platform.

The architectural posture mandates:
```text
CLI ──────────────┐
                  │
                  ▼
             Relay Core
                  │
                  ├── Cedar
                  ├── Credentials
                  ├── Connectors
                  ├── Egress
                  ├── Receipts
                  └── Ledger
                  ▲
                  │
Local UI ─────────┘
```

The browser UI is strictly an observer and controlled management interface over Relay's existing security core. It is never an alternate execution path or a shortcut around Cedar policies, JIT credentials, or out-of-band approval gates.

---

## 2. Evaluation Summary

1. **Locality & Privacy:** The console binds exclusively to `127.0.0.1`. Binding to `0.0.0.0` is prohibited. All assets are statically embedded in the binary. Zero external CDN, font, or telemetry requests occur.
2. **Local Web Security Boundary:** Strict HTTP `Host` header validation mitigates DNS rebinding attacks. Custom CSRF tokens and local `Origin` checks protect all mutating endpoints.
3. **Authentication:** A CLI-issued 256-bit ephemeral token is exchanged via constant-time comparison for a session token with a 15-minute idle expiration.
4. **Data Minimization & Redaction:** Credentials, PATs, database passwords, private keys, and authorization headers are scrubbed and redacted to `[REDACTED]` prior to serialization.
5. **Authentic Cryptographic Verification:** In-browser verification triggers real `ReceiptVerifier` (Ed25519) and `LedgerVerifier` (SHA-256 hash chains) implementations.
6. **Policy Safety:** Cedar policies are validated against the schema before reload; invalid policies cause an atomic rollback without disrupting active protection.
7. **Approval Security Boundary Preserved:** Authoritative approvals remain on `/dev/tty`. The UI does not provide a web click bypass for human-in-the-loop decisions.

---

CR002 LOCAL SECURITY CONSOLE — FINAL VERDICT

Architecture:
PASS

Local Security:
PASS

Authentication:
PASS

API Security:
PASS

Privacy:
PASS

Security Visualization:
PASS

Policy Management:
PASS

Evidence / Ledger:
PASS

External MCP Visibility:
PASS

Browser Security:
PASS

UX:
PASS

Commercial Boundary:
PASS

Release Readiness:
READY

Security Boundary:
The Relay Local Security Console operates strictly as a local loopback (127.0.0.1) view and controlled management surface over Relay's existing Cedar authorization, JIT credential broker, and cryptographic ledger engines. It introduces zero alternate tool execution paths, exposes zero ambient credentials or private signing keys, and preserves the out-of-band /dev/tty human approval boundary.

Known Limitations:
- On non-Linux platforms (macOS, Windows), network egress sandboxing operates in Managed Cooperative Proxy Mode; kernel-level raw socket blocking is unavailable without root containerization or hypervisor VMs.
- Browser sessions expire after 15 minutes of idle inactivity, requiring re-entry of the CLI-issued session token.
- Authoritative approvals for sensitive operations must be confirmed on the controlling terminal (/dev/tty) and cannot be approved directly via browser clicks.

Security Findings:
- None. All simulated local web attacks (DNS rebinding, CSRF, XSS, oversized payload DoS, direct execution bypassing) were successfully mitigated and verified by automated tests.

Blocking Issues:
- None.

Accepted Risks:
- An attacker with root / OS administrative compromise on the local machine can inspect local process memory or UDS sockets, which is explicitly outside Relay's host OS trust boundary.

Tests:
16 passed / 0 failed (CR002 UI Security Suite); 100% pass rate across workspace regression suites.

Next Milestone:
CR003 — Legal & Commercial Launch Readiness
