# Relay CR003 — Commercial Model Specification

**Document ID:** `CR003-COM-001`  
**Version:** `1.0.0`  
**Status:** Frozen Commercial Model Specification  
**Classification:** Strategic Business & Architectural Policy  
**Effective Date:** 2026-09-14  

---

## 1. Executive Summary & Philosophy

Relay operates under **Model B: Local-First Apache 2.0 Open Core + Optional Commercial Services**.

Our primary commercial philosophy is anchored in two immutable rules:
1. **Core Security Invariant:** *Payment status is never authorization status.* An enterprise customer cannot buy a bypass of Cedar policy enforcement, cryptographic receipt signing, local credential brokering, or human-in-the-loop interactive approvals.
2. **Local-First Autonomy:** The Apache 2.0 open core is 100% functional, self-contained, and air-gapped without any requirement to contact Relay-operated cloud infrastructure, transmit telemetry, or acquire a commercial license key.

---

## 2. Open Core vs. Commercial Boundary Matrix

| Capability / Layer | Free (Apache 2.0 Open Core) | Paid (Pro / Enterprise) |
| :--- | :---: | :---: |
| **Relay Core Engine & Daemon** | Fully Included | Fully Included (identical binary) |
| **Relay CLI (`init`, `run`, `doctor`, `inspect`, `verify`, `secret`, `ui`)** | Fully Included | Fully Included |
| **Cedar Policy Engine** | Full Default-Deny & Local Evaluation | Full Default-Deny & Local Evaluation |
| **Local Credential Brokering** | OS Keyring & Process Isolation | OS Keyring & Process Isolation |
| **Native Connectors** | Filesystem, PostgreSQL, GitHub | Filesystem, PostgreSQL, GitHub |
| **External MCP Mediation** | Anti-SSRF, Stdio, Unix Sockets | Anti-SSRF, Stdio, Unix Sockets |
| **Action Receipts & Ledger** | Ed25519 DSSE Receipts & SQLite Ledger | Ed25519 DSSE Receipts & SQLite Ledger |
| **Local Security Console (`relay ui`)** | Loopback Zero-Trust Web Console | Loopback Zero-Trust Web Console |
| **Offline License Entitlement** | Not Applicable (No license needed) | Signed Ed25519 Offline License Key |
| **Support SLA** | Community (GitHub Discussions) | 24-Hour Business SLA / Dedicated Slack |
| **Managed Policy Bundles** | Manual Cedar files on disk | Digitally Signed Enterprise Policy Packs |
| **Compliance & SIEM Export** | Individual CLI export | Automated Batch Compliance Export Formats |
| **Commercial Warranty & Indemnity** | Disclaimed (AS-IS per Apache 2.0) | Enterprise Contractual IP Indemnification |

---

## 3. What Free / Open Core Users Receive

Every user downloading the public Relay binary or building from source receives:
1. **Unconditional Sovereignty:** Zero phone-home pings, zero telemetry, zero cloud tracking, and zero forced account creation.
2. **Complete Security Controls:** All 24 Security Invariants (SI-001 through SI-024) are fully active in open source.
3. **Local Management:** The full local security console (`relay ui`) running on `127.0.0.1` with session auth, CSRF defenses, and audit viewers.
4. **Permanent Usability:** The binary will never lock out the user, expire, or throttle execution based on time or external SaaS outages.

---

## 4. What Commercial Customers Pay For

Commercial customers pay exclusively for operational scale, legal risk reduction, and enterprise integration:
1. **Commercial Support & SLA:**
   - Guaranteed response times (24-hour response on business days for Pro; custom 4-hour critical response for Enterprise).
   - Direct engineering access for architecture reviews, policy authoring, and connector onboarding.
2. **Cryptographically Signed Offline Entitlements:**
   - Multi-seat deployment licensing with tamper-evident Ed25519 signed certificates.
   - Machine-verifiable organization attestation for enterprise governance.
3. **Enterprise Compliance & Audit Packs:**
   - Structured export utilities for SOC 2, ISO 27001, and HIPAA auditor review.
   - Cryptographic chain-of-custody reports verifying ledger integrity across distributed agent fleets.
4. **Legal Protection & Commercial Assurance:**
   - Contractual enterprise terms replacing standard Apache 2.0 disclaimers.
   - Intellectual property non-infringement indemnification.
   - Enterprise Data Processing Addendum (DPA) where applicable for commercial services.

---

## 5. Architectural Integrity Constraints

To maintain trust and architectural integrity:
- **No Metered Tool Calling:** Relay does **not** charge by tool call volume, token counts, or prompt invocations. Pricing is seat-based and organization-based.
- **No Artificial Crippleware:** We do not artificially throttle local execution speed or limit receipt storage to force upgrades.
- **Strict Separation of Concerns:** Commercial license validation is decoupled from the Cedar policy engine. Even if an enterprise license expires, the engine remains operable in open-core mode without data loss.
