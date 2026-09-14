# Relay EB001 — Extended Private Beta Charter

**Document ID:** `EB001-CHA-001`  
**Milestone:** EB001 — Extended Private Beta & Commercial Validation  
**Effective Window:** Q3–Q4 2026  
**Classification:** Authoritative Commercial Program Charter  
**Version:** `1.0.0`  

---

## 1. Program Mission & Purpose

The objective of the **Relay Extended Private Beta (EB001)** is to validate Relay as a viable, scalable commercial product without destabilizing or diluting its proven security architecture.

### The Four Dimensions of Readiness:
1. **Technical Readiness:** Relay `v0.1.0` binary and Local Security Console are stable, performant, and pass all formal security invariant test suites.
2. **Commercial Readiness:** Stripe billing, offline Ed25519 entitlement licensing, 30-day term limits, and emergency CRL revocation function reliably without human intervention.
3. **Legal Readiness:** Corporate incorporation is complete (`Relay Security Technologies Private Limited`), and all customer-facing legal terms (Privacy Policy, Terms of Service, DPA, Refund Policy) are approved by legal counsel.
4. **Customer Readiness:** Diverse engineering teams can independently install, configure Cedar policies, vault credentials, inspect receipts, and operate the web console without hands-on assistance from Relay engineers.

---

## 2. The Critical Security Freeze

During this milestone, Relay enforces a strict architectural freeze:
- **No Compromises on Security:** We do not weaken Cedar default-deny, weaken OS credential isolation, or disable subprocess sandboxing for customer convenience.
- **No Client Telemetry:** No tracking beacons, analytics SDKs, or background telemetry pings will be added to the Relay binary.
- **No Centralization of Execution Data:** Prompts, agent arguments, target credentials, receipts, and SQLite ledger records remain strictly on customer-managed machines.
- **Separation Invariant:** *Payment Status ≠ Authorization Status.* A valid Enterprise license key will never be permitted to bypass Cedar authorization rules.
- **Roadmap Boundary:** All non-critical feature requests are deferred to the `v0.2.0` roadmap.

---

## 3. Scope & Eligible Customer Profiles

### Supported Platforms:
- **Linux:** x86_64 and aarch64 (Ubuntu 20.04+, Debian 11+, RHEL/CentOS 8+, Alpine 3.18+) with `libsecret` and Linux Network Namespaces.
- **macOS:** Apple Silicon (M1/M2/M3/M4) and Intel x86_64 (macOS 12.0 Monterey+) with Apple Keychain vaulting.
- **Windows:** Windows 10/11 and Windows Server 2022 (x86_64) with Windows Credential Manager.

### Supported Use Cases:
1. **Autonomous Coding & Dev Agents:** Sandboxed filesystem and repository access via the GitHub connector.
2. **Database Analytics & Migration Agents:** Read-only and bound PostgreSQL query execution with AST validation.
3. **Multi-Tool Orchestration:** Mediating external Model Context Protocol (MCP) servers with anti-SSRF and loopback protection.

---

## 4. Support Expectations & SLA Commitments

- **Dedicated Channels:** `support@relay.dev` (Technical), `billing@relay.dev` (Commercial), `security@relay.dev` (Vulnerabilities).
- **Service Level Agreements (SLAs):**
  - **Pro Tier:** 24 business hours response time.
  - **Enterprise Tier:** 4 hours response time for critical issues.
  - **Security Disclosures:** Mandatory 48-hour initial acknowledgment.
- **Zero-Secret Mandate:** Support personnel are strictly prohibited from asking for or accepting customer credentials, private keys, or raw production ledgers.

---

## 5. Commercial Terms & Pricing

- **Community (Free):** 100% Apache 2.0 open-core runtime and local web console (`relay ui`).
- **Team Pro:** $49 / seat / month (or $39 / seat / month billed annually). Includes offline signed license key, 24h SLA, signed policy bundles.
- **Enterprise:** Custom annual contract. Includes 4h SLA, custom DPA with SCCs, procurement assistance, and compliance audit packages.
- **Refund Policy:** 14-day no-questions-asked satisfaction guarantee on all initial subscriptions.

---

## 6. Exit Criteria for Public Commercial Launch (GA)

The Extended Private Beta terminates and declares **READY FOR PUBLIC PAID LAUNCH** when:
1. At least 10 independent enterprise customers complete onboarding and execute production agent workloads.
2. Customers demonstrate clear, unprompted comprehension of Relay's security boundary and local data ownership.
3. Zero unresolved P0 (security/data boundary) or P1 (safe operation blocked) issues exist.
4. Automated billing, webhook replay protection, offline entitlement, and emergency CRL revocation perform with 100% reliability.
5. Retained legal counsel approves transition to open public checkout.
