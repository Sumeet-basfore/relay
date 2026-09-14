# Relay Commercial Security Addendum Specification

**Document ID:** `CR003-SEC-001`  
**Version:** `1.0.0`  
**Status:** Security Addendum Specification  
**Date:** 2026-09-14  

---

## 1. Scope & Objective

This Commercial Security Addendum specifies the technical, cryptographic, and operational security commitments that Relay provides to commercial customers. It establishes clear boundaries between Relay-operated commercial systems, open-core software execution, and customer-managed infrastructure.

---

## 2. Core Security Invariants & Software Commitments

### 2.1 Local Execution Architecture
- **Air-Gapped Operation:** The Relay daemon and core execution engine run entirely on customer-managed hardware or cloud instances. No internet connection to Relay infrastructure is required for normal operation.
- **Zero Prompt & Tool Egress:** Relay software is compiled without telemetry frameworks, analytics trackers, or automated log-shipping logic directed at Relay-operated servers.
- **Ambient Credential Scrubbing:** Relay acts as a mediating credential proxy. Ambient target credentials (e.g. GitHub PATs, PostgreSQL passwords) are bound locally to the operating system credential manager and never exposed to the agent LLM prompt context or command-line parameters.

### 2.2 Cryptographic Integrity
- **Action Receipts:** Relay generates cryptographically signed Action Receipts using Ed25519 DSSE envelopes for governed executions.
- **Tamper-Evident Ledger:** Local receipts are appended to an immutable, hash-chained SQLite ledger (`SHA-256` hashing and Merkle progression).
- **Verification Guarantee:** Relay provides public, deterministic verification algorithms (`relay verify`) capable of independently validating ledger integrity without contacting Relay.

---

## 3. Commercial Services & Infrastructure Security

Where commercial customers interact with Relay-operated services (e.g. license issuance, commercial website, support channels):
1. **Transport Security:** All web traffic to commercial infrastructure requires modern TLS (TLS 1.3 preferred; TLS 1.2 minimum) with strict HTTPS enforcement and HTTP Strict Transport Security (HSTS).
2. **Payment Card Industry (PCI) Isolation:** All payment operations are outsourced to Stripe under PCI DSS Level 1 compliance. Relay never ingests, transmits, or stores credit card numbers, CVVs, or bank routing secrets.
3. **Least Privilege Internal Access:** Access to commercial billing databases and customer support queues is restricted to authorized employees, strictly conditioned upon multi-factor authentication (MFA) and least-privilege role definitions.

---

## 4. Vulnerability Disclosure & Patch Management

### 4.1 Vulnerability Handling Commitments
- **Dedicated Reporting Channel:** Relay maintains a monitored security disclosure address at `security@relay.dev` with public PGP keys available.
- **Acknowledgment:** Relay will make reasonable commercial efforts to acknowledge private vulnerability reports within two (2) business days.
- **Triage & Validation:** Relay will evaluate and score reported issues using CVSS v3.1 within seven (7) business days.
- **Coordinated Disclosure:** Relay commits to coordinating public disclosures with finders, allowing reasonable remediation windows prior to public notification.

### 4.2 Security Update Distribution
- Critical security advisories are published with CVE identifiers and distributed via GitHub Security Advisories and release manifests signed with Relay's release signing key.

---

## 5. Realistic Commitments & Explicit Exclusions

To ensure strict legal and operational accuracy, Relay explicitly does **not** warrant or commit to:
1. **Unilateral Breach Timelines:** Incident and regulatory notification timelines are governed by applicable law and counsel assessment, not contractual arbitrary hourly targets.
2. **Third-Party Infrastructure Uptime:** Relay does not warrant the uptime or latency of third-party model providers (e.g. OpenAI, Anthropic) or upstream target services.
3. **Mandatory Third-Party Certifications:** Relay does not falsely claim active SOC 2 Type II or ISO 27001 certifications until formal audits are completed.

---

## 6. Customer Security Responsibilities

Customer acknowledges and agrees that the customer retains sole responsibility for:
- Operating system hardening, patching, and malware defense on machines running Relay.
- Safeguarding local master encryption keys, Ed25519 receipt-signing private keys, and OS keyring passwords.
- Defining, testing, and reviewing Cedar authorization policies to ensure they align with customer risk tolerance.
- Exercising reasonable human oversight when responding to interactive `/dev/tty` approval requests.
