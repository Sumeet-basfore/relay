# Relay Operations: PB001 Incident Tabletop Simulation Exercises

**Document ID:** `PB001-OPS-002`  
**Milestone:** PB001 — Private Paid Beta & Production Operations  
**Exercise Date:** 2026-09-14  
**Classification:** Operational Security & Incident Response Record  
**Target:** Operational Readiness Verification for Private Paid Beta  

---

## Exercise 1: Suspected Target Credential Exposure

### 1. Incident Scenario Description
At 14:15 UTC, a beta customer's security engineer emails `security@relay.dev` reporting that a database password vaulted in Relay appears to have been logged in an upstream target service log file following an agent execution session.

---

### 2. Execution Runbook Walkthrough

```text
┌──────────┐     ┌───────────┐     ┌─────────────┐     ┌────────────┐
│ 1.Intake │ ──► │2.Severity │ ──► │3.Containment│ ──► │4.Evidence  │
└──────────┘     └───────────┘     └─────────────┘     └────────────┘
                                                             │
┌──────────────┐     ┌──────────────┐     ┌──────────────┐   ▼
│ 8.Postmortem │ ◄── │ 7.Disclosure │ ◄── │6.Remediation │ ◄─┴──────────┐
└──────────────┘     └──────────────┘     └──────────────┘   │5.Customer  │
                                                             └────────────┘
```

#### Step 1: Intake & Triage (T+0h15m)
- The on-call security engineer acknowledges the report within 30 minutes.
- Opened internal incident ticket `SEC-INC-2026-001` per `docs/security/incident-response.md`.
- Request sanitized configuration and anonymized log snippet from customer.

#### Step 2: Severity Assessment (T+0h45m)
- Scored against CVSS v3.1: Confidentiality Impact High, Privileges Required None (agent prompt).
- Classification: **Class 1 Security Incident** (Upstream credential boundary failure, potential SI-003 violation).

#### Step 3: Immediate Containment (T+1h00m)
- **Customer Action:** Advise customer to immediately revoke the exposed database password at the PostgreSQL server and provision a fresh credential.
- **Relay Action:** Check whether the token pattern was escaped or omitted from Relay's `SecretScrubber` rules.

#### Step 4: Evidence Preservation & Reproduction (T+2h00m)
- Reproduce the agent tool call sequence in an isolated test harness using `wiremock` and local Postgres testcontainer.
- Test findings: Relay's credential broker correctly replaced the secret in the subprocess arguments, but the target connector's error response contained the upstream database connection string reflected in an unscrubbed error payload.

#### Step 5: Customer Contact & Advisory (T+3h30m)
- Provide customer with exact technical root cause analysis.
- Confirm that the credential did not leak to Relay-operated systems (it remained between the customer's machine and their local database).

#### Step 6: Remediation & Patch Engineering (T+6h00m)
- Enhance `SecretScrubber` in `crates/relay-receipts/src/scrub.rs` to recursively scrub upstream database error strings.
- Add dedicated regression test in test suite.
- Re-run all security regression tests (`cargo test --workspace --all-features`).

#### Step 7: Coordinated Disclosure Decision (T+24h00m)
- Legal counsel and security team determine whether external regulatory notification is triggered.
- Finding: Since no data left the customer's infrastructure and no Relay cloud systems were breached, no regulatory DPDP/GDPR breach report is required for Relay; customer handles internal rotation.
- Issue patch release `v0.1.1` with CVE identifier and release notes crediting finder.

#### Step 8: Postmortem & Retrospective (T+72h00m)
- Document lessons learned in `docs/security/incident-response.md`.
- Enhance automated CI fuzzing for database connector error reflections.

---

## Exercise 2: Forged Commercial License Bypass Attempt

### 1. Incident Scenario Description
During the private beta, an organization attempts to deploy an altered license file with modified claims (elevating seat count from 5 to 5,000) or using a cracked public key.

---

### 2. Execution Runbook Walkthrough

#### Step 1: Detection & Local Behavior
- The customer installs Relay on a cluster and places the modified `license.json` on the nodes.
- Local Relay startup invokes `LicenseCertificate::verify_with_crl()`.
- Result: **Mathematical rejection.** Because Ed25519 signatures are computed over canonical JCS bytes, altering a single character in `seat_count` causes signature verification to fail immediately (`EntitlementError::InvalidSignature`).
- Crucial Verification: Relay outputs `[WARN] Commercial license verification failed. Operating in Apache 2.0 open-core mode.`
- **Open-Core Invariant Holds:** Basic execution, Cedar default-deny policies, and local receipt generation continue without interruption.

#### Step 2: Investigation & Revocation
- If a leaked private signing key is ever suspected, the security team invokes the **Hybrid Revocation Strategy (Phase 5)**:
  1. Generate a signed Certificate Revocation List (`crl_emergency_YYYY_MM.json`) containing the compromised license ID.
  2. Sign with the root offline authority key.
  3. Publish to GitHub Releases and distribute with release manifests.
- Relay instances loaded with the updated CRL immediately reject the revoked license ID (`EntitlementError::LicenseRevoked`).

#### Step 3: Postmortem Findings
- The offline verification architecture successfully prevented privilege escalation without requiring online DRM or telemetry tracking.
- Non-interference invariant remained 100% intact: security was neither weakened nor disabled.
