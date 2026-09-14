# Relay Security: Incident Response & Key Compromise Runbook

**Document ID:** `SEC-IR-001`  
**Classification:** Authoritative Security Operational Runbook  
**Target:** Relay `v0.1.x`  

---

## 1. Key & Credential Taxonomy

To ensure precise incident containment, Relay distinguishes between three separate classes of cryptographic and authorization material:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. Release Signing Authority (Distribution Layer)                           │
│    - Role: Signs public release tarballs and SHA256SUMS manifests.          │
│    - Scope: Global project distribution integrity.                          │
├─────────────────────────────────────────────────────────────────────────────┤
│ 2. Relay Receipt-Signing Keys (Local Control Plane Layer)                   │
│    - Role: Ed25519 keypair used by Relay to sign DSSE Action Receipts.      │
│    - Scope: Local SQLite ledger tamper-evidence and audit verification.     │
├─────────────────────────────────────────────────────────────────────────────┤
│ 3. Target Service Credentials (Upstream Resource Layer)                     │
│    - Role: Vaulted API tokens (GitHub PATs, AWS IAM keys, Postgres secrets).│
│    - Scope: Upstream service authentication during governed execution.       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Incident Runbook 1: Release Signing-Key Compromise

**Trigger:** Release signing private key is leaked, stolen, or suspected compromised.

1. **Immediate Revocation:**
   - Revoke the compromised release key from project distribution servers and key directories.
   - Publish an immediate revocation notice on the project homepage and security channels.
2. **Artifact Audit & Taint Analysis:**
   - Compute SHA-256 digests of all distributed packages in `dist/`.
   - Identify any unauthorized binaries or modified packages.
3. **Key Generation & Re-Signing:**
   - Provision a new Ed25519 release signing key on an offline hardware HSM.
   - Re-sign verified canonical release packages.
   - Publish updated `SHA256SUMS` signed by the new key.
4. **Advisory Publication:**
   - Issue a high-priority security advisory instructing users to re-verify installed binaries.

---

## 3. Incident Runbook 2: Relay Receipt-Signing Key Compromise

**Trigger:** A local Relay instance's Ed25519 signing key (`.relay/signing_key.ed25519` or OS keyring) is exposed.

1. **Historical Ledger Snapshot:**
   - Create an immediate immutable read-only snapshot of `.relay/ledger.db`.
   - Run `relay verify` to record the exact cryptographic state and last valid sequence number prior to compromise.
2. **Key Rotation:**
   - Delete the compromised key from disk/keyring.
   - Execute `relay init` or launch Relay to generate a fresh Ed25519 keypair.
   - Re-initialize ledger genesis entry with the new public key.
3. **Audit Trail Documentation:**
   - Mark historical receipts up to sequence $N$ as verified under previous key; all subsequent entries are bound to the new key ID.

---

## 4. Incident Runbook 3: Target Service Credential Exposure

**Trigger:** A target API key, database password, or GitHub PAT is observed in external logs or leaked.

1. **Upstream Revocation:**
   - Immediately revoke the token at the upstream provider (GitHub, AWS, database host).
2. **Exposure Path Analysis:**
   - Inspect Relay receipt scrubber logs (`SecretScrubber`) to confirm whether the credential was leaked through a non-standard format.
   - Check subprocess environments and command-line arguments.
3. **Credential Re-Provisioning:**
   - Generate a replacement credential with least-privilege scoping.
   - Store the new secret into Relay's vaulted provider (`relay secret set ...`).
4. **Pattern Database Update:**
   - If the leak occurred due to an unmodeled token pattern, add the regex to `crates/relay-receipts/src/scrub.rs` and deploy a patch.

---

## 5. Incident Runbook 4: Security Boundary / Invariant Violation

**Trigger:** A report or internal discovery of a Cedar PEP bypass, sandbox escape, or anti-SSRF failure.

1. **Reproduction & Triage:**
   - Reproduce the vulnerability within a clean isolated sandbox environment.
   - Determine affected invariants (e.g. SI-004, SI-022, SI-023).
2. **Temporary Mitigation:**
   - Provide immediate policy-level workarounds (e.g. strict Cedar `forbid` rules) if available.
3. **Patch Engineering:**
   - Implement boundary enforcement fix in Rust codebase.
   - Write dedicated adversarial regression test in `crates/relay-cli/tests/`.
4. **Release Emergency Patch (`v0.1.Z`):**
   - Execute GA004 ship checklist and publish emergency release within 72 hours.

---

## 6. Phase 24: Security vs Privacy vs Availability Incident Separation

Relay distinguishes three incident classes. Procedures must not conflate them — each class has different stakeholders, containment actions, and notification considerations.

### 6.1 Security Incident

**Definition:** Unauthorized access, boundary bypass, or cryptographic compromise affecting confidentiality, integrity, or authenticity of Relay's security guarantees.

**Examples:**
- Cedar PEP bypass or sandbox escape
- Credential leakage to agent/subprocess
- Receipt signing key or release signing key compromise
- Ledger tampering without detection
- Anti-SSRF or egress mediation failure

**Primary owner:** Security engineering  
**Primary runbooks:** §2–§5 above  
**Customer notification:** Required when customer deployment or data is affected; timeline **determined by counsel** — not pre-promised in engineering docs

### 6.2 Privacy Incident

**Definition:** Processing of personal data that violates documented purpose, retention, consent, or disclosure boundaries — whether or not a technical security boundary was breached.

**Examples:**
- Unintended collection of tool arguments or prompts into Relay-operated systems
- Accidental inclusion of PII in support logs or security report mishandling
- Retention beyond documented policy
- Incorrect deletion after verified data subject request
- Unauthorized employee access to customer account data (hosted — when implemented)
- Subprocessor disclosure not disclosed in subprocessor list
- Telemetry activated without documented consent mechanism

**Primary owner:** Privacy/legal coordination + engineering  
**Primary runbook:** §7 below  
**Regulatory notification:** **Counsel determines** applicability and timelines (DPDP Board, GDPR supervisory authority, etc.) — engineering provides factual record only

### 6.3 Availability Incident

**Definition:** Service or system outage affecting access without confirmed unauthorized data access.

**Examples:**
- Planned website outage (when live)
- Billing portal downtime (when live)
- Hosted dashboard unavailability (when implemented)
- GitHub Releases CDN outage affecting downloads

**Primary owner:** Operations  
**Note:** Local Relay binary operation is unaffected by Relay-operated availability incidents in v0.1.0 — customers run software locally.

### 6.4 Payment Incident

**Definition:** Disruption, vulnerability, compromise, or webhook failure affecting billing systems, payment gateway integration, subscription state, or merchant accounts.

**Examples:**
- Stripe webhook signing key leak or signature verification bypass
- Webhook processing replay attack or denial-of-service
- Compromise of Stripe API keys or merchant dashboard credentials
- Erroneous bulk billing or unintended subscription charge loop
- Payment gateway breach notification from Stripe

**Primary owner:** Finance / Commercial Operations + Security Engineering  
**Primary runbook:** §8 below  
**Customer / Regulatory notification:** Notification to affected cardholders or banking authorities coordinated by counsel and Stripe compliance.

### 6.5 Classification Decision Tree

```text
Incident reported
      │
      ├── Unauthorized access / boundary failure? ──► SECURITY (§2–§5)
      │
      ├── Data collected/shared/retained incorrectly? ──► PRIVACY (§7)
      │         (may also trigger SECURITY if breach-caused)
      │
      ├── Billing, Stripe webhook, or payment compromise? ──► PAYMENT (§8)
      │
      └── Service down, no data compromise? ──► AVAILABILITY (Ops)
```

A single event may span multiple classes (e.g., security breach causing privacy disclosure or billing disruption). Document both tracks.

---

## 7. Privacy Incident Runbook

**Trigger:** Confirmed or suspected privacy boundary violation per §6.2.

1. **Immediate Containment:**
   - Stop the processing activity (disable feature flag, take affected service offline, revoke access)
   - Preserve evidence without destroying audit trail
   - Do not mass-delete logs until counsel/investigation scope is defined
2. **Scope Assessment:**
   - Identify affected data categories (see `docs/commercial/data-flow.md` inventory)
   - Identify affected individuals/principals (count estimate TBD)
   - Determine whether data left customer-local boundary
   - Identify subprocessors involved (see `docs/commercial/subprocessors.md`)
3. **Cross-Reference Security:**
   - If root cause is security vulnerability, activate §2–§5 in parallel
   - If root cause is process/policy error, security patch may not be required
4. **Internal Escalation:**
   - Notify engineering lead, legal counsel (when engaged), and designated privacy contact (TBD)
   - Open internal incident record using §8 template
5. **Remediation:**
   - Delete or correct unlawfully retained data where technically feasible
   - Update documentation if architecture caused misunderstanding
   - Fix engineering defect if collection was unintended (e.g., accidental telemetry)
6. **External Communication:**
   - **Do not promise notification timelines** in engineering runbooks
   - Counsel maps internal record to DPDP/GDPR/contractual notification requirements
   - Customer communication draft requires legal approval
7. **Post-Incident:**
   - Update `privacy-threat-model.md` residual risks if needed
   - Update subprocessor list if vendor involved
   - Retrospective within 14 business days

---

## 8. Payment Incident Runbook

**Trigger:** Confirmed or suspected webhook tampering, signing key exposure, fraudulent license issuance, or Stripe integration compromise.

1. **Immediate Containment:**
   - Immediately rotate Stripe Webhook Signing Secret in the Stripe Dashboard and update the commercial server environment.
   - Revoke compromised Stripe API restricted keys (`rk_live_...`).
   - Halt automatic license issuance by setting the webhook consumer into temporary manual-triage mode.
2. **Transaction & Ledger Audit:**
   - Audit all `checkout.session.completed` events processed within the last 72 hours against authentic Stripe Dashboard charges.
   - Identify any fraudulently issued Ed25519 license keys.
   - If unauthorized license tokens were issued, add their `license_id` to the revoked license CRL (Certificate Revocation List).
3. **Double-Billing / Charge Failure Containment:**
   - If a duplicate billing loop is detected, pause subscription billing in Stripe and process immediate automated refunds via the Stripe API for all duplicate charges.
4. **Coordination & Escalation:**
   - Notify Stripe Risk & Security Team via official support channels.
   - Inform finance lead and legal counsel to assess PCI DSS and consumer protection disclosure obligations.
5. **Post-Incident Analysis:**
   - Conduct retrospective within 7 business days.
   - Deploy enhanced signature verification and replay window monitoring rules.

---

## 9. Breach Notification Readiness (Internal Record Template)

Engineering maintains factual records for counsel. **No notification timelines are promised here.**

### 8.1 Internal Privacy/Security Incident Record

| Field | Description |
|:---|:---|
| **Record ID** | Unique incident identifier |
| **Discovery date/time** | When Relay first learned of the incident (UTC) |
| **Discovery method** | Report, monitoring, audit, customer notification, etc. |
| **Incident class** | Security / Privacy / Availability / Multiple |
| **Affected system(s)** | Binary, website, billing, email, hosted API, etc. |
| **Affected data categories** | From `data-flow.md` inventory (e.g., account email, tool arguments, credentials) |
| **Approximate data volume** | Records/individuals affected (estimate) |
| **Affected customers/principals** | Customer IDs, regions, or "unknown/local-only" |
| **Root cause (preliminary)** | Technical or process cause |
| **Root cause (confirmed)** | Updated after investigation |
| **Containment actions** | What was done to stop ongoing harm |
| **Investigation status** | Open / in progress / closed |
| **Remediation actions** | Fixes deployed or planned |
| **Subprocessors involved** | Vendor names if applicable |
| **Cross-border transfer implicated** | Yes/No/Unknown |
| **Notification decision** | Pending counsel / Not required / Required — authority TBD |
| **Notification date(s)** | If sent — date and recipient category |
| **Evidence preserved** | Log locations, hashes, ticket references |
| **Retrospective date** | Scheduled review |
| **Record owner** | Named individual |
| **Legal reviewer** | Counsel name when engaged |

### 9.2 Counsel Mapping (Out of Scope for Engineering)

Counsel maps this record to applicable requirements, which may include:

- Digital Personal Data Protection Act / Rules (India) — Data Protection Board notification
- GDPR Articles 33–34 (if applicable)
- Contractual customer notification clauses
- Payment processor breach notification requirements

**Engineering does not determine legal notification deadlines.**

---

## 10. Related Commercial Documents

- `docs/commercial/data-flow.md` — Data inventory for scope assessment
- `docs/commercial/privacy-threat-model.md` — Privacy threat controls
- `docs/commercial/privacy-india.md` — India applicability analysis
- `docs/release/CR001-commercial-readiness-report.md` — CR001 milestone verdict
