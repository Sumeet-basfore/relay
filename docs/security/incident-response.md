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
