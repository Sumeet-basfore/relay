# Relay Private Paid Beta: Customer Onboarding & Security Guide

**Document ID:** `PB001-ONB-001`  
**Milestone:** PB001 — Private Paid Beta & Production Operations  
**Audience:** Beta Customers, Engineering Leads, Security Architects  
**Date:** 2026-09-14  

---

## 1. Welcome to the Relay Private Beta

Relay provides local-first, zero-trust governance for autonomous AI agents. This guide walks your team from initial invitation through first governed execution, receipt verification, and local security console inspection.

### Core Architecture Reminder
Relay operates completely on your infrastructure. Your prompts, database credentials, queries, and execution receipts **never leave your local environment**.

---

## 2. Eleven-Step Onboarding Workflow

```text
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  1. Invite   │ ──► │ 2. Activate  │ ──► │ 3. Download  │ ──► │  4. Verify   │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                                                                       │
┌──────────────┐     ┌──────────────┐     ┌──────────────┐             ▼
│ 8. Connect   │ ◄── │  7. Policy   │ ◄── │  6. Doctor   │ ◄── ┌──────────────┐
└──────┬───────┘     └──────────────┘     └──────────────┘     │  5. Install  │
       │                                                       └──────────────┘
       ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ 9. Run Agent │ ──► │ 10. Receipt  │ ──► │ 11. Local UI │
└──────────────┘     └──────────────┘     └──────────────┘
```

### Step 1: Receive Private Beta Invitation
You will receive an onboarding invitation email from `support@relay.dev` containing your unique onboarding link and organization token.

### Step 2: Commercial Activation & Offline License Issuance
1. Access the private checkout portal hosted on Stripe.
2. Complete subscription activation for your designated seat allocation.
3. Upon confirmation, download your cryptographically signed offline license certificate (`license.json`).
   - *Note:* Relay does not require online phone-home activation. The license certificate is verified mathematically on your machine.

### Step 3: Download Relay Release Binary
Download the official `v0.1.0` release package for your operating system:
```bash
curl -fsSL https://relay.dev/install.sh | sh
# Or download directly from GitHub Releases:
# https://github.com/relay-security/relay/releases/tag/v0.1.0
```

### Step 4: Cryptographically Verify Binary Signature
Verify that your binary matches the official release manifest signed by Relay's offline Ed25519 release key:
```bash
relay verify-release --manifest SHA256SUMS.sig
```

### Step 5: Install & Initialize Local Workspace
Run the initialization command in your target agent workspace:
```bash
relay init
```
This creates the local `.relay/` directory containing your local Ed25519 receipt-signing keypair, SQLite ledger (`.relay/ledger.db`), and default Cedar policies.

### Step 6: Run System Diagnostics (`relay doctor`)
Verify your host operating system keyring, Cedar policy parser, and filesystem permissions:
```bash
relay doctor
```
Ensure all diagnostic checks show `[PASS]`.

### Step 7: Configure Cedar Authorization Policy
Review and customize your default-deny authorization rules in `.relay/policies/default.cedar`. For example, to grant an agent read-only access to PostgreSQL while forbidding DDL:
```cedar
permit(
    principal == Relay::Role::"agent",
    action == Relay::Action::"read_query",
    resource == Relay::Database::"production"
);
forbid(
    principal,
    action in [Relay::Action::"drop_table", Relay::Action::"alter_table"],
    resource
);
```

### Step 8: Connect Target System Credentials
Vault your sensitive production credentials into your local OS keyring:
```bash
relay secret set GITHUB_TOKEN --secret "ghp_xxxxxxxxxxxx"
relay secret set DATABASE_URL --secret "postgres://app:secret@db.internal:5432/prod"
```
*Your secrets are stored in your operating system keyring (libsecret / macOS Keychain / Windows Credential Manager) and never written in plaintext to disk.*

### Step 9: Run Your First Governed Action
Execute your agent through Relay's mediated runtime:
```bash
relay run -- my-agent-command
```

### Step 10: Verify Action Receipt & Ledger Integrity
After execution, verify the cryptographic integrity of the SQLite ledger and DSSE Action Receipts:
```bash
relay verify
```
Confirm that the hash chain is unbroken and all signatures match your local key.

### Step 11: Launch the Local Security Console
Inspect your security posture, review redacted receipts, and validate policies in your browser:
```bash
relay ui
```
The console opens on `http://127.0.0.1:9876` with an ephemeral bootstrap token.

---

## 3. Customer Security Orientation

### What Relay Protects:
- **Default-Deny Boundaries:** Agents cannot invoke unpermitted tools, queries, or files.
- **Ambient Credential Isolation:** Target API keys and passwords never enter LLM prompt context or environment variables.
- **Cryptographic Auditability:** Every action generates an in-toto DSSE Ed25519 receipt linked into an append-only ledger.
- **Out-of-Band Approvals:** High-risk actions halt and prompt a human operator on `/dev/tty`.

### What Relay Does NOT Protect:
- **Host Compromise:** Relay does not defend against an adversary who already has root/administrator access on your host machine.
- **Flawed Cedar Policies:** If an administrator writes `permit(principal, action, resource);`, Relay will permit all actions as instructed.
- **Upstream LLM Behavior:** Relay mediates actions at the tool boundary; it does not control how models formulate prompt text.

### Operating System Nuances:
- **Linux:** Utilizes `libsecret` (or kernel keyrings) and Linux network namespaces for strict loopback mediation.
- **macOS:** Utilizes the Apple Keychain for credential vaulting.
- **Windows:** Utilizes Windows Credential Manager.
