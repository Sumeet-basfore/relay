# Relay Operations: PB001 Customer Support Runbook

**Document ID:** `PB001-OPS-001`  
**Milestone:** PB001 — Private Paid Beta & Production Operations  
**Classification:** Internal Customer Support & Operations Runbook  
**Effective Date:** 2026-09-14  

---

## 1. Golden Rules of Support Operations

Every support engineer and operator must adhere to the following mandatory data protection rules:
1. **NEVER Request Raw Secrets:** Never ask a customer to send API tokens, database passwords, private keys, or SSH credentials.
2. **Sanitized Logs Only:** When requesting diagnostic output, instruct customers to run `relay doctor --json` (which automatically redacts sensitive paths and values) or scrub output using `SecretScrubber`.
3. **Channel Segregation:** Never mix security disclosures, privacy requests, billing disputes, and technical support in the same thread. Route each to its authoritative team.

---

## 2. Inbound Channel Segregation & Routing

| Ticket Category | Inbound Address | Primary Responder | Response SLA Target | Escalation Target |
| :--- | :--- | :--- | :--- | :--- |
| **Technical & Installation** | `support@relay.dev` | Customer Support Eng | 24 business hours | Engineering Lead |
| **Billing & Invoicing** | `billing@relay.dev` | Operations / Finance | 24 business hours | Head of Finance |
| **License & Entitlements** | `billing@relay.dev` | Support / Crypto Eng | 12 business hours | Cryptography Lead |
| **Security Disclosures** | `security@relay.dev` | Security Incident Team | **48 hours (mandatory)**| Chief Security Architect |
| **Privacy & DPDP Requests** | `privacy@relay.dev` | Privacy Lead / Counsel | Statutory timeline | Statutory Grievance Officer |

---

## 3. Operational Handling by Category

### 3.1 Installation & Diagnostic Issues
- **Symptoms:** Binary fails checksum, missing dependencies (`libsecret`), keyring lock error.
- **Workflow:**
  1. Confirm operating system distribution and architecture (`uname -m`, `cat /etc/os-release`).
  2. Ask customer to run `relay doctor` and share the diagnostic summary.
  3. Verify OS keyring daemon state:
     - Linux: ensure `dbus-user-session` and `gnome-keyring` or `pass` are running.
     - macOS: ensure Keychain Access is unlocked.
  4. Remind customer: *Never attach terminal history containing raw secrets.*

### 3.2 Billing Inquiries & Payment Failures
- **Symptoms:** Card declined, invoice PDF request, VAT/GST reverse charge adjustment.
- **Workflow:**
  1. Locate customer by Stripe Customer ID (`cus_...`) or registered billing email in the Stripe Dashboard.
  2. For payment failures: Verify dunning status. Customers receive a 7-day grace period where licenses remain active.
  3. Send customer an authenticated direct link to the Stripe Customer Portal for self-service card update.
  4. Never accept credit card numbers over email, chat, or phone.

### 3.3 License Certificate Issues & Renewals
- **Symptoms:** License signature verification error, expired license warning, seat limit reached.
- **Workflow:**
  1. Check customer subscription status in Stripe.
  2. If subscription is active, regenerate an Ed25519 signed license token (`license.json`) using the offline license authority tool.
  3. Provide instructions to place the updated certificate in `.relay/license.json`.
  4. If license verification fails locally, ask customer to verify their binary version matches release `v0.1.0`.

### 3.4 Security Vulnerability Disclosures
- **Workflow:**
  1. Acknowledge receipt within **48 business hours** using the standard security acknowledgment template.
  2. Triage issue against Relay Security Invariants (SI-001 through SI-024).
  3. Open an internal security incident record in `docs/security/incident-response.md`.
  4. Involve cryptography or connector leads for reproduction in an isolated VM.
  5. Schedule patch engineering and coordinate CVE release window.

### 3.5 Privacy & Data Subject Requests (DPDP / GDPR / CCPA)
- **Workflow:**
  1. Verify identity of the requester by matching commercial account email.
  2. Distinguish local data from commercial metadata:
     - Inform requester that Relay servers hold **zero** local prompts, tool arguments, or receipts.
     - For commercial data (Stripe, Resend, support archives): execute search, update, or deletion within statutory deadlines.
  3. Record the fulfillment in the privacy compliance register.

### 3.6 Cancellation & Refund Requests
- **Workflow:**
  1. Determine if the request is within the **14-day initial satisfaction guarantee** window.
  2. If within 14 days: issue a 100% full refund in Stripe with reason `Customer Request`.
  3. Inform customer: *Cancellation takes effect immediately for commercial support, but does NOT disable your local Relay software or delete your local action receipts.*
