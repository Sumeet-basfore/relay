# Relay Commercial Security Architecture & Trust Boundaries

**Document ID:** `CR003-SEC-002`  
**Version:** `1.0.0`  
**Status:** Authoritative Commercial System Architecture  
**Date:** 2026-09-14  

---

## 1. System Context & Component Map

Relay's commercial ecosystem is divided into five strictly partitioned trust zones:

```text
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ ZONE 1: PUBLIC INTERNET & EDGE                                                          │
│  - relay.dev static site (Cloudflare edge, no cookies, no tracking)                     │
│  - Stripe Hosted Checkout (PCI DSS Level 1)                                             │
└────────────────────────────────────────┬────────────────────────────────────────────────┘
                                         │ HTTPS / TLS 1.3
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ ZONE 2: RELAY COMMERCIAL CONTROL PLANE                                                  │
│  - Billing Webhook Consumer (HMAC-SHA256 signature verification)                        │
│  - License Signing Authority (Offline Ed25519 root / KMS-backed signer)                 │
│  - Customer Support & CRM (Email-only, least privilege)                                 │
└────────────────────────────────────────┬────────────────────────────────────────────────┘
                                         │ Offline Signed License Key (Email / Download)
                                         │ NO INBOUND CONNECTIONS TO CUSTOMER
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ ZONE 3: CUSTOMER HOST / WORKSTATION BOUNDARY                                            │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
│  │ Local Relay Daemon (PID N)                                                        │  │
│  │  - Cedar PDP/PEP (Local Cedar policy evaluation)                                  │  │
│  │  - OS Keyring Vault (libsecret / macOS Keychain / Windows CredMgr)                │  │
│  │  - Local Action Receipts (Ed25519 DSSE)                                           │  │
│  │  - Local Immutable Ledger (SQLite hash-chained audit)                             │  │
│  │  - Offline Entitlement Validator (Signature check only, zero network)             │  │
│  └─────────────────────────────────┬─────────────────────────────────────────────────┘  │
│                                    │ 127.0.0.1 (Loopback only)                          │
│                                    ▼                                                    │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
│  │ Local Security Console (Browser UI)                                               │  │
│  │  - Ephemeral CLI-issued bootstrap token                                           │  │
│  │  - Anti-DNS rebinding Host checks & CSRF Origin validation                         │  │
│  └───────────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Trust Boundaries & Non-Interference Invariants

### 2.1 Invariant 1: Control Plane Compromise Cannot Grant Agent Authority
- **The Threat:** An adversary compromises Relay's commercial billing server, database, or Stripe account.
- **The Defense:** Relay's local execution engine does not listen to or accept execution commands from Relay-operated servers. There is no remote control API, no dynamic script pushing, and no cloud-override channel.
- **Result:** Even total compromise of Relay's commercial infrastructure cannot permit an action that Cedar forbids on the customer's machine.

### 2.2 Invariant 2: Hosted Systems Cannot Obtain Customer Credentials
- **The Threat:** Adversary attempts to exfiltrate database credentials or GitHub tokens stored in Relay.
- **The Defense:** Credentials stored in Relay are bound to the customer's local OS keyring and vaulted memory. They are never sent to Relay, never included in license tokens, never transmitted in receipts, and never embedded in error reports.

### 2.3 Invariant 3: Payment Status is Never Authorization Status
- An active Enterprise license grants access to support SLAs and team policy bundles.
- It **never** bypasses:
  1. Cedar default-deny evaluation
  2. Credential brokering isolation
  3. Interactive human `/dev/tty` approval requirements
  4. Filesystem or egress sandboxing rules
- Conversely, an expired commercial license **never** halts or disables open-core execution or locks customers out of their local receipts.

---

## 3. Communication Channel Security

| Channel | Protocols & Safeguards | Data Permitted | Data Strictly Prohibited |
| :--- | :--- | :--- | :--- |
| **Website -> Edge** | HTTPS, TLS 1.3, Strict CSP, HSTS | HTTP request metadata | Any customer execution data |
| **Stripe -> Relay API** | HTTPS, HMAC-SHA256 signature, 5-min timestamp window | Stripe event metadata, customer ID, subscription ID | Credit card PAN, CVV, customer passwords |
| **Relay -> Customer** | Offline Ed25519 signed license certificate | Customer ID, plan tier, seat count, expiry timestamp | Executable code, private keys, tracking pixels |
| **Relay CLI -> Local UI** | `127.0.0.1` loopback, ephemeral Bearer token, timing-safe auth | Redacted receipts, policy status, connector state | Plaintext secrets, raw passwords, un-redacted API tokens |
