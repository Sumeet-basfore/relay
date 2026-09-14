# Relay EB001 — Production Infrastructure Security & Availability Review

**Document ID:** `EB001-OPS-001`  
**Milestone:** EB001 — Extended Private Beta & Commercial Validation  
**Date:** 2026-09-14  
**Classification:** Operational Security & Reliability Audit  

---

## 1. Production Commercial Infrastructure Inventory

Relay's commercial control plane is strictly decoupled from customer-local execution environments:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. Edge & DNS Layer (Cloudflare, Inc.)                                      │
│    - Role: DNSSEC, Anycast CDN, DDoS protection, TLS 1.3 termination.       │
│    - Access: Restricted to authorized operations engineers via MFA & SSO.   │
├─────────────────────────────────────────────────────────────────────────────┤
│ 2. Payment & Billing Layer (Stripe, Inc.)                                   │
│    - Role: PCI DSS Level 1 payment processing, Checkout, Customer Portal.   │
│    - Access: Restricted keys (`rk_live_...`) with minimal required scopes. │
├─────────────────────────────────────────────────────────────────────────────┤
│ 3. Commercial Webhook Consumer & License Service                            │
│    - Role: Validates Stripe webhooks (HMAC-SHA256) & issues Ed25519 tokens. │
│    - Secrets: Webhook signing secret (`whsec_...`) stored in vaulted env.   │
├─────────────────────────────────────────────────────────────────────────────┤
│ 4. Transactional Messaging (Resend, Inc. / AWS SES)                         │
│    - Role: Delivery of offline license certificates and billing notices.    │
│    - Access: Least-privilege API tokens; zero marketing email mixing.       │
├─────────────────────────────────────────────────────────────────────────────┤
│ 5. Code & Release Hosting (GitHub, Inc.)                                    │
│    - Role: Open-source repository, binary asset releases, SHA256SUMS.sig.   │
│    - Signing: Offline hardware token release signing key (never in CI).     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Secrets Management & Least-Privilege Audit

1. **Zero Customer Secrets:** Commercial databases and logging systems hold **zero** customer credentials, zero target passwords, and zero prompt text.
2. **Access Control:** Multi-factor authentication (MFA) via hardware security keys (FIDO2/WebAuthn) is enforced on GitHub, Cloudflare, and Stripe dashboard accounts.
3. **Restricted Stripe API Keys:** The commercial server uses a scoped Restricted API Key with permissions limited to `Subscriptions: Read/Write` and `Invoices: Read`. Full administrative keys are strictly banned in application runtimes.
4. **Offline Release Key Isolation:** The Ed25519 release-signing private key is stored offline on hardware tokens and never uploaded to CI/CD runners or cloud servers.

---

## 3. Commercial Backup & Disaster Recovery Verification

A disaster recovery simulation was executed on 2026-09-14:
- **Test Objective:** Restore commercial billing metadata, customer account status, and transaction history from cold backups.
- **RTO / RPO Achieved:** Recovery Time Objective $< 15$ minutes; Recovery Point Objective $< 1$ hour.
- **Critical Verification:** Confirmed that **zero customer-local execution data, action receipts, or local ledgers** were included in the commercial backup (because they never enter Relay infrastructure).

---

## 4. Availability & Failure Mode Simulations

We simulated external third-party outages to verify that commercial failures **cannot break customer-local software execution**:

| Outage Scenario | Commercial Impact | Customer-Local Relay Binary Impact | Invariant Verification |
| :--- | :--- | :--- | :--- |
| **Stripe API Downtime** | Checkout and payment upgrades temporarily paused | **Zero Impact:** Local Relay daemon, CLI, Cedar policies, and receipts continue running normally. | **PASS (Local-First)** |
| **Relay Website (`relay.dev`) Offline** | Website inaccessible to new visitors | **Zero Impact:** Shipped binaries run completely offline on customer workstations/servers. | **PASS (Zero Tether)** |
| **Transactional Email Outage** | License certificate email delivery delayed | **Zero Impact:** Existing valid licenses continue to operate offline without phone-home checks. | **PASS (Offline Crypto)** |
| **CRL Distribution Outage** | Emergency revocation manifest cannot be fetched | **Graceful Handling:** Relay validates license against locally cached CRL; does not fail-closed unless expired. | **PASS (Resilient)** |

### Definitive Invariant Result:
A total outage of all Relay-operated commercial servers **never** halts customer agent execution, disables Cedar policies, or locks customers out of their local action receipts.
