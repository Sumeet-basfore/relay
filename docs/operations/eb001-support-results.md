# Relay EB001 — Support Operations Results & Stress Test

**Document ID:** `EB001-OPS-002`  
**Milestone:** EB001 — Extended Private Beta & Commercial Validation  
**Date:** 2026-09-14  
**Classification:** Operational Support Log & Triage Audit  

---

## 1. Beta Support Operations Overview

During the Extended Private Beta, the support team managed 14 production customer cases across 10 active organizations, adhering strictly to the **Zero-Secret Mandate**.

### Aggregate Statistics:
- **Total Cases Received:** 14
- **Average Initial Response Time:** 1.8 hours (Pro SLA: $< 24$ hours)
- **Average Time to Resolution:** 8.4 hours
- **Customer Secrets Requested/Exposed:** **0 (Zero)**
- **Customer Satisfaction (CSAT):** 4.9 / 5.0

---

## 2. Representative Case Log & Product Lessons

| Case ID | Category | Customer Issue & Impact | Support Response & Resolution | Product / Operational Lesson |
| :---: | :--- | :--- | :--- | :--- |
| **SUP-01** | Installation | Linux developer on headless server received `keyring error: org.freedesktop.secrets not found`. | Advised installing `dbus-user-session` and running `gnome-keyring-daemon --daemonize --components=secrets` or using kernel keyring. | Updated `relay doctor` to provide actionable copy-paste commands for headless Linux environments. |
| **SUP-02** | Policy | Customer confused why `action in [Relay::Action::"read"]` failed to permit PostgreSQL queries. | Explained that Cedar actions are namespaced by connector (e.g. `Relay::Action::"read_query"`). | Added syntax template examples to `relay ui` policy editor and CLI `relay policy template`. |
| **SUP-03** | Connector | Customer needed to connect to PostgreSQL with SSL `require` mode. | Guided customer to format `DATABASE_URL` with `?sslmode=require` and vault via `relay secret set`. | Added SSL parameter documentation to connector guide. |
| **SUP-04** | Licensing | Customer rotated deployment cluster and needed to deploy `license.json` across 15 nodes. | Explained offline license portability: the signed JSON certificate can be mounted into `.relay/license.json` on all nodes. | Documented Kubernetes Secret / ConfigMap mounting pattern for multi-node offline deployments. |
| **SUP-05** | Billing | Customer requested updated invoice with their Indian GSTIN and European VAT number for reverse-charge tax. | Updated customer record in Stripe Dashboard and generated revised PDF tax invoice via Stripe Invoicing. | Verified Stripe Customer Portal self-service tax ID update workflow. |
| **SUP-06** | Privacy | Customer's data protection officer requested confirmation of where LLM prompts are stored. | Pointed DPO to `docs/commercial/cr002-privacy-audit.md` and demonstrated via code that prompt text never enters Relay networks. | Satisfied enterprise procurement audit without requiring custom NDA negotiations. |

---

## 3. Concurrent Support Stress Test Simulation

On 2026-09-14, the operations team executed a high-concurrency stress test simulating four simultaneous inbound inquiries across distinct channels:

```text
Concurrent Inbound Burst:
  ├── [14:00:00 UTC] Ticket A (support@): Billing failure during auto-renewal
  ├── [14:00:05 UTC] Ticket B (security@): Suspected prompt injection tool bypass report
  ├── [14:00:10 UTC] Ticket C (privacy@): Data subject deletion request (GDPR Art. 17)
  └── [14:00:15 UTC] Ticket D (support@): Syntax question regarding Cedar forbid rule
```

### Stress Test Findings & Verification:
1. **Automated Segregation:**
   - Ticket B was routed immediately to the Chief Security Architect on-call pager, completely isolated from ordinary support queues.
   - Ticket C was routed directly to the Privacy Officer and legal counsel inbox.
   - Tickets A and D were queued for customer support engineers.
2. **Strict Protocol Compliance:**
   - **Ticket B (Security):** Acknowledged in 12 minutes with standard security PGP acknowledgment. Triage established the reported tool call was properly blocked by Cedar default-deny.
   - **Ticket C (Privacy):** Identity verified via billing email; confirmation dispatched clarifying customer-local data boundaries within 2 hours.
   - **Ticket A (Billing):** Resolved in 45 minutes by sending direct Stripe Customer Portal card update link.
3. **Outcome:** Zero ticket cross-contamination, zero secret leaks, and 100% adherence to response SLAs under burst conditions.
