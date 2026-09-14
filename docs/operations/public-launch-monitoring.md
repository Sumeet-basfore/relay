# Relay Public Paid Launch — Operational Monitoring

**Document ID:** `PL-MON-001`  
**Runbook Phase:** 12 — Stripe / Billing / Entitlement Monitoring  
**Effective Date:** 2026-09-14  
**Release Line:** `v0.1.0`  
**Status:** **ACTIVE**

---

## 1. Scope & Principles

This document defines production monitoring for Relay's **commercial control plane only**. Relay's local execution binary has **zero product telemetry** — monitoring does not collect agent prompts, tool arguments, credentials, or ledger contents.

**Monitored surfaces:**
- Public website availability (`relay.dev` via Cloudflare)
- Stripe checkout and Customer Portal
- Webhook consumer (HMAC-SHA256 verification, replay defense)
- Entitlement issuance and CRL publication
- Transactional email delivery (license certificates, billing notices)
- Public release artifact availability (GitHub Releases)

**Explicitly excluded:** Agent execution telemetry, local MCP traffic, customer ledger data.

---

## 2. Monitoring Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    COMMERCIAL CONTROL PLANE                      │
│  (Stripe, entitlement API, email, website — NOT agent execution) │
├─────────────────────────────────────────────────────────────────┤
│  Website (Cloudflare)  →  Uptime / TLS / 5xx rate              │
│  Stripe Checkout       →  Session success / failure rate         │
│  Webhook Consumer      →  Signature verify / replay / latency    │
│  Entitlement Service   →  Issue / revoke / CRL publish         │
│  Email (Resend/SES)    →  Delivery / bounce rate               │
│  GitHub Releases       →  Artifact availability / checksum match │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  Alert Routing (no card data) │
              │  billing@ / security@ / on-call│
              └───────────────────────────────┘
```

---

## 3. Stripe Webhook Monitoring

EB001 validated **100% webhook reliability (28/28 production events)**. Post-launch monitoring maintains this standard.

### 3.1 Health Checks

| Check | Threshold | Alert Severity | Owner |
| :--- | :--- | :---: | :--- |
| Webhook delivery success rate | ≥ 99.5% over 24h | P1 if < 99%; P0 if < 95% | Billing Eng |
| Signature verification failures | 0 tolerated in production | P0 on any sustained failure | Security Eng |
| Replay attempt (timestamp > 5 min) | Log and reject; alert if > 5/hour | P1 | Security Eng |
| Duplicate event ID (idempotency) | Deduplicate silently; alert if > 10 duplicates/day | P2 | Billing Eng |
| Webhook processing latency (p99) | < 2 seconds | P2 if > 5s | Billing Eng |
| Unhandled event type | 0 in production | P1 | Billing Eng |

### 3.2 Subscription State Transitions

Monitor abnormal transitions in the billing state machine (`NONE → CHECKOUT → ACTIVE → PAST_DUE → GRACE → CANCELLED`):

| Transition | Expected Trigger | Anomaly Alert |
| :--- | :--- | :--- |
| `CHECKOUT → ACTIVE` | `checkout.session.completed` | ACTIVE without prior CHECKOUT |
| `ACTIVE → PAST_DUE` | `invoice.payment_failed` | PAST_DUE without failed invoice |
| `PAST_DUE → GRACE` | Internal 7-day grace timer | GRACE without PAST_DUE |
| `GRACE → CANCELLED` | Grace expiry or manual cancel | CANCELLED without grace or refund |
| `ACTIVE → CANCELLED` | Customer portal cancel or 14-day refund | CANCELLED with active entitlement mismatch |

**Rule:** Never use browser redirect success as payment truth. Subscription state is authoritative only after verified webhook processing.

### 3.3 Payment Disputes & Refunds

| Check | Threshold | Alert |
| :--- | :--- | :--- |
| Refund processing failures | 0 | P1 — manual reconciliation required |
| Refund rate (14-day window) | Baseline from EB001; alert if > 2× 7-day rolling average | P2 |
| Chargeback/dispute opened | Any | P1 — billing@ + legal review |
| Abnormal refund volume (> 5/day) | Spike detection | P1 |

**PCI constraint:** Never log full card numbers, CVV, or Stripe raw payment method objects. Log only Stripe event IDs, customer IDs, and subscription IDs.

---

## 4. Entitlement Monitoring

| Check | Frequency | Threshold | Alert |
| :--- | :--- | :--- | :--- |
| License issuance after `ACTIVE` subscription | Per event | < 60 seconds | P1 if delayed > 5 min |
| Ed25519 signature verification failures | Per request | 0 in production | P0 |
| Expired license still receiving Pro API calls | Daily audit | 0 mismatches | P1 |
| CRL publication cadence | Monthly + emergency | CRL age < 35 days | P2 if stale |
| CRL signature verification failures (customer-side) | Support reports | Track trend | P2 |
| Compromised license revocation time | Per incident | < 15 minutes (EB001 validated) | P0 if exceeded |

### 4.1 Non-Interference Invariant Watch

Automated daily assertion (staging mirror):
- Enterprise license **cannot** bypass Cedar DENY
- Expired license **cannot** disable open-core `relay` CLI execution
- Commercial entitlement **does not** modify credential broker or approval gates

Any violation: **P0 — halt entitlement issuance, invoke security incident runbook**.

---

## 5. Website & Download Monitoring

| Check | Method | Threshold |
| :--- | :--- | :--- |
| Homepage / pricing / security pages | Cloudflare synthetic + external probe | 99.9% uptime |
| Checkout link resolves to live Stripe session | Hourly smoke test | 100% success |
| `install.sh` download from GitHub Releases | Hourly HEAD request | HTTP 200 |
| Published archive SHA matches certified manifest | Daily checksum verification | Bit-exact match to `6f843ab7…` |
| Legal pages (privacy, terms, subprocessors) | Content hash weekly | Match frozen counsel-approved versions |

---

## 6. Email Delivery Monitoring

| Email Type | Provider | Alert Threshold |
| :--- | :--- | :--- |
| License certificate delivery | Resend / AWS SES | Bounce rate > 2% |
| Renewal reminders | Resend / AWS SES | Delivery failure > 1% |
| Billing receipts (Stripe-managed) | Stripe | Stripe dashboard alerts |
| Security bulletins | Resend / AWS SES | Any hard bounce on security@ list |

---

## 7. Alert Routing & Escalation

| Severity | Response Time | Channel | Escalation |
| :--- | :--- | :--- | :--- |
| **P0** | < 15 minutes | Security on-call + billing@ | `docs/security/incident-response.md` §8 Payment Incident |
| **P1** | < 4 hours | billing@ / support@ | Operations lead |
| **P2** | < 24 hours | support@ | Next business day |
| **P3** | Best effort | support@ | Backlog |

**Contacts:** `billing@relay.dev`, `security@relay.dev`, `support@relay.dev`

---

## 8. Dashboard & Log Retention

| Data Class | Retention | Contains |
| :--- | :--- | :--- |
| Webhook event metadata | 90 days | Event ID, type, timestamp, processing result |
| Subscription state audit log | 7 years (tax/compliance) | State transitions, Stripe IDs — no card data |
| Entitlement issuance log | 7 years | License ID, org ID, issue/revoke timestamps |
| Website access logs | 30 days | IP, User-Agent (Cloudflare) |
| Alert history | 1 year | Alert type, severity, resolution |

---

## 9. Phase 11 Complementary Monitoring (Reference)

Phase 11 activated broader operational monitoring. This document (Phase 12) is the authoritative Stripe/billing/entitlement supplement:

- **Phase 13 — Security Monitoring:** `security@relay.dev`, dependency CVEs, signing-key concerns, CRL compromise
- **Phase 14 — CRL Operations:** Monthly CRL publication log, emergency revocation playbook

---

## 10. EB001 Baseline Metrics (Launch Reference)

| Metric | EB001 Value | Post-Launch Target |
| :--- | :--- | :--- |
| Webhook success rate | 100% (28/28) | ≥ 99.5% |
| Stripe replay rejections | 100% enforced | 100% |
| Entitlement non-interference | Proven | Daily automated assertion |
| Refund automation | PASS | 100% within SLA |
| Dunning grace recovery | PASS | Monitor GRACE → ACTIVE rate |

**Phase 12 Status:** **PASS — MONITORING ACTIVE**
