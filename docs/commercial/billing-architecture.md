# Relay Commercial Billing & Payment Architecture

**Document ID:** `CR003-BIL-001`  
**Version:** `1.0.0`  
**Status:** Authoritative Architectural Specification  
**Date:** 2026-09-14  

---

## 1. Architectural Principles & Boundary

Relay's billing architecture adheres strictly to data minimization and PCI isolation:
1. **Zero Cardholder Data Ingestion:** All sensitive payment card numbers, expiration dates, and CVVs are handled exclusively by Stripe on Stripe-hosted checkout surfaces (`checkout.stripe.com`) and Customer Portal pages (`billing.stripe.com`). Relay systems never touch, transmit, or store primary account numbers (PAN).
2. **Authoritative Server Webhooks:** Client-side redirects (e.g. `GET /success?session_id=...` or `payment_success=true`) are strictly treated as untrusted UI hints. Entitlements and license keys are issued **only** upon cryptographic receipt and validation of server-to-server signed webhooks from Stripe.
3. **Minimum Metadata Retention:** Relay stores only the bare minimum billing metadata needed to link subscriptions to license keys: Stripe Customer ID, Stripe Subscription ID, Plan Tier, Seat Count, and Expiration Timestamp.

---

## 2. End-to-End Billing Lifecycle

```text
┌──────────────┐         ┌──────────────────────┐         ┌──────────────────┐
│   Customer   │         │  Stripe (Hosted UI)  │         │  Relay License   │
│   Browser    │         │   PCI DSS Level 1    │         │  Backend Service │
└──────┬───────┘         └──────────┬───────────┘         └────────┬─────────┘
       │                            │                              │
       │  1. Initiate Checkout      │                              │
       ├───────────────────────────►│                              │
       │                            │                              │
       │  2. Submit Payment Card    │                              │
       ├───────────────────────────►│                              │
       │                            │                              │
       │  3. Payment Authorized     │                              │
       │◄───────────────────────────┤                              │
       │                            │  4. Signed Webhook Event     │
       │                            │     (checkout.session.compl) │
       │                            ├─────────────────────────────►│
       │                            │                              │
       │                            │                              │ 5. Verify Signature
       │                            │                              │    Verify Timestamp
       │                            │                              │    Check Replay
       │                            │                              │    Issue Ed25519
       │                            │                              │    Signed License
       │  6. License Certificate    │                              │
       │◄───────────────────────────┴──────────────────────────────┤
```

---

## 3. Webhook Security Specification

Stripe delivers lifecycle events to Relay's commercial webhook endpoint (`POST /api/v1/billing/webhook`). Relay enforces four sequential validation layers:

### 3.1 Signature Header Parsing
The request must contain the `Stripe-Signature` header in standard format:
```http
Stripe-Signature: t=1773576000,v1=9c4a6b2...3d8e,v0=...
```

### 3.2 HMAC-SHA256 Cryptographic Verification
Relay computes the expected signature over the concatenation of the timestamp and raw payload body:
$$\text{SignaturePayload} = t \,||\, "." \,||\, \text{RawBody}$$
$$\text{ExpectedSig} = \text{HMAC-SHA256}(\text{WebhookSecret}, \text{SignaturePayload})$$
Comparison between the header's `v1` signature and $\text{ExpectedSig}$ is executed using **constant-time equality** (`subtle::constant_time_eq`) to eliminate timing side-channels.

### 3.3 Strict Timestamp Replay Defense
To eliminate replay attacks:
- The timestamp $t$ is extracted and compared against the current system UTC clock.
- If $| \text{CurrentTime} - t | > 300\text{ seconds}$ (5 minutes), the event is immediately rejected with HTTP `400 Bad Request`.

### 3.4 Idempotency & Deduplication
- Every Stripe event includes a globally unique `event.id` (e.g. `evt_1N...`).
- Relay logs processed event IDs in an append-only transactional ledger with a unique constraint. If an event ID has already been processed, Relay returns HTTP `200 OK` immediately without reissuing duplicate licenses.

---

## 4. Authoritative Event State Machine

Relay maps authenticated Stripe events to internal lifecycle actions:

| Stripe Event Type | Relay Action | Entitlement State |
| :--- | :--- | :--- |
| `checkout.session.completed` | Extract `customer_id`, `plan`, `seats`; generate Ed25519 signed license; dispatch email via Resend | `Active` |
| `customer.subscription.updated` | Update seat count or plan tier; re-issue updated signed license token | `Active` (Updated) |
| `invoice.payment_failed` | Initiate 7-day dunning grace period; dispatch notification email | `GracePeriod` |
| `customer.subscription.deleted` | Mark subscription as cancelled; revoke auto-renewal; allow license to lapse at expiry | `Lapsed` |

---

## 5. Customer Self-Service & Cancellation Flow

Customers manage billing directly through Stripe Customer Portal sessions:
1. Customer clicks *"Manage Subscription"* on [https://relay.dev/billing](https://relay.dev/billing).
2. Relay generates an authenticated Stripe Customer Portal session URL via Stripe API and redirects the browser.
3. Customer can update payment cards, download historical PDF invoices, upgrade/downgrade seat allocations, or cancel auto-renewal.
4. Cancellation updates Stripe status; Stripe fires `customer.subscription.deleted` at cycle end.
