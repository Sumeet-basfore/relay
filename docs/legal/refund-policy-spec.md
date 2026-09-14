# Relay Commercial Refund & Cancellation Policy Specification

**Document ID:** `CR003-LEG-005`  
**Version:** `1.0.0`  
**Status:** Refund Policy Specification  
**Date:** 2026-09-14  

---

## 1. Scope & Objective

This policy outlines the commercial terms, timelines, and procedures governing subscription cancellations, renewals, and refund requests for Relay commercial offerings.

---

## 2. Cancellation Terms

1. **Self-Service Cancellation:** Customers may cancel active subscriptions at any time via the self-service billing portal hosted by Stripe or by emailing `billing@relay.dev`.
2. **Effective Date of Cancellation:** When a subscription is cancelled, the cancellation takes effect at the end of the current pre-paid billing cycle (monthly or annual). 
3. **Continuous Access:** The customer retains access to commercial support and active offline license validation until the conclusion of the paid term.
4. **Open-Core Continuation:** Cancellation of a commercial subscription **never disables or impairs local execution of the Apache 2.0 open-core binary**. Local policies, credentials, and ledgers remain completely accessible.

---

## 3. Refund Policy & Timelines

### 3.1 14-Day Initial Satisfaction Guarantee
- **Eligibility:** For all first-time commercial subscription purchases (monthly or annual), Customer may request a 100% full refund within **fourteen (14) calendar days** of the initial transaction date.
- **Process:** Customer must submit a refund request from their registered billing email to `billing@relay.dev` within the 14-day window.
- **No Questions Asked:** Initial refunds within this 14-day period are processed promptly without requiring proof of defect.

### 3.2 Post-14-Day Terms & Renewals
- **Subsequent Periods & Renewals:** After the initial 14-day window has elapsed, subscription fees are non-refundable. Relay does not provide pro-rated refunds for partial months or unused portions of annual subscriptions.
- **Renewal Notification:** For annual contracts, Relay sends an automated renewal reminder notice to the registered billing contact thirty (30) days prior to the renewal date.

### 3.3 Exceptional Circumstances
Relay may, in its sole and reasonable discretion, issue refunds outside the standard window in cases of:
- Duplicate or erroneous billing charges caused by gateway processing errors.
- Material service outage or documented inability to deliver commercial updates where Relay is unable to cure within thirty (30) days.

---

## 4. Payment Failures & Dunning Process

1. **Grace Period:** If an automated recurring charge fails (e.g. expired credit card), Relay provides a **seven (7) day dunning grace period** during which offline license validity remains active.
2. **Retry Schedule:** Stripe automatically retries the charge up to four (4) times over the grace period and dispatches payment failure notices to the billing email.
3. **Suspension:** If payment is not successfully cleared by the end of the grace period, commercial support entitlements and future license renewals are suspended until payment is resolved.

---

## 5. Tax Handling & Currency

- **Statutory Taxes:** Where refunds are issued, applicable sales tax, VAT, or GST previously collected will be refunded in accordance with applicable tax regulations in the customer's jurisdiction.
- **Processing Time:** Approved refunds are processed via Stripe to the original payment method within five to ten (5–10) business days, depending on the customer's issuing financial institution.
