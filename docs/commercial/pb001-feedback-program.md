# Relay Private Paid Beta: Customer Feedback & Operations Measurement

**Document ID:** `PB001-FDB-001`  
**Milestone:** PB001 — Private Paid Beta & Production Operations  
**Classification:** Beta Customer Feedback Framework  
**Date:** 2026-09-14  

---

## 1. Non-Telemetry Measurement Philosophy

Relay's privacy invariants strictly prohibit embedding telemetry beacons, tracking pixels, or automatic log exfiltration in the product binary.

Instead, production operational performance is measured through:
1. **Explicit Qualitative Feedback Interviews:** Scheduled 30-minute structured interviews with beta participants.
2. **Support & Operational Signals:** Tracking inbound ticket volume, resolution times, and billing dunning frequency.
3. **Voluntary Sanitized Feedback Forms:** Structured web questionnaires where customers opt in to evaluate usability without uploading execution data.

---

## 2. Seven-Dimension Feedback Matrix

Beta participants are evaluated across seven key dimensions:

| Dimension | Core Research Question | Operational Assessment Metric |
| :--- | :--- | :--- |
| **1. Product Understanding** | Do developers and operators clearly understand Relay's role as a local governance gateway? | Percentage of customers who accurately explain the boundary within 15 minutes of onboarding. |
| **2. Security Authority Model** | Is the principle of "Zero Ambient Authority" and OS keyring credential isolation understood? | Customer confirmation that no production API keys were pasted into LLM prompt templates. |
| **3. Independent Installation** | Can an engineering team install and run `relay doctor` without hands-on engineering intervention? | Time-to-first-successful-run (Target: $< 15$ minutes from download). |
| **4. Cedar Policy Authoring** | Are customers able to write, customize, and validate Cedar default-deny policies for their tools? | Number of policy syntax errors reported; ease of configuring read-only database rules. |
| **5. Local Security Console** | Does `relay ui` provide clear, high-contrast visibility into posture, receipts, and health? | Usability rating (1–5 scale); feedback on session expiration and anti-rebinding protections. |
| **6. Cryptographic Evidence** | Do security and compliance auditors understand in-toto receipts and ledger verification? | Auditor acceptance of `relay verify` outputs for chain-of-custody compliance. |
| **7. Commercial & Pricing Model** | Is the per-seat model perceived as fair and predictable compared to metered per-token taxes? | Willingness-to-renew score; feedback on offline license certificate handling. |

---

## 3. Operational Operational Metrics Dashboard (Zero Telemetry)

The beta program tracks metrics collected strictly outside the customer execution path:

| Metric | Target / Benchmark | Source of Truth |
| :--- | :---: | :--- |
| **Beta Cohort Size** | 5–10 Organizations | Commercial Invitation Roster |
| **Onboarding Completion Rate** | $\ge 80\%$ | Beta kickoff interview check-ins |
| **Billing Webhook Success Rate** | $100\%$ | Stripe Dashboard Webhook Log |
| **Installation Friction Tickets** | $\le 2$ tickets per cohort | `support@relay.dev` ticket log |
| **License Verification Failures** | $0$ legitimate failures | Inbound license support inquiries |
| **First Governed Action Executed** | $100\%$ of onboarded cohort | Verified via customer interview |
| **14-Day Refund Requests** | $\le 10\%$ | Stripe refund records |

---

## 4. Feedback Review & Iteration Schedule

1. **Day 1 Check-In:** Verify binary installation, `relay doctor` diagnostics, and initial workspace initialization.
2. **Day 7 Operational Review:** Review first governed agent runs, Cedar policy configurations, and local UI usage.
3. **Day 14 Commercial Evaluation:** Formal review of offline licensing, billing portal satisfaction, and 14-day refund window closure.
4. **Day 30 Beta Exit Interview:** Comprehensive assessment against Beta Exit Criteria before recommending Public Commercial Launch.
