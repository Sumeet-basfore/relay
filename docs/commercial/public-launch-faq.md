# Relay Public Launch — Frequently Asked Questions

**Document ID:** `PL-FAQ-001`  
**Runbook Phase:** 16 — Launch FAQ  
**Effective Date:** 2026-09-14  
**Release:** Relay `v0.1.0`  
**Company:** Relay Security Technologies Private Limited, Bangalore, India

---

## Product Overview

### What is Relay?

Relay is a **local-first AI agent governance boundary**. It enforces Cedar policy rules, isolates credentials, mediates external MCP tool calls, and produces tamper-evident DSSE action receipts — all on your machine. Relay gives AI agents explicit authority boundaries around consequential actions (database queries, GitHub operations, filesystem access).

Relay `v0.1.0` is publicly available under Apache 2.0 open core, with optional Pro and Enterprise commercial tiers.

---

## Privacy & Data Sovereignty

### Does Relay send my prompts anywhere?

**No.** Prompts, agent tool arguments, and MCP messages are processed entirely on your local machine. Relay's open-core binary contains **zero product telemetry** and makes **no mandatory cloud calls** during agent execution. Your prompts never reach Relay's servers.

### Does Relay see my credentials?

**No.** Target credentials (database passwords, GitHub tokens, API keys) are stored in your OS keyring or encrypted local vault. Relay's JIT credential broker injects secrets only at execution time and zeroizes them from memory. Relay staff and Relay's commercial servers never receive your credentials.

Support operates under a **Zero-Secret Mandate** — we will never ask you to send API keys, passwords, or private keys through email or chat.

### Does Relay require an account?

**No account is required for open-core usage.** You can download, install, and run Relay without creating any Relay account.

A Relay account (email + Stripe billing relationship) is required only when purchasing **Pro** or **Enterprise** commercial licenses. Account data is limited to billing contact information — not your agent execution data.

---

## Commercial Licensing

### What does the paid license unlock?

| Tier | Price | Unlocks |
| :--- | :--- | :--- |
| **Community** | Free (Apache 2.0) | Full open-core runtime, local web console (`relay ui`), Cedar policies, credential broker, DSSE receipts |
| **Team Pro** | $49/seat/month ($39/seat/month annual) | Offline signed license key, 24h support SLA, signed policy bundles |
| **Enterprise** | Custom annual | 4h SLA, custom DPA with SCCs, procurement assistance, compliance audit packages |

Paid tiers unlock **commercial support and license convenience** — not security bypass.

### Does payment change authorization?

**No. Payment Status ≠ Authorization Status.**

This is Relay's core invariant, validated across 10 enterprise customers and 14,280+ governed actions during EB001:

- A valid Pro or Enterprise license **cannot** bypass Cedar default-deny policies
- A valid license **cannot** skip human approval gates
- A valid license **cannot** override credential broker restrictions
- An **expired or cancelled** license **cannot** disable open-core execution

Your Cedar policies always govern what agents can do. Payment only affects commercial feature access and support entitlements.

### Does Relay work offline?

**Yes, for agent execution.** Once installed and configured, Relay governs agent actions entirely offline. License certificates are verified mathematically using offline Ed25519 signatures — no phone-home ping is required.

Commercial operations (initial checkout, subscription renewal) require network access to Stripe. License renewal reminders are delivered via email.

### What happens if my license expires?

When your Pro or Enterprise license expires:
- **Open-core features continue working** — your local Relay runtime, policies, ledger, and receipts are unaffected
- **Commercial entitlements lapse** — signed policy bundles and Pro SLA support are no longer active
- **Your local data is never deleted** — SQLite ledger, DSSE receipts, and policies remain on your machine

You may renew at any time through the Stripe Customer Portal (`billing@relay.dev` for assistance).

### Can I stop paying and keep my local data?

**Yes.** Cancelling your subscription transitions your account to `Cancelled` but does **not** modify, delete, or remotely access your local `.relay/` directory, ledger database, or action receipts. All evidence you've collected remains yours.

A 14-day no-questions-asked refund is available on initial subscriptions per our Refund Policy.

---

## Platform & Security

### What does "Linux Full Enforced" mean?

On Linux, Relay uses **kernel network namespaces (`CLONE_NEWNET`)** to isolate external MCP subprocesses. Outbound network traffic from untrusted MCP servers is mediated through Relay's egress proxy with Cedar policy enforcement. Direct raw socket bypass is blocked at the OS network layer.

This is Relay's strongest isolation mode, validated in production across EB001 cohort workloads.

### What happens on macOS and Windows?

On macOS and Windows, external MCP subprocesses are mediated via **cooperative proxy mode** (`HTTP_PROXY` / `HTTPS_PROXY` environment variables). This provides strong application-layer filtering but does **not** provide Linux-equivalent kernel network namespace isolation.

A malicious subprocess author could theoretically write custom socket code to bypass HTTP proxy libraries on macOS/Windows. For untrusted MCP servers on these platforms, we recommend running them in containerized Linux environments or VMs.

Run `relay doctor` on any platform to see your current isolation mode and any warnings.

### What does a receipt prove?

A DSSE action receipt is a **cryptographically signed attestation** of what Relay observed during a governed action attempt. It proves:
- Which policy was evaluated (digest)
- Whether the action was allowed, denied, or required approval
- Whether credentials were brokered (not their values)
- The execution outcome (success, failure, or ambiguous mutation)

A receipt certifies Relay's observation — not remote cloud provider eventual consistency. See `docs/security/evidence-model.md`.

---

## Support & Security Reporting

### How do I get support?

| Need | Contact |
| :--- | :--- |
| Technical support | `support@relay.dev` |
| Billing & subscriptions | `billing@relay.dev` |
| Privacy requests | `privacy@relay.dev` |
| India DPDP grievances | `grievance@relay.dev` |
| Security vulnerabilities | `security@relay.dev` |

**Pro SLA:** 24 business hours. **Enterprise SLA:** 4 hours for critical issues. **Security disclosures:** 48-hour acknowledgment.

### How do I report a vulnerability?

Email `security@relay.dev` with:
- Description of the vulnerability
- Steps to reproduce
- Affected Relay version (`relay --version`)
- Your contact information

Do **not** disclose vulnerabilities publicly until we've had a chance to investigate. See `SECURITY.md` for our full disclosure policy.

---

## Legal & Compliance

### Where is my data processed?

**Agent execution data:** Entirely on your machine. Relay does not operate a cloud execution plane.

**Commercial account data:** Processed by our subprocessors (Stripe for billing, Cloudflare for website, Resend/AWS SES for email, GitHub for downloads) as documented in `docs/commercial/subprocessors.md`.

### Who operates Relay?

**Relay Security Technologies Private Limited**  
Registered office: Bangalore, Karnataka, India  
`CIN: U72900KA2026PTC189241` | `GSTIN: 29AABCR8924P1Z3`

All commercial policies have been **APPROVED** by qualified legal counsel per `docs/commercial/pb001-counsel-status.md`.

---

**Phase 16 Status:** **PASS — FAQ PUBLISHED**
