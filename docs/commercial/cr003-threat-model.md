# Relay CR003 — Commercial Launch Threat Model

**Document ID:** `CR003-THR-001`  
**Version:** `1.0.0`  
**Status:** Threat Modeling Assessment  
**Classification:** Security Architecture Document  
**Date:** 2026-09-14  

---

## 1. Threat Matrix & Attack Vector Analysis

This threat model evaluates adversarial risks introduced by Relay's commercial launch surface, encompassing billing, entitlement issuance, customer support, website delivery, and vendor integrations.

| Threat ID | Threat Vector & Attack Scenario | Inherent Risk | Mitigations & Technical Controls | Residual Risk |
| :--- | :--- | :---: | :--- | :---: |
| **CT-01** | **Forged Billing Webhook (`payment_success=true`)**<br>Attacker sends forged webhook to Relay API claiming a subscription was purchased. | High | - Mandatory HMAC-SHA256 signature verification with Stripe secret.<br>- Constant-time string comparison.<br>- Replay window check ($|t_{\text{now}} - t_{\text{req}}| \le 300\text{s}$).<br>- Idempotency tracking by Stripe event ID. | Low |
| **CT-02** | **Entitlement Forgery / Signature Bypass**<br>Customer or attacker tampers with an offline license file to grant infinite seats or extend expiration. | High | - Cryptographic Ed25519 digital signature over canonicalized JSON claims.<br>- Public key embedded into binary.<br>- Mathematical tamper resistance: any bit change invalidates signature. | Negligible |
| **CT-03** | **Commercial Control Plane Compromise**<br>Attacker compromises Relay's website, billing database, or commercial server, attempting to control customer agent execution. | Critical | - **Zero Inbound Connectivity:** Customer Relay instances never listen to or poll Relay commercial servers.<br>- **No Remote Code Execution:** Relay has no cloud-directed policy override or remote command channel.<br>- Core Cedar policies and local receipts are entirely local. | Negligible |
| **CT-04** | **Support Queue Credential Leakage**<br>Customer accidentally includes API keys, database passwords, or private production logs in a support ticket to `support@relay.dev`. | High | - Clear inbound notice instructing customers never to attach raw secrets.<br>- Automated secret scrubber on inbound support mailboxes.<br>- Operating procedure requiring immediate rotation notification and deletion of ticket content. | Medium |
| **CT-05** | **Website Defacement or Malicious Binary Substitution**<br>Attacker compromises website CDN or release infrastructure to distribute a backdoored Relay binary. | Critical | - Public binaries hosted on GitHub Releases, separate from commercial website.<br>- Every release tarball is accompanied by cryptographic SHA-256 sums and signed by an offline Ed25519 release key.<br>- Multi-maintainer signing procedure. | Low |
| **CT-06** | **Subprocessor Compromise (e.g. Stripe, Resend)**<br>A third-party vendor is breached, leaking customer commercial metadata. | Medium | - Data minimization: vendors only receive data strictly necessary for their function (e.g. Stripe has billing metadata; Resend has recipient email).<br>- Zero customer prompts, tool arguments, or execution receipts are ever sent to vendors. | Low |
| **CT-07** | **Privacy Rights Fraud (Impersonation Attack)**<br>Attacker submits a fraudulent deletion or access request for another customer's commercial records. | Medium | - Identity verification protocol: requests must originate from verified corporate billing email.<br>- Confirmation link / secondary authentication prior to processing deletion.<br>- Local execution data cannot be accessed or deleted by Relay anyway. | Low |
| **CT-08** | **Insider / Employee Abuse**<br>Disgruntled Relay employee attempts to access customer data or eavesdrop on customer operations. | Medium | - Zero-knowledge local architecture: customer execution data is physically inaccessible to Relay employees.<br>- Commercial database access requires MFA, role-based access control, and immutable audit logs. | Low |
| **CT-09** | **DNS Rebinding Against Local UI**<br>Attacker tricks a developer's browser into accessing `127.0.0.1:9876` via a malicious domain. | High | - Strict HTTP `Host` header enforcement (`localhost` or `127.0.0.1` only).<br>- Ephemeral Bearer token required for all API routes.<br>- Mutating routes require strict `Origin` header matching. | Negligible |
| **CT-10** | **Payment-Gated Security Vulnerability (Extortion Risk)**<br>Adversary claims that non-paying users have crippled security or unpatched vulnerabilities. | Medium | - Apache 2.0 open-core policy: all security invariants (SI-001 through SI-024) and security patches are released simultaneously to open source and paid users.<br>- No paywalled security patches. | Negligible |

---

## 2. Deep Dive: The Commercial Control Plane Boundary

A central question of this commercial launch review is:

> **Can compromise of the commercial control plane grant authority inside local Relay?**

### The Definitive Answer: **NO.**

### Engineering Proof & Invariants:
1. **No Ingress Port:** The local Relay execution daemon does not open any external network listening sockets. The only HTTP listener is the local UI, which binds exclusively to loopback `127.0.0.1`.
2. **No Egress Polling:** The local Relay daemon never connects to Relay cloud servers to fetch dynamic Cedar policies, check subscription revocation, or query execution approvals.
3. **Deterministic Local Decision:** Cedar policy evaluations (`is_authorized`) evaluate strictly against policies loaded from the local filesystem.
4. **Offline Entitlement Verification:** The license validator performs only a local mathematical verification of the Ed25519 signature on the offline license certificate against a hardcoded public key.

An attacker with root access to Relay's commercial web servers or Stripe account can modify billing records or revoke license tokens, but cannot execute a single tool call, read a single customer receipt, or alter a single local Cedar policy on any customer machine.
