# Relay Commercial Privacy Policy (Counsel-Ready Draft)

**Document ID:** `CR003-LEG-002`  
**Version:** `1.0.0-DRAFT`  
**Effective Date:** `[LAUNCH_DATE_PLACEHOLDER]`  
**Status:** Counsel-Ready Draft for Legal Sign-off  
**Notice:** This document constitutes a formal draft prepared by engineering and data governance teams. It requires final review and adoption by qualified legal counsel prior to commercial publication.

---

## 1. Introduction & Who We Are

This Privacy Policy explains how **`[LEGAL_ENTITY_NAME]`** ("**Relay**", "we", "us", or "our"), trading as Relay, handles personal data across our software, commercial services, website ([https://relay.dev](https://relay.dev)), and customer support channels.

### The Fundamental Data Boundary:
Relay is designed with a strict architectural boundary that separates customer-controlled local software from Relay-operated commercial systems:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. LOCAL RELAY EXECUTION DATA (Customer Controlled — Never Collected)   │
│    Prompts, agent tool arguments, credentials, API keys, SQLite action  │
│    ledger, Ed25519 DSSE action receipts, and local security console     │
│    sessions remain 100% on your local machine or infrastructure.        │
│    Relay does NOT transmit, collect, sync, or observe this data.        │
└─────────────────────────────────────────────────────────────────────────┘
                                   ≠
┌─────────────────────────────────────────────────────────────────────────┐
│ 2. COMMERCIAL & WEBSITE METADATA (Relay Operated — Minimized Collection)│
│    Website visit logs, commercial license purchase records, billing     │
│    metadata, customer support correspondence, and security disclosures. │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Categories of Data We Collect and Do Not Collect

### 2.1 What We NEVER Collect (Local Execution Data)
When you run the Relay binary, CLI (`relay run`, `relay init`), or local web console (`relay ui`):
- **No Agent Telemetry:** We do not collect telemetry on agent execution, model completions, or tool usage.
- **No Prompts or Tool Arguments:** Your prompts, tool inputs, and tool outputs never touch our servers.
- **No Credentials or API Secrets:** Passwords, API tokens, database keys, and SSH credentials stored in Relay's local vault remain exclusively in your local operating system keyring or credential broker.
- **No Action Receipts or Ledger Sync:** The SQLite ledger and signed DSSE receipts reside solely on your local storage.

### 2.2 What We Collect Through Commercial Channels
We collect only the personal information necessary to deliver commercial services, process payments, and provide technical support:

| Data Category | Specific Elements | Source | Purpose & Justification |
| :--- | :--- | :--- | :--- |
| **Commercial Account & License Data** | Name, work email address, company name, license tier, seat count | Provided by you upon purchasing a license | Fulfilling our commercial contract, issuing cryptographically signed offline license keys |
| **Billing & Payment Metadata** | Billing contact name, billing address, country, tax identifier (GSTIN/VAT), last 4 digits of card, Stripe customer ID | Collected securely via Stripe | Contractual necessity, statutory tax compliance, invoice issuance (*we never store full card numbers or CVVs*) |
| **Support & Inquiries** | Email address, ticket title, correspondence text, voluntarily submitted configuration snippets | Provided directly by you via email | Resolving customer support inquiries, fulfilling service level agreements (SLAs) |
| **Security Reports** | Reporter email, name, vulnerability descriptions, proof-of-concept scripts | Sent to `security@relay.dev` | Triage and coordinated disclosure of security vulnerabilities |
| **Website Technical Logs** | IP address, timestamp, HTTP request method/path, User-Agent, referring URL | Automatically logged by edge network (Cloudflare) | Protecting against DDoS attacks, diagnosing network failures, ensuring website security |

---

## 3. Lawful Bases for Processing (Where Applicable)

Where applicable under data protection laws (such as GDPR or India DPDP Act):
1. **Contractual Necessity:** Processing required to issue license keys, manage commercial subscriptions, process payments, and honor support SLAs.
2. **Compliance with Legal Obligations:** Maintaining financial, accounting, and tax records (e.g. GST/VAT statutory retention).
3. **Legitimate Interests:** Securing our website and public infrastructure, defending against abuse and unauthorized access, and coordinating security vulnerability disclosures.
4. **Consent:** When you explicitly opt into optional communications, such as product release notifications or beta test invitations.

---

## 4. Subprocessors and Sharing

We do **not** sell, rent, or monetize personal information. We do **not** share personal data for cross-context behavioral advertising.

We share commercial metadata only with audited service providers acting on our instructions:
- **Payment Processing:** Stripe, Inc. (processes payments, generates invoices, and maintains PCI DSS compliance).
- **Hosting & Edge Delivery:** Cloudflare, Inc. (provides DNS, CDN, and DDoS mitigation for `relay.dev`).
- **Transactional Communications:** Resend, Inc. / AWS SES (delivers license certificates and billing receipts).
- **Code & Distribution Infrastructure:** GitHub, Inc. (hosts open-source repository and public binary release assets).

A complete list of our subprocessors and their locations is maintained at [https://relay.dev/subprocessors](https://relay.dev/subprocessors).

---

## 5. International Data Transfers

When commercial metadata is transferred across borders (e.g. processing by US-based service providers on behalf of an Indian entity), we implement recognized transfer mechanisms:
- Standard Contractual Clauses (SCCs) with vendors.
- Commercial Data Processing Addenda (DPAs) incorporating technical and organizational security measures.

---

## 6. Data Retention Schedules

We retain commercial personal data only for as long as required to fulfill the documented purpose:
- **Billing & Invoice Records:** 7 years, to satisfy statutory Indian Income Tax and GST compliance requirements.
- **License Records:** Active duration of the commercial subscription plus 1 year for audit and renewal purposes.
- **Support Correspondence:** 2 years following ticket closure, unless a shorter deletion request is submitted.
- **Security Vulnerability Disclosures:** 3 years following public resolution, to maintain historical security audit trails.
- **Website Edge Logs:** Automatically purged within 30 days by our edge infrastructure.

---

## 7. Security Measures & Technical Safeguards

We protect commercial data through industry-standard safeguards:
- **Encryption in Transit:** All traffic to `relay.dev` and commercial endpoints requires HTTPS / TLS 1.3 with HSTS.
- **PCI DSS Level 1 Outsourcing:** We never ingest or store primary account numbers (PAN) or security codes.
- **Strict Role-Based Access:** Relay employee access to commercial customer lists and billing data requires multi-factor authentication (MFA) and least-privilege authorization.
- **Air-Gapped Product Isolation:** Relay personnel possess zero technical capability to inspect or access customer-local Relay data.

---

## 8. Notice at Collection (California CCPA / CPRA Notice)

*This Notice at Collection applies to California residents interacting with Relay's commercial services:*

1. **Categories of Personal Information Collected:** Identifiers (name, email, IP address); Commercial Information (records of commercial licenses purchased); Internet or other electronic network activity information (server logs).
2. **Purposes of Collection:** Fulfilling software subscriptions, processing invoices, delivering support, and mitigating malicious traffic.
3. **Sale or Sharing:** Relay does **not** sell personal information and does **not** share personal information for cross-context behavioral advertising.
4. **Retention:** Data is retained according to the retention schedule in Section 6.
5. **Notice of Scope:** Relay does not collect or process sensitive personal information for the purpose of inferring characteristics about consumers.

---

## 9. Your Rights and Choices

Depending on your jurisdiction, you may have statutory rights regarding your personal information:

### 9.1 Indian Data Principals (DPDP Act, 2023)
Under the Digital Personal Data Protection Act, 2023 and the notified Digital Personal Data Protection Rules, 2025:
- **Right to Access:** You may request a summary of the personal data we process about you and the processing activities undertaken.
- **Right to Correction & Erasure:** You may request correction of inaccurate or incomplete data, or erasure of personal data that is no longer necessary for the purpose it was collected.
- **Right of Grievance Redressal:** You have the right to register a grievance with our designated Grievance Officer (`grievance@relay.dev`), who will respond within statutory timelines. If unresolved, you may appeal to the Data Protection Board of India once established.
- **Right to Nominate:** You may nominate an individual to exercise your rights in the event of death or incapacity.

### 9.2 European & UK Data Subjects (GDPR / UK GDPR)
You have rights under Articles 15–22 of the GDPR:
- Right of access, rectification, erasure, restriction of processing, data portability, and objection to processing based on legitimate interests.
- Right to lodge a complaint with your local Data Protection Supervisory Authority.

### 9.3 California Residents (CCPA / CPRA)
You have the right to know what personal information we collect, request deletion, request correction of inaccurate personal information, and be free from discrimination for exercising your privacy rights.

### How to Exercise Your Rights:
To exercise any privacy rights, email **`privacy@relay.dev`** with the subject line *"Privacy Rights Request"*. We verify your identity via your registered commercial email address before acting on your request.

*Note on Local Data:* Because local Relay execution data (prompts, tool calls, receipts) is stored solely on your own device, Relay cannot delete or modify local data on your behalf. You may purge local data at any time using Relay's local CLI tools.

---

## 10. Children's Privacy

Relay's commercial services and software are strictly intended for professional and business use by individuals aged 18 and older. We do not knowingly collect personal data from children under the age of 18.

---

## 11. Changes to This Policy

We may update this Privacy Policy from time to time to reflect changes in our legal obligations, commercial practices, or technical architecture. Material changes will be announced on our website and communicated to active commercial account holders via email at least 30 days before taking effect.

---

## 12. Contact Information & Grievance Redressal

For questions, feedback, or statutory privacy inquiries:

- **Privacy Inquiries:** `privacy@relay.dev`
- **Statutory Grievance Officer (India):**  
  Attn: Grievance Officer  
  `[LEGAL_ENTITY_NAME]`  
  `[REGISTERED_OFFICE_ADDRESS]`, Bangalore, Karnataka 560001, India  
  Email: `grievance@relay.dev`  
  Statutory Response Window: Within statutory timelines prescribed by the DPDP Rules, 2025.
