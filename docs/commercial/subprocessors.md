# Relay Commercial Subprocessor Register

**Document ID:** `CR003-SUB-001`  
**Version:** `2.0.0`  
**Status:** Audited Commercial Subprocessor Register  
**Effective Date:** 2026-09-14  

---

## 1. Scope & Policy

This Subprocessor Register identifies all third-party vendors and service providers engaged by Relay to process personal or operational metadata in connection with our commercial services, website ([https://relay.dev](https://relay.dev)), billing, and technical support.

### Customer Local Execution Exemption
Relay's open-core software runs entirely on the customer's own local machine or private cloud infrastructure. Prompts, agent tool invocations, local action receipts, SQLite ledger records, and target credentials **never leave the customer's device**. Therefore, Relay does not engage any subprocessors for customer-local software execution.

---

## 2. Active Commercial Subprocessors

The following service providers have been vetted, contracted, and integrated for commercial operations:

| Subprocessor Legal Name | Service Provided | Purpose & Activity | Categories of Data Processed | Processing & Storage Location | Security & Compliance Certifications | Contractual Status & Transfer Mechanism |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Stripe, Inc.** (and affiliates: Stripe Payments Europe, Ltd., Stripe India) | Payment Processing & Billing Portal | Card payment collection, subscription management, tax computation, invoicing | Billing contact name, billing address, country, tax IDs (GSTIN/VAT), last 4 digits of card, Stripe customer IDs | United States, European Union, India | PCI DSS Level 1 Service Provider, SOC 1 Type II, SOC 2 Type II | DPA executed with Standard Contractual Clauses (SCCs) |
| **GitHub, Inc.** (Microsoft Corporation) | Code Repository & Release Hosting | Source code version control, public binary asset downloads (`install.sh`), public issue tracking | GitHub account username, commit metadata, download request IP address & User-Agent | United States | SOC 1 Type II, SOC 2 Type II, ISO/IEC 27001 | GitHub Enterprise Agreement & Data Protection Addendum |
| **Cloudflare, Inc.** | Edge CDN, DNS & DDoS Defense | Web content delivery, DNS routing, edge DDoS mitigation for `relay.dev` | Request IP address, HTTP headers (User-Agent, referer), request timestamp | Global Anycast Edge Network (US, EU, Asia) | ISO/IEC 27001, SOC 2 Type II, PCI DSS Level 1 | DPA executed with Standard Contractual Clauses (SCCs) |
| **Resend, Inc.** / **Amazon Web Services, Inc. (AWS SES)** | Transactional Email Delivery | Delivering offline license certificates, renewal reminders, and security bulletins | Recipient email address, recipient name, license key payload metadata | United States | SOC 2 Type II, ISO/IEC 27001, FedRAMP | Vendor DPA with Standard Contractual Clauses (SCCs) |

---

## 3. Explicit Customer Targets (Not Subprocessors)

The following entities connect to Relay only upon the explicit, local configuration of the customer and are **not** Relay subprocessors:

| Entity | Customer Relationship | Rationale |
| :--- | :--- | :--- |
| **Customer's GitHub Organization** | Configured Target API | Customer configures local connector with their own token; Relay proxies requests locally. |
| **Customer's PostgreSQL Database** | Configured Target DB | Database connection strings and queries remain local to customer environment. |
| **Customer's Upstream LLM / Agent** | Agent Orchestration Layer | LLMs interface with Relay via local stdio or loopback MCP; Relay never sends prompts to Relay cloud. |
| **Customer's External MCP Servers** | Governed Tool Servers | Governed locally via anti-SSRF and Cedar PEP mediation. |

---

## 4. Subprocessor Governance & Modification Procedure

1. **Vendor Security Due Diligence:** Prior to onboarding, all potential subprocessors must undergo technical security review (verifying independent SOC 2 Type II or ISO 27001 audits) and privacy risk assessment.
2. **Contractual Safeguards:** Every subprocessor must execute a binding Data Processing Addendum (DPA) incorporating strict purpose limitation, confidentiality, and approved cross-border data transfer mechanisms.
3. **Advance Customer Notification:** Relay maintains this public register and provides at least thirty (30) days' advance notice to commercial enterprise customers prior to authorizing any new subprocessor.
