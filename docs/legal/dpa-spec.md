# Relay Data Processing Addendum (DPA) Specification

**Document ID:** `CR003-LEG-004`  
**Version:** `1.0.0`  
**Status:** DPA Specification for Commercial Operations  
**Date:** 2026-09-14  

---

## 1. DPA Applicability Assessment

A Data Processing Addendum (DPA) is **not automatically required for all Relay users**. The legal necessity of a DPA depends strictly on the service tier and data flow:

```text
┌────────────────────────────────────────────────────────────────────────┐
│ Scenario A: Pure Open-Core / Local Binary Usage                        │
│ ───────────────────────────────────────────────────────────────────────│
│ Customer downloads and runs Relay locally on premises or VPC.          │
│ All prompts, tool args, logs, and credentials stay on customer device. │
│ ──► DPA IS NOT APPLICABLE: Relay is not a Processor / Data Fiduciary. │
│     Relay is purely a software provider.                               │
└────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────┐
│ Scenario B: Commercial Support & Enterprise Services                   │
│ ───────────────────────────────────────────────────────────────────────│
│ Customer purchases commercial licenses and transmits support tickets,  │
│ configuration snippets, or enterprise identity records to Relay.       │
│ ──► DPA IS APPLICABLE: Required upon enterprise customer request to    │
│     govern personal data in support queues and account systems.        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Core Terms of the Enterprise DPA

Where an enterprise customer executes a DPA with Relay, the agreement shall incorporate the following core provisions:

### 2.1 Roles of the Parties
- **Customer as Controller / Data Fiduciary:** Customer determines the purposes and means of processing personal data within its systems.
- **Relay as Processor / Data Processor:** For Commercial Services, Relay processes commercial customer data solely in accordance with Customer's documented instructions and the Terms of Service.

### 2.2 Scope and Subject Matter of Processing
- **Subject Matter:** Providing technical support, commercial license issuance, and billing services.
- **Duration:** The term of the commercial subscription agreement plus post-termination retention periods required by law.
- **Nature and Purpose:** Ingesting support communications, verifying license compliance, issuing cryptographic license keys.
- **Categories of Personal Data:** Business contact information (names, corporate email addresses, job titles), support correspondence.
- **Categories of Data Subjects:** Customer's employees, contractors, and designated system administrators.

### 2.3 Subprocessor Management
- **Authorized Subprocessors:** Customer provides general written authorization for Relay to engage the subprocessors listed on Relay's public register ([https://relay.dev/subprocessors](https://relay.dev/subprocessors)).
- **Notification of Changes:** Relay will notify Customer of any planned additions or replacements of subprocessors with at least thirty (30) days prior notice.
- **Contractual Flow-Down:** Relay imposes data protection and security obligations on subprocessors that are substantially equivalent to those in this DPA.

### 2.4 Confidentiality & Security Measures
- **Staff Confidentiality:** Relay ensures that personnel authorized to process Customer personal data are bound by appropriate confidentiality obligations.
- **Technical & Organizational Measures (TOMs):** Relay implements the security safeguards set forth in the [Commercial Security Addendum](file:///home/sumeet/relay/docs/legal/security-addendum-spec.md), including transport encryption, access controls, and vulnerability scanning.

### 2.5 Data Subject / Data Principal Requests
- Relay will promptly notify Customer if Relay receives a request directly from an individual data subject relating to Customer's account.
- Relay will provide commercially reasonable assistance to enable Customer to fulfill its obligations to respond to data subject requests under GDPR, DPDP Act 2023, or CCPA.

### 2.6 Deletion or Return of Data
Upon termination of the commercial agreement, Relay shall, at Customer's choice, delete or return all Customer personal data in Relay's possession, unless applicable statutory law requires continuing retention (e.g. tax and accounting laws).

### 2.7 International Data Transfers
For transfers of personal data from the EU/EEA, UK, or Switzerland to jurisdictions without an adequacy decision, the parties agree to incorporate the European Commission's Standard Contractual Clauses (SCCs) (Module 2: Controller-to-Processor).

### 2.8 Audits and Inspections
Relay will make available to Customer information reasonably necessary to demonstrate compliance with this DPA, and allow for reasonable audits conducted by Customer or an independent auditor upon at least thirty (30) business days written notice.
