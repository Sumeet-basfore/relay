# Relay Commercial Terms of Service (Counsel-Ready Draft)

**Document ID:** `CR003-LEG-003`  
**Version:** `1.0.0-DRAFT`  
**Effective Date:** `[LAUNCH_DATE_PLACEHOLDER]`  
**Status:** Counsel-Ready Draft for Legal Sign-off  
**Notice:** This document is a draft prepared for review and execution by qualified legal counsel. It defines the contractual terms governing commercial offerings and support services.

---

## 1. Structure of Agreement & Service Definition

These Terms of Service ("**Terms**") constitute a binding contract between **`[LEGAL_ENTITY_NAME]`** ("**Relay**", "we", "us", or "our") and the individual or entity agreeing to them ("**Customer**" or "you").

### 1.1 Separation Between Open Core and Commercial Services
- **Open-Core Software:** The Relay engine, CLI, and local security console distributed in source or binary form are licensed separately under the terms of the **Apache License, Version 2.0** ("Apache 2.0"). Nothing in these Terms limits or restricts your rights under the Apache 2.0 license to the open-source software.
- **Commercial Services:** These Terms govern your purchase, access, and use of paid commercial licenses, enterprise policy packages, commercial support services, service level agreements (SLAs), and any Relay-operated commercial portals (collectively, "**Commercial Services**").

---

## 2. Accounts, Subscriptions, and Entitlements

### 2.1 Eligibility & Authority
If you enter into these Terms on behalf of an organization or corporate entity, you represent and warrant that you have full legal authority to bind that entity.

### 2.2 Commercial Subscriptions & Offline Entitlements
Commercial Services are provided on a recurring subscription basis (e.g. monthly or annual). Upon confirmed payment, Relay issues a cryptographically signed offline license certificate ("**License Key**") granting entitlements to the subscribed seat tier.
- Commercial License Keys are non-transferable and may only be utilized within the Customer's internal organization.
- Customer agrees not to forge, tamper with, reverse engineer, or mathematically alter the digital signature of any License Key.

---

## 3. Fees, Invoicing, Taxes, and Payment

### 3.1 Payment Processing
Customer authorizes Relay (through its designated payment processor, Stripe) to charge the designated payment method for all applicable subscription fees. All payments are billed in advance.

### 3.2 Taxes & Statutory Withholding
All fees stated on our website or invoices are exclusive of all applicable indirect taxes, value-added taxes (VAT), Goods and Services Tax (GST), customs duties, and similar governmental assessments. Customer is responsible for paying all applicable taxes. If Customer is legally required to withhold taxes, Customer will gross up payments such that Relay receives the full invoiced amount.

### 3.3 Cancellation & Refunds
- **Cancellation:** Customer may cancel their commercial subscription at any time via the billing portal. Cancellation becomes effective at the end of the current paid billing period.
- **Refunds:** All refund requests are governed by our [Refund Policy](file:///home/sumeet/relay/docs/legal/refund-policy-spec.md). For first-time subscriptions, Customer may request a full refund within fourteen (14) calendar days of initial purchase by contacting `billing@relay.dev`.

---

## 4. Customer Security Responsibilities & Acceptable Use

### 4.1 Customer Operational Responsibilities
Customer acknowledges that Relay is a local-first governance layer operating on Customer-controlled infrastructure:
- **Host Security:** Customer is solely responsible for the physical and operational security of the operating systems, containers, and machines executing Relay.
- **Credential Protection:** Customer maintains sole custody of API keys, tokens, and database passwords stored in local vaults.
- **Cedar Policy Authoring:** Relay provides the policy evaluation engine; Customer is solely responsible for creating, reviewing, and approving Cedar authorization policies appropriate for their security posture.
- **Human Interactive Approvals:** Customer is responsible for ensuring designated operators carefully inspect out-of-band `/dev/tty` approval prompts before confirming actions.

### 4.2 Prohibited Use
Customer shall not use Commercial Services:
1. To violate any applicable local, national, or international law or regulation.
2. In connection with hazardous or ultra-critical systems where failure could lead directly to death, personal injury, catastrophic physical property destruction, or severe environmental damage.
3. To deliberately distribute malware, weaponized exploits, or circumvent third-party security systems without authorization.
4. To probe, scan, or test the vulnerability of Relay-operated websites, payment systems, or support infrastructure without written permission.

---

## 5. Third-Party Integrations & Large Language Models

Customer acknowledges that:
1. Relay governs interactions with upstream target resources and Model Context Protocol (MCP) servers. Relay is not responsible for upstream outages, network failures, or service disruptions of third-party APIs (e.g. GitHub, AWS, OpenAI, Anthropic).
2. Relay enforces authorization at the action and credential boundary; Relay does not warrant that third-party LLMs will generate semantically correct or error-free tool invocations.

---

## 6. Intellectual Property & Feedback

1. **Relay Ownership:** Relay retains all right, title, and interest in and to the Commercial Services, documentation, trademarks, and all related intellectual property rights not expressly granted under Apache 2.0.
2. **Customer Data:** Customer retains full and exclusive ownership of all local execution data, prompts, tool outputs, receipts, and SQLite ledger entries. Relay asserts no proprietary interest or copyright over Customer execution data.
3. **Feedback:** If Customer provides suggestions, enhancements, or feedback regarding Relay, Relay may freely use and exploit such feedback without restriction or financial obligation.

---

## 7. Disclaimers of Warranties

EXCEPT AS EXPRESSLY SET FORTH IN A FORMAL WRITTEN ENTERPRISE AGREEMENT SIGNED BY AN AUTHORIZED OFFICER OF RELAY:
- COMMERCIAL SERVICES ARE PROVIDED ON AN "AS IS" AND "AS AVAILABLE" BASIS.
- RELAY EXPRESSLY DISCLAIMS ALL WARRANTIES OF ANY KIND, WHETHER EXPRESS, IMPLIED, OR STATUTORY, INCLUDING WITHOUT LIMITATION THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT.
- RELAY DOES NOT WARRANT THAT THE SOFTWARE OR SERVICES WILL BE UNINTERRUPTED, ERROR-FREE, IMMUNE FROM MALICIOUS ACTS, OR COMPLETELY FREE FROM SECURITY VULNERABILITIES.

---

## 8. Limitation of Liability

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW:
1. **Consequential Damages Waiver:** IN NO EVENT SHALL EITHER PARTY BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, PUNITIVE, OR CONSEQUENTIAL DAMAGES, INCLUDING LOSS OF PROFITS, DATA, USE, GOODWILL, OR BUSINESS INTERRUPTION, ARISING OUT OF OR IN CONNECTION WITH THESE TERMS OR THE USE OF COMMERCIAL SERVICES, WHETHER BASED ON CONTRACT, TORT (INCLUDING NEGLIGENCE), OR ANY OTHER LEGAL THEORY.
2. **Aggregate Liability Cap:** THE TOTAL AGGREGATE LIABILITY OF RELAY ARISING OUT OF OR RELATING TO THESE TERMS OR THE COMMERCIAL SERVICES SHALL BE STRICTLY LIMITED TO THE GREATER OF: (A) THE TOTAL FEES ACTUALLY PAID BY CUSTOMER TO RELAY UNDER THESE TERMS IN THE TWELVE (12) MONTHS PRECEDING THE EVENT GIVING RISE TO LIABILITY; OR (B) ONE HUNDRED UNITED STATES DOLLARS ($100 USD).

---

## 9. Term, Suspension, and Termination

1. **Term:** These Terms commence upon Customer's purchase or use of Commercial Services and continue until terminated.
2. **Termination for Cause:** Either party may terminate immediately if the other party breaches a material provision of these Terms and fails to cure such breach within thirty (30) days of receiving written notice.
3. **Effect of Termination:** Upon termination of Commercial Services, Customer's commercial support and enterprise SLAs terminate. **Termination of these Terms does not revoke or impair Customer's continued right to use the Apache 2.0 open-core software.**

---

## 10. Governing Law and Dispute Resolution

1. **Governing Law:** These Terms and any dispute arising out of or related to them shall be governed by and construed in accordance with the substantive laws of the **Republic of India**, without regard to conflict of laws principles.
2. **Arbitration:** Any dispute, controversy, or claim arising under or relating to these Terms shall be referred to and finally resolved by binding arbitration under the **Arbitration and Conciliation Act, 1996**. The arbitration shall be conducted in Bangalore, Karnataka, India, before a sole arbitrator mutually appointed by the parties. The language of arbitration shall be English.
3. **Equitable Relief:** Notwithstanding the foregoing, either party may seek emergency injunctive or equitable relief before any court of competent jurisdiction in Bangalore, India, to protect its intellectual property or trade secrets.
