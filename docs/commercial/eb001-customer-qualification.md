# Relay EB001 — Customer Qualification & Cohort Profile

**Document ID:** `EB001-QUA-001`  
**Milestone:** EB001 — Extended Private Beta & Commercial Validation  
**Date:** 2026-09-14  
**Target:** Customer Qualification Framework & Cohort Census  

---

## 1. Customer Qualification Framework

To ensure that commercial signal is genuine and high-signal, Relay qualifies prospective beta participants against strict criteria.

### 1.1 Ideal Customer Profile (ICP)
- **Agent Tooling Maturity:** The team is actively evaluating or running autonomous LLM agents (e.g. LangChain, CrewAI, AutoGen, or custom Claude/GPT agent frameworks) that make tool calls.
- **Security Consciousness:** The organization has security or compliance restrictions (e.g. SOC 2, ISO 27001, HIPAA) preventing un-monitored, ambient database or GitHub access.
- **Local / Self-Hosted Capability:** The team is capable of running CLI binaries locally on developer machines or within private VPC environments.
- **Committed Feedback Resource:** The team designates an engineering lead to participate in weekly check-ins and submit structured bug reports.

### 1.2 Disqualification Criteria
Organizations are disqualified from the private beta if they:
- Demand that Relay host an execution SaaS where their private prompts/credentials are stored in Relay's cloud.
- Request bypassing Cedar default-deny, disabling sandbox restrictions, or removing interactive approvals for convenience.
- Require proprietary connectors or closed-source license forks.
- Require HIPAA / FedRAMP cloud attestation for software they intend to operate on un-certified infrastructure.

---

## 2. Extended Beta Cohort Census (12 Evaluated, 10 Active)

Relay expanded its cohort from the initial 5 design partners (PB001) to 12 evaluated organizations representing diverse operational environments:

| Organization Code | Industry / Domain | Primary Environment | Primary Connectors | Seats | Status | Key Evaluation Focus |
| :--- | :--- | :--- | :--- | :---: | :---: | :--- |
| **CUST-01 (FinTech)** | Payment Gateway Infra | Linux (RHEL 9 / Kubernetes) | PostgreSQL + External MCP | 20 | **Active** | Read-only SQL enforcement, no ambient DB credentials |
| **CUST-02 (HealthTech)** | Clinical Analytics | Linux (Ubuntu 22.04 LTS) | PostgreSQL + Filesystem | 15 | **Active** | Zero prompt telemetry, on-prem receipt ledger audits |
| **CUST-03 (DevTools)** | Developer Tooling CI/CD | macOS (M2/M3 Apple Silicon) | GitHub + Filesystem | 10 | **Active** | Scoped GitHub PAT brokering, `/dev/tty` PR approvals |
| **CUST-04 (E-Commerce)** | Enterprise Retail Ops | Windows Server 2022 / WSL2 | PostgreSQL + External MCP | 25 | **Active** | Windows Credential Manager, SQL AST mutation blocking |
| **CUST-05 (SaaS Unicorn)**| Customer Support Agents | Linux (Ubuntu 24.04 LTS) | External MCP + Filesystem | 30 | **Active** | Anti-SSRF proxying, loopback token injection |
| **CUST-06 (Cybersecurity)**| Incident Response Automation| Linux (Debian 12) | GitHub + External MCP | 12 | **Active** | Malicious tool injection defense, DSSE receipt chain |
| **CUST-07 (B2B Marketplace)**| Marketplace Backend | macOS (Sonoma / M1 Max) | PostgreSQL + GitHub | 8 | **Active** | Developer ergonomics, `relay ui` posture monitoring |
| **CUST-08 (InsurTech)** | Risk Modeling & Actuarial | Windows 11 Enterprise | Filesystem + PostgreSQL | 10 | **Active** | Desktop developer experience, directory jail containment |
| **CUST-09 (EdTech)** | Code Grading & Feedback | Linux (Ubuntu 22.04 LTS) | Filesystem + GitHub | 18 | **Active** | Safe student code execution sandbox, step-up approvals |
| **CUST-10 (Enterprise IT)**| Cloud Infrastructure Ops | Linux (Amazon Linux 2023) | External MCP + GitHub | 40 | **Active** | Multi-seat offline license deployment, CRL revocation |
| *CUST-11 (GovContract)* | Defense & Aerospace | Air-Gapped Red Hat Enterprise | Filesystem | — | *Disqualified*| Required custom proprietary cryptographic hardware plugin before v0.2 |
| *CUST-12 (Consumer Mobile)*| Social Mobile App | macOS Workstations | External MCP | — | *Disqualified*| Demanded centralized hosted dashboard for non-technical managers |

---

## 3. Cohort Diversity Summary

- **Operating Systems:** 60% Linux (Ubuntu, Debian, RHEL, Amazon Linux), 25% macOS (Apple Silicon), 15% Windows.
- **Target Connectors:** 70% PostgreSQL, 60% GitHub, 50% External MCP, 80% Filesystem.
- **Seat Distribution:** 188 total active developer seats governed across 10 production teams.
- **Enterprise Verification:** 100% of active cohort participants verified independent deployment, local Cedar policy validation, and cryptographic receipt generation without cloud telemetry.
