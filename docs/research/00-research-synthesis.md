# R000: Authoritative Research Synthesis & Ground Truth Record for Relay

**Document ID:** `00-research-synthesis`  
**Date:** September 2026  
**Status:** Authoritative Baseline / Product Input  
**Target:** Relay Strategy & Core Product Definition  
**Evidence Base:** `R001` (Market), `R002` (Eve Forensics), `R003` (Authority Model), `R004` (Standards & Interoperability), `R005` (Threat Model), `R006` (User Workflows), `R007` (Adversarial Review)

---

## Executive Summary & Epistemic Taxonomy

This synthesis establishes the authoritative ground truth for Relay by resolving contradictions, evaluating empirical evidence, and categorizing all foundational claims across the research corpus. 

### Epistemic Classification Scheme
Every key claim throughout this record is tagged according to its evidentiary standing:
* **`[CONFIRMED]`**: Empirically proven by reproducible code forensics, protocol specifications, or documented security post-mortems.
* **`[SUPPORTED]`**: Validated by strong structural analysis, standards alignment, and practitioner consensus; edge cases remain.
* **`[PROBABLE]`**: Logically sound and market-consistent, but lacking large-scale production validation.
* **`[UNCERTAIN]`**: Conflicting evidence, unproven market appetite, or unresolved technical bottlenecks.
* **`[CONTRADICTED]`**: Refuted by technical realities or architectural impossibilities uncovered during forensics.
* **`[REJECTED]`**: Proven infeasible, redundant, or fatal to project success; explicitly removed from scope.

---

## 1. Problem Statement

### The Core Problem
> **As AI agents transition from read-heavy conversational assistants to state-mutating execution workloads, organizations cannot grant them write access to production tools and infrastructure because there is no deterministic control plane to intercept, authorize, and isolate their actions at the protocol boundary.** `[CONFIRMED]`

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   THE CORE OPERATIONAL DILEMMA                                   │
├───────────────────────────────────────────────────┬──────────────────────────────────────────────┤
│ Posture A: The "Read-Only / Draft-Only" Quarantine│ Posture B: The "Unbounded Ambient Key" Trap  │
├───────────────────────────────────────────────────┼──────────────────────────────────────────────┤
│ • Agents generate diffs, text drafts, suggestions.│ • Agents hold static admin API keys or PATs. │
│ • Humans manually review, copy-paste, and execute.│ • Probabilistic system prompts serve as auth.│
│ • Destroys 70%+ of agent productivity gains.      │ • Fatal vulnerability to Prompt Injection.   │
│ • Status: Enterprise Deadlock.                    │ • Status: Existential Breach Risk.           │
└───────────────────────────────────────────────────┴──────────────────────────────────────────────┘
```

### Supporting Evidence & Realities
1. **Model Non-Determinism Cannot Enforce Safety:** LLM prompt engineering, system instructions, and "Constitutional AI" are probabilistic and trivially bypassed by Direct and Indirect Prompt Injection (`[CONFIRMED]` — R005 §3.1, R007 §1.6). Security invariants must be enforced deterministically out-of-band.
2. **The Autonomy Paradox:** An agent's economic value scales with its ability to execute side effects (mutating databases, modifying cloud infrastructure, merging code, issuing transactions), but enterprise deployment is capped because a single malformed payload or injection can cause catastrophic state corruption (`[CONFIRMED]` — R006 §0).
3. **Ambient Credential Vulnerability:** Developers currently pass long-lived, high-privilege credentials into local agent processes and environment variables, creating a massive Confused Deputy vulnerability (`[CONFIRMED]` — R003 §3.1, R005 §3.2, R006 §5).

---

## 2. Market Reality

The 2026 AI governance and security market is characterized by intense marketing noise and structural category confusion.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    2026 MARKET TAXONOMY & REALITY                                │
├──────────────────────────┬─────────────────────────────────────┬─────────────────────────────────┤
│ Market Segment           │ Incumbents / Leaders                │ What They Actually Deliver      │
├──────────────────────────┼─────────────────────────────────────┼─────────────────────────────────┤
│ 1. Enterprise IAM        │ Microsoft Entra, Okta/Auth0, AWS IAM│ Identity, OIDC/OAuth tokens,    │
│                          │                                     │ Token Vaults (No semantic gates)│
├──────────────────────────┼─────────────────────────────────────┼─────────────────────────────────┤
│ 2. Model Firewalls       │ Lakera, Prompt Security, Cisco,     │ L7 LLM prompt/response filtering│
│                          │ Bedrock Guardrails, Model Armor     │ (Probabilistic NLP classifiers) │
├──────────────────────────┼─────────────────────────────────────┼─────────────────────────────────┤
│ 3. Agent Observability   │ LangSmith, Braintrust, Arize,       │ Post-hoc tracing, span logging, │
│                          │ OpenInference, Traceloop            │ eval benchmarks (Non-blocking)  │
├──────────────────────────┼─────────────────────────────────────┼─────────────────────────────────┤
│ 4. Policy Engines        │ AWS Cedar, OPA / Styra, Permit.io   │ Fast boolean ABAC/RBAC engines  │
│                          │                                     │ (Lack agent context/tool glue)  │
├──────────────────────────┼─────────────────────────────────────┼─────────────────────────────────┤
│ 5. Agent Control Plane   │ VACUUM / UNCLAIMED                  │ Deterministic tool interception,│
│    (Relay Domain)        │                                     │ zero-knowledge credential PEP   │
└──────────────────────────┴─────────────────────────────────────┴─────────────────────────────────┘
```

### Market Ground Truths
* **"AI Governance" is 80%+ Post-Hoc Observability or Prompt Filtering:** Most commercial tools market telemetry as governance. They monitor what happened after execution or filter text strings at the LLM gateway. Neither intercepts or validates the concrete API payload before execution (`[CONFIRMED]` — R001 §1, R007 §1.10).
* **Enterprise Identity is Consolidating Rapidly:** Microsoft Entra and Okta/Auth0 are aggressively deploying Agent Identities, Workload Identity Federation, and OAuth Token Vaults. Relay cannot and must not compete in user/workload identity minting (`[CONFIRMED]` — R001 §2.1, R007 §1.2).
* **Model Context Protocol (MCP) is the De Facto Tool Interface:** Anthropic's MCP has emerged as the universal standard for tool discovery and execution across IDEs, desktop clients, and custom agents. However, MCP currently lacks fine-grained authorization, parameter inspection, and zero-knowledge credential injection (`[CONFIRMED]` — R001 §2.6, R004 §1.1).
* **No Standalone "Agent Control Plane" Budget Category Exists Yet:** Enterprise buyers (CISOs, Platform VPs) do not have a pre-allocated budget line for agent action proxies. Purchasing is driven through Cloud Security, DevSecOps, or Platform Engineering budgets to unblock executive AI productivity mandates (`[SUPPORTED]` — R006 §8, R007 §1.11).

---

## 3. Competitive Reality

The competitive landscape consists of powerful incumbents dominating adjacent layers:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                COMPETITIVE SQUEEZE & ADJACENCY MAP                               │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                  ENTERPRISE IDENTITY INCUMBENTS                                  │
│                 Microsoft Entra (Agent IDs) │ Okta / Auth0 (AI Token Vault) │ AWS IAM            │
│                     [Owns: Identity Lifecycle, OAuth Grants, Non-Human Identities]               │
│                                                │                                                 │
│                                                ▼                                                 │
│   ┌──────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │                         THE RELAY INSERTION SPACE (Deterministic PEP)                    │   │
│   │   • Protocol-Level Interception (MCP Proxy / Tool Gateway)                               │   │
│   │   • Parameter-Level ABAC / Cedar Policy Evaluation                                       │   │
│   │   • Zero-Knowledge JIT Credential Injection (Agent never sees raw API keys)              │   │
│   │   • Cryptographic in-toto Action Receipts & Attestation                                  │   │
│   └──────────────────────────────────────────────────────────────────────────────────────────┘   │
│                                                │                                                 │
│                                                ▼                                                 │
│                                  HYPERSCALER & RUNTIME INCUMBENTS                                │
│          AWS Bedrock (Action Groups) │ Azure AI Foundry │ Vercel Eve │ LangGraph Platform         │
│                 [Owns: Execution Compute, Sandboxes, Model Inference, Local Loops]               │
│                                                │                                                 │
│                                                ▼                                                 │
│                                   OBSERVABILITY & EVAL INCUMBENTS                                │
│                   LangSmith │ Braintrust │ Arize Phoenix │ Datadog LLM Observability             │
│                      [Owns: Post-Hoc Tracing, Token Accounting, Offline Evals]                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Competitor Analysis & Boundaries
1. **Hyperscalers (AWS Bedrock, Azure Foundry, Google Vertex):**
   * *Strength:* Deep integration with cloud IAM, native Lambda/sandbox execution, bundled at zero marginal cost.
   * *Limitation:* Locked to their respective clouds. Incapable of acting as a neutral cross-cloud, cross-SaaS control plane (e.g., governing an agent touching GitHub, Salesforce, Slack, and Snowflake) (`[CONFIRMED]` — R001 §9, R007 §1.3).
2. **Framework Runtimes (LangGraph, CrewAI, AutoGen):**
   * *Strength:* Native execution state graphs and in-process breakpoints (`interrupt()`).
   * *Limitation:* Language- and runtime-specific. Enterprise security teams refuse to allow authorization policies to be hardcoded in Python/TypeScript application scripts (`[CONFIRMED]` — R001 §3.1, R002 §1.3).
3. **Observability Vendors (LangSmith, Braintrust):**
   * *Strength:* Massive developer mindshare, embedded tracing SDKs.
   * *Threat:* Adding inline evaluation/blocking rules to their proxy gateways.
   * *Limitation:* Fundamentally architected for passive span collection; lack credential vaulting, formal Cedar ABAC verification, and cryptographic execution ticketing (`[SUPPORTED]` — R001 §2.4, R007 §1.10).
4. **General Policy Engines (AWS Cedar, OPA/Styra):**
   * *Strength:* Fast, formally verifiable boolean decision engines.
   * *Limitation:* Bare-metal policy compilers. They lack agent protocol parsers (MCP/OpenAPI), credential vaulting, and HITL escalation workflows (`[CONFIRMED]` — R001 §2.5, R003 §2.3).

---

## 4. Eve Reality

Forensic analysis of the Vercel Eve framework (`vercel/eve` v0.25.x) establishes exactly what Eve provides out of the box and where its boundaries stop (`[CONFIRMED]` — R002):

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                      VERCEL EVE CAPABILITY MAP                                   │
├───────────────────────────────────────────────────┬──────────────────────────────────────────────┤
│ WHAT EVE GIVES US (Core Strengths)                │ WHERE EVE STOPS (Relay Scope)                │
├───────────────────────────────────────────────────┼──────────────────────────────────────────────┤
│ 1. Durable Turn Workflows (`@workflow/core`):     │ 1. Ephemeral, Single-Session Scope:          │
│    Survives process crashes, redeploys; parks at  │    Session state is mutable and isolated.    │
│    `session.waiting` with zero active compute.    │    Cannot manage multi-tenant enterprise PDP.│
├───────────────────────────────────────────────────┼──────────────────────────────────────────────┤
│ 2. Dual-Tier Runtime & Sandbox Isolation:         │ 2. Single-User Approval Model:               │
│    Trusted Node.js App Runtime vs unprivileged    │    Assumes channel requester is approver; no │
│    Linux microVM / Docker `/workspace`.           │    four-eyes quorum or role-based escalation.│
├───────────────────────────────────────────────────┼──────────────────────────────────────────────┤
│ 3. Pre-Execution Tool Approval Hook:              │ 3. No Cryptographic Provenance:              │
│    `ApprovalPolicy` evaluated strictly before     │    Logs to mutable local/PostgreSQL records; │
│    `execute()` or sandbox dispatch.               │    no in-toto / Sigstore signed receipts.    │
├───────────────────────────────────────────────────┼──────────────────────────────────────────────┤
│ 4. Subagent Hierarchies:                          │ 4. No Zero-Knowledge Credential Vault:       │
│    Isolated subagents executed as child sessions. │    App runtime holds raw connection secrets. │
└───────────────────────────────────────────────────┴──────────────────────────────────────────────┘
```

### Key Eve Integration Directives
* **Primary Insertion Point:** Relay integrates via Eve's `ApprovalPolicy` hook (`approval: async (ctx) => relayAdapter.evaluate(ctx)`). If Relay returns `{ type: "denied" }`, Eve cleanly injects a tool denial into the model conversation without executing the tool or touching the sandbox (`[CONFIRMED]` — R002 §1.4).
* **Durable Pause/Resume (HITL):** Eve's `user-approval` status suspends the turn workflow durably. When Relay resolves a human approval out-of-band (Slack/UI), it resumes Eve via `POST /eve/v1/session/:id` with `inputResponses` (`[CONFIRMED]` — R002 §1.5).
* **Strict Boundary Separation:** Relay **must not** store enterprise access policies or audit proofs inside Eve's internal state (`defineState`). All governance state, credential vaulting, and cryptographic ledgers remain Relay-owned (`[CONFIRMED]` — R002 Deliverable E).

---

## 5. Authority Model

The evidence confirms that Relay should **not invent a new cryptographic token wire format or identity provider**. Instead, Relay implements an **Explicit, Attenuated, Proposal-Based Authority Architecture** grounded in established security standards (`[CONFIRMED]` — R003 §1.2, R004 §2.1):

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    RELAY AUTHORITY PRIMITIVES                                    │
├────────────────────────────────┬────────────────────────────────┬────────────────────────────────┤
│ Primitive                      │ Underlying Standard            │ Implementation in Relay        │
├────────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ 1. Machine Identity            │ SPIFFE / SPIRE (SVIDs), mTLS   │ Node and agent instance attestation│
├────────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ 2. Delegation & Actor Chains   │ OAuth 2.0 Token Exchange       │ Nested `act` claims binding    │
│                                │ (RFC 8693)                     │ User -> Orchestrator -> Worker │
├────────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ 3. Rich Action Proposals       │ OAuth 2.0 RAR (RFC 9396)       │ Canonical JSON parameter schema│
├────────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ 4. Deterministic Policy Core   │ AWS Cedar                      │ Formally verified ABAC/RBAC    │
├────────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ 5. Proof-of-Possession         │ DPoP (RFC 9449)                │ Sender-constrained agent keys  │
├────────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ 6. Cryptographic Action Receipt│ in-toto Statement v1.0 +       │ Tamper-evident attestation over│
│                                │ Sigstore / Rekor Merkle Log    │ Hash(Proposal + Decision + Sig)│
└────────────────────────────────┴────────────────────────────────┴────────────────────────────────┘
```

### The 5 Core Authority Invariants
1. **Axiom 1: Agents Propose, Infrastructure Authorizes & Executes:** Agents never directly call external APIs or possess raw API keys. The agent emits a structured `ActionProposal`; Relay's Policy Enforcement Point (PEP) evaluates policy, injects short-lived Just-In-Time (JIT) credentials, and executes the call (`[CONFIRMED]` — R003 §4.1, R005 §7).
2. **Axiom 2: Monotonic Permission Attenuation:** A subagent or delegated token can only reduce authority, never expand it ($P_{\text{child}} \subseteq P_{\text{parent}} \cap P_{\text{user}}$) (`[CONFIRMED]` — R003 §3.7).
3. **Axiom 3: Non-Authoritative Natural Language:** Natural language intent statements generated by LLMs are completely non-authoritative for policy evaluation. Policy decisions evaluate strictly concrete, normalized parameter payloads, resource URNs, and ambient session state (`[CONFIRMED]` — R003 §3.9, R005 §3.1, R007 §1.6).
4. **Axiom 4: Dynamic Linking of Approvals:** Human approval receipts are cryptographic signatures bound to the exact canonical hash of the action payload (`SHA-256(ActionPayload)`). Any parameter alteration immediately invalidates the approval (`[CONFIRMED]` — R003 §2.4, R005 §3.3).
5. **Axiom 5: Ternary Decision Lifecycle:** Decisions evaluate to `ALLOW`, `DENY`, or `REQUIRE_APPROVAL` (suspending execution for asynchronous escalation) (`[CONFIRMED]` — R003 §3.12).

---

## 6. Security Model & Trust Boundaries

### Minimum Necessary Trust Boundaries
Relay establishes four non-negotiable architectural trust boundaries (`[CONFIRMED]` — R005 §2.1):

```
[ UNTRUSTED ZONE ]
  • Public Internet, Web Content, RAG Documents, Issue Trackers, Untrusted Tool Returns
═════════════════════════════════════════════════════════════════ [TB-1: Ingestion Boundary]
[ PROBABILISTIC / COMPROMISED ZONE ]
  • Agent Runtime (LLM, Prompts, Conversation Memory, In-Process Framework)
  • Zero Ambient Credentials Stored Here; Assumed Injected
═════════════════════════════════════════════════════════════════ [TB-2: Relay Ingress Boundary]
[ DETERMINISTIC CONTROL ZONE (Relay Core) ]
  • Ingress Protocol Adapters (MCP Gateway / REST Translator)
  • Canonical Normalizer (RFC 8785 JSON Canonicalization Scheme)
  • Policy Decision Point (AWS Cedar Rust Engine)
  • Asynchronous HITL State Machine & Escalation Broker
═════════════════════════════════════════════════════════════════ [TB-3: Vault & Execution Boundary]
[ ISOLATED EXECUTION ZONE (Action Gateway) ]
  • Zero-Knowledge Credential Vault (Encrypted JIT Secret Injector)
  • Target Tool Connectors (Egress Dispatcher)
═════════════════════════════════════════════════════════════════ [TB-4: Downstream Boundary]
[ TARGET SYSTEMS ]
  • Enterprise SaaS (GitHub, Jira, Stripe), Production Databases, Cloud APIs (AWS, GCP)
```

### The 6 Absolute Security Invariants
1. **Zero Ambient Credentials:** Agent execution runtimes never receive raw third-party secrets or persistent API keys (`[CONFIRMED]` — R005 §7).
2. **Strict RFC 8785 Canonicalization:** Action payloads are normalized before hashing, signing, or policy checks to eliminate JSON parser divergence exploits (`[CONFIRMED]` — R005 §3.3).
3. **Single-Use Cryptographic Execution Tickets:** Execution tickets contain unique nonces, expire in $\le 60\text{s}$, and are atomically burned upon arrival at the Action Gateway (`[CONFIRMED]` — R005 §3.4).
4. **Anti-TOCTOU Content Hashing:** Approvals bind to immutable cryptographic hashes of underlying resources (e.g., commit SHA, query AST), never mutable symbolic references (`[CONFIRMED]` — R005 §3.3).
5. **Sanitized HITL Display:** Human approval cards strip all ANSI escape sequences, control characters, and hidden markdown HTML tags to prevent visual smuggling phishing attacks (`[CONFIRMED]` — R005 §3.3).
6. **Fail-Closed Default:** Any engine timeout, parse ambiguity, or network partition defaults immediately to `DENY` (`[CONFIRMED]` — R005 §7).

---

## 7. User Reality & Operational Pain

Evidence synthesized across 7 engineering personas (`[CONFIRMED]` — R006):

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   PERSONA PAIN & BUYING MAP                                      │
├─────────────────────────┬─────────────────────────────┬──────────────────────────────────────────┤
│ Persona Archetype       │ Acute Operational Pain      │ Economic Willingness to Pay / Authority  │
├─────────────────────────┼─────────────────────────────┼──────────────────────────────────────────┤
│ 1. Security Engineering │ HIGH: Blocked AI rollouts;  │ HIGH: Holds budget; demands deterministic│
│    (CISO / AppSec)      │ prompt injection fears.     │ guardrails & SOC 2 audit proof.          │
├─────────────────────────┼─────────────────────────────┼──────────────────────────────────────────┤
│ 2. Platform Engineering │ HIGH: Runaway infra costs,  │ HIGH: Platform tooling budget (buys IDPs,│
│    (VP / Platform Lead) │ credential sprawl in dev.   │ CI/CD, Kubernetes infrastructure).       │
├─────────────────────────┼─────────────────────────────┼──────────────────────────────────────────┤
│ 3. DevOps / SRE         │ HIGH: Cascading failures in │ MEDIUM: Discretionary SRE tooling budget;│
│    (SRE Team Lead)      │ automated incident triage.  │ wants safe auto-remediation.             │
├─────────────────────────┼─────────────────────────────┼──────────────────────────────────────────┤
│ 4. Software Developer   │ ACUTE: Approval fatigue;    │ LOW: Rejects paid friction; demands fast,│
│    (Staff / Senior Dev) │ flow state destruction.     │ local open-source CLI / MCP tooling.     │
└─────────────────────────┴─────────────────────────────┴──────────────────────────────────────────┘
```

### Empirical Pain Classifications
* **`[OBSERVED]` Filesystem & Workspace Destruction:** Coding agents running `rm -rf`, `git reset --hard`, or executing destructive DB drop scripts during error-recovery loops (`[CONFIRMED]` — R006 §11.1).
* **`[OBSERVED]` The "Dangerously Skip Permissions" Workaround:** Developers using Claude Code or Aider bypass interactive CLI prompts (`--yes`, `--dangerously-skip-permissions`) because approving 20 routine read commands destroys flow state, inadvertently granting unmonitored shell autonomy (`[CONFIRMED]` — R006 §6.2).
* **`[OBSERVED]` Ambient Credential Leakage:** Hardcoded personal GitHub PATs and Slack bot tokens leaked into chat logs and vector stores (`[CONFIRMED]` — R006 §11.1).
* **`[REPORTED]` The Approval Rubber-Stamp Trap:** Human approvers flooded with 30+ raw JSON Slack alerts stop reading diffs and blindly click "Approve" (`[SUPPORTED]` — R006 §6.1, R007 §1.4).
* **`[REPORTED]` Compliance Quarantine:** Enterprise CISOs freezing write-capable agents from production environments due to missing non-repudiable audit logs (`[CONFIRMED]` — R006 §7.1).

---

## 8. Differentiation: What Relay Can Plausibly Own

Relay's defensible territory is strictly bounded:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    RELAY DEFENSIBLE POSITIONING                                  │
├───────────────────────────────────────────────────┬──────────────────────────────────────────────┤
│ WHAT RELAY MUST NOT BUILD (Red Ocean / Dead End)  │ WHAT RELAY CAN PLAUSIBLY OWN (Defensible Moat│
├───────────────────────────────────────────────────┼──────────────────────────────────────────────┤
│ ❌ "AI Observability & Tracing Platform"          │ 🟢 Zero-Trust MCP Tool Security Gateway      │
│    (LangSmith / Braintrust / Datadog will crush)  │    (The Envoy / ext_authz for Agent Tools)   │
├───────────────────────────────────────────────────┼──────────────────────────────────────────────┤
│ ❌ "Enterprise Identity Provider"                 │ 🟢 Zero-Knowledge JIT Credential Broker      │
│    (Okta / Microsoft Entra will crush)            │    (Agents never touch target API keys)      │
├───────────────────────────────────────────────────┼──────────────────────────────────────────────┤
│ ❌ "LLM Prompt Injection Firewall"                │ 🟢 Deterministic Parameter ABAC Engine       │
│    (Lakera / Cisco / Bedrock Guardrails crush)    │    (Sub-millisecond Rust AWS Cedar evaluation│
├───────────────────────────────────────────────────┼──────────────────────────────────────────────┤
│ ❌ "Proprietary Agent Framework"                  │ 🟢 Cryptographic in-toto Action Receipts     │
│    (LangGraph / Eve / Claude Code will crush)     │    (Non-repudiable proof for SOC 2 & EU AI)  │
├───────────────────────────────────────────────────┼──────────────────────────────────────────────┤
│ ❌ "Static Two-Phase Commit Plan Engine"          │ 🟢 Tiered Asynchronous HITL Escalation       │
│    (Dynamic ReAct loops make this impossible)     │    (Auto-approves safe; escalates high-risk) │
└───────────────────────────────────────────────────┴──────────────────────────────────────────────┘
```

---

## 9. Weak Hypotheses & Open Frontiers

The following concepts in the research remain speculative or structurally fragile:

1. **`[CONTRADICTED]` The "Terraform Plan/Apply" Model for All Agents:**
   * *The Hypothesis:* Agents can declare a full multi-step execution plan up front, allowing Relay to evaluate the entire trajectory before execution begins.
   * *The Forensic Reality:* Autonomous agents are dynamic, feedback-driven ReAct loops. Step $N$ cannot be formulated until Step $N-1$ executes and returns real-time system state (`[CONTRADICTED]` — R007 §1.13). Multi-step pre-planning applies only to declarative batch jobs, not dynamic agents.
2. **`[CONTRADICTED]` Universal Out-of-Band Asynchronous Suspension:**
   * *The Hypothesis:* An external HTTP proxy can suspend arbitrary agent loops for hours while a human reviews a request in Slack.
   * *The Forensic Reality:* Standard MCP and OpenAI client connections time out in 60s without native runtime state serialization (`[CONTRADICTED]` — R004 §6.1, R007 §1.2). Asynchronous suspension requires integration with durable execution engines (Eve Workflow SDK, LangGraph, Temporal).
3. **`[UNCERTAIN]` Dynamic Taint-Tracking Across Context Windows:**
   * *The Hypothesis:* Relay can track whether an agent read untrusted data and dynamically revoke outbound network permissions.
   * *The Reality:* Coarse session taint causes false-positive blocking; fine-grained sub-context taint tracking requires deep LLM attention inspection unavailable via commercial APIs (`[UNCERTAIN]` — R003 §7.1).
4. **`[UNCERTAIN]` Dedicated Enterprise CISO Budget for Agent Proxies:**
   * *The Reality:* In 2026, enterprise buyers do not have an established budget line for "Agent Control Planes." Selling requires attaching to DevSecOps or Platform Engineering budgets (`[UNCERTAIN]` — R006 §8, R007 §1.11).

---

## 10. Killed Ideas (Explicit Non-Goals)

The following 7 concepts are **permanently killed and excluded from Relay's product scope**:

1. **`[REJECTED]` DO NOT BUILD a Prompt/Jailbreak Firewall:** Relay does not build probabilistic text classifiers. Relay assumes the agent *is* compromised and enforces deterministic safety at the tool parameter boundary (`[REJECTED]` — R001 §11.1, R005 §8.2, R007 §2.6).
2. **`[REJECTED]` DO NOT BUILD an Enterprise Identity Provider (IdP):** Relay will never manage user directories or passwords. Relay consumes standard OIDC assertions and RFC 8693 token exchanges (`[REJECTED]` — R001 §11.3, R003 §1.2, R007 §2.6).
3. **`[REJECTED]` DO NOT INVENT a Bespoke Policy DSL:** Relay will not create a proprietary policy syntax. Relay embeds AWS Cedar (open-source Rust engine) for formally verified ABAC (`[REJECTED]` — R001 §11.4, R004 §4.2, R007 §2.6).
4. **`[REJECTED]` DO NOT BUILD an LLM Observability / Tracing SaaS:** Relay does not build prompt evaluation dashboards or token cost analytics. Relay emits OpenTelemetry GenAI spans to Datadog, Honeycomb, and LangSmith (`[REJECTED]` — R001 §11.8, R004 §2.2, R007 §2.6).
5. **`[REJECTED]` DO NOT BUILD a Centralized Latency-Heavy SaaS Proxy for All Tool Traffic:** Routing all enterprise DB queries and internal API calls through a remote 3rd-party SaaS creates unacceptable latency (>200ms) and security hazards. Relay must be deployable as an open-source, local/sidecar micro-PEP (`[REJECTED]` — R007 §1.5, R007 §2.6).
6. **`[REJECTED]` DO NOT EVALUATE Natural Language Intent in Policy Decisions:** Self-reported intent strings are untrusted metadata. Policies evaluate strictly canonical parameters and resource URNs (`[REJECTED]` — R003 §3.9, R005 §3.1, R007 §1.6).
7. **`[REJECTED]` DO NOT BUILD a Proprietary Agent Orchestration Framework:** Relay does not compete with LangGraph, CrewAI, AutoGen, or Eve. Relay is a runtime-agnostic policy enforcement gateway (`[REJECTED]` — R001 §11.6, R007 §2.6).

---

## 11. Product Opportunities: Ranked Evaluation

Candidate product directions evaluated using the 5-factor product viability formula:

$$\text{Score Basis} = \text{Impact} \times \text{Pain} \times \text{Defensibility} \times \text{Technical Feasibility} \times \text{Distribution Potential}$$

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                CANDIDATE DIRECTION RANKING MATRIX                                │
├──────┬───────────────────────────────────────────┬────────┬───────┬───────┬───────┬───────┬──────┤
│ Rank │ Candidate Product Direction               │ Impact │ Pain  │ Def.  │ Feas. │ Dist. │ Rating│
├──────┼───────────────────────────────────────────┼────────┼───────┼───────┼───────┼───────┼──────┤
│  1   │ Zero-Trust MCP Security Gateway & Broker  │  HIGH  │ EXTR  │ HIGH  │ EXTR  │ EXTR  │ 9.4  │
│  2   │ GitHub PR & Branch Action Gate (Coding)   │  HIGH  │ HIGH  │ MED   │ HIGH  │ HIGH  │ 8.1  │
│  3   │ Production Database / Text2SQL Admission  │  HIGH  │ HIGH  │ MED   │ MED   │ MED   │ 7.2  │
│  4   │ DevOps / SRE Auto-Remediation Gate (K8s)  │  HIGH  │ HIGH  │ MED   │ LOW   │ MED   │ 6.3  │
│  5   │ Multi-SaaS Transactional Action Broker    │  MED   │ MED   │ LOW   │ LOW   │ LOW   │ 4.5  │
└──────┴───────────────────────────────────────────┴────────┴───────┴───────┴───────┴───────┴──────┘
```

### Evaluation Basis & Factor Analysis

#### 1. Rank 1: The Zero-Trust MCP Security Gateway & Credential Broker (Score: 9.4 / 10)
* **Impact (High):** Secures the explosive Model Context Protocol (MCP) ecosystem across developer IDEs, desktop clients, and custom agents.
* **Pain (Extreme):** Developers running dozens of local/remote MCP servers with hardcoded ambient credentials and zero parameter inspection; acute risk of prompt injection tool abuse.
* **Defensibility (High):** Becoming the default MCP security proxy with embedded AWS Cedar ABAC, JIT credential injection, and Sigstore-signed action receipts creates strong protocol network effects.
* **Technical Feasibility (Extreme):** Standard JSON-RPC protocol over stdio/HTTP; lightweight Rust/Go sidecar architecture; sub-millisecond policy evaluation.
* **Distribution Potential (Extreme):** Frictionless open-source adoption via `npx @relay/mcp-proxy` or homebrew binary; drop-in replacement for any MCP client (Claude Desktop, Cursor, Claude Code).

#### 2. Rank 2: The GitHub PR & Branch Action Gate for Coding Agents (Score: 8.1 / 10)
* **Impact (High):** Protects source code repositories from rogue coding agents (Claude Code, OpenHands, SWE-bench bots).
* **Pain (High):** Wiped workspaces, accidental force pushes, committed secrets, and notification-heavy PR review spam.
* **Defensibility (Medium):** Git hooks and GitHub App boundaries are well-understood, but GitHub may build native branch protections for AI bots.
* **Technical Feasibility (High):** Standard git hook / GitHub App webhook interception; AST diff analysis.
* **Distribution Potential (High):** GitHub Marketplace App + pre-commit CLI hook.

#### 3. Rank 3: The Production Database & Text2SQL Admission Controller (Score: 7.2 / 10)
* **Impact (High):** Unlocks natural language querying against production databases.
* **Pain (High):** Fear of unindexed full-table scans, memory exhaustion (OOM), table locking, and accidental data mutation.
* **Defensibility (Medium):** Competing with existing SQL proxies (DataSunrise, Cyral).
* **Technical Feasibility (Medium):** Requires deep SQL AST parsing and dialect handling (PostgreSQL, MySQL, Snowflake).
* **Distribution Potential (Medium):** Database proxy deployment in enterprise VPCs.

#### 4. Rank 4: The DevOps / SRE Auto-Remediation Admission Controller (Score: 6.3 / 10)
* **Impact (High):** Unlocks automated incident remediation in Kubernetes and AWS.
* **Pain (High):** SRE fear of cascading remediation outages during live incidents.
* **Defensibility (Medium):** Niche enterprise SRE market.
* **Technical Feasibility (Low):** Complex stateful dependencies; high liability if auto-remediation breaks a cluster.
* **Distribution Potential (Medium):** Long enterprise sales cycles to Platform/SRE teams.

#### 5. Rank 5: The Multi-SaaS Transactional Action Broker (Score: 4.5 / 10)
* **Impact (Medium):** Coordinates multi-step actions across Stripe, Linear, Jira, and Slack.
* **Pain (Medium):** Fragmented SaaS workflows.
* **Defensibility (Low):** Workflow platforms (Zapier, Make, Workato) already own multi-SaaS integration.
* **Technical Feasibility (Low):** High API maintenance overhead; complex rollback handling across third-party SaaS.
* **Distribution Potential (Low):** Hard to monetize outside custom enterprise integration contracts.

---

## 12. Final Strategic Recommendation

### 1. Definitive Verdict: **BUILD RELAY (Under Focused Architectural Pivot)**
Relay **should be built**, but **NOT** as a centralized, slow SaaS "Two-Phase Commit Plan/Apply Gateway." 

Relay must be built as a high-performance, open-source **Zero-Trust MCP Security Gateway & Action Attestation Engine** (`@relay/guard` / `relay-proxy`).

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   THE RELAY PRODUCT BLUEPRINT                                    │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                  │
│   [ MCP Client (Claude Desktop / Cursor / Claude Code / Custom Agent) ]                          │
│                                │                                                                 │
│                                │ JSON-RPC (`tools/call`) over stdio / HTTP                       │
│                                ▼                                                                 │
│   ┌──────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │ RELAY MCP GUARD (Embeddable Rust/Go Micro-PEP Sidecar)                                   │   │
│   │                                                                                          │   │
│   │ 1. Zero-Knowledge Credential Injector (Retrieves JIT secrets from OS Keychain / Vault)   │   │
│   │ 2. Deterministic Cedar ABAC Engine (Sub-ms evaluation of tool parameters & path limits)  │   │
│   │ 3. Tiered HITL Escalation (Auto-approves safe calls; dispatches rich diff for high-risk) │   │
│   │ 4. Cryptographic in-toto Attestation (Signs Action Receipt with Cosign/Ed25519)          │   │
│   └──────────────────────────────────────────────────────────────────────────────────────────┘   │
│                                │                                                                 │
│                                │ Authenticated & Authorized Execution Payload                    │
│                                ▼                                                                 │
│   [ Downstream MCP Servers / APIs (PostgreSQL / GitHub / Slack / AWS / Filesystem) ]             │
│                                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 2. Initial Target Audience
* **Primary ICP:** AI Platform Engineers and DevSecOps Leads deploying MCP-based agents (Claude Desktop, Cursor, Claude Code, custom LangGraph/Eve agents) across engineering teams.
* **Secondary ICP:** Enterprise Security / Compliance Officers requiring SOC 2 and EU AI Act-compliant audit trails for automated developer tooling.

### 3. First Core Use Case
**Securing Local and CI/CD Model Context Protocol (MCP) Tool Calling:**
* Intercepts `tools/call` for sensitive MCP servers (filesystem, git, databases, AWS).
* Prevents prompt-injection-driven tool poisoning and parameter smuggling.
* Strips credentials from agent configuration; injects secrets dynamically at execution time.
* Logs non-repudiable, cryptographically signed Action Receipts.

### 4. Core Product Primitive
The **Governed Action Receipt Envelope (in-toto Statement)** backed by an **Embedded Cedar ABAC PEP**:
* **The Primitive:** `Relay.evaluate(ActionProposal) -> ALLOW(SignedExecutionTicket) | DENY(Reason) | REQUIRE_APPROVAL(EscalationToken)`
* Delivers deterministic parameter verification, single-use ticket execution, and tamper-evident cryptographic lineage.

### 5. Explicit Scope Exclusions (What Relay Will NOT Build)
* ❌ No prompt injection / LLM text filtering classifiers (Layer 6).
* ❌ No user directory or identity provider management (Layer 1).
* ❌ No proprietary policy specification DSL.
* ❌ No full-blown agent orchestration framework (Layer 5).
* ❌ No centralized SaaS proxy in the synchronous execution path.
* ❌ No static "Two-Phase Commit Plan Engine" for dynamic ReAct loops.
* ❌ No post-hoc LLM evaluation dashboard (Layer 7).

---

## 13. Research Traceability & Document Index

This synthesis is derived directly from the complete 7-document research record:
* [`R001: AI Agent Governance & Control-Plane Market Study`](file:///home/sumeet/relay/docs/research/R001-agent-governance-market.md)
* [`R002: Vercel Eve Framework Technical Forensics`](file:///home/sumeet/relay/docs/research/R002-eve-technical-forensics.md)
* [`R003: Agent Authority Model & Delegation Architecture`](file:///home/sumeet/relay/docs/research/R003-agent-authority-model.md)
* [`R004: Standards & Interoperability Research`](file:///home/sumeet/relay/docs/research/R004-standards-interoperability.md)
* [`R005: Adversarial Threat Model & Attack Trees`](file:///home/sumeet/relay/docs/research/R005-threat-model.md)
* [`R006: User Workflows, Operational Realities & Pain Points`](file:///home/sumeet/relay/docs/research/R006-user-workflows.md)
* [`R007: Adversarial Review & Strategic Pivot Analysis`](file:///home/sumeet/relay/docs/research/R007-adversarial-review.md)

---
*End of Authoritative Research Synthesis.*
