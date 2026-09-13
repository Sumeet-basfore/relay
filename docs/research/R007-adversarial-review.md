# R007: Adversarial Review of the Relay Thesis & Architecture

**Document ID:** `R007-adversarial-review`  
**Date:** September 2026  
**Status:** Complete / Decision Gate  
**Target:** Relay Thesis & Control Plane Architecture  
**Reviewer:** Adversarial Reviewer  
**Evidence Base:** `docs/research/R001-agent-governance-market.md`, `docs/research/R004-standards-interoperability.md`, `README.md`

---

## Executive Summary & Verdict Preview

Relay's core hypothesis posits:
> *"Agents should propose actions, while deterministic infrastructure determines whether those actions are authorized, approved, and executed."*

This adversarial review evaluated the Relay thesis against the empirical market, architectural, and standards evidence documented in `R001` and `R004`. 

### The Core Finding
**Relay in its current conceptual form—a centralized, runtime-agnostic, two-phase commit ("Plan/Apply") action gateway sitting synchronously in the agent execution path—cannot succeed.** It suffers from two fatal structural flaws and an insurmountable commercial squeeze:
1. **The Dynamic Plan Impossibility:** The "Terraform Plan/Apply" mental model fundamentally breaks for autonomous agents. Unlike declarative infrastructure code, agents are imperative, dynamic feedback loops where step $N$ cannot be formulated or evaluated until step $N-1$ has executed and returned real-time runtime state.
2. **The Runtime-Agnostic Suspension Paradox:** Relay claims to be 100% runtime-agnostic while simultaneously orchestrating asynchronous, multi-hour Human-in-the-Loop (HITL) approvals. As proven in R004, an out-of-band network proxy cannot suspend and resume an agent without native, framework-level execution state serialization (e.g., LangGraph checkpointing or Temporal replay).
3. **The Incumbent Vice-Grip:** Enterprise IAM (Microsoft Entra Agent IDs, Okta AI, AWS IAM) owns identity and token delegation; Hyperscalers (Bedrock, Azure Foundry, Vertex) own the runtime tool sandboxes; and Observability vendors (LangSmith, Braintrust, Datadog) own the telemetry and evaluation budgets.

**Final Recommendation:** **PIVOT** (Abandon the centralized Plan/Apply gateway proxy; re-architect around an embeddable, open-source **MCP Zero-Trust Credential Broker & Policy Sidecar** paired with an **Action Attestation Evidence Engine**).

---

## Part 1: The 13 Adversarial Stress Tests

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                ADVERSARIAL STRESS TEST SCORECARD                                │
├────────────────────────────────────────────────────────┬────────┬───────────────────────────────┤
│ Evaluation Dimension                                   │ Rating │ Primary Threat / Failure Mode │
├────────────────────────────────────────────────────────┼────────┼───────────────────────────────┤
│ 1. Is agent authority a distinct problem?              │ 🟡 MIXED│ Solved at API / IAM boundary  │
│ 2. Is this already solved by enterprise IAM?           │ 🔴 HIGH │ Entra & Okta absorb delegation│
│ 3. Will cloud vendors absorb the category?             │ 🔴 HIGH │ Bundled into Bedrock / Azure  │
│ 4. Are agent action approvals actually useful?         │ 🔴 HIGH │ Review fatigue & context opacity│
│ 5. Will devs tolerate control plane in execution path? │ 🔴 HIGH │ Latency, availability risk    │
│ 6. Can action intent be reliably represented?          │ 🔴 HIGH │ Self-reported intent is flawed│
│ 7. Can Relay meaningfully enforce policy?              │ 🟡 MIXED│ Parameter checks work; not DAG│
│ 8. Does Eve already solve enough of this?              │ 🔴 HIGH │ Verticals build in-app DAGs   │
│ 9. Is MCP making Relay unnecessary?                    │ 🟡 MIXED│ MCP needs auth, but standardizes│
│ 10. Are observability vendors likely to own this?      │ 🔴 HIGH │ Incremental gate feature      │
│ 11. Does the buyer actually have budget?               │ 🔴 HIGH │ No distinct CISO budget line  │
│ 12. What is Relay's strongest plausible wedge?         │ 🟢 REAL │ Zero-trust MCP Credential PEP │
│ 13. What part of the thesis is weakest?                │ 🔴 FATAL│ Two-Phase Commit Plan/Apply   │
└────────────────────────────────────────────────────────┴────────┴───────────────────────────────┘
```

---

### 1. Is agent authority really a distinct problem?
**Adversarial Finding: Largely No.**

The thesis asserts that agent actions require a specialized, new authority plane. In reality, downstream systems (Stripe, GitHub, Salesforce, PostgreSQL) have no concept of "AI agents"—they only evaluate HTTP requests, database queries, and API calls authenticated via OAuth tokens, API keys, or mTLS certificates. 

When an agent invokes `DELETE /users/42`, the authorization question is identical to whether a script, a microservice, or a human invoked it: *Does the authenticated principal have permission to delete user 42?* 
* If existing API gateways, Cedar/OPA policies, and resource-level RBAC already protect the downstream resource, Relay is redundant.
* The only part unique to agents is **delegated ambient authority across multi-turn prompts** (preventing an untrusted prompt from exploiting an agent's broad ambient credentials). But this is a **credential scoping and delegation problem**, not a new category of "agent authority."

### 2. Is this already solved by enterprise IAM?
**Adversarial Finding: Yes, for 80% of the enterprise attack surface.**

Enterprise identity giants are not standing still:
* **Microsoft Entra** has shipped dedicated **Agent Identities**, Workload Identity Federation, and RFC 8693 On-Behalf-Of (OBO) token exchange deeply integrated into Azure and Microsoft 365 Copilot.
* **Okta / Auth0** has deployed the **Auth0 AI Token Vault**, allowing agents to borrow scoped OAuth tokens on the fly without accessing raw secrets.
* **AWS IAM** provides STS Session Policies, Permission Boundaries, and Cedar integration via Amazon Verified Permissions.

Enterprise CISOs will mandate that agent identity and access control reside within their existing Okta or Entra tenant. CISOs will reject standing up an unproven third-party identity or authorization intermediary when their existing IAM stack already manages identity lifecycles, directory syncing, SOC2 compliance, and single sign-on.

### 3. Will cloud vendors absorb the category?
**Adversarial Finding: Yes, inside their cloud boundaries.**

Hyperscalers (AWS, Azure, GCP) already possess the native primitives to bundle agent governance at zero marginal cost:
* **AWS Bedrock**: Combines Bedrock Guardrails (content safety, PII masking), Bedrock Action Groups (OpenAPI mapping to Lambda), IAM execution roles, and AWS Cedar.
* **Azure AI Foundry**: Couples Microsoft Entra Agent IDs, Azure Content Safety, Purview DLP, and Azure API Management.
* **Google Vertex AI**: Integrates Model Armor, Vertex Extensions, and GCP Workload Identity Federation.

When an enterprise builds an agent on Bedrock or Azure OpenAI, the path of least resistance is using the native cloud action groups and IAM policies. Relay can only survive in multi-cloud, cross-SaaS environments (e.g., an agent spanning Salesforce, GitHub, Slack, and Snowflake), but hyperscaler gravity will capture the vast majority of enterprise spend.

### 4. Are agent action approvals actually useful?
**Adversarial Finding: Far less useful in practice than in theory.**

The thesis assumes that routing high-risk actions to human approvers via Slack or Teams provides robust safety. In production, this breaks down due to three severe operational realities:
1. **Approval Fatigue & Rubber-Stamping:** If an agent performs 50 actions an hour, human approvers are flooded with notifications and default to clicking "Approve" without scrutiny.
2. **Context Opacity:** To safely approve an action (e.g., `execute_sql("UPDATE orders SET status='processed' WHERE...")`), the human must understand the entire conversational history, previous API responses, and database state. A raw diff or JSON summary in Slack is insufficient to verify correctness, taking as much time to inspect as doing the task manually.
3. **Latency Invalidation:** If a human takes 45 minutes to approve a proposed action, the underlying target system state may have changed in the interim (e.g., inventory altered, order canceled), making the approved action stale or destructive when executed.

### 5. Will developers tolerate a control plane in the execution path?
**Adversarial Finding: No, unless mandated or zero-latency.**

Placing Relay as a synchronous, out-of-process network proxy between agent runtimes and tool backends introduces:
* **Latency Overhead:** Each tool call incurs extra network hops (Agent $\rightarrow$ Relay $\rightarrow$ PDP $\rightarrow$ Tool $\rightarrow$ Relay $\rightarrow$ Agent), adding 50–300ms to already sluggish LLM inference loops.
* **Single Point of Failure (SPOF):** If the Relay control plane experiences downtime, network partitioning, or database locks, all agent workflows across the enterprise immediately fail.
* **Developer Friction:** Engineers building with LangGraph, CrewAI, or raw OpenAI SDKs want velocity. They will actively bypass or disable an out-of-band proxy that blocks their local debugging or requires complex proxy routing configurations.

### 6. Can action intent be reliably represented?
**Adversarial Finding: No.**

Relay’s proposed RAPP schema includes an `intent_statement` provided by the agent. This introduces a fatal circular dependency:
* **The Non-Deterministic Intent Paradox:** The intent explanation is generated by the *same probabilistic LLM* that is susceptible to prompt injection, jailbreaking, or hallucination.
* A compromised agent executing an exfiltration attack will simply generate a benign intent string (e.g., `action: "export_metrics"`, `intent: "Aggregating daily performance data for analytics dashboard"` while sending sensitive PII to an external endpoint).
* Deterministic policy engines cannot evaluate the truthfulness of natural language intent statements. They can only evaluate concrete, typed parameters.

### 7. Can Relay meaningfully enforce policy?
**Adversarial Finding: Only on single-parameter schemas; NOT on multi-step plans.**

* **Where Relay CAN enforce policy:** Relay can execute deterministic ABAC on individual tool payloads (e.g., `amount <= 500`, `region == "us-east-1"`, `role == "admin"` using AWS Cedar or Rego).
* **Where Relay FAILS:** Relay cannot enforce holistic policies across multi-step dynamic plans because:
  1. The agent cannot know the full trajectory in advance (dynamic branching).
  2. Stateless PDP engines do not track cumulative blast radius or data-taint across multi-turn sessions without deep state serialization.

### 8. Does Eve already solve enough of this?
**Adversarial Finding: Yes, for high-assurance enterprise verticals.**

Vertical agent platforms like Eve (and counterparts in finance, legal, and healthcare) do not use generic, unbounded ReAct loops. Instead, they build:
* Hardcoded, deterministic DAGs and state machines.
* Domain-specific validation logic embedded directly in application code.
* Native, integrated compliance audit trails tailored to specific industry regulations.

These platforms do not need a generic, external L7 action proxy because they constrain the agent's autonomy at the application architecture level. Relay is left serving unstructured, generic agents—the very category least capable of structured governance.

### 9. Is MCP making Relay unnecessary?
**Adversarial Finding: Partially, but MCP creates a specific niche.**

* **Why MCP threatens Relay:** The Model Context Protocol (MCP) is standardizing tool definitions and client-server RPC. As Anthropic and the MCP open-source working groups add native authentication, OAuth tokens, and host-level permission prompts (e.g., Claude Desktop asking "Allow tool X?"), the need for a separate proprietary gateway diminishes.
* **Where a gap remains:** MCP servers are written with ambient credentials (the MCP server holds the API key). If an attacker compromises the agent, they can abuse the MCP server's ambient access. Relay could serve as an **MCP Security Proxy**, but this is a lightweight protocol shim, not a massive "Control Plane Platform."

### 10. Are observability vendors likely to own this space?
**Adversarial Finding: Yes.**

Observability platforms (LangSmith, Braintrust, Arize Phoenix, Datadog) already have:
* Deep SDK integration embedded in millions of agent applications.
* The complete trace history, prompt lineage, and token cost context.
* Existing enterprise SaaS contracts and security approvals.

Adding an inline evaluation/blocking hook (e.g., Braintrust Proxy rules or LangSmith/LangGraph breakpoint webhooks) is an incremental feature addition for them. It is far easier for an observability leader to add a blocking policy gate than for an action gate startup to build an enterprise-grade observability and tracing ecosystem.

### 11. Does the buyer actually have budget?
**Adversarial Finding: No established budget category exists.**

* **The CISO / SecOps Buyer:** Budgets are allocated to Cloud Security (Wiz, Prisma), IAM (Okta, CyberArk), and Endpoint/SIEM (CrowdStrike, Splunk). SecOps views agents as workloads to be governed under existing Non-Human Identity (NHI) or API Gateway budgets.
* **The AI / Platform Engineering Buyer:** Budgets are spent on compute (GPUs, OpenAI/Anthropic API credits), orchestration infrastructure, and developer tooling. They strongly prefer open-source libraries over expensive per-action governance SaaS.
* **The Line of Business Buyer:** Buys packaged solutions (Salesforce, ServiceNow, Workday) where governance is bundled.

Selling a standalone "Agent Action Control Plane" requires evangelizing a new line-item budget in an uncertain enterprise spending environment.

### 12. What is Relay's strongest plausible wedge?
**Adversarial Finding: An open-source Zero-Trust MCP Credential Broker & Micro-PEP.**

Relay’s only immediate, high-traction wedge is:
1. **The Problem:** Developers are running dozens of MCP servers locally and in production with hardcoded, ambient API keys and zero parameter-level authorization.
2. **The Wedge:** A lightweight, sub-millisecond, local/sidecar **MCP Policy Proxy & Credential Broker** (integrating AWS Cedar) that strips credentials from agents, enforces fine-grained ABAC on MCP `tools/call`, and produces Sigstore-signed in-toto audit receipts.

### 13. What part of the thesis is weakest?
**Adversarial Finding: The "Terraform Plan/Apply for Agents" Analogy.**

The weakest and most dangerous element of Relay's thesis is the claim that agents can be governed via a **Two-Phase Commit (Propose Plan $\rightarrow$ Evaluate $\rightarrow$ Approve $\rightarrow$ Commit)**:
* **Terraform works** because HCL is a purely declarative representation of static desired state. Terraform calculates the diff against existing cloud state *before* touching anything.
* **AI Agents do NOT work this way.** AI agents are imperative, non-deterministic, feedback-driven ReAct loops. An agent executing a complex task (e.g., "Investigate customer incident and remediate") cannot produce a complete, static plan up front:
  * Step 1: `query_logs()` $\rightarrow$ returns log payload.
  * Step 2: Agent reads log payload, analyzes error, decides to call `restart_pod()` or `scale_deployment()`.
  * Step 3: Agent checks health endpoint before deciding whether to notify the team or rollback.
* Because Step 2 and Step 3 *strictly depend on the runtime output of Step 1*, the agent **cannot propose a complete multi-step plan in Phase 1**.
* Attempting to force agents into a static Two-Phase Commit either restricts agents to trivial, hardcoded scripts (where LLMs are unnecessary) or forces Relay back into single-step reactive tool interception.

---

## Part 2: Required Adversarial Syntheses

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                               RELAY THESIS ADVERSARIAL SYNTHESIS                                │
├────────────────────────────────────────────────┬────────────────────────────────────────────────┤
│ STRONGEST ARGUMENTS FOR RELAY                  │ STRONGEST ARGUMENTS AGAINST RELAY              │
├────────────────────────────────────────────────┼────────────────────────────────────────────────┤
│ • L7 model firewalls are fundamentally broken  │ • Two-Phase Plan/Apply is impossible for       │
│   (probabilistic prompt checks cannot enforce    dynamic ReAct agent loops                      │
│   hard deterministic API safety).              │ • Asynchronous HITL breaks runtime agnosticism │
│ • Zero-knowledge credential brokering is       │   (timeouts kill standard MCP/OpenAI loops)    │
│   urgently needed (agents must not hold keys). │ • Enterprise IAM & Cloud providers will bundle │
│ • Regulatory compliance (EU AI Act, SOC2 AI)     80%+ of identity & action gates for free      │
│   requires cryptographic proof of auth.        │ • No dedicated buyer budget category exists    │
├────────────────────────────────────────────────┴────────────────────────────────────────────────┤
│ CRITICAL CONTRADICTION IN RESEARCH                                                              │
│ R001 claims the moat is "Plan-Level Governance (Terraform Plan/Apply)", while R004 proves that   │
│ real-world execution is single-step RPC (MCP/OpenAI) and calls single-step governance a fallacy.│
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 1. Strongest Arguments FOR Relay

1. **Deterministic Action Interception is Technically Mandatory:** Model-level guardrails (Lakera, Bedrock Guardrails) inspect natural language and fail against indirect prompt injection. The only mathematically sound enforcement point is deterministic, out-of-band policy evaluation (Cedar/OPA) executed on concrete tool parameters at the execution boundary.
2. **Ambient Credential Elimination (Zero-Knowledge Architecture):** Giving LLM runtimes static API keys or broad database credentials is an existential security vulnerability. Relay's model of holding credentials in an isolated vault and only injecting them upon verified policy compliance solves a genuine enterprise security hazard.
3. **Audit Immutability & Compliance Readiness:** In-toto attestations and Merkle-tree transparency logs (Sigstore/Rekor) provide non-repudiable proof of authorization, satisfying incoming compliance mandates (EU AI Act Article 14/17, SOC2 GenAI Trust Criteria) that passive JSON logs cannot meet.
4. **Tool Protocol Normalization:** Anthropic's Model Context Protocol (MCP) provides a real, standardized transport layer across models and tools, offering a clean insertion point for an intelligent policy proxy.

---

### 2. Strongest Arguments AGAINST Relay

1. **The Dynamic Plan Fallacy:** Agents cannot emit static multi-step plans in advance because agent execution is inherently state-dependent and iterative. A "Terraform Plan/Apply" gate is technically unviable for autonomous agent loops.
2. **The Asynchronous Suspension Trap:** When high-risk actions require human approval, standard LLM client connections time out within 60 seconds. Relay cannot pause and resume arbitrary agent runtimes out-of-band without framework-specific memory checkpointing, destroying Relay's claim of being "runtime-agnostic."
3. **The Incumbent Squeeze:** Okta, Microsoft Entra, and AWS IAM will capture agent identity and token downscoping; Bedrock, Azure Foundry, and Vertex will capture cloud tool execution gates; LangSmith and Datadog will capture observability and inline evaluation rules. Relay is left fighting for a sliver of multi-cloud, non-standard traffic.
4. **Severe Developer Friction & Latency:** Developers will not tolerate an extra 100ms+ synchronous network hop and a third-party single point of failure in their agent execution loops unless forced by compliance.
5. **Absence of Dedicated Budget:** Neither SecOps nor AI Engineering has an allocated line item for an "Agent Action Control Plane." Sales cycles will be long, educational, and friction-laden.

---

### 3. Contradictions in the Research Corpus

| Issue | Document R001 Claim | Document R004 Finding | Adversarial Resolution |
| :--- | :--- | :--- | :--- |
| **Core Moat & Mechanism** | Moat is **"Plan-Level Pre-Execution Governance (Two-Phase Commit / Terraform Plan-Apply)"** (§0.4, §4.1, §8.1). | Real-world agent protocols (MCP, OpenAI) operate strictly on **single-step RPC (`tools/call`)**. (§1.1, §3). R004 §6.2 explicitly labels single-step evaluation as a *"Dangerous Fallacy"*. | **Direct Contradiction.** If single-step evaluation is a fallacy, and multi-step plans cannot be generated by dynamic agents, Relay's core architectural thesis is structurally invalid. |
| **Runtime Agnosticism vs. HITL** | Relay is completely **runtime-agnostic and decoupled from agent internals** (§5 Q12, §8.2). | Asynchronous human approvals cause **synchronous connection timeouts in standard runtimes** (§6.1, §8.4), requiring framework-specific state serialization (e.g. LangGraph `interrupt()`). | **Direct Contradiction.** Out-of-band network proxies cannot suspend dynamic client agent state without framework-specific hooks. |
| **Semantic Intent vs. Prompt Injection** | Relay **"does not solve prompt injection"** and leaves LLM prompt evaluation to firewalls (§11.1). | Relay's RAPP schema relies on evaluating the agent's **`intent_statement` and multi-step semantic intent** (§4.1, §4.4). | **Direct Contradiction.** If an agent is compromised via prompt injection, its self-reported intent is untrustworthy, rendering intent-based policy evaluation useless. |

---

### 4. Unsupported Assumptions in the Research

1. **Assumption:** *Enterprises will deploy fully autonomous agents with broad write-access to core transactional systems if an action gate exists.*  
   *Reality:* Enterprise hesitation to deploy write-capable agents is driven by model non-determinism, reasoning errors, and liability—not merely the lack of an action proxy.
2. **Assumption:** *Human approvers in Slack/Teams can make informed authorization decisions on agent tool payloads.*  
   *Reality:* Approvers suffer from severe context opacity and notification fatigue, leading to rubber-stamping or operational paralysis.
3. **Assumption:** *Enterprises will manage security policies in a separate, dedicated Relay policy dashboard.*  
   *Reality:* Enterprise security teams demand centralized policy management in their existing SIEM, Okta/Entra policy consoles, or standard GitOps repositories using AWS Cedar/OPA.
4. **Assumption:** *A network proxy can govern local code interpreters and shell executions.*  
   *Reality:* Governed OS and bash actions require kernel-level micro-VM sandboxing (gVisor/Firecracker), not L7 HTTP proxies.

---

### 5. Existing Products We Underestimated

```
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 UNDERESTIMATED COMPETITOR STACK                                │
├───────────────────────────────┬────────────────────────────────────────────────────────────────┤
│ PRODUCT / PLATFORM            │ WHY WE UNDERESTIMATED THEM                                     │
├───────────────────────────────┼────────────────────────────────────────────────────────────────┤
│ • Microsoft Entra Agent IDs   │ Native integration into Azure OpenAI, M365 Copilot, and        │
│   & Purview                   │ Conditional Access. Free for existing E5 enterprise customers. │
├───────────────────────────────┼────────────────────────────────────────────────────────────────┤
│ • Temporal.io / Restate.dev   │ Already solved durable execution, distributed state, retries,  │
│                               │ and asynchronous human signal suspension with 100x reliability.│
├───────────────────────────────┼────────────────────────────────────────────────────────────────┤
│ • AWS Verified Permissions    │ Sub-millisecond Cedar evaluation directly hooked into API       │
│   & Bedrock Action Groups     │ Gateway and Lambda execution roles within AWS VPCs.            │
├───────────────────────────────┼────────────────────────────────────────────────────────────────┤
│ • Kong / Cloudflare AI        │ High-performance edge gateways already handling L7 AI proxying,│
│   Gateways                    │ rate limiting, token redaction, and credential vaulting.       │
├───────────────────────────────┼────────────────────────────────────────────────────────────────┤
│ • Braintrust & LangSmith      │ Moving rapidly from post-hoc tracing into inline proxy rules    │
│                               │ with deep developer loyalty and existing enterprise contracts. │
└───────────────────────────────┴────────────────────────────────────────────────────────────────┘
```

---

### 6. Ideas That Should Be Killed

1. **KILL: The "Two-Phase Commit (Plan/Apply) Engine for Agents"**  
   *Rationale:* Agents are dynamic ReAct loops, not static Terraform scripts. Statically pre-planning imperative multi-step agent trajectories before execution is technically impossible in non-trivial workflows.
2. **KILL: The Centralized SaaS Network Proxy for All Enterprise Tool Calls**  
   *Rationale:* High latency, security perimeter concerns, and single-point-of-failure risks make a centralized SaaS proxy an immediate non-starter for enterprise platform architects.
3. **KILL: Proprietary Policy Languages & RAPP Standards**  
   *Rationale:* Competing with AWS Cedar, OPA Rego, and MCP JSON-RPC schemas creates needless friction. Relay must adopt standard schemas without attempting to standardize a bespoke protocol envelope.
4. **KILL: Natural Language Intent Evaluation**  
   *Rationale:* Probabilistic intent statements cannot be validated by deterministic policy engines and are easily falsified by prompt-injected models.

---

### 7. Ideas That Should Be Strengthened

1. **STRENGTHEN: Zero-Trust MCP Credential Broker (The MCP Sidecar)**  
   *Focus:* Build an ultra-fast, local/sidecar MCP proxy that strips target credentials from agents, injects secrets only upon policy approval, and enforces strict schema validation on MCP `tools/call`.
2. **STRENGTHEN: Embedded AWS Cedar Policy Engine**  
   *Focus:* Compile fine-grained ABAC parameter policies using AWS Cedar (e.g., verifying SQL queries, transfer limits, and resource IDs in sub-millisecond Rust execution).
3. **STRENGTHEN: Cryptographic Action Attestation & Proof of Authorization**  
   *Focus:* Generate in-toto compliant, Sigstore/Cosign-signed cryptographic receipts for high-compliance industries (finance, healthcare, defense) to prove who/what authorized each state change.
4. **STRENGTHEN: Integration with Durable Execution Engines**  
   *Focus:* Partner with or integrate into Temporal, Restate, and LangGraph for asynchronous HITL suspension rather than attempting to handle state persistence out-of-band in an HTTP proxy.

---

### 8. Recommended Strategic Position

Relay must abandon the grandiose vision of being a *"Universal Multi-Step Agent Plan Control Plane"* and reposition as a focused, high-utility security primitive:

```
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   RELAY STRATEGIC PIVOT BLUEPRINT                              │
├────────────────────────────────────────────────┬───────────────────────────────────────────────┤
│ FROM (Flawed Current Form)                     │ TO (Defensible Pivot Position)                │
├────────────────────────────────────────────────┼───────────────────────────────────────────────┤
│ • Centralized SaaS Action Gateway              │ • Open-Source, Embeddable MCP Security Sidecar│
│ • Two-Phase Plan/Apply Engine                  │ • Fine-Grained Tool-Call Policy Enforcer (PEP)│
│ • Universal Asynchronous HITL Orchestrator     │ • Integration Plugin for Temporal / LangGraph │
│ • Bespoke Governance Protocol (RAPP/AAGI)      │ • Standard MCP + AWS Cedar + in-toto Receipts │
│ • Broad Enterprise "AI Governance"             │ • High-Assurance Action Attestation & Vaulting│
└────────────────────────────────────────────────┴───────────────────────────────────────────────┘
```

#### The Repositioned Product Profile: **Relay MCP Guard & Attest**
* **Form Factor:** Open-source Rust/Go sidecar binary and lightweight SDK.
* **Core Function:** Intercepts local or remote MCP JSON-RPC tool calls, evaluates deterministic Cedar ABAC policies on call arguments, securely injects vaulted API credentials, and emits Sigstore-signed action audit receipts.
* **Target User:** AI Platform Engineers and DevSecOps teams securing MCP-based agent deployments.

---

## Definitive Strategic Recommendation

# **PIVOT**

### Rationale for Decision:
* **Why NOT "BUILD" in current form:** Building Relay as a centralized Two-Phase Commit Plan/Apply Control Plane will fail because dynamic agent execution is incompatible with static pre-planning, asynchronous HITL breaks runtime agnosticism, and enterprise IAM/cloud providers will absorb the identity and tool-gating layers.
* **Why NOT "STOP":** The underlying security problem identified in R001 and R004 is genuine: *agents holding ambient credentials and executing unconstrained tool calls over protocols like MCP represents an urgent enterprise vulnerability.* There is clear commercial value in a lightweight, deterministic MCP policy proxy, zero-knowledge credential injector, and cryptographic attestation engine.
* **The Pivot Mandate:** Pivot immediately to an open-source, embeddable **MCP Zero-Trust Security Sidecar & Action Attestation Engine** leveraging AWS Cedar and in-toto provenance standards.
