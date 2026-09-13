# R004: Standards & Interoperability Research for a Runtime-Agnostic Agent Control Layer

**Document ID:** `R004`  
**Status:** Complete  
**Date:** 2026-09-12  
**Target:** Relay Architecture & Control Plane Design  

---

## Executive Summary

Relay's core product hypothesis states: *Agents should propose actions, while deterministic infrastructure determines whether those actions are authorized, approved, and executed.*

To function as a **runtime-agnostic agent control layer**, Relay cannot depend on the internal implementation, execution loop, or memory model of any specific agent framework (e.g., LangGraph, Anthropic Claude Code, OpenAI Assistants, AutoGen, CrewAI, or custom LLM loops). Instead, Relay must operate at standard protocol boundaries—intercepting, evaluating, and brokering actions before they hit downstream systems.

This research report investigates existing and emerging standards across five core domains:
1. **Tool Invocation & Interface Protocols** (MCP, OpenAPI/JSON Schema, Function Calling)
2. **Identity & Delegation** (OAuth 2.0 RAR/DPoP/Token Exchange, OIDC, SPIFFE/SPIRE, Workload Identity)
3. **Policy Evaluation & Decision** (NIST ABAC PEP/PDP, OPA/Rego, AWS Cedar, Zanzibar/ReBAC)
4. **Telemetry, Provenance & Cryptographic Evidence** (OpenTelemetry GenAI Semantic Conventions, W3C TraceContext, in-toto, Sigstore/Rekor, Merkle Trees)
5. **Agent Ecosystem Integrations** (Anthropic, OpenAI, LangGraph, Google Vertex, Custom Runtimes)

The report synthesizes these domains into an **Interoperability Architecture**, defines exact boundary adapters, maps which standards Relay must consume versus standardize, identifies critical failure modes ("dangerous assumptions"), and outlines open protocol questions.

---

## 1. Domain Standards Investigation

### 1.1 Model Context Protocol (MCP) & Tool Protocols

The Model Context Protocol (MCP), open-sourced by Anthropic in late 2024 and maintained by the Model Context Protocol working groups, has become the de facto protocol for connecting AI models/clients to tools, data resources, and prompt templates.

```
┌──────────────┐         MCP Protocol          ┌──────────────┐
│  MCP Host /  │ ◄───────────────────────────► │  MCP Server  │
│  Client      │   (JSON-RPC 2.0 over Stdio/   │  (Tools /    │
│ (Claude, etc)│    Streamed HTTP / SSE)       │   Resources) │
└──────────────┘                               └──────────────┘
```

#### Authentication & Authorization
* **Base Transport Mechanics:** The initial MCP specification relied predominantly on local process communication via `stdio` or remote communication via Server-Sent Events (SSE) with HTTP POST for client messages.
* **Authentication Gaps:** The base MCP spec does not define native, end-to-end credential negotiation or user authentication schemas within the JSON-RPC envelope itself. Authentication is deferred to the transport layer (e.g., standard HTTP `Authorization: Bearer <token>` headers on remote HTTP/SSE endpoints, or inherited OS process environment variables on `stdio`).
* **Authorization Primitives:** MCP exposes capability negotiation during initialization (`initialize` request), where client and server declare capabilities (`tools`, `resources`, `prompts`, `logging`, `sampling`, `roots`). However, fine-grained authorization (e.g., "Agent X can execute `query_database` but only `SELECT` queries on table `users`") is absent from the protocol layer.

#### Tool Invocation Lifecycle
* Tools are declared via `tools/list` returning JSON Schema declarations for tool parameters.
* Invocations occur via `tools/call` with arguments passed as JSON objects.
* Tool execution returns `{ content: [{ type: "text" | "image" | "resource", ... }], isError?: boolean }`.
* **State & Asynchrony:** Tool calls in MCP are RPC request-response pairs. Long-running actions rely on progress tokens (`notifications/progress`) or client-side polling; there is no native transaction/two-phase commit protocol or asynchronous approval suspension mechanism built into `tools/call`.

#### Server Identity, Gateways & Security Boundaries
* **Server Identity:** In `stdio` mode, server identity is implicit in the executable path and execution environment. In remote HTTP mode, server identity relies on standard Web PKI (TLS DNS names/certificates). There is no mutual cryptographic attestation or SPIFFE SVID verification standard in MCP today.
* **Gateways & Aggregators:** MCP gateways (e.g., multiplexing proxies that expose 50 downstream tools as a single MCP endpoint) aggregate `tools/list` and route `tools/call`. Gateways introduce a major security boundary challenge: schema collision, tool namespace shadowing, and loss of end-to-end provenance.
* **Confused Deputy & Delegation:** When an agent invokes a tool through an MCP server, the MCP server typically executes the action using its own ambient credentials (API keys, DB connections). The downstream target receives requests signed/authenticated by the MCP server, obscuring whether the human user, the parent agent, or a rogue subagent initiated the call.
* **Recent Specification Evolutions:** Shift from simple SSE to bidirectional streamed HTTP transports, inclusion of structured error payloads, root-level URI constraints (`roots/list`), and standardized elicitation/sampling controls (`sampling/createMessage`).

---

### 1.2 Identity & Delegation Protocols

AI agents break traditional 2-party identity models (Client $\leftrightarrow$ Resource Server) and 3-party OAuth flows (User $\leftrightarrow$ Client $\leftrightarrow$ Resource Server). Agents introduce a **4-party delegation problem**:

$$\text{End User } (U) \longrightarrow \text{Host/Platform } (H) \longrightarrow \text{Agent Runtime } (A) \longrightarrow \text{Tool / Resource } (T)$$

```
┌──────────────┐     Delegation Token      ┌──────────────┐     Constrained Token     ┌──────────────┐
│  Human User  │ ───────────────────────►  │ AI Agent (A) │ ────────────────────────► │ Tool/Service │
│     (U)      │   (OIDC / User Auth)      │  (Workload)  │   (RFC 8693 / RAR / DPoP) │     (T)      │
└──────────────┘                           └──────────────┘                           └──────────────┘
```

#### OAuth 2.0 Extensions Relevant to Agents
1. **RFC 8693 (OAuth 2.0 Token Exchange):**
   * Essential for agent delegation chains. Allows an agent $A$ holding a user token $U_{tok}$ to exchange it with an Authorization Server for a downstream token $T_{tok}$ scoped specifically to tool $T$, preserving the identity of both the subject ($U$) and the actor ($A$) via `act` (actor) claims.
2. **RFC 9396 (Rich Authorization Requests - RAR):**
   * Standardizes fine-grained authorization requests beyond simple coarse strings (`scope="read write"`).
   * Agents need dynamic, fine-grained scopes: e.g., `authorization_details: [{ type: "database_query", db: "analytics", operation: "SELECT", tables: ["metrics"] }]`.
3. **RFC 9449 (Demonstrating Proof-of-Possession - DPoP):**
   * Cryptographically binds access tokens to a private key held by the agent runtime, preventing token exfiltration and replay attacks if an agent's memory or context window is leaked.
4. **RFC 7523 (JWT Profile for Client Authentication and Authorization Grants):**
   * Enables agent workloads to authenticate directly to authorization servers using signed assertions without long-lived static secrets.

#### Workload Identity & SPIFFE / SPIRE
* **SPIFFE (Secure Production Identity Framework for Everyone):**
  * Defines standardized URIs (`spiffe://<trust-domain>/workload/<workload-id>`) encapsulated within SPIFFE Verifiable Identity Documents (SVIDs) via X.509 certificates or JWTs.
  * SPIRE provides the node agent and server to attest workloads based on OS/kernel attributes (cgroup, Linux UID/GID, Docker container hash, Kubernetes ServiceAccount).
* **Workload Identity Federation (GCP WIF, AWS IAM Roles Anywhere, Azure Workload Identity):**
  * Allows agent containers/pods running in Kubernetes or serverless environments to exchange OIDC identity tokens (e.g., from k8s or GitHub Actions) for short-lived cloud credentials without hardcoded API keys.
* **Agent vs. User Identity Duality:** An agent execution context requires a composite identity structure:
  * $\text{Identity} = \langle \text{Principal}_{\text{User}}, \text{Identity}_{\text{AgentInstance}}, \text{TrustDomain}_{\text{Runtime}}, \text{DelegationChain} \rangle$

---

### 1.3 Policy Enforcement & Decision Engines

Relay must evaluate proposed actions against deterministic policies. The established reference standard is the **NIST ABAC (Attribute-Based Access Control) & XACML architectural model**:

```
 ┌────────────────────────────────────────────────────────┐
 │                    Relay Policy Plane                  │
 │                                                        │
 │   ┌──────────────┐     Evaluate Proposal    ┌──────┐   │
 │   │  Policy      │ ◄──────────────────────► │ PDP  │   │
 │   │  Enforcement │                          │      │   │
 │   │  Point (PEP) │                          └──────┘   │
 │   └──────┬───────┘                             ▲       │
 │          │                                     │ Query │
 │          │                                     ▼       │
 │          │                                ┌─────────┐  │
 │          │ Intercept / Forward            │   PIP   │  │
 │          ▼                                └─────────┘  │
 │    Target Tool / API                                   │
 └────────────────────────────────────────────────────────┘
```

* **PEP (Policy Enforcement Point):** Intercepts action requests, halts execution, queries the PDP, enforces decision (Allow, Deny, Require Approval, Mutate).
* **PDP (Policy Decision Point):** Evaluates policies against request context and returns deterministic decisions.
* **PIP (Policy Information Point):** Supplies external state (e.g., user department, budget limits, rate counters).
* **PAP (Policy Administration Point):** Manages policy definitions, versions, and rollouts.

#### Comparison of Policy Technologies

| Dimension | Open Policy Agent (OPA / Rego) | AWS Cedar | Google Zanzibar / ReBAC (SpiceDB, OpenFGA) |
| :--- | :--- | :--- | :--- |
| **Primary Model** | ABAC / General Purpose Logic | ABAC + RBAC (Hierarchical) | ReBAC (Relationship-Based Access Control) |
| **Language Paradigm**| Declarative logic (Datalog derivative)| Strongly-typed policy language | Schema definition + Relation Tuples |
| **Execution Performance**| Sub-millisecond (in-memory Go / WASM)| Sub-millisecond (Rust engine, parallelizable)| Low latency for deep graph traversals (Zookies) |
| **Formal Verification**| No formal SMT verification | Built from ground-up for SMT/Z3 automated reasoning | Consistency checks via linearizable storage |
| **Payload Inspection** | **Exceptional** (complex JSON traversing, regex, arrays) | **Strong** (supports entities, attributes, context) | **Poor** (graphs only; does not evaluate arbitrary payload params) |
| **Action Suitability** | High (ideal for deep tool payload validation) | High (ideal for clear allow/deny and static analysis) | Medium (ideal for resource ownership, not tool arguments) |
| **Determinism** | Pure deterministic evaluation | Formally verified determinism | Deterministic graph expansion |

**Key Finding:** Zanzibar-style engines excel at answering *"Does User U have relation Owner on Document D?"*, but fail when answering *"Can Agent A invoke `stripe.transfer` where `amount < 500` and `destination_country == user.allowed_country`?"*. Relay requires **ABAC (Cedar or Rego)** for tool parameter inspection, combined with **ReBAC** for principal-resource relationship checks.

---

### 1.4 Telemetry, Traceability & Evidence

Action governance is incomplete without non-repudiable auditability and cryptographic evidence generation ("Action Receipts").

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Action Receipt Provenance Envelope                   │
├────────────────────────────────────────────────────────────────────────┤
│ • Subject: Hash(ActionPayload + ToolID)                                │
│ • Predicate: in-toto.io/attestation/agent-action/v1                     │
│ • Identity: SPIFFE SVID + OAuth act/sub claims                         │
│ • Decision: Relay PDP Allow Decision + Policy Hash                     │
│ • Telemetry: W3C traceparent (TraceID + SpanID)                        │
│ • Cryptographic Signature: Sigstore / Cosign Keyless Signature         │
│ • Immutability: Merkle Tree Inclusion Proof (Rekor / Trillian Log)     │
└────────────────────────────────────────────────────────────────────────┘
```

#### OpenTelemetry (OTel) & W3C TraceContext
* **W3C TraceContext (RFC / W3C Recommendation):**
  * `traceparent`: `00-<trace-id>-<parent-id>-<trace-flags>`
  * `tracestate`: vendor-specific routing state.
  * `baggage`: distributed key-value pairs (carries user ID, session ID, tenant ID across boundaries).
* **OpenTelemetry GenAI Semantic Conventions:**
  * Defines standard attributes for GenAI operations: `gen_ai.system`, `gen_ai.request.model`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`.
  * OpenTelemetry trace spans must link the LLM invocation span directly to downstream tool invocation spans (`gen_ai.tool.name`, `gen_ai.tool.call_id`).

#### Supply-Chain Provenance Standards Applied to Actions
* **in-toto Attestation Framework:**
  * Standardized JSON schema for software supply chain provenance statements consisting of:
    * `_type`: `https://in-toto.io/Statement/v1`
    * `subject`: Artifact / payload identification (e.g., hash of proposed tool call and resulting state).
    * `predicateType`: Custom or standardized predicate (e.g., `https://relay.dev/attestation/action-receipt/v1`).
    * `predicate`: Details of execution (policy ID, evaluator version, approvals, execution duration, response hash).
* **Sigstore / Rekor Transparency Log:**
  * Keyless signing via short-lived OIDC tokens.
  * Rekor provides an append-only, tamper-evident transparency log backed by a Merkle tree (RFC 6962), ensuring action receipts cannot be forged or deleted retroactively.

---

### 1.5 Agent Ecosystem Interoperability Analysis

To function as a truly runtime-agnostic control layer, Relay must integrate seamlessly across diverse agent architectures without imposing vendor lock-in.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        AGENT ECOSYSTEM INTEROPERABILITY MAP                            │
├───────────────────────┬───────────────────────────────────┬────────────────────────────┤
│ RUNTIME ECOSYSTEM     │ INTEROPERABILITY INTERFACE        │ SUSPENSION / HITL SUPPORT  │
├───────────────────────┼───────────────────────────────────┼────────────────────────────┤
│ • Anthropic / MCP     │ JSON-RPC 2.0 (Stdio / HTTP-SSE)   │ Client Confirmations / UX  │
│ • OpenAI / Assistants │ REST Tools Schema / Function Call │ `required_action` Polling  │
│ • Eve & Enterprise    │ Secure Webhooks / REST Dispatch   │ Task Review State Machine  │
│ • LangGraph / LangChain│ Python/TS SDK / `ToolNode`        │ Graph `interrupt()` / State│
│ • Google Vertex AI    │ `FunctionDeclaration` / Extensions│ Reasoning Engine Hooks     │
│ • Custom LLM Loops    │ Canonical RAPP REST / gRPC API    │ Ephemeral Token Expiry     │
└───────────────────────┴───────────────────────────────────┴────────────────────────────┘
```

#### Detailed Breakdown by Ecosystem

1. **Anthropic Ecosystem & MCP Clients/Servers:**
   * *Architecture:* Anthropic models communicate with external tools via the Model Context Protocol (MCP) or native XML/JSON tool schemas. MCP clients (Claude Desktop, Claude Code CLI, Goose, Continue, Zed, Cursor) connect to MCP servers.
   * *Relay Interception:* Relay operates as a **Multiplexing MCP Proxy**. The client configures Relay as its MCP server. Relay advertises filtered tool sets, intercepts `tools/call`, routes to the Relay PDP, and upon authorization, proxies to the downstream MCP server or target API.

2. **OpenAI Agent Systems (Assistants API, Realtime API, Function Calling):**
   * *Architecture:* OpenAI function calling relies on JSON Schema definitions in the `tools` array. The Assistants API introduces server-side run objects that enter a `requires_action` state when tool outputs are required.
   * *Relay Interception:* Relay provides an OpenAI-compatible API wrapper. When an agent requests a tool execution via `submit_tool_outputs`, Relay intercepts the payload, evaluates policy, routes approval if needed, executes the backend, and submits the verified outputs back into the Assistant thread.

3. **Eve & Enterprise Autonomous Agent Platforms:**
   * *Architecture:* Enterprise agent platforms like Eve (and similar high-assurance agent architectures in legal, finance, and enterprise operations) prioritize deterministic execution pipelines, rigorous audit trails, and strict role-based task delegation.
   * *Relay Interception:* Relay integrates at the task-execution dispatcher boundary. Eve agents propose multi-stage workflows; Relay evaluates each step against formal Cedar policies and generates cryptographic action receipts compliant with enterprise compliance and legal discovery standards.

4. **LangGraph & LangChain Ecosystem:**
   * *Architecture:* LangGraph organizes agent loops into state graphs with persistent checkpointing (Postgres/Redis). LangGraph has native support for human-in-the-loop via the `interrupt()` primitive.
   * *Relay Interception:* Relay provides a native `RelayToolNode` drop-in replacement. When a tool is invoked in the graph, the node sends a RAPP proposal to Relay. If Relay requires human approval, LangGraph smoothly checkpoints its state until Relay sends a webhook resume event.

5. **Google Agent Frameworks (Vertex AI Extensions, Reasoning Engine, Gemini API):**
   * *Architecture:* Google Vertex AI Reasoning Engine and Gemini utilize `FunctionDeclaration` structures and Vertex AI Extensions to invoke enterprise APIs using OpenAPI specs.
   * *Relay Interception:* Relay translates OpenAPI specs into governed Relay tools, acting as a secure Vertex Extension backend that enforces ABAC and generates immutable audit records before routing to GCP backend resources.

6. **Custom Agents & Bespoke LLM Loops:**
   * *Architecture:* Micro-frameworks (CrewAI, AutoGen, Semantic Kernel, custom Python/TypeScript scripts).
   * *Relay Interception:* Exposes a lightweight, universal gRPC/REST Policy Enforcement Point API and an optional zero-dependency local proxy sidecar.


---

## 2. Standards Map & Protocol Comparison

### 2.1 Complete Standards Map

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       RELAY STANDARDS MAP                                       │
├────────────────────────────────┬────────────────────────────────┬───────────────────────────────┤
│ 1. TRANSPORT & PROTOCOL LAYER  │ 2. IDENTITY & DELEGATION LAYER │ 3. POLICY & GOVERNANCE LAYER  │
│ • JSON-RPC 2.0 (MCP Transport) │ • OAuth 2.0 (RFC 6749)         │ • NIST SP 800-162 (ABAC Model)│
│ • gRPC / Protocol Buffers      │ • Token Exchange (RFC 8693)    │ • AWS Cedar Policy Language   │
│ • HTTP/1.1 & HTTP/2 REST       │ • Rich Auth Requests (RFC 9396)│ • Open Policy Agent (Rego)    │
│ • Server-Sent Events (SSE)     │ • DPoP (RFC 9449)              │ • OpenFGA / ReBAC (Zanzibar)  │
│ • JSON Schema (Draft 2020-12)  │ • SPIFFE / SPIRE (SVIDs)       │ • XACML 3.0 Architecture      │
├────────────────────────────────┴────────────────────────────────┴───────────────────────────────┤
│ 4. TELEMETRY, EVIDENCE & ATTESTATION LAYER                                                      │
│ • W3C TraceContext & W3C Baggage                                                                │
│ • OpenTelemetry GenAI & Trace Semantic Conventions                                              │
│ • in-toto Attestation Specification v1.0                                                        │
│ • Sigstore / Rekor Transparency Log (RFC 6962 Merkle Trees)                                     │
│ • JSON Web Signature (JWS / RFC 7515) & COSE (RFC 9052)                                         │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Deep Protocol Comparison Matrix

| Protocol / Standard | Layer | What it Solves | What it Leaves Unsolved / Limitations | Relay Role |
| :--- | :--- | :--- | :--- | :--- |
| **MCP (Model Context Protocol)** | Tool RPC & Context | Standardized tool schema discovery, resource access, and prompt templates across LLMs. | No fine-grained auth, no identity delegation, no multi-step transactions, no policy layer. | **Consume & Adapt** (Act as MCP Gateway / Server) |
| **OAuth 2.0 Token Exchange (RFC 8693)** | Identity & Auth | Propagates human identity alongside agent workload identity across microservice boundaries. | High complexity to deploy; requires compliant identity provider (IdP). | **Consume** (Core identity propagation standard) |
| **OAuth 2.0 RAR (RFC 9396)** | Fine-Grained Auth | Expresses complex, parameter-level authorization requests rather than flat strings. | Not yet universally supported by all legacy SaaS OAuth providers. | **Standardize in Relay Context** |
| **SPIFFE / SPIRE** | Workload Identity | Cryptographic, hardware/kernel-attested workload identities via mTLS / SVIDs. | Solves service identity, not user identity or delegation chains alone. | **Consume** (Agent workload & PEP node authentication) |
| **AWS Cedar** | Policy Decision | Ultra-fast, deterministic, formally verifiable ABAC/RBAC authorization decisions. | Static entity schemas; requires external PIP for dynamic database lookups. | **Consume / Core PDP Engine** |
| **Open Policy Agent (OPA)** | Policy Decision | Extremely expressive, Turing-complete JSON data policy evaluation. | Complex Rego semantics; no built-in formal SMT reasoning. | **Adapt / Optional PDP Engine** |
| **OpenTelemetry (OTel)** | Observability | Standardized distributed tracing, metrics, and GenAI semantic conventions. | Observability only; does not provide non-repudiation or cryptographic proof. | **Consume & Export** |
| **in-toto Attestations** | Evidence & Provenance | Standardized payload envelope linking subjects, predicates, signatures, and environment. | Requires verification infrastructure (Sigstore/Cosign). | **Standardize for Relay Action Receipts** |

---

## 3. Interoperability Architecture

Relay operates as a **Runtime-Agnostic Policy Enforcement Gateway & Evidence Engine**. The architecture separates concerns across three planes:
1. **Control Plane:** Agent framework interaction, tool discovery, protocol negotiation.
2. **Policy Plane:** Deterministic policy decision point (PDP), human approval routing, simulation.
3. **Execution & Evidence Plane:** Isolated tool execution, credential injection, cryptographic receipt generation.

```
                                      RELAY ARCHITECTURE
                                      
  ┌────────────────────────────────────────────────────────────────────────────────────────┐
  │ AGENT RUNTIMES (Framework Agnostic)                                                    │
  │  Claude Code / Anthropic  │  OpenAI Agents  │  LangGraph  │  Custom Agent / LLM Loop  │
  └───────────────────────────┬─────────────────┴─────────────┴────────────────────────────┘
                              │
                              │ Tool Invocation (MCP / HTTP / OpenAPI / gRPC)
                              ▼
  ┌────────────────────────────────────────────────────────────────────────────────────────┐
  │ RELAY INGRESS ADAPTER & PROTOCOL TRANSLATOR                                            │
  │ • MCP Server/Gateway Interface       • OpenAI Function Calling Adapter                 │
  │ • gRPC / REST Action Proposal API    • W3C TraceContext & Identity Context Extractor   │
  └───────────────────────────┬────────────────────────────────────────────────────────────┘
                              │ Normalized Action Proposal (JSON Schema + Identity Context)
                              ▼
  ┌────────────────────────────────────────────────────────────────────────────────────────┐
  │ RELAY POLICY ENFORCEMENT POINT (PEP)                                                   │
  │                                                                                        │
  │   ┌────────────────────────────────────────────────────────────────────────────────┐   │
  │   │ DETERMINISTIC POLICY DECISION POINT (PDP)                                      │   │
  │   │ • Cedar / Rego Policy Evaluation                                               │   │
  │   │ • Parameter Boundary & Type Checking                                           │   │
  │   │ • Rate Limit & Budget Enforcers                                                │   │
  │   │ • State Verification (PIP Queries)                                             │   │
  │   └───────────────────────┬────────────────────────────────────────────────────────┘   │
  │                           │                                                            │
  │             ┌─────────────┴─────────────┐                                              │
  │             ▼                           ▼                                              │
  │      [ALLOW / MUTATE]          [REQUIRE APPROVAL]             [DENY]                   │
  │             │                           │                       │                      │
  │             │                  ┌────────┴────────┐              ▼                      │
  │             │                  │ Human-in-the-   │    Return ActionDeniedError         │
  │             │                  │ Loop (HITL)     │    with Policy Reason               │
  │             │                  │ Webhook / UI    │                                     │
  │             │                  └────────┬────────┘                                     │
  │             │                           │ (Approved)                                   │
  │             └───────────────────────────┘                                              │
  │                           │                                                            │
  │                           ▼                                                            │
  │   ┌────────────────────────────────────────────────────────────────────────────────┐   │
  │   │ EXECUTION BROKER & VAULT                                                       │   │
  │   │ • Token Minting & Credential Injection (Downstream API Keys / OIDC)            │   │
  │   │ • Sandbox / Egress Execution Engine                                            │   │
  │   └───────────────────────┬────────────────────────────────────────────────────────┘   │
  └───────────────────────────┼────────────────────────────────────────────────────────────┘
                              │
             ┌────────────────┴────────────────┐
             ▼                                 ▼
┌───────────────────────────────┐   ┌──────────────────────────────────────────────────────┐
│ DOWNSTREAM TARGET SYSTEMS     │   │ RELAY EVIDENCE PLANE                                 │
│ • SaaS APIs (GitHub, Slack)   │   │ • OpenTelemetry Traces Emitted                       │
│ • Production Databases        │   │ • in-toto Action Receipt Signed (JWS/Cosign)         │
│ • Cloud Infrastructure (AWS)  │   │ • Appended to Immutability Log (Rekor / Merkle Tree) │
│ • Internal Microservices      │   │ • Non-repudiable Proof returned to caller           │
└───────────────────────────────┘   └──────────────────────────────────────────────────────┘
```

---

## 4. Strategic Protocol Decisions: The 4 Quadrants

```
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. STANDARDIZE (Relay-Owned Specs)         │ 2. CONSUME (Adopt Off-the-Shelf)                  │
│ • Relay Action Proposal Protocol (RAPP)    │ • W3C TraceContext & OpenTelemetry                │
│ • Relay Action Receipt Specification       │ • AWS Cedar & Open Policy Agent (Rego)            │
│ • Asynchronous Approval Suspension Contract│ • OAuth 2.0 (RFC 6749, RFC 8693, DPoP)            │
│ • Tool Intent & Dry-Run Semantic Schema    │ • SPIFFE / SPIRE Workload SVIDs                   │
├────────────────────────────────────────────┼───────────────────────────────────────────────────┤
│ 3. ADAPT (Bridge with Thin Shims)          │ 4. JUSTIFY NEW PROTOCOL (Where Existing Fails)    │
│ • MCP (Model Context Protocol)             │ • Deterministic Agent Action Suspension Protocol  │
│ • OpenAI Function Calling JSON Schema      │ • Multi-Agent Ambient Authority Attestation       │
│ • OpenAPI 3.1 REST Endpoints               │   (Cryptographically linking Prompt -> Intent     │
│ • Cloud Provider Workload Identity (AWS/GCP│    -> Proposal -> Decision -> Execution)          │
└────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 4.1 What Relay Should Standardize
1. **Relay Action Proposal Protocol (RAPP):**
   * A JSON/gRPC data schema representing a proposed action before execution, capturing:
     * `proposal_id`: UUIDv7 (time-sortable).
     * `actor_context`: Composite identity (User, Agent Instance, Runtime, SPIFFE ID).
     * `action_name`: Fully-qualified target action (e.g., `github.com/pull_request/merge`).
     * `parameters`: Canonical JSON structure of arguments.
     * `intent_statement`: Natural language rationale provided by the agent.
     * `idempotency_key`: Deduplication token.
2. **Relay Action Receipt Schema (in-toto Predicate):**
   * Cryptographically signed proof of what was proposed, who evaluated it, what policy version was checked, what human approval was provided, what downstream call was made, and what result was returned.
3. **Action Suspension & Resume Contract:**
   * A standardized state-machine contract allowing any synchronous agent tool call to be cleanly suspended (HTTP 202 Accepted / MCP Progress / Long-polling / Async Webhook) when human approval or multi-stage verification is required, without dropping socket connections or blowing LLM context windows.

### 4.2 What Relay Should Simply Consume
* **W3C TraceContext & Baggage:** Standard distributed tracing propagation.
* **AWS Cedar / OPA Rego:** Proven policy evaluation engines. Relay should not invent a new policy DSL.
* **OAuth 2.0 Token Exchange (RFC 8693) & OIDC:** Standard delegation and token propagation.
* **SPIFFE / SPIRE:** Node-level and container-level workload identity.
* **Sigstore / Rekor:** Keyless signing and transparency logging.

### 4.3 What Relay Should Adapt
* **Anthropic MCP:** Relay adapts MCP by providing a bidirectional MCP Proxy. To the agent, Relay appears as a standard MCP Server. To downstream tools, Relay appears as an MCP Client or API gateway.
* **OpenAI Function Calling:** Relay provides an adapter that ingests OpenAI `chat/completions` or Assistants API tool schemas and maps them to RAPP.
* **OpenAPI 3.1 Specs:** Relay automatically ingests OpenAPI definitions to generate tool schemas, parameter validation rules, and proxy stubs.

### 4.4 Where Creating a New Protocol Is Justified
Creating a new protocol is justified **only** for the **Agent Action Governance Interface (AAGI)**:
* Existing protocols (like HTTP REST or MCP) are point-to-point RPC mechanisms. They do not model **governance states** (e.g., `PROPOSED` $\rightarrow$ `SIMULATING` $\rightarrow$ `POLICY_EVALUATED` $\rightarrow$ `AWAITING_APPROVAL` $\rightarrow$ `EXECUTING` $\rightarrow$ `COMMITTED` $\rightarrow$ `ATTESTED`).
* AAGI provides the state machine and envelope for asynchronous, non-repudiable agent action transactions.

---

## 5. Architectural Evaluation: Can Relay Sit at a PEP Independent of Agent Runtime?

**Yes.** Relay can sit at a Policy Enforcement Point (PEP) completely independent of agent runtimes by utilizing three distinct deployment interception topologies:

```
  TOPOLOGY A: Transport / Gateway Interceptor (Recommended Default)
  ┌──────────────┐     MCP / HTTP RPC      ┌───────────────────┐     Governed API      ┌──────────────┐
  │ Agent System │ ──────────────────────► │ Relay Gateway PEP │ ────────────────────► │ Target SaaS/ │
  │ (Any Runtime)│                         │ (Auth + Policy)   │                       │ Tool Backend │
  └──────────────┘                         └───────────────────┘                       └──────────────┘

  TOPOLOGY B: Local Host Sidecar
  ┌──────────────────────────────────────────────┐
  │ Host / Container                             │
  │  ┌──────────────┐      Stdio / Local HTTP    │
  │  │ Agent Loop   │ ◄────────────────────────► │ ┌───────────────────┐     mTLS     ┌──────────────┐
  │  │ (LangGraph)  │                            │ │ Relay PEP Sidecar │ ───────────► │ Remote Relay │
  │  └──────────────┘                            │ └───────────────────┘              │ Policy Plane │
  └──────────────────────────────────────────────┘                                    └──────────────┘

  TOPOLOGY C: Reverse Proxy at Resource Boundary
  ┌──────────────┐     Direct API Call     ┌───────────────────┐     Internal Call     ┌──────────────┐
  │ Agent System │ ──────────────────────► │ Relay Tool PEP    │ ────────────────────► │ Target Core  │
  │ (Untrusted)  │                         │ (Enforces Policy) │                       │ Database/API │
  └──────────────┘                         └───────────────────┘                       └──────────────┘
```

### Evaluation of Interception Topologies

1. **Topology A: Gateway Proxy (MCP Server / REST Proxy)**
   * *Mechanism:* Agent connects to Relay as if Relay were its MCP Server or Tool Provider. Relay advertises available tools (`tools/list`). When the agent issues `tools/call`, Relay intercepts the call, executes PDP checks, and only then reaches out to the real underlying API.
   * *Runtime Independence:* 100%. Works with any agent capable of speaking MCP, OpenAPI, or HTTP.
2. **Topology B: Local Sidecar / SDK Wrapper**
   * *Mechanism:* For runtimes running in local containers (e.g., Python/Node agents), a lightweight Relay sidecar intercepts outbound network traffic or stdio pipes.
   * *Runtime Independence:* High. Requires sidecar deployment alongside agent containers.
3. **Topology C: Target Ingress Reverse Proxy**
   * *Mechanism:* Relay sits in front of the target system (e.g., production database or GitHub API). The agent attempts direct access, but is intercepted by Relay's reverse proxy requiring a Relay-evaluated token.
   * *Runtime Independence:* 100%. Zero agent modifications required; enforces security at the resource perimeter.

---

## 6. Dangerous Assumptions & Failure Modes

Building a runtime-agnostic agent control layer involves several subtle, high-risk assumptions:

```
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 CRITICAL DANGEROUS ASSUMPTIONS                                 │
├────────────────────────────────┬────────────────────────────────┬──────────────────────────────┤
│ 1. Synchronous Execution Model │ 2. Single-Step Tool Atomicity  │ 3. Ambient Identity Trust    │
│ Assuming tool calls return in  │ Assuming complex agent actions │ Assuming agent process       │
│ milliseconds. Real governance  │ can be authorized as isolated, │ identity equals the end-user │
│ requires human approvals.      │ independent API calls.         │ authorization context.       │
├────────────────────────────────┼────────────────────────────────┼──────────────────────────────┤
│ 4. Verbatim Argument Fidelity  │ 5. Client-Side Tool Containment│ 6. Out-of-Band State Blindness│
│ Assuming LLM arguments always  │ Assuming local bash/filesystem │ Assuming policies can decide │
│ match static types without     │ tools can be governed purely   │ actions without real-time    │
│ hallucinated or mutated fields.│ via network-level proxies.     │ external database state.     │
└────────────────────────────────┴────────────────────────────────┴──────────────────────────────┘
```

### Deep Dive into Failure Modes

1. **The Synchronous Timeout Trap:**
   * *Dangerous Assumption:* Standard LLM tool execution loops assume synchronous HTTP/RPC responses within 10–60 seconds.
   * *Failure Mode:* If a policy requires human-in-the-loop (HITL) approval (e.g., a manager reviewing a \$10,000 transfer), the approval may take minutes or hours. Standard MCP or OpenAI client connections will time out, drop connections, and crash the agent loop.
   * *Mitigation:* Relay must implement asynchronous suspension mechanics: returning structured suspension tokens (`Status: PendingApproval`), persisting graph state, or maintaining HTTP connection keep-alive streams with heartbeat progress notifications.

2. **The "Single-Step" Atomicity Fallacy:**
   * *Dangerous Assumption:* Evaluating `Step 1: Read Table` and `Step 2: Write File` separately is sufficient.
   * *Failure Mode:* An attacker performs Prompt Injection on Step 1, changing the agent's internal memory. In Step 2, the agent leaks data. Because Step 2 in isolation appears to be a benign `Write File` call, stateless PDP engines allow it.
   * *Mitigation:* Relay must maintain **Session-Level Policy State** and trace context across multi-step agent trajectories, evaluating cumulative data egress and permission taint tracking.

3. **Ambient Credential Leakage & Confused Deputy:**
   * *Dangerous Assumption:* Passing static target API keys into the agent environment is acceptable if the agent is "prompt-instructed" not to leak them.
   * *Failure Mode:* Prompt injection extracts the raw API keys from environment variables or tool headers, completely bypassing Relay.
   * *Mitigation:* **Zero-Knowledge Agent Architecture**. The agent must *never* hold target credentials. Relay holds credentials in an isolated vault. The agent only receives ephemeral, scoped Relay tokens; Relay injects real credentials at execution time.

4. **Local Execution (Bash/File) Blindspot:**
   * *Dangerous Assumption:* Network-level proxying can govern local code interpreter actions (e.g., `bash.execute("rm -rf /")`).
   * *Failure Mode:* If an agent runs arbitrary Python or Shell scripts locally, network proxies cannot prevent destructive OS actions.
   * *Mitigation:* Local tools must be executed inside deterministic micro-VMs (Firecracker / gVisor) managed by Relay, intercepting syscalls and filesystem mutations.

---

## 7. Recommended Adapter Boundaries

To maintain runtime agnosticism while delivering deterministic control, Relay must establish precise adapter boundaries:

```
                                  ADAPTER BOUNDARY SPECIFICATION
                                  
  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐
  │ INGRESS ADAPTER BOUNDARY                                                                    │
  │ Responsibilities:                                                                           │
  │ 1. Terminate agent transport (MCP Stdio/HTTP, OpenAI REST, LangGraph ToolNode, gRPC).      │
  │ 2. Extract W3C TraceContext headers & OAuth/OIDC tokens.                                    │
  │ 3. Normalize tool call payload into canonical Relay Action Proposal (RAPP).                 │
  │ 4. Inject Correlation IDs & Nonces.                                                         │
  └──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                                 │ Canonical RAPP Object
                                                 ▼
  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐
  │ CORE RELAY CONTROL & POLICY PLANE (Runtime-Agnostic Core)                                   │
  │ Responsibilities:                                                                           │
  │ 1. Schema Validation (JSON Schema Draft 2020-12).                                           │
  │ 2. Identity Context Binding (SPIFFE + User OIDC + Actor Chain).                             │
  │ 3. Deterministic Policy Evaluation (Cedar / Rego).                                          │
  │ 4. Approval Routing & State Machine Engine (Pending/Approved/Denied).                       │
  │ 5. Session State & Taint Tracking.                                                          │
  └──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                                 │ Authorized Execution Plan
                                                 ▼
  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐
  │ EGRESS & EXECUTION ADAPTER BOUNDARY                                                         │
  │ Responsibilities:                                                                           │
  │ 1. Retrieve & Inject Downstream Credentials from Secret Vault (OAuth, API Key, mTLS).       │
  │ 2. Execute target HTTP/gRPC/Database call or isolate in Micro-VM sandbox.                   │
  │ 3. Capture exact response payload & execution metrics.                                      │
  │ 4. Generate in-toto Action Receipt, sign with Sigstore/Cosign, emit to Rekor & OTel.        │
  │ 5. Format response back to Ingress protocol format (MCP ToolResult / OpenAI ToolOutput).    │
  └─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Unresolved Protocol Questions & Research Frontiers

While standardizing Relay's control plane on existing building blocks is highly viable, several protocol-level challenges remain open across the industry:

1. **Standardized Context Window Invalidation on Policy Denial:**
   * When Relay rejects an action (`ActionDenied: Violates Security Policy X`), how should the error be structured to prevent the agent from entering an infinite retry loop or hallucinations, while avoiding leaking sensitive policy internals to a potentially compromised model?
2. **Multi-Agent Cascade Attestation:**
   * When Agent $A_1$ spawns Subagent $A_2$, which delegates to Subagent $A_3$, how do we cryptographically bind and verify the cumulative lineage and prompt-chain intent without exceeding token context limits or incurring unacceptable signature verification latencies?
3. **Streaming & Partial-Argument Tool Calls:**
   * Modern LLMs support streamed tool calls (emitting argument JSON chunks incrementally). Can policy evaluation begin on partial argument streams (e.g., early-blocking an unauthorized URL domain before the full payload is generated), and what protocol standardizes early-abort notifications?
4. **Universal Asynchronous Tool Resumption:**
   * Until MCP and client agent frameworks adopt a formal asynchronous suspension protocol, what is the most resilient, transport-agnostic fallback mechanism to handle human approval delays exceeding 30 minutes without dropping connections or requiring framework-specific state rehydration?

---

## 9. Conclusion & Actionable Roadmap for Relay

1. **Adopt MCP as the Primary Ingress/Egress Adapter Protocol:** Treat MCP as the interface standard for agent-to-tool communication, wrapping Relay around MCP connections as an intelligent, policy-enforcing proxy.
2. **Standardize on AWS Cedar for Policy Definition:** Utilize Cedar for fast, deterministic, formally verifiable ABAC parameter inspection.
3. **Anchor Identity in OAuth 2.0 Token Exchange (RFC 8693) + SPIFFE:** Solve the 4-party agent identity problem using standardized actor/subject tokens and mTLS SVIDs.
4. **Build the Relay Action Receipt on in-toto + Sigstore:** Produce cryptographically signed, tamper-evident action receipts that integrate cleanly with enterprise SIEM and OpenTelemetry audit systems.
5. **Implement the Zero-Knowledge Execution Sandbox:** Ensure agent runtimes never directly possess target credentials, strictly enforcing Relay as the credential-injecting PEP.
