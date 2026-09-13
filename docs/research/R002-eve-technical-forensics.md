# R002: Vercel Eve Framework — Deep Technical Forensics & Relay Integration Analysis

**Document ID**: `R002-eve-technical-forensics`  
**Status**: Completed  
**Author**: Relay Research & Architecture  
**Target Dependency**: Vercel Eve (`vercel/eve` repository / `eve` npm package, v0.25.x line)  
**Primary Artifact**: `docs/research/R002-eve-technical-forensics.md`  

---

## Executive Summary

Relay's core product hypothesis states:
> *"Agents should propose actions, while deterministic infrastructure determines whether those actions are authorized, approved, and executed."*

This technical forensics investigation examines Vercel's **Eve framework** (`vercel/eve`), a filesystem-first, durable agent framework built on top of the Vercel Workflow SDK (`@workflow/core`) and Vercel AI SDK 7 (`ai`). We evaluated Eve's architecture, execution lifecycle, sandboxing, human-in-the-loop (HITL) approval primitives, subagent hierarchy, state persistence, failure semantics, and security boundaries.

### Key Findings
1. **Durable Orchestration via Workflow SDK**: Eve turns run as durable workflows compiled with `"use workflow"` directives. Work is divided into *Sessions* (durable conversations, default 30-day lifetime), *Turns* (one user delivery triggering an agent execution loop), and *Steps* (durable checkpoints containing one model-and-tool cycle).
2. **Two-Tier Runtime / Sandbox Boundary**: Eve explicitly partitions execution into an **App Runtime** (trusted Node.js / Vercel Function hosting tools, credentials, model loops, and state) and a **Sandbox** (isolated Linux microVM, Docker container, or VM rooted at `/workspace` for unprivileged bash/file operations).
3. **In-Framework Approval vs. External Governance**: Eve provides a built-in approval policy API (`approval: always() | once() | never() | ApprovalPolicy`) and human-in-the-loop (HITL) pause-and-resume protocol (`input.requested` $\to$ `session.waiting` $\to$ `inputResponses`). However, Eve treats approval as an **in-process callback** or **single-session prompt**, rather than an independent, tamper-proof, multi-party policy decision/enforcement point.
4. **Viability for Relay Integration**: Eve provides clear, deterministic technical hooks where Relay can intercept proposed tool actions before execution (`approval` policy adapters, wrapped tool executors, and channel proxies). However, Relay **must not delegate final authorization, policy storage, or multi-party approval state to Eve's internal session state**.

---

## 1. Technical Forensic Analysis (Questions 1–15)

### 1. What is Eve's actual execution model?
Eve's execution engine is built on a layered architecture:
- **Hosting & Transport**: Hosted via Nitro HTTP routes (`packages/eve/src/channel/http.ts`), exposing ID-addressed session endpoints (`POST /eve/v1/session`, `GET /eve/v1/session/:id/stream`, `POST /eve/v1/session/:id/cancel`).
- **Durable Orchestration**: Built upon `@workflow/core` (Vercel Workflow / Workflow SDK). Turns execute as durable workflows (`turnWorkflow` in `packages/eve/src/execution/turn-workflow.ts`). Every turn run is recorded in a Workflow World (`@workflow/world-local` on disk at `.eve/.workflow-data`, `@workflow/world-postgres`, or hosted Vercel Workflow).
- **In-Step Agent Loop**: Inside each durable workflow step (`turnStep`), Eve instantiates Vercel AI SDK 7's `ToolLoopAgent` (`packages/eve/src/harness/tool-loop.ts`). By default, each step evaluates `stopWhen: isStepCount(1)`, forcing a durable step boundary and checkpoint after each model call and its inline tool executions.
- **Dual Execution Contexts**:
  1. *App Runtime*: Trusted Node.js execution environment where model routing, tool dispatch, hooks, credentials, and state persist.
  2. *Sandbox*: Disposable or persistent compute environment (`packages/eve/src/sandbox/`) running Vercel Sandbox (microVM), Docker, microsandbox (local KVM/macOS VM), or `just-bash` (JS interpreter).

### 2. What is the lifecycle of an agent action?
1. **Action Generation**: The model emits a tool call during the `ToolLoopAgent` streaming loop (`actions.requested` emitted on the NDJSON stream).
2. **Pre-Execution Gating / Approval Policy**: Before executing the tool, Eve invokes the tool's configured `approval` policy (`buildApprovalFn` in `packages/eve/src/harness/tools.ts`, `packages/eve/src/approval/definition.ts`).
3. **Approval Resolution**:
   - If policy returns `"not-applicable"` or `"approved"`, execution proceeds immediately.
   - If policy returns `"denied"`, execution is skipped and a tool failure result (`TOOL_EXECUTION_DENIED`) is synthesized for the model.
   - If policy returns `"user-approval"` (or a custom request), the turn emits an `input.requested` event (carrying `requestId`, `callId`, `toolName`, `toolInput`), persists a pending input batch, and parks the durable turn at `session.waiting` via a Workflow SDK hook (`createHook`).
4. **Execution Dispatch**:
   - For *App-side tools*: The `execute(input, ctx)` function is called directly in the App Runtime.
   - For *Sandbox tools* (`bash`, `read_file`, `write_file`, `grep`, `glob`): The tool runs in the App Runtime and proxies commands/file I/O into the sandbox via `ctx.getSandbox()`.
   - For *Workflow tools* (`defineWorkflowTool`): A child workflow is started; the tool may suspend independently.
5. **Result Staging & Post-Processing**: Output is normalized (`normalizeToolJsonOutput`), written to the durable step journal, and emitted as `action.result`.
6. **Step / Turn Completion**: The AI SDK loop incorporates the tool result into the message history for the subsequent model step.

### 3. Where could Relay intercept an action?
There are four concrete technical interception points:
1. **Tool Approval Policy Adapter (`ApprovalPolicy`)**: Implemented at `approval: async (ctx) => Relay.evaluatePolicy(ctx)`. This intercepts the action in the App Runtime *before* `execute()` is called, with full access to `toolName`, `toolInput`, `callId`, session identity, and caller attributes.
2. **Tool Executor Wrapper (`defineTool` / `wrapToolExecute`)**: Wrapping the tool's `execute` function to delegate execution through Relay's deterministic gateway or proxy.
3. **HTTP Channel / Ingress Proxy**: Intercepting incoming requests (`POST /eve/v1/session/:sessionId`) and outgoing stream events (`GET /eve/v1/session/:sessionId/stream`) at the Nitro/HTTP boundary.
4. **Event Stream Hooks (`agent/hooks/*.ts`)**: Subscribing to `actions.requested` and `action.result` events via `defineHook`. (Note: Hooks are observe-only and fire *after* durable logging; they cannot block execution).

### 4. Can Relay reliably enforce authorization before execution?
**Yes, within the App Runtime via the `approval` policy hook.**  
When a tool has an `approval` callback, Eve's `ToolLoopAgent` harness evaluates `resolveApprovalPolicy(definition.approval)(ctx)` *strictly prior* to invoking `execute()`. If Relay's policy adapter returns `{ type: "denied", reason: "..." }`, Eve halts the execution of that tool call, persists an explicit denial, and injects the denial into the model's conversation history without ever invoking the underlying tool body or sandbox command.

### 5. Can an Eve workflow pause for approval and later resume?
**Yes, natively and durably.**  
When an approval policy returns `"user-approval"`, Eve:
1. Emits `input.requested` containing a stable `requestId` and `callId`.
2. Suspends the Workflow step using `@workflow/core`'s `createHook` (`packages/eve/src/execution/turn-workflow.ts`).
3. Sets session status to `session.waiting`. Zero compute is held while parked; process restarts, redeployments, or multi-day waits survive intact.
4. Resumes when a client sends `POST /eve/v1/session/:id` with `inputResponses: [{ requestId, optionId: "approve" | "cancel" }]`.
5. Upon resume, Eve verifies the approval response, settles the tool call, and resumes the turn from the exact checkpoint.

### 6. How are subagents represented?
Eve provides two subagent mechanisms (`packages/eve/src/subagents/`):
- **Built-in `agent` tool (Root-only)**: A tool injected exclusively into the root agent that spawns a replica of the root agent with fresh conversation history and state, but sharing the root's instructions, connections, auth, and sandbox workspace.
- **Declared Subagents (`agent/subagents/<id>/`)**: Distinct specialists defined in dedicated subdirectories with their own `agent.ts`, `instructions.md`, isolated `tools/`, `skills/`, and sandbox.
- **Runtime Representation**: Eve lowers subagents into model-visible tools accepting `{ message: string, agentId?: string, outputSchema?: object }`. Each subagent executes as an independent child session and durable workflow.

### 7. How does authority flow between parent and child agents?
- **Context Isolation**: By default, declared subagents inherit **nothing** from parent authored slots. They run with their own tools, instructions, and state.
- **Explicit Parameter Passing**: The parent communicates with the child solely through the `message` string input.
- **Principal Propagation**: The child session's `auth.initiator` retains the identity of the user who started the session, while `auth.current` can reflect the caller or app principal.
- **Approval Containment**: Child tool executions must satisfy their own tool-level `approval` policies. Interactive approval requests (`input.requested`) generated by a child are proxied onto the parent session's stream so the user/channel can resolve them.

### 8. What is persistent?
| Component | Persistence Mechanism | Lifetime / Scope |
| :--- | :--- | :--- |
| **Workflow State** | `@workflow/world-*` (Disk SQLite/JSON, PostgreSQL, Vercel Workflow) | Survives crashes, process restarts, redeploys. |
| **Session History** | Append-only NDJSON stream & durable snapshot store | Persisted for session duration (default 30 days). |
| **Durable State** | `defineState` key-value store in session snapshot | Scoped to individual session ID. |
| **Sandbox `/workspace`** | MicroVM snapshot (Vercel), Docker container, or local dir | Persists across turns; reattached by `sandbox.id`. |
| **Connection Credentials** | App runtime memory / OAuth token cache | Cached per step; **never** serialized to durable state. |

### 9. What happens on process failure?
- **Workflow Step Journaling**: Eve checkpoints at step boundaries. If the process crashes mid-step, the Workflow SDK detects uncommitted execution and **re-runs the step from the last committed snapshot** (up to 4 retry attempts).
- **Idempotency Requirement**: Completed steps are served from the recorded journal and never re-execute. However, uncompleted steps re-run from the beginning. Therefore, side-effecting tools must either be idempotent, use external idempotency keys (`${ctx.session.id}:${ctx.session.turn.id}`), or be gated by `approval: always()`.
- **Stream Re-emission**: Re-run steps emit fresh stream events under new ULID `meta.id`s.

### 10. What happens if Relay itself is unavailable?
- **Synchronous Policy Gating**: If an authored tool's `approval` policy delegates to Relay over HTTP and Relay times out or returns a 5xx error:
  - If the adapter throws an error or returns `{ type: "denied" }`, Eve **fails closed**, recording a step failure or tool denial and preventing execution.
  - If the adapter catches errors and returns a fallback `"user-approval"`, the turn safely parks until Relay/human resumes it.
- **Asynchronous Resumption**: If Relay's governance daemon is offline while an approval is pending, the Eve workflow remains parked in `session.waiting` indefinitely without data loss or compute consumption.

### 11. What security assumptions does Eve make?
1. **Trusted App Runtime**: Assumes the Node.js hosting environment (and its `process.env`) is fully trusted. Secrets are kept out of the sandbox.
2. **Untrusted Sandbox**: Assumes code executed inside the sandbox (via `bash`) is untrusted. Network egress is controlled via network policies (`deny-all`, allow-lists) and credential brokering.
3. **Channel Authenticity**: Assumes inbound channel requests verify HMAC signatures in constant time and derive identity strictly from verified claims, never unverified JSON body fields.
4. **Internal Single-User Approval Model**: Built-in approvals assume anyone with write access to the session channel is authorized to approve pending actions. Multi-tenant and four-eyes authorization must be implemented in application-level policies.

### 12. Which Eve APIs are stable enough to depend on?
- **`defineTool` / `defineWorkflowTool` (`eve/tools`)**: Stable high-level tool declaration API.
- **`ApprovalPolicy` & `ApprovalContext` (`eve/tools/approval`, `eve/approval/definition`)**: Stable signature for pre-execution evaluation.
- **Session HTTP API (`/eve/v1/session`, `/stream`, `/cancel`)**: Stable NDJSON stream format (v25) and control endpoints.
- **`defineAgent` (`eve`)**: Core agent configuration contract.

### 13. Which APIs should be hidden behind our own adapters?
- **Approval Policy Dispatcher**: Wrap Eve's `ApprovalPolicy` with a Relay Policy Enforcement Adapter.
- **Workflow State World Selection (`experimental.workflow.*`)**: Keep Workflow storage drivers decoupled behind standard interfaces.
- **Dynamic Capabilities (`defineDynamic`)**: Dynamic tools/resolvers should be abstracted to prevent tight coupling with Eve-specific AST/runtime compiler passes.
- **Sandbox Management (`ctx.getSandbox()`)**: Abstract filesystem/bash execution to allow swapping between Eve Sandboxes, Docker, and Relay-native isolation runners.

### 14. What would be risky to couple Relay to?
- **Internal AST Compiler / Discover Logic (`packages/eve/src/compiler/`)**: Eve relies on strict convention-based directory discovery (`agent/tools/*.ts`). Coupling Relay to Eve's internal filesystem bundler creates high maintenance overhead.
- **Beta/Experimental Features**: `experimental.workflow.modelCallsPerStep` (which groups multiple model/tool cycles into one step, breaking single-action replay boundaries).
- **AI SDK 7 Internal Harness Details**: Relying directly on private internals of `ToolLoopAgent` or Eve's `packages/eve/src/harness/` rather than the exported `eve/tools` APIs.

### 15. Which Relay capabilities can be built independently of Eve?
1. **Central Policy Engine & Rule Evaluator**: Authorization logic (ABAC/RBAC, risk classification, budget limits, parameter constraints) is 100% framework-agnostic.
2. **Multi-Party / Four-Eyes Approval Workflow**: The durable tracking of approval requests, reviewer assignments, quorum voting, and audit trails.
3. **Immutable Governance Audit Ledger**: Tamper-proof logging of proposed actions, policy evaluation proofs, approval signatures, and execution receipts.
4. **Credential Vault & Brokering Service**: Centralized token rotation and secret injection.

---

## Deliverable A: Eve Capability Inventory

| Capability | Evidence (Source / Spec) | Relay Relevance | Confidence |
| :--- | :--- | :--- | :--- |
| **Pre-Execution Tool Interception** | `packages/eve/src/harness/tools.ts:353`<br>`packages/eve/src/approval/definition.ts` | **Critical**: Primary insertion point for Relay deterministic authorization before any tool `execute()` or sandbox command runs. | **HIGH** |
| **Durable Pause & Resume (HITL)** | `packages/eve/src/execution/turn-workflow.ts:77`<br>`docs/tools/human-in-the-loop.md` | **Critical**: Allows Relay to park Eve turns during multi-party approval workflows and resume via standard `inputResponses`. | **HIGH** |
| **Structured Action Streaming** | `packages/eve/src/protocol/message.ts`<br>`docs/concepts/sessions-runs-and-streaming.md` | **High**: Real-time observability of `actions.requested`, `action.result`, and tool inputs for Relay audit telemetry. | **HIGH** |
| **Sandbox Execution & Isolation** | `packages/eve/src/sandbox/`<br>`docs/sandbox.mdx` | **High**: Isolates risky agent commands; Relay can govern both high-level tools and low-level sandbox bash execution. | **HIGH** |
| **Turn Cancellation & Steering** | `packages/eve/src/execution/turn-cancellation-control.ts`<br>`POST /eve/v1/session/:id/cancel` | **Medium**: Relay can terminate or steer rogue agent executions mid-flight upon policy violation. | **HIGH** |
| **Subagent Task Delegation** | `packages/eve/src/subagents/`<br>`docs/subagents/index.mdx` | **High**: Relay must track subagent lineage, ensuring authority boundaries and child-session governance. | **HIGH** |
| **Observe-Only Event Hooks** | `packages/eve/src/runtime/hooks/`<br>`docs/guides/hooks.md` | **Medium**: Suitable for passive audit streaming to Relay, but cannot be used for synchronous blocking. | **HIGH** |
| **Durable State Storage (`defineState`)** | `packages/eve/src/execution/durable-session-store.ts` | **Low**: Session-local storage. Relay should not store governance policies inside Eve session state. | **HIGH** |
| **Model Call Batching (`modelCallsPerStep`)** | `packages/eve/src/execution/model-call-batching.ts`<br>`agent-config.md` | **Warning / Risk**: Experimental batching merges multiple actions into one step, complicating step-level authorization replay. | **HIGH** |

---

## Deliverable B: Execution & Governance Lifecycle Diagram

The following diagram illustrates the complete execution lifecycle of an Eve turn and how Relay inserts deterministic authorization and governance at key boundaries:

```mermaid
sequenceDiagram
    autonumber
    actor User as Client / User
    participant Channel as Ingress Channel (HTTP/Slack)
    participant RelayGW as Relay Ingress Gateway
    participant EveWorkflow as Eve Turn Workflow (App Runtime)
    participant Model as LLM / AI Gateway
    participant RelayPEP as Relay Policy Engine (PEP/PDP)
    participant Tool as Tool Executor / Sandbox

    User->>Channel: Send message
    Channel->>RelayGW: Inbound payload
    RelayGW->>EveWorkflow: POST /eve/v1/session/:id (Auth verified)
    
    rect rgb(240, 248, 255)
        note over EveWorkflow,Model: Durable Step Initialization
        EveWorkflow->>Model: Call LLM with instructions & tools
        Model-->>EveWorkflow: Emit tool_call (e.g. refund_charge, bash)
        EveWorkflow-->>User: Stream `actions.requested` event
    end

    rect rgb(255, 245, 238)
        note over EveWorkflow,RelayPEP: Pre-Execution Interception Point
        EveWorkflow->>RelayPEP: Evaluate `approval` policy(ctx, toolInput, callId)
        alt Policy = ALLOW
            RelayPEP-->>EveWorkflow: Return { type: "approved" }
        alt Policy = DENY
            RelayPEP-->>EveWorkflow: Return { type: "denied", reason: "Policy violation" }
            EveWorkflow-->>Model: Inject Denial Result (Tool NOT executed)
        alt Policy = REQUIRE_APPROVAL (Four-Eyes / Multi-Party)
            RelayPEP-->>EveWorkflow: Return "user-approval"
            EveWorkflow-->>User: Emit `input.requested` (requestId: req_123)
            note over EveWorkflow: Workflow Suspends (session.waiting)<br/>Zero compute consumed
            User->>RelayPEP: Reviewers submit signed approvals
            RelayPEP->>EveWorkflow: POST /eve/v1/session/:id { inputResponses: [{ req_123, "approve" }] }
            note over EveWorkflow: Workflow Resumes from Checkpoint
        end
    end

    rect rgb(245, 255, 245)
        note over EveWorkflow,Tool: Governed Execution
        EveWorkflow->>Tool: execute(input, ctx) / Sandbox run
        Tool-->>EveWorkflow: Output / Result
        EveWorkflow-->>User: Stream `action.result` event
        EveWorkflow->>RelayGW: Post Execution Audit Record
    end

    EveWorkflow->>Model: Next turn step (pass tool result)
    Model-->>EveWorkflow: Final assistant message
    EveWorkflow-->>User: Stream `message.completed` & `session.waiting`
```

---

## Deliverable C: Technical Integration Points

Relay can integrate with Eve across four well-defined architectural boundaries:

```
+-----------------------------------------------------------------------------------+
|                                  RELAY CONTROL PLANE                               |
|   +-----------------------+  +-----------------------+  +-----------------------+  |
|   | Policy Decision (PDP) |  | Multi-Party Approvals |  | Immutable Audit Log   |  |
|   +-----------------------+  +-----------------------+  +-----------------------+  |
+---------------------------------------^-------------------------------------------+
                                        | (REST / gRPC / SDK)
+---------------------------------------v-------------------------------------------+
|                          VERCEL EVE AGENT RUNTIME                                  |
|                                                                                   |
|  [Insertion Point 1: Ingress Gateway]                                              |
|  HTTP / Channel Request ---> [ Relay Ingress Guard / Token Verification ]          |
|                                     |                                             |
|  [Insertion Point 2: Pre-Execution Policy Adapter]                                |
|  Tool Call Proposed -------> [ Relay Approval Policy (`approval: policyFn`) ]      |
|                                     | (Allow / Deny / Suspend)                     |
|  [Insertion Point 3: Execution Wrapper]                                           |
|  Tool Execution -----------> [ Relay Governed Tool Executor (`execute: wrapFn`) ]  |
|                                     |                                             |
|  [Insertion Point 4: Telemetry & Audit Hooks]                                     |
|  Stream Events ------------> [ Relay Event Hook (`agent/hooks/relay-audit.ts`) ]  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### Insertion Point 1: Pre-Execution Approval Policy Adapter (`approval`)
Every authored tool or connection tool in Eve accepts an `approval` field implementing `ApprovalPolicy`:
```ts
// agent/lib/relay-policy-adapter.ts
import type { ApprovalContext, ApprovalStatus } from "eve/tools/approval";

export function createRelayApprovalAdapter(relayClient: RelayClient) {
  return async (ctx: ApprovalContext): Promise<ApprovalStatus> => {
    const decision = await relayClient.evaluateAction({
      sessionId: ctx.session.id,
      turnId: ctx.session.turn.id,
      callId: ctx.callId,
      toolName: ctx.toolName,
      toolInput: ctx.toolInput,
      principal: ctx.session.auth.current,
      initiator: ctx.session.auth.initiator,
    });

    if (decision.status === "DENY") {
      return { type: "denied", reason: decision.reason };
    }
    if (decision.status === "REQUIRE_APPROVAL") {
      return "user-approval"; // Parks Eve workflow via Workflow SDK
    }
    return "approved";
  };
}
```

### Insertion Point 2: Governed Tool Executor (`defineTool`)
Wrap tool execution to pass through Relay execution middleware for telemetry, parameter sanitization, and idempotency key injection:
```ts
// agent/tools/transfer-funds.ts
import { defineTool } from "eve/tools";
import { z } from "zod";
import { relayPolicy, relayExecute } from "../lib/relay";

export default defineTool({
  description: "Transfer money to destination account.",
  inputSchema: z.object({ accountId: z.string(), amount: z.number() }),
  approval: relayPolicy("payments:transfer"),
  execute: (input, ctx) => relayExecute("payments:transfer", input, ctx, async () => {
    return await executePaymentTransfer(input);
  }),
});
```

### Insertion Point 3: HTTP Session Ingress & Resume Controller
Relay sits in front of Eve's HTTP route (`POST /eve/v1/session/:id`) to:
1. Validate client JWTs / tenant tenancy.
2. Intercept `inputResponses` resolving pending approvals.
3. Validate that the approver has legitimate authority in Relay's PDP before forwarding the resume payload to Eve.

### Insertion Point 4: Stream Event Hook for Audit Logging
Use Eve's `agent/hooks/` mechanism to stream full execution traces into Relay's audit log:
```ts
// agent/hooks/relay-audit.ts
import { defineHook } from "eve/hooks";
import { relayAuditClient } from "../lib/relay";

export default defineHook({
  events: {
    async "*"(event, ctx) {
      await relayAuditClient.recordEvent({
        sessionId: ctx.session.id,
        eventId: event.meta.id,
        timestamp: event.meta.at,
        type: event.type,
        data: "data" in event ? event.data : null,
      });
    },
  },
});
```

---

## Deliverable D: Dependency-Risk Assessment

| Dependency Component | Risk Level | Rationale & Mitigation |
| :--- | :---: | :--- |
| **Vercel Eve Framework (`eve`)** | **MEDIUM** | Currently in Public Beta. High release velocity, breaking changes possible across beta lines. **Mitigation**: Wrap Eve tool definitions, session routes, and policy adapters behind Relay abstractions. |
| **Workflow SDK (`@workflow/core`)** | **MEDIUM** | Under active specification. Vendored / protocol pinned to `5.0.0-beta` in Eve. **Mitigation**: Treat workflow state as Eve-internal; maintain separate Relay governance state in PostgreSQL. |
| **Vercel AI SDK 7 (`ai`)** | **LOW** | Industry standard TypeScript library for LLM orchestration. Well-typed contracts for `ToolLoopAgent`, `ModelMessage`, and tools. |
| **Vercel Sandbox / MicroVMs** | **MEDIUM** | Platform lock-in risk if coupling tightly to Vercel hosted sandboxes. **Mitigation**: Use Eve's pluggable `SandboxBackend` interface or default to Docker/container runner for self-hosted instances. |
| **Nitro HTTP Server Layer** | **LOW** | Mature, standard web server foundation used across modern JS frameworks. |
| **Experimental APIs (`modelCallsPerStep`)** | **HIGH** | Batching multiple model and tool calls into single Workflow steps breaks the 1:1 action-to-checkpoint guarantee required for reliable governance replay. **Mitigation**: Forbid `experimental.workflow.modelCallsPerStep` in Relay-managed Eve deployments. |

---

## Deliverable E: Strategic Architecture Recommendations

### 1. What Relay SHOULD Use Eve For
* **Durable Agent Loop**: Eve provides a first-class, battle-tested agent loop with built-in checkpointing, conversation history compaction, prompt caching, and transient failure recovery.
* **Sandbox Environment**: Eve's dual-tier isolation (App Runtime vs. Sandbox microVM/Docker) is ideal for safely running untrusted tools, bash scripts, and file manipulations.
* **Native Inbound/Outbound Channels**: Leveraging Eve's built-in platform channels (Slack, Discord, Linear, GitHub, HTTP) for receiving user commands and streaming interactive UI responses.

### 2. What Relay Should NOT Delegate to Eve
* **Policy Authoring & Decision (PDP)**: Never store enterprise access control rules, tenant separation logic, or risk budgets in Eve instructions or prompt context.
* **Approval State & Authority Records**: Do not rely on Eve's internal session state (`eve.runtime.hitl.approvedTools`) as a legal or security proof of authorization. Eve's session state is mutable and tied to a single session conversation.
* **Secret Storage**: Do not pass raw API keys or administrative credentials to Eve sessions or sandbox environments.

### 3. What Must Be Abstracted Behind Relay Adapters
* **`RelayPolicyAdapter`**: An abstraction over Eve's `ApprovalPolicy` function so that changing the agent framework does not impact Relay policy rules.
* **`RelaySessionProxy`**: An API gateway proxying `/eve/v1/session` to decouple front-end clients from raw Eve engine routes.
* **`RelayToolDefinition`**: An authoring wrapper that emits both Eve-compatible tools and Relay policy metadata.

### 4. What Must Remain Relay-Owned
* **Deterministic Policy Engine**: Evaluating ABAC/RBAC rules, spending limits, data access policies, and separation-of-duty constraints.
* **Multi-Party Approval Workflow Engine**: Managing human approval queues, escalation paths, quorum consensus, and signed authorization tokens.
* **Immutable Audit Ledger**: Cryptographically verifiable logs of all agent proposals, authorization decisions, approval events, and execution outcomes.

---

## Conclusion

Vercel Eve is a well-engineered, durable agent framework that fits cleanly into Relay's architectural vision. By leveraging Eve's `approval` policy hook and durable pause-and-resume workflow capabilities, Relay can act as the **external deterministic governance layer** that intercepts, evaluates, approves, and audits agent actions without having to reinvent the underlying LLM prompt loop or sandboxing infrastructure.
