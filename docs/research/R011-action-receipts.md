# R011: Governed Action Receipts — Evidence, Provenance, and Non-Repudiation for AI Agent Actions

**Status:** Research & Architecture Proposal  
**Document ID:** R011  
**Target:** Relay Core Architecture  
**Author:** AI Systems Architecture & Security Research  

---

## 1. Executive Summary & Epistemic Assessment

### 1.1 The Core Hypothesis Under Review
**Hypothesis:** Relay can provide trustworthy, tamper-evident, and non-repudiable evidence for governed AI agent actions by packaging execution metadata into an **in-toto / SLSA-style Governed Action Receipt Envelope** signed via **DSSE (Dead Simple Signing Envelope)** and committed to an append-only transparency log.

### 1.2 Epistemic Assessment & Ground Truth Verdict
We evaluate this hypothesis with high skepticism against real-world distributed systems, cryptographic threat models, and software provenance architectures:

```
+──────────────────────────────────────────────────────────────────────────────────────────────────+
|                                    EVIDENTIARY VERDICT MATRIX                                    |
+───────────────────────────────────┬──────────────┬───────────────────────────────────────────────+
| Claim / Architectural Concept     | Status       | Evidentiary Basis & Rationale                 |
+───────────────────────────────────┼──────────────┼───────────────────────────────────────────────+
| 1. in-toto Statement v1.0 + DSSE  | [CONFIRMED]  | Perfect match for envelope structure. Reuses  |
|    as receipt envelope wire format|              | standard tooling; avoids bespoke protocols.   |
+───────────────────────────────────┼──────────────┼───────────────────────────────────────────────+
| 2. Relay can cryptographically    | [CONFIRMED]  | Relay controls the PEP/PDP and can sign the   |
|    prove Authorization & Dispatch |              | decision, parameters, and JIT ticket.         |
+───────────────────────────────────┼──────────────┼───────────────────────────────────────────────+
| 3. Relay can cryptographically    | [CONTRADICTED| Relay is a proxy; it can only observe and sign|
|    prove Resource Mutation        |  / FALLACY]  | the target API's *response*. Actual state     |
|                                   |              | mutation inside a third-party DB is an        |
|                                   |              | *observation*, not a cryptographic proof.     |
+───────────────────────────────────┼──────────────┼───────────────────────────────────────────────+
| 4. Heavyweight Sigstore/Rekor     | [REJECTED    | Running full Trillian/Rekor clusters for      |
|    infrastructure required for MVP|  FOR MVP]    | sub-second agent tool calls adds massive ops  |
|                                   |              | friction. Local hash-chains + Ed25519 DSSE    |
|                                   |              | suffice for MVP; Rekor is an enterprise tier. |
+───────────────────────────────────┼──────────────┼───────────────────────────────────────────────+
| 5. Action Receipt Dynamic Linking | [CONFIRMED]  | PSD2-style dynamic linking (binding human     |
|    prevents TOCTOU & replay       |              | approvals to SHA-256 of canonical params)     |
|                                   |              | mathematically prevents parameter tampering.  |
+───────────────────────────────────┼──────────────┼───────────────────────────────────────────────+
```

### 1.3 Key Architectural Findings
1. **Reuse, Don't Reinvent:** Standardize Relay Action Receipts on **in-toto Attestation Statement v1.0** formatted with **DSSE (RFC 9598)**. Do not invent a bespoke receipt schema.
2. **Distinguish Cryptographic Proofs from Observational Claims:**
   * **Cryptographic Proofs:** What Relay *itself* generated, evaluated, and signed (e.g., Policy evaluation outcome, Canonical parameter hash, Approver digital signature, Execution nonce).
   * **Attested Observations:** What Relay observed from external systems (e.g., HTTP status code 200, DB rows affected reported by driver, LLM prompt tokens).
3. **No Cryptographic Over-Engineering for MVP:** A single Ed25519 keypair per Relay PEP node, wrapping canonical JSON (RFC 8785) in DSSE envelopes and chaining hashes in an append-only SQLite/Postgres table, achieves 99% of security goals without complex PKI infrastructure.

---

## 2. Comparative Analysis of Established Standards

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   STANDARDS COMPARISON FOR RECEIPTS                              │
├───────────────────────┬───────────────────────────────────────────┬──────────────────────────────┤
│ Standard / Technology │ Core Mechanism                            │ Applicability to Relay       │
├───────────────────────┼───────────────────────────────────────────┼──────────────────────────────┤
│ in-toto Statement v1.0│ Envelope with _type, subject[],           │ Primary Schema Foundation.   │
│                       │ predicateType, and predicate payload.     │ Industry standard for supply │
│                       │                                           │ chain and runtime evidence.  │
├───────────────────────┼───────────────────────────────────────────┼──────────────────────────────┤
│ DSSE (RFC 9598)       │ Dead Simple Signing Envelope:             │ Primary Wire Signing Format. │
│                       │ payloadType, payload (b64), signatures[]. │ Prevents type-confusion and  │
│                       │                                           │ canonicalization exploits.   │
├───────────────────────┼───────────────────────────────────────────┼──────────────────────────────┤
│ SLSA Provenance v1.0  │ Predicate format for software builds:     │ Architectural Metaphor.      │
│                       │ buildDefinition, runDetails, builder.     │ Adapt concept to Agent Run.  │
├───────────────────────┼───────────────────────────────────────────┼──────────────────────────────┤
│ Sigstore (Cosign/     │ Keyless signing via OIDC (Fulcio) +       │ Enterprise / Tier-2 Target.  │
│ Rekor / TUF)          │ public Merkle transparency log (Rekor).   │ Excellent for public logs;   │
│                       │                                           │ overkill for local sidecars. │
├───────────────────────┼───────────────────────────────────────────┼──────────────────────────────┤
│ OpenTelemetry (OTel)  │ Distributed tracing via W3C TraceContext  │ Telemetry Integration.       │
│                       │ (traceparent, tracestate, spans, events). │ Carry trace_id in receipt.   │
├───────────────────────┼───────────────────────────────────────────┼──────────────────────────────┤
│ W3C PROV-DM           │ Conceptual provenance model: Entity,      │ Lineage Formalism. Maps      │
│                       │ Activity, Agent, Derivation, Delegation.  │ Human -> Agent -> Subagent.  │
├───────────────────────┼───────────────────────────────────────────┼──────────────────────────────┤
│ SCITT (IETF WG)       │ Supply Chain Integrity, Transparency, and │ Emerging Transparency Standard│
│                       │ Trust: Signed Statements on Ledgers.      │ Long-term enterprise target. │
└───────────────────────┴───────────────────────────────────────────┴──────────────────────────────┘
```

### 2.1 in-toto Attestation Framework & DSSE (RFC 9598)
* **in-toto Framework:** Separates the *Envelope* (signature container) from the *Statement* (metadata binding subjects to a predicate) from the *Predicate* (domain-specific assertion payload).
* **DSSE (Dead Simple Signing Envelope):** Solves the cryptographic vulnerability of signature-wrapping formats where attackers mutate MIME types or payload encodings. DSSE signs the exact tuple:
  $$\text{Pre-Auth-Encoding} = \text{"DSSEv1"} \mathbin{\Vert} \text{len}(\text{payloadType}) \mathbin{\Vert} \text{payloadType} \mathbin{\Vert} \text{len}(\text{payload}) \mathbin{\Vert} \text{payload}$$
* **Relay Fit:** Using DSSE with payload type `application/vnd.in-toto+json` allows any standard in-toto validator (Cosign, in-toto CLI, enterprise verification engines) to verify Relay Action Receipts out of the box.

### 2.2 SLSA Provenance v1.0 vs. Agent Action Provenance
* **SLSA Provenance:** Designed for *static build pipelines* ($\text{Source Code} \to \text{Compiler/Builder} \to \text{Binary Artifact}$).
* **The Agent Reality:** An agent workflow is a *dynamic, interactive execution loop* ($\text{User Goal} \to \text{Agent Prompt} \to \text{Policy Decision} \to \text{Step-up Approval} \to \text{Tool Invocation} \to \text{Downstream Effect}$).
* **Conclusion:** Relay adopts the *structural concepts* of SLSA (verifiable execution context, external builder/runner identity, resolved dependencies) but defines an agent-specific predicate: `https://relay.dev/attestation/action-receipt/v1`.

### 2.3 OpenTelemetry (OTel) & W3C Trace Context
* **Role:** OTel is an observability and metrics standard, not a cryptographic non-repudiation standard. OTel spans are mutable, unauthenticated, and commonly sampled or dropped in high-volume environments.
* **Synergy with Relay:** Relay embeds the W3C `traceparent` (`trace_id` and `span_id`) directly into the cryptographic receipt. This enables cross-referencing: SIEM and APM dashboards query OTel for latency and logs, while compliance and legal discovery use the cryptographic Action Receipt for audit and non-repudiation.

---

## 3. The Agent Action Lifecycle: What Can Actually Be Proven?

A complete governed agent action flows through seven stages. We model each stage and identify what is **Cryptographically Provable**, what is an **Attested Observation**, and what is **Unprovable**.

```
  +--------------------+
  | 1. Agent Request   |  Agent emits ActionProposal (Tool, Parameters, Intent)
  +--------------------+
            |
            v
  +--------------------+
  | 2. Authorization   |  Relay PDP evaluates Cedar Policy -> ALLOW / REQUIRE_APPROVAL
  +--------------------+
            |
            v
  +--------------------+
  | 3. Credential Mint |  Relay PEP fetches short-lived JIT target token
  +--------------------+
            |
            v
  +--------------------+
  | 4. Tool Dispatch   |  Relay PEP transmits payload to target API / Driver
  +--------------------+
            |
            v
  +--------------------+
  | 5. Tool Result     |  Target returns response code & body to PEP
  +--------------------+
            |
            v
  +--------------------+
  | 6. Resource State  |  Target database / service applies mutation internally
  +--------------------+
            |
            v
  +--------------------+
  | 7. Verification    |  Audit log commit, Merkle chaining, SIEM ingestion
  +--------------------+
```

### Stage-by-Stage Proof Breakdown

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              STAGE-BY-STAGE EVIDENCE CAPABILITY MATRIX                             │
├────────────────────┬───────────────────────────────┬───────────────────────────────────────────────┤
│ Lifecycle Stage    │ What Can Be Cryptographically │ What Is Merely an Attested Observation        │
│                    │ Proven (Non-Repudiable)       │ (Relay / Target Assertion)                    │
├────────────────────┼───────────────────────────────┼───────────────────────────────────────────────┤
│ 1. Agent Request   │ • Proposal payload hash       │ • Agent's internal "thought process" / LLM    │
│                    │ • Session & Step Nonce        │   reasoning (Natural language is unprovable). │
│                    │ • DPoP proof of possession    │ • Whether the agent was "truly aligned".      │
├────────────────────┼───────────────────────────────┼───────────────────────────────────────────────┤
│ 2. Authorization   │ • Exact Cedar policy AST hash │ • Current ambient network health.             │
│    Decision        │ • PDP decision output         │ • External context values fetched from APIs   │
│                    │ • Approver digital signature  │   (unless those APIs provide signed claims).  │
│                    │   over ActionHash (if step-up)│                                               │
├────────────────────┼───────────────────────────────┼───────────────────────────────────────────────┤
│ 3. Credential      │ • JIT token thumbprint / ID   │ • Internal secret storage enclave state.      │
│    Issuance        │ • Downstream STS exchange sig │                                               │
├────────────────────┼───────────────────────────────┼───────────────────────────────────────────────┤
│ 4. Tool Dispatch   │ • Exact bytes sent on wire    │ • That no physical MITM occurred on an        │
│                    │ • TLS certificate of target   │   unauthenticated local socket.               │
│                    │ • Timestamp of dispatch       │                                               │
├────────────────────┼───────────────────────────────┼───────────────────────────────────────────────┤
│ 5. Tool Result     │ • Exact raw response hash     │ • Downstream execution latency on target host.│
│                    │ • HTTP status code / Error obj│                                               │
├────────────────────┼───────────────────────────────┼───────────────────────────────────────────────┤
│ 6. Resource        │ ❌ NOTHING (Unless target DB   │ • "Rows affected = 1" (Reported by driver).   │
│    Mutation        │    provides signed state tree │ • Target system state changes. Relay is an    │
│                    │    e.g. QLDB / Immutable Log) │   external proxy and cannot prove target disk.│
├────────────────────┼───────────────────────────────┼───────────────────────────────────────────────┤
│ 7. Verification    │ • Merkle inclusion proof      │ • That the auditor verified the receipt       │
│    & Ledger        │ • Cryptographic hash chain    │   promptly.                                   │
│                    │ • Relay PEP signature on DSSE │                                               │
└────────────────────┴───────────────────────────────┴───────────────────────────────────────────────┘
```

---

## 4. Systematic Answers to the 12 Research Questions

### Q1: What should a Relay receipt contain?
A Relay Action Receipt must contain four fundamental sections wrapped in an in-toto Statement:
1. **Subject:** Identifiers and hashes of the entities acted upon (Target Resource URNs, Input parameter hashes, Output artifact hashes).
2. **Invocation:** The exact tool name, canonical input arguments (RFC 8785 JSON Canonicalization Scheme), execution step index, session ID, and W3C trace context.
3. **Authorization & Governance:** Policy ID and SHA-256 version hash, PDP decision (`ALLOW` / `APPROVED`), evaluation timestamp, and any attached **Approval Receipts** (approver ID, timestamp, digital signature).
4. **Execution & Environment:** PEP node identity, execution timestamps (dispatched, completed), exit status (success/failure/error code), response payload hash, and previous receipt hash (chain link).

---

### Q2: What should be signed?
**The DSSE envelope signs the complete, canonicalized in-toto Statement.**
Specifically, signing covers:
* The Canonical Parameter Hash ($\text{SHA-256}(\text{CanonicalParams})$).
* The Authorization Record (Policy Hash + Decision).
* The Approver Signature (if human-in-the-loop escalation occurred).
* The Downstream Response Hash ($\text{SHA-256}(\text{RawResponse})$).
* The Execution Metadata (Timestamps, Step Index, Resource URN, Previous Receipt Hash).

---

### Q3: Who signs it?
Receipt generation involves a **Dual-Signer Hierarchy**:

1. **The Policy Enforcement Point (PEP) (Mandatory Signer):**
   * The Relay PEP node executing the action holds a private signing key (Ed25519) attested by its SPIFFE identity. It signs the final Action Receipt envelope upon action completion.
2. **The Human Approver / Supervisor (Conditional Co-Signer):**
   * When an action requires escalation (`REQUIRE_APPROVAL`), the human approver signs an `ApprovalReceipt` over the `ActionHash` using WebAuthn/Passkey, client certificate, or OIDC-backed signature. This signature is embedded verbatim inside the final receipt signed by the PEP.

---

### Q4: Can receipts be chained?
**Yes.** Receipts form a **Session Hash Chain (Directed Acyclic Graph)**:
$$\text{ReceiptHash}_n = \text{SHA-256}(\text{CanonicalStatement}_n \mathbin{\Vert} \text{ReceiptHash}_{n-1})$$

* **Genesis Link:** The first receipt in a session ($\text{Step } 0$) sets $\text{ReceiptHash}_0 = \text{SHA-256}(\text{SessionGenesisToken} \mathbin{\Vert} \text{HumanGoalPrompt})$.
* **Fork / Fan-out:** When subagents spawn concurrently, the DAG branches. Subagent genesis receipts reference the parent agent's spawning receipt hash.
* **Integrity:** Tampering with, reordering, or dropping any step breaks the cryptographic hash chain for the entire session.

---

### Q5: How should parent/child agent lineage work?
Lineage is modeled using **W3C PROV-DM relationships** represented within the receipt:
* `prov:wasAssociatedWith`: The Agent Instance SPIFFE ID executing this step.
* `prov:actedOnBehalfOf`: The Parent Agent Instance ID (and recursively up to the root Human Principal).
* `prov:wasDerivedFrom`: The parent task/step ID and the parent receipt hash.

```
[Human: Alice] 
      │ (initiates)
      ▼
[Agent: LeadOrchestrator] ── (Receipt #1: spawns child)
      │
      ├───────────────────────────────┐
      ▼ (delegates subtask)           ▼ (delegates subtask)
[Agent: SubagentA (SQL)]        [Agent: SubagentB (DocWriter)]
  (Receipt #2a: query db)         (Receipt #2b: write markdown)
  parent_receipt: #1              parent_receipt: #1
```

---

### Q6: How should approvals appear?
Approvals must appear as an **Embedded Cryptographic Approval Block** inside the governance section of the predicate:

```json
"approval": {
  "approval_type": "human_interactive",
  "decision": "APPROVED",
  "action_hash": "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
  "approver": {
    "type": "human_oidc",
    "id": "usr_alice@example.com",
    "issuer": "https://auth.enterprise.com"
  },
  "timestamp": "2026-09-12T18:30:00Z",
  "signature": {
    "key_id": "webauthn:credential-9988",
    "algorithm": "ES256",
    "sig": "MEQCIDz..."
  },
  "justification": "Approved schema migration for staging after reviewing index diff."
}
```

---

### Q7: How should policy versioning appear?
Policy versioning must **never rely on mutable names** (e.g. `policy.cedar` or `v1`). 
It must record:
1. **Policy Set URN:** `urn:relay:policy:rds-staging-rules`
2. **Policy AST Hash:** Cryptographic digest of the compiled Cedar policy AST:
   $$\text{PolicyHash} = \text{SHA-256}(\text{CanonicalPolicySourceOrAST})$$
3. **Evaluation Outcome Details:** Policy rule IDs evaluated, permit rule matched, and forbid rules tested.

---

### Q8: How should tool identity appear?
Tools must be identified by their **Immutable Tool Declaration Digest** and **Execution Target**:
* **Tool URN:** `urn:relay:tool:postgres:apply_migration`
* **Tool Specification Digest:** `SHA-256(ToolJSONSchema + ImplementationContainerImageDigest)`
* **Endpoint / Target Transport:** `mcp+stdio:///usr/local/bin/pg-mcp` or `https://internal-api.corp/v1/tools`
* **Server Attestation:** SPIFFE SVID or TLS certificate hash of the tool server (if remote).

---

### Q9: Can Relay distinguish authorization from successful execution?
**Yes, and Relay MUST explicitly decouple them in the receipt schema.**

An authorization decision and an execution outcome are distinct states with distinct failure domains:
* **State 1: Authorized and Executed Successfully** (`auth_status: "ALLOWED"`, `exec_status: "SUCCESS"`, `exit_code: 0`).
* **State 2: Authorized but Execution Failed** (`auth_status: "ALLOWED"`, `exec_status: "EXECUTION_ERROR"`, `exit_code: 1`, `error: "Postgres Connection Refused"`).
* **State 3: Denied by Policy (Never Executed)** (`auth_status: "DENIED"`, `exec_status: "NOT_EXECUTED"`, `exit_code: null`).
* **State 4: Timed Out in Approval (Never Executed)** (`auth_status: "APPROVAL_TIMEOUT"`, `exec_status: "NOT_EXECUTED"`).

---

### Q10: What claims require cryptographic evidence?
The following claims **require cryptographic evidence**:
1. **Identity of the executing Relay node** (Signed by PEP node private key).
2. **Integrity of the proposed action parameters** (SHA-256 digest of canonical RFC 8785 JSON).
3. **Policy Authorization** (Digest of active policy AST + signed PDP evaluation).
4. **Human Step-Up Approval** (Digital signature over `ActionHash`).
5. **Session Step Sequence** (Hash chain link to previous receipt).
6. **Integrity of the Downstream API Response** (SHA-256 digest of raw response bytes).

---

### Q11: What claims can only be recorded as observations?
The following claims **are observations** and must be documented as such without false claims of cryptographic proof:
1. **Actual internal resource state changes** (Relay observes HTTP 200 / SQL OK; Relay cannot prove the storage engine flushed to disk).
2. **Agent's subjective natural language intent** (The text explanation generated by the LLM).
3. **Downstream API service health / latency metrics**.
4. **External context data** fetched from third-party APIs during evaluation (unless those third parties return signed verifiable credentials).

---

### Q12: What existing standards should Relay reuse?
Relay strictly reuses existing, battle-tested standards:

```
┌───────────────────────────────────────┬────────────────────────────────────────────┐
│ Layer                                 │ Standard Reused                            │
├───────────────────────────────────────┼────────────────────────────────────────────┤
│ 1. Envelope Container & Signatures    │ DSSE (RFC 9598)                            │
│ 2. Attestation Schema & Structure     │ in-toto Attestation Statement v1.0         │
│ 3. JSON Canonicalization              │ RFC 8785 (JSON Canonicalization Scheme/JCS)│
│ 4. Distributed Tracing Context        │ W3C Trace Context (traceparent)            │
│ 5. Provenance Formalism               │ W3C PROV-DM                                │
│ 6. Cryptographic Signatures           │ Ed25519 (RFC 8032) / ECDSA P-256 (RFC 6979)│
│ 7. Transparency Ledger (Enterprise)   │ RFC 6962 / Sigstore Rekor                  │
└───────────────────────────────────────┴────────────────────────────────────────────┘
```

---

## 5. The Governed Action Receipt Architecture & Specification

```
+====================================================================================================+
|                                  GOVERNED ACTION RECEIPT ARCHITECTURE                              |
+====================================================================================================+

   [ Agent Sandbox ]
           |
           | 1. ActionProposal (Tool, Canonical JSON Params)
           v
   +------------------------------------------------------------------------------------------------+
   | RELAY POLICY ENFORCEMENT POINT (PEP)                                                           |
   |                                                                                                |
   |   [ Step A: Canonicalize Params (RFC 8785) & Compute ActionHash ]                              |
   |                                                                                                |
   |   [ Step B: Query Cedar PDP ]                                                                  |
   |          │                                                                                     |
   |          ├─ ALLOW ───────────────────────┐                                                     |
   |          ├─ REQUIRE_APPROVAL ──> [ Escalate to Approver UI ] ──> [ Approver Signs ActionHash ] |
   |          └─ DENY ──────────────> [ Generate Denied Receipt & Terminate ]                       |
   |                                          │                                                     |
   |   [ Step C: Execute Tool Call via JIT Token ]                                                  |
   |          │                                                                                     |
   |          ▼                                                                                     |
   |   [ External Tool / API ] ──> Returns Raw Response                                              |
   |                                          │                                                     |
   |   [ Step D: Assemble in-toto Statement v1.0 ]                                                  |
   |   [ Step E: Compute Chain Hash (ParentReceiptHash + CurrentStatementHash) ]                    |
   |   [ Step F: Wrap in DSSE Envelope & Sign with PEP Ed25519 Key ]                                |
   +------------------------------------------------------------------------------------------------+
           |
           ├───────────────────────────────────────┬────────────────────────────────────────┐
           ▼                                       ▼                                        ▼
   [ Local SQLite / PG Ledger ]            [ OpenTelemetry ]                      [ Enterprise Rekor Log ]
   (Append-Only Hash Chain)               (Span Link / Trace)                    (Merkle Inclusion Proof)
```

---

### 5.1 Candidate Receipt Schema (in-toto Statement v1.0)

A Governed Action Receipt is represented as an **in-toto Statement v1.0** with predicate type `https://relay.dev/attestation/action-receipt/v1`.

#### Complete Concrete JSON Example (Production-Grade)

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "urn:relay:postgres:staging-cluster:db/analytics",
      "digest": {
        "action_payload": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "target_resource": "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
      }
    }
  ],
  "predicateType": "https://relay.dev/attestation/action-receipt/v1",
  "predicate": {
    "receipt_id": "rcpt_01J7K8M9N0P1Q2R3S4T5U6V7W8",
    "session": {
      "session_id": "ses_01J7K8A1B2C3D4E5F6G7H8J9K0",
      "step_index": 4,
      "parent_receipt_hash": "sha256:9a3b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b",
      "root_goal_hash": "sha256:112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
    },
    "trace": {
      "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
      "span_id": "00f067aa0ba902b7"
    },
    "actor": {
      "agent_template_id": "spiffe://relay.internal/agent-template/devops-migrator/v1.2",
      "agent_instance_id": "spiffe://relay.internal/agent-instance/inst-9876",
      "parent_agent_id": "spiffe://relay.internal/agent-instance/orchestrator-1234",
      "root_human_principal": {
        "id": "usr_alice@example.com",
        "auth_issuer": "https://auth.enterprise.com",
        "subject_token_hash": "sha256:aabbccdd..."
      }
    },
    "invocation": {
      "tool_name": "postgres.apply_migration",
      "tool_urn": "urn:relay:tool:builtin:postgres",
      "tool_definition_digest": "sha256:f1d2d3e4f5a6...",
      "parameters_canonical_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "parameters_preview": {
        "migration_file": "20260912_add_index.sql",
        "dry_run": false
      },
      "idempotency_key": "idemp_01J7K8M9N0_step4"
    },
    "authorization": {
      "decision": "APPROVED",
      "policy_id": "urn:relay:policy:rds-staging-rules",
      "policy_ast_hash": "sha256:7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d",
      "evaluator_node": "spiffe://relay.internal/pep/node-us-east-1a",
      "evaluated_at": "2026-09-12T18:29:55.120Z",
      "approval": {
        "approval_type": "human_interactive",
        "approver_id": "usr_bob_secops@example.com",
        "action_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "approved_at": "2026-09-12T18:30:00.000Z",
        "signature": {
          "key_id": "webauthn:credential-9988",
          "algorithm": "ES256",
          "sig": "MEQCIDz1...="
        },
        "justification": "Verified non-blocking index creation on staging table."
      }
    },
    "execution": {
      "pep_node_id": "spiffe://relay.internal/pep/node-us-east-1a",
      "dispatched_at": "2026-09-12T18:30:00.050Z",
      "completed_at": "2026-09-12T18:30:01.450Z",
      "duration_ms": 1400,
      "status": "SUCCESS",
      "exit_code": 0,
      "response_raw_hash": "sha256:8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677",
      "response_preview": {
        "rows_affected": 1,
        "execution_status": "CREATE INDEX CONCURRENTLY SUCCESSFUL"
      },
      "error": null
    }
  }
}
```

---

### 5.2 DSSE Wire Envelope Specification (RFC 9598)

The in-toto Statement above is wrapped inside a standard DSSE envelope.

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "eyJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YxIiwgInN1YmplY3QiOiBbLi4uXSwgInByZWRpY2F0ZVR5cGUiOiAiaHR0cHM6Ly9yZWxheS5kZXYvYXR0ZXN0YXRpb24vYWN0aW9uLXJlY2VpcHQvdjEiLCAicHJlZGljYXRlIjogey4uLn19",
  "signatures": [
    {
      "keyid": "spiffe://relay.internal/pep/node-us-east-1a#key-202609",
      "sig": "R3B2OW...base64_signature..."
    }
  ]
}
```

---

## 6. Security, Replay, and Tampering Analysis

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   THREAT MODEL & MITIGATION MATRIX                               │
├──────────────────────────┬─────────────────────────────┬─────────────────────────────────────────┤
│ Attack / Threat Vector   │ Mechanism                   │ Relay Receipt Countermeasure            │
├──────────────────────────┼─────────────────────────────┼─────────────────────────────────────────┤
│ 1. Parameter Tampering   │ Attacker alters parameters  │ Canonical JSON Hashing (RFC 8785) &     │
│    (TOCTOU)              │ between PDP approval and    │ Dynamic Linking: Execution aborts if    │
│                          │ execution dispatch.         │ SHA-256(DispatchedParams) != ActionHash.│
├──────────────────────────┼─────────────────────────────┼─────────────────────────────────────────┤
│ 2. Post-Hoc Audit        │ Malicious admin edits local │ Merkle Hash-Chaining: Modifying receipt │
│    Log Modification      │ SQLite audit table to hide  │ N breaks hash links for all subsequent  │
│                          │ unauthorized tool call.     │ receipts N+1..M.                        │
├──────────────────────────┼─────────────────────────────┼─────────────────────────────────────────┤
│ 3. Action Replay Attack  │ Attacker intercepts signed  │ Single-Use Monotonic Nonces &           │
│                          │ approval receipt and        │ Idempotency Key cache. PEP rejects      │
│                          │ replays it to rerun action. │ duplicate ActionHashes in a session.   │
├──────────────────────────┼─────────────────────────────┼─────────────────────────────────────────┤
│ 4. Approver Identity     │ Compromised agent forges a  │ Approver signature verified against     │
│    Spoofing              │ fake human approval record. │ enterprise IdP / WebAuthn public key;   │
│                          │                             │ unverified signatures fail PEP check.   │
├──────────────────────────┼─────────────────────────────┼─────────────────────────────────────────┤
│ 5. False State Claim     │ Downstream API returns 200  │ Receipts explicitly classify target     │
│    (Driver Deception)    │ but silently dropped write. │ response as an Observation, not a State │
│                          │                             │ Proof, preventing false legal claims.   │
└──────────────────────────┴─────────────────────────────┴─────────────────────────────────────────┘
```

---

## 7. Pragmatic Minimal MVP Receipt Design vs. Enterprise Full-Stack

To ensure Relay builds a production-ready system without operational paralysis, we define two tiers of receipt infrastructure:

```
+──────────────────────────────────────────────────────────────────────────────────────────────────+
|                                  MVP vs. ENTERPRISE ARCHITECTURE                                 |
+───────────────────────────────────┬──────────────────────────────┬───────────────────────────────+
| Dimension                         | Tier 0: Minimal Viable MVP   | Tier 1: Enterprise Production |
+───────────────────────────────────┼──────────────────────────────┼───────────────────────────────+
| Envelope Format                   | DSSE (RFC 9598)              | DSSE (RFC 9598)              |
| Schema Definition                 | in-toto Statement v1.0       | in-toto Statement v1.0       |
| Signing Mechanism                 | Local Node Ed25519 Keypair   | Cloud KMS / HashiCorp Vault  |
| Ledger / Storage                  | Local SQLite (Append-Only    | Distributed PostgreSQL +      |
|                                   | Hash-Chained Table)          | Sigstore Rekor Log           |
| Tracing Integration               | W3C traceparent embedded     | OpenTelemetry OTLP Exporter  |
| Human Approval Verification       | Signed JWT / WebAuthn PubKey | Enterprise OIDC / Passkeys   |
| Verification Tooling              | Lightweight CLI (`relay verify`)| in-toto CLI, Cosign, SIEM  |
+───────────────────────────────────┴──────────────────────────────┴───────────────────────────────+
```

### 7.1 Minimal MVP Implementation Blueprint
1. **Zero External Dependencies:** The MVP Relay PEP generates the in-toto Statement JSON, canonicalizes it with RFC 8785, signs it with a local Ed25519 key, and inserts it into an SQLite table:
   ```sql
   CREATE TABLE action_receipts (
       receipt_id TEXT PRIMARY KEY,
       session_id TEXT NOT NULL,
       step_index INTEGER NOT NULL,
       parent_receipt_hash TEXT NOT NULL,
       current_receipt_hash TEXT NOT NULL,
       dsse_envelope JSON NOT NULL,
       created_at TIMESTAMP NOT NULL,
       UNIQUE(session_id, step_index)
   );
   ```
2. **Verification CLI:** A simple verification utility walks the SQLite rows, re-computes the hash chain, verifies the Ed25519 signatures, and outputs a clean audit tree.

---

## 8. Summary Recommendations for Relay Core

1. **Adopt in-toto Statement v1.0 + DSSE (RFC 9598) as the Official Receipt Standard.** Do not write a custom format.
2. **Implement Parameter Canonicalization (RFC 8785 / JCS) Immediately.** All action proposals, policies, and approvals must compute SHA-256 over canonical JSON to eliminate whitespace/key-ordering ambiguities.
3. **Decouple Authorization Proof from Execution Observation.** Never claim that Relay "proves database mutation." Relay proves *Authorization, Parameter Integrity, and Dispatch*, while recording the target API's response as an attested observation.
4. **Use Hash-Chained Sessions for Replay & Tamper Resistance.** Bind every receipt to its predecessor via `parent_receipt_hash`.
5. **Start with the Minimal MVP Ledger.** Deploy local Ed25519 DSSE signing with SQLite hash chains before integrating complex transparency log infrastructure like Rekor.
