# R015: Final Architecture and Security Build Gate — Relay MVP

**Document ID:** `R015-build-gate`  
**Date:** September 2026  
**Status:** Complete / Final Decision Gate  
**Target:** Relay MVP Architecture & Security Specification  
**Reviewer:** Architecture & Security Gate Reviewer  
**Evidence Base:** `00-research-synthesis`, `R009` (Trust Boundaries), `R010` (JIT Credentials), `R011` (Action Receipts), `R012` (MCP Boundary), `R013` (Eve Boundary), `R014` (MVP Definition)

---

## Executive Summary & Build Gate Verdict

This document serves as the final adversarial security and architecture gate prior to the implementation of the Relay MVP. Its explicit mandate is to **stress-test, break, and validate** the proposed Relay MVP architecture against real-world execution environments, operating system boundaries, adversarial threat actors, and protocol limitations.

### The Working MVP Hypothesis Under Test
> *"Relay is a local-first Rust binary that acts as a zero-trust MCP security gateway and credential broker. Agents possess no ambient target credentials. Relay intercepts MCP tool calls, canonicalizes the request, evaluates deterministic AWS Cedar policies, obtains credentials just-in-time, executes the action, and produces signed governed-action evidence."*

---

# 1. Security Guarantee Evaluation

### The Proposed Guarantee:
> *"Even under complete prompt-injection compromise of the agent, the agent cannot obtain ambient credentials or execute an unauthorized state-mutating tool action."*

### Deconstructed Claim Evaluation Matrix

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   SECURITY GUARANTEE CLAIM EVALUATION                                  │
├──────┬─────────────────────────────────────────────────┬────────────────────────────┬──────────────────┤
│ ID   │ Sub-Claim Description                           │ Verdict Classification     │ Technical Reason │
├──────┼─────────────────────────────────────────────────┼────────────────────────────┼──────────────────┤
│ A    │ Agent cannot obtain ambient credentials.        │ PROVEN BY DESIGN           │ Credential absent│
│ B    │ Agent cannot bypass Relay.                      │ REQUIRES ADDITIONAL CONTROL│ Local net/proc   │
│ C    │ Agent cannot cause Relay to authorize unauth.   │ PROVEN BY DESIGN           │ Deterministic PDP│
│ D    │ Agent cannot exploit canonicalization diffs.    │ REQUIRES ADDITIONAL CONTROL│ Nested JSON text │
│ E    │ Agent cannot exploit tool-name ambiguity.       │ PROVEN BY DESIGN           │ Namespace prefix │
│ F    │ Agent cannot exploit resource-id ambiguity.     │ REQUIRES ADDITIONAL CONTROL│ Path/URI collapse│
│ G    │ Agent cannot replay an authorized action.       │ PROVEN BY DESIGN           │ Monotonic Nonces │
│ H    │ Agent cannot alter action post-evaluation.      │ PROVEN BY DESIGN           │ Single-binary AST│
│ I    │ Agent cannot manipulate approval.               │ PROVEN BY DESIGN           │ TTY/Signature sig│
│ J    │ Downstream MCP cannot misuse injected creds.    │ FALSE                      │ MCP ambient scope│
└──────┴─────────────────────────────────────────────────┴────────────────────────────┴──────────────────┘
```

### Detailed Forensic Breakdown of Claims

#### Claim A: Agent cannot obtain ambient credentials.
* **Classification:** **`PROVEN BY DESIGN`**
* **Forensic Rationale:** Target secrets (e.g., GitHub PATs, AWS secret keys, database passwords) are stored exclusively in Relay's encrypted secret store or the host OS Keyring and are never injected into the agent's process environment (`env`), memory space, or prompt context. Even if an attacker executes arbitrary code inside the agent runtime, memory inspection of the agent process will yield zero target credentials.

#### Claim B: Agent cannot bypass Relay.
* **Classification:** **`REQUIRES ADDITIONAL CONTROL`**
* **Forensic Rationale:** If the agent is a pure LLM client connecting exclusively over stdio (e.g., Claude Desktop with an MCP tool configuration), it cannot bypass Relay within the MCP layer because Relay is its sole tool transport. **However**, if the agent executes arbitrary shell commands or code (e.g., Claude Code, OpenHands, Aider) on the host machine without network namespace isolation, the agent can execute raw `curl` commands or open TCP sockets directly to target APIs. While it lacks credentials for authenticated endpoints, it could reach unauthenticated internal endpoints or use alternate credentials found on disk (e.g., `~/.gitconfig`, `~/.aws/credentials`).
* **Required Control:** The MVP must explicitly require that code-executing agents run in an unprivileged container or sandbox where direct network egress is either blocked or redirected, or document that unconfined host bash execution is outside the stdio MCP proxy boundary.

#### Claim C: Agent cannot cause Relay to authorize an unauthorized action.
* **Classification:** **`PROVEN BY DESIGN`**
* **Forensic Rationale:** Policy decisions are evaluated deterministically by the embedded AWS Cedar engine running in memory-safe Rust. Cedar evaluates compiled Abstract Syntax Trees (ASTs) against typed entity attributes and canonical context. Natural language prompt strings, agent rationale, or hallucinated arguments cannot subvert boolean Cedar rules (`permit` vs `forbid`).

#### Claim D: Agent cannot exploit canonicalization differences.
* **Classification:** **`REQUIRES ADDITIONAL CONTROL`**
* **Forensic Rationale:** RFC 8785 (JSON Canonicalization Scheme / JCS) guarantees deterministic lexicographical sorting and numeric formatting for standard JSON structures. **However**, if a tool parameter accepts *stringified JSON* or *raw SQL/Shell commands* inside a string field (e.g., `args: { "query": "SELECT * FROM users;" }`), RFC 8785 normalizes the outer JSON envelope but **does NOT canonicalize the inner SQL/Shell syntax**. An attacker could use SQL comment injection (e.g., `SELECT/**/FROM`) to evade simple regex/string policies.
* **Required Control:** Policy evaluation on domain-specific string payloads (SQL, file paths, URLs) must parse the payload into normalized ASTs or canonical representations before passing them to Cedar context.

#### Claim E: Agent cannot exploit tool-name ambiguity.
* **Classification:** **`PROVEN BY DESIGN`**
* **Forensic Rationale:** Relay enforces mandatory, deterministic tool namespacing upon ingesting `tools/list` from downstream MCP servers (e.g., `github.merge_pull_request`). Downstream servers cannot register bare or colliding names, and Relay does not allow dynamic tool renaming at invocation time.

#### Claim F: Agent cannot exploit resource-identity ambiguity.
* **Classification:** **`REQUIRES ADDITIONAL CONTROL`**
* **Forensic Rationale:** If an agent requests `path: "/app/data/../etc/passwd"`, a policy restricting writes to `/app/data/*` would fail if evaluated on the unnormalized string.
* **Required Control:** Relay must enforce canonical path resolution (`std::fs::canonicalize` / URI normalization) before constructing the Cedar authorization context.

#### Claim G: Agent cannot replay an authorized action.
* **Classification:** **`PROVEN BY DESIGN`**
* **Forensic Rationale:** Every authorized tool call requires a single-use UUIDv7 nonce and monotonic step counter. In-memory execution tickets are atomically burned upon arrival at the dispatcher; replaying an identical JSON-RPC frame results in immediate rejection.

#### Claim H: Agent cannot alter an authorized action after policy evaluation.
* **Classification:** **`PROVEN BY DESIGN`**
* **Forensic Rationale:** Relay operates as a single, monolithic local binary. The parsed and canonicalized AST evaluated by the Cedar engine in Step 3 is the exact in-memory data structure dispatched to the execution broker in Step 5. There is no intermediate serialization or inter-process hop where an agent could alter parameters (eliminating TOCTOU).

#### Claim I: Agent cannot manipulate approval.
* **Classification:** **`PROVEN BY DESIGN`**
* **Forensic Rationale:** Interactive CLI approvals prompt the human operator directly on `/dev/tty` (or standard OS notification). The human approval binds to the SHA-256 hash of the canonicalized parameters. The agent process cannot inject synthetic keyboard input into Relay's direct TTY stream.

#### Claim J: Agent cannot cause a downstream MCP server to misuse credentials in a way Relay claims to prevent.
* **Classification:** **`FALSE`**
* **Forensic Rationale:** This is the most dangerous assumption in the current architecture. If Relay passes a valid, broad GitHub PAT to a third-party stdio MCP server process via environment variables or startup config, Relay has successfully withheld the key from the *agent*, but has given the key to the *MCP server*. If the MCP server is buggy, malicious, or coerced into invoking alternate GitHub APIs internally, Relay’s stdio proxy cannot prevent the MCP server itself from misusing the credential on the network!
* **Conclusion:** Claim J is false unless Relay either *executes the API call directly* (native tools) or *acts as a network-level egress proxy* for the MCP server's HTTP traffic.

---

# 2. Trust Boundaries

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       RELAY TRUST BOUNDARY MAP                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘

 [ UNTRUSTED ZONE ]
   • Human Prompt Input (May contain direct prompt injection)
   • LLM Provider / Model (Probabilistic, susceptible to jailbreaks)
   • Agent Memory / Context Window / Runtime Framework (Assumed fully compromised)
   • External Web Content / RAG Data (Untrusted ingestion sources)
 ═════════════════════════════════════════════════════════════════ [TB-1: Agent Ingress Boundary]
 [ TRUSTED COMPUTING BASE (TCB) — RELAY CORE ]
   • Relay CLI Binary (Rust, memory-safe, runs as local user)
   • Stdio JSON-RPC Stream Interceptor & RFC 8785 Normalizer
   • Embedded AWS Cedar PDP Engine (Deterministic evaluation)
   • In-Memory Ephemeral Secret Manager (Holds target tokens temporarily)
   • Local Ed25519 Signing Key & DSSE Receipt Generator
   • Local SQLite Receipt Ledger (`.relay/receipts.db`)
 ═════════════════════════════════════════════════════════════════ [TB-2: Credential Boundary]
 [ HOST OS SECURITY SERVICES (Trusted Host Infrastructure) ]
   • OS Keyring / Secure Enclave (macOS Keychain, Linux SecretService)
   • Host Kernel / Memory Isolation (Paging protection, `/proc` permissions)
   • Host Interactive TTY (`/dev/tty` for human HITL prompt)
 ═════════════════════════════════════════════════════════════════ [TB-3: Tool Execution Boundary]
 [ PARTIALLY TRUSTED ZONE ]
   • Downstream Stdio MCP Server Processes (Executes tool logic; must not leak tokens)
   • Target API Transport (TLS connection to `api.github.com`, etc.)
 ═════════════════════════════════════════════════════════════════ [TB-4: Target Resource Boundary]
 [ TARGET SYSTEMS ]
   • Upstream SaaS APIs, Cloud Infrastructure, Production Databases
```

### Component Trust Classification

| Component | Trust Level | Justification / Assumptions | Critical Attack Surfaces |
| :--- | :--- | :--- | :--- |
| **Human Operator** | Trusted | Assumed to be authorized user; may be tricked by phishing | Misleading diff displays on TTY |
| **Agent / LLM** | **UNTRUSTED** | Assumed 100% compromised via prompt injection | Emits malformed/malicious tool calls |
| **Relay Binary** | **TRUSTED (TCB)** | Core security enforcement point | Local binary tampering, bugs |
| **Cedar PDP** | **TRUSTED (TCB)** | Formally verified evaluation logic | Policy misconfiguration |
| **Credential Store** | **TRUSTED** | OS Keyring / Secure Enclave | Unauthorized local process read |
| **Credential Provider**| Partially Trusted| External STS/OAuth endpoints | Provider downtime, rate limits |
| **MCP Server** | **PARTIALLY TRUSTED** | Executes tool code; could be malicious or vulnerable | Exfiltrates credentials, tool shadowing |
| **Target API** | Trusted Target | Authoritative resource owner | Logic bugs, unauthenticated endpoints |
| **Local Machine** | Trusted Host | Assumes host OS is not already rooted | Local malware, shared UID access |
| **Operating System** | **TRUSTED (TCB)** | Enforces memory and filesystem permissions | Kernel exploits, swap leakage |
| **Receipt Store** | Trusted Local | SQLite append-only file | Local file tampering (detected by hash chain)|
| **Signing Key** | **TRUSTED (TCB)** | Ed25519 private key in memory / disk | Key exfiltration via memory dump |

---

# 3. Stdio Architecture & Credential Flow Investigation

### The Fundamental Stdio Dilemma
In `R014`, the specification states:
> *"Relay dispatches the call to the real downstream GitHub MCP server subprocess... Relay injects `Authorization: Bearer <token>` in the downstream transport."*

**This is technically inaccurate for standard stdio MCP servers.**
Standard stdio MCP servers (e.g., `@modelcontextprotocol/server-github`) communicate over standard I/O pipes (`stdin`/`stdout`) using JSON-RPC. They do not accept HTTP headers on `stdin`. They expect authentication credentials at process startup via **environment variables** (e.g., `GITHUB_PERSONAL_ACCESS_TOKEN=ghp_xxxx`).

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              EVALUATION OF STDIO CREDENTIAL INJECTION MECHANISMS                       │
├──────────────────────────┬──────────────┬──────────────────────────────────────────────────────────────┤
│ Mechanism                │ Viability    │ Security & Operational Failure Modes                         │
├──────────────────────────┼──────────────┼──────────────────────────────────────────────────────────────┤
│ 1. Process Environment   │ 🟡 FLAWED    │ • Credentials visible in `/proc/<pid>/environ` to same UID.  │
│    Inheritance at Spawn  │              │ • Grants ambient credentials to the MCP server for lifetime. │
│                          │              │ • Cannot do per-action JIT downscoping without process kill. │
├──────────────────────────┼──────────────┼──────────────────────────────────────────────────────────────┤
│ 2. JSON-RPC Payload      │ 🔴 REJECTED  │ • Modifies standard MCP tool schemas (breaks compatibility). │
│    Argument Injection    │              │ • Downstream MCP servers reject unrecognized parameters.     │
├──────────────────────────┼──────────────┼──────────────────────────────────────────────────────────────┤
│ 3. Transient Env Spawn   │ 🟡 SLOW      │ • Relay spawns a new MCP server process per tool call.       │
│    (Per-Call Process)    │              │ • Destroys stdio initialization performance (>500ms startup).│
├──────────────────────────┼──────────────┼──────────────────────────────────────────────────────────────┤
│ 4. Local Loopback Egress │ 🟢 OPTIMAL   │ • MCP server runs with ZERO credentials.                     │
│    Proxy with Header Inj.│ (HIGH ASSUR) │ • MCP server makes outbound HTTP calls to `127.0.0.1:Relay`. │
│                          │              │ • Relay inspects HTTP request, injects real Auth header.     │
├──────────────────────────┼──────────────┼──────────────────────────────────────────────────────────────┤
│ 5. Relay Native Tools    │ 🟢 OPTIMAL   │ • Relay implements high-value tools natively in Rust.        │
│    (Built-in Connectors) │ (RECOMMENDED)│ • Zero third-party MCP subprocess required for core tools.   │
└──────────────────────────┴─────────────────────────────────────────────────────────────────────────────┘
```

### The Safest Practical MVP Mechanism: **Dual-Track Execution Model**

To resolve this without breaking third-party MCP compatibility:

1. **Track 1 (Relay Native Governed Tools — Primary MVP Path):**
   * For the core demo and critical tools (e.g., `github`, `postgres`, `filesystem`), Relay provides **built-in native execution**. Relay evaluates policy, acquires the credential from Keyring, executes the HTTPS/DB call directly in Rust, signs the receipt, and returns the result over stdio. **Zero subprocesses, zero ambient credential exposure, zero `/proc` leakage.**
2. **Track 2 (Third-Party Subprocess Proxying — Compatibility Path):**
   * For external MCP servers (`relay run -- npx -y @modelcontextprotocol/server-slack`), Relay runs as a stdio proxy. Relay configures the subprocess's `HTTPS_PROXY` to route through Relay's internal loopback proxy, stripping any hardcoded tokens and injecting authorized credentials on the wire.

---

# 4. Malicious MCP Server Threat Analysis

### Threat Scenario:
```text
Agent = Compromised (Prompt Injected)
MCP Server = Malicious / Rogue
Relay = Uncompromised
```

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                MALICIOUS MCP SERVER THREAT MATRIX                                      │
├─────────────────────────────────────────┬──────────────┬───────────────────────────────────────────────┤
│ Attack Vector                           │ Can Succeed? │ Relay Countermeasure & Residual Risk          │
├─────────────────────────────────────────┼──────────────┼───────────────────────────────────────────────┤
│ 1. Can MCP server steal credentials?    │ CONDITIONAL  │ • If passed via Env: YES (Server steals env). │
│                                         │              │ • If Native / Loopback Injected: NO.          │
├─────────────────────────────────────────┼──────────────┼───────────────────────────────────────────────┤
│ 2. Can MCP server invoke extra APIs?    │ CONDITIONAL  │ • If it holds ambient token: YES.             │
│                                         │              │ • If network-constrained to Relay: NO.        │
├─────────────────────────────────────────┼──────────────┼───────────────────────────────────────────────┤
│ 3. Can it alter tool results?           │ YES          │ Server controls stdout; can return poisoned   │
│                                         │              │ text to inject the agent in subsequent turns. │
├─────────────────────────────────────────┼──────────────┼───────────────────────────────────────────────┤
│ 4. Can it request broader credentials?  │ NO           │ Relay enforces Cedar policy; server requests  │
│                                         │              │ cannot elevate permissions.                   │
├─────────────────────────────────────────┼──────────────┼───────────────────────────────────────────────┤
│ 5. Can it impersonate another tool?     │ NO           │ Relay enforces strict server-level namespacing│
│                                         │              │ (`server_a.tool` vs `server_b.tool`).         │
├─────────────────────────────────────────┼──────────────┼───────────────────────────────────────────────┤
│ 6. Can it falsify Action Receipts?      │ NO           │ Receipts are signed exclusively by Relay's    │
│                                         │              │ private key over canonicalized input/output.  │
└─────────────────────────────────────────┴──────────────┴───────────────────────────────────────────────┘
```

### Strategic Recommendation for MCP Servers in MVP:
* **Relay MUST treat third-party MCP servers as PARTIALLY TRUSTED / POTENTIALLY HOSTILE.**
* **Mandatory MVP Controls:**
  1. **Namespace Isolation:** Automatically prefix all discovered tools with the server alias (`<server-alias>.<tool-name>`).
  2. **Schema Pinning:** Hash tool definitions on `initialize`. If the server mutates descriptions or schemas dynamically, abort execution.
  3. **Output Sanitization:** Scan tool response text to prevent downstream secret echoing.
  4. **Explicit MVP Scope Exclusion:** Full microVM/container sandboxing of third-party stdio subprocesses is deferred to Post-MVP (Tier-1). The MVP assumes the local developer explicitly chose to run the specified MCP server command.

---

# 5. Canonicalization Security (RFC 8785 / JCS)

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   CANONICAL AUTHORIZATION ENVELOPE (CAE)                               │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘

    Raw MCP JSON-RPC Frame ──► [ Schema Validator ] ──► [ JCS Normalizer (RFC 8785) ] ──► CAE Struct
```

### Deep Forensic Analysis of Normalization Dimensions

1. **What is Canonicalized:**
   * The exact invocation payload: `tool_name`, `principal`, `resource_urn`, and the sorted, normalized `arguments` map.
   * JSON-RPC protocol transport metadata (`jsonrpc: "2.0"`, `id: "req-123"`) is **excluded** from the ActionHash to prevent transport-level replay invalidation.
2. **Key Ordering & Whitespace:**
   * Strictly formatted according to RFC 8785: all object keys sorted lexicographically by UTF-16 code units; zero whitespace between keys/values.
3. **Duplicate Keys:**
   * Handled by strict JSON parser rejection (RFC 8259 compliance). Any payload with duplicate object keys fails parsing with immediate `Fail-Closed` error.
4. **Numeric Normalization:**
   * IEEE 754 floating-point numbers normalized to standard decimal representation (no trailing zeros, exponential notation standardized as per JCS §3.2.2.3). Integers preserved without decimal points.
5. **Unicode Normalization:**
   * Strings must undergo **Unicode Normalization Form C (NFC)** before hashing to prevent homograph evasion attacks (e.g., combining characters vs precomposed characters).
6. **Null vs. Omitted Fields:**
   * In Cedar evaluation, an explicit `null` field is normalized by **omitting the key** from the canonical arguments map to prevent `null` vs `undefined` attribute confusion in Cedar rules.

### "Policy Sees X, Execution Receives Y" Anti-Pattern Mitigation
To guarantee that the target tool executes the exact payload evaluated by policy:
* Relay **does not re-serialize** the request from text.
* Relay parses the raw JSON into a strongly-typed, memory-safe Rust structure `CanonicalActionProposal`, computes the SHA-256 `ActionHash`, evaluates Cedar against this structure, and serializes *this exact canonical structure* to the downstream target.

---

# 6. Concrete Cedar Policy Model

Relay MVP expresses all authorization logic purely in **AWS Cedar** without inventing any custom DSL.

### Entity & Context Mapping Definition
* **Principal:** `Agent::"<agent-id>"` (e.g., `Agent::"claude-code"`)
* **Action:** `Action::"tools/call"`
* **Resource:** `Tool::"<namespace>.<tool-name>"` (e.g., `Tool::"github.merge_pull_request"`)
* **Context Attributes:**
  * `arguments`: Record containing canonical tool arguments.
  * `environment`: Record (`host_user: String`, `is_interactive: Bool`, `workdir: String`).
  * `action_hash`: `String` (SHA-256 hex digest).

---

### Concrete Cedar Policy Examples

#### 1. Read Operation (Permitted)
```cedar
// Allow all agents to list and read GitHub issues across public repos
permit (
    principal,
    action == Action::"tools/call",
    resource in [Tool::"github.list_issues", Tool::"github.get_issue"]
)
when {
    context.arguments.repo like "public/*"
};
```

#### 2. Normal Write (Permitted with Boundary Constraints)
```cedar
// Allow creating issues, but enforce label and repository restrictions
permit (
    principal == Agent::"claude-code",
    action == Action::"tools/call",
    resource == Tool::"github.create_issue"
)
when {
    context.arguments.repo == "acme/backend" &&
    context.arguments.title like "bug: *"
};
```

#### 3. Destructive Write (Requires Approval / Forbid by Default)
```cedar
// Forbid repository deletion unconditionally for all automated agents
forbid (
    principal,
    action == Action::"tools/call",
    resource == Tool::"github.delete_repo"
);
```

#### 4. Production Operation (Constrained Parameter Check)
```cedar
// Allow SQL migrations only if explicitly marked as dry_run on staging
permit (
    principal,
    action == Action::"tools/call",
    resource == Tool::"postgres.execute_query"
)
when {
    context.arguments.database == "staging_db" &&
    !(context.arguments.query like "*DROP*") &&
    !(context.arguments.query like "*TRUNCATE*")
};
```

#### 5. Approval-Required Operation (Interactive Step-Up)
```cedar
// Permit pull request merges ONLY if approved interactively by operator
permit (
    principal,
    action == Action::"tools/call",
    resource == Tool::"github.merge_pull_request"
)
when {
    context.environment.is_interactive == true &&
    context.arguments.merge_method == "squash"
};
```

#### 6. Denied Operation (Default Deny)
* Any tool invocation not explicitly matched by a `permit` rule is denied automatically by Cedar's fundamental default-deny semantics.

---

# 7. Credential Lifecycle & Memory Security

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    CREDENTIAL LIFECYCLE STATE MACHINE                                  │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  [ 1. Keyring Storage ] (Encrypted at rest in macOS Keychain / SecretService)
            │
            ▼ (On Policy ALLOW / Operator Approval)
  [ 2. JIT Fetch to Memory ] (Decrypted into zeroize-backed Rust buffer)
            │
            ▼
  [ 3. Wire Dispatch ] (Injected into outbound HTTPS TLS stream / Loopback proxy)
            │
            ▼
  [ 4. Immediate Zeroization ] (Memory overwritten with 0x00 via `zeroize::ZeroizeOnDrop`)
            │
            ▼
  [ 5. Execution Complete ] (Receipt emitted; token no longer exists in memory)
```

### Explicit Memory & Process Security Invariants

1. **Memory Zeroization:** All decrypted secrets must be stored in data structures implementing `Zeroize` and `ZeroizeOnDrop` (from the Rust `zeroize` crate). Secrets are scrubbed immediately upon completion of the downstream network dispatch.
2. **No Secret in `/proc`:** Secrets must **never** be passed as CLI command-line arguments to child processes (which are world-readable via `ps aux` or `/proc/<pid>/cmdline`).
3. **Core Dump Protection:** Relay binary must invoke `prctl(PR_SET_DUMPABLE, 0)` on Linux and `minherit(MAP_INHERIT_NONE)` / `madvise(MADV_DONTDUMP)` on secret memory pages to prevent secrets from being written to disk in core dumps or crash logs.
4. **Log Sanitization:** Tracing and log subscribers must be wrapped in a redaction filter that pattern-matches and scrubs known secret prefixes (`ghp_`, `sk-`, `AKIA`, `Bearer `) before writing to stdout/stderr or log files.
5. **Concurrency & Thread Isolation:** Secrets are never stored in global static variables. Secrets are passed as ephemeral, scoped stack variables pinned to the individual request thread/future.

---

# 8. Receipt Security & Evidence Formalism

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 GOVERNED ACTION RECEIPT STRUCTURE                                      │
├────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ DSSE Envelope (RFC 9598)                                                                               │
│  ├─ payloadType: "application/vnd.in-toto+json"                                                        │
│  ├─ signatures: [{ keyid: "relay:node:ed25519:01", sig: "..." }]                                      │
│  └─ payload (Base64 in-toto Statement v1.0):                                                          │
│      ├─ _type: "https://in-toto.io/Statement/v1"                                                       │
│      ├─ subject: [{ name: "<resource-urn>", digest: { "action_payload": "sha256:..." } }]             │
│      ├─ predicateType: "https://relay.dev/attestation/action-receipt/v1"                               │
│      └─ predicate:                                                                                     │
│          ├─ receipt_id: "rcpt_01J7K8M9N0..." (UUIDv7)                                                  │
│          ├─ session: { session_id, step_index, parent_receipt_hash }                                   │
│          ├─ invocation: { tool_name, canonical_arguments_hash }                                        │
│          ├─ authorization: { decision: "ALLOW", policy_ast_hash, evaluated_at }                        │
│          └─ execution: { status: "SUCCESS", duration_ms, response_raw_hash }                           │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### The 4 Levels of Evidence Formalism

Relay must strictly differentiate what it cryptographically proves versus what it merely observes:

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   EVIDENCE TAXONOMY & CLASSIFICATION                                   │
├──────────────┬──────────────────────────────────────────┬──────────────────────────────────────────────┤
│ State Class  │ Concrete Meaning                         │ Cryptographic Standing                       │
├──────────────┼──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ AUTHORIZED   │ Relay evaluated Cedar policy & permitted │ CRYPTOGRAPHICALLY PROVEN (Signed by Relay)   │
├──────────────┼──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ EXECUTED     │ Relay dispatched payload to target API   │ CRYPTOGRAPHICALLY PROVEN (Signed by Relay)   │
├──────────────┼──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ OBSERVED     │ Target API returned HTTP 200 / SQL OK    │ ATTESTED OBSERVATION (Relay observed return) │
├──────────────┼──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ VERIFIED     │ Target DB state mutated on physical disk │ UNPROVABLE (Requires target storage proof)   │
└──────────────┴──────────────────────────────────────────┴──────────────────────────────────────────────┘
```

* **Anti-Deception Rule:** Relay Action Receipts **must never claim** to "prove database state mutation." Receipts prove **Authorization, Parameter Integrity, and Dispatch Observation**.

---

# 9. Failure Analysis & Resiliency State Machine

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    FAILURE MODE RESILIENCY MATRIX                                      │
├──────────────────────────┬──────────────────────┬──────────────────────────────────────────────────────┤
│ Failure Event            │ Default Behavior     │ Concrete Recovery & Mitigation Mechanism             │
├──────────────────────────┼──────────────────────┼──────────────────────────────────────────────────────┤
│ 1. Relay Crash           │ Fail-Closed (Safe)   │ Stdio pipe closes; agent tool call fails cleanly.    │
├──────────────────────────┼──────────────────────┼──────────────────────────────────────────────────────┤
│ 2. MCP Server Crash      │ Fail-Closed (Safe)   │ Relay returns JSON-RPC error `-32603` to agent.      │
├──────────────────────────┼──────────────────────┼──────────────────────────────────────────────────────┤
│ 3. Keyring Read Failure  │ Fail-Closed (Safe)   │ Action aborted; zero credentials injected; error log.│
├──────────────────────────┼──────────────────────┼──────────────────────────────────────────────────────┤
│ 4. Cedar Engine Panic    │ Fail-Closed (Safe)   │ Catch unwind in Rust; returns `DENIED: Policy Error`.│
├──────────────────────────┼──────────────────────┼──────────────────────────────────────────────────────┤
│ 5. SQLite Write Failure  │ Fail-Closed (Safe)   │ If receipt cannot be recorded, tool execution aborts.│
├──────────────────────────┼──────────────────────┼──────────────────────────────────────────────────────┤
│ 6. Signing Key Corrupted │ Fail-Closed (Safe)   │ Refuses startup or aborts execution with error.      │
├──────────────────────────┼──────────────────────┼──────────────────────────────────────────────────────┤
│ 7. Downstream Timeout    │ Fail-Closed (Safe)   │ Emits TIMEOUT receipt; closes downstream connection. │
├──────────────────────────┼──────────────────────┼──────────────────────────────────────────────────────┤
│ 8. Partial Network Write │ Fail-Closed (Safe)   │ Records failure receipt with `status: NETWORK_ERROR`.│
├──────────────────────────┼──────────────────────┼──────────────────────────────────────────────────────┤
│ 9. Duplicate Request     │ Idempotent Reject    │ Monotonic step check rejects duplicate nonce.        │
└──────────────────────────┴──────────────────────┴──────────────────────────────────────────────────────┘
```

* **Core Architectural Invariant:** **All security-sensitive failure paths in Relay default unconditionally to `FAIL-CLOSED` (Abort & Deny).**

---

# 10. Adversarial Attack Scenarios (The 20-Attack Gauntlet)

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                      THE 20-ATTACK ADVERSARIAL GAUNTLET                                │
├────┬─────────────────────────────┬───────────┬─────────────────────────────────────────────────────────┤
│ #  │ Attack Description          │ Can Stop? │ Mitigation & Forensic Details                           │
├────┼─────────────────────────────┼───────────┼─────────────────────────────────────────────────────────┤
│ 1  │ Direct Prompt Injection     │ YES (MVP) │ Cedar enforces deterministic parameters out-of-band.    │
│ 2  │ Tool Schema Poisoning       │ YES (MVP) │ Schema SHA-256 pinned on startup; description sanitized.│
│ 3  │ Malicious Tool Arguments    │ YES (MVP) │ Cedar parameter-boundary inspection.                    │
│ 4  │ Unicode Confusion / NFC     │ YES (MVP) │ Mandatory Unicode NFC normalization prior to hashing.   │
│ 5  │ JSON Parse Discrepancy      │ YES (MVP) │ RFC 8785 strict canonicalization on single parsed AST.  │
│ 6  │ Schema Type Confusion       │ YES (MVP) │ Strict JSON Schema Draft 2020-12 parameter validation.  │
│ 7  │ Tool Shadowing / Impersonate│ YES (MVP) │ Mandatory server-alias namespacing (`server.tool`).     │
│ 8  │ Path Traversal Resource Imp.│ YES (MVP) │ Canonical path resolution (`fs::canonicalize`) in Cedar.│
│ 9  │ Credential Exfiltration     │ YES (MVP) │ Secrets stored in Keyring; zero keys in agent env/mem.  │
│ 10 │ Action Replay Attack        │ YES (MVP) │ Unique UUIDv7 proposal nonces & single-use execution.   │
│ 11 │ TOCTOU Race Condition       │ YES (MVP) │ Monolithic binary memory pass; no intermediate re-parse.│
│ 12 │ Credential Reuse Across Turn│ YES (MVP) │ Stack-scoped zeroized buffers; ephemeral leases.        │
│ 13 │ Process Env Leakage (/proc) │ YES (MVP) │ Zero secrets in process CLI args or child env vars.     │
│ 14 │ SQLite Ledger Tampering     │ YES (MVP) │ `relay verify` detects broken SHA-256 hash chains.      │
│ 15 │ Policy Version Downgrade    │ YES (MVP) │ Policy AST SHA-256 digest embedded in signed receipt.   │
│ 16 │ CLI Approval Bypass         │ YES (MVP) │ Direct `/dev/tty` prompt; agent stdin cannot inject TTY.│
│ 17 │ Direct Network Bypass       │ OUT SCOPE │ Unconfined host bash can `curl`; requires netns/sandbox.│
│ 18 │ Malicious Downstream MCP    │ PARTIAL   │ Stopped for Native tools; Third-party needs Post-MVP VM.│
│ 19 │ Compromised Local UID       │ OUT SCOPE │ Host OS root compromise breaks all user-space software. │
│ 20 │ Relay Binary Replacement    │ OUT SCOPE │ Binary integrity belongs to OS file integrity / SIP.    │
└────┴─────────────────────────────┴───────────┴─────────────────────────────────────────────────────────┘
```

---

# 11. Correcting the Product Language

To preserve scientific rigor and legal defensibility, the following misleading marketing terms in `R014` are formally corrected:

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       PRODUCT LANGUAGE CORRECTIONS                                     │
├──────────────────────────┬─────────────────────────────────────────────────────────────────────────────┤
│ Misleading / Strong Claim│ Technically Defensible Replacement Language                                 │
├──────────────────────────┼─────────────────────────────────────────────────────────────────────────────┤
│ ❌ "Zero Knowledge"      │ 🟢 "Zero Ambient Agent Credentials" (Relay possesses keys; agent does not) │
├──────────────────────────┼─────────────────────────────────────────────────────────────────────────────┤
│ ❌ "Zero Trust"          │ 🟢 "Deterministic Policy Enforcement Point (PEP) at Tool Boundary"          │
├──────────────────────────┼─────────────────────────────────────────────────────────────────────────────┤
│ ❌ "Tamper-Proof"        │ 🟢 "Tamper-Evident Hash-Chained Audit Ledger"                               │
├──────────────────────────┼─────────────────────────────────────────────────────────────────────────────┤
│ ❌ "Cryptographically    │ 🟢 "Cryptographically Proven Authorization, Dispatch, and Parameter         │
│     Proven Mutation"     │     Integrity (with Attested Downstream Execution Observation)"             │
├──────────────────────────┼─────────────────────────────────────────────────────────────────────────────┤
│ ❌ "Cannot execute       │ 🟢 "Cannot execute unauthorized actions through the Relay-governed MCP      │
│     unauthorized action" │     interface"                                                              │
└──────────────────────────┴─────────────────────────────────────────────────────────────────────────────┘
```

---

# 12. Final Build Decision & Concrete Architecture

## SECURITY VERDICT
# **PASS WITH CONDITIONS**

## ARCHITECTURAL VERDICT
# **READY TO BUILD**

---

### Required Changes Before Implementation (Blocking Conditions)

1. **Adopt Dual-Track Tool Execution (Fix Stdio Credential Injection):**  
   Do not attempt to pass dynamic per-call credentials to third-party stdio MCP servers via environment variables. For the MVP golden path, implement **Native Governed Connectors** in Rust for GitHub, PostgreSQL, and Filesystem where Relay performs the execution directly.
2. **Mandatory Domain-Specific AST Canonicalization:**  
   Implement canonical path normalization and SQL statement parsing before Cedar evaluation to prevent parameter bypasses.
3. **Strict Memory Zeroization:**  
   Enforce `zeroize` crate integration on all secret buffers and enable core-dump disabling flags (`prctl(PR_SET_DUMPABLE, 0)`).
4. **Explicit Non-Confined Bash Disclaimer:**  
   Explicitly document that governing arbitrary host `bash` execution requires OS sandboxing/containers, which is a companion control to the MCP gateway.

---

### Safe MVP Guarantees (What Relay Confidently Advertises)
1. **Zero Ambient Secrets:** Target API keys are never exposed to the agent process, environment, or memory.
2. **Deterministic Tool Gating:** Every MCP `tools/call` passing through Relay is evaluated against formal AWS Cedar policies; prompt injections cannot bypass policy rules.
3. **Tamper-Evident Auditability:** Every executed action produces a DSSE-signed in-toto Action Receipt stored in a cryptographically verifiable local SQLite hash chain.
4. **Interactive Step-Up Safety:** High-risk actions halt execution and require direct human confirmation on `/dev/tty`.

---

### Explicit Non-Guarantees (What Relay Does NOT Protect Against)
1. Relay does not prevent an agent with unconfined local bash access from making unauthenticated network requests or reading unencrypted user files on the host.
2. Relay does not verify the internal correctness of third-party APIs or prove physical storage engine disk mutation.
3. Relay does not protect against a root/kernel-level compromise of the developer's host operating system.

---

### Final MVP Architecture Blueprint (For Implementation Team)

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                     RELAY MVP IMPLEMENTATION BLUEPRINT                                 │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘

 [ Crate: `relay-core` ] (Single Rust Binary)
   │
   ├── Module 1: `transport::stdio`
   │     • Async JSON-RPC 2.0 parser (`tokio::io::Stdin`, `tokio::io::Stdout`)
   │     • Intercepts `tools/list` (prefixes names, hashes schema)
   │     • Intercepts `tools/call` (extracts arguments)
   │
   ├── Module 2: `canonicalizer`
   │     • RFC 8785 JSON Canonicalization Scheme (`serde_jcs`)
   │     • Path normalizer (`dunce::canonicalize`)
   │     • Computes `ActionHash = SHA-256(JCS(NormalizedPayload))`
   │
   ├── Module 3: `policy::cedar`
   │     • Embedded AWS Cedar Rust Engine (`cedar-policy` crate)
   │     • Loads local `.cedar` policy files on startup
   │     • Maps Principal, Tool Resource, and Canonical Context to Cedar Request
   │     • Returns `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`
   │
   ├── Module 4: `approval::tty`
   │     • Opens `/dev/tty` directly for human confirmation
   │     • Displays sanitized diff and SHA-256 ActionHash
   │     • Captures operator keystroke (`[y/N]`)
   │
   ├── Module 5: `secrets::keyring`
   │     • Interfaces with OS Keyring (`keyring-rs`)
   │     • Zeroize-backed ephemeral secret buffer (`zeroize` crate)
   │     • Fetches token strictly after Cedar ALLOW
   │
   ├── Module 6: `executor::native`
   │     • Native GitHub REST client (`reqwest` with injected Bearer token)
   │     • Native Postgres client (`tokio-postgres`)
   │     • Native filesystem writer (`tokio::fs`)
   │     • Dispatches call, captures raw response & duration
   │
   └── Module 7: `receipt::ledger`
         • Constructs in-toto Statement v1.0
         • Wraps in DSSE Envelope (RFC 9598)
         • Signs with local Ed25519 node key (`ed25519-dalek`)
         • Appends to `.relay/receipts.db` (`rusqlite` hash-chained table)
         • Emits sanitized JSON-RPC result to stdout
```

**Implementation is authorized to proceed immediately under these specifications.**
