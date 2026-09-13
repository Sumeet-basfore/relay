# A007: Relay MVP CLI Specification & Developer Experience Architecture

**Document ID:** `A007-cli-and-dx`  
**Date:** September 2026  
**Status:** Approved Architectural Baseline / Developer Experience Specification  
**Target System:** Relay MVP (Local-First Zero-Trust MCP Security Gateway & Credential Broker)  
**Author:** Developer Experience & Systems Architect  
**Corpus Dependencies:** `00-research-synthesis`, `A001` (System Architecture), `A002` (Domain Model), `A003` (Interfaces & Contracts), `A004` (Security Invariants), `R014` (MVP Definition), `R015` (Build Gate)

---

## Executive Summary

This document specifies the Developer Experience (DX), Command Line Interface (CLI) grammar, subprocess execution mechanics, terminal I/O multiplexing, and human-in-the-loop (HITL) approval ergonomics for the **Relay MVP**.

Relay operates directly in the developer's execution path. If Relay introduces cognitive overhead, configuration friction, log noise, or execution latency, developers will bypass it. Therefore, Relay’s CLI is designed around three strict principles:

1. **Zero Protocol Contamination:** The agent's standard input and output streams (`stdio`) are strictly reserved for MCP JSON-RPC 2.0 frames. Relay diagnostics, structured logs, and interactive HITL approval UI must never leak into stdout.
2. **Transparent Drop-in Wrap:** Wrapping an existing MCP server requires prefixing the launch command with `relay run -- <command>`. No changes to agent clients or MCP server binaries are permitted.
3. **Local-First, Boring, and Predictable:** Sub-millisecond policy evaluations, sub-10ms gateway overhead, zero background daemon prerequisites for basic operation, standard exit codes, and immediate actionable error messages.

---

## Table of Contents

1. [Developer Experience Philosophy](#1-developer-experience-philosophy)
2. [CLI Command Set Architecture](#2-cli-command-set-architecture)
3. [`relay run` — Subprocess & Gateway Lifecycle](#3-relay-run--subprocess--gateway-lifecycle)
4. [Stdio Multiplexing & Terminal Handling](#4-stdio-multiplexing--terminal-handling)
5. [Interactive Approval UX (`/dev/tty`)](#5-interactive-approval-ux-devtty)
6. [Secret Management UX (`relay secret`)](#6-secret-management-ux-relay-secret)
7. [Policy Authoring & Validation UX (`relay policy`)](#7-policy-authoring--validation-ux-relay-policy)
8. [Receipt & Verification UX (`relay verify` & `relay receipt`)](#8-receipt--verification-ux-relay-verify--relay-receipt)
9. [Diagnostic Health Check UX (`relay doctor`)](#9-diagnostic-health-check-ux-relay-doctor)
10. [Exit Codes & Scriptability](#10-exit-codes--scriptability)
11. [Agent Client Configuration Templates](#11-agent-client-configuration-templates)
12. [Developer Experience Invariants](#12-developer-experience-invariants)

---

## 1. Developer Experience Philosophy

### 1.1 The Invisible Guardian Pattern
Relay acts as a transparent, high-integrity shim between an AI agent client (e.g., Claude Desktop, Cursor, VS Code, Zed) and downstream MCP tool servers (e.g., Postgres, Filesystem, GitHub, Bash, AWS).

```
┌─────────────────┐             ┌─────────────────────────┐             ┌────────────────────┐
│   Agent Client  │             │   Relay Gateway Binary  │             │  MCP Tool Server   │
│ (Claude/Cursor) │             │        (`relay`)        │             │ (e.g. Postgres)    │
└────────┬────────┘             └────────────┬────────────┘             └─────────┬──────────┘
         │                                   │                                    │
         │ 1. MCP stdio (JSON-RPC)           │                                    │
         │──────────────────────────────────►│                                    │
         │                                   │ 2. Canonicalize & Evaluate Cedar   │
         │                                   │    [Decision: ALLOW / PROMPT]      │
         │                                   │                                    │
         │                                   │ ───► [/dev/tty Prompt] (if PROMPT) │
         │                                   │                                    │
         │                                   │ 3. Inject Vaulted Secret & Execute │
         │                                   │───────────────────────────────────►│
         │                                   │                                    │
         │                                   │ 4. Child Result                    │
         │                                   │◄───────────────────────────────────│
         │                                   │                                    │
         │                                   │ 5. Record Signed in-toto Receipt   │
         │ 6. Governed MCP Response          │                                    │
         │◄──────────────────────────────────│                                    │
```

### 1.2 Performance & Friction Budgets
* **Policy Evaluation Latency:** $\le 2\text{ ms}$ (Rust AWS Cedar engine in-memory evaluation).
* **Gateway Interception Overhead:** $\le 10\text{ ms}$ roundtrip per MCP tool invocation.
* **Cold Start Time:** $\le 50\text{ ms}$ from `relay run` execution to child subprocess readiness.
* **Zero Telemetry / Zero Cloud Phoning:** Relay MVP runs 100% locally. No external telemetry or cloud dependencies.

---

## 2. CLI Command Set Architecture

Relay exposes a compact, disciplined command surface implemented via `clap` (derive API) in Rust. Every command directly supports local policy enforcement, secret vaulting, or cryptographic auditability.

```
relay <COMMAND> [OPTIONS]

COMMANDS:
  run       Wrap and govern an MCP server over stdio
  policy    Validate, test, and inspect AWS Cedar security policies
  secret    Manage vaulted credentials in the OS secure keyring
  verify    Cryptographically verify action receipts and audit chains
  receipt   Query and inspect local ledger action receipts
  doctor    Diagnose system health, keyring access, keys, and permissions
  help      Print this message or the help of the given subcommand(s)

GLOBAL OPTIONS:
  -c, --config <PATH>    Path to relay configuration file [default: ~/.config/relay/relay.toml]
  -v, --verbose          Increase diagnostic logging verbosity (-v: DEBUG, -vv: TRACE)
  -q, --quiet            Silence all diagnostic logging to stderr
      --json             Format diagnostic output as JSON (where applicable)
  -h, --help             Print help information
  -V, --version          Print version information
```

### 2.1 Justification of Retained vs. Excluded Commands

| Command | Status | Rationale / Justification |
| :--- | :--- | :--- |
| `relay run` | **RETAINED** | Core MVP execution loop; acts as the stdio gateway proxy. |
| `relay policy` | **RETAINED** | Necessary for developers to check policy syntax, list rules, and run policy unit tests. |
| `relay secret` | **RETAINED** | Required to store credentials into OS Keyring without writing secrets to cleartext config files. |
| `relay verify` | **RETAINED** | Core audit capability; verifies DSSE signatures and in-toto statements independently. |
| `relay receipt` | **RETAINED** | Local forensic inspection tool for querying the SQLite receipt ledger. |
| `relay doctor` | **RETAINED** | Essential self-diagnostic for troubleshooting keyring, TTY, keypair, and DB permissions. |
| `relay init` | **EXCLUDED** | Unnecessary ceremony. `relay run` automatically initializes default config/db if missing. |
| `relay serve` | **EXCLUDED** | MVP is strictly stdio-based. Network HTTP/SSE listener deferred to enterprise/remote milestone. |
| `relay sync` | **EXCLUDED** | No remote server or cloud sync exists in MVP. Local-first only. |
| `relay login` | **EXCLUDED** | No cloud accounts or SaaS authentication in MVP. |

---

## 3. `relay run` — Subprocess & Gateway Lifecycle

The `relay run` command is the primary entry point. It wraps an MCP tool server command, establishing a secure Policy Enforcement Point (PEP).

```bash
relay run [OPTIONS] -- <MCP_COMMAND> [MCP_ARGS...]
```

### 3.1 Syntax and Argument Parsing
Relay uses standard POSIX double-dash (`--`) syntax to separate Relay flags from child subprocess arguments.

```bash
# Example 1: Governing a Postgres MCP server
relay run -- npx -y @modelcontextprotocol/server-postgres postgresql://localhost:5432/devdb

# Example 2: Governing a custom Python filesystem server with specific policies
relay run --policy-dir ./policies --ledger-path ./ledger.db -- uv run server_fs.py /data

# Example 3: Non-interactive CI mode with strict fail-closed policy
relay run --non-interactive --strict -- ./bin/mcp-aws-server
```

#### Command Options for `relay run`
* `--policy-dir <DIR>`: Directory containing `.cedar` policy files [default: `~/.config/relay/policies`].
* `--ledger-path <FILE>`: SQLite ledger database file [default: `~/.local/share/relay/ledger.db`].
* `--non-interactive`: Disable interactive `/dev/tty` prompts. Any action requiring human approval is immediately rejected with a deterministic Cedar policy denial.
* `--strict`: Enforce strict fail-closed mode: if the policy engine encountered an error or a tool schema is unrecognized, abort immediately.
* `--timeout <DURATION>`: Tool execution timeout before Relay forcibly terminates the child invocation [default: `60s`].
* `--redact-patterns <REGEX>`: Additional custom regex patterns for parameter redaction in receipts and logs.

### 3.2 Subprocess Lifecycle & Process Isolation

```
┌───────────────────────────────────────────────────────────────────────────┐
│                           RELAY RUN LIFECYCLE                             │
└───────────────────────────────────────────────────────────────────────────┘

1. INITIALIZATION
   ├── Load Ed25519 signing key from OS Keyring (generate if first run)
   ├── Initialize SQLite WAL ledger (`PRAGMA journal_mode=WAL;`)
   ├── Compile & validate AWS Cedar policy store from policy directory
   └── Initialize loopback credential proxy (ephemeral TCP port)

2. SUBPROCESS SPAWN
   ├── Create child process via `std::process::Command`
   ├── Clear ambient environment variables (`cmd.env_clear()`)
   ├── Inject sanitized system paths (`PATH`, `HOME`, `TMPDIR`, `USER`)
   ├── Inject proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY=localhost,127.0.0.1`)
   └── Pipe stdin, stdout, and stderr

3. FRAMING & MESSAGE DISPATCH LOOP
   ├── Read UTF-8 JSON-RPC frame from Agent stdin
   ├── Intercept `tools/call` requests
   │   ├── Parse tool name & JSON arguments
   │   ├── Canonicalize arguments via RFC 8785 (JCS)
   │   ├── Generate deterministic ActionHash: sha256(canonical_request)
   │   ├── Query Cedar PDP Engine with Principal, Action, Resource, Context
   │   ├── Handle Policy Decision:
   │   │   ├── ALLOW: Inject JIT credentials & forward frame to child stdout
   │   │   ├── PROMPT: Trigger /dev/tty interactive approval workflow
   │   │   │   ├── Approved: Inject JIT credentials & forward frame
   │   │   │   └── Denied: Return JSON-RPC error (Code -32001) to Agent
   │   │   └── FORBID: Return JSON-RPC error (Code -32003) to Agent
   │   ├── Await child response frame on child stdout
   │   ├── Redact sensitive tokens from output
   │   ├── Generate signed in-toto v1.0 Action Receipt (DSSE envelope)
   │   ├── Write receipt to SQLite ledger (hash-chained)
   │   └── Forward sanitized response frame to Agent stdout
   └── Transparently pass non-governed frames (`initialize`, `tools/list`, `ping`)

4. TEARDOWN & CLEANUP
   ├── Intercept termination signals (SIGINT, SIGTERM)
   ├── Flush uncommitted receipts to SQLite ledger
   ├── Gracefully terminate child process (SIGTERM -> 500ms -> SIGKILL)
   ├── Securely zeroize in-memory credentials (`zeroize::Zeroize`)
   └── Exit with child exit code or Relay failure code
```

### 3.3 Environment Sanitization (`env_clear`)
Relay strictly prevents child MCP subprocesses from inheriting ambient credentials from the developer's shell environment.

* **Cleared Variables:** `AWS_*`, `GITHUB_*`, `GH_*`, `DATABASE_URL`, `PG*`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `VAULT_*`, `KUBECONFIG`, `SSH_AUTH_SOCK`.
* **Retained Standard Variables:** `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `LC_*`, `TMPDIR`, `SYSTEMROOT` (Windows).
* **Injected Variables:** `RELAY_ACTIVE=1`, `RELAY_VERSION=0.1.0`, `HTTP_PROXY=http://127.0.0.1:<PORT>`, `HTTPS_PROXY=http://127.0.0.1:<PORT>`, `NO_PROXY=localhost,127.0.0.1`.

---

## 4. Stdio Multiplexing & Terminal Handling

### 4.1 Strict Stdio Separation Architecture

A primary failure mode of MCP proxies is log contamination. If a proxy writes debugging text, status updates, or ANSI escape codes to stdout, the agent client's JSON parser crashes with a syntax error.

```
┌────────────────────────────────────────────────────────────────────────┐
│                      STDIO MULTIPLEXING BOUNDARIES                     │
└────────────────────────────────────────────────────────────────────────┘

 [ Agent Client (Claude / Cursor) ]
      │                   ▲
      │ (1) Raw JSON-RPC  │ (6) Governed JSON-RPC
      │     stdin         │     stdout
      ▼                   │
┌─────────────────────────┴──────────────────────────────────────────────┐
│ Relay Gateway Binary (`relay run`)                                     │
│                                                                        │
│   Diagnostics / Logs ──► stderr ──► Agent Client Log Window / Console   │
│                                                                        │
│   Approval Prompt    ──► /dev/tty (Direct Terminal File Descriptor)    │
│   Approval Input     ◄── /dev/tty (Raw Keyboard Input)                 │
└─────────────────────────┬──────────────────────────────────────────────┘
      │                   ▲
      │ (3) Injected      │ (4) Child Result
      │     JSON-RPC      │     stdout
      │     stdin         │
      ▼                   │
 [ Child MCP Server Subprocess ]
      │
      └───► Child stderr ──► Relay stderr (prefixed: `[child:postgres] ...`)
```

### 4.2 Terminal Device Handling (`/dev/tty` / `CONIN$/CONOUT$`)
* **Unix / Linux / macOS:** Relay explicitly opens `/dev/tty` using `std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty")`. This bypasses process stdin/stdout entirely, attaching directly to the controlling terminal session.
* **Windows:** Relay opens `CONIN$` for input and `CONOUT$` for screen output using standard Win32 handle creation APIs.
* **Headless / Non-TTY Detection:** If `/dev/tty` fails to open (e.g., in a CI pipeline, background daemon, or headless Docker container), Relay automatically switches to **Non-Interactive Mode**. Any policy evaluating to `PROMPT` is immediately treated as `FORBID` (fail-closed).

---

## 5. Interactive Approval UX (`/dev/tty`)

When an action evaluates to a `PROMPT` decision under Cedar policies, Relay halts the MCP request and renders an interactive, human-readable confirmation prompt on `/dev/tty`.

### 5.1 Visual Layout Specification
The prompt displays exact contextual metadata, risk classification, normalized operation parameters, and matched policy IDs.

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ RELAY — ACTION REQUIRES APPROVAL                                         │
└──────────────────────────────────────────────────────────────────────────┘
 Tool:      postgres.execute
 Resource:  prod/billing_db
 Risk:      CRITICAL
 Policy:    policy::billing_update_requires_mfa (line 14)
 Hash:      sha256:8f4c2e7b1a90d3e5...5b61

 Operation Summary:
   SQL Mutation: UPDATE customer_accounts SET status = 'suspended' WHERE balance < 0;

 Parameters:
   {
     "query": "UPDATE customer_accounts SET status = 'suspended' WHERE balance < 0;",
     "timeout_ms": 5000,
     "credentials": "[VAULTED: pg_prod_billing_role]"
   }

 ──────────────────────────────────────────────────────────────────────────
 [y] Approve once    [a] Approve all for session    [d] View JSON diff    [n] Deny    [q] Abort
 Selection [y/a/d/n/q] (default: n)? _
```

### 5.2 Key Bindings & Actions
* `y` / `Enter` (if approved): **Approve Once**. Authorize this single canonical ActionHash. Relay proceeds with credential injection and tool execution.
* `a`: **Approve for Session**. Cache authorization for identical tool + resource operations for the remainder of the `relay run` process session.
* `d`: **View Full Diff**. Open an inline paginated JSON view showing the normalized RFC 8785 request payload, environment state, and evaluated Cedar policy ast.
* `n` / `Esc`: **Deny Request**. Deny execution. Relay immediately returns an MCP JSON-RPC error response to the agent client (`Code: -32001`, `Message: "Action rejected by operator approval policy"`).
* `q`: **Abort Session**. Forcibly terminate the child MCP server and shut down `relay run` with exit code `4`.

### 5.3 Secret Redaction Invariant
Under no circumstances may cleartext passwords, tokens, API keys, or private key materials appear in the `/dev/tty` parameter preview. All vaulted credentials injected by Relay are rendered as `[VAULTED: <key_alias>]`.

---

## 6. Secret Management UX (`relay secret`)

Relay stores and retrieves target credentials using the operating system’s secure hardware-backed keyring:
* **macOS:** Apple Keychain Services (`Security.framework`)
* **Linux:** Secret Service API over DBus (GNOME Keyring / KWallet / freedesktop.org)
* **Windows:** Windows Credential Manager (`wincred`)

### 6.1 `relay secret set`
Stores a credential securely into the keyring under Relay's service namespace (`dev.relay.secrets`).

```bash
# Interactive masked input (recommended for developers)
relay secret set pg_prod_billing_role
# Output:
# Enter secret for 'pg_prod_billing_role': ******************
# Confirm secret: ******************
# ✔ Secret 'pg_prod_billing_role' saved to OS Keyring (scope: default).

# Pipe from standard input (useful for CI automation or secret managers)
echo "$PROD_DB_PASSWORD" | relay secret set pg_prod_billing_role --from-stdin

# Store structured JSON secret
relay secret set aws_prod_creds --file ./aws_creds.json
```

### 6.2 `relay secret list`
Lists all managed secret aliases without ever displaying cleartext values.

```bash
relay secret list
```

**Human Output:**
```text
ALIAS                  SCOPE       CREATED (UTC)          FINGERPRINT (SHA256)
──────────────────────────────────────────────────────────────────────────────
pg_prod_billing_role   default     2026-09-12 14:22:01    e3b0c44298fc1c14...
aws_prod_deployer      default     2026-09-10 09:15:33    8f4c2e7b1a90d3e5...
github_ops_token       ci          2026-09-08 18:02:49    1a7c3e5d90b2f4a1...
```

**JSON Output (`relay secret list --json`):**
```json
[
  {
    "alias": "pg_prod_billing_role",
    "scope": "default",
    "created_at": "2026-09-12T14:22:01Z",
    "fingerprint": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }
]
```

### 6.3 `relay secret remove`
Deletes a secret from the OS Keyring.

```bash
relay secret remove pg_prod_billing_role
# Output:
# ✔ Secret 'pg_prod_billing_role' deleted from OS Keyring.
```

---

## 7. Policy Authoring & Validation UX (`relay policy`)

Relay uses standard **AWS Cedar** (`.cedar`) policy files. Developers write readable, formal policies governing which tools agents can run.

### 7.1 Example Cedar Policy File (`policies/database.cedar`)

```cedar
// Allow read-only SELECT queries without prompting
permit (
    principal == Relay::Agent::"claude",
    action == Relay::Action::"tools/call",
    resource == Relay::Resource::"postgres/billing_db"
)
when {
    context.tool == "execute_sql" &&
    context.ast.statement_type == "SELECT"
};

// Require human approval on /dev/tty for updates or deletions
forbid (
    principal,
    action == Relay::Action::"tools/call",
    resource == Relay::Resource::"postgres/billing_db"
)
when {
    context.tool == "execute_sql" &&
    context.ast.statement_type in ["UPDATE", "DELETE", "DROP", "ALTER"]
}
unless {
    context.human_approved == true
};
```

### 7.2 `relay policy check`
Validates the syntax and schema consistency of all `.cedar` files in a policy directory.

```bash
relay policy check ./policies
```

**Output on Success:**
```text
✔ Validated 4 policy files (8 rules total) in 1.2ms.
  ├── ./policies/database.cedar (2 rules) [OK]
  ├── ./policies/filesystem.cedar (3 rules) [OK]
  ├── ./policies/github.cedar (2 rules) [OK]
  └── ./policies/aws.cedar (1 rule) [OK]
```

**Output on Syntax Error:**
```text
✖ Policy validation failed in ./policies/database.cedar:14:5
   │
14 │     context.tool == "execute_sql" &&
15 │     context.ast.statement_type in ["UPDATE", "DELETE"
   │                                                     ^ Unexpected token, expected ']'
   │
Error: 1 parse error encountered across 4 policy files.
```

### 7.3 `relay policy test`
Executes automated policy unit test suites against mock action contexts.

```bash
relay policy test ./policies/tests
```

**Output:**
```text
Running 6 policy tests...
  test database::test_select_permitted ... ok (0.3ms)
  test database::test_drop_table_forbidden ... ok (0.2ms)
  test filesystem::test_read_workspace_ok ... ok (0.2ms)
  test filesystem::test_write_etc_forbidden ... ok (0.2ms)
  test github::test_pr_create_prompt ... ok (0.3ms)
  test aws::test_s3_delete_forbidden ... ok (0.2ms)

Test result: 6 passed; 0 failed; 0 ignored in 1.4ms.
```

### 7.4 `relay policy list`
Displays a structured summary of all active policies, their conditions, and target resources.

```bash
relay policy list
```

---

## 8. Receipt & Verification UX (`relay verify` & `relay receipt`)

Every governed state mutation produces a cryptographically signed **in-toto v1.0 / DSSE (RFC 9598)** receipt signed by Relay's local Ed25519 keypair and recorded in the append-only SQLite WAL ledger.

### 8.1 `relay receipt list`
Queries the local SQLite ledger for recent receipts.

```bash
relay receipt list --limit 5
```

**Output:**
```text
RECEIPT ID                             TIMESTAMP (UTC)        TOOL              DECISION  STATUS   SIGNATURE
──────────────────────────────────────────────────────────────────────────────────────────────────────────────
rcpt_01J7N3A8QW9Z2Y1K0M4P5R6T7V        2026-09-12 14:30:11    postgres.execute  PROMPTED  SUCCESS  ed25519:9f8b...
rcpt_01J7N39Z8X7Y1W0V9U8T7S6R5Q        2026-09-12 14:29:45    postgres.execute  ALLOWED   SUCCESS  ed25519:3c2a...
rcpt_01J7N38K7J6H5G4F3E2D1C0B9A        2026-09-12 14:25:02    fs.write_file     FORBIDDEN DENIED   ed25519:7e1d...
```

### 8.2 `relay receipt show`
Inspects a specific receipt by ID, displaying the formatted provenance statement or raw DSSE JSON.

```bash
relay receipt show rcpt_01J7N3A8QW9Z2Y1K0M4P5R6T7V
```

**Human Output:**
```text
RECEIPT DETAILS: rcpt_01J7N3A8QW9Z2Y1K0M4P5R6T7V
──────────────────────────────────────────────────────────────────────────
Timestamp:        2026-09-12T14:30:11.412Z
Tool Name:        postgres.execute
Resource Target:  prod/billing_db
ActionHash:       sha256:8f4c2e7b1a90d3e5b61a4c8e7f2b1a0d9e8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a
Policy ID:        policy::billing_update_requires_mfa
Decision:         PROMPT (Approved by operator via /dev/tty)
Execution Status: SUCCESS (Execution duration: 14.2ms)
Ledger Chain:     Sequence #1042 (Previous Block: sha256:4a3b2c1d...)
Signer Identity:  ed25519:7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b
DSSE Envelope:    RFC 9598 compliant (in-toto v1.0 Statement)
```

**Raw JSON Output (`relay receipt show <ID> --json`):**
```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEuMCIsInN1YmplY3QiOlt7Im5hbWUiOiJyZWxheS9hY3Rpb24iLCJkaWdlc3QiOnsic2hhMjU2IjoiOGY0YzJlN2IxYTkwZDNlNWI2MWE0YzhlN2YyYjFhMGQ5ZThjN2I2YTVmNGUzZDJjMWIwYTlmOGU3ZDZjNWI0YSJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3JlbGF5LmRldi9wcm92ZW5hbmNlL3YwLjEiLCJwcmVkaWNhdGUiOnsidG9vbCI6InBvc3RncmVzLmV4ZWN1dGUiLCJkZWNpc2lvbiI6IlBST01QVCIsImFwcHJvdmFsIjoidHR5X2h1bWFuX29uY2UiLCJwb2xpY3lfaWQiOiJiaWxsaW5nX3VwZGF0ZV9yZXF1aXJlc19tZmEifX0=",
  "signatures": [
    {
      "keyid": "ed25519:7a8b9c0d1e2f3a4b",
      "sig": "MEYCIQDxK9...e4rT2=="
    }
  ]
}
```

### 8.3 `relay verify`
Verifies the cryptographic integrity of an action receipt file or ledger sequence.

```bash
# Verify receipt file directly
relay verify ./receipts/rcpt_01J7N3A8QW9Z2Y1K0M4P5R6T7V.json

# Verify entire local SQLite ledger chain
relay verify --ledger ~/.local/share/relay/ledger.db
```

**Output on Success:**
```text
✔ Receipt verification SUCCESSFUL.
  ├── DSSE envelope structure: VALID (RFC 9598)
  ├── in-toto Statement: VALID (v1.0)
  ├── ActionHash digest: MATCHED (sha256:8f4c2e7b...)
  ├── Ed25519 signature: VALID (Signed by local authority: ed25519:7a8b9c...)
  └── Ledger chain integrity: VALID (Block #1042 continuous from genesis)
```

---

## 9. Diagnostic Health Check UX (`relay doctor`)

`relay doctor` performs an end-to-end audit of Relay's local environment, verifying OS Keyring communication, signing keys, ledger permissions, Cedar policy directories, and TTY availability.

```bash
relay doctor
```

**Output:**
```text
Relay System Diagnostics (v0.1.0 - Linux x86_64)
──────────────────────────────────────────────────────────────────────────
[✔] Operating System Keyring: Accessible (Secret Service API / GNOME Keyring)
[✔] Local Signing Key: Found in Keyring (Ed25519 / Public Key: ed25519:7a8b9c0d...)
[✔] Ledger Database: Writable (~/.local/share/relay/ledger.db [WAL mode])
[✔] Ledger Chain Integrity: 1,042 blocks verified without corruption
[✔] Policy Store: 4 files parsed successfully (~/.config/relay/policies)
[✔] Loopback Proxy Engine: Ephemeral TCP port binding operational (127.0.0.1)
[✔] Controlling Terminal: /dev/tty accessible and interactive
[✔] Memory Locking Support: mlock() permitted (Resource limits OK)

Diagnostics: 8 checks passed, 0 warnings, 0 errors. Relay is ready for operation.
```

**Output with Failures & Actionable Remediation:**
```text
Relay System Diagnostics (v0.1.0 - Linux x86_64)
──────────────────────────────────────────────────────────────────────────
[✖] Operating System Keyring: UNAVAILABLE (DBus connection to org.freedesktop.secrets timed out)
    └─► FIX: Ensure gnome-keyring-daemon or kwallet is running, or export RELAY_KEYRING_FALLBACK=file.
[✖] Policy Store: FAILED (~/.config/relay/policies/database.cedar:14 syntax error)
    └─► FIX: Run `relay policy check` to view syntax errors and repair policy file.
[✔] Ledger Database: Writable (~/.local/share/relay/ledger.db)
[✔] Controlling Terminal: /dev/tty accessible

Diagnostics: 2 checks failed. Relay cannot guarantee zero-trust boundary.
```

---

## 10. Exit Codes & Scriptability

Relay adheres strictly to standard Unix exit code conventions to ensure deterministic behavior in scripts, wrappers, and CI/CD pipelines.

| Exit Code | Constant | Meaning / Trigger Condition |
| :--- | :--- | :--- |
| `0` | `EXIT_SUCCESS` | Subprocess terminated normally with code 0; all in-flight receipts flushed. |
| `1` | `EXIT_RUNTIME_ERROR` | Child MCP subprocess terminated with non-zero exit status or uncaught runtime crash. |
| `2` | `EXIT_CONFIG_ERROR` | Invalid CLI arguments, missing configuration file, or unparseable Cedar policy files. |
| `3` | `EXIT_POLICY_DENIED` | Governed action was denied by Cedar policy (in non-interactive / strict mode). |
| `4` | `EXIT_APPROVAL_DENIED` | Operator rejected action on `/dev/tty` or aborted approval session. |
| `5` | `EXIT_PROTOCOL_ERROR` | Malformed MCP JSON-RPC frame received from client or child subprocess. |
| `6` | `EXIT_SECURITY_FAILURE`| Keyring unavailable, signing key corrupted, or SQLite ledger tampering detected. |

---

## 11. Agent Client Configuration Templates

Relay requires zero code changes to agent clients or MCP servers. Configuration consists of prefixing the MCP launch command with `relay run --`.

### 11.1 Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "postgres-billing": {
      "command": "relay",
      "args": [
        "run",
        "--policy-dir",
        "/home/developer/.config/relay/policies",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-postgres",
        "postgresql://localhost:5432/billing_db"
      ]
    },
    "filesystem-governed": {
      "command": "relay",
      "args": [
        "run",
        "--",
        "uv",
        "run",
        "mcp-server-filesystem",
        "/home/developer/workspace"
      ]
    }
  }
}
```

### 11.2 Cursor IDE (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "aws-deployer": {
      "command": "relay",
      "args": [
        "run",
        "--strict",
        "--",
        "/usr/local/bin/mcp-aws-server"
      ]
    }
  }
}
```

### 11.3 CI / Headless Pipeline Integration (GitHub Actions)

```yaml
- name: Run Governed Agent Integration Test
  env:
    RELAY_NON_INTERACTIVE: "1"
    RELAY_STRICT: "1"
  run: |
    # Secret injected into ephemeral keyring before run
    echo "$CI_DB_TOKEN" | relay secret set pg_ci_role --from-stdin
    
    # Run test agent using Relay wrapper
    relay run -- ./bin/agent-task-runner --suite smoke
```

---

## 12. Developer Experience Invariants

To guarantee that Relay remains predictable, performant, and secure, implementation engineers must strictly observe the following developer experience invariants:

1. **The Pure Stdio Invariant:** `relay` must NEVER write anything to standard output (`stdout`) except valid MCP JSON-RPC 2.0 frames destined for the agent client. All logs, diagnostics, and human prompts belong strictly on `stderr` or `/dev/tty`.
2. **The Prompt Isolation Invariant:** Interactive approval prompts must bind directly to `/dev/tty` (or `CONIN$/CONOUT$`). If `/dev/tty` is unavailable, Relay must fail-closed on `PROMPT` policies unless `--non-interactive` is explicitly acknowledged.
3. **The Zero-Cleartext Invariant:** `relay secret list`, `relay receipt show`, and `/dev/tty` approval screens must NEVER render vaulted credential values in cleartext.
4. **The Sub-10ms Overhead Invariant:** The total roundtrip latency added by Relay (canonicalization, Cedar PDP evaluation, and ledger enqueueing) must not exceed 10 milliseconds for unprompted tool invocations.
5. **The Transparent Exit Invariant:** If the child MCP server exits voluntarily, Relay must flush all pending receipts and exit with the exact exit code of the child subprocess.

---

### Architectural Sign-Off

* **Developer Experience Architect:** *Approved*
* **Security & Invariants Review:** *Approved*
* **Implementation Target:** `relay-cli` crate (Rust workspace)
