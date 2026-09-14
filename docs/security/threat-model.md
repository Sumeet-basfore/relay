# Relay Threat Model

**Document ID:** `SEC-TM-001`  
**Version:** `0.1.0`  
**Author:** Principal Security Architect  
**Status:** Approved Baseline  

---

## 1. System Assets

Relay protects and manages the following primary system assets:

| Asset | Sensitivity | Integrity Impact | Confidentiality Impact | Protection Mechanism |
|:---|:---:|:---:|:---:|:---|
| **Target Credentials** (PATs, DB passwords) | Critical | High | Critical | OS Keyring / AES-256-GCM, zero ambient delivery, JIT lease memory zeroization |
| **Node Signing Key** (`signing_key.seed`) | Critical | Critical | Critical | Mode `0600`, zeroized in RAM on `Drop`, isolated from child process |
| **Cedar Security Policies** (`*.cedar`) | High | Critical | Low | Loaded from local filesystem, bound via SHA-256 policy digest (SI-010) |
| **Local Filesystem Resources** | High | Critical | Critical | Root jail confinement, lexical normalization, path canonicalization |
| **PostgreSQL Database Resources** | High | Critical | Critical | SQL AST canonicalization, JIT credential injection, TLS encryption |
| **GitHub Repository Resources** | High | Critical | Critical | Path/repo canonicalization, JIT PAT injection, TLS verification |
| **Action Receipts & Audit Ledger** | High | Critical | Medium | Ed25519 DSSE envelopes, SHA-256 hash chaining, SQLite immutability triggers |
| **Operator Approvals** | High | Critical | Low | Direct `/dev/tty` prompt, non-reusable nonce cryptographically bound to `ActionHash` |

---

## 2. Adversary Profiles

Relay models nine adversary archetypes:

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                                ADVERSARY PROFILES                                │
├────────────────────────────────┬─────────────────────────────────────────────────┤
│ 1. Prompt-Injected Agent       │ Attacker controls agent LLM context, instructions,│
│                                │ and outputs via malicious indirect prompt injection.│
├────────────────────────────────┼─────────────────────────────────────────────────┤
│ 2. Malicious Tool Arguments    │ Attacker attempts argument smuggling, SQL injection,│
│                                │ path traversal, or JSON key duplication.        │
├────────────────────────────────┼─────────────────────────────────────────────────┤
│ 3. Compromised MCP Server      │ Malicious downstream subprocess attempts to steal│
│                                │ parent environment or forge JSON-RPC frames.    │
├────────────────────────────────┼─────────────────────────────────────────────────┤
│ 4. Unprivileged Local Attacker │ Local OS user on same machine attempts to read   │
│                                │ Relay memory, config files, ledger, or keys.     │
├────────────────────────────────┼─────────────────────────────────────────────────┤
│ 5. Stale Approval Replayer     │ Attacker captures a valid human approval and     │
│                                │ attempts to replay it against mutated actions.  │
├────────────────────────────────┼─────────────────────────────────────────────────┤
│ 6. Credential Thief            │ Attacker attempts to exfiltrate long-lived       │
│                                │ target API keys from memory or subprocess env.  │
├────────────────────────────────┼─────────────────────────────────────────────────┤
│ 7. Policy Bypass Adversary     │ Attacker attempts to craft edge-case syntax to   │
│                                │ circumvent default-deny Cedar rules.            │
├────────────────────────────────┼─────────────────────────────────────────────────┤
│ 8. Evidence Tamperer           │ Attacker attempts to rewrite or truncate historical│
│                                │ ledger entries after executing malicious actions│
├────────────────────────────────┼─────────────────────────────────────────────────┤
│ 9. Ambiguous State Exploiter   │ Attacker forces network timeouts to cause        │
│                                │ desynchronization between agent and target.     │
└────────────────────────────────┴─────────────────────────────────────────────────┘
```

---

## 3. Concrete Threat Analysis

### Threat T-01: Indirect Prompt Injection / Full Agent Subversion
- **Threat:** An external webpage, repository file, or database record contains an indirect prompt injection payload that completely subverts the LLM's behavioral alignment.
- **Attack Preconditions:** Agent reads untrusted data and executes instructions dictated by the injection.
- **Attack:** The compromised agent invokes tools to exfiltrate SSH keys (`fs.read_file path="/home/user/.ssh/id_rsa"`), drop database tables (`postgres.query sql="DROP TABLE users"`), or delete GitHub repositories.
- **Relay Control:** Strict Cedar PEP authorization enforces default-deny and explicit `forbid` rules regardless of natural-language intent. Sensitive file paths (`.ssh`, `.env`) are blocked at policy level. Destructive actions require human step-up approval on `/dev/tty`.
- **Expected Result:** Action is rejected with `ExitCode::PolicyDenied` (`3`) or `ExitCode::ApprovalDenied` (`4`).
- **Residual Risk:** Actions explicitly permitted by administrator policy (e.g. reading a file within the permitted workspace) can still be executed by the compromised agent.

---

### Threat T-02: Path Traversal & Symlink Escapes
- **Threat:** Agent attempts to escape designated workspace root directory to access sensitive operating system files.
- **Attack Preconditions:** Agent invokes `fs.read_file` or `fs.write_file` with relative paths containing `../` or symlinks pointing outside the workspace.
- **Attack:** `path = "../../etc/shadow"` or `path = "symlink_to_root/etc/passwd"`.
- **Relay Control:** Lexical path canonicalizer normalizes paths, resolves components against the configured root jail, and rejects symlink traversal by default (`follow_symlinks = false`). Prohibited system directories (`/etc`, `/proc`, `/sys`, `~/.ssh`) are forbidden unconditionally.
- **Expected Result:** Request rejected with `ExitCode::PolicyDenied` (`3`) or `CanonicalizationFailed` (`-32602`).
- **Residual Risk:** None within the configured root jail when symlinks are disabled.

---

### Threat T-03: SQL Injection & AST Normalization Divergence
- **Threat:** Agent submits malicious SQL queries designed to alter statement semantics or execute unauthorized data modification.
- **Attack Preconditions:** Agent has permission to execute `SELECT` queries on a database.
- **Attack:** `sql = "SELECT * FROM orders; DROP TABLE customers; --"` or parameter injection manipulating table names.
- **Relay Control:** Full AST parsing via `sqlparser-rs` normalizes statements into canonical representation. Multi-statement batches are decomposed; DDL statements (`DROP`, `ALTER`, `TRUNCATE`) are strictly classified as DDL actions and denied under read-only policies.
- **Expected Result:** Denied at policy evaluation; single-statement read policies reject batched or mutating queries.
- **Residual Risk:** Database-side stored procedures or functions (`SECURITY DEFINER`) that perform internal mutations when invoked via `SELECT`.

---

### Threat T-04: Ambient Credential Theft via Subprocess Environment
- **Threat:** Agent or malicious MCP child process scans environment variables (`env`, `/proc/self/environ`) to harvest target API keys.
- **Attack Preconditions:** Subprocess spawned on host.
- **Attack:** Subprocess executes `printenv` or reads `/proc/$PPID/environ`.
- **Relay Control:** Relay uses `tokio::process::Command::env_clear()` and an explicit whitelist of safe system variables (`PATH`, `HOME`, `USER`, `LANG`). Target API tokens (`GITHUB_TOKEN`, `PGPASSWORD`, `AWS_SECRET_ACCESS_KEY`) are scrubbed before spawning.
- **Expected Result:** Child process sees zero target credentials.
- **Residual Risk:** Compromised host kernel allowing root memory inspection across process boundaries.

---

### Threat T-05: Stale Approval Reuse & Parameter Mutation
- **Threat:** Attacker intercepts a human approval for a benign action and replays the approval token for a malicious action.
- **Attack Preconditions:** Operator approved action $A_1$. Attacker attempts to execute $A_2$.
- **Attack:** Attacker substitutes parameter payload while attaching $A_1$'s approval ID.
- **Relay Control:** Approvals are cryptographically bound to the canonical `ActionHash` (SHA-256 of RFC 8785 JCS payload). When $A_2$ is dispatched, Relay recomputes `ActionHash(A_2)`. If `approval.action_hash != ActionHash(A_2)`, approval verification fails closed. Nonces are single-use and burned upon dispatch.
- **Expected Result:** Execution rejected with `ActionHashMismatch` / `SecurityFailure` (`6`).
- **Residual Risk:** None; cryptographic binding prevents cross-action approval reuse.

---

### Threat T-06: Historical Ledger Tampering & Log Truncation
- **Threat:** Attacker modifies, deletes, or truncates SQLite ledger rows to conceal unauthorized activity.
- **Attack Preconditions:** Attacker obtains write access to the SQLite file `ledger.db`.
- **Attack:** Attacker modifies `payload` or deletes rows in `ledger_entries` or `receipts`.
- **Relay Control:** SQLite database enforces `BEFORE UPDATE` and `BEFORE DELETE` triggers. Each ledger entry contains a SHA-256 `entry_hash = SHA256(seq || parent_hash || payload_hash)`. Offline forensic verifier (`relay verify`) detects sequence gaps, payload hash mismatches, and signature corruption.
- **Expected Result:** `relay verify` outputs `✗ FAILED: BrokenChain / PayloadHashMismatch` with exit code `6`.
- **Residual Risk:** An attacker who has write access to the disk can destroy the file entirely; Relay guarantees **tamper-evidence**, not physical hardware write-once durability (WORM).

---

### Threat T-07: Ambiguous Network Timeout & Desynchronization
- **Threat:** Network connection drops or times out after Relay dispatches a mutating HTTP or SQL request to a remote server.
- **Attack Preconditions:** Network packet loss or endpoint lag during GitHub issue creation or Postgres transaction.
- **Attack:** Agent assumes action failed and blindly retries, causing duplicate mutations, or assumes action succeeded when it failed remotely.
- **Relay Control:** Relay explicitly refuses to manufacture success or pretend rollback occurred. It generates an `ActionReceipt` with `GovernanceStatus::AmbiguousMutation` and `ExecutionObservationStatus::Undetermined`, recording the exact timeout and preventing automated retry without operator awareness.
- **Expected Result:** Execution returns error `-32010 Ambiguous Mutation`, signed receipt records the uncertainty in the ledger.
- **Residual Risk:** The remote target service may have executed the mutation or discarded it; manual reconciliation may be required.

---

### Threat T-08: Subprocess Raw Socket Bypass & Cloud Metadata SSRF / DNS Rebinding
- **Threat:** Malicious MCP subprocess bypasses proxy environment variables using direct raw socket syscalls (`socket(AF_INET, SOCK_STREAM)`), or queries cloud metadata (`169.254.169.254`) / internal subnets via DNS rebinding.
- **Attack Preconditions:** Untrusted or compromised third-party MCP server binary executed as a child process.
- **Attack:** Subprocess attempts direct TCP egress to arbitrary C2 servers, or connects to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` via proxy.
- **Relay Control:** 
  1. On Linux, subprocess is spawned inside unprivileged User and Network Namespaces (`CLONE_NEWUSER | CLONE_NEWNET` - SI-023), causing direct raw socket syscalls to fail with `ENETUNREACH`.
  2. Proxy DNS resolver evaluates target hostnames and resolved IP addresses against a strict blacklist (`169.254.0.0/16`, `fd00:ec2::254`, `metadata.google.internal`, RFC 1918) before connection dispatch (SI-022).
  3. Resolved IP addresses are pinned for subsequent connections to prevent DNS rebinding.
- **Expected Result:** Direct socket attempts fail (`ENETUNREACH`); metadata queries rejected with HTTP 403 Forbidden (`BlockedMetadataOrPrivateIp`).
- **Residual Risk:** On macOS and Windows, direct raw socket syscalls bypass proxy variables in Managed Cooperative Mode (documented limitation).

---

### Threat T-09: Proxy Lease Forgery, Replay & Upstream Credential Interception
- **Threat:** Adversary attempts to forge proxy lease tokens, replay expired tokens, or inspect network traffic to steal vaulted API keys.
- **Attack Preconditions:** Subprocess has access to local loopback interface.
- **Attack:** Attacker crafts requests with fabricated `Proxy-Authorization` headers, reuses old tokens after tool completion, or attempts to read secrets from proxy responses.
- **Relay Control:**
  1. Lease tokens are cryptographically generated UUID v7 tokens with 30s TTL, bound to `ActionHash` and `Principal` (SI-020).
  2. All leases tied to an `ActionHash` are burned upon tool completion. Replays return HTTP 407.
  3. Real target credentials remain vaulted inside Relay and are injected into upstream TLS headers; child processes only hold ephemeral lease tokens and never observe target secrets (SI-021).
  4. Hop-by-hop headers (`Proxy-Authorization`, `Connection`, `Relay-Proxy-Auth`) are stripped before upstream dispatch.
- **Expected Result:** Forged or replayed requests fail with HTTP 407 Proxy Authentication Required; zero credentials leaked to child.
- **Residual Risk:** None within the memory and process isolation boundaries of the host OS.
