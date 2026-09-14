# Relay v0.1.0 — Golden Reference Demo Presentation Script

**Target Audience:** Security Engineers, AI Platform Engineers, Enterprise Architects  
**Duration:** 10 Minutes  
**Format:** Live Terminal / CLI Walkthrough  

---

## 00:00 — Introduction: The AI Agent Security Problem

**Visual:** Clean terminal showing `./scripts/demo/setup.sh` output.

**Presenter:**
> "Modern AI agents operate with high autonomy. When an agent is connected to tools via the Model Context Protocol (MCP), it typically inherits ambient credentials—such as GitHub tokens, database passwords, or filesystem permissions. If that agent suffers a prompt-injection attack, an attacker inherits all of those ambient privileges.
>
> Relay solves this through a local-first security architecture founded on three principles: **Authority, Credential Isolation, and Evidence**. Relay intercepts MCP communications over stdio, deterministically canonicalizes requests with RFC 8785 JCS, evaluates declarative Cedar policies, injects credentials only just-in-time, isolates external subprocesses inside Linux network namespaces, and records cryptographic in-toto DSSE receipts into an append-only SQLite hash-chain ledger.
>
> Let's see this in action."

---

## 01:00 — Scene 1: Authorized Action Execution

**Command:**
```bash
./scripts/demo/run.sh
```

**Presenter:**
> "In Scene 1, our agent issues an MCP tool call `demo_read_public` targeting `fixtures/public.txt`.
>
> Notice what happens behind the scenes: Relay receives the JSON-RPC request over stdio, canonicalizes the arguments, and queries the Cedar Policy Engine. Because our policy explicitly permits reads to `public.txt`, Cedar evaluates to `ALLOW`. Relay allows execution to proceed, records the action in the cryptographic ledger, and returns the contents cleanly to the agent."

---

## 02:00 — Scene 2: Prompt-Injection Defense (Unauthorized Action Denied)

**Presenter:**
> "Now consider Scene 2. The agent has been compromised via indirect prompt injection and attempts to read a confidential file: `fixtures/protected.txt`.
>
> In an unmediated setup, the agent would read the file immediately. But Relay intercepts the call. Cedar matches the `@id("forbid_protected_assets")` policy and returns a strict `DENY`. The execution is blocked fail-closed before any bytes are read. The agent receives an error, and zero confidential data is disclosed."

---

## 03:00 — Scene 3 & 4: Scoped Mutation & Interactive Human Approval

**Presenter:**
> "Next, what about state mutations? In Scene 3, the agent writes output data to `fixtures/output/result.txt`. Because the target path is within the scoped output directory, write permissions are granted.
>
> In Scene 4, when the agent attempts a file deletion, Cedar policy triggers `@advice("REQUIRE_HUMAN_APPROVAL")`. Relay pauses execution and opens an out-of-band prompt on `/dev/tty`. The human operator sees the exact canonical action hash, resource path, and principal before approving or denying the request. If approved, the action executes; if denied or timed out, it fails closed."

---

## 04:00 — Scene 5: Credential Isolation & Zero Ambient Secrets

**Presenter:**
> "Let's inspect the credential boundary. In an unmediated environment, environment variables like `GITHUB_TOKEN` or `AWS_SECRET_ACCESS_KEY` reside directly in process memory.
>
> In Relay, external subprocesses run in a sanitized environment. When our demo tool `attack_exfiltrate_credentials` inspects `os.environ`, `/proc/self/environ`, and disk, zero target credentials exist. Credentials are held exclusively in Relay's encrypted in-memory broker and injected just-in-time into outbound requests."

---

## 05:00 — Scene 6: Adversarial External MCP Sandboxing & Anti-SSRF

**Presenter:**
> "What if the tool server itself is malicious or compromised? Here we execute five distinct attack probes:
>
> 1. **Localhost Escape:** The server attempts to connect to `127.0.0.1:8080`. Result: **BLOCKED**.
> 2. **Cloud Metadata SSRF:** The server attempts to access AWS/GCP IMDS at `169.254.169.254`. Result: **BLOCKED** under Invariant SI-022.
> 3. **Private Network Probe:** The server attempts to access internal subnets (`10.0.0.1`). Result: **BLOCKED** by Cedar destination allowlists.
> 4. **Raw Socket Bypass:** The server attempts a raw TCP socket connection bypassing HTTP proxy variables. On Linux, Relay executes the subprocess in an isolated Network Namespace (`CLONE_NEWNET`) with no default gateway. The attempt immediately receives `ENETUNREACH`.
> 5. **Post-Action Session Reuse:** The server attempts an outbound request after the action has completed. The request is rejected because the ephemeral proxy session token has burned."

---

## 07:00 — Scene 7: Cryptographic Receipt Verification

**Command:**
```bash
relay verify --ledger .relay/ledger.db
```

**Presenter:**
> "Every governed action produces an immutable in-toto Statement wrapped in an RFC 9598 DSSE cryptographic envelope and signed with an Ed25519 key.
>
> Running `relay verify` validates the cryptographic signatures, confirms that the action payload hash matches the signed statement, and verifies that the policy set digest remains unchanged."

---

## 08:00 — Scene 8: SQLite Hash-Chain Ledger Verification

**Presenter:**
> "Relay records every receipt into an append-only SQLite hash-chain ledger. Each entry's `entry_hash` is computed over the previous entry hash and the current receipt hash.
>
> In addition, SQLite write-once triggers prevent any SQL `UPDATE` or `DELETE` commands on ledger entries, guaranteeing database immutability."

---

## 09:00 — Scene 9: Live Tamper Detection Demonstration

**Presenter:**
> "To prove that this evidence is cryptographically real, we create a copy of the ledger database and flip a single byte in storage.
>
> When we run `relay verify --ledger .relay/tampered_ledger.db`, Relay immediately detects the hash mismatch and signature invalidity, exiting with an error. Tampering is mathematically impossible to hide."

---

## 10:00 — Conclusion & Security Boundary Boundaries

**Presenter:**
> "In summary:
> - Same agent, same MCP server, same environment.
> - Authorized actions succeed seamlessly.
> - Unauthorized actions, credential thefts, SSRF attacks, and raw network bypasses fail closed.
> - Every action produces non-repudiable cryptographic proof.
>
> For full technical details and architecture documentation, consult `docs/architecture/` and the reproduce guide in `docs/demo/reproduce.md`. Thank you."
