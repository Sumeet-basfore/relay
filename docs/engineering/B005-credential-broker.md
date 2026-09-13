# Milestone B005: JIT Credential Broker & Secret-Isolation Boundary

**Status:** Completed & Verified  
**Milestone:** B005  
**Specification References:** [R010 JIT Credentials](../research/R010-jit-credentials.md), [A001 System Architecture](../architecture/A001-system-architecture.md), [A002 Domain Model](../architecture/A002-domain-model.md), [A003 Interfaces & Contracts](../architecture/A003-interfaces-and-contracts.md), [A004 Security Invariants](../architecture/A004-security-invariants.md), [A005 Test Strategy](../architecture/A005-test-strategy.md), [A006 Persistence & Storage](../architecture/A006-persistence-and-storage.md), [A008 Dependency Architecture](../architecture/A008-rust-dependency-architecture.md), [A010 Build Specification](../architecture/A010-build-specification.md)  
**Implementation Crates:** `crates/relay-domain`, `crates/relay-credentials`, `crates/relay-policy`

---

## 1. Executive Summary

Milestone B005 establishes Relay's **Just-In-Time (JIT) Credential Broker** and **Secret-Isolation Boundary**. 

In traditional AI agent architectures, long-lived target API keys, AWS credentials, and database passwords are injected directly into agent environment variables, command-line arguments, or disk configuration files. When an agent is compromised via prompt injection, hallucination, or tool poisoning, all persistent ambient credentials are fundamentally exposed.

Relay enforces the **Anti-Vault Principle**: Relay does not store static credentials at rest in domain databases, nor does it hand credentials to the agent process. Instead, Relay acts as a cryptographic PEP that holds credentials ephemerally in memory only during authorized action execution, downscopes authority, injects credentials at the execution boundary, and zeroes memory immediately upon drop.

```text
+----------------------------------------------------------------------------------------------------+
|                                    RELAY JIT CREDENTIAL LIFECYCLE                                  |
|                                                                                                    |
|  [Agent Workflow]  ───(Proposes Action)───►  [Cedar Policy PEP]  ───(Evaluates Policy & Scope)     |
|                                                     │                                              |
|                                                     ▼                                              |
|                                        [PolicyDecision::Allow]                                     |
|                                                     │                                              |
|                                                     ▼                                              |
|                                    [JitCredentialBroker::acquire]                                  |
|                                                     │                                              |
|                       +─────────────────────────────┼─────────────────────────────+                |
|                       ▼                             ▼                             ▼                |
|            [OS Keyring Provider]        [Encrypted File Fallback]     [In-Memory Test Provider]    |
|            (Keychain/SecretService)     (0700 dir, 0600 file AES-GCM) (Zeroized on drop)           |
|                       │                             │                             │                |
|                       +─────────────────────────────┼─────────────────────────────+                |
|                                                     │                                              |
|                                                     ▼                                              |
|                                         SecretBuffer (mlock pinned)                                |
|                                                     │                                              |
|                                                     ▼                                              |
|                                    CredentialLeaseGuard (Single-Use)                               |
|                                                     │                                              |
|                                                     ▼                                              |
|                                       Execution Dispatch (In-Flight)                                |
|                                                     │                                              |
|                                                     ▼                                              |
|                                         Drop ──► zeroize() + munlock                               |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Threat Model & Security Invariants

Milestone B005 specifically addresses the credential threats defined in [R005 Threat Model](../research/R005-threat-model.md) and enforces core security invariants:

| Threat Vector | Description | Relay Mitigation |
| :--- | :--- | :--- |
| **T-01: Prompt Injection Exfiltration** | LLM agent is coerced into dumping environment variables or memory strings. | **Zero Agent Exposure**: Credentials are never present in agent process memory, subprocess environment, or command-line arguments. |
| **T-02: Scope Creep & Lateral Movement** | Agent attempts to reuse credentials across unauthorized resources. | **Strict ActionHash Binding**: Leases are cryptographic single-use capability tokens bound to a single `ActionHash`, `PrincipalId`, and `ResourceUri`. |
| **T-03: Credential Replay & Hoarding** | Agent or compromised worker hoards expired or previously used tokens. | **SI-006 Single-Use Lease**: Leases are burned immediately upon consumption (`LeaseAlreadyConsumed`); expired leases reject access (`LeaseExpired`). |
| **T-04: RAM Swapping to Disk** | Operating system pages secret memory buffers to unencrypted swap space. | **Memory Pinning (`mlock`)**: Secrets in `SecretBuffer` invoke `libc::mlock` upon allocation and `libc::munlock` upon drop. |
| **T-05: Core Dump & Crash Leakage** | Process panic or crash writes core dumps containing secret material. | **`PR_SET_DUMPABLE` + Auto-Zeroization**: Core dumps disabled via Linux `prctl`; buffers zeroized on drop during stack unwinding. |
| **T-06: Log / Trace Leakage** | Secrets accidentally printed in `tracing` spans, `println!`, or error payloads. | **Custom `Debug` & `Display` Masking**: `SecretBuffer` and `CredentialLeaseGuard` mask all output (`[REDACTED ... bytes]`, `[REDACTED SECRET]`). |

---

## 3. Secret Lifecycle & In-Memory Protection

### 3.1 Protected Memory Container: `SecretBuffer`
`SecretBuffer` is Relay's protected in-memory secret container:
* **Memory Locking (`mlock`):** On allocation (`SecretBuffer::new`), Relay invokes `libc::mlock(ptr, len)`. If `mlock` fails (e.g. `RLIMIT_MEMLOCK` exceeded on unprivileged containers), Relay logs a diagnostic warning and proceeds with memory zeroization only, documenting the residual swapping risk.
* **Auto-Zeroization on Drop:** Implements `zeroize::Zeroize` and a custom `Drop` handler. Upon drop:
  1. Overwrites all secret bytes with `0x00` in RAM using volatile memory writes.
  2. Calls `libc::munlock(ptr, len)` if memory locking was established.
* **Redaction Discipline:**
  - `fmt::Debug` prints `SecretBuffer([REDACTED <len> bytes])`.
  - `fmt::Display` prints `[REDACTED SECRET]`.
  - Implements negative traits: `SecretBuffer` **NEVER** implements `Clone`, `Serialize`, or `Deserialize`.
* **Scoped Access:** Exposes secret bytes exclusively through scoped closures (`expose_scoped<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R`) to minimize the lifetime of references in calling registers.

### 3.2 Affine RAII Token: `CredentialLeaseGuard`
From [A003 Interfaces & Contracts](../architecture/A003-interfaces-and-contracts.md) §5.1, Relay wraps leased secrets in `CredentialLeaseGuard`:
```rust
pub struct CredentialLeaseGuard {
    lease_id: LeaseId,
    secret: SecretBuffer,
    expires_at: DateTime<Utc>,
}
```
* Access is gated by `use_secret` and `use_secret_bytes`.
* If `Utc::now() > expires_at`, access immediately fails with `CredentialError::LeaseExpired`.
* `CredentialLeaseGuard` cannot be cloned or serialized. Dropping the guard immediately drops the enclosed `SecretBuffer`, scrubbing memory.

---

## 4. Credential Broker & Lease Architecture

### 4.1 Lookup Authorization & Anti-Bypass
To prevent the broker from acting as an authorization bypass, raw key lookups (e.g. `broker.get_secret("gh-token")`) are forbidden.

Every credential acquisition requires an explicit, strongly typed `CredentialRequest` AND a valid `PolicyDecision`:
```rust
pub struct CredentialRequest {
    pub action_hash: ActionHash,
    pub principal: PrincipalId,
    pub resource: ResourceUri,
    pub provider: CredentialProviderType,
    pub key_alias: String,
    pub target_system: String,
    pub scope: String,
    pub ttl_seconds: u32,
}
```

The broker executes strict invariant checks before leasing:
1. **Policy Decision Verification:**
   - If `decision.decision == PolicyDecisionType::Deny` $\to$ Returns `CredentialError::AccessDenied`.
   - If `decision.decision == PolicyDecisionType::ApprovalRequired` $\to$ Returns `CredentialError::ApprovalRequired`.
   - Only `PolicyDecisionType::Allow` permits acquisition.
2. **ActionHash Cryptographic Binding (SI-006):**
   - Verifies `request.action_hash == decision.action_hash`. Mismatches immediately reject with `CredentialError::ActionHashMismatch`.
3. **Scope & TTL Validation:**
   - Empty or whitespace scopes return `CredentialError::InvalidScope`.
   - TTLs outside $[1\text{s}, 3600\text{s}]$ return `CredentialError::InvalidScope`.
4. **Provider Resolution:**
   - Looks up registered `CredentialProvider`. Missing providers return `CredentialError::NotFound`.
5. **Single-Action Ephemeral Lease Minting:**
   - Issues a `CredentialLease` with UUIDv7 `lease_id`, bound to `action_hash`, `principal`, `provider`, `key_identifier`, `target_system`, `scoped_resource`, and expiry timestamp.
   - Registers the lease in the broker's active lease table.
6. **Burning / Single-Use Consumption:**
   - Once executed, `broker.consume_lease(&lease_id)` transitions state from `Issued` to `Consumed`.
   - Any secondary attempt to consume or validate the lease fails with `CredentialError::LeaseAlreadyConsumed`.

---

## 5. Credential Provider Implementations

### 5.1 `KeyringCredentialProvider` (OS Keyring Tier)
* **Underlying Engine:** Cross-platform `keyring` crate utilizing OS security daemons:
  - Linux: Secret Service API / D-Bus (`libsecret-1.so`)
  - macOS: Apple Keychain Services
  - Windows: Windows Credential Manager (DPAPI)
* **Service Namespace:** Default `io.relay.gateway` (per A006 §3.1).
* **Binary-Safe Secret Resolution:** Uses `entry.get_secret()` and `entry.set_secret(&[u8])` to handle arbitrary binary tokens without intermediate string reallocations.
* **Sanitized Failure:** Errors return `CredentialError::KeyringUnavailable` or `CredentialError::NotFound`, never leaking secret material in error descriptions.

### 5.2 `EncryptedFileCredentialProvider` (Headless / CI Fallback)
When running in headless Linux containers or CI runners without D-Bus or X11:
* **Location:** Base directory (e.g. `~/.relay/keys`) enforced with POSIX `0700` directory permissions.
* **File Permissions:** Credential files created with strict POSIX `0600` permissions.
* **Authenticated Encryption:**
  - Keystream: SHA-256 counter mode (CTR) derived from master key, key alias, and UUIDv7 16-byte nonce.
  - Authentication Tag: SHA-256 HMAC tag over nonce, ciphertext, and key alias.
  - Constant-time MAC comparison prevents timing side-channels.
  - File format: `[16 bytes nonce] [32 bytes MAC] [ciphertext]`.
* **Tamper-Evident:** Any bit flip in ciphertext or MAC header causes immediate `CredentialError::ProviderError` rejection.

### 5.3 `InMemoryCredentialProvider` (Deterministic Testing Tier)
* Thread-safe in-memory provider using `Arc<RwLock<HashMap<String, SecretBuffer>>>`.
* Pre-seeded with deterministic fixtures during integration and adversarial testing.
* Zeroized on drop.

---

## 6. Security Guarantees & Non-Guarantees

### What Relay Guarantees
1. **Zero Agent Credentials:** The agent process never possesses raw API keys or database passwords.
2. **Deterministic Fail-Closed:** If policy denies, approval is missing, ActionHash mismatches, or keyring fails, zero credentials are released.
3. **Cryptographic Binding:** Ephemeral leases cannot be used for any action other than the exact `ActionHash` authorized by Cedar.
4. **Single-Use Affine Consumption:** Leases cannot be hoarded, shared across concurrent tasks, or replayed.
5. **No Plaintext Persistence:** Raw secrets never enter SQLite ledger tables, configuration files, or logs.
6. **Automatic Zeroization:** Secret memory is scrubbed with zeroes when dropped, even during panic unwinding.
7. **No Ambient Leakage:** Credentials are never passed via child process environment variables or command-line arguments.

### What Relay Does NOT Guarantee
1. **Host Root / Kernel Compromise:** If an attacker has `root` / `CAP_SYS_PTRACE` on the host, they can inspect process memory (`/proc/$PID/mem`) while a secret is actively in-flight.
2. **Hardware Fault Injection:** Relay does not mitigate physical side-channel or Rowhammer attacks on unprivileged RAM.
3. **Unprivileged Memory Locking Guarantees:** When running in unprivileged Docker containers where `RLIMIT_MEMLOCK` is zero or restricted, Linux `mlock` will return `EPERM`/`ENOMEM`. Relay logs this residual swap risk, relying on memory zeroization.
4. **Upstream Token Revocation Propagation:** If Relay mints a 1-hour GitHub installation token and the process is killed abruptly (`kill -9`), Relay cannot actively revoke the token upstream before natural expiration.

---

## 7. Performance Benchmarks

Measured on Linux x86_64 (`cargo test -p relay-credentials --test performance_tests -- --nocapture`):

```text
=======================================================
  RELAY B005 CREDENTIAL BROKER PERFORMANCE BENCHMARKS  
=======================================================
[Lease Create + Validate] Iterations: 1000, Total: 18.23ms, Avg: 18.23 µs/op
  TARGET:   < 500.00 µs/op
  MEASURED: 18.23 µs/op (PASS - 27x faster than SLA)

[SecretBuffer Memory Zeroization] Iterations: 10000, Total: 4.48ms, Avg: 447.96 ns/op
  TARGET:   < 1,000.00 ns/op
  MEASURED: 447.96 ns/op (PASS - 2.2x faster than SLA)

[Concurrent Throughput] 50 workers x 100 ops = 5000 total ops in 70.59ms
  TARGET:   > 5,000 ops/sec
  MEASURED: 70,830.37 ops/sec (PASS - 14.1x faster than SLA)
=======================================================
```

---

## 8. Test Suite Summary

The B005 milestone adds 37 focused automated tests across 5 test targets, bringing the total workspace test count to **179 passing tests**:

| Test Target | Tests | Description | Status |
| :--- | :---: | :--- | :---: |
| `tests/keyring_tests.rs` | 5 | Keyring lookup, EncryptedFile provider, 0600 permissions, MAC tampering, formatting hygiene | 🟢 PASS |
| `tests/lease_tests.rs` | 6 | Issuance, ActionHash mismatch, scope validation, single-use consumption, revocation, expiry purge | 🟢 PASS |
| `tests/cedar_integration_tests.rs` | 4 | Cedar ALLOW $\to$ Lease, Cedar DENY $\to$ AccessDenied, APPROVAL_REQUIRED $\to$ blocked | 🟢 PASS |
| `tests/security_tests.rs` | 6 | `SecretBuffer` & Guard redaction, zeroization, mlock status, subprocess env/arg isolation, lease isolation | 🟢 PASS |
| `tests/adversarial_tests.rs` | 15 | 15 attack vectors: forged hashes, principal spoofing, panic unwinding, MAC tampering, reuse prevention | 🟢 PASS |
| `tests/performance_tests.rs` | 1 | Benchmarking lease creation, validation, zeroization, and concurrent throughput | 🟢 PASS |

---

## 9. Handoff to Milestone B006 (Native Connectors)

Milestone B006 will implement native in-process connectors for GitHub (`reqwest`), PostgreSQL (`tokio-postgres`), and Filesystem operations.

### How the Future GitHub Connector Consumes Credentials
1. **Agent proposes tool call:** `github.create_pull_request({ title, branch, repo })`.
2. **Canonicalization & Cedar evaluation:**
   - Canonicalizes arguments into `CanonicalAction` with `ActionHash`.
   - Cedar evaluates policy $\to$ produces `PolicyDecision::Allow`.
3. **Connector requests credential lease:**
   ```rust
   let cred_req = CredentialRequest::new(
       decision.action_hash,
       auth_request.principal.clone(),
       auth_request.resource.clone(),
       CredentialProviderType::GithubApp,
       "github_app_default",
       "https://api.github.com",
       "repo:relay/core:pull_requests:write",
       300,
   );
   
   let (lease, guard) = credential_broker.acquire_lease_guard(&cred_req, &decision).await?;
   ```
4. **Scrubbed In-Flight Dispatch:**
   ```rust
   let response = guard.use_secret(|token| {
       client.post("https://api.github.com/repos/relay/core/pulls")
           .bearer_auth(token)
           .json(&canonical_payload)
           .send()
   })?;
   ```
5. **Affine Lease Burning:**
   - The connector burns the lease immediately upon execution completion:
     ```rust
     credential_broker.consume_lease(&lease.lease_id).await?;
     ```
   - Dropping `guard` sweeps the secret buffer with zeroes in RAM.
   - The connector never accesses the OS Keyring directly, never knows where the secret was stored, and retains zero residual credentials in memory.
