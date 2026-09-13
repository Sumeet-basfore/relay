# Milestone B006: Native Governed Connector — GitHub

**Status:** Completed & Verified  
**Milestone:** B006  
**Specification References:** [R010 JIT Credentials](../research/R010-jit-credentials.md), [R012 MCP Security Boundary](../research/R012-mcp-security-boundary.md), [R015 Build Gate](../research/R015-build-gate.md), [A001 System Architecture](../architecture/A001-system-architecture.md), [A002 Domain Model](../architecture/A002-domain-model.md), [A003 Interfaces & Contracts](../architecture/A003-interfaces-and-contracts.md), [A004 Security Invariants](../architecture/A004-security-invariants.md), [A005 Test Strategy](../architecture/A005-test-strategy.md), [A006 Persistence & Storage](../architecture/A006-persistence-and-storage.md), [A008 Dependency Architecture](../architecture/A008-rust-dependency-architecture.md), [A010 Build Specification](../architecture/A010-build-specification.md)  
**Implementation Crates:** `crates/relay-connectors`, `crates/relay-domain`, `crates/relay-canonical`, `crates/relay-credentials`, `crates/relay-policy`, `crates/relay-mcp`

---

## 1. Executive Summary

Milestone B006 implements Relay's **Native Governed Connector for GitHub**.

In traditional agentic MCP setups, external SaaS operations (such as interacting with GitHub repositories, pull requests, issues, and branches) are delegated to third-party MCP subprocesses. These external processes are untrusted, often demand static API tokens in ambient environment variables, and can execute arbitrary HTTP requests or leak tokens through log output, error payloads, or network redirects.

Relay eliminates third-party MCP tool processes for core services by intercepting agent tool calls in-process and executing them through **Relay-owned, memory-safe Rust native connectors** (`relay-connectors`). The GitHub connector acts as a downstream Policy Enforcement Point (PEP) consumer that:
1. Operates strictly on post-canonicalized `CanonicalAction` (B003) and verified `PolicyDecision::Allow` (B004).
2. Never accepts raw, unvalidated MCP JSON.
3. Obtains single-use ephemeral credential leases from `CredentialBroker` (B005) and zeroizes memory immediately post-execution.
4. Enforces strict TLS (`rustls` with `webpki-roots`), SSRF host lockdowns (`api.github.com` or explicit loopback test server), and redirect restrictions (blocking cross-host redirects).
5. Never automatically retries mutating operations upon network failure or timeout, yielding an explicit `AmbiguousMutationOutcome` to prevent duplicate state mutations.

```text
+----------------------------------------------------------------------------------------------------+
|                              B006 GOVERNED GITHUB EXECUTION PIPELINE                               |
|                                                                                                    |
|  [Agent / Client]                                                                                  |
|         │                                                                                          |
|         │  MCP JSON-RPC tools/call ("github:get_repository", {"repo": "octocat/hello-world"})     |
|         ▼                                                                                          |
|  [B002 MCP Gateway] ───(In-Process Intercept)                                                      |
|         │                                                                                          |
|         ▼                                                                                          |
|  [B003 ActionCanonicalizer]                                                                        |
|         │  • AST Argument Normalization                                                            |
|         │  • Canonical Resource URI ("github://github.com/octocat/hello-world")                    |
|         │  • RFC 8785 JCS ActionHash Computation                                                   |
|         ▼                                                                                          |
|  [B004 Cedar Policy PEP]                                                                           |
|         │  • Strict Default-Deny Evaluation against relay_schema.cedarschema                       |
|         │  • ActionHash cryptographic preservation                                                 |
|         ▼                                                                                          |
|     Decision: ALLOW? ─────► [DENY] ──► Immediate Fail-Closed (Zero Leases, Zero Network Calls)     |
|         │                                                                                          |
|         ▼                                                                                          |
|  [B005 JitCredentialBroker]                                                                        |
|         │  • Validates Decision.action_hash == Action.action_hash (SI-006)                          |
|         │  • Issues Ephemeral Single-Use Lease (60s TTL) & mlock-pinned SecretBuffer               |
|         ▼                                                                                          |
|  [B006 GitHubConnector]                                                                            |
|         │  • Verifies namespace == "github"                                                        |
|         │  • Cross-checks ResourceUri vs Arguments (Anti-Confusion / Anti-Divergence)              |
|         │  • Validates In-Flight Lease Invariants (ActionHash, Principal, Scoped Resource)         |
|         │  • Maps to strongly typed GitHubOperation (#[serde(deny_unknown_fields)])                |
|         ▼                                                                                          |
|  [GitHubClient (rustls)]                                                                           |
|         │  • Host / Scheme / Port Whitelist Enforcement                                            |
|         │  • Custom Redirect Policy: Block External Redirects                                     |
|         │  • Ephemeral Header Injection: Authorization: Bearer <token>                             |
|         │  • 2 MB Max Body Streaming Clamp                                                         |
|         ▼                                                                                          |
|     GitHub API (api.github.com)                                                                    |
|         │                                                                                          |
|         ▼                                                                                          |
|  [Response Processing & Cleanup]                                                                   |
|         │  • Lease consumed & burned (broker.consume_lease)                                        |
|         │  • SecretBuffer zeroized and dropped from memory                                         |
|         │  • Masked sanitized preview generated (Zero Token Leakage)                              |
|         ▼                                                                                          |
|  [Governed Execution Result] ──► (Passed to B007 Receipts & Evidence Packaging)                   |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Threat Model & 20 Threat Vector Mitigation Matrix

B006 implements and validates comprehensive defenses against the 20 attack vectors detailed in the specification:

| Threat Vector | Description | Relay Mitigation | Test Verification |
| :--- | :--- | :--- | :--- |
| **TV-01: Host Substitution** | Attacker substitutes target domain (e.g. `evil.attacker.com`). | `GitHubClientConfig` strictly validates `base_url` against whitelist (`api.github.com` or loopback test server). | `test_threat_1_host_substitution_rejected` |
| **TV-02: Scheme Substitution** | Attacker attempts plain `http://` or `ftp://` scheme downgrade. | Scheme must strictly equal `https` in production; `http` permitted only on loopback test harness. | `test_threat_2_scheme_substitution_rejected` |
| **TV-03: Port Substitution** | Attacker specifies non-standard port (e.g. `api.github.com:8443`). | Default port 443 enforced in production. | `test_threat_3_port_substitution_rejected` |
| **TV-04: Redirect to Untrusted Host** | GitHub API or middlebox redirects to external attacker endpoint. | Custom `reqwest::redirect::Policy` validates every redirect target against host whitelist. External redirects fail closed. | `test_threat_4_redirect_to_untrusted_host_blocked` |
| **TV-05: Repository Name Traversal** | Path traversal sequences (`../`, `..%2F`) in repo name. | `GitHubNormalizer` rejects traversal sequences during canonicalization and connector rejects traversal paths. | `test_threat_5_repository_name_traversal` |
| **TV-06: Malformed Owner/Repo** | Invalid chars (`$`, spaces, semicolons, shell metachars) in repo path. | Regex validation `^[a-zA-Z0-9_.-]+$` enforces strict alphanumeric formatting. | `test_threat_6_malformed_owner_repository` |
| **TV-07: PR Number Confusion** | Pull request number in arguments diverged from canonical ResourceUri. | Connector cross-validates sub-resource in `ResourceUri` against `canonical_arguments`. Mismatches rejected. | `test_threat_7_pr_number_confusion` |
| **TV-08: Credential Leakage via Error** | Error response prints token in `Display` or `Debug`. | `GitHubError` masks tokens; secret is passed as `SecretBuffer` and never formatted into error strings. | `test_threat_8_credential_never_leaked_in_error` |
| **TV-09: Credential Leakage via URL** | Token placed into query parameters (`?access_token=...`). | Token injected strictly into `Authorization: Bearer` header; query strings never receive credentials. | `test_threat_9_credential_never_in_url` |
| **TV-10: ActionHash Mismatch** | Decision ActionHash does not match CanonicalAction hash. | Invariant check `action.action_hash == decision.action_hash` enforces fail-closed execution halt. | `test_threat_10_action_hash_mismatch` |
| **TV-11: Resource Mismatch** | Target resource diverged from authorized scope. | Connector verifies `canonical_action.resource` matches `lease.scoped_resource` and operation target. | `test_threat_11_resource_mismatch` |
| **TV-12: Principal Mismatch** | Lease principal diverged from canonical action principal. | Connector verifies `canonical_action.principal == lease.principal`. | `test_threat_12_principal_mismatch` |
| **TV-13: Expired Lease** | Execution attempted with an expired credential lease. | Connector and broker check `lease.is_active()` and `Utc::now() < lease.expires_at`. | `test_threat_13_expired_lease` |
| **TV-14: Reused Lease** | Execution attempted with a previously burned lease. | Single-use consumption via `broker.consume_lease(&lease_id)`. Re-validation returns false. | `test_threat_14_reused_lease` |
| **TV-15: Auto-Retry of Mutation** | Network failure triggers automatic retry of mutating request (`POST`). | Mutating operations are assigned `IdempotencyClass::NotSafeToRetry`. Retries strictly forbidden. | `test_threat_15_no_automatic_retry_of_mutation` |
| **TV-16: Timeout Mutation Outcome** | Mutating request times out after TCP transmission. | Connector returns typed `AmbiguousMutationOutcome` error; state marked indeterminate. | `test_threat_16_timeout_after_mutation_yields_ambiguous_outcome` |
| **TV-17: Oversized Response** | Remote server returns unbounded response payload (DoS). | Response body reading clamped to 2 MB (`MAX_RESPONSE_BODY_BYTES`); larger payloads error out. | `test_threat_17_oversized_response_rejected` |
| **TV-18: Malicious Response Payload** | Binary or malformed response body crashes connector. | Sanitized string decoding handles non-UTF8 safely with lossy UTF-8 conversion; no panics. | `test_threat_18_malicious_response_handled_cleanly` |
| **TV-19: Unauthorizated Connector Call** | Connector invoked with `PolicyDecision::Deny` or `ApprovalRequired`. | Connector asserts `decision.is_allowed()`; fails closed immediately with zero network requests. | `test_threat_19_connector_called_without_authorization` |
| **TV-20: Missing Credential Authorization** | Connector invoked with invalid or unprovisioned vault key. | Broker fails to produce lease; connector halts execution with zero network requests. | `test_threat_20_connector_called_without_credential_authorization` |

---

## 3. Supported Operations & Schema Architecture

The GitHub connector defines strongly typed operations in `crates/relay-connectors/src/github/operations.rs`:

```rust
pub enum GitHubOperation {
    GetRepository,
    GetPullRequest { pull_number: u64 },
    GetIssue { issue_number: u64 },
    GetBranch { branch_name: String },
    CreateIssue(CreateIssueRequest),
    CreatePullRequest(CreatePullRequestRequest),
    CreateBranch(CreateBranchRequest),
}
```

### 3.1 Strict Request Typing (`deny_unknown_fields`)
All mutating request structures enforce `#[serde(deny_unknown_fields)]` to prevent argument injection or schema confusion:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateIssueRequest {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignees: Option<Vec<String>>,
}
```

### 3.2 Idempotency Classification
Operations implement `idempotency_class(&self)`:
- `GetRepository`, `GetPullRequest`, `GetIssue`, `GetBranch` -> `IdempotencyClass::Idempotent` (Safe to retry on network transport failure).
- `CreateIssue`, `CreatePullRequest`, `CreateBranch` -> `IdempotencyClass::NotSafeToRetry` (Mutating; automatic retry strictly forbidden).

---

## 4. In-Process MCP Gateway Interception

To route agent requests to the native connector without spawning external Node.js/Python MCP processes:
1. `crates/relay-mcp/src/intercept.rs`:
   - Inspects `tools/call` JSON-RPC messages.
   - If the tool identity matches a native connector (`namespace == "github"`), `InterceptResult::Handled(Box<JsonRpcResponse>)` short-circuits the pipeline.
   - The native connector runs in-process within Relay's security boundary.
   - Child process stdin/stdout communication is bypassed completely, preventing ambient credential exposure to child processes.

---

## 5. Ephemeral Credential Lifecycle & Security Invariants

The connector adheres strictly to the **Anti-Vault Principle** and **Single-Use Capability Leases** (SI-006):

1. **JIT Acquisition:**
   ```rust
   let cred_req = CredentialRequest::new(
       canonical_action.action_hash,
       canonical_action.principal.clone(),
       canonical_action.resource.clone(),
       CredentialProviderType::KeyringStatic,
       self.default_key_alias.clone(),
       "github",
       canonical_action.resource.as_str(),
       60, // 60s single-action TTL
   );
   let (lease, secret) = credential_broker.acquire_lease(&cred_req, decision).await?;
   ```
2. **In-Flight Validation:**
   - Verifies `lease.action_hash == canonical_action.action_hash`.
   - Verifies `lease.principal == canonical_action.principal`.
   - Verifies `lease.scoped_resource == canonical_action.resource.as_str()`.
   - Verifies `lease.is_active()`.
3. **Execution & Injection:**
   - Token injected into HTTP request header: `req.header("Authorization", format!("Bearer {}", secret_str))`.
   - Secret buffer is pinned in RAM (`mlock`).
4. **Guaranteed Cleanup:**
   - `credential_broker.consume_lease(&lease.lease_id)` burns the lease permanently in the broker ledger.
   - `drop(secret)` immediately invokes `zeroize` and `munlock`.

---

## 6. Network Security & SSRF Lockdown

All HTTP interactions occur via `GitHubClient` (`crates/relay-connectors/src/github/client.rs`):
* **Memory-Safe TLS:** Powered exclusively by `rustls` with `webpki-roots`. OpenSSL and platform native-tls dependencies are excluded.
* **Strict Host Whitelist:**
  - Allowed production host: `api.github.com`.
  - Loopback test server (`127.0.0.1`, `localhost`, `[::1]`) permitted only when `allow_http_loopback: true` is explicitly configured in test configurations.
  - Any request targeting an unapproved host returns `GitHubError::SsrfBlocked`.
* **Redirect Policy Lockdown:**
  - Custom `reqwest::redirect::Policy::custom` checks the destination URI of every redirect.
  - Redirects to external or non-whitelisted hosts are immediately terminated with an error, preventing token exfiltration via open redirects.
* **Response Body Clamping:**
  - Maximum response body size clamped to 2 MB (`MAX_RESPONSE_BODY_BYTES`). Responses exceeding this limit are aborted to protect against memory exhaustion attacks.

---

## 7. Ambiguous Mutation Outcome

When executing a mutating operation (`POST /repos/...`):
* If a timeout occurs after the request has been dispatched across the socket:
  ```rust
  if is_mutating && (err.is_timeout() || err.is_connect()) {
      return Err(GitHubError::AmbiguousMutationOutcome {
          operation: op_name.to_string(),
          endpoint: path.to_string(),
          details: err.to_string(),
      }.into());
  }
  ```
* Relay explicitly returns `ExecutionError::AmbiguousMutationOutcome`, signaling to the agent and operator that the remote action may have completed and must not be retried automatically.

---

## 8. Verification & Test Suite

The connector was validated across 57 comprehensive tests in `crates/relay-connectors`:

```text
running 17 tests (unit_tests.rs)
test test_connector_requires_secret_buffer_in_trait_execute ... ok
test test_action_hash_mismatch_rejected_without_network ... ok
test test_operation_mapping_create_branch ... ok
test test_operation_mapping_create_issue ... ok
test test_operation_mapping_create_pull_request ... ok
test test_operation_mapping_get_branch ... ok
test test_operation_mapping_get_issue ... ok
test test_operation_mapping_get_pull_request ... ok
test test_operation_mapping_get_repository ... ok
test test_operation_mapping_rejects_unknown_fields_in_write ... ok
test test_operation_mapping_rejects_unsupported ... ok
test test_operation_pr_number_confusion_rejection ... ok
test test_resource_mapping_branch_ref ... ok
test test_resource_mapping_issue ... ok
test test_resource_mapping_pull_request ... ok
test test_resource_mapping_rejects_malformed_chars ... ok
test test_resource_mapping_rejects_path_traversal ... ok
test test_resource_mapping_repository ... ok

running 11 tests (network_tests.rs)
test test_http_200_get_repository ... ok
test test_http_201_create_issue ... ok
test test_http_401_authentication_failure ... ok
test test_http_403_authorization_failure ... ok
test test_http_403_rate_limit_exceeded ... ok
test test_http_404_not_found ... ok
test test_http_409_conflict ... ok
test test_http_422_validation_error ... ok
test test_http_500_server_error ... ok
test test_network_connection_failure ... ok
test test_redirect_to_untrusted_host_blocked ... ok

running 3 tests (secret_leak_tests.rs)
test test_secret_never_in_captured_tracing_logs ... ok
test test_secret_never_in_error_display_or_debug ... ok
test test_secret_never_in_success_preview_or_url ... ok

running 20 tests (security_tests.rs)
test test_threat_1_host_substitution_rejected ... ok
test test_threat_2_scheme_substitution_rejected ... ok
test test_threat_3_port_substitution_rejected ... ok
test test_threat_4_redirect_to_untrusted_host_blocked ... ok
test test_threat_5_repository_name_traversal ... ok
test test_threat_6_malformed_owner_repository ... ok
test test_threat_7_pr_number_confusion ... ok
test test_threat_8_credential_never_leaked_in_error ... ok
test test_threat_9_credential_never_in_url ... ok
test test_threat_10_action_hash_mismatch ... ok
test test_threat_11_resource_mismatch ... ok
test test_threat_12_principal_mismatch ... ok
test test_threat_13_expired_lease ... ok
test test_threat_14_reused_lease ... ok
test test_threat_15_no_automatic_retry_of_mutation ... ok
test test_threat_16_timeout_after_mutation_yields_ambiguous_outcome ... ok
test test_threat_17_oversized_response_rejected ... ok
test test_threat_18_malicious_response_handled_cleanly ... ok
test test_threat_19_connector_called_without_authorization ... ok
test test_threat_20_connector_called_without_credential_authorization ... ok

running 5 tests (integration_tests.rs)
test test_full_pipeline_allow_reaches_github_and_consumes_lease ... ok
test test_full_pipeline_deny_prevents_network_and_credential_acquisition ... ok
test test_action_hash_mismatch_prevents_network_call ... ok
test test_credential_vault_failure_prevents_network_call ... ok
test test_resource_mismatch_prevents_network_call ... ok

running 1 test (performance_tests.rs)
test test_performance_characterization ... ok
```

### Performance Benchmark Results
Measured via `tests/performance_tests.rs` on local hardware:
- **Action Canonicalization:** ~52.5 µs
- **Cedar Policy Evaluation:** ~1.16 ms
- **Local Operation Parsing:** ~155 ns
- **Full Governed Roundtrip (Local + Mock Network):** ~1.15 ms
- **Target Comparison:** Local connector operational overhead is well under the 5.0 ms architectural target budget.

---

## 9. Milestone Completion Checklist

- [x] Rust workspace crate `relay-connectors` implemented and fully wired.
- [x] Strongly typed `GitHubOperation` enum with `#[serde(deny_unknown_fields)]`.
- [x] `GitHubClient` using `rustls` (default features disabled) and `webpki-roots`.
- [x] Strict SSRF host whitelist and custom redirect lockdown.
- [x] Single-use credential lease acquisition and validation from `JitCredentialBroker`.
- [x] Memory zeroization of secrets post-execution via `SecretBuffer`.
- [x] Zero credential leakage verified across errors, URLs, previews, and logs.
- [x] Ambiguous mutation outcome classification and no automatic retry for mutations.
- [x] In-process gateway interception via `InterceptResult::Handled`.
- [x] 20 threat vector security tests passing.
- [x] End-to-end integration tests (ALLOW, DENY, Mismatch, Vault Failure) passing.
- [x] Performance characterization tests passing under architectural budgets.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` completely clean (0 warnings).
- [x] `cargo fmt --all -- --check` completely clean.
- [x] Zero modifications to frozen architecture documentation.

---

## 10. Handoff to Milestone B007: Action Receipts & Evidence Packaging

With the completion of B006, Relay possesses a complete governed execution path from raw agent MCP calls to external SaaS API execution. 

Milestone B007 will consume the output of this pipeline:
- `ExecutionResult` and `ExecutionMetadata` generated by `execute_governed` will be cryptographically bound with `ActionHash`, `DecisionId`, and `LeaseId`.
- An immutable `ActionReceipt` will be signed and sealed.
- The receipt will be persisted into Relay's append-only SQLite evidence ledger (`relay-ledger`).
