# GA004 — Authoritative Security Invariant Registry

**Release:** Relay `v0.1.0`  
**Candidate Commit:** `0360a95f74c33a9fc3d7628876dd9bb7d307e2bb`  
**Status:** **FROZEN / CERTIFIED**  
**Classification:** Complete Authoritative Security Invariant Registry  

---

## Executive Summary

This document establishes the single authoritative registry of all **24 Security Invariants (SI-001 through SI-024)** governing Relay `v0.1.0`. All prior draft numbering systems from `A004`, `RC001`, `M002`, `GA001`, `GA002`, and `GA003` are reconciled into this immutable release registry.

```text
================================================================================
                    RELAY v0.1.0 SECURITY INVARIANTS STATUS
================================================================================
Total Defined Invariants: 24 (SI-001 to SI-024)
Enforced Invariants:     24 / 24 (100%)
Passing Invariants:      24 / 24 (100%)
Status:                  ALL SATISFIED & RELEASE READY
================================================================================
```

---

## Authoritative Invariant Registry (SI-001 to SI-024)

### SI-001
* **ID:** `SI-001`
* **Canonical Statement:** Zero target credentials in agent environment and memory. Agent client processes, context windows, standard I/O streams, and child environments must never receive or observe target service credentials (API tokens, database passwords, private keys).
* **Implementation:** `crates/relay-mcp/src/subprocess.rs` (`apply_sanitized_env`) and `crates/relay-cli/src/runner.rs`.
* **Test:** `crates/relay-cli/tests/rc001_hardening_tests.rs::test_rc001_subprocess_env_sanitization_strips_secrets` and `crates/relay-cli/tests/ga003_golden_demo_tests.rs`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** Relies on OS kernel process isolation. If host root is compromised, `/proc` memory can be inspected.

---

### SI-002
* **ID:** `SI-002`
* **Canonical Statement:** Deterministic action hashing and canonicalization. Every proposed action is converted to RFC 8785 JSON Canonicalization Scheme (JCS) representation before computing the SHA-256 `ActionHash`.
* **Implementation:** `crates/relay-canonical/src/jcs.rs` and `crates/relay-canonical/src/action.rs`.
* **Test:** `crates/relay-canonical/tests/jcs_rfc8785_tests.rs` and `crates/relay-cli/tests/ga002_audit_tests.rs::test_audit_unicode_and_whitespace_canonicalization_determinism`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** Input payloads exceeding `MAX_CANONICAL_BYTES` (4MB default) are rejected fail-closed.

---

### SI-003
* **ID:** `SI-003`
* **Canonical Statement:** Tool schema and identity pinning. Tool names and parameter schemas are validated and pinned by cryptographic schema digests (`SchemaDigest`) before authorization.
* **Implementation:** `crates/relay-canonical/src/tool_identity.rs` and `crates/relay-canonical/src/schema.rs`.
* **Test:** `crates/relay-canonical/tests/tool_identity_tests.rs`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** Third-party MCP servers that dynamically mutate tool schemas at runtime must be re-initialized.

---

### SI-004
* **ID:** `SI-004`
* **Canonical Statement:** Fail-closed Cedar policy authorization. Authorization strictly precedes execution. If an action is not explicitly permitted by an active Cedar policy rule, it is denied fail-closed with zero target execution.
* **Implementation:** `crates/relay-policy/src/engine.rs` (`CedarPolicyEngine::authorize`).
* **Test:** `crates/relay-policy/tests/authorization_tests.rs::test_strict_default_deny_unpermitted_action` and `crates/relay-connectors/tests/golden_path_security_tests.rs`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** Overly permissive administrator policies (`permit(principal, action, resource);`) will permit actions as authored.

---

### SI-005
* **ID:** `SI-005`
* **Canonical Statement:** Approval binding and expiration invariant. Out-of-band human approvals are cryptographically bound to the exact canonical `ActionHash` and are non-transferable, single-use, and time-bounded.
* **Implementation:** `crates/relay-domain/src/approval.rs` and `crates/relay-mcp/src/approval/`.
* **Test:** `crates/relay-receipts/tests/binding_tests.rs::test_action_hash_mismatch_between_action_and_approval`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** Headless / non-interactive execution mode immediately rejects approval-required actions fail-closed.

---

### SI-006
* **ID:** `SI-006`
* **Canonical Statement:** Ephemeral JIT credential leasing. Leased credentials exist exclusively in transient memory for the microsecond duration of a single authorized action and are burned upon completion.
* **Implementation:** `crates/relay-credentials/src/broker.rs` (`JitCredentialBroker`).
* **Test:** `crates/relay-credentials/tests/lease_tests.rs::test_single_use_lease_consumption_si_006`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** Does not revoke upstream API tokens on the remote SaaS provider if the provider lacks short-lived credential APIs.

---

### SI-007
* **ID:** `SI-007`
* **Canonical Statement:** Zero ambient credentials to child subprocesses. External MCP subprocesses are spawned with cleansed environments stripped of target API keys, AWS credentials, and database passwords.
* **Implementation:** `crates/relay-mcp/src/subprocess.rs` (`apply_sanitized_env`).
* **Test:** `crates/relay-cli/tests/ga003_golden_demo_tests.rs`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** None within supported POSIX / Windows process models.

---

### SI-008
* **ID:** `SI-008`
* **Canonical Statement:** In-memory secret zeroization. All memory buffers holding sensitive credentials implement `zeroize::Zeroize` and zeroize on drop. Custom `Debug` formatters prevent credential leakage into logs.
* **Implementation:** `crates/relay-credentials/src/secret.rs` (`SecretBuffer`).
* **Test:** `crates/relay-receipts/tests/signer_tests.rs::test_signer_never_leaks_private_key_in_debug`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** Core dumps generated by fatal kernel signals (`SIGKILL`/hardware panic) before drop could contain residual bytes if core dumps are not disabled by the OS.

---

### SI-009
* **ID:** `SI-009`
* **Canonical Statement:** DSSE RFC 9598 cryptographic envelope signing. Every executed governed action produces an immutable in-toto Statement wrapped in a DSSE envelope and signed with an Ed25519 private key.
* **Implementation:** `crates/relay-receipts/src/dsse.rs` and `crates/relay-receipts/src/signer.rs`.
* **Test:** `crates/relay-receipts/tests/crypto_tests.rs::test_ed25519_sign_and_verify_success`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** Requires local signing key security; hardware HSM / KMS is recommended for enterprise root trust.

---

### SI-010
* **ID:** `SI-010`
* **Canonical Statement:** Immutable policy set digest evidence. Every Action Receipt records the SHA-256 `PolicySetDigest` of the active Cedar policy set at authorization time.
* **Implementation:** `crates/relay-policy/src/loader.rs` and `crates/relay-receipts/src/builder.rs`.
* **Test:** `crates/relay-policy/tests/schema_validation_tests.rs::test_policy_digest_tamper_detection_si_010`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** None.

---

### SI-011
* **ID:** `SI-011`
* **Canonical Statement:** SQLite hash-chain ledger integrity. Action Receipts are appended to an SQLite ledger chained via cryptographic SHA-256 hashes ($H_i = \text{SHA256}(i \parallel H_{i-1} \parallel \text{PayloadHash}_i)$).
* **Implementation:** `crates/relay-ledger/src/storage.rs` (`SqliteStorageEngine::append`).
* **Test:** `crates/relay-ledger/tests/tamper_detection_tests.rs`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** Ledger must reside on storage supporting POSIX file locks.

---

### SI-012
* **ID:** `SI-012`
* **Canonical Statement:** Database write-once immutability triggers. The SQLite schema defines active `BEFORE UPDATE` and `BEFORE DELETE` triggers that reject modifications with a constraint violation.
* **Implementation:** `crates/relay-ledger/src/schema.sql` (`prevent_ledger_update`, `prevent_receipts_update`).
* **Test:** `crates/relay-cli/tests/ga002_audit_tests.rs::test_audit_ledger_tamper_detection_single_byte_flip`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** Direct hex modification of raw disk blocks bypasses SQLite triggers, but is caught by `relay verify` (SI-013).

---

### SI-013
* **ID:** `SI-013`
* **Canonical Statement:** Verification self-consistency. `relay verify` independently validates the genesis block, sequential continuity, parent hash links, and Ed25519 signatures.
* **Implementation:** `crates/relay-cli/src/verify_cmd.rs` and `crates/relay-ledger/src/verifier.rs`.
* **Test:** `crates/relay-cli/tests/ledger_cli_tests.rs::test_cli_verify_tampered_fails`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** Verification is an offline/on-demand process.

---

### SI-014
* **ID:** `SI-014`
* **Canonical Statement:** Restrictive filesystem permissions. Configuration files, private signing keys, and ledger databases are initialized with restrictive permissions (`0600` for files, `0700` for directories).
* **Implementation:** `crates/relay-cli/src/doctor.rs` and `crates/relay-cli/src/main.rs`.
* **Test:** `crates/relay-cli/tests/rc001_hardening_tests.rs::test_rc001_permission_hardening`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** Windows filesystem ACLs map permissions differently; standard Windows DACLs apply.

---

### SI-015
* **ID:** `SI-015`
* **Canonical Statement:** Subprocess clean environment scrubbing. Subprocess execution strips ambient system credentials, API tokens, and private keys from the environment before spawning.
* **Implementation:** `crates/relay-mcp/src/subprocess.rs`.
* **Test:** `crates/relay-cli/tests/ga003_golden_demo_tests.rs`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** Preserves minimal system runtime paths (`PATH`, `TMPDIR`, `HOME`).

---

### SI-016
* **ID:** `SI-016`
* **Canonical Statement:** Deterministic CLI exit semantics. Relay uses standardized process exit codes (`0` Success, `1` Config Error, `2` Subprocess Error, `3` Policy Denied, `4` Approval Denied, `6` Security Failure).
* **Implementation:** `crates/relay-domain/src/exit_code.rs` (`ExitCode`).
* **Test:** `crates/relay-cli/tests/rc001_hardening_tests.rs::test_rc001_deterministic_exit_codes`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** None.

---

### SI-017
* **ID:** `SI-017`
* **Canonical Statement:** Secret scrubbing in receipts and diagnostic logs. Regex pattern matchers scrub Authorization headers, GitHub PATs, and private keys from output payloads before receipt signing.
* **Implementation:** `crates/relay-receipts/src/scrub.rs` (`SecretScrubber`).
* **Test:** `crates/relay-receipts/tests/secret_scrub_tests.rs`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** Custom proprietary non-standard token formats require explicit pattern definitions.

---

### SI-018
* **ID:** `SI-018`
* **Canonical Statement:** Out-of-band interactive human approval. Step-up approval prompts render to `/dev/tty` directly, preventing agent processes on stdio from answering their own prompts.
* **Implementation:** `crates/relay-mcp/src/approval/tty.rs` (`TtyApprovalProvider`).
* **Test:** `crates/relay-mcp/tests/approval_tty_tests.rs`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** Requires an interactive TTY; headless environments fail closed.

---

### SI-019
* **ID:** `SI-019`
* **Canonical Statement:** External MCP egress destination authorization. Outbound network requests from external MCP subprocesses are evaluated against Cedar policy destination allowlists before connection establishment.
* **Implementation:** `crates/relay-mcp/src/egress_proxy.rs` (`EgressProxy::evaluate_policy`).
* **Test:** `crates/relay-mcp/tests/m002_egress_security_tests.rs::test_egress_proxy_cedar_policy_denial_yields_403`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** Subprocesses must route HTTP/HTTPS traffic through the proxy.

---

### SI-020
* **ID:** `SI-020`
* **Canonical Statement:** Ephemeral proxy session token binding. Proxy authentication tokens are UUID v7 tokens bound to a single action with a 30s TTL, burned immediately on action completion.
* **Implementation:** `crates/relay-mcp/src/egress_session.rs` (`ProxySessionManager`).
* **Test:** `crates/relay-mcp/tests/m002_egress_security_tests.rs::test_proxy_lease_lifecycle_and_invalidation_si_020`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** None.

---

### SI-021
* **ID:** `SI-021`
* **Canonical Statement:** Vaulted upstream credential injection. Outbound requests have target service credentials injected into HTTP headers by Relay's proxy; subprocesses never observe the injected credentials.
* **Implementation:** `crates/relay-mcp/src/egress_injector.rs` (`CredentialInjector`).
* **Test:** `crates/relay-mcp/tests/m002_egress_security_tests.rs::test_upstream_credential_injection_si_021`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** Requires proxy-based injection; binary proprietary protocols not supported in v0.1.0.

---

### SI-022
* **ID:** `SI-022`
* **Canonical Statement:** Cloud metadata, private IP, and anti-SSRF pre-DNS blocking. Pre-DNS resolution filters reject loopback, RFC 1918 subnets, IPv4-mapped IPv6, multicast, and cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`).
* **Implementation:** `crates/relay-mcp/src/egress_dns.rs` (`DnsResolverWithBlacklist`).
* **Test:** `crates/relay-cli/tests/ga002_audit_tests.rs::test_audit_ssrf_evasion_variants`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** None.

---

### SI-023
* **ID:** `SI-023`
* **Canonical Statement:** Linux unprivileged network namespace sandbox. On Linux, subprocesses run in an isolated Network Namespace (`CLONE_NEWNET`) with no default gateway; raw sockets fail with `ENETUNREACH`.
* **Implementation:** `crates/relay-mcp/src/egress_sandbox.rs` and `crates/relay-mcp/src/netns.rs`.
* **Test:** `crates/relay-mcp/tests/m003_adversarial_tests.rs::test_phase8_linux_netns_sandbox_blocks_raw_sockets`.
* **Release Status:** **SATISFIED (Enforced on Linux)**
* **Known Limitation:** Full namespace isolation requires Linux kernel namespaces; macOS and Windows run in Managed Cooperative Mode.

---

### SI-024
* **ID:** `SI-024`
* **Canonical Statement:** Fail-closed sandbox initialization. If the platform sandbox or loopback forward proxy fails to initialize, Relay refuses to launch the subprocess and terminates fail-closed.
* **Implementation:** `crates/relay-mcp/src/egress_sandbox.rs` (`EgressSandboxLauncher::spawn_sandboxed`).
* **Test:** `crates/relay-mcp/tests/m002_egress_security_tests.rs::test_platform_sandbox_launcher_modes`.
* **Release Status:** **SATISFIED (Enforced)**
* **Known Limitation:** None.
