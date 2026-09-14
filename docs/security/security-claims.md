# Relay Security Claims & Verification Matrix

**Document ID:** `SEC-CLM-001`  
**Version:** `0.1.0`  
**Author:** Principal Security Architect  
**Status:** Approved Verification Matrix  

---

## 1. Verified Security Claims Matrix

Every public security claim made by Relay maps directly to concrete source code enforcement points and automated unit/integration test evidence:

| Claim | Test Evidence | Enforcement Point | Architectural Boundary | Residual Limitation |
|:---|:---|:---|:---|:---|
| **Zero Ambient Credentials** | `rc001_hardening_tests::test_rc001_subprocess_env_sanitization_strips_secrets` | `relay-mcp::gateway::sanitized_child_env` | Subprocess spawn boundary | Does not protect against root memory dumps on compromised host OS. |
| **Deterministic Cedar Authorization** | `authorization_tests::test_strict_default_deny_unpermitted_action` | `relay-policy::engine::CedarPolicyEngine` | Pre-dispatch policy gate | Policy rules must be correctly configured by human administrator. |
| **Complete Mediation (Native Connectors)** | `golden_path_security_tests::test_sec_01_cedar_deny_prevents_connector_dispatch` | `relay-connectors::coordinator::GovernedActionRunner` | In-process native execution | External MCP subprocesses making raw TCP outbound calls require future egress proxy. |
| **Fail-Closed on All Errors** | `adversarial_campaign_tests::test_adv_01_fail_closed_on_panic` | Universal `Result<T, CliError>` pipeline | System-wide error propagation | N/A (Always fails closed). |
| **Canonical Action Integrity (RFC 8785)** | `jcs_rfc8785_tests::test_rfc8785_canonicalization_determinism` | `relay-canonical::jcs::canonicalize_json` | Ingress argument parsing | Target services with non-standard JSON parsers could diverge on duplicate keys. |
| **Cryptographic Human Approval Binding** | `binding_tests::test_action_hash_mismatch_between_action_and_approval` | `relay-domain::approval::Approval` | Direct `/dev/tty` interceptor | Compromised host user interface could trick the human operator into approving. |
| **Single-Use JIT Credential Leases** | `lease_tests::test_single_use_lease_consumption_si_006` | `relay-credentials::broker::JitCredentialBroker` | Internal lease state manager | Leases in memory exist for the active execution duration (<30s). |
| **Cryptographic Action Receipts** | `crypto_tests::test_ed25519_sign_and_verify_success` | `relay-receipts::signer::Ed25519ReceiptSigner` | RFC 9598 DSSE + in-toto v1.0 | A receipt proves Relay's observation; it does not guarantee remote cloud state. |
| **Tamper-Evident Ledger Integrity** | `tamper_detection_tests::test_payload_tamper_detection` | `relay-ledger::verifier::LedgerVerifier` | SQLite SHA-256 hash-chain | An attacker with disk write access can delete the entire file; tampering is detectable, not un-deletable. |
| **Explicit Uncertainty for Ambiguous Mutations** | `construction_tests::test_action_with_ambiguous_mutation` | `relay-connectors::coordinator::GovernedActionRunner` | Network timeout classifier | Remote target may have executed the action before the connection dropped. |
| **Memory Zeroization on Drop** | `keyring_tests::test_keyring_provider_no_plaintext_in_display_or_debug` | `relay-domain::SecretBuffer` | RAII `zeroize::Zeroize` hook | Kernel page swapping prevented via `mlock` where permitted by OS ulimits. |
| **Filesystem Root Jail Confinement** | `fs_unit_tests::test_root_jail_prevents_escape` | `relay-connectors::fs::FilesystemConnector` | Path resolution & symlink gate | Hard links created inside the jail pointing to external inodes require OS permissions. |
| **SQL AST Normalization & DDL Blocking** | `postgres_security_tests::test_postgres_ddl_denied_by_policy` | `relay-canonical::resource::sql::canonicalize_sql` | AST parsing via `sqlparser-rs` | Target database stored procedures (`SECURITY DEFINER`) could have side effects. |
