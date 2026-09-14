# Security Review Checklist: RC003 — Public Release Readiness

**Document ID:** `SEC-CHK-001`  
**Version:** `0.1.0-RC003`  
**Date:** 2026-09-14  
**Evaluator:** Principal Security Architect & Release Auditor  
**Overall Verdict:** `PASS` (Ready for Public Release)  

---

## 1. Security Architecture & Boundary Gates

| Item | Requirement | Verification / Evidence | Status |
|:---|:---|:---|:---:|
| **SEC-01** | Trust boundary explicitly separates Agent (untrusted) from Relay (trusted) | `docs/security/README.md`, `docs/security/threat-model.md` | `PASS` |
| **SEC-02** | Host kernel compromise is explicitly documented as out-of-scope | `docs/security/limitations.md` §1 | `PASS` |
| **SEC-03** | Third-party external MCP network limitations are explicitly stated | `docs/security/mcp-boundary.md` §3 | `PASS` |
| **SEC-04** | Prompt injection model assumes 100% agent subversion | `docs/security/prompt-injection.md` §1 | `PASS` |

---

## 2. Secrets & Credential Management Gates

| Item | Requirement | Verification / Evidence | Status |
|:---|:---|:---|:---:|
| **CRED-01** | Child subprocess environment is cleared (`env_clear`) | `relay-mcp::gateway::sanitized_child_env` | `PASS` |
| **CRED-02** | Target credentials never leak to agent process (SI-001) | `rc001_hardening_tests::test_rc001_subprocess_env_sanitization_strips_secrets` | `PASS` |
| **CRED-03** | JIT leases are single-use and bound to `ActionHash` (SI-006) | `lease_tests::test_single_use_lease_consumption_si_006` | `PASS` |
| **CRED-04** | Memory buffers containing secrets are zeroized on drop (SI-017) | `relay_domain::SecretBuffer`, `keyring_tests` | `PASS` |
| **CRED-05** | Sensitive material is masked in `Debug` and `Display` (SI-008) | `rc001_hardening_tests::test_rc001_secret_buffers_and_keys_masked_in_debug` | `PASS` |
| **CRED-06** | Secret scrubber blocks receipts containing leaked credentials (SI-007) | `secret_scrub_tests::test_prohibited_secret_patterns_rejected_before_signing` | `PASS` |

---

## 3. Policy & Deterministic Authorization Gates

| Item | Requirement | Verification / Evidence | Status |
|:---|:---|:---|:---:|
| **POL-01** | Authorization strictly precedes execution (SI-002) | `golden_path_security_tests::test_sec_01_cedar_deny_prevents_connector_dispatch` | `PASS` |
| **POL-02** | Strict default-deny architecture enforced (SI-003) | `authorization_tests::test_strict_default_deny_unpermitted_action` | `PASS` |
| **POL-03** | Active policy-set digest recorded in decision and receipt (SI-010) | `schema_validation_tests::test_policy_digest_tamper_detection_si_010` | `PASS` |
| **POL-04** | Human step-up approval cryptographically bound to `ActionHash` (SI-004) | `binding_tests::test_action_hash_mismatch_between_action_and_approval` | `PASS` |
| **POL-05** | Non-interactive execution fails closed when approval required | `approval_headless_tests::test_headless_gate_fails_closed` | `PASS` |

---

## 4. Evidence & Ledger Storage Gates

| Item | Requirement | Verification / Evidence | Status |
|:---|:---|:---|:---:|
| **EVID-01** | Receipts conform to RFC 9598 DSSE and in-toto Statement v1.0 | `serialization_tests::test_dsse_envelope_schema_compliance` | `PASS` |
| **EVID-02** | Receipts signed using Ed25519 with isolated node key | `crypto_tests::test_ed25519_sign_and_verify_success` | `PASS` |
| **EVID-03** | Ledger entries chained via SHA-256 (SI-009) | `hash_chain_tests::test_hash_chain_continuity_over_many_entries` | `PASS` |
| **EVID-04** | Out-of-band ledger tampering detected offline by verifier | `tamper_detection_tests::test_payload_tamper_detection` | `PASS` |
| **EVID-05** | Ambiguous mutations classified with explicit uncertainty (SI-015) | `construction_tests::test_action_with_ambiguous_mutation` | `PASS` |
| **EVID-06** | SQLite triggers prevent UPDATE and DELETE on receipts/entries | `append_tests::test_immutability_triggers_prevent_update_and_delete` | `PASS` |

---

## 5. Public Packaging & Disclosure Gates

| Item | Requirement | Verification / Evidence | Status |
|:---|:---|:---|:---:|
| **PUB-01** | Safe non-root installer script provided (`install.sh`) | `rc002_clean_machine_e2e_tests::test_rc002_packaging_and_installer_script_integration` | `PASS` |
| **PUB-02** | Checksum manifest (`SHA256SUMS`) distributed with release | `scripts/package-release.sh` verification | `PASS` |
| **PUB-03** | Public vulnerability disclosure policy published | `SECURITY.md` | `PASS` |
| **PUB-04** | Public README avoids misleading marketing jargon | `README.md` | `PASS` |
| **PUB-05** | All 315 workspace tests passing (100% green) | `cargo test --workspace` | `PASS` |
| **PUB-06** | Compiler lints and formatting completely clean | `cargo clippy`, `cargo fmt` | `PASS` |
