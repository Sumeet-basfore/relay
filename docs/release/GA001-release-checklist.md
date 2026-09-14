# Relay GA001 Release Verification Checklist

**Document ID:** `REL-CHK-GA001`  
**Milestone:** `GA001 — General Availability Release Engineering`  
**Target Version:** `v0.1.0`  
**Target Commit:** `0360a95f74c33a9fc3d7628876dd9bb7d307e2bb`  
**Evaluation Date:** 2026-09-14  
**Evaluator:** Principal Security Architect & Lead Release Engineer  

---

## 1. Supply-Chain & Build Verification

| Verification Item | Requirement | Verification Method | Status |
|:---|:---|:---|:---:|
| **Git Working Tree State** | Clean working tree; no unintended or untracked temporary files. | `git status` | `PASS` |
| **Dependency Lock State** | `Cargo.lock` deterministic and reproducible. | `cargo fetch --locked` | `PASS` |
| **Compiler Toolchain** | Stable Rust compiler (`rustc 1.85.0`). | `rustc --version` | `PASS` |
| **Release Profile Hardening** | `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = true`. | `Cargo.toml` inspection | `PASS` |
| **Binary Strip & Symbols** | Production binary is stripped of local path info and debug symbols. | `file target/release/relay` | `PASS` |
| **Zero Embedded Secrets** | Release binary contains zero private keys, API tokens, or test credentials. | `strings` & binary audit | `PASS` |

---

## 2. Packaging & Integrity Verification

| Verification Item | Requirement | Verification Method | Status |
|:---|:---|:---|:---:|
| **Deterministic Archive Name** | `relay-v0.1.0-<target>.tar.gz` naming convention. | `scripts/package-release.sh` | `PASS` |
| **Archive Content Audit** | Contains only `relay`, `README.md`, `deny.toml`, and `policies/`. | `tar -ztvf` inspection | `PASS` |
| **Cryptographic Checksums** | SHA-256 checksum manifest generated (`SHA256SUMS`). | `sha256sum --check` | `PASS` |
| **Secure File Permissions** | Binary `0755`, assets `0644`, archive directory `0755`. | `tar -ztvf` | `PASS` |

---

## 3. Installation, UX & Lifecycle Testing

| Verification Item | Requirement | Verification Method | Status |
|:---|:---|:---|:---:|
| **Non-Root Safe Installer** | `install.sh` downloads/installs without root privileges; verifies checksums. | Isolated temp directory test | `PASS` |
| **Reinstall & Upgrade Safety** | Reinstalling over existing binary preserves user configs and ledger. | `install.sh` overwrite test | `PASS` |
| **System Diagnostics** | `relay doctor` reports accurate status across all subsystems without leaking secrets. | `relay doctor` | `PASS` |
| **First-Run Initialization** | Safe default initialization; no silent fail-open choices. | `test_ga_smoke_doctor_clean_environment` | `PASS` |
| **Ledger Continuity Across Upgrade** | Existing ledger entries remain intact and cryptographically verifiable. | `test_rc002_upgrade_simulation_ledger_continuity` | `PASS` |

---

## 4. Security Invariant & Adversarial Certification

| Verification Item | Requirement | Verification Method | Status |
|:---|:---|:---|:---:|
| **Zero Ambient Subprocess Credentials** | Target credentials completely excluded from child environment (`env_clear()`). | `test_phase3_target_secrets_never_observable_in_child_environment` | `PASS` |
| **Deterministic Authorization** | Cedar PEP default-deny enforced on all tools and egress destinations. | `authorization_tests`, `test_egress_proxy_cedar_policy_denial_yields_403` | `PASS` |
| **Ephemeral Session Leases** | Single-use tokens (30s TTL) burned upon completion; replay fails. | `test_phase4_proxy_session_forgery_and_replay_attacks` | `PASS` |
| **SSRF & DNS Rebinding Protection** | Link-local metadata and RFC 1918 IPs blocked; socket IP pinned. | `test_phase6_redirect_to_private_ip_and_metadata_blocked`, `test_phase7_dns_rebinding_ip_pinning_and_literal_checks` | `PASS` |
| **Linux NetNS Hard Sandbox** | Unprivileged `CLONE_NEWUSER \| CLONE_NEWNET` blocks 100% of raw sockets (`ENETUNREACH`). | `test_phase8_linux_netns_sandbox_blocks_raw_sockets` | `PASS` |
| **DSSE Evidence & Ledger Integrity** | In-toto signed receipts; SQLite append-only SHA-256 hash chaining. | `crypto_tests`, `test_ga_smoke_full_governed_lifecycle_and_verification` | `PASS` |

---

## 5. Test Suite & Code Quality Summary

- **Total Workspace Tests Passing:** 346 / 346 (100% green).
- **Cargo Format Check:** `cargo fmt --check` (PASS, 0 diffs).
- **Clippy Strict Lints:** `cargo clippy --workspace --all-targets --all-features -- -D warnings` (PASS, 0 warnings).
- **GA Smoke Test Suite:** `cargo test --test ga_smoke_test` (PASS, 5/5).

---

## 6. Release Sign-Off

$$\text{GA001 Release Verification Status: } \mathbf{PASSED\ (READY\ FOR\ v0.1.0\ GA)}$$
