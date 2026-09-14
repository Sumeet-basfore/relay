# Release Candidate Checklist: RC002 — Production Packaging & Distribution

**Version:** `0.1.0-RC002`  
**Milestone:** RC002  
**Date:** 2026-09-14  
**Status:** `READY FOR RELEASE`

---

## 1. Quality & Code Assurance Gates

| Gate Item | Requirement | Verification Command | Status |
|:---|:---|:---|:---:|
| **Workspace Test Suite** | 315 tests passing across 9 crates | `cargo test --workspace` | `PASS` (315/315) |
| **Compiler Lints (Clippy)** | 0 warnings under `-D warnings` | `cargo clippy --workspace --all-targets -- -D warnings` | `PASS` (0 warnings) |
| **Code Formatting** | Standard Rust formatting | `cargo fmt --all -- --check` | `PASS` |
| **Release Build Profile** | `opt-level = 3`, `lto = "fat"`, `strip = true` | `cargo build --release --bin relay` | `PASS` |
| **Binary Size** | Standalone static binary < 15 MB | `ls -lh target/release/relay` (~14 MB) | `PASS` |

---

## 2. Packaging & Installer Verification

| Packaging Item | Requirement | Verification Output | Status |
|:---|:---|:---|:---:|
| **Packaging Script** | `scripts/package-release.sh` packages tarball | `dist/relay-v0.1.0-x86_64-unknown-linux-gnu.tar.gz` | `PASS` |
| **Checksum Manifest** | `SHA256SUMS` generated and valid | `sha256sum --check SHA256SUMS` | `PASS` |
| **Safe Installer** | `install.sh` non-root user execution | Validates hash, sets `0755` perms, runs doctor | `PASS` |
| **Permissions Hygiene** | DB (`0600`), Dir (`0700`), Keys (`0600`) | Unix `stat -c %a` verified | `PASS` |

---

## 3. End-to-End Clean Machine Gates

| E2E Item | Requirement | Test Case | Status |
|:---|:---|:---|:---:|
| **Cold-Start Doctor** | Runs cleanly with isolated HOME | `test_rc002_clean_machine_doctor` | `PASS` |
| **Config Fail-Closed** | Missing explicit `--config` fails exit code 2 | `test_rc002_missing_explicit_config_fails_closed` | `PASS` |
| **Governed Lifecycle** | FS execution -> DSSE -> Ledger -> Verify | `test_rc002_clean_machine_full_governed_lifecycle` | `PASS` |
| **Upgrade Continuity** | Hash-chain integrity verified across versions | `test_rc002_upgrade_simulation_ledger_continuity` | `PASS` |
| **Tamper Detection** | Corrupt SQLite entry fails closed exit code 6 | `test_rc002_corrupted_ledger_detected_fail_closed` | `PASS` |
| **Installer Integration** | Shell installer script end-to-end execution | `test_rc002_packaging_and_installer_script_integration` | `PASS` |

---

## 4. Documentation & Operational Deliverables

| Deliverable | Location | Status |
|:---|:---|:---:|
| **Packaging Engineering Record** | `docs/engineering/RC002-packaging.md` | `COMPLETE` |
| **Installation Guide** | `docs/getting-started/installation.md` | `COMPLETE` |
| **Upgrade Guide** | `docs/operations/upgrade.md` | `COMPLETE` |
| **Backup & Recovery Guide** | `docs/operations/backup-and-recovery.md` | `COMPLETE` |
| **Signing Key Guide** | `docs/operations/signing-keys.md` | `COMPLETE` |
| **Troubleshooting Guide** | `docs/operations/troubleshooting.md` | `COMPLETE` |
| **Release Checklist** | `docs/release/RC002-release-checklist.md` | `COMPLETE` |
| **Release Report** | `docs/release/RC002-release-report.md` | `COMPLETE` |
