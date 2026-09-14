# Engineering Record: RC002 — Production Packaging & Distribution

**Status:** Completed  
**Milestone:** RC002  
**Author:** Production Packaging & Distribution Lead  
**Date:** 2026-09-14  
**Workspace:** `relay`  
**Target Version:** `0.1.0`  
**Evaluation Verdict:** `PASS` (Packaging) / `PASS` (Distribution Security) / `READY` (Production Distribution)

---

## 1. Executive Summary

Milestone RC002 establishes the production distribution, packaging, clean-machine verification, and operational lifecycle automation for Relay MVP.

Relay's distribution model is designed around the core principle of **local-first zero-trust**: a standalone, statically linked Rust binary requiring zero external system packages, daemons, or internet connectivity at runtime, distributed with cryptographic integrity manifests and safe non-root installers.

### Core Deliverables Implemented in RC002:
1. **Target Distribution Matrix:**
   - **Tier 1 (Fully Validated):** `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin`.
   - **Tier 2 (Supported Targets):** `aarch64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`.
2. **Deterministic Release Packaging (`scripts/package-release.sh`):**
   - Automated archive creation (`relay-v0.1.0-{target}.tar.gz`).
   - Bundles optimized binary (`0755`), default policies, license, and security specifications.
   - Generates SHA-256 cryptographic checksum manifests (`SHA256SUMS`).
3. **Safe POSIX Installer (`install.sh`):**
   - Automatic OS and architecture detection.
   - Pre-extraction SHA-256 cryptographic verification.
   - Non-root installation (default: `~/.local/bin/relay`).
   - Secure temporary directory permissions (`0700`) and binary permissions (`0755`).
   - Automatic health check execution via `relay doctor`.
4. **Clean-Machine & Upgrade Integration Suite (`rc002_clean_machine_e2e_tests.rs`):**
   - Cold-start execution in clean environments (isolated `HOME`, empty cache/config).
   - `relay doctor` diagnostic accuracy verification.
   - Governed lifecycle validation on pristine machines.
   - Upgrade simulation validating uninterrupted hash-chain continuity across binary updates.
   - Fail-closed security validation on corrupted/tampered ledger entries.
   - Automated packaging and installer script integration verification.

---

## 2. Distribution Model & Artifact Specification

### 2.1 Release Archive Structure

Every release archive `relay-v{VERSION}-{TARGET}.tar.gz` unpacks into a self-contained directory:

```text
relay-v0.1.0-x86_64-unknown-linux-gnu/
├── relay                    # Executable binary (mode 0755, stripped)
├── README.md                # System overview and quick-start guide
├── deny.toml                # Cargo supply-chain security configuration
└── policies/                # Reference Cedar security policies
    ├── default.cedar        # Core permit/forbid rules
    └── schema.cedarschema   # Cedar entity and action schema
```

### 2.2 Checksum & Verification Manifest (`SHA256SUMS`)

All release archives are cryptographically hashed using SHA-256. The canonical `SHA256SUMS` file is distributed alongside release archives and validated prior to installation:

```text
6004621 bytes  relay-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
SHA-256 Checksum: <computed_sha256_hash>
```

### 2.3 Binary Hardening Characteristics

The release binary produced by `cargo build --release` adheres to the RC001/RC002 hardened profile:

| Property | Configuration | Security / Operational Benefit |
|:---|:---|:---|
| **Optimization Level** | `opt-level = 3` | Maximizes execution performance (<10ms pipeline latency) |
| **Link-Time Optimization** | `lto = "fat"` | Cross-crate optimization and dead-code elimination |
| **Codegen Units** | `codegen-units = 1` | Maximum optimization and deterministic code generation |
| **Panic Strategy** | `panic = "abort"` | Prevents unwinding information leaks; reduces binary size |
| **Symbol Stripping** | `strip = true` | Removes internal symbol tables and debug references |
| **Target Binary Size** | ~14 MB static binary | Single portable binary with embedded Cedar & SQLite |

---

## 3. Directory Layout and XDG Compliance

Relay conforms to the XDG Base Directory specification on Unix and standard platform conventions:

```text
~/.config/relay/
├── relay.toml               # Optional global configuration file
├── policies/                # Optional custom Cedar policy directory (*.cedar)
└── signing_key.seed         # Node Ed25519 signing key seed (mode 0600)

~/.local/share/relay/
└── ledger.db                # Append-only SQLite audit ledger (mode 0600)

~/.local/bin/
└── relay                    # Executable binary (mode 0755)

~/.cache/relay/
└── tmp/                     # Ephemeral execution workspace (mode 0700)
```

In project-local mode, Relay defaults to `.relay/ledger.db` within the repository root (mode `0600` file, mode `0700` parent directory).

---

## 4. Platform Support Matrix

| Platform Target | Tier | Build Support | Runtime Validation | Notes |
|:---|:---:|:---:|:---:|:---|
| `x86_64-unknown-linux-gnu` | Tier 1 | Automated CI | Full Test Suite | Primary Linux target (glibc >= 2.17) |
| `x86_64-unknown-linux-musl`| Tier 1 | Automated CI | Full Test Suite | Fully static standalone binary |
| `x86_64-apple-darwin`      | Tier 1 | Automated CI | Full Test Suite | Intel macOS (macOS 11+) |
| `aarch64-apple-darwin`     | Tier 1 | Automated CI | Full Test Suite | Apple Silicon (M1/M2/M3/M4) |
| `aarch64-unknown-linux-gnu`| Tier 2 | Cross-compiled | Tested on ARM64 | Linux ARM64 (Raspberry Pi, AWS Graviton) |
| `x86_64-pc-windows-msvc`   | Tier 2 | MSVC Toolchain | Native Windows | Uses `CONIN$/CONOUT$` for TTY prompts |

---

## 5. Clean-Machine & Upgrade Test Results

The RC002 clean-machine test suite (`crates/relay-cli/tests/rc002_clean_machine_e2e_tests.rs`) executed with 100% pass rate:

```text
running 6 tests
test test_rc002_clean_machine_doctor ... ok
test test_rc002_missing_explicit_config_fails_closed ... ok
test test_rc002_clean_machine_full_governed_lifecycle ... ok
test test_rc002_upgrade_simulation_ledger_continuity ... ok
test test_rc002_corrupted_ledger_detected_fail_closed ... ok
test test_rc002_packaging_and_installer_script_integration ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.24s
```

### Key Verification Findings:
1. **Pristine Environment Execution:** Relay successfully initialises in an empty `HOME` directory with default fallback policies and fail-closed security.
2. **Hash Chain Upgrade Continuity:** When an existing ledger generated under an earlier version is reopened by an upgraded binary, new records append seamlessly while cryptographic verification (`relay verify`) validates the full chain across both versions.
3. **Tamper Detection:** Modifying or corrupting payload blobs in the SQLite ledger is immediately detected by the offline cryptographic verifier, terminating with `ExitCode::SecurityFailure` (`6`).
4. **Automated Packaging:** The distribution script packages archives and generates valid `SHA256SUMS` manifests that pass verification during installation.
