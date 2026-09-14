# GA004 — Final Ship Gate Checklist (Relay v0.1.0)

**Release:** Relay `v0.1.0`  
**Candidate Commit:** `0360a95f74c33a9fc3d7628876dd9bb7d307e2bb`  
**Status:** **100% COMPLETE — READY TO SHIP**  

---

## 1. Source & Repository State
- [x] **PASS** — Git working tree clean of temporary files, generated secrets, and local overrides.
- [x] **PASS** — Candidate commit recorded and tagged (`0360a95f74c33a9fc3d7628876dd9bb7d307e2bb`).
- [x] **PASS** — Cargo.lock frozen and pinned.

## 2. Dependencies & Supply Chain
- [x] **PASS** — `cargo audit`: 0 vulnerabilities, 0 active RUSTSEC advisories.
- [x] **PASS** — `cargo deny check`: Approved open-source licenses (Apache-2.0 / MIT / BSD), duplicate dependencies pruned.
- [x] **PASS** — Build scripts reviewed; no arbitrary network access during compilation.

## 3. Build & Compilation
- [x] **PASS** — Stable Rust compiler 1.85.0 (`x86_64-unknown-linux-gnu`).
- [x] **PASS** — `cargo fmt --check` clean.
- [x] **PASS** — `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- [x] **PASS** — Release profile configured with `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`.

## 4. Binary Hardening & Inspection
- [x] **PASS** — Position Independent Executable (PIE) enabled.
- [x] **PASS** — Stack canaries (`__stack_chk_fail`) enabled.
- [x] **PASS** — Full RELRO (`GNU_RELRO` + `BIND_NOW`) enabled.
- [x] **PASS** — Non-executable stack (`GNU_STACK` `RW`) enabled.
- [x] **PASS** — Debug symbols stripped; symbols table cleaned.
- [x] **PASS** — No hard-coded keys, passwords, or test credentials embedded in binary.

## 5. Packaging & Distribution
- [x] **PASS** — Tarball generated: `dist/relay-v0.1.0-x86_64-unknown-linux-gnu.tar.gz`.
- [x] **PASS** — File permissions in archive: `0755` for binary, `0644` for documentation and policies.
- [x] **PASS** — Checksum manifest `dist/SHA256SUMS` computed and validated.

## 6. Installer & Upgrades
- [x] **PASS** — `install.sh` fresh non-root installation verified.
- [x] **PASS** — Re-installation and checksum validation verified.
- [x] **PASS** — Checksum mismatch and corrupted archive rejection verified fail-closed.
- [x] **PASS** — State preservation on database upgrade verified.

## 7. Security Invariants (SI-001 to SI-024)
- [x] **PASS** — All 24 security invariants reconciled and satisfied in `docs/release/GA004-invariant-registry.md`.
- [x] **PASS** — Fail-closed Cedar authorization (SI-004) verified across all routes.
- [x] **PASS** — Ephemeral JIT credential leasing (SI-006) and memory zeroization (SI-008, SI-017) verified.
- [x] **PASS** — Cryptographic DSSE Action Receipts (SI-009) and SQLite hash-chain ledger (SI-011, SI-012) verified.

## 8. Platform Sandboxing & Isolation
- [x] **PASS** — Linux Network Namespace sandbox (`CLONE_NEWNET`) blocks raw socket escapes with `ENETUNREACH`.
- [x] **PASS** — Pre-DNS anti-SSRF resolver (SI-022) blocks cloud metadata (`169.254.169.254`, `fd00:ec2::254`), loopback, and private IPs.
- [x] **ACCEPTED RISK** — macOS and Windows operate in Managed Cooperative Mode (documented in `docs/release/GA004-known-limitations.md`).

## 9. Governed Connectors
- [x] **PASS** — Native Filesystem Connector verified (read, write, delete, path traversal containment).
- [x] **PASS** — Native PostgreSQL Connector verified (SELECT, DDL rejection, SQL injection protection).
- [x] **PASS** — Native GitHub Connector verified (read, issue/PR creation, permission containment).

## 10. External MCP Subprocesses
- [x] **PASS** — Action-bound ephemeral proxy session tokens (SI-020, SI-023) burn upon action completion.
- [x] **PASS** — Upstream vaulted credential injection (SI-021) confirmed; subprocess never sees credentials.
- [x] **PASS** — Adversarial probe suite (`scripts/demo/attack.sh`) passes with 100% attacks blocked.

## 11. Golden Demo & UX
- [x] **PASS** — `./scripts/demo/run.sh` runs cleanly and completes in <10 seconds.
- [x] **PASS** — `./scripts/demo/cleanup.sh` cleanly destroys disposable demo state.
- [x] **PASS** — Human approval step-up prompts render cleanly to `/dev/tty` (SI-018).

## 12. Documentation & Vulnerability Disclosure
- [x] **PASS** — README prominently guides users to installation, Golden Demo, security model, and limitations.
- [x] **PASS** — `SECURITY.md` defines vulnerability reporting process and PGP key contact.
- [x] **PASS** — All release documentation frozen and aligned with v0.1.0 release reality.

---

**Final Checklist Status:** 100% COMPLETE — APPROVED TO SHIP
