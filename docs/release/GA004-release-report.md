# GA004 — Final Ship Gate & v0.1.0 Release Certification Report

**Release:** Relay `v0.1.0`  
**Candidate Commit:** `0360a95f74c33a9fc3d7628876dd9bb7d307e2bb`  
**Certification Date:** September 2026  
**Final Ship Decision:** **SHIP (APPROVED FOR GENERAL AVAILABILITY)**  

---

## 1. Executive Summary

Milestone GA004 represents the final formal technical ship gate for Relay `v0.1.0`. Every engineering gate, platform sandbox mode, cryptographic verification mechanism, native connector, external MCP egress mediation boundary, installer script, and documentation artifact was rigorously inspected and certified against the release artifact:

* **Release Package:** `dist/relay-v0.1.0-x86_64-unknown-linux-gnu.tar.gz`
* **Package SHA-256:** `6f843ab71592ee55cc9c3b9c556af23e58b1fe8b192404c28ee753912f9de206`
* **Binary SHA-256:** `a4a3f930ecd36ee0c207bc014610a21b48d5718b5913443552e94fb49dd43a98`
* **Release Manifest:** `release/v0.1.0/RELEASE-MANIFEST.md`

The certification confirms that Relay `v0.1.0` satisfies its foundational thesis:

> **Authority + Credential Isolation + Evidence**  
> *Under complete prompt-injection compromise of the agent, the agent cannot obtain ambient credentials, bypass Cedar authorization, escape network sandbox boundaries, or mutate state without generating tamper-evident cryptographic evidence.*

---

## 2. Release Gate Assessment

| Gate | Verification Method | Status |
| :--- | :--- | :--- |
| **Source Freeze** | Git tree inspected; candidate commit pinned | **PASS (FROZEN)** |
| **Supply Chain & Dependencies** | `cargo audit` (0 vulns), `cargo deny check` (approved licenses) | **PASS** |
| **Clean Build Hardening** | PIE, stack canaries, full RELRO, NX stack, stripped symbols, Fat LTO | **PASS** |
| **Security Invariants** | All 24 invariants satisfied in `GA004-invariant-registry.md` | **PASS (24/24)** |
| **Native Execution** | Filesystem, PostgreSQL, GitHub connectors completely mediated | **PASS** |
| **External MCP Egress** | In-process proxy, Linux NetNS sandbox (`CLONE_NEWNET`), anti-SSRF | **PASS** |
| **Credential Isolation** | Ephemeral JIT leasing, zero ambient secrets, memory zeroization | **PASS** |
| **Cryptographic Evidence** | in-toto DSSE (RFC 9598) receipts, Ed25519 signatures, SQLite hash-chain | **PASS** |
| **Tamper Detection** | Single-byte mutation detection on disk and ledger verified fail-closed | **PASS** |
| **Installer & Packaging** | `install.sh` non-root install, checksum verification, corrupt package rejection | **PASS** |
| **Golden Reference Demo** | `./scripts/demo/run.sh` passes 7 scenes end-to-end in <10s | **PASS** |
| **Full Automated Tests** | 380 passed / 0 failed (100% passing across workspace) | **PASS** |

---

## 3. Absolute Ship Blocker Evaluation

Relay defines 11 absolute ship blockers that prevent release:
1. **Unresolved security invariant violation:** None (24/24 satisfied).
2. **Linux network isolation bypass:** None (`ENETUNREACH` on raw sockets, anti-SSRF enforced).
3. **Credential exposure:** None (Sanitized subprocess environments, zero ambient secrets).
4. **Unauthorized governed execution:** None (Fail-closed Cedar default deny).
5. **Receipt forgery accepted as valid:** None (Tampered Ed25519 signatures rejected).
6. **Ledger tampering undetected:** None (Hash chain mismatch detected by `relay verify`).
7. **Installer executes unverified artifact:** None (SHA-256 verification mandatory).
8. **Release artifact differs from certified artifact:** None (Bit-for-bit SHA-256 match).
9. **Undocumented security limitation:** None (All residual risks documented in `GA004-known-limitations.md`).
10. **Unresolved BLOCKER or HIGH security finding:** None (0 Blocker, 0 High).
11. **Failed final regression:** None (100% test pass rate).

---

## 4. Certification Conclusion

Relay `v0.1.0` has successfully passed all technical, security, and operational release criteria and is **FORMALLY CERTIFIED FOR PUBLIC GENERAL AVAILABILITY RELEASE**.
