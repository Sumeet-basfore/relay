# Relay Operations: Maintenance & Lifecycle Policy

**Release Line:** `v0.1.x`  
**Status:** Active Maintenance  
**Date:** September 2026  

---

## 1. Supported Release Lines

Relay maintains a strict **N-1 major/minor** maintenance policy:
* **Current Active Release Line:** `v0.1.x` (Receives security updates, critical bug fixes, and dependency patches).
* **Pre-Release Builds:** `< v0.1.0` are End-of-Life (EOL) with no support.

---

## 2. Release Cadence & Versioning

Relay strictly adheres to [Semantic Versioning 2.0.0](https://semver.org/):

| Release Type | Format | Scope | Cadence |
| :--- | :--- | :--- | :--- |
| **Emergency Security Patch** | `v0.1.Z` | Critical security fixes, credential isolation repairs, CVE remediation | As needed (<72 hours from validation) |
| **Maintenance Patch** | `v0.1.Z` | High-priority bug fixes, platform regressions, doc fixes | Monthly or as needed |
| **Minor Release** | `v0.X.0` | Backward-compatible features, new connectors, new sandbox platforms | Quarterly (v0.2.0 planned Q4 2026) |
| **Major Release** | `vX.0.0` | Breaking architectural changes, policy schema overhauls | As required |

---

## 3. Dependency Monitoring & Upgrades

Security-critical dependencies are monitored continuously:
* **AWS Cedar (`cedar-policy`):** Policy language updates and engine security patches.
* **Cryptography (`ed25519-dalek`, `sha2`, `zeroize`):** Crypto audits and timing vulnerability mitigations.
* **Database (`rusqlite`, `sqlparser`):** SQLite security updates and SQL injection parsing rules.
* **HTTP / Network (`hyper`, `tokio`, `rustls`):** Egress proxy security, TLS cipher suites, and parser robustness.

---

## 4. Emergency Security Release Procedure

In the event of a verified security invariant violation or high/critical CVE:
1. **Private Patch Development:** Remediation is developed in a private security fork.
2. **Adversarial Regression Test:** A dedicated test is added to the attack suite to prevent regressions.
3. **Artifact Build & Verification:** Release artifacts are packaged and verified bit-for-bit.
4. **Coordinated Release & Advisory:** Publish `v0.1.Z` alongside a GitHub Security Advisory (GHSA) detailing impact, affected versions, and mitigation.
