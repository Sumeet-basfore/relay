# GA005 — v0.1.0 Public Launch & Maintenance Handoff Report

**Release:** Relay `v0.1.0`  
**Candidate Commit:** `0360a95f74c33a9fc3d7628876dd9bb7d307e2bb`  
**Git Tag:** `v0.1.0`  
**Status:** **PUBLICLY RELEASED / SHIPPED**  

---

## 1. Executive Summary

Milestone GA005 represents the final milestone in the Relay `v0.1.0` release train. Relay is now formally declared **SHIPPED** and available for public production use. All engineering gates, packaging pipelines, installer scripts, security runbooks, and documentation suites are verified and frozen.

### Certified Release Package:
* **Release Archive:** `dist/relay-v0.1.0-x86_64-unknown-linux-gnu.tar.gz`
* **Archive SHA-256:** `6f843ab71592ee55cc9c3b9c556af23e58b1fe8b192404c28ee753912f9de206`
* **Binary SHA-256:** `a4a3f930ecd36ee0c207bc014610a21b48d5718b5913443552e94fb49dd43a98`
* **Checksum Manifest:** `dist/SHA256SUMS`

---

## 2. Launch Verification Matrix

| Verification Area | Method | Result |
| :--- | :--- | :--- |
| **Release Tag** | Immutable Git tag `v0.1.0` on certified commit | **PASS** |
| **Published Package** | SHA-256 matches manifest bit-for-bit | **PASS** |
| **Fresh Installation** | `install.sh` non-root install & checksum check | **PASS** |
| **System Diagnostics** | `relay doctor` verifies Linux NetNS & config | **PASS** |
| **Golden Reference Demo** | `./scripts/demo/run.sh` 7 scenes execute <10s | **PASS** |
| **Adversarial Harness** | `./scripts/demo/attack.sh` 100% attacks blocked | **PASS** |
| **Security Disclosure** | `SECURITY.md` operational contact active | **PASS** |
| **Incident Response** | Key compromise runbooks established | **PASS** |
| **Maintenance Handoff** | Ownership transferred to maintenance | **PASS** |
| **v0.2 Roadmap Isolation** | Post-GA feature backlog isolated | **PASS** |

---

## 3. Maintenance Handoff & Future Governance

The `v0.1.x` release line is now in active maintenance. Future updates to `v0.1.x` will follow the patch criteria defined in `docs/operations/maintenance-policy.md`, limited exclusively to security invariant repairs, critical CVE fixes, and platform installation regressions. All new feature development is directed to `docs/roadmap/v0.2.md`.
