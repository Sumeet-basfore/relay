# GA005 Architecture & Release Decision Record: v0.1.0 Public Launch

* **Status:** APPROVED & SHIPPED
* **Date:** 2026-09-14
* **Deciders:** Project Lead, Principal Security Architect, Operations Gatekeeper
* **Subject:** Official Public Launch and Maintenance Handoff for Relay v0.1.0

---

## Decision Drivers & Launch Determination

Relay `v0.1.0` has completed all technical development milestones, release candidate validations, adversarial campaigns, and independent security audits.

All launch verification criteria have been satisfied:
1. **Immutable Git Tag:** Tag `v0.1.0` created and verified pointing to certified commit `0360a95f74c33a9fc3d7628876dd9bb7d307e2bb`.
2. **Package & Binary Provenance:** Archive SHA-256 (`6f843ab71592ee55cc9c3b9c556af23e58b1fe8b192404c28ee753912f9de206`) and Binary SHA-256 (`a4a3f930ecd36ee0c207bc014610a21b48d5718b5913443552e94fb49dd43a98`) verified against manifests.
3. **Operational Readiness:** Maintenance policies, incident response runbooks, security baselines, and issue templates are published and active.
4. **Handoff Complete:** Release engineering is frozen; the v0.1.0 release line is officially transferred to maintenance mode.

---

GA005 v0.1.0 PUBLIC LAUNCH — FINAL VERDICT

Release Tag:
PASS

Published Artifact:
PASS

Artifact Integrity:
PASS

Public Installation:
PASS

Golden Demo:
PASS

Security Documentation:
PASS

Security Disclosure:
PASS

Maintenance Handoff:
PASS

Public Availability:
PUBLIC

Final Version:
v0.1.0

Final Commit:
0360a95f74c33a9fc3d7628876dd9bb7d307e2bb

Archive SHA-256:
6f843ab71592ee55cc9c3b9c556af23e58b1fe8b192404c28ee753912f9de206

Binary SHA-256:
a4a3f930ecd36ee0c207bc014610a21b48d5718b5913443552e94fb49dd43a98

Security Boundary:
Under complete prompt-injection compromise of the agent, the agent cannot obtain ambient credentials, bypass Cedar authorization, escape network sandbox boundaries, or mutate state without generating tamper-evident cryptographic evidence.

Known Limitations:
- Host OS root/kernel compromise is outside the software security boundary.
- macOS and Windows operate in Managed Cooperative Proxy Mode (raw socket isolation requires container/VM sandboxes).
- Remote cloud provider eventual consistency on network drop cannot be proven locally.
- Direct in-library Rust connector usage outside the CLI requires embedding GovernedActionRunner.

Post-Launch Risks:
- Third-party MCP servers modifying tool schemas dynamically at runtime.
- High-concurrency database connection exhaustion on unpooled local PostgreSQL targets.
- Upstream cloud provider API rate limits during automated agent loops.

v0.2 Candidates:
- macOS Network Extension / Endpoint Security kernel-level sandboxing.
- Windows AppContainer isolation.
- Native Kubernetes, AWS IAM, and Redis connectors.
- HashiCorp Vault dynamic leasing plugin and Hardware HSM PKCS#11 signing.
- Asynchronous MCP Task state machine support.

Tests:
380 passed / 0 failed

Release Status:
SHIPPED
