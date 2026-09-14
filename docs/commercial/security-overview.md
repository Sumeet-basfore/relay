# Relay Security Overview (Commercial Trust Package)

**Document ID:** `CR001-SEC-001`  
**Version:** `1.0.0`  
**Status:** Customer-Facing Engineering Summary  
**Applies To:** Relay `v0.1.0`  
**Last Updated:** 2026-09-14  

---

## 1. Executive Summary

Relay is a **local-first, policy-enforced execution boundary** for AI agents. The v0.1.0 binary runs entirely on customer infrastructure. It does not phone home, does not collect product telemetry, and does not require a Relay account.

This document summarizes security architecture for procurement and trust review. It does **not** claim regulatory certification.

---

## 2. Architecture

```text
Agent (untrusted) ──stdio──► Relay Gateway ──► Governed Connectors ──► Targets
                                   │
                                   ├── Cedar Policy Engine (default DENY)
                                   ├── Credential Broker (OS keyring)
                                   ├── Human Approval Gate (/dev/tty)
                                   ├── DSSE Receipt Signer (Ed25519)
                                   └── Append-Only SQLite Ledger
```

**Core thesis:** Authority + Credential Isolation + Evidence

---

## 3. Local-First Model

| Property | v0.1.0 Behavior |
|:---|:---|
| Deployment | Single binary on customer host |
| Data residency | Customer-controlled filesystem and keyring |
| Relay cloud dependency | **None** for operation |
| Multi-tenancy | **None** — single-tenant local instance |
| Network to Relay infra | **None** (automatic) |

---

## 4. Credential Handling

- **Agent isolation (SI-001):** Target API tokens never enter agent memory, environment, or subprocesses
- **Storage:** OS keyring via `keyring-rs` (Secret Service / macOS Keychain / Windows Credential Manager)
- **Just-in-time leasing:** Credentials exist in secure memory for ≤30 seconds during execution
- **Prohibited persistence:** Raw credentials are never written to SQLite ledger or log files
- **Scrubbing:** Receipt signer rejects payloads containing detected secret patterns

See `docs/security/credential-model.md` for full specification.

---

## 5. Encryption & Key Management

| Asset | Protection |
|:---|:---|
| Receipt signing key | Ed25519 seed, file mode `0600` or OS keyring |
| Ledger database | SQLite file mode `0600`; WAL mode |
| Target credentials | OS keyring encryption (platform-dependent) |
| In-flight leases | `zeroize` on drop; volatile memory |
| Release artifacts | SHA256SUMS manifest; user verifies on install |

Relay v0.1.0 does **not** implement full-disk encryption or HSM-backed signing (planned v0.2 candidate).

---

## 6. Network Behavior

| Traffic | Direction | Authorization |
|:---|:---|:---|
| MCP stdio | Agent ↔ Relay local | Process pipe |
| Egress proxy | External MCP ↔ `127.0.0.1` | Cedar policy + lease token |
| GitHub API | Relay → customer GitHub | Customer PAT, policy-governed |
| PostgreSQL | Relay → customer DB | Customer credentials, policy-governed |
| Relay-operated services | **None** | N/A |

**Linux hardening:** External MCP subprocesses run in network namespaces (`CLONE_NEWNET`); anti-SSRF blocks cloud metadata endpoints.

---

## 7. Signed Evidence

Every governed action produces:

1. RFC 8785 canonical action representation
2. Cedar policy decision record
3. RFC 9598 DSSE envelope with Ed25519 signature
4. Append-only hash-chained ledger entry in `.relay/ledger.db`

Verification: `relay verify` validates chain integrity and signatures.

---

## 8. Policy Enforcement

- **Engine:** AWS Cedar embedded PEP
- **Default:** DENY all actions unless explicitly permitted
- **Human gate:** Interactive approval via `/dev/tty` when policy requires
- **Headless mode:** FAIL CLOSED — exits with code 10 if approval required

---

## 9. Vulnerability Reporting

| Channel | Details |
|:---|:---|
| Email | `security@relay.dev` |
| Public issues | **Do not** report vulnerabilities publicly |
| Supported versions | `0.1.x` active; `<0.1.0` EOL |
| Acknowledgment target | 48 business hours (see `SECURITY.md`) |

---

## 10. Update Process

| Mechanism | Behavior |
|:---|:---|
| Automatic update checks in binary | **None** |
| In-binary updater | **None** |
| Distribution | GitHub Releases + optional `install.sh` (user-initiated) |
| Integrity | SHA256SUMS verification recommended |
| Release signing | Project release signing key (see `incident-response.md`) |

---

## 11. Diagnostics (`relay doctor`)

`relay doctor` performs **local-only** checks:

- Relay version, OS, architecture
- Config directory existence (`~/.config/relay`)
- Ledger path and file permissions
- Policy directory status
- TTY availability for human approval
- Linux egress sandbox capability

**No network calls.** No data transmitted to Relay.

---

## 12. Access Controls

| Surface | Access Model |
|:---|:---|
| Relay CLI | OS user running the process |
| Ledger file | File permissions `0600` |
| Signing key | File permissions `0600` / keyring ACL |
| OS keyring secrets | Platform keyring ACL |
| MCP gateway | Stdio attached to agent process |

Customers must protect host OS access; Relay cannot enforce OS-level access control beyond file permissions.

---

## 13. Incident Response

Documented runbooks in `docs/security/incident-response.md`:

- Release signing key compromise
- Receipt signing key compromise
- Target credential exposure
- Security boundary / invariant violation
- Privacy incident separation (Phase 24–25)

---

## 14. Explicit Non-Certifications

Relay v0.1.0 has **not** obtained:

- SOC 2 Type I or II
- ISO 27001
- HIPAA compliance attestation
- FedRAMP authorization
- PCI DSS (no payment processing in binary)

---

## 15. Shared Responsibility

See `docs/commercial/data-flow.md` §7 for full matrix. Summary:

**Relay provides:** authorization boundary, credential isolation, evidence integrity  
**Customer controls:** host OS, policies, signing keys, target permissions, local data retention

---

## 16. Related Documents

- `docs/security/security-claims.md`
- `docs/release/GA004-security-claims.md`
- `docs/security/v0.1.0-security-baseline.md`
- `docs/commercial/product-boundary.md`
