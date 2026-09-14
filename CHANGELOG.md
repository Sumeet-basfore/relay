# Changelog

All notable changes to Relay are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-09-14

### Initial General Availability Release

Relay is a local-first, zero-trust MCP Security Gateway and Credential Broker delivered as a lightweight Rust binary.

#### Key Features & Capabilities:
- **Bounded MCP Stdio Gateway:** Interposes between untrusted AI agents (Claude, Cursor, custom loops) and MCP tool providers.
- **Deterministic Cedar Policy Authorization:** Evaluates declarative AWS Cedar policies over RFC 8785 JSON Canonicalization Scheme (JCS) action representations.
- **Ambient Credential Elimination:** Completely isolates target service credentials (GitHub tokens, PostgreSQL passwords, AWS keys) from agent context windows, disk files, and subprocess memory.
- **Ephemeral JIT Credential Leasing:** Leases credentials for single-action microsecond lifecycles with automatic in-memory zeroization (`zeroize::Zeroize`).
- **Governed Native Connectors:**
  - Filesystem: Root-jailed path containment, path traversal/symlink blocking, extension allowlisting.
  - PostgreSQL: AST-level SQL validation, table-scoped queries, destructive DDL blocking.
  - GitHub: Canonical URI routing, fine-grained operation permissions (Issues, PRs, Comments).
- **Out-of-Band Interactive Human Approval:** Direct `/dev/tty` step-up prompts bound cryptographically to canonical `ActionHash`.
- **Cryptographic DSSE Action Receipts:** Produces signed in-toto Statement v1.0 attestations wrapped in RFC 9598 DSSE envelopes signed with Ed25519.
- **Append-Only SQLite Hash-Chain Ledger:** SHA-256 chained audit ledger with write-once immutability database triggers.
- **External MCP Subprocess Egress Mediation:**
  - In-process loopback HTTP forward proxy with dynamic credential injection and Cedar destination allowlisting.
  - Action-bound ephemeral proxy session tokens (UUID v7 with 30s TTL).
  - Pre-DNS anti-SSRF resolver blocking cloud metadata (`169.254.169.254`, `fd00:ec2::254`), loopback, and RFC 1918 private subnets (SI-022).
  - Linux Network Namespace isolation (`CLONE_NEWNET`) blocking raw socket escapes with `ENETUNREACH`.
  - Managed Cooperative Proxy Mode for macOS and Windows.
- **Verification Engine:** `relay verify` CLI command for independent offline audit chain and signature validation.
- **Golden Reference Deployment:** Automated, reproducible 7-scene demonstration (`scripts/demo/run.sh`).

#### Security & Quality Assurance:
- 24 Formal Security Invariants (SI-001 through SI-024) 100% enforced and verified.
- 0 BLOCKER, 0 HIGH findings in independent security audit (GA002).
- 0 vulnerabilities across all Rust dependencies (`cargo audit`, `cargo deny`).
- Full binary hardening: Position Independent Executable (PIE), Stack Canaries, Full RELRO (`BIND_NOW`), Non-Executable Stack (`NX`), Stripped Symbols, Fat LTO.
