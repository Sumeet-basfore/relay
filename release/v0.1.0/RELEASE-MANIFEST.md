# Canonical Release Manifest: Relay v0.1.0

```text
Product:              Relay — Local-First Zero-Trust MCP Security Gateway & Credential Broker
Version:              v0.1.0
Git Commit:           0360a95f74c33a9fc3d7628876dd9bb7d307e2bb
Build Toolchain:      rustc 1.85.0 (stable x86_64-unknown-linux-gnu)
Supported Targets:    x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu, x86_64-apple-darwin, aarch64-apple-darwin, x86_64-pc-windows-msvc
Primary Dist Package: dist/relay-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
Archive SHA-256:      6f843ab71592ee55cc9c3b9c556af23e58b1fe8b192404c28ee753912f9de206
Binary SHA-256:       a4a3f930ecd36ee0c207bc014610a21b48d5718b5913443552e94fb49dd43a98
Binary Hardening:     PIE, Stack Canaries, Full RELRO (BIND_NOW), NX Stack, Stripped Symbols, Fat LTO, Panic Abort
Release Signature:    Ed25519 (RFC 9598 DSSE Envelope / in-toto Statement v1.0)
Total Tests:          380 passed / 0 failed (100% pass across 9 workspace crates)
Security Audit:       INDEPENDENT AUDIT COMPLETED (0 BLOCKER, 0 HIGH, 0 MEDIUM, 1 LOW RESOLVED)
Documentation Status: FROZEN & AUDITED (docs/security/, docs/demo/, docs/getting-started/, docs/release/)
Known Limitations:    Documented in docs/release/GA004-known-limitations.md (Host root boundary, macOS/Windows cooperative proxy, distributed eventual consistency)
Certification Date:   2026-09-14
Certification Status: APPROVED FOR GENERAL AVAILABILITY RELEASE
```
