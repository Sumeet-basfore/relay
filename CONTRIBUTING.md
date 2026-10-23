# Contributing to Relay

Thank you for your interest in contributing to Relay! Relay is a local-first, zero-trust security gateway and credential broker for AI agents.

Because Relay enforces critical security boundaries around AI agent tool execution, we maintain rigorous engineering standards, strict default-deny policies, and automated invariant tests.

---

## 1. Prerequisites

- **Rust Toolchain:** Stable Rust 1.78 or higher (`rustup update stable`).
- **Operating System:**
  - **Linux (x86_64, aarch64):** Full feature set including Linux Network Namespace sandboxing (`CLONE_NEWUSER | CLONE_NEWNET`).
  - **macOS & Windows:** Supported in Managed Cooperative Proxy mode (`HTTP_PROXY`, `HTTPS_PROXY`).
- **Dependencies:** Standard development tools (`git`, `gcc`/`clang`, `pkg-config`).

---

## 2. Workspace Architecture

Relay is structured as a Cargo workspace with 9 modular crates:

```text
crates/
├── relay-domain       # Core domain entities, IDs, error types, traits, and SecretBuffer
├── relay-canonical    # RFC 8785 JSON Canonicalization Scheme (JCS) and SQL AST parser
├── relay-policy       # AWS Cedar policy engine, schema validator, and request mappers
├── relay-credentials  # JIT credential lease broker, OS keyring, and AES-GCM vault
├── relay-receipts     # RFC 9598 DSSE signing & verification with in-toto Statement v1.0
├── relay-connectors   # Governed native connectors (Filesystem, PostgreSQL, GitHub)
├── relay-mcp          # MCP stdio gateway, HTTP loopback proxy, and Linux netns sandbox
├── relay-ledger       # Append-only SQLite hash-chain audit ledger with trigger protection
└── relay-cli          # Command-line interface, doctor diagnostics, daemon, and local web UI
```

---

## 3. Development Workflow

### Building from Source

```bash
# Debug build
cargo build

# Optimized release binary
cargo build --release
```

### Running the Test Suite

Relay features over 380 automated tests spanning unit, integration, adversarial, and property-based test suites:

```bash
# Run all workspace tests
cargo test --workspace --all-targets --all-features

# Run specific crate tests
cargo test -p relay-policy       # Cedar authorization & schema validation
cargo test -p relay-credentials  # JIT lease lifecycles & memory zeroization
cargo test -p relay-receipts     # DSSE / in-toto cryptographic signing
cargo test -p relay-mcp          # MCP stdio proxy & Linux network sandbox
cargo test -p relay-ledger       # SQLite hash-chain & tamper detection
```

### Code Formatting & Linting

All PRs must pass strict formatting and clippy rules without warnings:

```bash
# Check code formatting
cargo fmt --check

# Run Clippy with warnings treated as errors
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

### Dependency & Security Audits

We use `cargo-deny` to verify dependency licenses, bans, and security advisories:

```bash
cargo deny check
```

### Running the Golden Reference Demo

Before submitting major changes, verify that the automated 7-scene reference demonstration passes cleanly:

```bash
./scripts/demo/run.sh
./scripts/demo/attack.sh
./scripts/demo/cleanup.sh
```

---

## 4. Security Invariants (SI-001 through SI-024)

Any PR modifying gateway boundaries, policy evaluation, credential leasing, or cryptographic receipts must maintain the 24 formal Security Invariants:

- **SI-004 (Strict Default-Deny):** If an action is not explicitly permitted by a Cedar policy, it MUST fail closed.
- **SI-006 (Single-Use JIT Leases):** Credential leases must be scoped to a single action execution and revoked immediately.
- **SI-008 (Memory Zeroization):** Plaintext secrets held in memory must implement RAII zeroization (`zeroize::Zeroize`) upon drop.
- **SI-009 (Signed Evidence):** Every action receipt must be signed using Ed25519 within an RFC 9598 DSSE envelope.
- **SI-011 (Immutable Hash-Chain):** Ledger entries must link via SHA-256 parent hashes in an append-only database.
- **SI-022 (Anti-SSRF):** Egress proxy must block link-local and cloud metadata addresses (`169.254.169.254`) before DNS resolution.
- **SI-023 (Linux Network Isolation):** External MCP subprocesses on Linux must run in unprivileged network namespaces (`CLONE_NEWNET`).

See [`docs/security/security-invariants.md`](docs/security/security-invariants.md) for the complete invariant specification.

---

## 5. Submitting Pull Requests

1. **Create a Topic Branch:** `git checkout -b feature/your-feature-name`
2. **Write Tests:** Include unit or integration tests verifying happy-path and adversarial boundary conditions.
3. **Run CI Checks Locally:** Ensure `cargo test`, `cargo clippy`, and `cargo fmt` all pass cleanly.
4. **Descriptive Commit Messages:** Use conventional commits format (e.g. `feat(policy): ...`, `fix(mcp): ...`, `docs: ...`).
5. **Open a Pull Request:** Provide a clear summary of your changes, referencing any relevant issues or security invariant impacts.

---

## 6. Security Vulnerability Reporting

If you discover a security vulnerability in Relay, please **do not** open a public issue. Follow the instructions in [SECURITY.md](SECURITY.md) to submit a responsible disclosure report.
