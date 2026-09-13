# A008: Rust Ecosystem & Dependency Architecture

**Document ID:** `A008-rust-dependency-architecture`  
**Date:** September 2026  
**Status:** Approved Architectural Specification  
**Target System:** Relay MVP (Local-First Zero-Trust MCP Security Gateway & Credential Broker)  
**Author:** Rust Platform & Supply-Chain Security Architect  
**Corpus Dependencies:** `A001-system-architecture`, `A002-domain-model`, `A003-interfaces-and-contracts`, `A004-security-invariants`, `A005-test-strategy`, `00-research-synthesis`

---

## Executive Summary

Relay is a high-assurance, local-first security control plane and credential broker interposed between untrusted AI agents and sensitive enterprise tools. Because Relay sits directly on the critical execution and credential isolation boundary, **every external crate dependency represents an expansion of the Trusted Computing Base (TCB) and an inherent supply-chain attack surface.**

This specification defines the complete Rust dependency architecture for the Relay MVP. Dependencies are not selected for convenience or popularity. Each candidate is audited against rigorous selection criteria: project maturity, maintenance velocity, memory safety / unsafe code footprint, platform compatibility, transitive bloat, and license compliance (MIT, Apache-2.0, or BSD-3).

Furthermore, this document enforces a **strict Cargo workspace crate layering structure** that mathematically prevents layer inversion (e.g., domain logic depending on I/O or SQLite), defines explicit supply-chain controls (`cargo-deny`, `cargo-audit`, SBOM generation, reproducible builds), and codifies automated vulnerability response protocols.

---

## Table of Contents

1. [Dependency Evaluation Methodology & Security Criteria](#1-dependency-evaluation-methodology--security-criteria)
2. [Category-by-Category Dependency Evaluation](#2-category-by-category-dependency-evaluation)
3. [Master Dependency Matrix](#3-master-dependency-matrix)
4. [Explicitly Rejected Alternatives & Justification](#4-explicitly-rejected-alternatives--justification)
5. [Cargo Workspace Architecture & Crate Layering](#5-cargo-workspace-architecture--crate-layering)
6. [Dependency Architectural Rules & Negative Constraints](#6-dependency-architectural-rules--negative-constraints)
7. [Supply-Chain Security Controls](#7-supply-chain-security-controls)
8. [Upgrade Policy & Vulnerability Lifecycle](#8-upgrade-policy--vulnerability-lifecycle)

---

## 1. Dependency Evaluation Methodology & Security Criteria

Every third-party crate evaluated for inclusion in Relay must satisfy seven architectural quality gates:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                               RELAY DEPENDENCY ADMISSION CRITERIA                                │
├──────────────────────────┬───────────────────────────────────────────────────────────────────────┤
│ Evaluation Vector        │ Minimum Acceptance Standard                                           │
├──────────────────────────┼───────────────────────────────────────────────────────────────────────┤
│ 1. License Compatibility │ Permissive OSI-approved licenses only: MIT, Apache-2.0, BSD-2/3.      │
│                          │ Strict ban on Copyleft (GPL, AGPL, LGPL, SSPL, BSL).                 │
├──────────────────────────┼───────────────────────────────────────────────────────────────────────┤
│ 2. Unsafe Code Footprint │ Zero unvetted `unsafe` blocks in domain or protocol parsing crates.   │
│                          │ Unsafe code restricted to audited syscall abstractions (libc/rustix). │
├──────────────────────────┼───────────────────────────────────────────────────────────────────────┤
│ 3. Transitive Footprint  │ Minimal transitive tree depth. Default features disabled by default.   │
│                          │ Prefer self-contained implementations over monolithic umbrellas.      │
├──────────────────────────┼───────────────────────────────────────────────────────────────────────┤
│ 4. Native Dependencies   │ Zero dynamic C library linkages (e.g. OpenSSL, libgit2). Pure Rust    │
│                          │ or statically bundled/isolated C (e.g. SQLite amalgam) only.          │
├──────────────────────────┼───────────────────────────────────────────────────────────────────────┤
│ 5. Upstream Maintenance  │ Active core maintainers, predictable release cadence, active CVE      │
│                          │ disclosure channels, and documented MSRV (Minimum Supported Rust).    │
├──────────────────────────┼───────────────────────────────────────────────────────────────────────┤
│ 6. Platform Parity       │ First-class Tier-1 support for Linux (x86_64/aarch64) and macOS       │
│                          │ (Apple Silicon/Intel); buildable on Windows without native toolchains.│
├──────────────────────────┼───────────────────────────────────────────────────────────────────────┤
│ 7. Auditability          │ Clean, readable Rust code base amenable to automated static analysis  │
│                          │ and independent third-party security audits.                          │
└──────────────────────────┴───────────────────────────────────────────────────────────────────────┘
```

---

## 2. Category-by-Category Dependency Evaluation

### 2.1 Async Runtime & Process Management
* **Selected:** `tokio` (v1.38+, features: `rt-multi-thread`, `macros`, `io-std`, `process`, `sync`, `time`, `net`, `fs`)
* **Evaluation:**
  * *Maturity & Maintenance:* De facto standard async runtime in Rust. Maintained by the Tokio Core team with exceptional stability guarantees (v1.x API stability pledge).
  * *Unsafe Footprint:* Low, concentrated within low-level crossbeam/mio epoll/kqueue bindings. Highly audited.
  * *Platform Support:* Linux (epoll), macOS (kqueue), Windows (IOCP).
  * *Transitive Risk:* Moderate, but heavily optimized and ubiquitous across the ecosystem.
  * *Role in Relay:* Powers the async event loop, stdio MCP transport, concurrent tool dispatch, TTY user prompt coordination, and child subprocess spawning with environment scrubbing.

### 2.2 Model Context Protocol (MCP) & JSON-RPC 2.0
* **Selected:** *Custom In-Tree Implementation (`relay-mcp`)* backed by `serde` / `serde_json` / `tokio::io`.
* **Evaluation:**
  * *Evaluation of Existing Crates (`mcp-sdk`, `mcp-core`, `jsonrpc-core`):* Existing community MCP crates are early-stage (v0.1-v0.2), undergo frequent breaking API changes, often depend on unneeded web frameworks (Axum/Actix), or lack strict RFC 8259 duplicate-key rejection. `jsonrpc-core` is largely unmaintained.
  * *Decision:* Model Context Protocol is a lightweight JSON-RPC 2.0 protocol over stdio/SSE. Relay requires strict frame size limits ($\le 4\text{ MB}$), zero-copy JSON parsing, strict duplicate-key detection, and custom tool namespace prefixing (`server_name.tool_name`). A bespoke, zero-dependency domain crate (~500 lines of audited Rust) eliminates unstable external dependencies.

### 2.3 Serialization & Deserialization
* **Selected:** `serde` (v1.0+, features: `derive`, `alloc`), `serde_json` (v1.0+, features: `alloc`, `raw_value`, `preserve_order`)
* **Evaluation:**
  * *Maturity & Maintenance:* Industry-standard, foundational serialization framework with unmatched performance, battle-tested type safety, and active maintenance.
  * *Unsafe Footprint:* Extensively audited; `derive` macro generates safe, compile-time trait implementations.
  * *Feature Justification:* `preserve_order` (via `indexmap`) ensures deterministic JSON key traversal when feeding payloads to normalization pipelines.

### 2.4 Deterministic JSON Canonicalization (RFC 8785 / JCS)
* **Selected:** `serde_jcs` (v0.1+)
* **Evaluation:**
  * *Maturity & Maintenance:* Pure Rust implementation of RFC 8785 (JSON Canonicalization Scheme). Stable, standard-compliant, zero unvetted unsafe code.
  * *Transitive Risk:* Extremely small (depends only on `serde` and `itoa`/`dtoa`).
  * *Role in Relay:* Produces deterministic, byte-for-byte canonical JSON byte arrays for computing `ActionHash`, `SchemaSetHash`, and in-toto subject digests.

### 2.5 Policy Engine (ABAC & Cedar PDP)
* **Selected:** `cedar-policy` (v4.0+, features: none default/pure)
* **Evaluation:**
  * *Maturity & Maintenance:* Developed and formally verified with automated SMT reasoning (Lean theorem prover) by Amazon Web Services. Released under Apache-2.0. High development activity.
  * *Security Posture:* Strict default-deny semantics, strongly typed entity schemas, sub-millisecond in-memory evaluation latency, and zero I/O execution within the policy evaluation core.
  * *Role in Relay:* Core Policy Decision Point (PDP) evaluating whether `(Principal, Action, Resource, Context)` is permitted prior to credential leasing or tool invocation.

### 2.6 Local Storage & Audit Ledger (SQLite)
* **Selected:** `rusqlite` (v0.31+, features: `bundled`, `backup`, `hooks`)
* **Evaluation:**
  * *Maturity & Maintenance:* Premier synchronous SQLite wrapper in Rust. Actively maintained.
  * *Native Dependency Mitigation:* The `bundled` feature compiles SQLite from the official, audited C amalgamation source code directly into the Relay binary, eliminating external dynamically linked `libsqlite3.so` / `libsqlite3.dylib` dependencies and avoiding system version divergence.
  * *Role in Relay:* Append-only cryptographic ledger (`ledger.db`), hash-chain parent linkage, WAL-mode ACID persistence, and session state storage.

### 2.7 SQL AST Parsing & Canonicalization
* **Selected:** `sqlparser` (v0.47+, features: `standard`, `postgres`)
* **Evaluation:**
  * *Maturity & Maintenance:* Widely adopted pure-Rust SQL parser developed under the Apache DataFusion ecosystem. Zero unsafe code.
  * *Security Posture:* Parses ANSI and PostgreSQL SQL dialects into concrete ASTs. Strips inline comments (`--`, `/* */`), detects multi-statement batching (anti-SQL injection), and reconstructs canonical AST representations for Cedar resource policy evaluation.

### 2.8 Native PostgreSQL Connector
* **Selected:** `tokio-postgres` (v0.7+, features: `runtime`, `with-chrono-0_4`, `with-serde_json-1`)
* **Evaluation:**
  * *Maturity & Maintenance:* De facto asynchronous native PostgreSQL driver in Rust. Actively maintained by the community. Pure Rust; no `libpq` C dependency required.
  * *Comparison with SQLx:* SQLx includes heavy compile-time query macros, connection poolers, and database migration tooling unnecessary for a controlled connector. `tokio-postgres` provides low-level, direct protocol control with minimal overhead.
  * *Role in Relay:* Native connector executing approved SQL statements using JIT-injected database credentials.

### 2.9 Native HTTP Client
* **Selected:** `reqwest` (v0.12+, `default-features = false`, features: `rustls-tls`, `json`, `stream`, `tokio-util`)
* **Evaluation:**
  * *Maturity & Maintenance:* High-performance, universal HTTP client maintained by the Tokio team.
  * *Security Posture:* `default-features = false` disables native OpenSSL and native certificate stores. `rustls-tls` utilizes `rustls` (pure memory-safe Rust TLS) and `webpki-roots`, completely removing C-based OpenSSL CVE vectors.
  * *Role in Relay:* Powers outbound API calls for native connectors (e.g. GitHub REST API).

### 2.10 Loopback Egress Proxy (HTTP/1.1 & HTTP/2)
* **Selected:** `hyper` (v1.4+, features: `http1`, `http2`, `server`, `client`), `hyper-util` (v0.1+, features: `tokio`, `server-auto`), `http-body-util` (v0.1+)
* **Evaluation:**
  * *Maturity & Maintenance:* Foundational low-level HTTP primitives in Rust. Hyper 1.x provides a slim, composable, memory-safe foundation.
  * *Role in Relay:* Binds an isolated loopback proxy on `127.0.0.1:0` for child MCP servers requiring outbound HTTP. Inspects, filters, and JIT-injects authorization headers (`Authorization: Bearer <token>`) without exposing long-lived tokens to the child process environment.

### 2.11 Cryptographic Signing & Hashing (Ed25519 & SHA-256)
* **Selected:** `ed25519-dalek` (v2.1+, features: `rand_core`, `serde`, `zeroize`), `sha2` (v0.10+, features: none)
* **Evaluation:**
  * *Maturity & Maintenance:* `ed25519-dalek` (maintained by the RustCrypto team) is the industry benchmark for Ed25519 signatures, audited by NCC Group, featuring constant-time operations and integrated zeroization. `sha2` provides audited, pure-Rust SHA-256 implementations with CPU hardware acceleration (ARM NEON, x86 SHA extensions).
  * *Role in Relay:* Keypair generation, signing DSSE envelopes for Action Receipts, and computing SHA-256 hash chains across ledger records.

### 2.12 Attestation Envelopes (DSSE RFC 9598 & in-toto v1.0)
* **Selected:** *Custom In-Tree Implementation (`relay-receipts`)* backed by `serde`, `serde_json`, `base64` (v0.22+), and `ed25519-dalek`.
* **Evaluation:**
  * *Evaluation of Existing Crates:* Existing in-toto/DSSE crates in Rust are either abandoned prototypes or C/Go-shims.
  * *Decision:* DSSE (Dead Simple Signing Envelope - RFC 9598) and in-toto v1.0 Statement schemas are concise, well-defined JSON formats. Implementing them in-tree guarantees exact compliance with the pre-authentication encoding specification (`PAE(type, body)`), strict byte verification, and zero bloat.

### 2.13 Memory Zeroization & Secret Sanitization
* **Selected:** `zeroize` (v1.8+, features: `derive`, `zeroize_derive`, `alloc`), `secrecy` (v0.8+, features: `serde`, `alloc`)
* **Evaluation:**
  * *Maturity & Maintenance:* Developed by RustCrypto; widely verified mechanism using `core::sync::atomic::compiler_fence` and `volatile_set_memory` to prevent compiler dead-code elimination from stripping memory-clearing operations.
  * *Role in Relay:* Encapsulates all plaintext tokens, private keys, and intermediate authorization headers inside `SecretBuffer` types that deterministically wipe memory on `Drop`.

### 2.14 Operating System Memory Locking & Hardening
* **Selected:** `rustix` (v0.38+, features: `mm`, `process`, `param`)
* **Evaluation:**
  * *Maturity & Maintenance:* Safe, modern, low-level POSIX and Linux/macOS syscall wrappers designed to replace raw `libc` calls with type-safe, provenance-aware Rust primitives.
  * *Security Capabilities:* Invokes `mlock` to lock secret pages into RAM (preventing disk swapping), `mprotect` for memory protection boundaries, and `prctl(PR_SET_DUMPABLE, 0)` on Linux to block core dumps and unprivileged `/proc/<pid>/mem` access.

### 2.15 OS Secure Credential Storage (Keyring)
* **Selected:** `keyring` (v3.0+, features: `apple-native`, `sync-secret-service`, `windows-native`)
* **Evaluation:**
  * *Maturity & Maintenance:* Maintained cross-platform abstraction for native platform credential stores.
  * *Platform Integration:* Backed by Apple Keychain on macOS (via Security framework), Secret Service API / D-Bus on Linux, and Credential Manager on Windows.
  * *Role in Relay:* Secure, encrypted persistent storage for master long-lived secrets (e.g. GitHub PATs, Database passwords) outside the Relay process.

### 2.16 CLI Parsing & Configuration
* **Selected:** `clap` (v4.5+, features: `derive`, `env`, `help`, `usage`, `error-context`), `toml` (v0.8+, features: `parse`, `display`)
* **Evaluation:**
  * *Maturity & Maintenance:* Standard Rust CLI parser. Robust validation, auto-generated shell completions, structured error reporting.
  * *Role in Relay:* CLI entrypoint (`relay run`, `relay config`, `relay ledger verify`, `relay receipt inspect`).

### 2.17 Structured Logging, Tracing & Redaction
* **Selected:** `tracing` (v0.1+), `tracing-subscriber` (v0.3+, features: `env-filter`, `fmt`, `json`, `ansi`), `regex` (v1.10+, `default-features = false`, features: `std`, `perf`, `unicode-case`)
* **Evaluation:**
  * *Maturity & Maintenance:* Standard diagnostics framework from Tokio. Zero performance cost when disabled.
  * *Security Invariant:* Integrated with a custom redaction layer in `relay-cli` utilizing `regex` to intercept log events and mask known secret patterns (e.g., `ghp_[A-Za-z0-9]{36}`, `sk-[A-Za-z0-9]{48}`) before outputting to stderr.

### 2.18 Error Handling
* **Selected:** `thiserror` (v1.0 / v2.0+) for all internal domain/library crates; `eyre` / `color-eyre` (v0.6+) for the CLI binary entrypoint.
* **Evaluation:**
  * *Maturity & Maintenance:* David Tolnay’s `thiserror` is the benchmark for deterministic, strongly-typed enum error definitions in library crates. `eyre` provides rich backtraces and user-friendly error formatting at the CLI application boundary without polluting library crates.

### 2.19 Testing, Mocks & Property-Based Verification
* **Selected:** `proptest` (v1.5+), `wiremock` (v0.6+), `tempfile` (v3.10+), `assert_cmd` (v2.0+), `predicates` (v3.1+)
* **Evaluation:**
  * *Role in Relay:*
    * `proptest`: Property-based fuzzing of canonicalizers, path resolvers, and JSON encoding invariants.
    * `wiremock`: Deterministic HTTP mock server for testing native connectors and loopback proxies.
    * `tempfile`: Ephemeral directory and SQLite file isolation for hermetic unit and integration tests.
    * `assert_cmd` & `predicates`: Black-box CLI integration tests.

### 2.20 Continuous Coverage-Guided Fuzzing
* **Selected:** `cargo-fuzz` / `libfuzzer-sys` (v0.4+)
* **Evaluation:**
  * *Role in Relay:* Powers the continuous fuzzing suite targeting the stdio JSON-RPC framing parser, JCS canonicalizer, SQL AST normalizer, and DSSE signature verification routines.

---

## 3. Master Dependency Matrix

The following matrix specifies all approved dependencies across the entire Relay project workspace:

| Crate Name | Version | Primary Purpose / Role | Crate Target(s) | Default Features | Required Features |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`tokio`** | `1.38` | Async runtime, process, I/O | `relay-mcp`, `relay-connectors`, `relay-credentials`, `relay-cli` | `false` | `rt-multi-thread`, `macros`, `io-std`, `process`, `sync`, `time`, `net`, `fs` |
| **`serde`** | `1.0` | Serialization framework | *All crates* | `false` | `derive`, `alloc` |
| **`serde_json`** | `1.0` | JSON parsing & AST | *All crates* | `false` | `alloc`, `raw_value`, `preserve_order` |
| **`serde_jcs`** | `0.1` | RFC 8785 JSON Canonicalization | `relay-canonical` | `true` | Standard |
| **`cedar-policy`** | `4.0` | Cedar ABAC Policy Engine | `relay-policy` | `true` | Standard in-memory engine |
| **`rusqlite`** | `0.31` | SQLite Ledger Storage | `relay-ledger` | `false` | `bundled`, `backup`, `hooks` |
| **`sqlparser`** | `0.47` | SQL AST Normalization | `relay-canonical` | `false` | `standard`, `postgres` |
| **`tokio-postgres`** | `0.7` | Native PostgreSQL Driver | `relay-connectors` | `false` | `runtime`, `with-chrono-0_4`, `with-serde_json-1` |
| **`reqwest`** | `0.12` | Native Outbound HTTPS Client | `relay-connectors` | `false` | `rustls-tls`, `json`, `stream`, `tokio-util` |
| **`hyper`** | `1.4` | Loopback Egress Proxy | `relay-credentials` | `false` | `http1`, `http2`, `server`, `client` |
| **`hyper-util`** | `0.1` | Hyper 1.x Tokio Glue | `relay-credentials` | `false` | `tokio`, `server-auto` |
| **`http-body-util`** | `0.1` | HTTP Body combinators | `relay-credentials` | `true` | Standard |
| **`ed25519-dalek`** | `2.1` | Ed25519 DSSE Signatures | `relay-receipts` | `false` | `rand_core`, `serde`, `zeroize` |
| **`sha2`** | `0.10` | SHA-256 Digest Computation | `relay-canonical`, `relay-receipts`, `relay-ledger` | `true` | Standard |
| **`base64`** | `0.22` | DSSE Payload Encoding | `relay-receipts` | `true` | Standard |
| **`zeroize`** | `1.8` | Secure Memory Scrubbing | `relay-domain`, `relay-credentials` | `false` | `derive`, `zeroize_derive`, `alloc` |
| **`secrecy`** | `0.8` | Secret String Encapsulation | `relay-domain`, `relay-credentials` | `false` | `serde`, `alloc` |
| **`rustix`** | `0.38` | Memory Locking (`mlock`) | `relay-credentials`, `relay-cli` | `false` | `mm`, `process`, `param` |
| **`keyring`** | `3.0` | OS Secure Credential Keyring | `relay-credentials` | `false` | `apple-native`, `sync-secret-service`, `windows-native` |
| **`clap`** | `4.5` | CLI Argument Parsing | `relay-cli` | `false` | `derive`, `env`, `help`, `usage`, `error-context` |
| **`toml`** | `0.8` | Configuration Deserialization | `relay-cli` | `false` | `parse`, `display` |
| **`uuid`** | `1.9` | UUIDv7 Monotonic IDs | `relay-domain`, `relay-receipts` | `false` | `v7`, `serde` |
| **`chrono`** | `0.4` | Deterministic UTC Timestamps | `relay-domain`, `relay-receipts` | `false` | `clock`, `serde` |
| **`tracing`** | `0.1` | Structured Instrumentation | *All crates* | `false` | `std`, `attributes` |
| **`tracing-subscriber`** | `0.3` | Logging Output & Filtering | `relay-cli` | `false` | `env-filter`, `fmt`, `json`, `ansi` |
| **`regex`** | `1.10` | Secret Redaction Engine | `relay-cli` | `false` | `std`, `perf`, `unicode-case` |
| **`thiserror`** | `1.0` | Strongly Typed Error Enums | *All library crates* | `true` | Standard |
| **`color-eyre`** | `0.6` | User-Facing CLI Errors | `relay-cli` | `true` | Standard |
| **`proptest`** | `1.5` | Property-Based Testing | `[dev-dependencies]` | `true` | Standard |
| **`wiremock`** | `0.6` | HTTP Mock Testing | `[dev-dependencies]` | `true` | Standard |
| **`tempfile`** | `3.10` | Ephemeral Test Directories | `[dev-dependencies]` | `true` | Standard |
| **`assert_cmd`** | `2.0` | CLI Binary Assertions | `[dev-dependencies]` | `true` | Standard |
| **`predicates`** | `3.1` | Test Assertion Matchers | `[dev-dependencies]` | `true` | Standard |

---

## 4. Explicitly Rejected Alternatives & Justification

To maintain a lean, secure, and auditable codebase, several popular crates were evaluated and explicitly rejected:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 REJECTED CRATES & JUSTIFICATIONS                                 │
├───────────────────────┬──────────────────────────┬───────────────────────────────────────────────┤
│ Evaluated Candidate   │ Selected Replacement     │ Technical & Security Rejection Rationale      │
├───────────────────────┼──────────────────────────┼───────────────────────────────────────────────┤
│ `openssl`             │ `rustls` (via `reqwest`) │ Massive C dependency, complicated cross-      │
│                       │                          │ compilation, memory unsafety attack surface.  │
├───────────────────────┼──────────────────────────┼───────────────────────────────────────────────┤
│ `sqlx`                │ `tokio-postgres` +       │ Heavy compile-time macro engine, bulky query  │
│                       │ `rusqlite`               │ parsing, unnecessary connection pool overhead.│
├───────────────────────┼──────────────────────────┼───────────────────────────────────────────────┤
│ `diesel` / `sea-orm`  │ `rusqlite`               │ ORM bloat, complex relational mapping layer   │
│                       │                          │ unnecessary for append-only hash chains.      │
├───────────────────────┼──────────────────────────┼───────────────────────────────────────────────┤
│ `mcp-sdk` (Unofficial)│ `relay-mcp` (In-Tree)    │ Incomplete spec compliance, rapid breaking    │
│                       │                          │ changes, unvetted transitive dependencies.    │
├───────────────────────┼──────────────────────────┼───────────────────────────────────────────────┤
│ `ring`                │ `ed25519-dalek` + `sha2` │ `ring` includes complex C and assembly files   │
│                       │                          │ that complicate pure Rust supply-chain audits.│
├───────────────────────┼──────────────────────────┼───────────────────────────────────────────────┤
│ `async-std` / `smol`  │ `tokio`                  │ Fractured ecosystem compatibility; lacks the  │
│                       │                          │ extensive audit history and tooling of Tokio. │
├───────────────────────┼──────────────────────────┼───────────────────────────────────────────────┤
│ `anyhow` (in libs)    │ `thiserror`              │ Dynamic type-erased errors prevent caller     │
│                       │                          │ pattern matching on specific security faults. │
├───────────────────────┼──────────────────────────┼───────────────────────────────────────────────┤
│ `in-toto` (C/Go FFI)  │ `relay-receipts` (Pure)  │ FFI boundary overhead, unsafe memory risk,    │
│                       │                          │ and brittle cross-platform toolchains.        │
└───────────────────────┴──────────────────────────┴───────────────────────────────────────────────┘
```

---

## 5. Cargo Workspace Architecture & Crate Layering

Relay is structured as a tightly cohesive, single-binary Cargo workspace. Workspace crates are decoupled along strict functional and security boundaries:

```
relay/
├── Cargo.toml                      # Workspace root manifest & shared dependency versions
├── Cargo.lock                      # Pinned dependency lockfile (committed to Git)
├── deny.toml                       # cargo-deny security & license policy configuration
├── crates/
│   ├── relay-domain/               # Core pure domain models, newtypes, state machines
│   ├── relay-canonical/            # RFC 8785 JCS, SQL AST, and path normalizers
│   ├── relay-policy/               # Cedar PDP engine integration & schema validators
│   ├── relay-credentials/          # Keyring, SecretBuffer, loopback proxy & JIT leases
│   ├── relay-receipts/             # in-toto v1.0 Statement formatting & Ed25519 DSSE
│   ├── relay-connectors/           # Native connectors (GitHub, Postgres, Filesystem)
│   ├── relay-mcp/                  # Stdio JSON-RPC transport, framing & tool registry
│   ├── relay-ledger/               # SQLite append-only hash-chain ledger
│   └── relay-cli/                  # Binary entrypoint, CLI commands, TTY prompts
└── tests/                          # Workspace-level black-box and adversarial E2E tests
```

### 5.1 Crate Dependency Graph

The workspace enforces a unidirectional Directed Acyclic Graph (DAG). Lower-level domain crates have zero dependencies on higher-level I/O, database, or network crates:

```
                                  ┌─────────────┐
                                  │  relay-cli  │ (Binary Entrypoint)
                                  └──────┬──────┘
                                         │
        ┌───────────────────┬────────────┴───────┬───────────────────┐
        │                   │                    │                   │
        ▼                   ▼                    ▼                   ▼
┌──────────────┐    ┌──────────────┐     ┌──────────────┐    ┌──────────────┐
│  relay-mcp   │    │ relay-connect│     │relay-credent │    │ relay-ledger │
└───────┬──────┘    └───────┬──────┘     └───────┬──────┘    └───────┬──────┘
        │                   │                    │                   │
        │                   ▼                    ▼                   │
        │           ┌──────────────┐     ┌──────────────┐            │
        │           │relay-receipts│     │ relay-policy │            │
        │           └───────┬──────┘     └───────┬──────┘            │
        │                   │                    │                   │
        └───────────┬───────┴────────────┬───────┴───────────────────┘
                    │                    │
                    ▼                    ▼
            ┌──────────────┐     ┌──────────────┐
            │relay-canonic │     │ relay-domain │ (Zero I/O, Pure Logic)
            └───────┬──────┘     └──────────────┘
                    │
                    ▼
            ┌──────────────┐
            │ relay-domain │
            └──────────────┘
```

### 5.2 Workspace Manifest (`Cargo.toml`)

```toml
[workspace]
resolver = "2"
members = [
    "crates/relay-domain",
    "crates/relay-canonical",
    "crates/relay-policy",
    "crates/relay-credentials",
    "crates/relay-receipts",
    "crates/relay-connectors",
    "crates/relay-mcp",
    "crates/relay-ledger",
    "crates/relay-cli",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
rust-version = "1.78"
authors = ["Relay Security Architects <security@relay.dev>"]
license = "Apache-2.0"
repository = "https://github.com/relay-security/relay"

[workspace.dependencies]
# Internal Workspace Crates
relay-domain = { path = "crates/relay-domain" }
relay-canonical = { path = "crates/relay-canonical" }
relay-policy = { path = "crates/relay-policy" }
relay-credentials = { path = "crates/relay-credentials" }
relay-receipts = { path = "crates/relay-receipts" }
relay-connectors = { path = "crates/relay-connectors" }
relay-mcp = { path = "crates/relay-mcp" }
relay-ledger = { path = "crates/relay-ledger" }

# Serialization & Canonicalization
serde = { version = "1.0.203", default-features = false, features = ["derive", "alloc"] }
serde_json = { version = "1.0.117", default-features = false, features = ["alloc", "raw_value", "preserve_order"] }
serde_jcs = { version = "0.1.0" }

# Policy Engine
cedar-policy = { version = "4.0.0" }

# Database & SQL
rusqlite = { version = "0.31.0", default-features = false, features = ["bundled", "backup", "hooks"] }
sqlparser = { version = "0.47.0", default-features = false, features = ["standard", "postgres"] }
tokio-postgres = { version = "0.7.10", default-features = false, features = ["runtime", "with-chrono-0_4", "with-serde_json-1"] }

# Async & Networking
tokio = { version = "1.38.0", default-features = false }
reqwest = { version = "0.12.5", default-features = false, features = ["rustls-tls", "json", "stream", "tokio-util"] }
hyper = { version = "1.4.1", default-features = false, features = ["http1", "http2", "server", "client"] }
hyper-util = { version = "0.1.6", default-features = false, features = ["tokio", "server-auto"] }
http-body-util = { version = "0.1.2" }

# Cryptography & Memory Security
ed25519-dalek = { version = "2.1.1", default-features = false, features = ["rand_core", "serde", "zeroize"] }
sha2 = { version = "0.10.8" }
base64 = { version = "0.22.1" }
zeroize = { version = "1.8.1", default-features = false, features = ["derive", "zeroize_derive", "alloc"] }
secrecy = { version = "0.8.0", default-features = false, features = ["serde", "alloc"] }
rustix = { version = "0.38.34", default-features = false, features = ["mm", "process", "param"] }
keyring = { version = "3.0.0", default-features = false, features = ["apple-native", "sync-secret-service", "windows-native"] }

# CLI, Configuration & Telemetry
clap = { version = "4.5.7", default-features = false, features = ["derive", "env", "help", "usage", "error-context"] }
toml = { version = "0.8.14", default-features = false, features = ["parse", "display"] }
uuid = { version = "1.9.0", default-features = false, features = ["v7", "serde"] }
chrono = { version = "0.4.38", default-features = false, features = ["clock", "serde"] }
tracing = { version = "0.1.40", default-features = false, features = ["std", "attributes"] }
tracing-subscriber = { version = "0.3.18", default-features = false, features = ["env-filter", "fmt", "json", "ansi"] }
regex = { version = "1.10.5", default-features = false, features = ["std", "perf", "unicode-case"] }
thiserror = { version = "1.0.61" }
color-eyre = { version = "0.6.3" }

# Test Dependencies
proptest = { version = "1.5.0" }
wiremock = { version = "0.6.0" }
tempfile = { version = "3.10.1" }
assert_cmd = { version = "2.0.14" }
predicates = { version = "3.1.0" }

[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
strip = true
```

---

## 6. Dependency Architectural Rules & Negative Constraints

To enforce the separation of concerns and prevent security boundary violations, the workspace strictly enforces the following **Negative Dependency Rules**:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   NEGATIVE DEPENDENCY INVARIANTS                                 │
├────────────────────┬─────────────────────────────┬───────────────────────────────────────────────┤
│ Workspace Crate    │ PROHIBITED Dependencies     │ Rationale / Architectural Boundary            │
├────────────────────┼─────────────────────────────┼───────────────────────────────────────────────┤
│ `relay-domain`     │ `tokio`, `rusqlite`,        │ The domain model must remain 100% pure,       │
│                    │ `reqwest`, `hyper`,         │ deterministic, and free of I/O, network, or   │
│                    │ `keyring`, `cedar-policy`   │ storage side-effects.                         │
├────────────────────┼─────────────────────────────┼───────────────────────────────────────────────┤
│ `relay-canonical`  │ `tokio`, `rusqlite`,        │ Canonicalization and AST normalization must   │
│                    │ `reqwest`, `keyring`        │ be pure CPU transformations without ambient   │
│                    │                             │ network or filesystem side-effects.           │
├────────────────────┼─────────────────────────────┼───────────────────────────────────────────────┤
│ `relay-policy`     │ `rusqlite`, `reqwest`,      │ Cedar PDP evaluation must be isolated from    │
│                    │ `keyring`, `tokio`          │ external I/O and execute entirely in-memory.  │
├────────────────────┼─────────────────────────────┼───────────────────────────────────────────────┤
│ `relay-receipts`   │ `tokio`, `reqwest`,         │ Receipt attestation and DSSE signing operate  │
│                    │ `rusqlite`, `keyring`       │ purely on in-memory domain structures.        │
├────────────────────┼─────────────────────────────┼───────────────────────────────────────────────┤
│ `relay-credentials`│ `relay-mcp`, `rusqlite`     │ Credential broker must not have direct access │
│                    │                             │ to the untrusted agent transport or ledger.   │
├────────────────────┼─────────────────────────────┼───────────────────────────────────────────────┤
│ `relay-ledger`     │ `reqwest`, `hyper`,         │ SQLite storage layer must not perform network │
│                    │ `keyring`, `cedar-policy`   │ calls or policy evaluations.                  │
└────────────────────┴─────────────────────────────┴───────────────────────────────────────────────┘
```

These rules are enforced at build time via `cargo-deny` ban configurations and CI check scripts that inspect `cargo metadata`.

---

## 7. Supply-Chain Security Controls

### 7.1 Pinned Dependency Lockfile (`Cargo.lock`)
* The exact `Cargo.lock` file is committed to version control.
* All CI/CD build gates execute `cargo build --locked` and `cargo test --locked` to prevent unexpected transitive dependency drift.

### 7.2 Automated License & Advisory Checking (`cargo-deny`)
The workspace enforces the following `deny.toml` configuration on every Git push and pull request:

```toml
# deny.toml - Relay Supply Chain & Security Policy

[graph]
targets = [
    { triple = "x86_64-unknown-linux-gnu" },
    { triple = "aarch64-unknown-linux-gnu" },
    { triple = "x86_64-apple-darwin" },
    { triple = "aarch64-apple-darwin" },
]

[advisories]
vulnerability = "deny"
unmaintained = "deny"
yanked = "deny"
ignore = []

[licenses]
unlicensed = "deny"
allow = [
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-DFS-2016",
]
confidence-threshold = 0.92

[bans]
multiple-versions = "deny"
wildcards = "deny"
deny = [
    # Strictly ban C-based OpenSSL
    { name = "openssl" },
    { name = "openssl-sys" },
    # Ban unvetted dynamic FFI crates
    { name = "libsqlite3-sys", wrappers = ["rusqlite"] },
]
```

### 7.3 Software Bill of Materials (SBOM) Generation
* Releases utilize `cargo-auditable` during compilation:
  ```bash
  cargo auditable build --release --locked
  ```
  `cargo-auditable` embeds a cryptographically secure, JSON-encoded dependency graph directly into the `.dep-v0` ELF/Mach-O binary section.
* Formal CycloneDX and SPDX SBOMs are generated in CI using `cargo-sbom`:
  ```bash
  cargo sbom --output-format cyclonedx-json > dist/relay-sbom.json
  ```

### 7.4 Hermetic & Reproducible Builds
* Official release binaries are compiled within hermetic Docker build containers (`rust:1.78-slim-bookworm` pinned by SHA-256 digest).
* Build environment flags enforce deterministic binary hashing:
  ```bash
  export RUSTFLAGS="-C target-cpu=generic -C symbol-mangling-version=v0 --remap-path-prefix=$(pwd)=/build"
  export SOURCE_DATE_EPOCH=1726185480
  ```

### 7.5 Release Binary Signing
* Release artifacts (binaries and SBOMs) are cryptographically signed using **Cosign** / **Sigstore** with ambient GitHub Actions OIDC identity.
* The release tarball includes an Ed25519 signature file (`relay.sig`) and SHA-256 checksums (`SHA256SUMS`).

---

## 8. Upgrade Policy & Vulnerability Lifecycle

Relay enforces a rigorous dependency upgrade and CVE response protocol:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   VULNERABILITY RESPONSE CADENCE                                 │
├────────────────────┬─────────────────────────────────────────────────────────────────────────────┤
│ Severity           │ Required Remediation Timeline & Action                                      │
├────────────────────┼─────────────────────────────────────────────────────────────────────────────┤
│ **CRITICAL (CVSS $\ge 9.0$)** │ Immediate build break in CI. Triage and patch release issued within 24 hours. │
│                    │ If no upstream patch exists, remove feature or deploy in-tree mitigation.   │
├────────────────────┼─────────────────────────────────────────────────────────────────────────────┤
│ **HIGH (CVSS $7.0 - 8.9$)**   │ Remediation branch merged and patch release issued within 72 hours.         │
├────────────────────┼─────────────────────────────────────────────────────────────────────────────┤
│ **MEDIUM / LOW**   │ Addressed in the next bi-weekly dependency maintenance sprint.              │
└────────────────────┴─────────────────────────────────────────────────────────────────────────────┘
```

### 8.1 Maintenance Cadence
* **Weekly Automated Scans:** GitHub Actions runs `cargo audit` and `cargo deny check` on a weekly schedule.
* **Bi-Weekly Dependabot Updates:** Minor and patch updates are reviewed and merged bi-weekly following full passing of the 26-Vector Adversarial Gauntlet (`A005`).
* **Major Version Upgrades:** Major crate version increments (e.g. Tokio 2.0 or Cedar 5.0) require a formal Architectural Change Proposal (ACP) and re-audit of unsafe code boundaries.
