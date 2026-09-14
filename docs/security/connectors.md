# Native Connector Security Boundaries

**Document ID:** `SEC-CONN-001`  
**Version:** `0.1.0`  
**Author:** Principal Security Architect  
**Status:** Approved Specification  

---

## 1. Overview of In-Process Native Connectors

Relay executes governed tools via native, in-process Rust connector modules rather than spawning uncontrolled child subshells.

Executing in-process provides three critical security properties:
1. **Zero IPC Overhead:** Eliminates intermediate serialization and socket listening ports.
2. **Deterministic Credential Binding:** Credentials are held exclusively in typed, ephemeral Rust memory buffers (`SecretBuffer`) and injected directly into target client structs.
3. **Strict Parameter Validation:** Tool arguments are canonicalized into strongly-typed domain structs before dispatch.

---

## 2. Filesystem Connector (`fs.*`)

The Filesystem Connector mediates local disk access.

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                           FILESYSTEM SECURITY BOUNDARY                           │
├──────────────────────────┬───────────────────────────────────────────────────────┤
│ Root Jail Confinement    │ Operations are restricted to the configured root dir. │
│ Lexical Normalization    │ Redundant `.` and `..` segments are normalized out.   │
│ Symlink Traversal Gate   │ Symlinks pointing outside the root are rejected.      │
│ Special File Blocking    │ Sockets, device nodes, pipes, and FIFOs are rejected. │
│ Atomic Write Pattern     │ Writes write to a hidden dotfile before atomic rename.│
│ File Size Limits         │ Default 10 MB maximum per read/write operation.       │
└──────────────────────────┴───────────────────────────────────────────────────────┘
```

### Residual Risks:
- Concurrent external processes modifying files in the workspace (TOCTOU outside Relay control).
- OS disk space exhaustion.

---

## 3. PostgreSQL Connector (`postgres.*`)

The PostgreSQL Connector provides governed SQL execution over TLS-encrypted connections.

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                          POSTGRESQL SECURITY BOUNDARY                            │
├──────────────────────────┬───────────────────────────────────────────────────────┤
│ AST Canonicalization     │ Full SQL AST parsing via `sqlparser-rs`.              │
│ Statement Classification │ Strict distinction between DML (SELECT/INSERT/UPDATE) │
│                          │ and DDL (CREATE/ALTER/DROP).                          │
│ JIT Credential Injection │ Passwords leased just-in-time and zeroized on drop.   │
│ Statement Cancellation   │ Governed by query timeout (default 10s).              │
│ Target Resource Scoping  │ Canonicalized as `postgres://host:port/db/schema/table│
└──────────────────────────┴───────────────────────────────────────────────────────┘
```

### Permitted & Rejected Statements:
- **Permitted under Read Policy:** Single-statement `SELECT` queries without mutating Common Table Expressions (CTEs).
- **Permitted under Write Policy:** Single-statement `INSERT`, `UPDATE`, `DELETE` bounded by WHERE clauses.
- **Rejected by Default:** Multi-statement queries (`SELECT 1; DROP TABLE users;`), DDL statements (`DROP`, `TRUNCATE`, `ALTER`), administrative commands (`VACUUM`, `GRANT`, `COPY`).

### Residual Risks:
- Database functions, triggers, or stored procedures (`SECURITY DEFINER`) that execute internal data mutations when invoked from a `SELECT` statement.

---

## 4. GitHub Connector (`github.*`)

The GitHub Connector mediates REST API operations against GitHub repositories.

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                            GITHUB SECURITY BOUNDARY                              │
├──────────────────────────┬───────────────────────────────────────────────────────┤
│ Endpoint Pinning         │ Strict HTTPS communication to `api.github.com`.       │
│ Redirect Sanitization    │ HTTP redirects to untrusted domains are blocked.      │
│ JIT Token Injection      │ Personal Access Tokens (PATs) injected into headers.  │
│ Scoped API Operations    │ `get_repository`, `create_issue`, `update_issue`, etc.│
│ Ambiguous Mutation Gate  │ Network drop after POST/PATCH flagged as Ambiguous.   │
│ Response Size Bounds     │ Responses capped at 2 MB to prevent memory exhaustion.│
└──────────────────────────┴───────────────────────────────────────────────────────┘
```

### Residual Risks:
- Upstream GitHub API rate limiting or downtime.
- Remote webhook triggers configured on the repository that execute outside Relay's visibility.
