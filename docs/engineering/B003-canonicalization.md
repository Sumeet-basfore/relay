# Milestone B003: Canonicalization and Resource-Normalization Layer

**Status:** Completed & Verified  
**Milestone:** B003  
**Specification References:** [A001 System Architecture](../architecture/A001-system-architecture.md), [A002 Domain Model](../architecture/A002-domain-model.md), [A003 Interfaces & Contracts](../architecture/A003-interfaces-and-contracts.md), [A004 Security Invariants](../architecture/A004-security-invariants.md), [A005 Test Strategy](../architecture/A005-test-strategy.md), [A010 Build Specification](../architecture/A010-build-specification.md)  
**Implementation Crates:** `crates/relay-domain`, `crates/relay-canonical`, `crates/relay-mcp`

---

## 1. Executive Summary

Milestone B003 establishes the single authoritative, canonical security representation (`CanonicalAction`) of an agent action in Relay. The primary security objective of B003 is to enforce **Canonical Representation Equivalence (SI-005)**: making it structurally impossible for downstream Cedar authorization (B004) and execution dispatch (B006) to consume different representations of an action.

```text
MCP tools/call frame (raw bytes)
             ↓
Strict JSON Parser (rejection of duplicate keys, NaN, Infinity)
             ↓
ToolCallContext Validation & ToolIdentity Resolution
             ↓
Domain AST Normalization (Filesystem, SQL AST, GitHub URI)
             ↓
RFC 8785 JSON Canonicalization Scheme (JCS)
             ↓
CanonicalAction Payload & SHA-256 ActionHash
             │
             ├──► Cedar Policy Authorization (B004)
             └──► Execution Dispatch (B006)
```

---

## 2. The Authoritative Canonical Action Model

Relay defines `CanonicalAction` in `relay-canonical::action` as the immutable unit of work passed forward:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalAction {
    pub action_id: ActionId,
    pub session_id: SessionId,
    pub principal: PrincipalId,
    pub mcp_method: String,
    pub tool: ToolIdentity,
    pub resource: ResourceUri,
    pub canonical_arguments: serde_json::Value,
    pub schema_digest: SchemaDigest,
    pub environment: ExecutionEnvironment,
    pub action_hash: ActionHash,
    pub canonical_bytes: Vec<u8>,
    pub created_at: DateTime<Utc>,
}
```

### Invariant Guarantee: Single Source of Truth
Neither Cedar authorization nor connector execution parses raw MCP JSON or reconstructs arguments. Both modules consume `CanonicalAction` directly. The exact same arguments and resource URI evaluated by Cedar are dispatched to the native connector or governed subprocess.

---

## 3. RFC 8785 / JCS Implementation

Relay canonicalizes JSON payloads using RFC 8785 (JSON Canonicalization Scheme) via `serde_jcs`:

1. **Key Sorting:** Object keys are sorted lexicographically by UTF-16 code units (RFC 8785 §3.2.3).
2. **Whitespace Stripping:** All whitespace outside string literals is eliminated.
3. **Number Normalization:** Numbers with whole integer values are serialized without trailing decimals (`1.0` becomes `1`, `1e0` becomes `1`, `-0` becomes `0`).
4. **String Escaping:** Only quotation marks (`"`), reverse solidus (`\`), and ASCII control characters (`\u0000` through `\u001f`) are escaped. Non-control UTF-8 code points are emitted directly without escaping.

Conformance is validated against RFC 8785 test vectors in `crates/relay-canonical/tests/jcs_rfc8785_tests.rs`.

---

## 4. Duplicate JSON Key Rejection

Standard JSON parsers exhibit unpredictable last-write-wins or first-write-wins semantics when object keys are duplicated (RFC 8259 §4). In a security gateway, this introduces critical authorization bypass vulnerabilities (e.g., `{"path": "/safe", "path": "/etc/passwd"}`).

Relay implements `StrictValueVisitor` (`crates/relay-canonical/src/json_checker.rs`), which recursively inspects JSON objects during deserialization:
- If `map.contains_key(&key)` evaluates to true at any nesting depth, deserialization fails immediately with `CanonicalizationError::DuplicateKey(key)`.
- At the MCP gateway boundary, duplicate keys produce JSON-RPC error code `-32700` (Parse Error) before entering the interception or authorization pipelines.

---

## 5. Numeric Edge Cases and Disallowed Tokens

1. **NaN and Infinity:** Disallowed in standard JSON; rejected immediately with `CanonicalizationError::MalformedJson`.
2. **Floats vs. Integers:** In accordance with JCS, whole floats (`1.0`, `1e0`) serialize identically to integers (`1`), eliminating numeric parser ambiguity.
3. **Integer Bounds:** 64-bit signed and unsigned bounds are strictly checked; overflow returns errors rather than truncating.

---

## 6. Unicode Policy

Relay enforces a strict, explicit Unicode policy:
1. **UTF-8 Validity:** Inbound JSON and string parameters must be valid UTF-8. Invalid byte sequences produce `CanonicalizationError::UnsupportedEncoding`.
2. **No Silent Normalization (No NFC/NFD Folding):** Relay does **not** silently normalize Unicode forms (such as NFC or NFD). On Linux, filesystems are byte-addressed: two strings that are canonically equivalent under Unicode NFC/NFD may point to two distinct files on disk. Silently rewriting bytes would create file-aliasing and TOCTOU bugs.
3. **JCS UTF-8 Output:** RFC 8785 preserves exact UTF-8 byte sequences for valid characters while standardizing escaped characters.

---

## 7. Tool Identity Model

A raw tool name (e.g. `read`) is insufficient to prevent cross-server collisions. Relay establishes `ToolIdentity`:

```rust
pub struct ToolIdentity {
    pub server_id: String,
    pub namespace: String,
    pub name: String,
    pub version: Option<String>,
}
```

- **Canonical Format:** `server:namespace.name` (e.g. `mock-server:fs.read_file`).
- **Parsing Flexibility:** Supports `server:namespace.name`, `server::namespace::name`, `namespace.name`, and `name`.
- **Collision Resistance:** `serverA:fs.read` and `serverB:fs.read` produce distinct canonical IDs and distinct `ActionHash` values, preventing tool-spoofing attacks.

---

## 8. Tool Schema Pinning & SchemaDigest

Every tool registration binds a cryptographic digest of its input schema:

$$\text{SchemaDigest} = \text{SHA-256}(\text{JCS}(\text{ToolInputSchema}))$$

When computing `CanonicalAction`, the pinned `SchemaDigest` is embedded in the hash payload. If an MCP server updates its schema (e.g. adding parameters or relaxing constraints), the resulting `ActionHash` changes, invalidating any prior authorization or cached approval.

---

## 9. Domain Resource Normalization

Relay implements dedicated domain normalizers rather than naive string concatenation:

### 9.1 Filesystem Normalization (`FilesystemNormalizer`)
- **Lexical Resolution:** Resolves `.` and `..` segments, eliminates duplicate slashes, strips trailing slashes, and normalizes Windows backslashes (`\`) to forward slashes (`/`).
- **Boundary Enforcement:** Rejects directory traversal attempts above the designated base directory (`CanonicalizationError::PathTraversal`).
- **Symlink Resolution:** Resolves physical targets via `std::fs::canonicalize`. If a symlink points outside the base directory, it is rejected.
- **Dangling Symlink Detection:** Detecting broken symlinks returns `CanonicalizationError::DanglingSymlink`.
- **Symlink Cycle Detection:** Detecting symlink loops returns `CanonicalizationError::SymlinkCycle`.
- **Non-Existent Path Handling:** For paths that do not yet exist, Relay walks up to the deepest existing ancestor directory, resolves that ancestor physically (including symlink resolution), and appends the non-existent remainder.
- **Resource URI:** Canonicalized as `file:///absolute/resolved/path`.

### 9.2 PostgreSQL / SQL Normalization (`SqlNormalizer`)
- **Real AST Parsing:** Uses `sqlparser` with `PostgreSqlDialect`.
- **Multi-Statement Rejection:** Enforces single-statement semantics. Queries containing `;` followed by additional statements are rejected with `CanonicalizationError::MultiStatementSqlNotAllowed`.
- **Comment Elimination:** Comments (`--`, `/* */`) are eliminated by re-serializing from the parsed AST.
- **Identifier Lowercasing:** Unquoted identifiers (table and column names) are converted to lowercase per PostgreSQL specification. Quoted identifiers (`"SensitiveData"`) retain exact case and quotes.
- **Destructive Operation Detection:** Operations such as `DROP`, `TRUNCATE`, `ALTER TABLE`, and `UPDATE`/`DELETE` queries without a `WHERE` clause are classified as `is_destructive: true`.
- **Resource URI:** Canonicalized as `postgres://{host}/{db}/{table_list}`.

### 9.3 GitHub Resource Normalization (`GitHubNormalizer`)
- **Format Unification:** Unifies `https://github.com/org/repo`, `git@github.com:org/repo.git`, and shorthand `org/repo`.
- **Case Folding:** Normalizes host, owner, and repo to lowercase.
- **Suffix Removal:** Strips `.git` suffixes.
- **Sub-Resource Parsing:** Classifies pull requests (`/pull/123`, `#123`), issues (`/issues/456`, `#456`), and Git references (`/tree/main`, `@v1.0.0`).
- **Traversal Rejection:** Rejects `..` path traversals in repo or branch identifiers.
- **Resource URI:** Canonicalized as `github://github.com/{owner}/{repo}[/pull/{n}|/issues/{n}|/refs/{ref}]`.

---

## 10. ActionHash Specification

The `ActionHash` is the definitive cryptographic identifier of an authorized action:

$$\text{ActionHash} = \text{SHA-256}(\text{JCS}(\text{CanonicalActionPayload}))$$

Where `CanonicalActionPayload` contains:
- `session_id`: Session UUIDv7
- `principal`: Principal URN string (e.g. `principal:agent:worker1`)
- `mcp_method`: Method string (`tools/call`)
- `tool`: Canonical tool ID (`server:namespace.name`)
- `resource`: Canonical resource URI (`file://...`, `postgres://...`, `github://...`)
- `arguments`: Normalized argument values
- `schema_digest`: Hex-encoded SHA-256 schema digest
- `environment`: `{ cwd, platform, is_interactive_tty }`

---

## 11. Security Divergence Verification (SI-005)

A dedicated test suite (`crates/relay-canonical/tests/security_divergence_tests.rs`) proves that policy and execution representations cannot diverge:

| Adversarial Vector | Inbound Variations | Canonical Representation | Result |
| :--- | :--- | :--- | :--- |
| **Path Traversal** | `/safe/sub/../file.txt` vs. `/safe/file.txt` | Identical physical path `file:///safe/file.txt` | Single ActionHash; no divergence |
| **Symlink Confusion** | `alias_link.txt` -> `real_target.txt` | Resolves to physical target `real_target.txt` | Policy evaluates real target |
| **SQL Comment Injection** | `SELECT * FROM u -- bypass` vs. `SELECT * FROM u` | Identical AST `SELECT * FROM u` | Single ActionHash; no divergence |
| **SQL Batch Injection** | `SELECT 1; DROP TABLE users;` | Rejected (`MultiStatementSqlNotAllowed`) | Attack aborted at gateway |
| **Repo Aliases** | `HTTPS`, `SSH`, and `shorthand` | Identical `github://github.com/owner/repo` | Single ActionHash; no divergence |
| **Server Spoofing** | `serverA:fs.read` vs. `serverB:fs.read` | Distinct canonical IDs | Distinct ActionHashes |
| **Schema Substitution** | Schema v1 vs. Schema v2 | Distinct SchemaDigests | Distinct ActionHashes |

---

## 12. End-to-End Canonicalization Walkthrough

### 12.1 Raw Inbound Tool Call
```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "method": "tools/call",
  "params": {
    "name": "fs.read_file",
    "arguments": {
      "path": "/workspace/subdir/../config/app.toml"
    }
  }
}
```

### 12.2 Gateway Processing
1. **Strict JSON Parsing:** Evaluated with `parse_json_bytes_strictly()`. No duplicate keys found.
2. **Context Resolution:** `session_id` extracted; `tool_name` parsed into `ToolIdentity { server_id: "default", namespace: "fs", name: "read_file" }`.
3. **Filesystem Normalization:** Path `/workspace/subdir/../config/app.toml` is lexically normalized and ancestor-resolved to `/workspace/config/app.toml`.
4. **Resource Resolution:** Evaluated to `file:///workspace/config/app.toml`.
5. **JCS Serialization:** Canonical arguments formatted as `{"path":"/workspace/config/app.toml"}`.
6. **CanonicalActionPayload Assembly:**
   ```json
   {
     "arguments": {"path": "/workspace/config/app.toml"},
     "environment": {"cwd": "/workspace", "is_interactive_tty": false, "platform": "linux"},
     "mcp_method": "tools/call",
     "principal": "principal:agent:default",
     "resource": "file:///workspace/config/app.toml",
     "schema_digest": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
     "session_id": "0191ed3a-932c-7b18-8f83-e1d84b2c1590",
     "tool": "default:fs.read_file"
   }
   ```
7. **ActionHash:** `SHA-256(JCS(Payload))` produces:
   `c8e71822...`

The resulting `CanonicalAction` is passed to the interceptor and onwards to Cedar evaluation and connector dispatch.

---

## 13. Performance Characterization

Measured on Linux x86_64 (`crates/relay-canonical/tests/performance_tests.rs`):

| Operation | Measured Duration |
| :--- | :--- |
| **Small JSON Action Canonicalization** | $74.1\ \mu\text{s}$ |
| **Large JSON Action (100 keys) Canonicalization** | $331.4\ \mu\text{s}$ |
| **Typical SQL Normalization (AST)** | $36.5\ \mu\text{s}$ |
| **Large Multi-Join SQL Normalization (AST)** | $212.8\ \mu\text{s}$ |
| **Filesystem Lexical Normalization** | $1.1\ \mu\text{s}$ |
| **GitHub Resource Normalization** | $2.3\ \mu\text{s}$ |

All normalization operations execute well within sub-millisecond budgets.

---

## 14. B004 Handoff Contract

Milestone B004 (Cedar Policy Engine) will directly consume `CanonicalAction`. To facilitate zero-copy and zero-divergence conversion, `CanonicalAction` provides:

```rust
impl CanonicalAction {
    pub fn to_authorization_request(&self) -> Result<AuthorizationRequest, DomainError>;
}
```

This maps directly to Cedar policy evaluation:
- `principal` $\to$ Cedar Principal entity
- `tool.namespace` + `tool.name` $\to$ Cedar Action entity
- `resource` $\to$ Cedar Resource entity
- `canonical_arguments` $\to$ Cedar Context record
- `action_hash` $\to$ Cached decision correlation and action receipt binding
