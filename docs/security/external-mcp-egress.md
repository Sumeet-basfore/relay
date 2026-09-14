# External MCP Egress & HTTP Mediation Specification

**Document ID:** `SEC-EGRESS-001`  
**Version:** `0.2.0` (Implemented & Verified in Milestone M002)  
**Author:** Principal Security Architect  
**Status:** Authoritative Implementation Specification  

---

## 1. Overview & Protocol Baseline

This document specifies Relay's architecture for governing third-party MCP subprocess network egress.

- **MCP Transport Baseline:** Model Context Protocol Specification `2026-07-28` (Streamable HTTP and Stdio).
- **Core Principle:** **Authority + Credential Isolation + Evidence** applied to outbound network requests.
- **Implemented Components:** `relay-mcp::egress_proxy`, `relay-mcp::egress_session`, `relay-mcp::egress_dns`, `relay-mcp::egress_injector`, `relay-mcp::egress_sandbox`.

---

## 2. Enforcement Modes & Security Guarantees

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                            EGRESS ENFORCEMENT MODES                              │
├────────────────────────────┬─────────────────────────────────────────────────────┤
│ Enforced Sandbox Mode      │ Linux (User + Network Namespaces: CLONE_NEWNET).    │
│                            │ Zero raw sockets allowed; all network I/O routed    │
│                            │ strictly through Relay's proxy (SI-023).            │
├────────────────────────────┼─────────────────────────────────────────────────────┤
│ Managed Cooperative Mode   │ macOS, Windows, Containerized runtimes.             │
│                            │ Mediates all HTTP/HTTPS client requests respecting  │
│                            │ standard proxy environment variables.               │
└────────────────────────────┴─────────────────────────────────────────────────────┘
```

### What is Guaranteed:
1. **Target Credential Isolation (SI-001, SI-021):** The third-party MCP subprocess never receives raw target API keys or secrets in environment variables or configuration files.
2. **JIT Outbound Header Injection (SI-021):** Relay injects real target credentials into upstream HTTPS requests only after verifying active Cedar policy authorization and valid ephemeral lease tokens.
3. **Cloud Metadata & Private Network Protection (SI-022):** Link-local (`169.254.169.254`), loopback, and unapproved private subnets are blocked before DNS/socket dispatch, with IP pinning to prevent DNS rebinding.
4. **Deterministic Policy Evaluation (SI-019):** Outbound destinations are evaluated as canonical Cedar entities (`Relay::NetworkEndpoint`).
5. **Ephemeral Lease Binding (SI-020):** Proxy leases are time-bounded (30s TTL) and tied to the initiating `ActionHash` and `Principal`.
6. **Hard Linux Kernel Containment (SI-023):** On Linux, direct raw sockets fail with `ENETUNREACH` at the kernel boundary.
7. **Fail-Closed Sandbox (SI-024):** If platform sandbox setup fails, Relay immediately aborts without executing the child process.

### Explicit Non-Guarantees (Residual Risks in Cooperative Mode):
- On macOS and Windows (Managed Cooperative Mode), an intentionally malicious binary executing direct kernel socket syscalls can bypass the proxy environment variables. True hard containment on non-Linux platforms requires host OS containerization (e.g. Docker).

---

## 3. Ephemeral Lease & Credential Flow

1. **Lease Generation:** Upon receiving a permitted `tools/call`, Relay issues an ephemeral lease token $T_{\text{lease}}$ (TTL: 30s) bound to the permitted destination.
2. **Subprocess Invocation:** Relay passes $T_{\text{lease}}$ to the child process via `RELAY_PROXY_AUTH`.
3. **Proxy Interception:** When the subprocess connects to `http://127.0.0.1:<port>`:
   - Subprocess sends `Proxy-Authorization: Bearer <T_lease>`.
   - Relay validates $T_{\text{lease}}$ against the destination host and expiration time.
   - Relay evaluates Cedar PDP policy on `Relay::NetworkEndpoint`.
   - Relay strips `Proxy-Authorization` and injects `Authorization: Bearer <vaulted_secret>`.
4. **Upstream Execution:** Relay establishes the TLS connection to the pinned IP of the remote server and streams the request.
5. **Lease Burning:** When the tool call finishes, $T_{\text{lease}}$ is burned. Subsequent requests are rejected with HTTP `407 Proxy Authentication Required`.

---

## 4. Destination Canonicalization & Cedar Integration

### Canonical Destination Format:
$$\text{URI} = \text{scheme} \mathbin{:} \text{"//"} \text{canonical\_host} \mathbin{:} \text{port} \mathbin{/} \text{normalized\_path}$$

### Example Cedar Policy:
```cedar
// Permit Jira MCP server to contact Jira cloud API
permit (
    principal == Relay::Agent::"principal:agent:claude-code",
    action == Relay::Action::"mcp.http_request",
    resource is Relay::NetworkEndpoint
)
when {
    resource.host == "mycompany.atlassian.net" &&
    resource.port == 443 &&
    resource.scheme == "https"
};
```

---

## 5. Failure Semantics

- **Proxy Down / Unreachable:** Child process network connections fail immediately.
- **Lease Expired / Missing:** Returns HTTP `407 Proxy Authentication Required`.
- **Destination Denied by Cedar:** Returns HTTP `403 Forbidden` with Cedar decision metadata.
- **DNS Resolution Failure / Blacklisted IP (SI-022):** Connection aborted with HTTP `403 Forbidden` or `502 Bad Gateway`.
- **Sandbox Setup Failure (SI-024):** Aborts execution immediately with non-zero exit code.
- **Ambiguous Timeout:** Emits JSON-RPC `-32010 Ambiguous Mutation` and records undetermined receipt in ledger.
