# Model Context Protocol (MCP) Mediation Boundary

**Document ID:** `SEC-MCP-001`  
**Version:** `0.2.0` (Updated in Milestone M002)  
**Author:** Principal Security Architect  
**Status:** Authoritative Specification  

---

## 1. Overview of MCP Mediation in Relay

Relay functions as a Model Context Protocol (MCP) Security Gateway. It intercepts JSON-RPC protocol communication between an AI agent (the MCP Client) and tool execution providers (MCP Servers), mediating both standard input/output framing and external subprocess network egress.

---

## 2. Currently Mediated in Relay

1. **Stdio MCP Framing:** Intercepting all `tools/call`, `tools/list`, and JSON-RPC frames over standard I/O streams (`stdin`/`stdout`).
2. **Native Filesystem Tools (`relay.fs.*`):** File read, write, append, stat, list, and delete operations executed via the in-process Native Filesystem Connector.
3. **Native PostgreSQL Tools (`relay.postgres.*`):** SQL queries and statements executed via the in-process Native PostgreSQL Connector.
4. **Native GitHub Tools (`relay.github.*`):** Repository queries, issue tracking, and PR management executed via the in-process Native GitHub Connector.
5. **Human Approval Escalation:** Interactive approval prompts delivered over `/dev/tty` for step-up actions.
6. **In-Process Loopback HTTP Egress Proxy (`relay-mcp::egress_proxy`):** Intercepting outbound HTTP and HTTPS `CONNECT` tunnels with Cedar destination allowlists (SI-019).
7. **Ephemeral Proxy Session Leases (`relay-mcp::egress_session`):** Single-use and time-bounded (30s TTL) proxy lease tokens bound to `ActionHash` (SI-020).
8. **Vaulted Upstream Credential Injection (`relay-mcp::egress_injector`):** Injecting secrets into upstream requests without exposing credentials to child processes (SI-021).
9. **Pre-DNS Blacklist & IP Pinning (`relay-mcp::egress_dns`):** Blocking cloud metadata (`169.254.169.254`), loopback, and private IP ranges to prevent SSRF and DNS rebinding (SI-022).
10. **Linux Network Namespace Sandbox (`relay-mcp::egress_sandbox`):** Unprivileged user & network namespaces (`CLONE_NEWUSER | CLONE_NEWNET`) eliminating 100% of raw socket bypass attempts (SI-023).

---

## 3. Mediation Architecture Scope

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                            RELAY MEDIATION SCOPE                                 │
├──────────────────────────────────────────────────────────────────────────────────┤
│ FULLY MEDIATED & HARDENED:                                                       │
│   • All Stdio JSON-RPC Frames                                                    │
│   • Native In-Process Filesystem Connector                                       │
│   • Native In-Process PostgreSQL Connector                                       │
│   • Native In-Process GitHub Connector                                           │
│   • Child Subprocess Environment Sanitization (No Ambient Tokens - SI-001)       │
│   • Ephemeral Header-Injecting Loopback HTTP Forward Proxy (SI-021)              │
│   • Destination Allowlisting via AWS Cedar (Relay::NetworkEndpoint - SI-019)     │
│   • Pre-DNS Cloud Metadata & Private IP Blocking with IP Pinning (SI-022)        │
│   • Linux User & Network Namespace Sandboxing (Zero Raw Sockets - SI-023)        │
│   • Fail-Closed Sandbox Initialization (SI-024)                                  │
├──────────────────────────────────────────────────────────────────────────────────┤
│ MANAGED COOPERATIVE MODE (macOS / Windows):                                      │
│   • Environment Variable Proxy Injection (HTTP_PROXY / HTTPS_PROXY)              │
│   • Documented residual risk for adversarial binaries calling raw socket syscalls│
└──────────────────────────────────────────────────────────────────────────────────┘
```

