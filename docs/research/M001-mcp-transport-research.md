# M001: Model Context Protocol (MCP) 2026 Transport & Specification Research

**Document ID:** `RES-M001-001`  
**Date:** 2026-09-14  
**Status:** Completed Research Baseline  
**Author:** Principal Security & Protocol Architect  
**Authoritative Specification Baseline:** Model Context Protocol Specification (Revision `2026-07-28` & `2026-11-25` updates)  

---

## 1. Executive Summary

This research establishes the protocol-level foundation for extending Relay's zero-trust governance model to external, third-party Model Context Protocol (MCP) servers.

The Model Context Protocol has evolved significantly from its initial 2024/2025 drafts. Most notably:
1. **Stateless Protocol Core & Streamable HTTP (2026-07-28):** Deprecated legacy stateful HTTP+SSE transport pairings in favor of a unified **Streamable HTTP** transport.
2. **Header-Based Protocol Routing:** Introduced standard HTTP headers (`Mcp-Method`, `Mcp-Name`, `Mcp-Version`, `Mcp-Session-Id`) enabling intermediate network gateways to route and authorize requests without buffering and parsing entire multi-megabyte JSON-RPC request bodies.
3. **Decoupled Asynchronous Tasks (`tasks/*`):** Standardized long-running background operations that execute independently of synchronous request-response lifecycles.
4. **OAuth 2.1 & Local Server Authorization:** Formalized resource server discovery (RFC 8414), token presentation via standard headers, and strict localhost DNS rebinding protections.

This document analyzes the current protocol mechanics, official SDK behaviors (TypeScript, Python, Rust), and their architectural implications for Relay's proposed egress proxy.

---

## 2. Authoritative Protocol Mechanics (2026 Specification)

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             MCP 2026 TRANSPORT MATRIX                            │
├──────────────────────────┬───────────────────────────────────────────────────────┤
│ STDIO Transport          │ Bidirectional JSON-RPC 2.0 over standard I/O pipes.   │
│                          │ Local subprocess spawned by host; environment filtered│
│                          │ by Relay (SI-001, SI-018).                            │
├──────────────────────────┼───────────────────────────────────────────────────────┤
│ Streamable HTTP Transport│ Single HTTP/1.1 or HTTP/2 endpoint. Requests are HTTP │
│ (Current Standard)       │ POST with JSON-RPC payload. Responses are direct JSON │
│                          │ or chunked `text/event-stream` for progressive tools. │
├──────────────────────────┼───────────────────────────────────────────────────────┤
│ HTTP + SSE (Deprecated)  │ Dual-endpoint transport (/sse GET + /message POST).   │
│                          │ Maintained strictly for backward compatibility with   │
│                          │ 2024-era servers; deprecated in modern 2026 SDKs.     │
└──────────────────────────┴───────────────────────────────────────────────────────┘
```

---

## 3. Protocol Headers & Interception Points

The 2026-07-28 specification establishes explicit HTTP header semantics designed for proxying and gateway mediation:

### 3.1 Routing & Inspection Headers
- `Mcp-Method`: Contains the JSON-RPC method being invoked (e.g., `tools/call`, `tools/list`, `resources/read`, `prompts/get`, `tasks/create`).
  - *Relay Significance:* Allows Relay's proxy to evaluate Cedar authorization rules at the HTTP header stage before parsing body bytes.
- `Mcp-Name`: For `tools/call` and `resources/read`, contains the specific tool identity (e.g., `github.create_issue`) or resource URI.
- `Mcp-Version`: Identifies protocol schema negotiation (e.g., `2026-07-28`).
- `Mcp-Session-Id`: Ephemeral session identifier generated during protocol initialization.

### 3.2 Protocol Version Negotiation
During initialization:
```http
POST /mcp HTTP/1.1
Host: api.example.com
Mcp-Version: 2026-07-28
Mcp-Method: initialize
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2026-07-28",
    "capabilities": {
      "tools": { "listChanged": true },
      "resources": { "subscribe": true },
      "tasks": { "create": true }
    },
    "clientInfo": {
      "name": "relay-gateway",
      "version": "0.1.0"
    }
  }
}
```

---

## 4. Official SDK Implementation Behavior

### 4.1 TypeScript SDK (`@modelcontextprotocol/sdk` v1.8+)
- **Transport Defaults:** Defaults to `StdioClientTransport` for local subprocesses and `StreamableHttpClientTransport` for remote endpoints.
- **Proxy Support:** Respects standard `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` environment variables when running under Node.js via `undici` / `node-fetch` proxy agents.
- **Connection Pooling:** Maintains an internal HTTP keep-alive connection pool reusing TCP connections across sequential `tools/call` invocations.

### 4.2 Python SDK (`mcp` v1.5+)
- **Transport Defaults:** `mcp.client.stdio` and `mcp.client.streamable_http` built on `httpx` and `anyio`.
- **Proxy Support:** Automatically reads `HTTP_PROXY` and `HTTPS_PROXY` from the process environment when creating `httpx.AsyncClient`.
- **Streaming:** Uses chunked HTTP streaming for long-running outputs and Task events.

### 4.3 Rust SDK Ecosystem (`rmcp` / community)
- **Transport Defaults:** `tokio` asynchronous I/O with `reqwest` (using `rustls`).
- **Proxy Support:** Respects `HTTP_PROXY` / `HTTPS_PROXY` via `reqwest::Proxy`.

---

## 5. Architectural Implications for Relay

1. **Header-First Cedar Authorization:** Relay's proxy can inspect `Mcp-Method` and `Mcp-Name` on ingress HTTP frames to perform fast Cedar policy checks before buffering large request bodies.
2. **Elimination of SSE Session Complexity:** The adoption of Streamable HTTP removes the need for Relay to maintain stateful synchronization between paired `/sse` GET listeners and `/message` POST dispatchers.
3. **Connection Pooling vs. Action Binding:** Because SDKs reuse persistent TCP connections across multiple distinct tool calls, Relay **cannot** assume that one TCP connection corresponds to one tool execution. Authorization and credential leasing must operate at the **HTTP request layer**, not the transport layer.
4. **Task Decoupling:** Asynchronous tasks (`tasks/create`, `tasks/result`) execute across extended timeframes (>30s), requiring explicit policy handling for long-lived operations.
