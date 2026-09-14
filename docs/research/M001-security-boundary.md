# M001: Security Boundary Analysis & Action-to-Network Binding

**Document ID:** `RES-M001-004`  
**Date:** 2026-09-14  
**Status:** Completed Boundary Analysis  
**Author:** Principal Security Architect  

---

## 1. Defining the Three Security Goals

When mediating third-party MCP subprocess networking, Relay evaluates three distinct security goals:

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                            THREE SECURITY GOALS (G1-G3)                          │
├──────────────────────────────────────────────────────────────────────────────────┤
│ G1: Credential Mediation                                                         │
│     Prevent target credentials from being observed by the MCP subprocess while   │
│     injecting them dynamically into authorized upstream HTTP requests.           │
│     STATUS: REALISTICALLY ENFORCEABLE across all platforms via forward proxy.    │
├──────────────────────────────────────────────────────────────────────────────────┤
│ G2: Destination Mediation                                                         │
│     Restrict network destinations so the subprocess can only contact explicitly  │
│     permitted hostnames and IPs, blocking cloud metadata and internal subnets.   │
│     STATUS: ENFORCEABLE on Linux via netns sandbox; COOPERATIVE on macOS/Windows.│
├──────────────────────────────────────────────────────────────────────────────────┤
│ G3: Action-to-Network Correlation Binding                                        │
│     Cryptographically bind a single MCP `tools/call` JSON-RPC frame to exact      │
│     outbound HTTP network requests and returned responses.                       │
│     STATUS: PARTIALLY ENFORCEABLE via ephemeral time-bounded proxy sessions.     │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Action-to-Network Binding: Technical Realities & Limits

A common misconception in API proxying is assuming that one high-level tool invocation (e.g. `jira.create_ticket`) maps 1:1 to exactly one outbound HTTP request.

### In Reality, Modern HTTP Client Libraries Exhibit:
1. **Multiple Requests per Action:** A single tool execution may perform:
   - Token exchange / OAuth refresh.
   - Resource discovery (`GET /api/v2/schema`).
   - Mutation (`POST /api/v2/tickets`).
   - Secondary fetch (`GET /api/v2/tickets/PROJ-101`).
2. **HTTP Redirects:** `POST /resource` returning `302 Found` to an alternate URL.
3. **Connection Reuse & Pooling:** Keep-alive connections stay open and are reused across different tool invocations over the lifetime of the process.
4. **Background / Speculative Prefetching:** SDKs may prefetch schemas or cache data concurrently.

### Relay's Defensible Action-to-Network Binding Model:
Relay rejects the false claim of "cryptographic packet-level 1:1 action binding" for arbitrary third-party code.

Instead, Relay implements an **Ephemeral Time-Bounded Proxy Session Model**:
1. When Relay receives a governed `tools/call` from the agent, Cedar evaluates policy.
2. If permitted, Relay's Credential Broker generates an ephemeral, short-lived **Proxy Authorization Token** ($T_{\text{lease}}$) with a 30-second TTL bound to:
   - Permitted destination hostname (e.g., `api.atlassian.com`).
   - Permitted tool identity (e.g., `jira.create_ticket`).
   - ActionHash of the initiating tool call.
3. The proxy allows outbound requests authenticated with $T_{\text{lease}}$ to the permitted destination.
4. When the tool call completes (or times out), the proxy burns $T_{\text{lease}}$, terminating any inflight connections.

```text
       Agent                     Relay Gateway                   MCP Subprocess            Upstream API
         │                             │                                │                       │
         │ 1. tools/call (jira.create) │                                │                       │
         ├────────────────────────────►│                                │                       │
         │                             │ 2. Cedar Authorize (Allow)     │                       │
         │                             │ 3. Generate Ephemeral Lease    │                       │
         │                             │ 4. Forward tools/call (stdio)  │                       │
         │                             ├───────────────────────────────►│                       │
         │                             │                                │ 5. HTTP POST /tickets │
         │                             │ 6. Validate Destination        ├──────────────────────►│
         │                             │ 7. Inject Target Credential    │   (via Relay Proxy)   │
         │                             │ 8. Forward to Upstream         │                       │
         │                             │                                │                       ├──────┐
         │                             │                                │                       │ Exec │
         │                             │ 9. Observe HTTP 201            │                       │◄─────┘
         │                             │◄───────────────────────────────┤                       │
         │                             │                                │                       │
         │                             │ 10. Burn Lease Token           │                       │
         │ 11. Return tools/call result│                                │                       │
         │◄────────────────────────────┤                                │                       │
```

---

## 3. Credential Flow Design (Model B: Forward Proxy Header Injection)

To satisfy **SI-001** (Zero Target Credentials in Subprocess) while supporting third-party servers:

1. **Subprocess Environment:** The child process receives an ephemeral proxy token `RELAY_PROXY_AUTH=<lease_token>` (or sends it via `Proxy-Authorization: Bearer <lease_token>`).
2. **Vaulted Secret Custody:** The real target API secret (e.g. Jira API Token) remains inside Relay's JIT Credential Broker.
3. **Upstream Header Replacement:** When the proxy receives the outbound request from the subprocess:
   - Validates `<lease_token>` against active, unexpired leases.
   - Strips `Proxy-Authorization`.
   - Injects `Authorization: Bearer <vaulted_jira_token>` into the upstream TLS request.
4. **Zero Subprocess Visibility:** The child process never observes the real vaulted credential in memory, disk, or response headers.
