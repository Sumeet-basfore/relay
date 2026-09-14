# M001: Architecture Options & Evaluation Matrix

**Document ID:** `RES-M001-003`  
**Date:** 2026-09-14  
**Status:** Completed Architecture Evaluation  
**Author:** Principal Security Architect  

---

## 1. Candidate Architecture Overview

Six architectural designs were evaluated for mediating third-party MCP subprocess network traffic:

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             ARCHITECTURE ALTERNATIVES                            │
├──────────────────────────────────────────────────────────────────────────────────┤
│ Option A: Cooperative Environment Proxy (`HTTP_PROXY` / `HTTPS_PROXY` injection) │
│ Option B: Explicit Local Forward Proxy (`127.0.0.1:<port>` with client config)   │
│ Option C: Transparent Network Interception (`nftables` / eBPF / socket redirect) │
│ Option D: OS Sandbox + Loopback Proxy (Linux User Namespaces + netns + Proxy)    │
│ Option E: Containerized Sidecar Isolation (Docker / Podman network bridge)       │
│ Option F: Dynamic Linker Interception (`LD_PRELOAD` / `DYLD_INSERT_LIBRARIES`)   │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Detailed Technical Evaluation

### Option A: Cooperative Environment Proxy (`HTTP_PROXY` / `HTTPS_PROXY`)
- **Mechanism:** Relay spawns the MCP subprocess with `HTTP_PROXY=http://127.0.0.1:<port>`, `HTTPS_PROXY=http://127.0.0.1:<port>`, `ALL_PROXY=http://127.0.0.1:<port>`.
- **Strengths:** Zero root privileges required; works identically across Linux, macOS, and Windows; natively supported by official TypeScript, Python, and Go HTTP clients.
- **Weaknesses:** Cooperative only; a malicious subprocess can bypass it simply by opening a raw TCP socket (`socket(AF_INET, SOCK_STREAM)`).
- **Verdict:** Essential baseline for developer tooling, but cannot claim "complete mediation" against active malware.

---

### Option B: Explicit Local Forward Proxy
- **Mechanism:** Subprocess is explicitly configured with Relay's loopback URL as its base API gateway.
- **Strengths:** Transparent inspection of full HTTP requests (methods, paths, headers, JSON bodies).
- **Weaknesses:** Requires tool-specific configuration; same raw-socket bypass vulnerability as Option A.
- **Verdict:** Useful for native connectors; insufficient for generic third-party binary subprocesses.

---

### Option C: Transparent Network Interception (eBPF / `nftables` / WFP)
- **Mechanism:** Kernel packet filter redirects all outbound TCP packets from subprocess PID/cgroup to Relay's local listening port.
- **Strengths:** True complete mediation; impossible for subprocess to bypass even with raw sockets.
- **Weaknesses:** Requires `root` / `CAP_NET_ADMIN` privileges; platform-specific kernel implementations (`nftables` on Linux, NetworkExtension on macOS, WFP on Windows); heavy operational complexity.
- **Verdict:** Too heavyweight and privilege-intensive for a lightweight, non-root local developer binary.

---

### Option D: OS Sandbox + Loopback Proxy (Linux User Namespaces)
- **Mechanism:** On Linux, Relay spawns the MCP subprocess inside an unprivileged User Namespace and Network Namespace (`CLONE_NEWUSER | CLONE_NEWNET`). The only network interface inside the namespace is a loopback `lo` interface routed via a `veth` pair or slirp4netns to Relay's proxy.
- **Strengths:** True complete mediation on Linux without requiring root permissions; completely blocks raw socket bypass; lightweight.
- **Weaknesses:** Linux-specific (macOS and Windows lack direct unprivileged user network namespaces).
- **Verdict:** Best-in-class security boundary for Linux environments.

---

### Option E: Containerized Sidecar Model (Docker / Podman)
- **Mechanism:** Run third-party MCP servers in separate isolated containers attached to a controlled Docker network bridge.
- **Strengths:** Strong isolation and cross-platform consistency where Docker Desktop is installed.
- **Weaknesses:** Requires external Docker/Podman runtime; heavy memory and startup latency (>500ms); violates Relay's single static binary design principle.
- **Verdict:** Viable as an enterprise deployment pattern, but rejected as Relay's core MVP mechanism.

---

### Option F: Dynamic Linker Interception (`LD_PRELOAD`)
- **Mechanism:** Inject a shared library to hook libc `connect()`, `getaddrinfo()`, and `socket()` syscall wrappers.
- **Strengths:** Can intercept socket creation without root.
- **Weaknesses:** Trivially defeated by statically linked binaries (Go, Rust, musl), inline assembly syscalls, and macOS System Integrity Protection (SIP) which strips `DYLD_INSERT_LIBRARIES`.
- **Verdict:** Fragile, unreliable, and easily bypassed.

---

## 3. Comprehensive Comparison Matrix

| Dimension | Option A: Env Proxy | Option B: Forward Proxy | Option C: Transparent | Option D: Netns Sandbox | Option E: Container | Option F: LD_PRELOAD |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Root Privileges Required** | **No** | **No** | Yes (CAP_NET_ADMIN) | **No (Linux)** | No (User daemon) | **No** |
| **Raw Socket Prevention** | No | No | **Yes** | **Yes** | **Yes** | No (Static binaries) |
| **Credential Injection (G1)**| **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** |
| **Destination Allowlist (G2)**| Cooperative | Cooperative | **Enforced** | **Enforced** | **Enforced** | Cooperative |
| **Action Correlation (G3)** | Time-window | Time-window | Time-window | Time-window | Time-window | Time-window |
| **Cross-Platform Portability**| **Linux/macOS/Win**| **Linux/macOS/Win**| Linux only | Linux only | Docker-dependent | Broken on macOS |
| **Startup Overhead** | **< 1 ms** | **< 1 ms** | < 5 ms | **< 5 ms** | > 500 ms | < 2 ms |
| **Implementation Complexity** | **Low** | **Low** | High | **Medium** | High | High |
