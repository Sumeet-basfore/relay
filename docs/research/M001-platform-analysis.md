# M001: Platform Portability & OS Security Analysis

**Document ID:** `RES-M001-005`  
**Date:** 2026-09-14  
**Status:** Completed Platform Analysis  
**Author:** Principal Security Architect  

---

## 1. Platform-Specific Enforcement Capabilities

To prevent raw socket bypass (TM-MCP-01), the host operating system must restrict network interface access for the child process.

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                            PLATFORM ENFORCEMENT MATRIX                           │
├───────────────────┬──────────────────────────────────┬───────────────────────────┤
│ OS PLATFORM       │ UNPRIVILEGED SANDBOX PRIMITIVE   │ ENFORCEMENT CLASSIFICATION│
├───────────────────┼──────────────────────────────────┼───────────────────────────┤
│ Linux (Kernel 3.8+)│ User Namespaces + Network NS     │ **HARD ENFORCED**         │
│                   │ (`unshare -U -n` / `CLONE_NEWNET`)│ (Zero Raw Sockets Allowed)│
├───────────────────┼──────────────────────────────────┼───────────────────────────┤
│ macOS (12+)       │ `sandbox-exec` (Seatbelt / SBPL) │ **MANAGED COOPERATIVE**   │
│                   │ Network Extensions require daemon│ (Cooperative Proxy)       │
├───────────────────┼──────────────────────────────────┼───────────────────────────┤
│ Windows (10/11)   │ AppContainer / Job Objects       │ **MANAGED COOPERATIVE**   │
│                   │ WFP requires Administrator driver│ (Cooperative Proxy)       │
└───────────────────┴──────────────────────────────────┴───────────────────────────┘
```

---

## 2. Linux Deep Dive: Unprivileged User & Network Namespaces

On modern Linux kernels (Ubuntu, Debian, Fedora, Arch, RHEL 8+), an unprivileged process can create a new User Namespace and Network Namespace without `root` or `sudo`:

1. **Namespace Isolation:**
   ```rust
   // Spawning child with private network namespace
   use nix::sched::{unshare, CloneFlags};
   unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET).expect("Unshare netns");
   ```
2. **Loopback Routing:** The isolated child process only possesses a local `lo` loopback device. Any attempt to connect to external IP addresses (`8.8.8.8:443`) fails immediately with `ENETUNREACH` (Network is unreachable).
3. **Controlled Proxy Access:** Relay bridges loopback traffic from the child network namespace to Relay's listening proxy socket using a local UNIX domain socket or slirp4netns bridge.
4. **Result:** **100% Raw Socket Prevention.** Even a malicious C binary calling `socket(AF_INET, SOCK_STREAM)` cannot establish outbound connections outside Relay.

---

## 3. macOS Deep Dive: Sandbox Limitations

On macOS:
- **`sandbox-exec` (Seatbelt):** Apple has officially deprecated `sandbox-exec` and restricted its profile language in macOS 14 (Sonoma) and macOS 15 (Sequoia). While `(deny network-outbound)` can block all networking, allowing network traffic *only* to a specific local port is brittle across macOS updates.
- **Network Extensions (NEAppProxyProvider):** Requires system extension installation, Developer ID signing entitlements, and interactive root approval in System Settings.
- **Decision:** On macOS, Relay provides **Managed Cooperative Proxy Mode** via `HTTP_PROXY` / `HTTPS_PROXY` environment injection and proxy authentication tokens.

---

## 4. Windows Deep Dive: AppContainer Limitations

On Windows:
- **AppContainer:** Restricts network isolation using `INTERNET_CLIENT` and `PRIVATE_NETWORK_CLIENT_SERVER` capabilities. However, allowing loopback connections to the parent process requires explicit loopback exemptions (`CheckNetIsolation.exe LoopbackExempt`).
- **Windows Filtering Platform (WFP):** Requires kernel-mode driver installation and Administrator privileges.
- **Decision:** On Windows, Relay provides **Managed Cooperative Proxy Mode** via standard proxy environment variables and named pipes.

---

## 5. Formal Portability Decision: Tiered Enforcement Model

Relay will not compromise integrity by pretending all operating systems offer identical unprivileged sandboxing.

Instead, Relay defines a **Tiered Enforcement Model**:

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                            TIERED ENFORCEMENT MODES                              │
├──────────────────────────────────────────────────────────────────────────────────┤
│ MODE 1: ENFORCED SANDBOX MODE (Linux)                                            │
│   • Hard isolation via Linux User & Network Namespaces.                          │
│   • Raw socket bypass: IMPOSSIBLE (ENETUNREACH).                                 │
│   • Credential isolation: FULLY ENFORCED.                                        │
│   • Destination allowlisting: FULLY ENFORCED.                                    │
├──────────────────────────────────────────────────────────────────────────────────┤
│ MODE 2: MANAGED COOPERATIVE PROXY MODE (macOS / Windows / Non-Netns Linux)       │
│   • Mediation via `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and header leasing.  │
│   • Credential isolation: FULLY ENFORCED for all proxied traffic.                │
│   • Destination allowlisting: ENFORCED for standard HTTP/HTTPS clients.          │
│   • Documented Residual Risk: Direct raw TCP socket evasion possible by malware. │
└──────────────────────────────────────────────────────────────────────────────────┘
```
