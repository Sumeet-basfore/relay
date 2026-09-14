# M001: Threat Model for Third-Party MCP Subprocesses

**Document ID:** `RES-M001-002`  
**Date:** 2026-09-14  
**Status:** Completed Threat Model  
**Author:** Principal Security Architect  

---

## 1. Adversary Model: The Untrusted MCP Subprocess

In Relay's extended architecture, third-party MCP servers are executed as local child subprocesses to provide domain-specific tools (e.g. Jira MCP server, Slack MCP server, custom internal tool).

**Core Adversarial Assumption:**
> **The MCP server subprocess is completely untrusted, potentially malicious, or vulnerable to remote code execution.**

The subprocess is assumed to be an active adversary attempting to exfiltrate data, bypass network controls, harvest credentials, or access internal infrastructure.

---

## 2. Threat Analysis Matrix

| Threat ID | Threat Vector | Attack Preconditions | Concrete Attack Scenario | Relay Control | Residual Risk |
|:---|:---|:---|:---|:---|:---|
| **TM-MCP-01** | **Direct Raw Socket Bypass** | Subprocess executed on host without OS network sandboxing | Malicious server opens `socket(AF_INET, SOCK_STREAM)` directly to `attacker-c2.com:443`, ignoring `HTTP_PROXY` env vars. | **OS Network Sandbox Mode (Linux netns):** Blocks all non-loopback egress.<br>**Cooperative Mode:** Not blocked. | High on platforms lacking OS network namespace isolation (macOS/Windows without kernel drivers). |
| **TM-MCP-02** | **Cloud Metadata Service Access (SSRF)** | Subprocess running on AWS EC2, GCP GCE, or Azure VM | Subprocess issues HTTP request to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` or `fd00:ec2::254` to steal instance role tokens. | **IP/CIDR Blacklist Gate:** Relay proxy unconditionally blocks loopback link-local (`169.254.0.0/16`, `fe80::/10`), IPv6 link-local, and cloud metadata IPs before DNS resolution. | Requires proxy mediation to intercept the request. |
| **TM-MCP-03** | **Internal RFC 1918 Lateral Movement** | Subprocess running on corporate intranet or VPC | Subprocess scans `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` to attack internal Redis, Kubernetes API, or databases. | **Destination Allowlist Policy:** Cedar policy enforces strict default-deny on destination hostnames; private IP ranges blocked unless explicitly permitted. | Direct socket bypass in un-sandboxed mode. |
| **TM-MCP-04** | **Localhost Service Exploitation** | Local daemon running on `127.0.0.1` (e.g., local database, Docker daemon) | Subprocess targets `127.0.0.1:2375` (Docker API) or `127.0.0.1:5432` to bypass authentication. | **Loopback Isolation:** Relay proxy rejects proxy requests targeting `127.0.0.1`, `localhost`, `::1` other than Relay's designated gateway port. | Direct socket access to local ports in un-sandboxed mode. |
| **TM-MCP-05** | **CONNECT Tunneling Abuse** | Subprocess uses `HTTP CONNECT` method through proxy | Subprocess sends `CONNECT 10.0.0.1:22 HTTP/1.1` through Relay proxy to establish raw SSH or arbitrary TCP tunnel. | **CONNECT Policy Gate:** Relay restricts `CONNECT` strictly to port `443` for approved TLS hostnames, or terminates TLS locally for deep inspection. | TLS inspection requires local CA trust. |
| **TM-MCP-06** | **DNS Rebinding Attack** | Attacker controls public DNS server | Subprocess requests `attacker.com` (initially resolves to public IP), then DNS changes to `169.254.169.254` on subsequent lookup. | **Pre-Authorization DNS Resolution & IP Pinning:** Relay resolves DNS *before* policy check, validates the resolved IP against blacklist, and connects directly to the validated IP. | Direct DNS queries in un-sandboxed mode. |
| **TM-MCP-07** | **Proxy Credential Sniffing** | Subprocess inspects headers sent by proxy | Subprocess attempts to read `Authorization` headers injected by Relay. | **Outbound-Only Injection:** Relay injects target credentials into the *upstream* HTTP connection to the remote API, *never* returning headers to the subprocess. | None (traffic flows upstream). |
| **TM-MCP-08** | **HTTP Request Smuggling** | Upstream server and Relay have mismatched HTTP parsers | Subprocess sends pipelined requests with conflicting `Content-Length` and `Transfer-Encoding` to bypass policy. | **Strict HTTP Parsing via `hyper` / `httparse`:** Rejects ambiguous framing, enforces RFC 9112 strict compliance, disables HTTP/1.1 pipelining. | Upstream server vulnerabilities. |
| **TM-MCP-09** | **Subprocess Child Spawning (`fork`/`exec`)** | Subprocess spawns secondary background process | Subprocess launches `curl` or a background reverse shell to evade process tracking. | **OS Process Limits (`prctl`/`seccomp`):** In sandboxed mode, `CLONE_NEWPID` and `setrlimit(RLIMIT_NPROC)` prevent unmonitored background process proliferation. | Platform dependent. |

---

## 3. Threat Modeling Takeaway

An **application-layer HTTP proxy alone** (`HTTP_PROXY=http://127.0.0.1:<port>`) provides **Cooperative Governance** (effective against well-behaved SDKs and benign tools).

To defend against an **actively malicious subprocess** executing raw sockets, the architecture **must combine the HTTP proxy with OS-level network containment** (e.g. Linux Network Namespaces).
