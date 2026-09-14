# GA004 — Authoritative Known Limitations & Residual Risk Registry

**Release:** Relay `v0.1.0`  
**Candidate Commit:** `0360a95f74c33a9fc3d7628876dd9bb7d307e2bb`  
**Status:** **FROZEN & CERTIFIED**  

---

## Authoritative Known Limitations

The following limitations represent the explicit technical boundaries of Relay `v0.1.0`. Each item has been analyzed, documented, and approved as an accepted risk for General Availability:

### 1. Host OS / Kernel / Root Compromise
* **Limitation:** If an adversary achieves `root` / `Administrator` privileges on the host machine running Relay, they can read `/proc/<pid>/mem`, bypass local filesystem permissions, extract the local Ed25519 signing key, or alter kernel networking rules.
* **Impact:** Loss of local confidentiality, evidence integrity, and network isolation.
* **Affected Platform:** All (Linux, macOS, Windows).
* **Mitigation:** Run Relay under an unprivileged dedicated service user (`relay`), enforce SELinux / AppArmor profiles, and utilize hardware HSM/KMS keys in enterprise deployments.
* **Why Accepted:** Standard operating system threat model baseline. Software gateways cannot protect against root kernel compromise.

---

### 2. macOS & Windows Managed Cooperative Proxy Mode
* **Limitation:** On macOS and Windows, external MCP subprocesses are mediated via standard environment proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`). Direct raw TCP socket calls bypassing standard proxy libraries are not blocked at the OS network layer.
* **Impact:** A malicious subprocess author could write custom socket code to bypass HTTP proxy filters on macOS/Windows.
* **Affected Platform:** macOS and Windows only (Linux enforces full NetNS isolation).
* **Mitigation:** Run untrusted third-party MCP servers in containerized Linux environments or VMs when executing on macOS/Windows hosts.
* **Why Accepted:** Full network namespace isolation is a Linux-native kernel capability (`CLONE_NEWNET`). Cross-platform cooperative mode is clearly labeled and diagnosed via `relay doctor`.

---

### 3. Remote SaaS Eventual Consistency & Network Partitions
* **Limitation:** An Action Receipt certifies Relay's exact observation of an execution attempt; it cannot guarantee that a remote cloud provider (e.g. GitHub API, cloud database) reached eventual consistency if a network drop occurred post-dispatch.
* **Impact:** Potential uncertainty regarding whether a remote state mutation occurred on network disconnect.
* **Affected Platform:** All.
* **Mitigation:** Relay records ambiguous outcomes explicitly as `AmbiguousMutation` with epistemology status `Undetermined` (SI-015).
* **Why Accepted:** Fundamental distributed systems reality (Two Generals' Problem).

---

### 4. Direct In-Library Rust Connector Construction
* **Limitation:** If a third-party developer uses Relay as a Rust crate and manually instantiates `FilesystemConnector` directly without embedding it within `GovernedActionRunner`, Cedar policy enforcement must be orchestrated manually.
* **Impact:** In-library misuse could bypass policy if the coordinator is omitted.
* **Affected Platform:** Library integrations.
* **Mitigation:** The CLI binary (`relay`) strictly enforces `GovernedActionRunner` across all tool invocations. Documentation explicitly specifies `GovernedActionRunner` as the mandatory coordinator.
* **Why Accepted:** Library composability design; CLI distribution is 100% complete and fail-closed.
