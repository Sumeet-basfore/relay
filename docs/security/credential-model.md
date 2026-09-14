# Relay Credential Security Model

**Document ID:** `SEC-CRED-001`  
**Version:** `0.1.0`  
**Author:** Principal Security Architect  
**Status:** Approved Specification  

---

## 1. Architectural Distinction: Three Credential Tiers

Relay distinguishes three fundamental security dimensions regarding credentials:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               CREDENTIAL SECURITY TIERS                                │
├────────────────────────────┬────────────────────────────┬──────────────────────────────┤
│ 1. AGENT ISOLATION         │ 2. SECRET STORAGE SECURITY │ 3. HARDWARE-BACKED CUSTODY   │
├────────────────────────────┼────────────────────────────┼──────────────────────────────┤
│ Preventing the AI agent    │ Encrypting secrets at rest │ Storing root master keys in  │
│ process from ever observing│ in the OS secure store or  │ hardware security modules,   │
│ target credentials in env, │ local encrypted vault.     │ Apple Secure Enclave, or TPM.│
│ memory, or IPC streams.    │                            │                              │
│ [ENFORCED BY RELAY GATEWAY]│ [OS KEYRING / ENCRYPTED DB]│ [PLATFORM DEPENDENT]         │
└────────────────────────────┴────────────────────────────┴──────────────────────────────┘
```

**Core Invariant (SI-001):** Relay's primary guarantee is **Agent Credential Isolation**. Under no circumstances does the agent process receive raw API tokens, connection strings, or passwords.

---

## 2. JIT Lease Lifecycle & Enforcement

Credentials are never held persistently in Relay worker memory. They are retrieved Just-In-Time (JIT) exclusively upon policy approval:

```text
                      1. Tool Invocation (No Secrets)
     Agent Process ─────────────────────────────────────► Relay Gateway
                                                                │
                                                                │ 2. Canonicalize & Evaluate
                                                                ▼
                                                          Cedar Policy
                                                          (Strict Allow)
                                                                │
                                                                │ 3. Policy Approved
                                                                ▼
                                                        Approval Provider
                                                          (/dev/tty if needed)
                                                                │
                                                                │ 4. Issue Scoped Lease
                                                                ▼
                                                        Credential Broker
                                                      (Keyring / Memory Store)
                                                                │
                                                                │ 5. Ephemeral SecretBuffer
                                                                ▼
                                                         Native Connector
                                                       (In-Process Execution)
                                                                │
                                                                │ 6. Complete Action
                                                                ▼
                                                        Auto-Zeroize on Drop
                                                       (zeroize::Zeroize + munlock)
```

### Key Lease Properties:
1. **Action-Bound (SI-006):** Each lease is bound to the exact `ActionHash` computed during canonicalization. Attempting to consume a lease for a different tool or modified arguments fails closed.
2. **Single-Use:** Once an action executes, the lease token is immediately consumed and invalidated.
3. **Strict Ephemeral Lifetime:** Leases have a default TTL of 30 seconds. Expired leases cannot be redeemed.
4. **Approval-Before-Credential:** If an action requires step-up human approval, the Credential Broker **refuses** to retrieve or lease secrets until human approval is cryptographically verified.

---

## 3. In-Memory Secret Protection (`SecretBuffer`)

Secret material in Relay is encapsulated within `relay_domain::SecretBuffer`:

- **Virtual Memory Locking (`mlock`):** Locks the allocated memory pages into physical RAM, preventing the host OS from paging sensitive bytes into unencrypted disk swap space.
- **Automatic Memory Scrubbing (`Drop`):** Upon completion or panic, the `Drop` handler invokes `zeroize::Zeroize` to overwrite memory with zero bytes prior to deallocation.
- **Redaction by Default (SI-008):** `fmt::Debug` emits `"[REDACTED <N> bytes]"` and `fmt::Display` emits `"[REDACTED SECRET]"`. Plaintext secrets can never be printed by logging frameworks.

---

## 4. Credential Provider Matrix

Relay supports three credential backends:

| Provider | Mechanism | Security Classification | Recommended Deployment |
|:---|:---|:---:|:---|
| **OS Keyring (`KeyringProvider`)** | Apple Keychain, Windows Credential Manager, Linux Secret Service (DBus) | **Production (Recommended)** | Standard desktop, developer workstations, authenticated servers with OS keyring daemon |
| **Encrypted File (`EncryptedFileProvider`)** | AES-256-GCM authenticated encryption with PBKDF2 key derivation | **Production Fallback** | Headless CI/CD runners, containerized environments lacking DBus/keyring |
| **In-Memory (`InMemoryCredentialProvider`)** | Ephemeral process RAM | **Testing / Transient** | Automated integration tests and short-lived ephemeral CLI sessions |

> [!WARNING]
> **Fallback Storage Limitations:** When using `EncryptedFileProvider`, the master encryption key must be provided via `RELAY_MASTER_KEY` or an interactive passphrase. In automated CI/CD environments where the master key is passed as an environment variable to Relay, compromise of the Relay process user identity grants access to the master key.
