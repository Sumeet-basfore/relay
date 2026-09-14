# Secure Deployment & Operations Guide

**Document ID:** `SEC-DEP-001`  
**Version:** `0.1.0`  
**Author:** Principal Security Architect  
**Status:** Approved Operations Baseline  

---

## 1. Hardening Recommendations by Classification

Every deployment recommendation is explicitly labeled:
- **`[REQUIRED]`**: Non-negotiable for system security and invariant guarantees.
- **`[RECOMMENDED]`**: Production best practice to minimize blast radius.
- **`[OPTIONAL]`**: Environment-dependent hardening.
- **`[DEVELOPMENT-ONLY]`**: Strictly prohibited in production environments.

---

## 2. Host OS & Process Hardening

### 2.1 Dedicated Unprivileged User `[RECOMMENDED]`
Run Relay and governed agent processes under a dedicated, unprivileged operating system user account (e.g., `relay-agent`):
- Never run Relay or agent processes as `root` or `Administrator`.
- Disable `sudo` privileges for the agent runtime user.

### 2.2 Strict Filesystem Permissions `[REQUIRED]`
Enforce Unix permissions on Relay state and configuration files:

```bash
# Configuration and Keys
chmod 0700 ~/.config/relay
chmod 0600 ~/.config/relay/signing_key.seed
chmod 0600 ~/.config/relay/relay.toml

# Audit Ledger
chmod 0700 ~/.local/share/relay
chmod 0600 ~/.local/share/relay/ledger.db

# Binary Executable
chmod 0755 ~/.local/bin/relay
```

---

## 3. Credential Provider Selection

| Environment | Recommended Provider | Configuration Requirement | Classification |
|:---|:---|:---|:---:|
| **Developer Workstation (macOS/Linux/Windows)** | `KeyringProvider` (OS Keyring) | Default configuration | `[RECOMMENDED]` |
| **Headless CI/CD Runner / Docker Container** | `EncryptedFileProvider` | Set `RELAY_MASTER_KEY` via CI secrets manager | `[REQUIRED for CI]` |
| **Automated Testing / Ephemeral Sandbox** | `InMemoryCredentialProvider` | Pass credentials via in-memory mock store | `[DEVELOPMENT-ONLY]` |

---

## 4. Policy Configuration Hardening

### 4.1 Principle of Least Privilege `[REQUIRED]`
1. **Explicit Resource Paths:** Never use wildcards (`*`) for root directories. Explicitly bind resource permissions to specific project directories:
   ```cedar
   // CORRECT
   when { resource.path like "/home/user/workspace/project-alpha/*" };
   
   // INCORRECT / DANGEROUS
   when { resource.path like "/*" };
   ```
2. **Explicit Unconditional Forbids `[REQUIRED]`:** Always include explicit `forbid` rules for sensitive files:
   ```cedar
   forbid (principal, action, resource is Relay::Resource)
   when {
       resource.path like "*/.ssh/*" ||
       resource.path like "*/.env*" ||
       resource.path like "*/.aws/*"
   };
   ```
3. **Step-Up Approvals for State Deletions `[RECOMMENDED]`:** Require human interaction (`/dev/tty`) for destructive operations (`fs.delete_file`, `github.delete_branch`).

---

## 5. Non-Interactive / CI/CD Environments

When deploying Relay in automated CI/CD pipelines where no interactive terminal (`/dev/tty`) is present:
- Run with the `--non-interactive` flag.
- Actions that require step-up approval will **fail closed** with `ExitCode::ApprovalRequired` (`7`).
- Ensure all CI/CD actions are covered by explicit, non-interactive Cedar `permit` rules.

---

## 6. Audit Ledger Verification & Rotation

### 6.1 Automated Verification `[RECOMMENDED]`
Incorporate automated ledger verification into daily monitoring or CI/CD pipelines:
```bash
relay verify --ledger /path/to/ledger.db
```

### 6.2 Disaster Recovery Backups `[RECOMMENDED]`
Regularly back up the SQLite ledger and encrypt the node signing key seed into secure cold storage as documented in [Backup & Disaster Recovery](../operations/backup-and-recovery.md).
