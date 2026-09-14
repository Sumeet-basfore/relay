# Operations Guide: Diagnostics & Troubleshooting

This guide provides diagnostic procedures, standard error mappings, and resolution steps for common Relay operational issues.

---

## 1. Diagnostic Health Check (`relay doctor`)

The first step in diagnosing any Relay issue is running the built-in diagnostic suite:

```bash
relay doctor
```

`relay doctor` checks:
- Binary version and host architecture.
- Configuration file readability and valid syntax.
- SQLite ledger file existence, accessibility, and strict Unix permissions (`0600`).
- Cedar policy directory validity.
- Interactive TTY availability (`/dev/tty`).

---

## 2. Standard CLI Exit Codes

Relay maps all operational outcomes to standard deterministic exit codes:

| Exit Code | Classification | Description | Typical Cause | Resolution |
|:---:|:---|:---|:---|:---|
| **`0`** | `Success` | Normal clean execution | Operation succeeded | No action needed |
| **`1`** | `RuntimeError` | General runtime fault | Subprocess crashed or OS I/O error | Check stderr diagnostics |
| **`2`** | `ConfigError` | Configuration parsing error | Invalid TOML, missing explicit config file | Fix `relay.toml` syntax or path |
| **`3`** | `PolicyDenied` | Cedar policy forbidden action | Action violates Cedar authorization rules | Update Cedar policy if action is intended |
| **`4`** | `ApprovalDenied` | User rejected approval prompt | Human operator selected 'Deny' on `/dev/tty` | Normal rejection |
| **`5`** | `ProtocolError` | JSON-RPC / MCP framing error | Malformed JSON-RPC or frame exceeds 4 MB | Inspect upstream agent payload |
| **`6`** | `SecurityFailure` | Ledger tamper / security fault | Ledger hash-chain mismatch, secret leak | Run `relay verify` to inspect ledger |
| **`7`** | `ApprovalRequired` | Action requires approval in headless mode | Destructive action executed without TTY | Configure `--non-interactive` policy rules |
| **`8`** | `ApprovalExpired` | Human prompt timed out | Operator did not respond within 30 seconds | Increase `approval_timeout_secs` |
| **`9`** | `ApprovalCancelled` | Human interrupted prompt (Ctrl+C / EOF) | Cancelled by operator | Re-run if action is still desired |

---

## 3. Common Troubleshooting Scenarios

### 3.1 Error: `Storage error: Failed to open ledger file: Permission denied`
- **Cause:** SQLite ledger file or parent directory does not have sufficient user read/write permissions.
- **Resolution:**
  ```bash
  chmod 0700 .relay ~/.local/share/relay
  chmod 0600 .relay/ledger.db ~/.local/share/relay/ledger.db
  ```

### 3.2 Error: `Configuration file not found: ...`
- **Cause:** An explicit `--config` path was passed to Relay that does not exist.
- **Resolution:** Verify the config path or omit `--config` to use defaults.

### 3.3 Error: `Ledger verification failed: PayloadHashMismatch`
- **Cause:** Out-of-band modification, disk corruption, or manual tampering with a receipt in the SQLite database.
- **Resolution:** Restore `ledger.db` from a verified backup.

### 3.4 Error: `Action requires human approval, but running in headless mode`
- **Cause:** An action flagged by Cedar policy as requiring step-up approval was invoked in a CI/CD or non-interactive environment where `/dev/tty` is unavailable.
- **Resolution:** Add an explicit Cedar `permit` rule for the agent principal or run in an interactive terminal.
