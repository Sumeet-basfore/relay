# Getting Started with the Relay Local Security Console

The **Relay Local Security Console** is a local-first web UI providing security operators, platform engineers, and developers with real-time visibility into Relay's security boundary:
- Real-time security posture and policy decision tracking.
- Governed action lifecycle inspection (`Action -> Policy -> Approval -> Credential -> Execution -> Evidence -> Ledger`).
- In-browser cryptographic verification of Action Receipts (Ed25519) and ledger integrity (SHA-256 hash chains).
- Cedar policy syntax validation and atomic reload with fail-closed rollback.
- External MCP network egress sandbox monitoring and blocked destination audit.
- Connector operational status across Filesystem, PostgreSQL, GitHub, and external MCP subprocesses.

---

## 1. Starting the Console

Launch the console using the `relay ui` subcommand:

```bash
relay ui
```

By default, Relay:
1. Generates a secure, ephemeral 256-bit authentication token.
2. Binds to `127.0.0.1:8765` (strict loopback only).
3. Prints the localized launch URL with bootstrap token to `stdout`.
4. Automatically opens your default system web browser.

### Console Launch Output:
```text
============================================================
 Relay Local Security Console (CR002)
============================================================
 Status:       Active & Protected
 Console URL:  http://127.0.0.1:8765/?token=4f8b2c8e1a...
 Binding:      127.0.0.1:8765 (Loopback only)
 Session Auth: CLI-Issued Ephemeral Token (Idle TTL 15m)
 Origin Check: Strict (127.0.0.1 / localhost)
 Telemetry:    Zero Outbound Data (100% Localhost)
============================================================
Press Ctrl+C to terminate the console.
```

---

## 2. CLI Options & Configuration

| Flag / Option | Description | Default |
| :--- | :--- | :--- |
| `-p, --port <PORT>` | Port to bind the local UI server | `8765` |
| `--host <HOST>` | Host address to bind (MUST be a loopback address) | `127.0.0.1` |
| `--no-browser` | Do not automatically open the web browser | `false` |
| `--token <TOKEN>` | Pre-shared session token (instead of generating an ephemeral token) | Ephemeral UUID |

### Headless or Remote SSH Usage:
If you are accessing a remote workstation via SSH:
```bash
# Launch console without opening local browser
relay ui --no-browser --port 8765

# From your local laptop, tunnel the port securely over SSH:
ssh -N -L 8765:127.0.0.1:8765 user@remote-host

# Open the printed URL with token in your local browser
```

---

## 3. Local Authentication & Session Lifecycle

1. **Bootstrap Token Exchange:**  
   The token parameter in `http://127.0.0.1:8765/?token=...` is immediately extracted by the frontend and scrubbed from the browser URL bar and history via `window.history.replaceState`.
2. **Session Tokens:**  
   The token is exchanged with Relay for an active session token (`X-Relay-Session`) and a CSRF token (`X-Relay-CSRF`).
3. **Idle Auto-Lock:**  
   Sessions automatically expire after **15 minutes** of operator inactivity. When locked, the console displays an authentication prompt requiring the token or restarting the CLI command.
4. **Manual Lock:**  
   Click the **Lock** button in the top navigation bar at any time to immediately invalidate the browser session.

---

## 4. Local-Only Security Guarantees & Safeguards

- **Strict Loopback Binding:** Relay refuses to bind to `0.0.0.0` or external network adapters.
- **Anti-DNS Rebinding:** The server validates the HTTP `Host` header on every request. External domains (e.g., `attacker.com` pointing to `127.0.0.1`) are rejected with `403 Forbidden`.
- **CSRF & Origin Verification:** All state-changing requests (`POST`, `PUT`, `DELETE`) require a matching `X-Relay-CSRF` header and strict local origin headers (`http://127.0.0.1:<port>`).
- **No Direct Execution:** The UI exposes zero endpoints to execute arbitrary commands or connect directly to backend databases/filesystems. Execution only occurs via governed MCP stdio channels.
- **Out-of-Band Approvals Preserved:** Critical destructive actions (e.g., file deletion, database modification) continue to require approval on the controlling terminal (`/dev/tty`). The web UI displays approval status, but does not allow a web click to bypass the operator terminal boundary.
- **Data Minimization & Redaction:** Credentials, API tokens (PATs), private keys, and authorization headers are scrubbed and replaced with `[REDACTED]` prior to JSON serialization.

---

## 5. Platform Modes & Limitations

### Linux (Full Enforced Sandbox)
On Linux systems with unprivileged user namespaces enabled:
- Subprocesses spawned by Relay are isolated in a dedicated network namespace (`netns`).
- Raw socket creation and direct host network access are blocked by the Linux kernel.
- Egress network calls are forced through Relay's loopback egress proxy.

### macOS & Windows (Managed Cooperative Proxy Mode)
On macOS and Windows:
- Subprocesses are governed via environment variable stripping and proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`).
- Kernel-level raw socket blocking is unavailable without root containerization or hypervisor VMs.
- Relay clearly highlights this operational limitation in the **Security** view.

---

## 6. Troubleshooting & Diagnostics

### Port Already in Use:
If port 8765 is in use by another service:
```bash
relay ui --port 8766
```

### Browser Displays "Forbidden: Invalid Host Header":
Ensure you are accessing the console using `127.0.0.1` or `localhost`. Accessing via custom hostnames or public IPs will be rejected by Relay's anti-DNS rebinding defenses.

### Session Expired:
If the console has been idle for more than 15 minutes, re-enter your session token or restart `relay ui`.

### Health Diagnostics:
Run `relay doctor` or navigate to the **Doctor** view in the console to inspect ledger file permissions, policy directories, and sandbox capabilities.

---

## 7. Terminating the Console

Press `Ctrl+C` in the terminal where `relay ui` is running. Relay handles `SIGINT` and `SIGTERM` signals gracefully, cleans up active sessions, and terminates the TCP listener cleanly.
