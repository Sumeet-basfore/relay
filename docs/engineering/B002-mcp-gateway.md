# Milestone B002: MCP Stdio Gateway & Lifecycle Hardening (B002.1)

**Status:** Hardened & Verified (B002 + B002.1)  
**Milestone:** B002 / B002.1  
**Specification References:** [A001 System Architecture](../architecture/A001-system-architecture.md), [A003 Interfaces](../architecture/A003-interfaces-and-contracts.md), [A004 Security Invariants](../architecture/A004-security-invariants.md), [A005 Test Strategy](../architecture/A005-test-strategy.md), [A007 CLI & DX](../architecture/A007-cli-and-dx.md), [A010 Build Specification](../architecture/A010-build-specification.md)

---

## 1. Executive Summary

Milestone B002 implements Relay's MCP stdio gateway: a bounded, bidirectional JSON-RPC transport between an agent client and a child MCP server subprocess. Milestone B002.1 completes the lifecycle hardening pass resolving process lifecycle edge cases, graceful shutdown sequencing, startup timeouts, broken-pipe resilience, in-flight request error correlation, signal handling, and environment/secret sanitization.

---

## 2. Process Topology & Lifecycle Guardrails

```text
Agent process (e.g. Claude Desktop, Cursor)
    │ stdin/stdout (newline-delimited JSON-RPC)
    ▼
relay run -- <mcp-server> [args...]
    │ diagnostics → stderr only (secrets redacted)
    ▼
MCP child subprocess (env_clear + safe vars + prctl PDEATHSIG)
```

To prevent orphaned or zombie subprocesses across abrupt parent crashes:
1. `cmd.kill_on_drop(true)` is registered on the child handle.
2. On Linux, `prctl(PR_SET_PDEATHSIG, SIGKILL)` is invoked in `pre_exec` so the Linux kernel automatically delivers `SIGKILL` to the child if the Relay process terminates abnormally.

---

## 3. Graceful Shutdown Sequence

Per A001 and A007, Relay enforces the following deterministic termination state machine:

```text
SIGTERM / SIGINT / EOF / Requested Shutdown
                    ↓
   Send termination request (SIGTERM on Unix)
                    ↓
      Wait grace period (default 500ms)
                    ↓
          Child exited in time?
          ├── Yes → reap exit status
          └── No  → escalate to SIGKILL; reap exit status
```

Platform implementation details:
- **Unix:** `libc::kill(pid, libc::SIGTERM)` initiates the graceful shutdown request. If the child does not terminate within `shutdown_grace_period` (default 500ms), Relay escalates to `child.kill()` (`SIGKILL`).
- **Windows / non-Unix:** `child.start_kill()` initiates process termination; fallback to `TerminateProcess`.

---

## 4. Subprocess Startup & Progress Tracking

Relay protects against hung or defective downstream MCP servers through configurable startup constraints:

1. **Default Startup Timeout:** 5.0s (`DEFAULT_STARTUP_TIMEOUT`), configurable via `SubprocessConfig` and `GatewayConfig`.
2. **Immediate Exit Detection:** `child.try_wait()` is evaluated immediately after `spawn()` to catch instant crashes, missing interpreters, or bad entrypoints before entering the transport loop.
3. **Protocol Progress Disarming:** The startup timeout is disarmed as soon as the child emits its first valid downstream JSON-RPC response (handshake progress).
4. **Startup Timeout Expiry:** If the child fails to emit valid protocol progress within the startup timeout, the gateway halts with `GatewayError::StartupTimeout`, terminates the child subprocess, and returns.
5. **In-flight Request Crash Handling:** If the downstream MCP subprocess terminates (due to crash, EOF, broken pipe, or startup timeout) while an active request is pending, Relay emits JSON-RPC error code `-32011` (`Downstream MCP Subprocess Terminated`) to the agent with the correlated request ID per A001.

---

## 5. Broken Pipe & Signal Handling

All pipe failure modes are handled gracefully without hanging or deadlocks:

| Condition | Cause | Gateway Action |
|-----------|-------|----------------|
| Agent stdout consumer closes | Agent exited or closed stdout reader | Gateway catches `BrokenPipe`, aborts I/O tasks, shuts down child gracefully |
| Agent stdin closes | Agent closed stdin (EOF) | Child stdin closed (EOF); child terminates cleanly |
| Child stdin closes | Downstream closed stdin (`libc::close(0)`) | Gateway detects write error / EOF, terminates cleanly |
| Child stdout closes | Downstream closed stdout (`libc::close(1)`) | Gateway detects read EOF, terminates cleanly |
| Child exits during request | Downstream process crashes mid-flight | Returns `-32011 Downstream MCP Subprocess Terminated` to agent; reaps child |
| SIGTERM received | Host / container orchestrator shutdown | Relay CLI intercepts `SIGTERM`, initiates graceful child termination |
| SIGINT received | Terminal Ctrl+C | Relay CLI intercepts `SIGINT`, initiates graceful child termination |

---

## 6. Secret Isolation & Logging Sanitization

1. **Environment Sanitization:** `env_clear()` strips all ambient secrets (`AWS_*`, `GITHUB_*`, `DATABASE_URL`, API keys). Only explicitly allowlisted variables (`PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `LC_*`, `TMPDIR`, Windows system paths) are passed.
2. **Command Argument Redaction:** CLI structured logging records only `arg_count = child_args.len()`, never printing raw command arguments or flags which may contain sensitive tokens.
3. **Error Path Purity:** Diagnostics and error traces never echo subprocess environment maps, token flags, or raw credential strings to stdout or stderr.

---

## 7. Framing & Transport Model

- **Transport:** Newline-delimited JSON-RPC 2.0 (one message per line).
- **Max Frame Size:** 4 MiB (`MAX_FRAME_SIZE_BYTES`).
- **Buffer Safety:** `FrameBuffer` enforces incremental bounded buffering. Oversized frames return JSON-RPC error `-32700` or `-32600` without allocating beyond the limit.
- **Purity:** `stdout` is strictly reserved for valid JSON-RPC frames. All logging (`tracing`) is routed exclusively to `stderr`.

---

## 8. Extension Point for Authorization

- `ToolCallInterceptor` trait intercepts `tools/call` prior to downstream forwarding.
- Shipped with `PassThroughInterceptor` for B002.
- Milestone **B004 (Cedar PEP)** will plug policy evaluation and action authoring directly into this hook.

---

## 9. Comprehensive Test Matrix

The test suite covers unit, integration, broken-pipe, lifecycle, and security properties:

| Test File | Test Case | Target Behavior |
|-----------|-----------|-----------------|
| `broken_pipe_tests.rs` | `test_broken_pipe_agent_stdout_consumer_disappears` | Exits cleanly on agent stdout disconnect |
| `broken_pipe_tests.rs` | `test_broken_pipe_agent_stdin_closing` | Closes downstream on agent EOF |
| `broken_pipe_tests.rs` | `test_broken_pipe_child_stdin_closing` | Handles downstream stdin closure cleanly |
| `broken_pipe_tests.rs` | `test_broken_pipe_child_stdout_closing` | Handles downstream stdout EOF cleanly |
| `broken_pipe_tests.rs` | `test_broken_pipe_child_exiting_during_active_request` | Returns `-32011` error on mid-request crash |
| `lifecycle_signal_tests.rs` | `test_child_fails_immediately` | Immediate exit detection on launch |
| `lifecycle_signal_tests.rs` | `test_child_hangs_on_startup` | Aborts on startup timeout if hung |
| `lifecycle_signal_tests.rs` | `test_child_never_produces_protocol_progress` | Returns `-32011` and exits on timeout |
| `lifecycle_signal_tests.rs` | `test_child_exits_during_initialization` | Propagates error code and child exit status |
| `lifecycle_signal_tests.rs` | `test_signal_graceful_termination` | Clean exit on SIGTERM within grace period |
| `lifecycle_signal_tests.rs` | `test_signal_forced_sigkill_after_grace_period` | Escalates to SIGKILL after 500ms grace period |
| `lifecycle_signal_tests.rs` | `test_gateway_shutdown_signal` | Watch channel triggers graceful child termination |
| `cli_tests.rs` | `test_cli_sigterm_shutdown` | CLI intercepts SIGTERM and exits cleanly |
| `cli_tests.rs` | `test_cli_sigint_shutdown` | CLI intercepts SIGINT and exits cleanly |
| `cli_tests.rs` | `test_cli_secret_regression_in_logs_and_errors` | Zero secrets or sensitive CLI args leaked |
| `cli_tests.rs` | `test_gateway_stdout_is_protocol_only` | Stdout purity verified |
| `cli_tests.rs` | `test_gateway_env_isolation` | Stripped environment verified via child dump |
| `gateway_integration.rs` | `gateway_forwards_initialize` | Initialize handshake roundtrip |
| `gateway_integration.rs` | `gateway_tools_call_echo_roundtrip` | Tool call execution & response |
| `gateway_integration.rs` | `gateway_malformed_json_returns_error` | Malformed frame handling |
| `gateway_integration.rs` | `gateway_oversized_frame_returns_error` | Frame size boundary rejection |
| `frame.rs` (proptest) | `frame_buffer_never_exceeds_limit` | Proptest bounding memory invariants |
| `rpc.rs` (proptest) | `parse_never_panics` | Proptest fuzzing arbitrary JSON-RPC input |

---

## 10. Known Platform Limitations

1. **Linux `PR_SET_PDEATHSIG`:** Relies on Linux-specific `prctl`. On macOS / BSD, child orphan protection relies on `kill_on_drop(true)` in Rust. On Windows, child lifetime is governed by Job Objects or `TerminateProcess`.
2. **Signal Escapes:** Non-cooperative child processes that ignore `SIGTERM` are guaranteed to be killed via `SIGKILL` on Unix after the 500ms grace period.

---

## 11. Verification Commands

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
