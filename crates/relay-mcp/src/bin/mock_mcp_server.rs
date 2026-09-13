//! Minimal MCP stdio server for Relay integration tests, with controllable
//! modes for testing startup timeouts, process signals, and broken pipes.

use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

fn write_frame(stdout: &mut io::Stdout, value: &Value) -> io::Result<()> {
    let line = serde_json::to_string(value).expect("serialize");
    stdout.write_all(line.as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn handle_request(id: &Value, method: &str, params: Option<&Value>) -> Value {
    match method {
        "initialize" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-mcp-server", "version": "0.1.0"}
            }
        }),
        "tools/list" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": [
                    {
                        "name": "echo",
                        "description": "Echo tool arguments",
                        "inputSchema": {"type": "object"}
                    },
                    {
                        "name": "relay.internal.env_dump",
                        "description": "Return sanitized child environment keys for tests",
                        "inputSchema": {"type": "object"}
                    }
                ]
            }
        }),
        "tools/call" => {
            let params = params.cloned().unwrap_or_else(|| json!({}));
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));

            let content = if name == "relay.internal.env_dump" {
                let keys: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
                json!({"keys": keys})
            } else {
                json!({"echo": arguments})
            };

            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{"type": "text", "text": content.to_string()}],
                    "isError": false
                }
            })
        }
        "ping" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {}
        }),
        other => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32601,
                "message": format!("Method not found: {other}")
            }
        }),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Mode 1: Fail immediately on startup
    if args.iter().any(|a| a == "--exit-on-startup") {
        std::process::exit(42);
    }

    // Mode 2: Hang indefinitely on startup without reading or writing
    if args.iter().any(|a| a == "--hang-on-startup") {
        std::thread::sleep(std::time::Duration::from_secs(3600));
        return;
    }

    // Mode 3: Ignore SIGTERM (forces SIGKILL after grace period)
    if args.iter().any(|a| a == "--ignore-sigterm") {
        #[cfg(unix)]
        unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
        }
    }

    // Mode 4: Close stdin early
    if args.iter().any(|a| a == "--close-stdin-early") {
        #[cfg(unix)]
        unsafe {
            libc::close(0);
        }
        std::thread::sleep(std::time::Duration::from_secs(3600));
        return;
    }

    // Mode 5: Close stdout early
    let close_stdout_early = args.iter().any(|a| a == "--close-stdout-early");
    if close_stdout_early {
        #[cfg(unix)]
        unsafe {
            libc::close(1);
        }
        std::thread::sleep(std::time::Duration::from_secs(3600));
        return;
    }

    let exit_during_init = args.iter().any(|a| a == "--exit-during-init");
    let exit_on_request_method = args
        .iter()
        .position(|a| a == "--exit-on-request")
        .and_then(|pos| args.get(pos + 1).cloned());

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut lines = stdin.lock().lines();

    while let Some(line) = lines.next().transpose().expect("read stdin") {
        if line.trim().is_empty() {
            continue;
        }

        let value: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let method = value.get("method").and_then(|v| v.as_str());
        let id = value.get("id").cloned();
        let params = value.get("params");

        if let Some(method) = method {
            if method == "initialize" && exit_during_init {
                // Exit immediately during initialization without writing response
                std::process::exit(43);
            }

            if let Some(ref target) = exit_on_request_method {
                if method == target {
                    // Exit immediately on target request without writing response
                    std::process::exit(44);
                }
            }

            if let Some(id) = id {
                let response = handle_request(&id, method, params);
                write_frame(&mut stdout, &response).expect("write stdout");
            } else if method == "notifications/initialized" {
                // notification: no response
            }
        }
    }
}
