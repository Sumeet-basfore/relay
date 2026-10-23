use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use crate::cli_error::CliError;
use relay_policy::scaffold::{
    classify_tool, generate_and_validate_bundle, ToolDefinition, ToolTier,
};

/// Timeout for MCP stdio discovery handshake.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Executes the `relay policy scaffold` subcommand.
pub async fn execute(
    output: PathBuf,
    from_json: Option<PathBuf>,
    dry_run: bool,
    force: bool,
    env: Vec<String>,
    command: Vec<String>,
) -> Result<(), CliError> {
    let tools = if let Some(json_path) = from_json {
        load_tools_from_json(&json_path)?
    } else if !command.is_empty() {
        discover_tools_from_subprocess(&command, &env).await?
    } else {
        return Err(CliError::ConfigError(
            "Either --from-json <file> or an MCP server command (e.g. `relay policy scaffold -- <cmd>`) must be provided."
                .to_string(),
        ));
    };

    if tools.is_empty() {
        return Err(CliError::ExecutionError(
            "No tools discovered to scaffold policies for.".to_string(),
        ));
    }

    // Pre-flight in-memory compilation & validation against Cedar engine
    let (policy_src, schema_src, policy_set, _) = generate_and_validate_bundle(&tools)
        .map_err(|e| CliError::ExecutionError(format!("Cedar validation failed: {e}")))?;

    // Compute tier counts
    let mut read_count = 0;
    let mut mutation_count = 0;
    let mut destructive_count = 0;

    for tool in &tools {
        match classify_tool(tool) {
            ToolTier::ReadOnly => read_count += 1,
            ToolTier::Mutation => mutation_count += 1,
            ToolTier::Destructive => destructive_count += 1,
        }
    }

    let policy_digest = relay_policy::loader::PolicyLoader::compute_policy_digest(&policy_src);
    let rule_count = policy_set.policies().count();

    if dry_run {
        println!("=== Relay Policy Scaffold (Dry Run) ===");
        println!("Discovered Tools : {}", tools.len());
        println!("  • Read-Only    : {read_count} (Permitted)");
        println!("  • Mutation     : {mutation_count} (Approval Required)");
        println!("  • Destructive  : {destructive_count} (Approval Required)");
        println!("Pre-Flight Check : PASSED (Valid Cedar Schema & Policies)");
        println!("Rule Count       : {rule_count}");
        println!("Policy Digest    : {policy_digest}");
        println!("\n--- schema.cedarschema ---\n{schema_src}");
        println!("--- policy.cedar ---\n{policy_src}");
        return Ok(());
    }

    // Overwrite safety check
    let schema_file = output.join("schema.cedarschema");
    let policy_file = output.join("policy.cedar");

    if !force && (schema_file.exists() || policy_file.exists()) {
        return Err(CliError::ConfigError(format!(
            "Destination directory '{}' already contains Cedar policy files. Pass --force to overwrite.",
            output.display()
        )));
    }

    std::fs::create_dir_all(&output).map_err(|e| {
        CliError::ExecutionError(format!(
            "Failed to create output directory '{}': {e}",
            output.display()
        ))
    })?;

    std::fs::write(&schema_file, &schema_src).map_err(|e| {
        CliError::ExecutionError(format!(
            "Failed to write schema file '{}': {e}",
            schema_file.display()
        ))
    })?;

    std::fs::write(&policy_file, &policy_src).map_err(|e| {
        CliError::ExecutionError(format!(
            "Failed to write policy file '{}': {e}",
            policy_file.display()
        ))
    })?;

    println!("=== Relay Policy Scaffold ===");
    println!("Status           : SUCCESS");
    println!("Discovered Tools : {}", tools.len());
    println!("  • Read-Only    : {read_count} (Permitted)");
    println!("  • Mutation     : {mutation_count} (Approval Required)");
    println!("  • Destructive  : {destructive_count} (Approval Required)");
    println!("Pre-Flight Check : PASSED (Compiled Cleanly via Cedar PDP)");
    println!("Rule Count       : {rule_count}");
    println!("Policy Digest    : {policy_digest}");
    println!("Generated Files  :");
    println!("  ├── {}", schema_file.display());
    println!("  └── {}", policy_file.display());
    println!("\nNext steps:");
    println!(
        "  1. Review generated policies in {}",
        policy_file.display()
    );
    println!(
        "  2. Validate with: relay policy validate --path {}",
        output.display()
    );
    println!(
        "  3. Run governed:  relay run --policy {} -- <server-command>",
        output.display()
    );

    Ok(())
}

/// Loads and normalizes tool definitions from a static JSON file.
pub fn load_tools_from_json(path: &Path) -> Result<Vec<ToolDefinition>, CliError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        CliError::ConfigError(format!(
            "Failed to read tool definition file '{}': {e}",
            path.display()
        ))
    })?;

    let value: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| CliError::ConfigError(format!("Invalid JSON in '{}': {e}", path.display())))?;

    parse_tools_from_json_value(&value)
}

/// Parses tool definitions from various MCP response structures.
pub fn parse_tools_from_json_value(
    value: &serde_json::Value,
) -> Result<Vec<ToolDefinition>, CliError> {
    let raw_tools = if let Some(arr) = value.as_array() {
        arr
    } else if let Some(arr) = value.get("tools").and_then(|t| t.as_array()) {
        arr
    } else if let Some(arr) = value
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
    {
        arr
    } else {
        return Err(CliError::ConfigError(
            "JSON must be an array of tools or an MCP tools/list object containing a 'tools' field."
                .to_string(),
        ));
    };

    let mut tools = Vec::with_capacity(raw_tools.len());
    for item in raw_tools {
        let name = item
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or_else(|| {
                CliError::ConfigError("Tool item missing string 'name' attribute".to_string())
            })?
            .to_string();

        let description = item
            .get("description")
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());

        let input_schema = item
            .get("inputSchema")
            .or_else(|| item.get("input_schema"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        tools.push(ToolDefinition {
            name,
            description,
            input_schema,
        });
    }

    Ok(tools)
}

/// Spawns the MCP server subprocess and executes stdio JSON-RPC handshake to query `tools/list`.
async fn discover_tools_from_subprocess(
    command: &[String],
    env_vars: &[String],
) -> Result<Vec<ToolDefinition>, CliError> {
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::inherit());

    for env_entry in env_vars {
        if let Some((k, v)) = env_entry.split_once('=') {
            cmd.env(k, v);
        }
    }

    let mut child = cmd.spawn().map_err(|e| {
        CliError::ExecutionError(format!(
            "Failed to launch MCP subprocess '{}': {e}",
            command.join(" ")
        ))
    })?;

    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| CliError::ExecutionError("Failed to open child stdin".to_string()))?;

    let stdout = child
        .stdout
        .as_mut()
        .ok_or_else(|| CliError::ExecutionError("Failed to open child stdout".to_string()))?;

    let mut reader = BufReader::new(stdout);

    let discovery_future = async {
        // Step 1: Send MCP initialize request
        let init_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "relay-policy-scaffolder",
                    "version": "0.1.0"
                }
            }
        });

        let mut init_line = serde_json::to_string(&init_req)
            .map_err(|e| CliError::ExecutionError(e.to_string()))?;
        init_line.push('\n');
        stdin
            .write_all(init_line.as_bytes())
            .await
            .map_err(|e| CliError::ExecutionError(format!("Failed to write initialize: {e}")))?;
        stdin
            .flush()
            .await
            .map_err(|e| CliError::ExecutionError(e.to_string()))?;

        // Read initialize response
        let mut resp_line = String::new();
        reader
            .read_line(&mut resp_line)
            .await
            .map_err(|e| CliError::ExecutionError(format!("Failed to read init response: {e}")))?;

        // Step 2: Send initialized notification
        let initialized_notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        let mut notif_line = serde_json::to_string(&initialized_notif)
            .map_err(|e| CliError::ExecutionError(e.to_string()))?;
        notif_line.push('\n');
        stdin.write_all(notif_line.as_bytes()).await.map_err(|e| {
            CliError::ExecutionError(format!("Failed to write initialized notification: {e}"))
        })?;
        stdin
            .flush()
            .await
            .map_err(|e| CliError::ExecutionError(e.to_string()))?;

        // Step 3: Send tools/list request
        let tools_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        });
        let mut tools_line = serde_json::to_string(&tools_req)
            .map_err(|e| CliError::ExecutionError(e.to_string()))?;
        tools_line.push('\n');
        stdin.write_all(tools_line.as_bytes()).await.map_err(|e| {
            CliError::ExecutionError(format!("Failed to write tools/list request: {e}"))
        })?;
        stdin
            .flush()
            .await
            .map_err(|e| CliError::ExecutionError(e.to_string()))?;

        // Read tools/list response
        let mut tools_resp_line = String::new();
        reader.read_line(&mut tools_resp_line).await.map_err(|e| {
            CliError::ExecutionError(format!("Failed to read tools/list response: {e}"))
        })?;

        let val: serde_json::Value = serde_json::from_str(&tools_resp_line).map_err(|e| {
            CliError::ExecutionError(format!("Failed to parse tools/list response as JSON: {e}"))
        })?;

        parse_tools_from_json_value(&val)
    };

    let result = tokio::time::timeout(DISCOVERY_TIMEOUT, discovery_future)
        .await
        .map_err(|_| {
            CliError::ExecutionError(format!(
                "MCP tool discovery timed out after {}s",
                DISCOVERY_TIMEOUT.as_secs()
            ))
        })?;

    // Gracefully terminate child process
    let _ = child.kill().await;

    result
}
