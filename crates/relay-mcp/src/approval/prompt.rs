//! Safe prompt formatting and secret redaction for TTY human approvals (A004, A007).

use chrono::Utc;
use relay_domain::Approval;
use serde_json::Value;

/// Recursively traverses a JSON value and redacts sensitive keys and secret patterns.
pub fn redact_sensitive_value(val: &Value) -> Value {
    match val {
        Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (k, v) in map {
                let lower_k = k.to_lowercase();
                if is_sensitive_key(&lower_k) {
                    new_map.insert(k.clone(), Value::String("[VAULTED]".to_string()));
                } else {
                    new_map.insert(k.clone(), redact_sensitive_value(v));
                }
            }
            Value::Object(new_map)
        }
        Value::Array(arr) => {
            let new_arr = arr.iter().map(redact_sensitive_value).collect();
            Value::Array(new_arr)
        }
        Value::String(s) => {
            if is_sensitive_string_pattern(s) {
                Value::String("[VAULTED]".to_string())
            } else {
                Value::String(s.clone())
            }
        }
        other => other.clone(),
    }
}

/// Identifies key names that commonly hold secrets
fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    lower.contains("password")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("key")
        || lower.contains("auth")
        || lower.contains("credential")
        || lower.contains("bearer")
        || lower.contains("cookie")
        || lower.contains("private")
        || lower == "sig"
        || lower == "signature"
}

/// Identifies strings that match known secret signatures
fn is_sensitive_string_pattern(s: &str) -> bool {
    s.contains("BEGIN PRIVATE KEY")
        || s.contains("BEGIN RSA PRIVATE KEY")
        || s.contains("BEGIN OPENSSH PRIVATE KEY")
        || s.starts_with("ghp_")
        || s.starts_with("github_pat_")
        || s.starts_with("Bearer ")
        || s.starts_with("Basic ")
}

/// Renders the safe terminal prompt string for an approval request
pub fn render_approval_prompt(approval: &Approval) -> String {
    let now = Utc::now();
    let remaining_secs = if approval.expires_at > now {
        approval.expires_at.timestamp() - now.timestamp()
    } else {
        0
    };

    let action_id = approval
        .action_identity
        .as_deref()
        .unwrap_or("unknown.action");
    let resource = approval.resource.as_deref().unwrap_or("unspecified");
    let principal = approval
        .principal
        .as_ref()
        .map(|p| p.as_str())
        .unwrap_or("unknown");
    let action_hash = approval.action_hash.to_hex();

    let mut out = String::new();
    out.push_str("\n──────────────────────────────────────────────────────────────────────────\n");
    out.push_str("RELAY — HUMAN APPROVAL REQUIRED\n");
    out.push_str("──────────────────────────────────────────────────────────────────────────\n");
    out.push_str(&format!(" Action:    {}\n", action_id));
    out.push_str(&format!(" Resource:  {}\n", resource));
    out.push_str(&format!(" Principal: {}\n", principal));
    out.push_str(" Decision:  APPROVAL_REQUIRED\n");
    out.push_str(&format!(" Hash:      {}\n", action_hash));
    out.push_str(&format!(" Expires:   {}s remaining\n\n", remaining_secs));
    out.push_str(&format!(" Summary:\n   {}\n", approval.summary));

    if let Some(params) = &approval.parameters_preview {
        let redacted = redact_sensitive_value(params);
        if let Ok(pretty) = serde_json::to_string_pretty(&redacted) {
            out.push_str("\n Parameters Preview (Sanitized):\n");
            for line in pretty.lines() {
                out.push_str(&format!("   {}\n", line));
            }
        }
    }

    out.push_str("──────────────────────────────────────────────────────────────────────────\n");
    out.push_str(" [y] Approve once    [n] Deny    [d] Show parameters    [q] Cancel/Abort\n");
    out.push_str(" Selection [y/n/d/q] (default: n)? ");

    out
}

/// Renders detailed parameters view for option [d]
pub fn render_details_view(approval: &Approval) -> String {
    let mut out = String::new();
    out.push_str("\n--- FULL OPERATION DETAILS ---\n");
    out.push_str(&format!("Action Hash: {}\n", approval.action_hash.to_hex()));
    out.push_str(&format!("Decision ID: {}\n", approval.decision_id));
    if let Some(policy_digest) = &approval.policy_digest {
        out.push_str(&format!("Policy Digest: {}\n", policy_digest.to_hex()));
    }
    if let Some(params) = &approval.parameters_preview {
        let redacted = redact_sensitive_value(params);
        if let Ok(pretty) = serde_json::to_string_pretty(&redacted) {
            out.push_str("Sanitized Parameters Payload:\n");
            out.push_str(&pretty);
            out.push('\n');
        }
    } else {
        out.push_str("No parameters provided with approval request.\n");
    }
    out.push_str("------------------------------\n");
    out
}
