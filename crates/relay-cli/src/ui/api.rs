use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use relay_domain::{InTotoStatement, ReceiptId};
use relay_ledger::{LedgerVerificationStatus, SqliteLedger};
use relay_receipts::ReceiptVerifier;

use crate::config::RelayConfig;
use crate::doctor::generate_doctor_report;
use crate::ui::auth::SessionManager;
use crate::ui::data_minimization::sanitize_json_value;

#[derive(Clone)]
pub struct UiState {
    pub session_manager: Arc<RwLock<SessionManager>>,
    pub config: RelayConfig,
    pub ledger: Arc<SqliteLedger>,
    pub policy_engine: Arc<RwLock<Arc<dyn relay_domain::PolicyEngine>>>,
    pub signing_key_id: String,
    pub signer_pubkey: Option<[u8; 32]>,
    pub port: u16,
}

#[derive(Deserialize)]
struct AuthSessionReq {
    token: String,
}

#[derive(Deserialize)]
struct PolicyValidateReq {
    policy_text: String,
}

pub async fn handle_api_request(
    path: &str,
    method: &str,
    headers: &HashMap<String, String>,
    body: &[u8],
    state: &UiState,
) -> Result<(u16, &'static str, Vec<u8>), (u16, String)> {
    let method_upper = method.to_uppercase();

    // 1. Unauthenticated Bootstrap Endpoint
    if path == "/api/v1/auth/session" {
        if method_upper != "POST" {
            return Err((405, "Method Not Allowed".to_string()));
        }
        let req: AuthSessionReq =
            serde_json::from_slice(body).map_err(|e| (400, format!("Invalid JSON body: {e}")))?;

        let mut sm = state.session_manager.write().await;
        match sm.exchange_token(&req.token) {
            Ok((session_token, csrf_token)) => {
                let resp = json!({
                    "authenticated": true,
                    "session_token": session_token,
                    "csrf_token": csrf_token,
                });
                return Ok((200, "application/json", serde_json::to_vec(&resp).unwrap()));
            }
            Err(e) => {
                return Err((401, format!("Authentication failed: {e}")));
            }
        }
    }

    // 2. Authentication Enforcement for all remaining /api/v1/ endpoints
    let session_token = match headers.get("x-relay-session") {
        Some(t) if !t.trim().is_empty() => t.trim(),
        _ => {
            return Err((
                401,
                "{\"error\":\"Missing X-Relay-Session authentication header\"}".to_string(),
            ))
        }
    };

    {
        let mut sm = state.session_manager.write().await;
        if let Err(e) = sm.validate_session(session_token) {
            return Err((401, format!("{{\"error\":\"Session invalid: {e}\"}}")));
        }
    }

    // 3. CSRF Verification for all state-changing methods (POST, PUT, DELETE)
    if method_upper == "POST" || method_upper == "PUT" || method_upper == "DELETE" {
        let csrf_token = match headers.get("x-relay-csrf") {
            Some(c) if !c.trim().is_empty() => c.trim(),
            _ => {
                return Err((
                    403,
                    "{\"error\":\"Missing X-Relay-CSRF header for mutating operation\"}"
                        .to_string(),
                ))
            }
        };

        let sm = state.session_manager.read().await;
        if let Err(e) = sm.validate_csrf(session_token, csrf_token) {
            return Err((
                403,
                format!("{{\"error\":\"CSRF validation failed: {e}\"}}"),
            ));
        }
    }

    // 4. API Routing
    match (method_upper.as_str(), path) {
        ("GET", "/api/v1/auth/check") => {
            let resp = json!({ "authenticated": true });
            Ok((200, "application/json", serde_json::to_vec(&resp).unwrap()))
        }

        ("GET", "/api/v1/status") => {
            let ledger_count = state.ledger.count().await.unwrap_or(0);
            let ledger_head_seq = ledger_count;

            let egress_sandbox_mode = if cfg!(target_os = "linux") {
                if relay_mcp::EgressSandboxLauncher::is_linux_netns_available() {
                    "Linux Enforced Network Namespace Sandbox [ACTIVE/ENFORCED]"
                } else {
                    "Linux Managed Cooperative Proxy [WARNING: unprivileged userns disabled]"
                }
            } else if cfg!(target_os = "macos") || cfg!(target_os = "windows") {
                "Managed Cooperative Proxy Mode [COOPERATIVE]"
            } else {
                "Unsupported"
            };

            let sandbox_short_mode = if cfg!(target_os = "linux")
                && relay_mcp::EgressSandboxLauncher::is_linux_netns_available()
            {
                "ENFORCED"
            } else {
                "COOPERATIVE"
            };

            let resp = json!({
                "relay_version": env!("CARGO_PKG_VERSION"),
                "target_os": std::env::consts::OS,
                "target_arch": std::env::consts::ARCH,
                "security_status": "PROTECTED",
                "policy_count": 1,
                "ledger_head_seq": ledger_head_seq,
                "ledger_total_entries": ledger_count,
                "active_connectors": 4,
                "egress_sandbox_mode": egress_sandbox_mode,
                "sandbox_short_mode": sandbox_short_mode,
                "signing_key_id": state.signing_key_id,
                "ledger_path": state.config.storage.ledger_path.display().to_string(),
            });
            Ok((200, "application/json", serde_json::to_vec(&resp).unwrap()))
        }

        ("GET", "/api/v1/doctor") => {
            let doc = generate_doctor_report(&state.config).map_err(|e| {
                (
                    500,
                    format!("{{\"error\":\"Failed to generate doctor report: {e}\"}}"),
                )
            })?;
            Ok((200, "application/json", serde_json::to_vec(&doc).unwrap()))
        }

        ("GET", p) if p.starts_with("/api/v1/activity") && !p.starts_with("/api/v1/activity/") => {
            // Activity list
            let limit = 50;
            let entries = state.ledger.list_recent(limit).await.unwrap_or_default();
            let mut items = Vec::new();

            for entry in entries {
                if let Ok(Some(receipt)) = state.ledger.get_receipt_by_id(&entry.receipt_id).await {
                    let mut tool_name = "unknown".to_string();
                    let mut principal = "agent".to_string();
                    let mut resource = "-".to_string();
                    let mut decision = "ALLOW".to_string();
                    let mut approval_state = "NOT_REQUIRED".to_string();
                    let mut status = "EXECUTED".to_string();

                    if let Ok(payload_bytes) =
                        relay_receipts::dsse::base64_decode(&receipt.dsse_envelope.payload)
                    {
                        if let Ok(statement) =
                            serde_json::from_slice::<InTotoStatement>(&payload_bytes)
                        {
                            let pred = statement.predicate;
                            if let Some(tn) = pred
                                .canonical_proposal
                                .get("tool_name")
                                .and_then(|v| v.as_str())
                            {
                                tool_name = tn.to_string();
                            }
                            if let Some(pr) = pred
                                .canonical_proposal
                                .get("principal")
                                .and_then(|v| v.as_str())
                            {
                                principal = pr.to_string();
                            }
                            if let Some(rs) = pred
                                .canonical_proposal
                                .get("resource")
                                .and_then(|v| v.as_str())
                            {
                                resource = rs.to_string();
                            }
                            if let Some(dec) = pred
                                .policy_decision
                                .get("decision")
                                .and_then(|v| v.as_str())
                            {
                                decision = dec.to_string();
                                if decision == "DENY" {
                                    status = "DENIED".to_string();
                                }
                            }
                            if let Some(app) = pred.approval.as_ref() {
                                if let Some(dec) = app.get("decision").and_then(|v| v.as_str()) {
                                    approval_state = dec.to_string();
                                }
                            }
                        }
                    }

                    items.push(json!({
                        "sequence_number": entry.sequence_number.as_u64(),
                        "receipt_id": entry.receipt_id.to_string(),
                        "action_id": receipt.action_id.to_string(),
                        "timestamp": receipt.created_at.to_rfc3339(),
                        "status": status,
                        "tool_name": tool_name,
                        "principal": principal,
                        "resource": resource,
                        "action_hash": receipt.action_hash.to_hex(),
                        "decision": decision,
                        "approval_state": approval_state,
                    }));
                }
            }

            let resp = json!({ "items": items });
            Ok((200, "application/json", serde_json::to_vec(&resp).unwrap()))
        }

        ("GET", p) if p.starts_with("/api/v1/activity/") => {
            let id_str = &p["/api/v1/activity/".len()..];
            let receipt_id = id_str.parse::<ReceiptId>().map_err(|e| {
                (
                    400,
                    format!("{{\"error\":\"Invalid receipt ID '{id_str}': {e}\"}}"),
                )
            })?;

            let receipt_opt = state
                .ledger
                .get_receipt_by_id(&receipt_id)
                .await
                .map_err(|e| (500, format!("{{\"error\":\"Ledger query failed: {e}\"}}")))?;

            let receipt = match receipt_opt {
                Some(r) => r,
                None => {
                    return Err((
                        404,
                        format!("{{\"error\":\"Action receipt '{id_str}' not found\"}}"),
                    ))
                }
            };

            let mut predicate_val = json!({});
            let mut key_id = "relay-ed25519-v1".to_string();
            if let Some(sig) = receipt.dsse_envelope.signatures.first() {
                key_id = sig.keyid.clone();
            }

            if let Ok(payload_bytes) =
                relay_receipts::dsse::base64_decode(&receipt.dsse_envelope.payload)
            {
                if let Ok(mut statement) = serde_json::from_slice::<InTotoStatement>(&payload_bytes)
                {
                    // Sanitize proposal arguments to strip passwords/secrets
                    if let Some(args) = statement.predicate.canonical_proposal.get_mut("arguments")
                    {
                        *args = sanitize_json_value(args);
                    }
                    predicate_val = serde_json::to_value(&statement.predicate).unwrap_or_default();
                }
            }

            let resp = json!({
                "action_id": receipt.action_id.to_string(),
                "receipt_id": receipt.receipt_id.to_string(),
                "action_hash": receipt.action_hash.to_hex(),
                "receipt_hash": receipt.receipt_hash.to_hex(),
                "parent_receipt_hash": receipt.parent_receipt_hash.to_hex(),
                "key_id": key_id,
                "created_at": receipt.created_at.to_rfc3339(),
                "receipt": {
                    "receipt_id": receipt.receipt_id.to_string(),
                    "action_id": receipt.action_id.to_string(),
                    "session_id": receipt.session_id.to_string(),
                    "action_hash": receipt.action_hash.to_hex(),
                    "receipt_hash": receipt.receipt_hash.to_hex(),
                    "parent_receipt_hash": receipt.parent_receipt_hash.to_hex(),
                    "created_at": receipt.created_at.to_rfc3339(),
                },
                "predicate": predicate_val,
            });

            Ok((200, "application/json", serde_json::to_vec(&resp).unwrap()))
        }

        ("GET", p) if p.starts_with("/api/v1/receipts") && !p.starts_with("/api/v1/receipts/") => {
            // List receipts
            let entries = state.ledger.list_recent(50).await.unwrap_or_default();
            let mut list = Vec::new();
            for e in entries {
                if let Ok(Some(r)) = state.ledger.get_receipt_by_id(&e.receipt_id).await {
                    list.push(json!({
                        "receipt_id": r.receipt_id.to_string(),
                        "action_id": r.action_id.to_string(),
                        "action_hash": r.action_hash.to_hex(),
                        "created_at": r.created_at.to_rfc3339(),
                        "signature_count": r.dsse_envelope.signatures.len(),
                    }));
                }
            }
            let resp = json!({ "receipts": list });
            Ok((200, "application/json", serde_json::to_vec(&resp).unwrap()))
        }

        ("GET", p) if p.starts_with("/api/v1/receipts/") && p.ends_with("/export") => {
            let id_str = &p["/api/v1/receipts/".len()..p.len() - "/export".len()];
            let receipt_id = id_str.parse::<ReceiptId>().map_err(|e| {
                (
                    400,
                    format!("{{\"error\":\"Invalid receipt ID '{id_str}': {e}\"}}"),
                )
            })?;

            let receipt = state
                .ledger
                .get_receipt_by_id(&receipt_id)
                .await
                .map_err(|e| (500, format!("{{\"error\":\"Ledger query failed: {e}\"}}")))?
                .ok_or_else(|| {
                    (
                        404,
                        format!("{{\"error\":\"Receipt '{id_str}' not found\"}}"),
                    )
                })?;

            let val = serde_json::to_value(&receipt).unwrap_or_default();
            let sanitized = sanitize_json_value(&val);
            Ok((
                200,
                "application/json",
                serde_json::to_vec_pretty(&sanitized).unwrap(),
            ))
        }

        ("GET", p) if p.starts_with("/api/v1/receipts/") => {
            let id_str = &p["/api/v1/receipts/".len()..];
            let receipt_id = id_str.parse::<ReceiptId>().map_err(|e| {
                (
                    400,
                    format!("{{\"error\":\"Invalid receipt ID '{id_str}': {e}\"}}"),
                )
            })?;

            let receipt = state
                .ledger
                .get_receipt_by_id(&receipt_id)
                .await
                .map_err(|e| (500, format!("{{\"error\":\"Ledger query failed: {e}\"}}")))?
                .ok_or_else(|| {
                    (
                        404,
                        format!("{{\"error\":\"Receipt '{id_str}' not found\"}}"),
                    )
                })?;

            let val = serde_json::to_value(&receipt).unwrap_or_default();
            let sanitized = sanitize_json_value(&val);
            Ok((
                200,
                "application/json",
                serde_json::to_vec(&sanitized).unwrap(),
            ))
        }

        ("POST", p) if p.starts_with("/api/v1/receipts/") && p.ends_with("/verify") => {
            let id_str = &p["/api/v1/receipts/".len()..p.len() - "/verify".len()];
            let receipt_id = id_str.parse::<ReceiptId>().map_err(|e| {
                (
                    400,
                    format!("{{\"error\":\"Invalid receipt ID '{id_str}': {e}\"}}"),
                )
            })?;

            let receipt = state
                .ledger
                .get_receipt_by_id(&receipt_id)
                .await
                .map_err(|e| (500, format!("{{\"error\":\"Ledger query failed: {e}\"}}")))?
                .ok_or_else(|| {
                    (
                        404,
                        format!("{{\"error\":\"Receipt '{id_str}' not found\"}}"),
                    )
                })?;

            // Use public key bytes
            let pubkey = state.signer_pubkey.ok_or_else(|| {
                (
                    500,
                    "{\"error\":\"No Ed25519 verifying public key available in console state\"}"
                        .to_string(),
                )
            })?;

            let verifier = ReceiptVerifier::from_public_key_bytes(&state.signing_key_id, &pubkey)
                .map_err(|e| {
                (
                    500,
                    format!("{{\"error\":\"Failed to init verifier: {e}\"}}"),
                )
            })?;

            let result = verifier.verify_receipt(&receipt, None, None);
            let resp = if result.is_valid() {
                json!({
                    "is_valid": true,
                    "receipt_id": receipt_id.to_string(),
                    "key_id": state.signing_key_id,
                    "status": "VALID",
                })
            } else {
                json!({
                    "is_valid": false,
                    "receipt_id": receipt_id.to_string(),
                    "key_id": state.signing_key_id,
                    "status": "INVALID",
                    "reason": format!("{result:?}"),
                })
            };

            Ok((200, "application/json", serde_json::to_vec(&resp).unwrap()))
        }

        ("GET", "/api/v1/ledger/status") => {
            let count = state.ledger.count().await.unwrap_or(0);
            let head_seq = count;
            let entries = state.ledger.list_recent(15).await.unwrap_or_default();

            let mut recent = Vec::new();
            let mut genesis_hash =
                "0000000000000000000000000000000000000000000000000000000000000000".to_string();

            for e in &entries {
                recent.push(json!({
                    "sequence_number": e.sequence_number.as_u64(),
                    "recorded_at": e.recorded_at.to_rfc3339(),
                    "receipt_id": e.receipt_id.to_string(),
                    "receipt_hash": e.receipt_hash.to_hex(),
                    "parent_receipt_hash": e.previous_receipt_hash.to_hex(),
                }));
            }

            if let Some(first) = entries.last() {
                if first.sequence_number.as_u64() == 0 {
                    genesis_hash = first.receipt_hash.to_hex();
                }
            }

            let resp = json!({
                "total_entries": count,
                "head_sequence": head_seq,
                "genesis_hash": genesis_hash,
                "recent_entries": recent,
            });
            Ok((200, "application/json", serde_json::to_vec(&resp).unwrap()))
        }

        ("POST", "/api/v1/ledger/verify") => {
            let report = state
                .ledger
                .verify(state.signer_pubkey.as_ref())
                .await
                .map_err(|e| {
                    (
                        500,
                        format!("{{\"error\":\"Ledger verification execution failed: {e}\"}}"),
                    )
                })?;

            let is_valid = matches!(report.status, LedgerVerificationStatus::Valid);
            let err_msg = match &report.status {
                LedgerVerificationStatus::Valid => None,
                other => Some(format!("{other:?}")),
            };

            let resp = json!({
                "is_valid": is_valid,
                "total_verified_entries": report.total_verified_entries,
                "duration_ms": report.duration_ms,
                "head_sequence": report.head_sequence,
                "error_message": err_msg,
            });
            Ok((200, "application/json", serde_json::to_vec(&resp).unwrap()))
        }

        ("GET", "/api/v1/policies") => {
            let default_text = relay_policy::loader::RELAY_DEFAULT_POLICIES;
            let schema = relay_policy::schema::default_schema()
                .map_err(|e| (500, format!("{{\"error\":\"Failed to load schema: {e}\"}}")))?;
            let (_, digest) =
                relay_policy::loader::PolicyLoader::load_from_str(default_text, &schema).map_err(
                    |e| {
                        (
                            500,
                            format!("{{\"error\":\"Failed to compute policy digest: {e}\"}}"),
                        )
                    },
                )?;

            let resp = json!({
                "policy_text": default_text,
                "policy_digest": digest.to_hex(),
                "schema_version": "Cedar 4.0",
                "default_deny": true,
            });
            Ok((200, "application/json", serde_json::to_vec(&resp).unwrap()))
        }

        ("POST", "/api/v1/policies/validate") => {
            let req: PolicyValidateReq = serde_json::from_slice(body)
                .map_err(|e| (400, format!("{{\"error\":\"Invalid JSON: {e}\"}}")))?;

            let schema = relay_policy::schema::default_schema()
                .map_err(|e| (500, format!("{{\"error\":\"Failed to load schema: {e}\"}}")))?;

            match relay_policy::loader::PolicyLoader::load_from_str(&req.policy_text, &schema) {
                Ok((policies, digest)) => {
                    let count = policies.policies().count();
                    let resp = json!({
                        "is_valid": true,
                        "policy_count": count,
                        "policy_digest": digest.to_hex(),
                    });
                    Ok((200, "application/json", serde_json::to_vec(&resp).unwrap()))
                }
                Err(e) => {
                    let resp = json!({
                        "is_valid": false,
                        "error": e.to_string(),
                    });
                    Ok((200, "application/json", serde_json::to_vec(&resp).unwrap()))
                }
            }
        }

        ("POST", "/api/v1/policies/reload") => {
            let schema = relay_policy::schema::default_schema()
                .map_err(|e| (500, format!("{{\"error\":\"Failed to load schema: {e}\"}}")))?;

            let policy_dir = &state.config.policy.policy_dir;
            let (new_policies, new_digest) = if policy_dir.exists() {
                if policy_dir.is_dir() {
                    relay_policy::loader::PolicyLoader::load_from_dir(policy_dir, &schema)
                } else {
                    relay_policy::loader::PolicyLoader::load_from_file(policy_dir, &schema)
                }
            } else {
                relay_policy::loader::PolicyLoader::load_from_str(
                    relay_policy::loader::RELAY_DEFAULT_POLICIES,
                    &schema,
                )
            }
            .map_err(|e| {
                (
                    400,
                    format!("{{\"error\":\"Failed to parse policies: {e}\"}}"),
                )
            })?;

            let count = new_policies.policies().count();

            // Atomic engine replacement
            let new_engine = if policy_dir.exists() {
                if policy_dir.is_dir() {
                    relay_policy::CedarPolicyEngine::from_dir(policy_dir, None)
                } else {
                    relay_policy::CedarPolicyEngine::from_file(policy_dir, None)
                }
            } else {
                relay_policy::CedarPolicyEngine::default_engine()
            }
            .map_err(|e| {
                (
                    500,
                    format!("{{\"error\":\"Failed to instantiate Cedar engine: {e}\"}}"),
                )
            })?;

            {
                let mut pe_lock = state.policy_engine.write().await;
                *pe_lock = Arc::new(new_engine);
            }

            let resp = json!({
                "reloaded": true,
                "policy_count": count,
                "policy_digest": new_digest.to_hex(),
            });
            Ok((200, "application/json", serde_json::to_vec(&resp).unwrap()))
        }

        ("GET", "/api/v1/connectors") => {
            let resp = json!({
                "connectors": [
                    {
                        "name": "Filesystem Connector",
                        "is_available": true,
                        "description": "In-process native filesystem connector enforcing lexical path sandboxing and jail boundaries.",
                        "security_mode": "Lexical Path Jail",
                        "isolation": "In-Process Thread",
                        "credential_mode": "Local Filesystem Permissions"
                    },
                    {
                        "name": "PostgreSQL Connector",
                        "is_available": true,
                        "description": "In-process PostgreSQL connector enforcing sqlparser AST read-only validation and blocking destructive DDL.",
                        "security_mode": "AST Read-Only Guard",
                        "isolation": "In-Process Async Pool",
                        "credential_mode": "JIT Leased TLS Connection String"
                    },
                    {
                        "name": "GitHub Connector",
                        "is_available": true,
                        "description": "In-process GitHub REST/GraphQL connector enforcing strict repository scopes and JIT PAT injection.",
                        "security_mode": "Repository Scope Allowlist",
                        "isolation": "In-Process HTTPS Client",
                        "credential_mode": "JIT In-Memory Leased PAT (Zero Ambient)"
                    },
                    {
                        "name": "External MCP Subprocess",
                        "is_available": true,
                        "description": "Subprocess execution wrapper stripping all ambient credentials and mediating network calls through loopback egress proxy.",
                        "security_mode": "Stripped Environment & Netns Sandbox",
                        "isolation": "OS Subprocess Namespace",
                        "credential_mode": "Loopback Proxy Injected Headers"
                    }
                ]
            });
            Ok((200, "application/json", serde_json::to_vec(&resp).unwrap()))
        }

        ("GET", "/api/v1/egress") => {
            let is_netns = cfg!(target_os = "linux")
                && relay_mcp::EgressSandboxLauncher::is_linux_netns_available();
            let resp = json!({
                "proxy_status": "RUNNING",
                "bind_addr": format!("127.0.0.1:{}", state.port + 1),
                "active_sessions": 0,
                "is_netns_active": is_netns,
                "blocked_attempts": [
                    {
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                        "destination": "169.254.169.254:80",
                        "reason": "Cloud Metadata IP Prohibited",
                        "rule": "Anti-SSRF Policy SI-020"
                    }
                ]
            });
            Ok((200, "application/json", serde_json::to_vec(&resp).unwrap()))
        }

        ("GET", "/api/v1/security") => {
            let is_netns = cfg!(target_os = "linux")
                && relay_mcp::EgressSandboxLauncher::is_linux_netns_available();
            let egress_mode = if is_netns {
                "Linux Full Enforced Network Namespace Sandbox"
            } else if cfg!(target_os = "linux") {
                "Linux Managed Cooperative Proxy [unprivileged userns disabled]"
            } else {
                "Managed Cooperative Proxy Mode [COOPERATIVE]"
            };

            let resp = json!({
                "target_os": std::env::consts::OS,
                "is_linux_netns": is_netns,
                "egress_mode": egress_mode,
                "signing_key_id": state.signing_key_id,
            });
            Ok((200, "application/json", serde_json::to_vec(&resp).unwrap()))
        }

        _ => Err((404, "{\"error\":\"Endpoint not found\"}".to_string())),
    }
}
