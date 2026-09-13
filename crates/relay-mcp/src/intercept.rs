//! Tool-call interception boundary for policy authorization and governance.

use crate::mcp::ToolCallContext;
use crate::rpc::JsonRpcResponse;
use async_trait::async_trait;
use relay_canonical::CanonicalAction;

/// Result of intercepting an agent-originated `tools/call` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptResult {
    /// Forward the (possibly unchanged) frame bytes to the downstream MCP server.
    Forward(Vec<u8>),
    /// Reject the tool call with a JSON-RPC error response to the agent.
    Reject(Box<JsonRpcResponse>),
    /// Successfully handled in-process (e.g. by a native connector), returning a response to the agent.
    Handled(Box<JsonRpcResponse>),
}

/// Intercepts `tools/call` requests with authoritative `CanonicalAction` before downstream execution.
#[async_trait]
pub trait ToolCallInterceptor: Send + Sync {
    async fn on_tool_call(
        &self,
        ctx: &ToolCallContext,
        canonical_action: &CanonicalAction,
        frame: &[u8],
    ) -> InterceptResult;
}

/// Pass-through interceptor: forwards tool calls unchanged.
#[derive(Debug, Default, Clone, Copy)]
pub struct PassThroughInterceptor;

#[async_trait]
impl ToolCallInterceptor for PassThroughInterceptor {
    async fn on_tool_call(
        &self,
        _ctx: &ToolCallContext,
        _canonical_action: &CanonicalAction,
        frame: &[u8],
    ) -> InterceptResult {
        InterceptResult::Forward(frame.to_vec())
    }
}

/// Interceptor evaluating canonical tool calls against a PolicyEngine (Cedar PEP).
pub struct PolicyToolCallInterceptor {
    policy_engine: std::sync::Arc<dyn relay_domain::PolicyEngine>,
}

impl PolicyToolCallInterceptor {
    pub fn new(policy_engine: std::sync::Arc<dyn relay_domain::PolicyEngine>) -> Self {
        Self { policy_engine }
    }

    pub fn policy_engine(&self) -> &std::sync::Arc<dyn relay_domain::PolicyEngine> {
        &self.policy_engine
    }
}

/// Alias for PolicyToolCallInterceptor
pub type CedarToolCallInterceptor = PolicyToolCallInterceptor;

#[async_trait]
impl ToolCallInterceptor for PolicyToolCallInterceptor {
    async fn on_tool_call(
        &self,
        ctx: &ToolCallContext,
        canonical_action: &CanonicalAction,
        frame: &[u8],
    ) -> InterceptResult {
        let auth_request = match canonical_action.to_authorization_request() {
            Ok(req) => req,
            Err(e) => {
                let err_resp = JsonRpcResponse::custom_error(
                    ctx.request_id.clone(),
                    -32602,
                    format!("Failed to build authorization request: {e}"),
                    None,
                );
                return InterceptResult::Reject(Box::new(err_resp));
            }
        };

        match self.policy_engine.evaluate(&auth_request).await {
            Ok(decision) => {
                if decision.is_allowed() {
                    tracing::info!(
                        action_hash = %decision.action_hash.to_hex(),
                        determining_policies = ?decision.determining_policies,
                        "Action authorized by policy; forwarding downstream"
                    );
                    InterceptResult::Forward(frame.to_vec())
                } else if decision.requires_approval() {
                    tracing::warn!(
                        action_hash = %decision.action_hash.to_hex(),
                        determining_policies = ?decision.determining_policies,
                        "Action requires step-up operator approval; halting execution"
                    );
                    let reason = decision
                        .reason
                        .as_deref()
                        .unwrap_or("Step-up operator approval required");
                    let data = serde_json::json!({
                        "action_hash": decision.action_hash.to_hex(),
                        "decision_id": decision.decision_id.to_string(),
                        "determining_policies": decision.determining_policies,
                        "approval_required": true,
                    });
                    let err_resp = JsonRpcResponse::custom_error(
                        ctx.request_id.clone(),
                        -32005,
                        format!("Approval Required: {reason}"),
                        Some(data),
                    );
                    InterceptResult::Reject(Box::new(err_resp))
                } else {
                    tracing::warn!(
                        action_hash = %decision.action_hash.to_hex(),
                        determining_policies = ?decision.determining_policies,
                        reason = ?decision.reason,
                        "Action forbidden by policy; blocking execution"
                    );
                    let reason = decision
                        .reason
                        .as_deref()
                        .unwrap_or("Action not permitted by policy");
                    let data = serde_json::json!({
                        "action_hash": decision.action_hash.to_hex(),
                        "decision_id": decision.decision_id.to_string(),
                        "determining_policies": decision.determining_policies,
                    });
                    let err_resp = JsonRpcResponse::custom_error(
                        ctx.request_id.clone(),
                        -32003,
                        format!("Action Forbidden: {reason}"),
                        Some(data),
                    );
                    InterceptResult::Reject(Box::new(err_resp))
                }
            }
            Err(policy_err) => {
                tracing::error!(
                    error = %policy_err,
                    "Policy evaluation error; failing closed (SI-014)"
                );
                let data = serde_json::json!({
                    "error": policy_err.to_string(),
                });
                let err_resp = JsonRpcResponse::custom_error(
                    ctx.request_id.clone(),
                    -32002,
                    "Policy evaluation failed",
                    Some(data),
                );
                InterceptResult::Reject(Box::new(err_resp))
            }
        }
    }
}
