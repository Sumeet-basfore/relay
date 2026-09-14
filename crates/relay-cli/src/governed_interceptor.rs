//! Governed Tool Call Interceptor for MCP Gateway.
//!
//! Integrates `GovernedActionRunner` into the MCP Gateway event loop:
//! - Routes native connector tools directly through the governed lifecycle.
//! - Forwards external MCP subprocess tool calls directly across the ExecutionTarget::ExternalMcp boundary.

use std::sync::Arc;

use async_trait::async_trait;
use relay_canonical::CanonicalAction;
use relay_connectors::GovernedActionRunner;
use relay_mcp::{InterceptResult, JsonRpcResponse, ToolCallContext, ToolCallInterceptor};

/// An MCP tool-call interceptor powered by `GovernedActionRunner`.
pub struct GovernedToolCallInterceptor {
    runner: Arc<GovernedActionRunner>,
}

impl GovernedToolCallInterceptor {
    pub fn new(runner: Arc<GovernedActionRunner>) -> Self {
        Self { runner }
    }

    #[allow(dead_code)]
    pub fn runner(&self) -> &Arc<GovernedActionRunner> {
        &self.runner
    }
}

#[async_trait]
impl ToolCallInterceptor for GovernedToolCallInterceptor {
    async fn on_tool_call(
        &self,
        ctx: &ToolCallContext,
        canonical_action: &CanonicalAction,
        frame: &[u8],
    ) -> InterceptResult {
        if self.runner.is_native_action(canonical_action) {
            match self.runner.run_action(canonical_action).await {
                Ok(outcome) => {
                    let content = serde_json::json!({
                        "content": [
                            {
                                "type": "text",
                                "text": outcome.execution_result.sanitized_preview,
                            }
                        ]
                    });
                    let resp = JsonRpcResponse::success(ctx.request_id.clone(), content);
                    InterceptResult::Handled(Box::new(resp))
                }
                Err(err) => {
                    let (code, msg, data) = err.to_jsonrpc_error_parts();
                    let resp =
                        JsonRpcResponse::custom_error(ctx.request_id.clone(), code, msg, data);
                    InterceptResult::Reject(Box::new(resp))
                }
            }
        } else {
            // ExecutionTarget::ExternalMcp: Clean architectural boundary forwarding to child MCP subprocess
            InterceptResult::Forward(frame.to_vec())
        }
    }
}
