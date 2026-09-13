//! MCP protocol method classification and tool-call parameter extraction.

use relay_domain::{ProtocolError, SessionId};
use serde_json::Value;

/// Known MCP JSON-RPC methods relevant to the Relay gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpMethod {
    Initialize,
    InitializedNotification,
    ToolsList,
    ToolsCall,
    Ping,
    Other(String),
}

impl McpMethod {
    pub fn from_rpc_method(method: &str) -> Self {
        match method {
            "initialize" => Self::Initialize,
            "notifications/initialized" => Self::InitializedNotification,
            "tools/list" => Self::ToolsList,
            "tools/call" => Self::ToolsCall,
            "ping" => Self::Ping,
            other => Self::Other(other.to_string()),
        }
    }

    pub fn is_tool_call(&self) -> bool {
        matches!(self, Self::ToolsCall)
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Initialize => "initialize",
            Self::InitializedNotification => "notifications/initialized",
            Self::ToolsList => "tools/list",
            Self::ToolsCall => "tools/call",
            Self::Ping => "ping",
            Self::Other(s) => s,
        }
    }
}

/// Parsed `tools/call` parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCallParams {
    pub name: String,
    pub arguments: Value,
}

/// Context extracted from an agent-originated `tools/call` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCallContext {
    pub session_id: SessionId,
    pub request_id: Value,
    pub method: String,
    pub tool_name: String,
    pub arguments: Value,
}

/// Parse MCP `tools/call` params from a JSON-RPC params value.
pub fn parse_tool_call_params(params: &Value) -> Result<ToolCallParams, ProtocolError> {
    let obj = params.as_object().ok_or_else(|| {
        ProtocolError::InvalidParams("tools/call params must be a JSON object".into())
    })?;

    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| ProtocolError::InvalidParams("tools/call requires non-empty 'name'".into()))?
        .to_string();

    let arguments = obj
        .get("arguments")
        .cloned()
        .unwrap_or(Value::Object(Default::default()));

    if !arguments.is_object() && !arguments.is_null() {
        return Err(ProtocolError::InvalidParams(
            "tools/call 'arguments' must be a JSON object".into(),
        ));
    }

    Ok(ToolCallParams { name, arguments })
}

/// Build a `ToolCallContext` for the authorization pipeline handoff.
pub fn build_tool_call_context(
    session_id: SessionId,
    request_id: Value,
    method: &str,
    params: &Value,
) -> Result<ToolCallContext, ProtocolError> {
    let tool = parse_tool_call_params(params)?;
    Ok(ToolCallContext {
        session_id,
        request_id,
        method: method.to_string(),
        tool_name: tool.name,
        arguments: tool.arguments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classifies_tools_call() {
        assert_eq!(
            McpMethod::from_rpc_method("tools/call"),
            McpMethod::ToolsCall
        );
    }

    #[test]
    fn parses_tool_call_params() {
        let params = json!({"name": "echo", "arguments": {"msg": "hi"}});
        let parsed = parse_tool_call_params(&params).unwrap();
        assert_eq!(parsed.name, "echo");
        assert_eq!(parsed.arguments["msg"], "hi");
    }

    #[test]
    fn rejects_missing_tool_name() {
        let params = json!({"arguments": {}});
        let err = parse_tool_call_params(&params).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidParams(_)));
    }
}
