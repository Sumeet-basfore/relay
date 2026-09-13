//! JSON-RPC 2.0 message types and validation.

use relay_domain::ProtocolError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Standard JSON-RPC 2.0 Request Envelope
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// Standard JSON-RPC 2.0 Notification (no `id` field)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// Standard JSON-RPC 2.0 Response Envelope
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// Standard JSON-RPC 2.0 Error Object
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Parsed JSON-RPC message classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonRpcMessage {
    Request(JsonRpcRequest),
    Notification(JsonRpcNotification),
    Response(JsonRpcResponse),
}

impl JsonRpcRequest {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.jsonrpc != "2.0" {
            return Err(ProtocolError::InvalidRequest(format!(
                "Invalid JSON-RPC version '{}', expected '2.0'",
                self.jsonrpc
            )));
        }
        if self.method.trim().is_empty() {
            return Err(ProtocolError::InvalidRequest(
                "Method name cannot be empty".into(),
            ));
        }
        if self.id.is_null() {
            return Err(ProtocolError::InvalidRequest(
                "Request id cannot be null".into(),
            ));
        }
        Ok(())
    }
}

impl JsonRpcNotification {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.jsonrpc != "2.0" {
            return Err(ProtocolError::InvalidRequest(format!(
                "Invalid JSON-RPC version '{}', expected '2.0'",
                self.jsonrpc
            )));
        }
        if self.method.trim().is_empty() {
            return Err(ProtocolError::InvalidRequest(
                "Method name cannot be empty".into(),
            ));
        }
        Ok(())
    }
}

impl JsonRpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Value, error: ProtocolError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code: error.jsonrpc_code(),
                message: error.to_string(),
                data: None,
            }),
        }
    }

    pub fn custom_error(
        id: Value,
        code: i32,
        message: impl Into<String>,
        data: Option<Value>,
    ) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data,
            }),
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.jsonrpc != "2.0" {
            return Err(ProtocolError::InvalidRequest(format!(
                "Invalid JSON-RPC version '{}', expected '2.0'",
                self.jsonrpc
            )));
        }
        match (&self.result, &self.error) {
            (Some(_), None) | (None, Some(_)) => Ok(()),
            (None, None) => Err(ProtocolError::InvalidRequest(
                "Response must contain either result or error".into(),
            )),
            (Some(_), Some(_)) => Err(ProtocolError::InvalidRequest(
                "Response cannot contain both result and error".into(),
            )),
        }
    }
}

/// Classify and validate a raw JSON-RPC frame.
pub fn parse_message(frame: &[u8]) -> Result<JsonRpcMessage, ProtocolError> {
    let value: Value = serde_json::from_slice(frame)
        .map_err(|e| ProtocolError::ParseError(format!("JSON parse failed: {e}")))?;

    if !value.is_object() {
        return Err(ProtocolError::InvalidRequest(
            "JSON-RPC message must be a JSON object".into(),
        ));
    }

    let obj = value.as_object().expect("checked is_object");

    let has_id = obj.contains_key("id");
    let has_method = obj.contains_key("method");
    let has_result = obj.contains_key("result");
    let has_error = obj.contains_key("error");

    if has_method {
        if has_id {
            let request: JsonRpcRequest = serde_json::from_value(value).map_err(|e| {
                ProtocolError::InvalidRequest(format!("Invalid request envelope: {e}"))
            })?;
            request.validate()?;
            Ok(JsonRpcMessage::Request(request))
        } else {
            let notification: JsonRpcNotification = serde_json::from_value(value).map_err(|e| {
                ProtocolError::InvalidRequest(format!("Invalid notification envelope: {e}"))
            })?;
            notification.validate()?;
            Ok(JsonRpcMessage::Notification(notification))
        }
    } else if has_result || has_error {
        let response: JsonRpcResponse = serde_json::from_value(value).map_err(|e| {
            ProtocolError::InvalidRequest(format!("Invalid response envelope: {e}"))
        })?;
        response.validate()?;
        Ok(JsonRpcMessage::Response(response))
    } else {
        Err(ProtocolError::InvalidRequest(
            "Unrecognized JSON-RPC message structure".into(),
        ))
    }
}

/// Best-effort extraction of a JSON-RPC request `id` from a raw frame.
///
/// Returns `None` when the frame is not valid JSON or has no `id` field.
/// Callers should use `Value::Null` when responding to unidentifiable requests.
pub fn try_extract_request_id(frame: &[u8]) -> Option<Value> {
    let value: Value = serde_json::from_slice(frame).ok()?;
    value.get("id").cloned()
}

/// Serialize a JSON-RPC message to a single-line JSON payload (no trailing newline).
pub fn serialize_message(message: &JsonRpcMessage) -> Result<Vec<u8>, ProtocolError> {
    let value = match message {
        JsonRpcMessage::Request(req) => serde_json::to_value(req),
        JsonRpcMessage::Notification(notif) => serde_json::to_value(notif),
        JsonRpcMessage::Response(resp) => serde_json::to_value(resp),
    }
    .map_err(|e| ProtocolError::InternalError(format!("JSON serialization failed: {e}")))?;

    serde_json::to_vec(&value)
        .map_err(|e| ProtocolError::InternalError(format!("JSON serialization failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classifies_request() {
        let frame = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let msg = parse_message(frame).unwrap();
        assert!(matches!(msg, JsonRpcMessage::Request(_)));
    }

    #[test]
    fn classifies_notification() {
        let frame = br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let msg = parse_message(frame).unwrap();
        assert!(matches!(msg, JsonRpcMessage::Notification(_)));
    }

    #[test]
    fn classifies_response() {
        let frame = br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
        let msg = parse_message(frame).unwrap();
        assert!(matches!(msg, JsonRpcMessage::Response(_)));
    }

    #[test]
    fn rejects_malformed_json() {
        let err = parse_message(b"{not json").unwrap_err();
        assert!(matches!(err, ProtocolError::ParseError(_)));
    }

    #[test]
    fn rejects_request_with_null_id() {
        let frame = br#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#;
        let err = parse_message(frame).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidRequest(_)));
    }

    #[test]
    fn extracts_request_id() {
        let frame = br#"{"jsonrpc":"2.0","id":42,"method":"ping"}"#;
        assert_eq!(try_extract_request_id(frame), Some(json!(42)));
    }

    #[test]
    fn protocol_error_response_has_code() {
        let resp = JsonRpcResponse::error(
            json!(42),
            ProtocolError::FrameTooLarge {
                size_bytes: 10,
                max_bytes: 4,
            },
        );
        assert_eq!(resp.error.as_ref().unwrap().code, -32600);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = parse_message(&bytes);
        }
    }
}
