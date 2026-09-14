//! Model Context Protocol (MCP) JSON-RPC 2.0 framing and gateway for Relay

pub mod approval;
pub mod egress;
pub mod egress_dns;
pub mod egress_headers;
pub mod egress_injector;
pub mod egress_proxy;
pub mod egress_sandbox;
pub mod egress_session;
pub mod env;
pub mod frame;
pub mod gateway;
pub mod intercept;
pub mod mcp;
pub mod rpc;
pub mod subprocess;

pub use approval::{
    redact_sensitive_value, render_approval_prompt, render_details_view, HeadlessApprovalGate,
    TtyApprovalProvider, TtyConfig, TtyTarget,
};
pub use egress::{
    CredentialInjector, DnsFilterConfig, DnsResolverWithBlacklist, EgressProxy,
    EgressSandboxLauncher, HeaderPolicy, PlatformSandboxMode, ProxySessionManager,
    DEFAULT_PROXY_LEASE_TTL_SECS, HOP_BY_HOP_HEADERS,
};
pub use env::{apply_sanitized_env, sanitized_child_env, SAFE_ENV_VARS};
pub use frame::{encode_frame, FrameBuffer, RawFrame, MAX_FRAME_SIZE_BYTES};
pub use gateway::{run_gateway, GatewayConfig, GatewayError, GatewayExitStatus};
pub use intercept::{
    CedarToolCallInterceptor, InterceptResult, PassThroughInterceptor, PolicyToolCallInterceptor,
    ToolCallInterceptor,
};
pub use mcp::{
    build_tool_call_context, parse_tool_call_params, McpMethod, ToolCallContext, ToolCallParams,
};
pub use rpc::{
    parse_message, serialize_message, try_extract_request_id, JsonRpcError, JsonRpcMessage,
    JsonRpcNotification, JsonRpcRequest, JsonRpcResponse,
};
pub use subprocess::{
    spawn, terminate_child_gracefully, McpSubprocess, SubprocessConfig,
    DEFAULT_SHUTDOWN_GRACE_PERIOD, DEFAULT_STARTUP_TIMEOUT,
};
