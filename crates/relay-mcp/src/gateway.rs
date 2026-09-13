//! MCP stdio gateway: bidirectional frame forwarding with tool-call interception,
//! startup timeouts, graceful shutdown, and robust broken-pipe handling.

use crate::frame::{encode_frame, FrameBuffer, RawFrame};
use crate::intercept::{InterceptResult, ToolCallInterceptor};
use crate::mcp::{build_tool_call_context, McpMethod};
use crate::rpc::{
    parse_message, serialize_message, try_extract_request_id, JsonRpcMessage, JsonRpcResponse,
};
use crate::subprocess::{McpSubprocess, DEFAULT_SHUTDOWN_GRACE_PERIOD, DEFAULT_STARTUP_TIMEOUT};
use relay_canonical::{parse_json_bytes_strictly, ActionCanonicalizer};
use relay_domain::{PrincipalId, ProtocolError, SessionId, ToolIdentity};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{watch, Mutex};

const READ_CHUNK_SIZE: usize = 8192;

type SharedAgentWriter<W> = Arc<Mutex<W>>;

/// Gateway runtime configuration.
#[derive(Clone)]
pub struct GatewayConfig {
    pub session_id: SessionId,
    pub interceptor: Arc<dyn ToolCallInterceptor>,
    pub canonicalizer: Arc<ActionCanonicalizer>,
    pub max_frame_bytes: usize,
    pub startup_timeout: Duration,
    pub shutdown_grace_period: Duration,
}

impl GatewayConfig {
    pub fn with_pass_through(session_id: SessionId) -> Self {
        Self {
            session_id,
            interceptor: Arc::new(crate::intercept::PassThroughInterceptor),
            canonicalizer: Arc::new(ActionCanonicalizer::default()),
            max_frame_bytes: crate::frame::MAX_FRAME_SIZE_BYTES,
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
            shutdown_grace_period: DEFAULT_SHUTDOWN_GRACE_PERIOD,
        }
    }

    pub fn with_policy_engine(
        session_id: SessionId,
        policy_engine: Arc<dyn relay_domain::PolicyEngine>,
    ) -> Self {
        Self {
            session_id,
            interceptor: Arc::new(crate::intercept::PolicyToolCallInterceptor::new(
                policy_engine,
            )),
            canonicalizer: Arc::new(ActionCanonicalizer::default()),
            max_frame_bytes: crate::frame::MAX_FRAME_SIZE_BYTES,
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
            shutdown_grace_period: DEFAULT_SHUTDOWN_GRACE_PERIOD,
        }
    }
}

/// Gateway termination status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayExitStatus {
    pub child_exit_code: Option<i32>,
}

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("subprocess execution error: {0}")]
    Execution(#[from] relay_domain::ExecutionError),

    #[error("subprocess startup timed out after {0:?}")]
    StartupTimeout(Duration),

    #[error("downstream subprocess terminated unexpectedly")]
    SubprocessTerminated,
}

/// Internal termination trigger for the event loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminationEvent {
    AgentEof,
    AgentBrokenPipe,
    ChildEof,
    ChildBrokenPipe,
    ShutdownSignal,
    StartupTimeout,
}

/// Run the bidirectional MCP gateway until streams close, errors occur, or shutdown is signaled.
pub async fn run_gateway<R, W>(
    agent_reader: R,
    agent_writer: W,
    subprocess: McpSubprocess,
    config: GatewayConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<GatewayExitStatus, GatewayError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let session_id = config.session_id;
    let interceptor = config.interceptor.clone();
    let max_frame_bytes = config.max_frame_bytes;
    let startup_timeout = config.startup_timeout;
    let shutdown_grace_period = config.shutdown_grace_period;

    let McpSubprocess {
        mut child,
        stdin: child_stdin,
        stdout: child_stdout,
    } = subprocess;

    let agent_writer: SharedAgentWriter<W> = Arc::new(Mutex::new(agent_writer));
    let agent_writer_for_agent = agent_writer.clone();
    let agent_writer_for_child = agent_writer.clone();

    // Track in-flight request IDs for fail-closed notification if child exits mid-request
    let active_request_id: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let active_request_id_for_agent = active_request_id.clone();
    let active_request_id_for_child = active_request_id.clone();

    // Signal channels for coordination
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<TerminationEvent>(8);
    let (progress_tx, mut progress_rx) = watch::channel(false);

    let canonicalizer = config.canonicalizer.clone();
    let event_tx_agent = event_tx.clone();
    let agent_to_child = tokio::spawn(async move {
        let result = forward_agent_to_child(
            agent_reader,
            child_stdin,
            agent_writer_for_agent,
            session_id,
            interceptor,
            canonicalizer,
            max_frame_bytes,
            active_request_id_for_agent,
        )
        .await;

        match result {
            Ok(()) => {
                let _ = event_tx_agent.send(TerminationEvent::AgentEof).await;
            }
            Err(GatewayError::Io(e)) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                let _ = event_tx_agent.send(TerminationEvent::ChildBrokenPipe).await;
            }
            Err(_) => {
                let _ = event_tx_agent.send(TerminationEvent::AgentEof).await;
            }
        }
    });

    let event_tx_child = event_tx.clone();
    let child_to_agent = tokio::spawn(async move {
        let result = forward_child_to_agent(
            child_stdout,
            agent_writer_for_child,
            max_frame_bytes,
            progress_tx,
            active_request_id_for_child,
        )
        .await;

        match result {
            Ok(()) => {
                let _ = event_tx_child.send(TerminationEvent::ChildEof).await;
            }
            Err(GatewayError::Io(e)) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                let _ = event_tx_child.send(TerminationEvent::AgentBrokenPipe).await;
            }
            Err(_) => {
                let _ = event_tx_child.send(TerminationEvent::ChildEof).await;
            }
        }
    });

    // Startup timeout timer
    let startup_timer = tokio::time::sleep(startup_timeout);
    tokio::pin!(startup_timer);

    let mut protocol_ready = false;
    let exit_reason;

    loop {
        if *shutdown.borrow() {
            exit_reason = TerminationEvent::ShutdownSignal;
            break;
        }

        tokio::select! {
            // External shutdown signal (SIGTERM / SIGINT)
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    exit_reason = TerminationEvent::ShutdownSignal;
                    break;
                }
            }

            // Internal stream / pipe / EOF event
            Some(event) = event_rx.recv() => {
                exit_reason = event;
                break;
            }

            // Protocol progress notification (first valid response from child disarms startup timer)
            Ok(()) = progress_rx.changed(), if !protocol_ready => {
                if *progress_rx.borrow() {
                    protocol_ready = true;
                }
            }

            // Subprocess startup timeout (fires only if child never produced protocol progress)
            () = &mut startup_timer, if !protocol_ready => {
                tracing::warn!(
                    timeout_ms = startup_timeout.as_millis(),
                    "Child subprocess failed to produce protocol progress within startup timeout"
                );
                exit_reason = TerminationEvent::StartupTimeout;
                break;
            }
        }
    }

    let termination_event = exit_reason;

    // If child exited while an active request was in flight, return JSON-RPC error -32011 (A001 line 917)
    if matches!(
        termination_event,
        TerminationEvent::ChildEof
            | TerminationEvent::ChildBrokenPipe
            | TerminationEvent::StartupTimeout
    ) {
        let req_id = active_request_id.lock().await.take();
        if let Some(id) = req_id {
            let err_response = JsonRpcResponse::error(
                id,
                ProtocolError::InternalError("Downstream MCP Subprocess Terminated".into()),
            );
            // We specifically use JSON-RPC code -32011 for downstream MCP crash per A001
            let mut val = serde_json::to_value(&err_response).unwrap_or(Value::Null);
            if let Some(err_obj) = val.get_mut("error").and_then(|e| e.as_object_mut()) {
                err_obj.insert("code".into(), Value::from(-32011));
            }
            if let Ok(payload) = serde_json::to_vec(&val) {
                let _ = write_agent_response(&agent_writer, &payload).await;
            }
        }
    }

    // Abort active I/O forwarding tasks so neither task hangs waiting on an unclosed reader
    agent_to_child.abort();
    child_to_agent.abort();

    // Execute architecture-defined graceful termination sequence (SIGTERM -> 500ms -> SIGKILL)
    let exit_status =
        crate::subprocess::terminate_child_gracefully(&mut child, shutdown_grace_period)
            .await
            .ok()
            .flatten();

    let child_exit_code = exit_status.and_then(|s| s.code());

    match termination_event {
        TerminationEvent::StartupTimeout => Err(GatewayError::StartupTimeout(startup_timeout)),
        _ => Ok(GatewayExitStatus { child_exit_code }),
    }
}

async fn write_agent_response<W>(
    agent_writer: &SharedAgentWriter<W>,
    payload: &[u8],
) -> Result<(), GatewayError>
where
    W: AsyncWrite + Unpin,
{
    let mut writer = agent_writer.lock().await;
    writer.write_all(&encode_frame(payload)?).await?;
    writer.flush().await?;
    Ok(())
}

async fn write_agent_protocol_error<W>(
    agent_writer: &SharedAgentWriter<W>,
    request_id: Value,
    error: ProtocolError,
) -> Result<(), GatewayError>
where
    W: AsyncWrite + Unpin,
{
    let response = JsonRpcResponse::error(request_id, error);
    let payload = serialize_message(&JsonRpcMessage::Response(response))?;
    write_agent_response(agent_writer, &payload).await
}

#[allow(clippy::too_many_arguments)]
async fn forward_agent_to_child<R, CW, AW>(
    mut agent_reader: R,
    mut child_stdin: CW,
    agent_writer: SharedAgentWriter<AW>,
    session_id: SessionId,
    interceptor: Arc<dyn ToolCallInterceptor>,
    canonicalizer: Arc<ActionCanonicalizer>,
    max_frame_bytes: usize,
    active_request_id: Arc<Mutex<Option<Value>>>,
) -> Result<(), GatewayError>
where
    R: AsyncRead + Unpin,
    CW: AsyncWrite + Unpin,
    AW: AsyncWrite + Unpin,
{
    let mut read_buf = [0u8; READ_CHUNK_SIZE];
    let mut frame_buffer = FrameBuffer::new(max_frame_bytes);

    loop {
        let n = agent_reader.read(&mut read_buf).await?;
        if n == 0 {
            // EOF on agent stdin: drop child_stdin to signal EOF to child
            drop(child_stdin);
            break;
        }

        let frames = match frame_buffer.push(&read_buf[..n]) {
            Ok(frames) => frames,
            Err(err) => {
                tracing::warn!(error = %err, "rejecting oversized agent frame");
                write_agent_protocol_error(&agent_writer, Value::Null, err).await?;
                frame_buffer = FrameBuffer::new(max_frame_bytes);
                continue;
            }
        };

        for frame in frames {
            if let Err(err) = handle_agent_frame(
                &frame,
                &mut child_stdin,
                &agent_writer,
                session_id,
                &interceptor,
                &canonicalizer,
                &active_request_id,
            )
            .await
            {
                // If writing to child failed with BrokenPipe, return error immediately
                if let GatewayError::Io(ref e) = err {
                    if e.kind() == std::io::ErrorKind::BrokenPipe {
                        return Err(err);
                    }
                }
                tracing::warn!(error = %err, "failed to handle agent frame");
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_agent_frame<CW, AW>(
    frame: &RawFrame,
    child_stdin: &mut CW,
    agent_writer: &SharedAgentWriter<AW>,
    session_id: SessionId,
    interceptor: &Arc<dyn ToolCallInterceptor>,
    canonicalizer: &Arc<ActionCanonicalizer>,
    active_request_id: &Arc<Mutex<Option<Value>>>,
) -> Result<(), GatewayError>
where
    CW: AsyncWrite + Unpin,
    AW: AsyncWrite + Unpin,
{
    let bytes = frame.as_bytes();
    let fallback_id = try_extract_request_id(bytes).unwrap_or(Value::Null);

    // 1. Strict duplicate key and syntax validation
    if let Err(canon_err) = parse_json_bytes_strictly(bytes) {
        tracing::warn!(error = %canon_err, "rejecting invalid agent frame");
        let mut err_val = serde_json::to_value(JsonRpcResponse::error(
            fallback_id,
            ProtocolError::InvalidRequest(canon_err.to_string()),
        ))
        .unwrap_or(Value::Null);
        if let Some(err_obj) = err_val.get_mut("error").and_then(|e| e.as_object_mut()) {
            err_obj.insert("code".into(), Value::from(canon_err.jsonrpc_code()));
        }
        let payload = serde_json::to_vec(&err_val)
            .map_err(|e| ProtocolError::InternalError(e.to_string()))?;
        write_agent_response(agent_writer, &payload).await?;
        return Ok(());
    }

    let outbound = match parse_message(bytes) {
        Ok(JsonRpcMessage::Request(req)) => {
            // Track in-flight request ID
            *active_request_id.lock().await = Some(req.id.clone());

            let method = McpMethod::from_rpc_method(&req.method);
            if method.is_tool_call() {
                let params = req
                    .params
                    .as_ref()
                    .cloned()
                    .unwrap_or(Value::Object(Default::default()));

                let ctx =
                    match build_tool_call_context(session_id, req.id.clone(), &req.method, &params)
                    {
                        Ok(ctx) => ctx,
                        Err(err) => {
                            *active_request_id.lock().await = None;
                            write_agent_protocol_error(agent_writer, req.id.clone(), err).await?;
                            return Ok(());
                        }
                    };

                let tool_ident = match ToolIdentity::parse(&ctx.tool_name) {
                    Ok(t) => t,
                    Err(e) => {
                        *active_request_id.lock().await = None;
                        let err_resp = JsonRpcResponse::error(
                            req.id.clone(),
                            ProtocolError::InvalidParams(format!("Invalid tool identity: {e}")),
                        );
                        let payload = serialize_message(&JsonRpcMessage::Response(err_resp))?;
                        write_agent_response(agent_writer, &payload).await?;
                        return Ok(());
                    }
                };

                let raw_arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or(Value::Object(Default::default()));

                let principal = PrincipalId::new("principal:agent:default")
                    .map_err(|e| ProtocolError::InternalError(e.to_string()))?;

                let canonical_action = match canonicalizer.canonicalize(
                    session_id,
                    principal,
                    &req.method,
                    tool_ident,
                    &raw_arguments,
                    None,
                    None,
                ) {
                    Ok(action) => action,
                    Err(err) => {
                        *active_request_id.lock().await = None;
                        let mut err_val = serde_json::to_value(JsonRpcResponse::error(
                            req.id.clone(),
                            ProtocolError::InvalidParams(err.to_string()),
                        ))
                        .unwrap_or(Value::Null);
                        if let Some(err_obj) =
                            err_val.get_mut("error").and_then(|e| e.as_object_mut())
                        {
                            err_obj.insert("code".into(), Value::from(err.jsonrpc_code()));
                        }
                        let payload = serde_json::to_vec(&err_val)
                            .map_err(|e| ProtocolError::InternalError(e.to_string()))?;
                        write_agent_response(agent_writer, &payload).await?;
                        return Ok(());
                    }
                };

                match interceptor
                    .on_tool_call(&ctx, &canonical_action, bytes)
                    .await
                {
                    InterceptResult::Forward(frame_bytes) => frame_bytes,
                    InterceptResult::Reject(resp) | InterceptResult::Handled(resp) => {
                        *active_request_id.lock().await = None;
                        let payload = serialize_message(&JsonRpcMessage::Response(*resp))?;
                        write_agent_response(agent_writer, &payload).await?;
                        return Ok(());
                    }
                }
            } else {
                bytes.to_vec()
            }
        }
        Ok(JsonRpcMessage::Notification(_)) => bytes.to_vec(),
        Ok(JsonRpcMessage::Response(_)) => bytes.to_vec(),
        Err(err) => {
            tracing::warn!(error = %err, "rejecting invalid agent frame");
            write_agent_protocol_error(agent_writer, fallback_id, err).await?;
            return Ok(());
        }
    };

    child_stdin.write_all(&encode_frame(&outbound)?).await?;
    child_stdin.flush().await?;
    Ok(())
}

async fn forward_child_to_agent<R, W>(
    mut child_stdout: R,
    agent_writer: SharedAgentWriter<W>,
    max_frame_bytes: usize,
    progress_tx: watch::Sender<bool>,
    active_request_id: Arc<Mutex<Option<Value>>>,
) -> Result<(), GatewayError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut read_buf = [0u8; READ_CHUNK_SIZE];
    let mut frame_buffer = FrameBuffer::new(max_frame_bytes);

    loop {
        let n = child_stdout.read(&mut read_buf).await?;
        if n == 0 {
            break;
        }

        let frames = match frame_buffer.push(&read_buf[..n]) {
            Ok(frames) => frames,
            Err(err) => {
                tracing::warn!(error = %err, "rejecting oversized child frame");
                continue;
            }
        };

        for frame in frames {
            // Signal protocol progress on first valid frame received
            let _ = progress_tx.send(true);

            // If this frame is a response to the active request, clear active request tracking
            if let Ok(JsonRpcMessage::Response(ref resp)) = parse_message(frame.as_bytes()) {
                let mut active = active_request_id.lock().await;
                if active.as_ref() == Some(&resp.id) {
                    *active = None;
                }
            }

            write_agent_response(&agent_writer, frame.as_bytes()).await?;
        }
    }

    Ok(())
}
