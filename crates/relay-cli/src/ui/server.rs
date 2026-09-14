use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::ui::api::{handle_api_request, UiState};
use crate::ui::assets::get_static_asset;
use crate::ui::security_middleware::{SecurityHeaders, SecurityValidator};

const MAX_BODY_SIZE: usize = 1024 * 1024; // 1 MB
const MAX_HEADER_SIZE: usize = 16 * 1024; // 16 KB

pub struct UiServer {
    state: UiState,
    bind_addr: SocketAddr,
}

impl UiServer {
    pub fn new(state: UiState, bind_addr: SocketAddr) -> Self {
        Self { state, bind_addr }
    }

    pub async fn run(
        self,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<(), crate::cli_error::CliError> {
        let listener = TcpListener::bind(self.bind_addr).await.map_err(|e| {
            crate::cli_error::CliError::ExecutionError(format!(
                "Failed to bind UI server to {}: {e}",
                self.bind_addr
            ))
        })?;

        let validator = Arc::new(SecurityValidator::new(self.state.port));
        let state = Arc::new(self.state);

        info!(addr = %self.bind_addr, "Relay Security Console listening on loopback");

        loop {
            tokio::select! {
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((stream, client_addr)) => {
                            let val = Arc::clone(&validator);
                            let st = Arc::clone(&state);
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, client_addr, val, st).await {
                                    debug!(client = %client_addr, error = %e, "UI client connection error");
                                }
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "Error accepting UI TCP connection");
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Relay Security Console received shutdown signal");
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    validator: Arc<SecurityValidator>,
    state: Arc<UiState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buffer = vec![0u8; MAX_HEADER_SIZE];
    let mut total_read = 0;

    // Read headers
    let (header_len, method, path, headers) = loop {
        let n = stream.read(&mut buffer[total_read..]).await?;
        if n == 0 {
            return Ok(());
        }
        total_read += n;

        let mut headers_raw = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers_raw);
        match req.parse(&buffer[..total_read]) {
            Ok(httparse::Status::Complete(hlen)) => {
                let method = req.method.unwrap_or("GET").to_string();
                let path = req.path.unwrap_or("/").to_string();
                let mut headers = HashMap::new();
                for h in req.headers.iter() {
                    let name = h.name.to_lowercase();
                    if let Ok(val) = std::str::from_utf8(h.value) {
                        headers.insert(name, val.trim().to_string());
                    }
                }
                break (hlen, method, path, headers);
            }
            Ok(httparse::Status::Partial) => {
                if total_read >= MAX_HEADER_SIZE {
                    send_response(
                        &mut stream,
                        431,
                        "text/plain",
                        b"Request Header Fields Too Large",
                    )
                    .await?;
                    return Ok(());
                }
            }
            Err(e) => {
                send_response(
                    &mut stream,
                    400,
                    "text/plain",
                    format!("Bad Request: {e}").as_bytes(),
                )
                .await?;
                return Ok(());
            }
        }
    };

    // 1. Host header validation (DNS rebinding defense)
    if let Err(err_msg) = validator.validate_host(&headers) {
        warn!(client = %client_addr, error = err_msg, "Blocked request with invalid Host header");
        send_response(
            &mut stream,
            403,
            "application/json",
            format!("{{\"error\":\"{err_msg}\"}}").as_bytes(),
        )
        .await?;
        return Ok(());
    }

    // 2. Origin & Referer validation (CSRF defense)
    if let Err(err_msg) = validator.validate_origin(&method, &headers) {
        warn!(client = %client_addr, error = err_msg, "Blocked cross-origin request");
        send_response(
            &mut stream,
            403,
            "application/json",
            format!("{{\"error\":\"{err_msg}\"}}").as_bytes(),
        )
        .await?;
        return Ok(());
    }

    // 3. Read Body if Content-Length specified
    let content_len = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    if content_len > MAX_BODY_SIZE {
        send_response(&mut stream, 413, "text/plain", b"Payload Too Large").await?;
        return Ok(());
    }

    let mut body = Vec::with_capacity(content_len);
    let initial_body = &buffer[header_len..total_read];
    body.extend_from_slice(initial_body);

    while body.len() < content_len {
        let mut chunk = vec![0u8; (content_len - body.len()).min(8192)];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }

    // Clean path (strip query params)
    let clean_path = path.split('?').next().unwrap_or("/");

    // 4. Dispatch Request
    if clean_path.starts_with("/api/v1/") {
        match handle_api_request(clean_path, &method, &headers, &body, &state).await {
            Ok((status, content_type, data)) => {
                send_response(&mut stream, status, content_type, &data).await?;
            }
            Err((status, msg)) => {
                send_response(&mut stream, status, "application/json", msg.as_bytes()).await?;
            }
        }
    } else {
        // Static Asset
        if method.to_uppercase() != "GET" {
            send_response(&mut stream, 405, "text/plain", b"Method Not Allowed").await?;
            return Ok(());
        }

        match get_static_asset(clean_path) {
            Some(asset) => {
                send_response(&mut stream, 200, asset.content_type(), asset.bytes()).await?;
            }
            None => {
                // SPA fallback: return index.html for unrecognized routes
                if let Some(index) = get_static_asset("/") {
                    send_response(&mut stream, 200, index.content_type(), index.bytes()).await?;
                } else {
                    send_response(&mut stream, 404, "text/plain", b"Not Found").await?;
                }
            }
        }
    }

    Ok(())
}

async fn send_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), std::io::Error> {
    let status_text = match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        _ => "Response",
    };

    let mut headers = vec![("Server", "Relay-Console/0.1.0"), ("Connection", "close")];

    SecurityHeaders::apply(&mut headers);

    let mut resp = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        resp.push_str(&format!("{k}: {v}\r\n"));
    }
    resp.push_str("\r\n");

    stream.write_all(resp.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}
