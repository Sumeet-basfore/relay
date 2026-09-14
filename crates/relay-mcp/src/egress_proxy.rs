use chrono::Utc;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use relay_domain::authorization::{AuthorizationRequest, PolicyDecisionType};
use relay_domain::egress::{EgressDecision, NetworkEndpoint, ProxyLease};
use relay_domain::error::{InvariantViolationError, RelayError};
use relay_domain::id::{SessionId, ToolId};
use relay_domain::principal::Principal;
use relay_domain::resource::ResourceUri;
use relay_domain::traits::PolicyEngine;

use crate::egress_dns::DnsResolverWithBlacklist;
use crate::egress_headers::HeaderPolicy;
use crate::egress_injector::CredentialInjector;
use crate::egress_session::ProxySessionManager;

/// In-process loopback HTTP forward proxy with Cedar destination allowlisting and JIT credential injection (SI-019, SI-020, SI-021, SI-022)
#[derive(Clone)]
pub struct EgressProxy {
    bind_addr: SocketAddr,
    session_manager: ProxySessionManager,
    dns_resolver: DnsResolverWithBlacklist,
    credential_injector: CredentialInjector,
    policy_engine: Option<Arc<dyn PolicyEngine>>,
}

impl fmt::Debug for EgressProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EgressProxy")
            .field("bind_addr", &self.bind_addr)
            .field("session_manager", &self.session_manager)
            .field("dns_resolver", &self.dns_resolver)
            .field("credential_injector", &self.credential_injector)
            .field("policy_engine", &self.policy_engine.is_some())
            .finish()
    }
}

impl EgressProxy {
    pub fn new(
        bind_addr: SocketAddr,
        session_manager: ProxySessionManager,
        dns_resolver: DnsResolverWithBlacklist,
        credential_injector: CredentialInjector,
        policy_engine: Option<Arc<dyn PolicyEngine>>,
    ) -> Self {
        Self {
            bind_addr,
            session_manager,
            dns_resolver,
            credential_injector,
            policy_engine,
        }
    }

    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    pub fn proxy_url(&self) -> String {
        format!("http://{}", self.bind_addr)
    }

    pub fn session_manager(&self) -> &ProxySessionManager {
        &self.session_manager
    }

    pub fn dns_resolver(&self) -> &DnsResolverWithBlacklist {
        &self.dns_resolver
    }

    pub fn credential_injector(&self) -> &CredentialInjector {
        &self.credential_injector
    }

    /// Start listening on loopback and processing proxy requests until shutdown signal received
    pub async fn run_server(
        self: Arc<Self>,
        listener: TcpListener,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<(), RelayError> {
        info!(addr = %self.bind_addr, "Egress proxy server listening on loopback");

        loop {
            tokio::select! {
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((stream, client_addr)) => {
                            let proxy = Arc::clone(&self);
                            tokio::spawn(async move {
                                if let Err(e) = proxy.handle_client(stream, client_addr).await {
                                    debug!(client = %client_addr, error = %e, "Proxy client connection terminated");
                                }
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "Error accepting proxy connection");
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Egress proxy received shutdown signal, stopping listener");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Parse initial HTTP request and route to CONNECT tunnel or HTTP Forward handler
    async fn handle_client(
        &self,
        mut client_stream: TcpStream,
        client_addr: SocketAddr,
    ) -> Result<(), RelayError> {
        let mut buffer = vec![0u8; 8192];
        let n = client_stream.read(&mut buffer).await.map_err(|e| {
            RelayError::Execution(relay_domain::error::ExecutionError::EgressProxyError(
                format!("Failed to read from proxy client {client_addr}: {e}"),
            ))
        })?;

        if n == 0 {
            return Ok(());
        }

        let raw_req = String::from_utf8_lossy(&buffer[..n]);
        let mut lines = raw_req.lines();
        let request_line = match lines.next() {
            Some(line) => line,
            None => {
                let _ = client_stream
                    .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    .await;
                return Ok(());
            }
        };

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 3 {
            let _ = client_stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                .await;
            return Ok(());
        }

        let method = parts[0];
        let target = parts[1];
        let _http_version = parts[2];

        // Parse headers
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }

        // Extract proxy token
        let proxy_token = HeaderPolicy::extract_proxy_token(&headers);

        if method.eq_ignore_ascii_case("CONNECT") {
            self.handle_connect(client_stream, target, proxy_token, client_addr)
                .await
        } else {
            self.handle_http_forward(
                client_stream,
                method,
                target,
                headers,
                proxy_token,
                client_addr,
            )
            .await
        }
    }

    /// Handle HTTPS CONNECT tunnel (e.g. `CONNECT api.github.com:443 HTTP/1.1`)
    async fn handle_connect(
        &self,
        mut client_stream: TcpStream,
        target: &str,
        proxy_token: Option<String>,
        client_addr: SocketAddr,
    ) -> Result<(), RelayError> {
        let (host, port) = match target.split_once(':') {
            Some((h, p)) => {
                let parsed_p = p.parse::<u16>().unwrap_or(443);
                (h, parsed_p)
            }
            None => (target, 443),
        };

        let endpoint = NetworkEndpoint::new("https", host, port);

        // 1. Validate Proxy Lease Token (SI-020)
        let lease = match self
            .authenticate_lease(proxy_token.as_deref(), Some(&endpoint))
            .await
        {
            Ok(l) => l,
            Err(e) => {
                warn!(client = %client_addr, target = target, error = %e, "Proxy authentication rejected");
                let _ = client_stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Bearer\r\n\r\n").await;
                return Ok(());
            }
        };

        // 2. Validate DNS and Blacklists (SI-022)
        let target_addr = match self.dns_resolver.resolve_and_validate(host, port).await {
            Ok(addr) => addr,
            Err(e) => {
                warn!(host = host, port = port, error = %e, "Egress destination blocked by DNS blacklist (SI-022)");
                let _ = client_stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                    .await;
                return Ok(());
            }
        };

        // 3. Cedar PDP Destination Authorization (SI-019)
        let decision = self
            .evaluate_policy(&lease.principal, &endpoint, "CONNECT")
            .await?;
        match decision {
            EgressDecision::Allow => {
                debug!(target = target, "Cedar policy ALLOWED CONNECT tunnel");
            }
            EgressDecision::Deny { reason } => {
                warn!(target = target, reason = %reason, "Cedar policy DENIED CONNECT tunnel (SI-019)");
                let _ = client_stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                    .await;
                return Ok(());
            }
            EgressDecision::RequireStepUp { reason } => {
                warn!(target = target, reason = %reason, "Step-up approval required for CONNECT tunnel");
                let _ = client_stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                    .await;
                return Ok(());
            }
        }

        // 4. Connect to upstream pinned IP
        let upstream_stream = match TcpStream::connect(target_addr).await {
            Ok(s) => s,
            Err(e) => {
                warn!(target = target, addr = %target_addr, error = %e, "Failed to connect to upstream target");
                let _ = client_stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await;
                return Ok(());
            }
        };

        // 5. Send 200 Connection Established to client
        if let Err(e) = client_stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
        {
            return Err(RelayError::Execution(
                relay_domain::error::ExecutionError::EgressProxyError(format!(
                    "Failed to send 200 Connection Established: {e}"
                )),
            ));
        }

        // 6. Bidirectional splice/copy
        let (mut client_rd, mut client_wr) = client_stream.into_split();
        let (mut upstream_rd, mut upstream_wr) = upstream_stream.into_split();

        let client_to_upstream = tokio::io::copy(&mut client_rd, &mut upstream_wr);
        let upstream_to_client = tokio::io::copy(&mut upstream_rd, &mut client_wr);

        tokio::select! {
            _ = client_to_upstream => {},
            _ = upstream_to_client => {},
        };

        Ok(())
    }

    /// Handle standard HTTP forward requests (e.g. `GET http://api.github.com/repos HTTP/1.1`)
    async fn handle_http_forward(
        &self,
        mut client_stream: TcpStream,
        method: &str,
        target_url: &str,
        headers: Vec<(String, String)>,
        proxy_token: Option<String>,
        client_addr: SocketAddr,
    ) -> Result<(), RelayError> {
        let endpoint = match NetworkEndpoint::parse(target_url) {
            Ok(ep) => ep,
            Err(e) => {
                warn!(target = target_url, error = %e, "Failed to parse target URL");
                let _ = client_stream
                    .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    .await;
                return Ok(());
            }
        };

        // 1. Authenticate proxy lease (SI-020)
        let lease = match self
            .authenticate_lease(proxy_token.as_deref(), Some(&endpoint))
            .await
        {
            Ok(l) => l,
            Err(e) => {
                warn!(client = %client_addr, target = target_url, error = %e, "Proxy authentication failed");
                let _ = client_stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Bearer\r\n\r\n").await;
                return Ok(());
            }
        };

        // 2. Validate DNS and Blacklists (SI-022)
        let target_addr = match self
            .dns_resolver
            .resolve_and_validate(&endpoint.host, endpoint.port)
            .await
        {
            Ok(addr) => addr,
            Err(e) => {
                warn!(host = %endpoint.host, port = endpoint.port, error = %e, "Destination blocked by DNS blacklist (SI-022)");
                let _ = client_stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                    .await;
                return Ok(());
            }
        };

        // 3. Cedar Policy Authorization (SI-019)
        let decision = self
            .evaluate_policy(&lease.principal, &endpoint, method)
            .await?;
        match decision {
            EgressDecision::Allow => {
                debug!(endpoint = %endpoint, method = method, "Cedar policy ALLOWED HTTP egress request");
            }
            EgressDecision::Deny { reason } => {
                warn!(endpoint = %endpoint, method = method, reason = %reason, "Cedar policy DENIED HTTP egress request (SI-019)");
                let _ = client_stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                    .await;
                return Ok(());
            }
            EgressDecision::RequireStepUp { reason } => {
                warn!(endpoint = %endpoint, reason = %reason, "Step-up approval required for HTTP egress");
                let _ = client_stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                    .await;
                return Ok(());
            }
        }

        // 4. Sanitize headers (strip hop-by-hop and proxy-auth) and Inject vaulted credentials (SI-021)
        let mut sanitized_headers = HeaderPolicy::sanitize_for_upstream(&headers);
        self.credential_injector
            .inject(&endpoint, &mut sanitized_headers)
            .await;

        // Ensure Host header is present
        if !sanitized_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("host"))
        {
            sanitized_headers.push(("Host".to_string(), endpoint.host.clone()));
        }

        // 5. Connect to upstream pinned IP
        let mut upstream_stream = match TcpStream::connect(target_addr).await {
            Ok(s) => s,
            Err(e) => {
                warn!(addr = %target_addr, error = %e, "Failed to connect to upstream target");
                let _ = client_stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await;
                return Ok(());
            }
        };

        // Construct upstream request path
        let path = endpoint.path_prefix.as_deref().unwrap_or("/");
        let mut req_buf = format!("{} {} HTTP/1.1\r\n", method, path);
        for (k, v) in sanitized_headers {
            req_buf.push_str(&format!("{}: {}\r\n", k, v));
        }
        req_buf.push_str("\r\n");

        if let Err(e) = upstream_stream.write_all(req_buf.as_bytes()).await {
            let _ = client_stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await;
            return Err(RelayError::Execution(
                relay_domain::error::ExecutionError::EgressProxyError(format!(
                    "Failed to write upstream request: {e}"
                )),
            ));
        }

        // 6. Splice response back to client
        let (mut client_rd, mut client_wr) = client_stream.into_split();
        let (mut upstream_rd, mut upstream_wr) = upstream_stream.into_split();

        let client_to_upstream = tokio::io::copy(&mut client_rd, &mut upstream_wr);
        let upstream_to_client = tokio::io::copy(&mut upstream_rd, &mut client_wr);

        tokio::select! {
            _ = client_to_upstream => {},
            _ = upstream_to_client => {},
        };

        Ok(())
    }

    async fn authenticate_lease(
        &self,
        token: Option<&str>,
        endpoint: Option<&NetworkEndpoint>,
    ) -> Result<ProxyLease, RelayError> {
        let token_str = token.ok_or(RelayError::InvariantViolation(
            InvariantViolationError::EphemeralProxySessionInvalid,
        ))?;

        self.session_manager
            .validate_lease(token_str, endpoint)
            .await
    }

    async fn evaluate_policy(
        &self,
        principal: &Principal,
        endpoint: &NetworkEndpoint,
        action_verb: &str,
    ) -> Result<EgressDecision, RelayError> {
        if let Some(engine) = &self.policy_engine {
            let auth_req = AuthorizationRequest {
                principal: principal.id().clone(),
                action: "mcp.http_request".to_string(),
                resource: ResourceUri::parse(&endpoint.to_uri())?,
                session_id: SessionId::new_v7(),
                tool: ToolId::new("mcp", "http_request")?,
                arguments: serde_json::json!({
                    "host": endpoint.host,
                    "port": endpoint.port,
                    "scheme": endpoint.scheme,
                    "verb": action_verb,
                }),
                working_directory: ".".to_string(),
                timestamp: Utc::now(),
                action_hash: None,
            };

            let decision = engine.evaluate(&auth_req).await?;
            match decision.decision {
                PolicyDecisionType::Allow => Ok(EgressDecision::Allow),
                PolicyDecisionType::Deny => Ok(EgressDecision::Deny {
                    reason: decision
                        .reason
                        .unwrap_or_else(|| "Forbidden by Cedar policy".to_string()),
                }),
                PolicyDecisionType::ApprovalRequired => Ok(EgressDecision::RequireStepUp {
                    reason: decision.reason.unwrap_or_else(|| {
                        "Human step-up approval required for endpoint".to_string()
                    }),
                }),
            }
        } else {
            // Default allow for testing if no policy engine attached
            Ok(EgressDecision::Allow)
        }
    }
}
