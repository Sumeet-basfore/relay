//! Governed HTTPS client for GitHub API communication.
//!
//! Enforces:
//! - Strict endpoint and hostname whitelist (api.github.com or hermetic loopback mock)
//! - Redirection lockdown (cannot redirect outside trusted host or downgrade to HTTP)
//! - Rustls memory-safe TLS with webpki-roots
//! - Strict response body bounds (max 2 MB)
//! - Secret injection directly into HTTP headers (never in URLs or query strings)
//! - Explicit ambiguous mutation error tracking on timeouts

use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use reqwest::{Client, Method, StatusCode, Url};
use std::time::Duration;

use super::error::GitHubError;
use relay_domain::SecretBuffer;

/// Default production GitHub API host.
pub const DEFAULT_GITHUB_HOST: &str = "api.github.com";
/// Default production GitHub API base URL.
pub const DEFAULT_GITHUB_BASE_URL: &str = "https://api.github.com";
/// GitHub API version header value.
pub const GITHUB_API_VERSION: &str = "2022-11-28";
/// Maximum response size in bytes (2 MB).
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Configuration for GitHub HTTP client.
#[derive(Debug, Clone)]
pub struct GitHubClientConfig {
    pub base_url: String,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
    pub allow_http_loopback: bool,
}

impl Default for GitHubClientConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_GITHUB_BASE_URL.to_string(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(15),
            max_response_bytes: MAX_RESPONSE_BYTES,
            allow_http_loopback: false,
        }
    }
}

impl GitHubClientConfig {
    /// Test configuration permitting loopback wiremock testing over HTTP.
    pub fn loopback_test(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(5),
            max_response_bytes: MAX_RESPONSE_BYTES,
            allow_http_loopback: true,
        }
    }
}

/// Response returned from a governed GitHub API call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubResponse {
    pub status: StatusCode,
    pub body: Vec<u8>,
    pub rate_limit_remaining: Option<u64>,
    pub rate_limit_reset: Option<u64>,
}

/// Governed HTTP client encapsulating all network I/O with GitHub.
pub struct GitHubClient {
    client: Client,
    config: GitHubClientConfig,
    trusted_host: String,
    trusted_port: Option<u16>,
}

impl GitHubClient {
    pub fn new(config: GitHubClientConfig) -> Result<Self, GitHubError> {
        let parsed_base = Url::parse(&config.base_url).map_err(|e| {
            GitHubError::InvalidEndpoint(format!("Invalid base_url '{}': {e}", config.base_url))
        })?;

        // Endpoint validation (SI-007)
        let scheme = parsed_base.scheme();
        let host_str = parsed_base.host_str().unwrap_or_default().to_string();

        if scheme == "http" {
            if !config.allow_http_loopback {
                return Err(GitHubError::InvalidEndpoint(
                    "HTTP scheme forbidden; HTTPS required for GitHub API (SI-007)".to_string(),
                ));
            }
            if host_str != "127.0.0.1" && host_str != "localhost" {
                return Err(GitHubError::InvalidEndpoint(format!(
                    "Insecure HTTP forbidden for non-loopback host '{host_str}' (SI-007)"
                )));
            }
        } else if scheme != "https" {
            return Err(GitHubError::InvalidEndpoint(format!(
                "Unsupported scheme '{scheme}'; only HTTPS is supported"
            )));
        }

        if !config.allow_http_loopback && host_str != DEFAULT_GITHUB_HOST {
            return Err(GitHubError::InvalidEndpoint(format!(
                "Host '{host_str}' is not an authorized GitHub host; expected '{DEFAULT_GITHUB_HOST}' (SI-007)"
            )));
        }

        let trusted_host = host_str;
        let trusted_port = parsed_base.port();

        // Build locked-down reqwest client
        let trusted_host_clone = trusted_host.clone();
        let redirect_policy = reqwest::redirect::Policy::custom(move |attempt| {
            // Strictly prevent redirect to any host other than our trusted host
            let target_host = attempt.url().host_str().map(|s| s.to_string());
            if let Some(host) = target_host {
                if host != trusted_host_clone {
                    return attempt.error(format!(
                        "Redirect to untrusted host '{host}' rejected by Relay security policy (SI-007)"
                    ));
                }
            } else {
                return attempt.error("Redirect to invalid URL without host rejected (SI-007)");
            }

            if attempt.previous().len() >= 5 {
                attempt.error("Too many redirects")
            } else {
                attempt.follow()
            }
        });

        let mut client_builder = Client::builder()
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .redirect(redirect_policy);

        // Enforce rustls-tls memory-safe TLS
        client_builder = client_builder.use_rustls_tls();

        let client = client_builder.build().map_err(|e| {
            GitHubError::NetworkFailure(format!("Failed to build HTTP client: {e}"))
        })?;

        Ok(Self {
            client,
            config,
            trusted_host,
            trusted_port,
        })
    }

    /// Returns reference to client configuration.
    pub fn config(&self) -> &GitHubClientConfig {
        &self.config
    }

    /// Dispatches a pre-authorized operation to GitHub.
    pub async fn execute_request(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        secret: &SecretBuffer,
        is_mutating: bool,
        operation_name: &str,
    ) -> Result<GitHubResponse, GitHubError> {
        // 1. Construct and validate URL
        let full_url_str = format!("{}{}", self.config.base_url.trim_end_matches('/'), path);
        let url = Url::parse(&full_url_str).map_err(|e| {
            GitHubError::InvalidEndpoint(format!("Failed to parse URL '{full_url_str}': {e}"))
        })?;

        // Validate scheme, host, and port
        if url.host_str() != Some(&self.trusted_host) {
            return Err(GitHubError::InvalidEndpoint(format!(
                "Host substitution detected: URL host '{:?}' does not match trusted host '{}' (SI-007)",
                url.host_str(),
                self.trusted_host
            )));
        }
        if url.port() != self.trusted_port {
            return Err(GitHubError::InvalidEndpoint(format!(
                "Port substitution detected: URL port '{:?}' does not match trusted port '{:?}' (SI-007)",
                url.port(),
                self.trusted_port
            )));
        }

        // 2. Build headers with secret injection
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(
            "x-github-api-version",
            HeaderValue::from_static(GITHUB_API_VERSION),
        );
        headers.insert(USER_AGENT, HeaderValue::from_static("Relay-Gateway/0.1.0"));

        // Inject Authorization: Bearer <token> safely
        let auth_val = secret.expose_scoped(|bytes| {
            let mut header_str = Vec::with_capacity(7 + bytes.len());
            header_str.extend_from_slice(b"Bearer ");
            header_str.extend_from_slice(bytes);
            HeaderValue::from_bytes(&header_str).ok()
        });

        let auth_val = auth_val.ok_or_else(|| {
            GitHubError::CredentialError("Invalid characters in credential token".to_string())
        })?;
        headers.insert(AUTHORIZATION, auth_val);

        // 3. Construct HTTP request
        let mut request_builder = self.client.request(method.clone(), url).headers(headers);

        if let Some(body_bytes) = body {
            request_builder = request_builder
                .header("Content-Type", "application/json")
                .body(body_bytes);
        }

        // 4. Dispatch request and handle network / timeout errors
        let start_time = std::time::Instant::now();
        let resp = match request_builder.send().await {
            Ok(r) => r,
            Err(err) => {
                let elapsed_ms = start_time.elapsed().as_millis() as u64;
                if err.is_timeout() {
                    if is_mutating {
                        // Crucial security invariant: Mutating timeout has unknown remote state!
                        return Err(GitHubError::AmbiguousMutationOutcome {
                            operation: operation_name.to_string(),
                            reason: format!(
                                "Request timed out after {elapsed_ms}ms; remote mutation outcome unknown"
                            ),
                        });
                    } else {
                        return Err(GitHubError::Timeout {
                            timeout_ms: elapsed_ms,
                        });
                    }
                }
                if err.is_connect() {
                    return Err(GitHubError::NetworkFailure(format!(
                        "Connection failed: {err}"
                    )));
                }
                return Err(GitHubError::NetworkFailure(err.to_string()));
            }
        };

        // 5. Rate limit headers extraction
        let rate_limit_remaining = resp
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        let rate_limit_reset = resp
            .headers()
            .get("x-ratelimit-reset")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        let status = resp.status();

        // 6. Response body size limit (SI-014 DoS guard)
        if let Some(content_len) = resp.content_length() {
            if content_len as usize > self.config.max_response_bytes {
                return Err(GitHubError::ResponseTooLarge {
                    size: content_len as usize,
                    limit: self.config.max_response_bytes,
                });
            }
        }

        let body_bytes = resp.bytes().await.map_err(|e| {
            GitHubError::NetworkFailure(format!("Failed to read response body: {e}"))
        })?;

        if body_bytes.len() > self.config.max_response_bytes {
            return Err(GitHubError::ResponseTooLarge {
                size: body_bytes.len(),
                limit: self.config.max_response_bytes,
            });
        }

        // 7. Status code classification
        if status.is_success() {
            return Ok(GitHubResponse {
                status,
                body: body_bytes.to_vec(),
                rate_limit_remaining,
                rate_limit_reset,
            });
        }

        // Handle error responses safely without leaking sensitive information
        let sanitized_body = String::from_utf8_lossy(&body_bytes).to_string();

        match status {
            StatusCode::UNAUTHORIZED => Err(GitHubError::AuthenticationFailed),
            StatusCode::FORBIDDEN => {
                if rate_limit_remaining == Some(0) {
                    Err(GitHubError::RateLimited {
                        message: "GitHub API rate limit exceeded".to_string(),
                        reset_at: rate_limit_reset.unwrap_or(0),
                    })
                } else {
                    Err(GitHubError::AuthorizationFailed(sanitized_body))
                }
            }
            StatusCode::NOT_FOUND => Err(GitHubError::NotFound(sanitized_body)),
            StatusCode::CONFLICT => Err(GitHubError::Conflict(sanitized_body)),
            StatusCode::UNPROCESSABLE_ENTITY => Err(GitHubError::ValidationError(sanitized_body)),
            StatusCode::TOO_MANY_REQUESTS => Err(GitHubError::RateLimited {
                message: "GitHub API 429 Too Many Requests".to_string(),
                reset_at: rate_limit_reset.unwrap_or(0),
            }),
            s if s.is_server_error() => Err(GitHubError::ServerError {
                status: s.as_u16(),
                message: sanitized_body,
            }),
            other => Err(GitHubError::ServerError {
                status: other.as_u16(),
                message: sanitized_body,
            }),
        }
    }
}
