use relay_domain::error::{CanonicalizationError, RelayError};

/// List of standard RFC 7230 hop-by-hop headers plus Relay-specific authentication headers
pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "relay-proxy-auth",
];

/// Policy for sanitizing and transforming HTTP headers during proxy forwarding
#[derive(Debug, Clone, Default)]
pub struct HeaderPolicy;

impl HeaderPolicy {
    /// Check if a header is a hop-by-hop or proxy-internal header that must be stripped before upstream forwarding
    pub fn is_hop_by_hop(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        HOP_BY_HOP_HEADERS.contains(&lower.as_str())
    }

    /// Validate header names and values to prevent HTTP response/request splitting and CRLF injection
    pub fn validate_header(name: &str, value: &str) -> Result<(), RelayError> {
        if name.contains('\r') || name.contains('\n') || name.contains('\0') {
            return Err(RelayError::Canonicalization(
                CanonicalizationError::MalformedJson("CRLF injection in header name".to_string()),
            ));
        }
        if value.contains('\r') || value.contains('\n') || value.contains('\0') {
            return Err(RelayError::Canonicalization(
                CanonicalizationError::MalformedJson("CRLF injection in header value".to_string()),
            ));
        }
        Ok(())
    }

    /// Extract bearer token from `Proxy-Authorization` or `RELAY_PROXY_AUTH` header
    pub fn extract_proxy_token(headers: &[(String, String)]) -> Option<String> {
        for (name, value) in headers {
            let lower = name.to_ascii_lowercase();
            if lower == "proxy-authorization" {
                let trimmed = value.trim();
                if let Some(token) = trimmed.strip_prefix("Bearer ") {
                    return Some(token.trim().to_string());
                } else if let Some(token) = trimmed.strip_prefix("Basic ") {
                    // Support basic auth formatting where username or password is the token
                    if let Ok(decoded) = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        token.trim(),
                    ) {
                        if let Ok(s) = String::from_utf8(decoded) {
                            if let Some((user, _pass)) = s.split_once(':') {
                                return Some(user.to_string());
                            } else {
                                return Some(s);
                            }
                        }
                    }
                }
            } else if lower == "relay-proxy-auth" {
                return Some(value.trim().to_string());
            }
        }
        None
    }

    /// Filter headers for upstream forwarding (stripping hop-by-hop headers)
    pub fn sanitize_for_upstream(headers: &[(String, String)]) -> Vec<(String, String)> {
        headers
            .iter()
            .filter(|(name, _)| !Self::is_hop_by_hop(name))
            .cloned()
            .collect()
    }
}
