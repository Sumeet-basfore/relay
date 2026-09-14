use std::collections::HashMap;

pub struct SecurityHeaders;

impl SecurityHeaders {
    pub fn apply(headers: &mut Vec<(&'static str, &'static str)>) {
        headers.push(("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"));
        headers.push(("X-Content-Type-Options", "nosniff"));
        headers.push(("X-Frame-Options", "DENY"));
        headers.push(("Referrer-Policy", "no-referrer"));
        headers.push((
            "Cache-Control",
            "no-store, no-cache, must-revalidate, max-age=0",
        ));
    }
}

pub struct SecurityValidator {
    port: u16,
}

impl SecurityValidator {
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    /// Validates that the Host header matches 127.0.0.1:<port> or localhost:<port>
    /// to mitigate DNS rebinding attacks.
    pub fn validate_host(&self, headers: &HashMap<String, String>) -> Result<(), &'static str> {
        let host = match headers.get("host") {
            Some(h) => h.trim(),
            None => return Err("Missing Host header"),
        };

        let allowed_1 = format!("127.0.0.1:{}", self.port);
        let allowed_2 = format!("localhost:{}", self.port);
        let allowed_3 = "127.0.0.1";
        let allowed_4 = "localhost";

        if host == allowed_1 || host == allowed_2 || host == allowed_3 || host == allowed_4 {
            Ok(())
        } else {
            Err("Host header does not match local interface (potential DNS rebinding attack)")
        }
    }

    /// Validates Origin and Referer for state-changing HTTP methods
    pub fn validate_origin(
        &self,
        method: &str,
        headers: &HashMap<String, String>,
    ) -> Result<(), &'static str> {
        let method_upper = method.to_uppercase();
        if method_upper != "POST" && method_upper != "PUT" && method_upper != "DELETE" {
            return Ok(());
        }

        let origin_opt = headers.get("origin");
        let allowed_origin_1 = format!("http://127.0.0.1:{}", self.port);
        let allowed_origin_2 = format!("http://localhost:{}", self.port);

        if let Some(origin) = origin_opt {
            let o = origin.trim();
            if o == allowed_origin_1 || o == allowed_origin_2 {
                return Ok(());
            } else {
                return Err("Origin header does not match permitted local origin");
            }
        }

        // Fallback to Referer
        if let Some(referer) = headers.get("referer") {
            let r = referer.trim();
            if r.starts_with(&allowed_origin_1) || r.starts_with(&allowed_origin_2) {
                return Ok(());
            } else {
                return Err("Referer header does not match permitted local origin");
            }
        }

        // For local CLI tools/tests calling POST directly with custom header,
        // if neither Origin nor Referer is present, check if custom header X-Relay-Local-Client is set or require CSRF
        Ok(())
    }
}
