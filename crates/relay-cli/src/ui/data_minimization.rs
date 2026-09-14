use serde_json::{Map, Value};

const REDACTED_MARKER: &str = "[REDACTED]";

/// List of key names (lowercased) that indicate sensitive fields
const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "pass",
    "pwd",
    "token",
    "secret",
    "key",
    "private_key",
    "authorization",
    "auth",
    "pat",
    "credential",
    "api_key",
    "access_token",
    "refresh_token",
    "cookie",
];

/// Substrings that trigger value redaction
const SENSITIVE_VALUE_PATTERNS: &[&str] = &[
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "sk-proj-",
    "AKIA",
    "ASIA",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "bearer ",
    "basic ",
];

/// Recursively sanitizes and minimizes a JSON structure for UI rendering
pub fn sanitize_json_value(val: &Value) -> Value {
    match val {
        Value::Object(map) => {
            let mut new_map = Map::new();
            for (k, v) in map {
                let k_lower = k.to_lowercase();
                if SENSITIVE_KEYS.iter().any(|&sk| k_lower.contains(sk)) {
                    new_map.insert(k.clone(), Value::String(REDACTED_MARKER.to_string()));
                } else {
                    new_map.insert(k.clone(), sanitize_json_value(v));
                }
            }
            Value::Object(new_map)
        }
        Value::Array(arr) => {
            let new_arr: Vec<Value> = arr.iter().map(sanitize_json_value).collect();
            Value::Array(new_arr)
        }
        Value::String(s) => {
            let s_lower = s.to_lowercase();
            if SENSITIVE_VALUE_PATTERNS
                .iter()
                .any(|&pattern| s.contains(pattern) || s_lower.contains(pattern))
            {
                Value::String(REDACTED_MARKER.to_string())
            } else {
                Value::String(s.clone())
            }
        }
        other => other.clone(),
    }
}

/// Sanitizes SQL string to strip embedded passwords or secrets
pub fn sanitize_sql_preview(query: &str) -> String {
    let lower = query.to_lowercase();
    if lower.contains("password") || lower.contains("secret") || lower.contains("identified by") {
        return "[SQL QUERY REDACTED: Contains credential keywords]".to_string();
    }
    query.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_redacts_sensitive_keys() {
        let dirty = json!({
            "username": "alice",
            "password": "supersecretpassword",
            "github_token": "ghp_1234567890abcdef",
            "nested": {
                "api_key": "xyz987"
            }
        });

        let sanitized = sanitize_json_value(&dirty);
        assert_eq!(sanitized["username"], "alice");
        assert_eq!(sanitized["password"], "[REDACTED]");
        assert_eq!(sanitized["github_token"], "[REDACTED]");
        assert_eq!(sanitized["nested"]["api_key"], "[REDACTED]");
    }

    #[test]
    fn test_redacts_sensitive_values() {
        let dirty = json!({
            "info": "Connecting with ghp_9999999999999999 to github",
            "cert": "-----BEGIN RSA PRIVATE KEY-----..."
        });

        let sanitized = sanitize_json_value(&dirty);
        assert_eq!(sanitized["info"], "[REDACTED]");
        assert_eq!(sanitized["cert"], "[REDACTED]");
    }
}
