//! Child subprocess environment sanitization policy.

use std::collections::BTreeMap;
use tokio::process::Command;

/// Environment variables explicitly restored after `env_clear()`.
pub const SAFE_ENV_VARS: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "TMPDIR",
    "SYSTEMROOT",
    "WINDIR",
];

const RELAY_ACTIVE: &str = "RELAY_ACTIVE";
const RELAY_VERSION: &str = "RELAY_VERSION";

fn is_safe_var(key: &str) -> bool {
    SAFE_ENV_VARS.contains(&key) || key.starts_with("LC_")
}

/// Build the sanitized environment map for a child MCP subprocess.
pub fn sanitized_child_env(relay_version: &str) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();

    for (key, value) in std::env::vars_os() {
        let key_str = key.to_string_lossy();
        if is_safe_var(&key_str) {
            env.insert(key_str.into_owned(), value.to_string_lossy().into_owned());
        }
    }

    env.insert(RELAY_ACTIVE.into(), "1".into());
    env.insert(RELAY_VERSION.into(), relay_version.into());

    env
}

/// Apply the sanitized environment policy to a `Command`.
pub fn apply_sanitized_env(cmd: &mut Command, relay_version: &str) {
    cmd.env_clear();
    for (key, value) in sanitized_child_env(relay_version) {
        cmd.env(key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_lc_vars() {
        std::env::set_var("LC_ALL", "en_US.UTF-8");
        let env = sanitized_child_env("0.1.0");
        assert_eq!(env.get("LC_ALL").map(String::as_str), Some("en_US.UTF-8"));
        std::env::remove_var("LC_ALL");
    }

    #[test]
    fn strips_sensitive_vars() {
        std::env::set_var("RELAY_TEST_SECRET_ENV", "super-secret");
        let env = sanitized_child_env("0.1.0");
        assert!(!env.contains_key("RELAY_TEST_SECRET_ENV"));
        assert_eq!(env.get(RELAY_ACTIVE).map(String::as_str), Some("1"));
        std::env::remove_var("RELAY_TEST_SECRET_ENV");
    }
}
