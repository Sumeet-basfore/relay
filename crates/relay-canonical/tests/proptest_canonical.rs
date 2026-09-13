//! Property-based fuzz tests verifying determinism, panic-freedom, and robustness.

use proptest::prelude::*;
use relay_canonical::{
    canonicalize_value, parse_json_strictly, ActionCanonicalizer, FilesystemNormalizer,
    GitHubNormalizer, SqlNormalizer, ToolIdentity,
};
use relay_domain::{PrincipalId, SessionId};
use std::path::PathBuf;

proptest! {
    /// Strict JSON parser never panics on arbitrary string inputs
    #[test]
    fn prop_strict_json_parser_never_panics(s in "\\PC*") {
        let _ = parse_json_strictly(&s);
    }

    /// RFC 8785 JCS canonicalization is always deterministic for any valid JSON value
    #[test]
    fn prop_jcs_canonicalization_deterministic(
        num in any::<i64>(),
        string_val in "\\PC*",
        flag in any::<bool>(),
    ) {
        let val = serde_json::json!({
            "key1": num,
            "key2": string_val,
            "key3": flag,
            "nested": {
                "inner_num": num,
                "inner_bool": flag
            }
        });

        let bytes1 = canonicalize_value(&val).expect("valid JSON must canonicalize");
        let bytes2 = canonicalize_value(&val).expect("valid JSON must canonicalize");
        prop_assert_eq!(bytes1, bytes2);
    }

    /// Filesystem lexical normalizer never panics on arbitrary string inputs
    #[test]
    fn prop_fs_normalizer_never_panics(path_str in "\\PC*") {
        let normalizer = FilesystemNormalizer::new(PathBuf::from("/workspace"), false);
        let _ = normalizer.normalize_lexical(&path_str);
    }

    /// SQL AST normalizer never panics on arbitrary string inputs
    #[test]
    fn prop_sql_normalizer_never_panics(sql_str in "\\PC*") {
        let _ = SqlNormalizer::normalize(&sql_str);
    }

    /// GitHub normalizer never panics on arbitrary string inputs
    #[test]
    fn prop_github_normalizer_never_panics(repo_str in "\\PC*") {
        let _ = GitHubNormalizer::parse(&repo_str);
    }

    /// ActionCanonicalizer pipeline is deterministic: running twice yields identical ActionHash
    #[test]
    fn prop_action_canonicalizer_determinism(
        server in "[a-zA-Z0-9_-]{1,16}",
        namespace in "[a-zA-Z0-9_-]{1,16}",
        name in "[a-zA-Z0-9_-]{1,16}",
        arg_val in "\\PC*",
    ) {
        let canonicalizer = ActionCanonicalizer::new(PathBuf::from("/workspace"));
        let session = SessionId::new_v7();
        let principal = PrincipalId::new("principal:agent:worker1").unwrap();
        let tool = ToolIdentity::new(server, namespace, name);
        let args = serde_json::json!({ "param": arg_val });

        if let Ok(action1) = canonicalizer.canonicalize(
            session,
            principal.clone(),
            "tools/call",
            tool.clone(),
            &args,
            None,
            None,
        ) {
            let action2 = canonicalizer.canonicalize(
                session,
                principal,
                "tools/call",
                tool,
                &args,
                None,
                None,
            ).unwrap();

            prop_assert_eq!(action1.action_hash, action2.action_hash);
            prop_assert_eq!(action1.canonical_bytes, action2.canonical_bytes);
        }
    }
}
