//! Security divergence test suite: proving that policy representation and execution
//! representation are strictly identical (SI-005) and cannot diverge.

use relay_canonical::{
    pin_tool_schema, ActionCanonicalizer, FilesystemNormalizer, GitHubNormalizer, SqlNormalizer,
    ToolIdentity,
};
use relay_domain::{ExecutionEnvironment, PrincipalId, SessionId};
use serde_json::json;
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_path_traversal_divergence_prevention() {
    let temp = tempdir().unwrap();
    let safe_file = temp.path().join("safe.txt");
    let mut f = File::create(&safe_file).unwrap();
    writeln!(f, "hello").unwrap();

    let normalizer = FilesystemNormalizer::new(temp.path(), false);

    // Path with redundant .. and .
    let complex_path = format!("{}/sub/.././safe.txt", temp.path().display());
    let direct_path = safe_file.to_string_lossy().to_string();

    let norm_complex = normalizer.resolve_path(&complex_path).unwrap();
    let norm_direct = normalizer.resolve_path(&direct_path).unwrap();

    // Both MUST produce identical canonical representations
    assert_eq!(norm_complex.canonical_path(), norm_direct.canonical_path());
    assert_eq!(
        norm_complex.to_resource_uri().unwrap(),
        norm_direct.to_resource_uri().unwrap()
    );
}

#[test]
#[cfg(unix)]
fn test_symlink_physical_target_resolution_prevents_divergence() {
    let temp = tempdir().unwrap();
    let real_file = temp.path().join("real_target.txt");
    let mut f = File::create(&real_file).unwrap();
    writeln!(f, "confidential").unwrap();

    let symlink = temp.path().join("alias_link.txt");
    std::os::unix::fs::symlink(&real_file, &symlink).unwrap();

    let normalizer = FilesystemNormalizer::new(temp.path(), false);

    let norm_symlink = normalizer.resolve_path(&symlink.to_string_lossy()).unwrap();
    let norm_real = normalizer
        .resolve_path(&real_file.to_string_lossy())
        .unwrap();

    // Canonical physical path of symlink must resolve to real physical target
    assert_eq!(norm_symlink.canonical_path(), norm_real.canonical_path());
    assert_eq!(
        norm_symlink.to_resource_uri().unwrap(),
        norm_real.to_resource_uri().unwrap()
    );
}

#[test]
fn test_sql_comment_injection_divergence_prevention() {
    let raw_clean = "SELECT id, email FROM users WHERE id = 1;";
    let raw_injected =
        "SELECT  id,  email  FROM  users  /* bypass */ WHERE  id = 1  -- trailing comment\n;";

    let norm_clean = SqlNormalizer::normalize(raw_clean).unwrap();
    let norm_injected = SqlNormalizer::normalize(raw_injected).unwrap();

    // AST-based canonical SQL must be byte-identical regardless of comments or whitespace
    assert_eq!(norm_clean.canonical_sql, norm_injected.canonical_sql);
    assert_eq!(norm_clean.tables, norm_injected.tables);
    assert_eq!(norm_clean.operation, norm_injected.operation);
    assert_eq!(norm_clean.is_destructive, norm_injected.is_destructive);
}

#[test]
fn test_github_alias_divergence_prevention() {
    let alias1 = "https://github.com/AcmeCorp/SecretRepo.git";
    let alias2 = "git@github.com:acmecorp/secretrepo.git";
    let alias3 = "acmecorp/secretrepo";

    let norm1 = GitHubNormalizer::parse(alias1).unwrap();
    let norm2 = GitHubNormalizer::parse(alias2).unwrap();
    let norm3 = GitHubNormalizer::parse(alias3).unwrap();

    assert_eq!(norm1.canonical_uri, norm2.canonical_uri);
    assert_eq!(norm2.canonical_uri, norm3.canonical_uri);
    assert_eq!(
        norm1.canonical_uri.as_str(),
        "github://github.com/acmecorp/secretrepo"
    );
}

#[test]
fn test_tool_server_spoofing_divergence_prevention() {
    let temp = tempdir().unwrap();
    let canonicalizer = ActionCanonicalizer::new(temp.path().to_path_buf());
    let session = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:worker1").unwrap();
    let args = json!({"path": "/workspace/file.txt"});

    let tool_server_a = ToolIdentity::new("server-alpha", "fs", "read_file");
    let tool_server_b = ToolIdentity::new("server-bravo", "fs", "read_file");

    let action_a = canonicalizer
        .canonicalize(
            session,
            principal.clone(),
            "tools/call",
            tool_server_a,
            &args,
            None,
            None,
        )
        .unwrap();

    let action_b = canonicalizer
        .canonicalize(
            session,
            principal,
            "tools/call",
            tool_server_b,
            &args,
            None,
            None,
        )
        .unwrap();

    // Different servers MUST produce distinct canonical tool identities and distinct ActionHashes
    assert_ne!(action_a.tool.canonical_id(), action_b.tool.canonical_id());
    assert_ne!(action_a.action_hash, action_b.action_hash);
    assert_ne!(action_a.canonical_bytes, action_b.canonical_bytes);
}

#[test]
fn test_schema_pinning_divergence_prevention() {
    let temp = tempdir().unwrap();
    let canonicalizer = ActionCanonicalizer::new(temp.path().to_path_buf());
    let session = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:worker1").unwrap();
    let tool = ToolIdentity::new("server1", "fs", "read_file");
    let args = json!({"path": "/workspace/file.txt"});

    let schema_v1 = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string" }
        }
    });

    let schema_v2 = json!({
        "type": "object",
        "properties": {
            "path": { "type": "string" },
            "dangerous_override": { "type": "boolean" }
        }
    });

    let pinned_v1 = pin_tool_schema(schema_v1).unwrap();
    let pinned_v2 = pin_tool_schema(schema_v2).unwrap();

    assert_ne!(pinned_v1.schema_digest, pinned_v2.schema_digest);

    let action_v1 = canonicalizer
        .canonicalize(
            session,
            principal.clone(),
            "tools/call",
            tool.clone(),
            &args,
            Some(&pinned_v1),
            None,
        )
        .unwrap();

    let action_v2 = canonicalizer
        .canonicalize(
            session,
            principal,
            "tools/call",
            tool,
            &args,
            Some(&pinned_v2),
            None,
        )
        .unwrap();

    // Changing schema changes the ActionHash, preventing schema substitution attacks
    assert_ne!(action_v1.action_hash, action_v2.action_hash);
    assert_ne!(action_v1.canonical_bytes, action_v2.canonical_bytes);
}

#[test]
fn test_action_hash_determinism_across_formatting() {
    let temp = tempdir().unwrap();
    let canonicalizer = ActionCanonicalizer::new(temp.path().to_path_buf());
    let session = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:worker1").unwrap();
    let tool = ToolIdentity::new("server1", "db", "query");
    let env = ExecutionEnvironment::new("/workspace", "linux", false);

    // Two raw arguments with different key order, spacing, and SQL comments
    let args1 = json!({
        "query": "SELECT  u.id,  u.email   FROM   Users u  WHERE u.id = 1",
        "database": "production",
        "host": "db.internal"
    });

    let args2 = json!({
        "host": "db.internal",
        "database": "production",
        "query": "SELECT u.id, u.email FROM Users u /* comment */ WHERE u.id = 1"
    });

    let action1 = canonicalizer
        .canonicalize(
            session,
            principal.clone(),
            "tools/call",
            tool.clone(),
            &args1,
            None,
            Some(env.clone()),
        )
        .unwrap();

    let action2 = canonicalizer
        .canonicalize(
            session,
            principal,
            "tools/call",
            tool,
            &args2,
            None,
            Some(env),
        )
        .unwrap();

    // Semantically equivalent actions MUST produce identical canonical arguments, bytes, and ActionHash!
    assert_eq!(action1.canonical_arguments, action2.canonical_arguments);
    assert_eq!(action1.canonical_bytes, action2.canonical_bytes);
    assert_eq!(action1.action_hash, action2.action_hash);
}
