//! Performance characterization tests measuring execution durations.

use relay_canonical::{
    ActionCanonicalizer, FilesystemNormalizer, GitHubNormalizer, SqlNormalizer, ToolIdentity,
};
use relay_domain::{PrincipalId, SessionId};
use serde_json::json;
use std::path::PathBuf;
use std::time::Instant;

#[test]
fn test_performance_characterization() {
    let base_dir = PathBuf::from("/workspace");
    let canonicalizer = ActionCanonicalizer::new(base_dir.clone());
    let session = SessionId::new_v7();
    let principal = PrincipalId::new("principal:agent:bench").unwrap();
    let fs_normalizer = FilesystemNormalizer::new(base_dir, false);

    // 1. Small JSON action
    let small_args = json!({ "path": "/workspace/data.csv" });
    let tool = ToolIdentity::new("srv", "fs", "read");
    let iterations = 1000;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = canonicalizer
            .canonicalize(
                session,
                principal.clone(),
                "tools/call",
                tool.clone(),
                &small_args,
                None,
                None,
            )
            .unwrap();
    }
    let small_json_duration = start.elapsed() / iterations;

    // 2. Large JSON action (100 items)
    let mut large_map = serde_json::Map::new();
    large_map.insert("path".to_string(), json!("/workspace/file.txt"));
    for i in 0..100 {
        large_map.insert(format!("key_{i}"), json!(format!("value_{i}")));
    }
    let large_args = serde_json::Value::Object(large_map);
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = canonicalizer
            .canonicalize(
                session,
                principal.clone(),
                "tools/call",
                tool.clone(),
                &large_args,
                None,
                None,
            )
            .unwrap();
    }
    let large_json_duration = start.elapsed() / iterations;

    // 3. Typical SQL statement
    let typical_sql =
        "SELECT id, name, email FROM users WHERE active = true ORDER BY created_at DESC LIMIT 10;";
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = SqlNormalizer::normalize(typical_sql).unwrap();
    }
    let typical_sql_duration = start.elapsed() / iterations;

    // 4. Large SQL statement (multi-join complex query)
    let large_sql = r#"
        SELECT u.id, u.email, o.order_id, p.product_name, c.category_name, SUM(oi.price * oi.quantity) as total
        FROM Users u
        JOIN Orders o ON u.id = o.user_id
        JOIN Order_Items oi ON o.order_id = oi.order_id
        JOIN Products p ON oi.product_id = p.id
        JOIN Categories c ON p.category_id = c.id
        WHERE o.status = 'COMPLETED' AND o.created_at >= '2026-01-01'
        GROUP BY u.id, u.email, o.order_id, p.product_name, c.category_name
        HAVING SUM(oi.price * oi.quantity) > 1000
        ORDER BY total DESC;
    "#;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = SqlNormalizer::normalize(large_sql).unwrap();
    }
    let large_sql_duration = start.elapsed() / iterations;

    // 5. Filesystem lexical normalization
    let complex_path = "project/nested/../../workspace/subdir/./file.txt";
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = fs_normalizer.normalize_lexical(complex_path).unwrap();
    }
    let fs_norm_duration = start.elapsed() / iterations;

    // 6. GitHub resource normalization
    let gh_url = "https://github.com/Relay-Security/Relay/pull/123";
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = GitHubNormalizer::parse(gh_url).unwrap();
    }
    let gh_norm_duration = start.elapsed() / iterations;

    println!("\n=== B003 Performance Characterization (avg per operation) ===");
    println!(
        "Small JSON action canonicalization: {:?}",
        small_json_duration
    );
    println!(
        "Large JSON action (100 keys) canonicalization: {:?}",
        large_json_duration
    );
    println!("Typical SQL normalization: {:?}", typical_sql_duration);
    println!(
        "Large multi-join SQL normalization: {:?}",
        large_sql_duration
    );
    println!("Filesystem lexical normalization: {:?}", fs_norm_duration);
    println!("GitHub resource normalization: {:?}", gh_norm_duration);
    println!("============================================================\n");
}
