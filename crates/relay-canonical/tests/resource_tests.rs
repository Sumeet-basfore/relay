//! Comprehensive tests for filesystem, SQL, and GitHub resource normalizers.

use relay_canonical::{
    FilesystemNormalizer, GitHubNormalizer, GitHubSubResource, SqlNormalizer, SqlOperation,
};
use relay_domain::CanonicalizationError;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_fs_lexical_normalization() {
    let temp = tempdir().unwrap();
    let normalizer = FilesystemNormalizer::new(temp.path(), false);

    let norm = normalizer
        .normalize_lexical("foo/./bar/../baz//qux")
        .expect("normalize");
    assert!(norm.to_string_lossy().ends_with("foo/baz/qux"));

    // Backslashes
    let norm_win = normalizer
        .normalize_lexical("foo\\bar\\baz")
        .expect("normalize");
    assert!(norm_win.to_string_lossy().ends_with("foo/bar/baz"));
}

#[test]
fn test_fs_boundary_traversal_rejection() {
    let temp = tempdir().unwrap();
    let normalizer = FilesystemNormalizer::new(temp.path(), true);

    let err = normalizer
        .normalize_lexical("../../etc/passwd")
        .expect_err("must reject traversal outside base");
    assert!(matches!(err, CanonicalizationError::PathTraversal { .. }));
}

#[test]
fn test_fs_non_existent_path_ancestor_resolution() {
    let temp = tempdir().unwrap();
    let existing_sub = temp.path().join("existing_dir");
    fs::create_dir(&existing_sub).unwrap();

    let normalizer = FilesystemNormalizer::new(temp.path(), false);
    let target = existing_sub.join("new_subdir").join("file.txt");

    let result = normalizer
        .resolve_path(&target.to_string_lossy())
        .expect("resolve non-existent path");

    assert!(!result.is_existing);
    assert!(result.physical_path.is_some());
    assert!(result
        .physical_path
        .unwrap()
        .ends_with("existing_dir/new_subdir/file.txt"));
}

#[test]
#[cfg(unix)]
fn test_fs_dangling_symlink_rejection() {
    let temp = tempdir().unwrap();
    let broken_target = temp.path().join("does_not_exist");
    let link = temp.path().join("broken_link");
    std::os::unix::fs::symlink(&broken_target, &link).unwrap();

    let normalizer = FilesystemNormalizer::new(temp.path(), false);
    let err = normalizer
        .resolve_path(&link.to_string_lossy())
        .expect_err("must detect dangling symlink");

    match err {
        CanonicalizationError::DanglingSymlink { path } => {
            assert!(path.contains("broken_link"));
        }
        other => panic!("expected DanglingSymlink, got: {other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn test_fs_symlink_cycle_rejection() {
    let temp = tempdir().unwrap();
    let link_a = temp.path().join("link_a");
    let link_b = temp.path().join("link_b");

    std::os::unix::fs::symlink(&link_b, &link_a).unwrap();
    std::os::unix::fs::symlink(&link_a, &link_b).unwrap();

    let normalizer = FilesystemNormalizer::new(temp.path(), false);
    let err = normalizer
        .resolve_path(&link_a.to_string_lossy())
        .expect_err("must detect symlink cycle");

    match err {
        CanonicalizationError::SymlinkCycle { path } => {
            assert!(path.contains("link_a") || path.contains("link_b"));
        }
        other => panic!("expected SymlinkCycle, got: {other:?}"),
    }
}

#[test]
fn test_sql_ast_select_and_comment_stripping() {
    let raw_sql = r#"
        -- Querying users table with sensitive comment
        SELECT  u.id,  u.email   FROM   Users u /* inline comment */
        JOIN  Public.Orders o  ON  u.id = o.user_id
        WHERE u.active = true
    "#;

    let norm = SqlNormalizer::normalize(raw_sql).expect("normalize sql");
    assert_eq!(norm.operation, SqlOperation::Select);
    assert!(!norm.is_destructive);
    // Comments must be completely stripped
    assert!(!norm.canonical_sql.contains("sensitive comment"));
    assert!(!norm.canonical_sql.contains("inline comment"));
    // Unquoted table identifiers lowercased and sorted
    assert_eq!(norm.tables, vec!["public.orders", "users"]);
}

#[test]
fn test_sql_multi_statement_rejection() {
    let raw_sql = "SELECT * FROM users; DROP TABLE accounts;";
    let err = SqlNormalizer::normalize(raw_sql).expect_err("must reject multi-statement SQL");

    match err {
        CanonicalizationError::MultiStatementSqlNotAllowed { count } => {
            assert_eq!(count, 2);
        }
        other => panic!("expected MultiStatementSqlNotAllowed, got: {other:?}"),
    }
}

#[test]
fn test_sql_destructive_operations_detection() {
    // DROP TABLE
    let drop_norm = SqlNormalizer::normalize("DROP TABLE users;").unwrap();
    assert_eq!(drop_norm.operation, SqlOperation::Ddl);
    assert!(drop_norm.is_destructive);

    // TRUNCATE TABLE
    let trunc_norm = SqlNormalizer::normalize("TRUNCATE TABLE users;").unwrap();
    assert_eq!(trunc_norm.operation, SqlOperation::Ddl);
    assert!(trunc_norm.is_destructive);

    // DELETE without WHERE (destructive)
    let del_all = SqlNormalizer::normalize("DELETE FROM users;").unwrap();
    assert_eq!(del_all.operation, SqlOperation::Delete);
    assert!(del_all.is_destructive);

    // DELETE with WHERE (non-destructive bulk drop)
    let del_where = SqlNormalizer::normalize("DELETE FROM users WHERE id = 1;").unwrap();
    assert_eq!(del_where.operation, SqlOperation::Delete);
    assert!(!del_where.is_destructive);

    // UPDATE without WHERE (destructive)
    let upd_all = SqlNormalizer::normalize("UPDATE users SET active = false;").unwrap();
    assert_eq!(upd_all.operation, SqlOperation::Update);
    assert!(upd_all.is_destructive);
}

#[test]
fn test_sql_quoted_identifiers_case_preservation() {
    let sql = r#"SELECT * FROM "SensitiveData" JOIN normal_table ON 1=1"#;
    let norm = SqlNormalizer::normalize(sql).unwrap();
    assert_eq!(norm.tables, vec!["\"SensitiveData\"", "normal_table"]);
}

#[test]
fn test_github_resource_normalization() {
    // HTTPS URL
    let res1 = GitHubNormalizer::parse("https://github.com/Relay-Security/Relay.git").unwrap();
    assert_eq!(res1.owner, "relay-security");
    assert_eq!(res1.repo, "relay");
    assert_eq!(
        res1.canonical_uri.as_str(),
        "github://github.com/relay-security/relay"
    );

    // SSH format
    let res2 = GitHubNormalizer::parse("git@github.com:Relay-Security/Relay.git").unwrap();
    assert_eq!(res2.canonical_uri, res1.canonical_uri);

    // Shorthand format
    let res3 = GitHubNormalizer::parse("relay-security/relay").unwrap();
    assert_eq!(res3.canonical_uri, res1.canonical_uri);

    // Pull request
    let pr = GitHubNormalizer::parse("https://github.com/owner/repo/pull/123").unwrap();
    assert_eq!(pr.sub_resource, Some(GitHubSubResource::PullRequest(123)));
    assert_eq!(
        pr.canonical_uri.as_str(),
        "github://github.com/owner/repo/pull/123"
    );

    // Issue shorthand
    let issue = GitHubNormalizer::parse("owner/repo#456").unwrap();
    assert_eq!(issue.sub_resource, Some(GitHubSubResource::Issue(456)));
    assert_eq!(
        issue.canonical_uri.as_str(),
        "github://github.com/owner/repo/issues/456"
    );
}

#[test]
fn test_github_path_traversal_rejection() {
    let err =
        GitHubNormalizer::parse("owner/../malicious/repo").expect_err("must reject traversal");
    assert!(matches!(err, CanonicalizationError::InvalidResource(..)));
}
