//! Unit tests for Filesystem connector root-jail, operations, and error boundaries.

use relay_connectors::fs::{
    lexical_normalize, resolve_and_verify_within_root, validate_prohibited_system_paths,
    FsConnectorConfig, FsError,
};
use std::path::{Path, PathBuf};
use tempfile::tempdir;

#[test]
fn test_lexical_normalization() {
    assert_eq!(
        lexical_normalize(Path::new("/workspace/project/../project/src/./main.rs")),
        PathBuf::from("/workspace/project/src/main.rs")
    );
    assert_eq!(
        lexical_normalize(Path::new("/workspace/project/../../../../etc/passwd")),
        PathBuf::from("/etc/passwd")
    );
}

#[test]
fn test_prohibited_system_paths() {
    assert!(validate_prohibited_system_paths(Path::new("/proc/self/cmdline")).is_err());
    assert!(validate_prohibited_system_paths(Path::new("/sys/kernel/debug")).is_err());
    assert!(validate_prohibited_system_paths(Path::new("/dev/urandom")).is_err());
    assert!(validate_prohibited_system_paths(Path::new("/workspace/project/file.txt")).is_ok());
}

#[test]
fn test_root_jail_prevents_escape() {
    let tmp = tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let cfg = FsConnectorConfig::new(&root);

    // Inside root
    let inside = root.join("safe.txt");
    std::fs::write(&inside, b"safe").unwrap();
    assert!(resolve_and_verify_within_root(&cfg, &inside, true).is_ok());

    // Relative traversal escape
    let escape = Path::new("../outside.txt");
    assert!(resolve_and_verify_within_root(&cfg, escape, false).is_err());

    // Absolute path escape
    let abs_escape = Path::new("/etc/passwd");
    assert!(resolve_and_verify_within_root(&cfg, abs_escape, false).is_err());
}

#[test]
fn test_symlink_rejection_by_default() {
    let tmp = tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let cfg = FsConnectorConfig::new(&root);

    let real_file = root.join("target.txt");
    std::fs::write(&real_file, b"content").unwrap();

    let link_file = root.join("link.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_file, &link_file).unwrap();

    #[cfg(unix)]
    {
        // By default, follow_symlinks is false -> rejects
        let res = resolve_and_verify_within_root(&cfg, &link_file, true);
        assert!(matches!(res, Err(FsError::SymlinkError { .. })));
    }
}

#[test]
fn test_basic_crud_operations() {
    let tmp = tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let cfg = FsConnectorConfig::new(&root);

    // 1. Write file
    let file_path = root.join("test.txt");
    let write_res =
        relay_connectors::fs::operations::write_file_atomic(&cfg, &file_path, b"hello world")
            .unwrap();
    assert_eq!(write_res.bytes_written, 11);

    // 2. Stat metadata
    let stat = relay_connectors::fs::operations::stat_metadata(&cfg, &file_path).unwrap();
    assert!(stat.is_file);
    assert_eq!(stat.size_bytes, 11);

    // 3. Read file
    let read_res = relay_connectors::fs::operations::read_file(&cfg, &file_path).unwrap();
    assert_eq!(read_res.content, "hello world");

    // 4. Append
    let app_res =
        relay_connectors::fs::operations::append_file(&cfg, &file_path, b" again").unwrap();
    assert_eq!(app_res.bytes_written, 6);
    let read_res2 = relay_connectors::fs::operations::read_file(&cfg, &file_path).unwrap();
    assert_eq!(read_res2.content, "hello world again");

    // 5. List directory
    let entries = relay_connectors::fs::operations::list_directory(&cfg, &root).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "test.txt");

    // 6. Delete file
    relay_connectors::fs::operations::delete_file(&cfg, &file_path).unwrap();
    assert!(!file_path.exists());
}

#[test]
fn test_file_size_limit_rejection() {
    let tmp = tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let mut cfg = FsConnectorConfig::new(&root);
    cfg.max_read_bytes = 10;
    cfg.max_write_bytes = 10;

    let file_path = root.join("large.txt");
    let err = relay_connectors::fs::operations::write_file_atomic(
        &cfg,
        &file_path,
        b"01234567890123456789",
    )
    .unwrap_err();
    assert!(matches!(err, FsError::FileTooLarge { .. }));
}
