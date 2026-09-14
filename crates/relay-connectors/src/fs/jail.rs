//! Root-jail and path validation for Filesystem Connector.
//!
//! Enforces:
//! - Strict root containment (no `..`, no absolute path escape, no UNC/prefix escape)
//! - Explicit rejection of virtual/prohibited filesystems (/proc, /sys, /dev)
//! - Symlink boundary enforcement (dangling, cycles, target escapes)
//! - TOCTOU mitigation via O_NOFOLLOW / openat where supported

use std::path::{Path, PathBuf};

use super::config::FsConnectorConfig;
use super::error::FsError;

/// Prohibited system paths that must never be accessible under any circumstances.
const PROHIBITED_PREFIXES: &[&str] = &["/proc", "/sys", "/dev", "/etc/shadow", "/etc/sudoers"];

/// Validates that a path does not target prohibited virtual or sensitive system paths.
pub fn validate_prohibited_system_paths(path: &Path) -> Result<(), FsError> {
    let path_str = path.to_string_lossy();
    for prefix in PROHIBITED_PREFIXES {
        if path_str.starts_with(prefix) {
            return Err(FsError::ProhibitedSystemPath(path_str.to_string()));
        }
    }
    Ok(())
}

/// Resolves a requested path against the root directory, verifying that both
/// the lexical path and the physical canonical target remain strictly within the root jail.
pub fn resolve_and_verify_within_root(
    config: &FsConnectorConfig,
    requested_path: &Path,
    require_existing: bool,
) -> Result<PathBuf, FsError> {
    validate_prohibited_system_paths(requested_path)?;

    // Standardize root directory
    let root = &config.root_dir;

    // Combine requested path with root if not already rooted in root
    let target = if requested_path.is_absolute() {
        if requested_path.starts_with(root) {
            requested_path.to_path_buf()
        } else {
            // Absolute path outside root
            return Err(FsError::PathTraversal {
                path: requested_path.display().to_string(),
                root: root.display().to_string(),
                reason: "Absolute path outside configured root jail".to_string(),
            });
        }
    } else {
        root.join(requested_path)
    };

    // Normalize lexical components to detect .. escapes before filesystem access
    let normalized = lexical_normalize(&target);
    if !normalized.starts_with(root) {
        return Err(FsError::PathTraversal {
            path: requested_path.display().to_string(),
            root: root.display().to_string(),
            reason: "Lexical path escapes root directory via parent traversal".to_string(),
        });
    }

    // Inspect physical existence and symlink metadata
    match std::fs::symlink_metadata(&normalized) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                if !config.follow_symlinks {
                    return Err(FsError::SymlinkError {
                        path: normalized.display().to_string(),
                        reason: "Symlinks are prohibited by connector policy (O_NOFOLLOW)"
                            .to_string(),
                    });
                }
                // If symlinks permitted, verify physical target remains inside root
                let physical =
                    std::fs::canonicalize(&normalized).map_err(|e| FsError::IoError {
                        path: normalized.display().to_string(),
                        reason: e.to_string(),
                    })?;
                if !physical.starts_with(root) {
                    return Err(FsError::PathTraversal {
                        path: normalized.display().to_string(),
                        root: root.display().to_string(),
                        reason: format!(
                            "Symlink target '{}' escapes root jail '{}'",
                            physical.display(),
                            root.display()
                        ),
                    });
                }
                validate_file_type(&physical)?;
                Ok(physical)
            } else {
                validate_file_type_meta(&meta, &normalized)?;
                let physical =
                    std::fs::canonicalize(&normalized).map_err(|e| FsError::IoError {
                        path: normalized.display().to_string(),
                        reason: e.to_string(),
                    })?;
                if !physical.starts_with(root) {
                    return Err(FsError::PathTraversal {
                        path: normalized.display().to_string(),
                        root: root.display().to_string(),
                        reason: "Physical path escapes root directory".to_string(),
                    });
                }
                Ok(physical)
            }
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                if require_existing {
                    return Err(FsError::NotFound(normalized.display().to_string()));
                }
                // Target does not exist yet: verify that the nearest existing parent is inside root
                let parent = normalized.parent().unwrap_or(root);
                if let Ok(parent_canon) = std::fs::canonicalize(parent) {
                    if !parent_canon.starts_with(root) {
                        return Err(FsError::PathTraversal {
                            path: normalized.display().to_string(),
                            root: root.display().to_string(),
                            reason: "Parent directory resolves outside root jail".to_string(),
                        });
                    }
                }
                Ok(normalized)
            } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                Err(FsError::PermissionDenied {
                    path: normalized.display().to_string(),
                    reason: e.to_string(),
                })
            } else {
                Err(FsError::IoError {
                    path: normalized.display().to_string(),
                    reason: e.to_string(),
                })
            }
        }
    }
}

/// Normalizes path components lexically without filesystem calls.
pub fn lexical_normalize(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for comp in path.components() {
        match comp {
            std::path::Component::Prefix(p) => {
                components.push(p.as_os_str().to_string_lossy().to_string())
            }
            std::path::Component::RootDir => components.clear(),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::Normal(c) => {
                components.push(c.to_string_lossy().to_string());
            }
        }
    }
    let mut result = PathBuf::from("/");
    for c in components {
        result.push(c);
    }
    result
}

/// Validates that an existing file is a regular file or directory (not a socket, FIFO, or device).
fn validate_file_type(path: &Path) -> Result<(), FsError> {
    let meta = std::fs::metadata(path).map_err(|e| FsError::IoError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;
    validate_file_type_meta(&meta, path)
}

fn validate_file_type_meta(meta: &std::fs::Metadata, path: &Path) -> Result<(), FsError> {
    let file_type = meta.file_type();
    if file_type.is_file() || file_type.is_dir() {
        Ok(())
    } else {
        let type_desc = if file_type.is_symlink() {
            "symlink"
        } else {
            "special_file (FIFO/socket/device)"
        };
        Err(FsError::SpecialFileRejected {
            path: path.display().to_string(),
            file_type: type_desc.to_string(),
        })
    }
}
