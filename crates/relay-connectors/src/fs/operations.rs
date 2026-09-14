//! Core bounded filesystem operations for Relay Native Filesystem Connector.
//!
//! Supported MVP operations:
//! - Read: read_file, list_directory, stat
//! - Write: create_file, write_file (atomic temp+rename), append_file, create_directory
//! - Destructive: delete_file, remove_directory (non-recursive only)

use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use super::config::FsConnectorConfig;
use super::error::FsError;

/// Metadata information returned by `stat`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsStatResult {
    pub path: String,
    pub is_file: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size_bytes: u64,
    pub modified_unix_secs: Option<u64>,
    pub readonly: bool,
}

/// Directory entry item returned by `list_directory`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsDirEntry {
    pub name: String,
    pub is_file: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size_bytes: u64,
}

/// Result of a file read operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsReadResult {
    pub path: String,
    pub size_bytes: usize,
    pub content: String,
}

/// Result of a file write or mutation operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsWriteResult {
    pub path: String,
    pub bytes_written: usize,
    pub sha256_digest: String,
}

/// Bounded file read. Rejects files larger than `config.max_read_bytes`.
pub fn read_file(config: &FsConnectorConfig, path: &Path) -> Result<FsReadResult, FsError> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| FsError::IoError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    if meta.is_dir() {
        return Err(FsError::UnsupportedOperation(format!(
            "Cannot read directory '{}' as a file; use list_directory",
            path.display()
        )));
    }

    let file_len = meta.len();
    if file_len > config.max_read_bytes {
        return Err(FsError::FileTooLarge {
            size: file_len,
            limit: config.max_read_bytes,
        });
    }

    let file = File::open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => FsError::NotFound(path.display().to_string()),
        std::io::ErrorKind::PermissionDenied => FsError::PermissionDenied {
            path: path.display().to_string(),
            reason: e.to_string(),
        },
        _ => FsError::IoError {
            path: path.display().to_string(),
            reason: e.to_string(),
        },
    })?;

    let mut buf = Vec::with_capacity(file_len as usize);
    file.take(config.max_read_bytes + 1)
        .read_to_end(&mut buf)
        .map_err(|e| FsError::IoError {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

    if buf.len() as u64 > config.max_read_bytes {
        return Err(FsError::FileTooLarge {
            size: buf.len() as u64,
            limit: config.max_read_bytes,
        });
    }

    let content = String::from_utf8_lossy(&buf).to_string();
    let size_bytes = buf.len();

    Ok(FsReadResult {
        path: path.display().to_string(),
        size_bytes,
        content,
    })
}

/// Bounded directory listing. Rejects directories containing more than `config.max_dir_entries`.
pub fn list_directory(config: &FsConnectorConfig, path: &Path) -> Result<Vec<FsDirEntry>, FsError> {
    let read_dir = std::fs::read_dir(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => FsError::NotFound(path.display().to_string()),
        std::io::ErrorKind::PermissionDenied => FsError::PermissionDenied {
            path: path.display().to_string(),
            reason: e.to_string(),
        },
        _ => FsError::IoError {
            path: path.display().to_string(),
            reason: e.to_string(),
        },
    })?;

    let mut entries = Vec::new();
    for item in read_dir {
        let entry = item.map_err(|e| FsError::IoError {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

        if entries.len() >= config.max_dir_entries {
            return Err(FsError::DirectoryEntryLimitExceeded {
                count: entries.len() + 1,
                limit: config.max_dir_entries,
            });
        }

        let file_name = entry.file_name().to_string_lossy().to_string();
        let meta = entry.metadata().ok();
        let is_file = meta.as_ref().map(|m| m.is_file()).unwrap_or(false);
        let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        let is_symlink = meta
            .as_ref()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        let size_bytes = meta.as_ref().map(|m| m.len()).unwrap_or(0);

        entries.push(FsDirEntry {
            name: file_name,
            is_file,
            is_dir,
            is_symlink,
            size_bytes,
        });
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Retrieves file or directory metadata.
pub fn stat_metadata(_config: &FsConnectorConfig, path: &Path) -> Result<FsStatResult, FsError> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => FsError::NotFound(path.display().to_string()),
        std::io::ErrorKind::PermissionDenied => FsError::PermissionDenied {
            path: path.display().to_string(),
            reason: e.to_string(),
        },
        _ => FsError::IoError {
            path: path.display().to_string(),
            reason: e.to_string(),
        },
    })?;

    let modified_unix_secs = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());

    Ok(FsStatResult {
        path: path.display().to_string(),
        is_file: meta.is_file(),
        is_dir: meta.is_dir(),
        is_symlink: meta.file_type().is_symlink(),
        size_bytes: meta.len(),
        modified_unix_secs,
        readonly: meta.permissions().readonly(),
    })
}

/// Atomic file write using a temporary sibling file and atomic rename.
pub fn write_file_atomic(
    config: &FsConnectorConfig,
    path: &Path,
    data: &[u8],
) -> Result<FsWriteResult, FsError> {
    if data.len() as u64 > config.max_write_bytes {
        return Err(FsError::FileTooLarge {
            size: data.len() as u64,
            limit: config.max_write_bytes,
        });
    }

    let parent = path.parent().ok_or_else(|| FsError::IoError {
        path: path.display().to_string(),
        reason: "No parent directory found for write target".to_string(),
    })?;

    if !parent.exists() {
        std::fs::create_dir_all(parent).map_err(|e| FsError::IoError {
            path: parent.display().to_string(),
            reason: e.to_string(),
        })?;
    }

    let file_stem = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp_path = parent.join(format!(".tmp.{}.{}", file_stem, uuid::Uuid::now_v7()));

    // Write to temp file
    let mut tmp_file = File::create(&tmp_path).map_err(|e| FsError::IoError {
        path: tmp_path.display().to_string(),
        reason: e.to_string(),
    })?;

    if let Err(e) = tmp_file.write_all(data) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(FsError::IoError {
            path: path.display().to_string(),
            reason: format!("Failed writing data to temporary file: {e}"),
        });
    }

    if let Err(e) = tmp_file.sync_data() {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(FsError::IoError {
            path: path.display().to_string(),
            reason: format!("Failed to fsync data to temporary file: {e}"),
        });
    }
    drop(tmp_file);

    // Atomic rename
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(FsError::IoError {
            path: path.display().to_string(),
            reason: format!("Atomic rename failed: {e}"),
        });
    }

    let sha256_digest = hex::encode(sha2::Sha256::digest(data));
    Ok(FsWriteResult {
        path: path.display().to_string(),
        bytes_written: data.len(),
        sha256_digest,
    })
}

/// Appends bytes to an existing or newly created file.
pub fn append_file(
    config: &FsConnectorConfig,
    path: &Path,
    data: &[u8],
) -> Result<FsWriteResult, FsError> {
    if data.len() as u64 > config.max_write_bytes {
        return Err(FsError::FileTooLarge {
            size: data.len() as u64,
            limit: config.max_write_bytes,
        });
    }

    if !path.exists() {
        return Err(FsError::NotFound(path.display().to_string()));
    }

    let mut file = std::fs::OpenOptions::new()
        .create(false)
        .append(true)
        .open(path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => FsError::NotFound(path.display().to_string()),
            std::io::ErrorKind::PermissionDenied => FsError::PermissionDenied {
                path: path.display().to_string(),
                reason: e.to_string(),
            },
            _ => FsError::IoError {
                path: path.display().to_string(),
                reason: e.to_string(),
            },
        })?;

    if let Err(e) = file.write_all(data) {
        return Err(FsError::AmbiguousMutationOutcome {
            operation: "append_file".to_string(),
            path: path.display().to_string(),
            reason: format!("Partial append failure: {e}"),
        });
    }

    let sha256_digest = hex::encode(sha2::Sha256::digest(data));
    Ok(FsWriteResult {
        path: path.display().to_string(),
        bytes_written: data.len(),
        sha256_digest,
    })
}

/// Creates a new directory.
pub fn create_directory(_config: &FsConnectorConfig, path: &Path) -> Result<(), FsError> {
    std::fs::create_dir_all(path).map_err(|e| FsError::IoError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })
}

/// Deletes a file. Rejects directory deletion through `delete_file`.
pub fn delete_file(_config: &FsConnectorConfig, path: &Path) -> Result<(), FsError> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => FsError::NotFound(path.display().to_string()),
        std::io::ErrorKind::PermissionDenied => FsError::PermissionDenied {
            path: path.display().to_string(),
            reason: e.to_string(),
        },
        _ => FsError::IoError {
            path: path.display().to_string(),
            reason: e.to_string(),
        },
    })?;

    if meta.is_dir() {
        return Err(FsError::UnsupportedOperation(format!(
            "Cannot delete directory '{}' using delete_file; use remove_directory",
            path.display()
        )));
    }

    std::fs::remove_file(path).map_err(|e| FsError::IoError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })
}

/// Deletes an empty directory. Recursive directory deletion is explicitly rejected in MVP.
pub fn remove_directory(_config: &FsConnectorConfig, path: &Path) -> Result<(), FsError> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => FsError::NotFound(path.display().to_string()),
        _ => FsError::IoError {
            path: path.display().to_string(),
            reason: e.to_string(),
        },
    })?;

    if !meta.is_dir() {
        return Err(FsError::UnsupportedOperation(format!(
            "Path '{}' is not a directory",
            path.display()
        )));
    }

    std::fs::remove_dir(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::DirectoryNotEmpty => FsError::UnsupportedOperation(format!(
            "Directory '{}' is not empty; recursive directory deletion is rejected",
            path.display()
        )),
        _ => FsError::IoError {
            path: path.display().to_string(),
            reason: e.to_string(),
        },
    })
}
