//! Configuration and bounds for Relay Native Filesystem Connector (B010).

use std::path::{Path, PathBuf};

/// Default maximum size for file reads (10 MB).
pub const DEFAULT_MAX_READ_BYTES: u64 = 10 * 1024 * 1024;

/// Default maximum size for file writes (10 MB).
pub const DEFAULT_MAX_WRITE_BYTES: u64 = 10 * 1024 * 1024;

/// Default maximum directory entries returned in `list_directory` (1,000).
pub const DEFAULT_MAX_DIR_ENTRIES: usize = 1_000;

/// Default maximum path length (4,096 bytes).
pub const DEFAULT_MAX_PATH_LENGTH: usize = 4_096;

/// Configuration for Filesystem Connector.
#[derive(Debug, Clone)]
pub struct FsConnectorConfig {
    /// The mandatory root jail directory. All operations must resolve within this root.
    pub root_dir: PathBuf,
    /// Maximum bytes allowed in a single read operation.
    pub max_read_bytes: u64,
    /// Maximum bytes allowed in a single write operation.
    pub max_write_bytes: u64,
    /// Maximum entries returned when listing a directory.
    pub max_dir_entries: usize,
    /// Whether symlinks pointing within the root are followed (default: false for maximum safety).
    pub follow_symlinks: bool,
}

impl FsConnectorConfig {
    /// Creates a configuration with standard production limits pinned to a root directory.
    pub fn new(root_dir: impl AsRef<Path>) -> Self {
        let root_dir = std::fs::canonicalize(root_dir.as_ref())
            .unwrap_or_else(|_| root_dir.as_ref().to_path_buf());
        Self {
            root_dir,
            max_read_bytes: DEFAULT_MAX_READ_BYTES,
            max_write_bytes: DEFAULT_MAX_WRITE_BYTES,
            max_dir_entries: DEFAULT_MAX_DIR_ENTRIES,
            follow_symlinks: false,
        }
    }

    /// Sets whether internal symlinks within the root are permitted to be followed.
    pub fn with_follow_symlinks(mut self, follow: bool) -> Self {
        self.follow_symlinks = follow;
        self
    }
}
