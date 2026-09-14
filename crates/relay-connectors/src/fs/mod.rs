//! Native Filesystem connector module for Relay (Milestone B010).

pub mod config;
pub mod connector;
pub mod error;
pub mod jail;
pub mod operations;

pub use config::{
    FsConnectorConfig, DEFAULT_MAX_DIR_ENTRIES, DEFAULT_MAX_PATH_LENGTH, DEFAULT_MAX_READ_BYTES,
    DEFAULT_MAX_WRITE_BYTES,
};
pub use connector::FilesystemConnector;
pub use error::FsError;
pub use jail::{
    lexical_normalize, resolve_and_verify_within_root, validate_prohibited_system_paths,
};
pub use operations::{
    append_file, create_directory, delete_file, list_directory, read_file, remove_directory,
    stat_metadata, write_file_atomic, FsDirEntry, FsReadResult, FsStatResult, FsWriteResult,
};
