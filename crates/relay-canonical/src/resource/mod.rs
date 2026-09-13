//! Domain-specific resource normalizers and resolver implementations.

pub mod fs;
pub mod github;
pub mod resolver;
pub mod sql;

pub use fs::{FilesystemNormalizer, NormalizedPath};
pub use github::{GitHubNormalizer, GitHubSubResource, NormalizedGitHubResource};
pub use resolver::DefaultResourceResolver;
pub use sql::{NormalizedSql, SqlNormalizer, SqlOperation};
