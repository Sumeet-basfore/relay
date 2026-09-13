//! Native tool connectors for Relay (GitHub, PostgreSQL, Filesystem).
//!
//! Provides in-process governed tool execution for trusted native connectors.

pub mod github;
pub mod postgres;
pub mod registry;

pub use github::{
    CreateBranchRequest, CreateIssueRequest, CreatePullRequestRequest, GitHubClient,
    GitHubClientConfig, GitHubConnector, GitHubError, GitHubOperation, IdempotencyClass,
};
pub use postgres::{
    PostgresClient, PostgresClientConfig, PostgresConnector, PostgresCredentials, PostgresError,
    PostgresResource, PostgresResponse,
};
pub use registry::ConnectorRegistry;

use async_trait::async_trait;
use relay_domain::{ExecutionError, ExecutionResult, NativeConnector, SecretBuffer};

/// Filesystem native connector foundation stub (Milestone B010)
pub struct FilesystemConnector;

#[async_trait]
impl NativeConnector for FilesystemConnector {
    fn namespace(&self) -> &'static str {
        "fs"
    }

    async fn execute(
        &self,
        tool_name: &str,
        _canonical_args: &serde_json::Value,
        _secret: Option<&SecretBuffer>,
    ) -> Result<ExecutionResult, ExecutionError> {
        Ok(ExecutionResult::success(
            format!("fs.{} executed (foundation stub)", tool_name).as_bytes(),
            "Filesystem operation simulated",
        ))
    }
}
