pub mod coordinator;
pub mod fs;
pub mod github;
pub mod postgres;
pub mod registry;

pub use coordinator::{
    ExecutionTarget, GovernedActionError, GovernedActionRunner, GovernedActionRunnerBuilder,
    GovernedExecutionOutcome,
};
pub use fs::{
    FilesystemConnector, FsConnectorConfig, FsDirEntry, FsError, FsReadResult, FsStatResult,
    FsWriteResult, DEFAULT_MAX_DIR_ENTRIES, DEFAULT_MAX_PATH_LENGTH, DEFAULT_MAX_READ_BYTES,
    DEFAULT_MAX_WRITE_BYTES,
};
pub use github::{
    CreateBranchRequest, CreateIssueRequest, CreatePullRequestRequest, GitHubClient,
    GitHubClientConfig, GitHubConnector, GitHubError, GitHubOperation, IdempotencyClass,
};
pub use postgres::{
    PostgresClient, PostgresClientConfig, PostgresConnector, PostgresCredentials, PostgresError,
    PostgresResource, PostgresResponse,
};
pub use registry::ConnectorRegistry;
