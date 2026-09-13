//! Native GitHub connector module for Relay.

pub mod client;
pub mod connector;
pub mod error;
pub mod operations;

pub use client::{GitHubClient, GitHubClientConfig, GitHubResponse, DEFAULT_GITHUB_HOST};
pub use connector::GitHubConnector;
pub use error::GitHubError;
pub use operations::{
    CreateBranchRequest, CreateIssueRequest, CreatePullRequestRequest, GitHubOperation,
    IdempotencyClass,
};
