//! Strongly typed GitHub operations and request models.
//!
//! Enforces:
//! - Strict schema validation (`deny_unknown_fields`)
//! - Explicit idempotency classification (no automatic retries on mutating requests)
//! - Sub-resource correlation between canonical ResourceUri and operation arguments
//! - Prevention of arbitrary HTTP request passthrough

use reqwest::Method;
use serde::{Deserialize, Serialize};

use super::error::GitHubError;
use relay_canonical::{CanonicalAction, GitHubSubResource};

/// Idempotency classification for network requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdempotencyClass {
    /// Safe to retry automatically upon transient network timeout or connection reset.
    SafeToRetry,
    /// Must NEVER be retried automatically; retrying risks duplicate issues, commits, or comments.
    NotSafeToRetry,
    /// May be retried only if server response or state allows safe re-submission.
    ConditionallyRetryable,
    /// Idempotency properties unknown.
    Unknown,
}

/// Request body for creating an issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateIssueRequest {
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assignees: Vec<String>,
}

/// Request body for creating a pull request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePullRequestRequest {
    pub title: String,
    pub head: String,
    pub base: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<bool>,
}

/// Request body for creating a branch / git reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBranchRequest {
    /// Full git reference, e.g. "refs/heads/feature-branch"
    #[serde(rename = "ref")]
    pub ref_name: String,
    /// The 40-character SHA-1 commit hash of the base commit
    pub sha: String,
}

/// Strongly typed, bounded set of supported GitHub operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitHubOperation {
    /// Read repository metadata: GET /repos/{owner}/{repo}
    GetRepository,
    /// Read pull request: GET /repos/{owner}/{repo}/pulls/{pull_number}
    GetPullRequest { pull_number: u64 },
    /// Read issue: GET /repos/{owner}/{repo}/issues/{issue_number}
    GetIssue { issue_number: u64 },
    /// Read branch info: GET /repos/{owner}/{repo}/branches/{branch}
    GetBranch { branch: String },
    /// Create issue: POST /repos/{owner}/{repo}/issues
    CreateIssue(CreateIssueRequest),
    /// Create pull request: POST /repos/{owner}/{repo}/pulls
    CreatePullRequest(CreatePullRequestRequest),
    /// Create git reference / branch: POST /repos/{owner}/{repo}/git/refs
    CreateBranch(CreateBranchRequest),
}

impl GitHubOperation {
    /// Parses a `CanonicalAction` into a typed `GitHubOperation`.
    pub fn from_canonical_action(action: &CanonicalAction) -> Result<Self, GitHubError> {
        if action.tool.namespace != "github" {
            return Err(GitHubError::UnsupportedOperation(format!(
                "Non-GitHub namespace '{}'",
                action.tool.namespace
            )));
        }

        let tool_name = action.tool.name.as_str();
        let args = &action.canonical_arguments;

        match tool_name {
            "get_repository" | "read" | "get_repo" => Ok(GitHubOperation::GetRepository),

            "get_pull_request" | "read_pull_request" => {
                let pull_number = args
                    .get("pull_number")
                    .or_else(|| args.get("pull"))
                    .or_else(|| args.get("number"))
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| GitHubError::InvalidArguments {
                        operation: tool_name.to_string(),
                        reason: "Missing required 'pull_number' parameter".to_string(),
                    })?;

                // Correlate with sub-resource in ResourceUri if present (anti-PR confusion)
                if let Ok(norm_gh) =
                    relay_canonical::GitHubNormalizer::parse(action.resource.as_str())
                {
                    if let Some(GitHubSubResource::PullRequest(uri_num)) = norm_gh.sub_resource {
                        if uri_num != pull_number {
                            return Err(GitHubError::ResourceMismatch {
                                action_target: format!("pull_request #{}", uri_num),
                                op_target: format!("pull_request #{}", pull_number),
                            });
                        }
                    }
                }

                Ok(GitHubOperation::GetPullRequest { pull_number })
            }

            "get_issue" | "read_issue" => {
                let issue_number = args
                    .get("issue_number")
                    .or_else(|| args.get("issue"))
                    .or_else(|| args.get("number"))
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| GitHubError::InvalidArguments {
                        operation: tool_name.to_string(),
                        reason: "Missing required 'issue_number' parameter".to_string(),
                    })?;

                // Correlate with sub-resource in ResourceUri if present (anti-issue confusion)
                if let Ok(norm_gh) =
                    relay_canonical::GitHubNormalizer::parse(action.resource.as_str())
                {
                    if let Some(GitHubSubResource::Issue(uri_num)) = norm_gh.sub_resource {
                        if uri_num != issue_number {
                            return Err(GitHubError::ResourceMismatch {
                                action_target: format!("issue #{}", uri_num),
                                op_target: format!("issue #{}", issue_number),
                            });
                        }
                    }
                }

                Ok(GitHubOperation::GetIssue { issue_number })
            }

            "get_branch" | "read_branch" | "get_ref" => {
                let branch = args
                    .get("branch")
                    .or_else(|| args.get("ref"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| GitHubError::InvalidArguments {
                        operation: tool_name.to_string(),
                        reason: "Missing required 'branch' or 'ref' parameter".to_string(),
                    })?
                    .to_string();

                if branch.is_empty() || branch.contains("..") {
                    return Err(GitHubError::InvalidArguments {
                        operation: tool_name.to_string(),
                        reason: "Invalid branch name".to_string(),
                    });
                }

                Ok(GitHubOperation::GetBranch { branch })
            }

            "create_issue" => {
                // Deserialize strictly into CreateIssueRequest
                let mut req_val = args.clone();
                if let Some(obj) = req_val.as_object_mut() {
                    // Remove routing metadata if present in arguments map
                    obj.remove("repo");
                    obj.remove("repository");
                }
                let create_req: CreateIssueRequest =
                    serde_json::from_value(req_val).map_err(|e| GitHubError::InvalidArguments {
                        operation: tool_name.to_string(),
                        reason: format!("Failed to parse CreateIssueRequest: {e}"),
                    })?;

                if create_req.title.trim().is_empty() {
                    return Err(GitHubError::InvalidArguments {
                        operation: tool_name.to_string(),
                        reason: "Issue title cannot be empty".to_string(),
                    });
                }

                Ok(GitHubOperation::CreateIssue(create_req))
            }

            "create_pull_request" => {
                let mut req_val = args.clone();
                if let Some(obj) = req_val.as_object_mut() {
                    obj.remove("repo");
                    obj.remove("repository");
                }
                let create_req: CreatePullRequestRequest = serde_json::from_value(req_val)
                    .map_err(|e| GitHubError::InvalidArguments {
                        operation: tool_name.to_string(),
                        reason: format!("Failed to parse CreatePullRequestRequest: {e}"),
                    })?;

                if create_req.title.trim().is_empty() {
                    return Err(GitHubError::InvalidArguments {
                        operation: tool_name.to_string(),
                        reason: "Pull request title cannot be empty".to_string(),
                    });
                }
                if create_req.head.trim().is_empty() || create_req.base.trim().is_empty() {
                    return Err(GitHubError::InvalidArguments {
                        operation: tool_name.to_string(),
                        reason: "Pull request 'head' and 'base' branches cannot be empty"
                            .to_string(),
                    });
                }

                Ok(GitHubOperation::CreatePullRequest(create_req))
            }

            "create_branch" | "create_ref" => {
                let mut req_val = args.clone();
                if let Some(obj) = req_val.as_object_mut() {
                    obj.remove("repo");
                    obj.remove("repository");
                    // Accept "branch" alias mapping to "ref"
                    if let Some(b) = obj
                        .remove("branch")
                        .and_then(|v| v.as_str().map(String::from))
                    {
                        let full_ref = if b.starts_with("refs/") {
                            b
                        } else {
                            format!("refs/heads/{b}")
                        };
                        obj.insert("ref".to_string(), serde_json::Value::String(full_ref));
                    }
                }
                let create_req: CreateBranchRequest =
                    serde_json::from_value(req_val).map_err(|e| GitHubError::InvalidArguments {
                        operation: tool_name.to_string(),
                        reason: format!("Failed to parse CreateBranchRequest: {e}"),
                    })?;

                if create_req.ref_name.trim().is_empty()
                    || !create_req.ref_name.starts_with("refs/")
                {
                    return Err(GitHubError::InvalidArguments {
                        operation: tool_name.to_string(),
                        reason: "Branch ref must start with 'refs/' (e.g. 'refs/heads/feature')"
                            .to_string(),
                    });
                }

                if create_req.sha.trim().len() != 40
                    || !create_req.sha.chars().all(|c| c.is_ascii_hexdigit())
                {
                    return Err(GitHubError::InvalidArguments {
                        operation: tool_name.to_string(),
                        reason: "SHA must be a 40-character hexadecimal commit hash".to_string(),
                    });
                }

                Ok(GitHubOperation::CreateBranch(create_req))
            }

            other => Err(GitHubError::UnsupportedOperation(format!(
                "Operation '{other}' is not a supported GitHub operation"
            ))),
        }
    }

    /// Whether this operation mutates remote state.
    pub fn is_mutating(&self) -> bool {
        matches!(
            self,
            Self::CreateIssue(_) | Self::CreatePullRequest(_) | Self::CreateBranch(_)
        )
    }

    /// The idempotency class for retry analysis.
    pub fn idempotency_class(&self) -> IdempotencyClass {
        match self {
            Self::GetRepository
            | Self::GetPullRequest { .. }
            | Self::GetIssue { .. }
            | Self::GetBranch { .. } => IdempotencyClass::SafeToRetry,
            Self::CreateIssue(_) => IdempotencyClass::NotSafeToRetry,
            Self::CreatePullRequest(_) | Self::CreateBranch(_) => {
                IdempotencyClass::ConditionallyRetryable
            }
        }
    }

    /// Human-readable operation name for tracing and error context.
    pub fn operation_name(&self) -> &'static str {
        match self {
            Self::GetRepository => "get_repository",
            Self::GetPullRequest { .. } => "get_pull_request",
            Self::GetIssue { .. } => "get_issue",
            Self::GetBranch { .. } => "get_branch",
            Self::CreateIssue(_) => "create_issue",
            Self::CreatePullRequest(_) => "create_pull_request",
            Self::CreateBranch(_) => "create_branch",
        }
    }

    /// HTTP method used for this operation.
    pub fn http_method(&self) -> Method {
        match self {
            Self::GetRepository
            | Self::GetPullRequest { .. }
            | Self::GetIssue { .. }
            | Self::GetBranch { .. } => Method::GET,
            Self::CreateIssue(_) | Self::CreatePullRequest(_) | Self::CreateBranch(_) => {
                Method::POST
            }
        }
    }

    /// Computes the exact REST API path for this operation given owner and repo.
    pub fn endpoint_path(&self, owner: &str, repo: &str) -> String {
        match self {
            Self::GetRepository => format!("/repos/{owner}/{repo}"),
            Self::GetPullRequest { pull_number } => {
                format!("/repos/{owner}/{repo}/pulls/{pull_number}")
            }
            Self::GetIssue { issue_number } => {
                format!("/repos/{owner}/{repo}/issues/{issue_number}")
            }
            Self::GetBranch { branch } => format!("/repos/{owner}/{repo}/branches/{branch}"),
            Self::CreateIssue(_) => format!("/repos/{owner}/{repo}/issues"),
            Self::CreatePullRequest(_) => format!("/repos/{owner}/{repo}/pulls"),
            Self::CreateBranch(_) => format!("/repos/{owner}/{repo}/git/refs"),
        }
    }

    /// Serializes request body for POST operations.
    pub fn serialize_body(&self) -> Result<Option<Vec<u8>>, GitHubError> {
        match self {
            Self::GetRepository
            | Self::GetPullRequest { .. }
            | Self::GetIssue { .. }
            | Self::GetBranch { .. } => Ok(None),
            Self::CreateIssue(req) => serde_json::to_vec(req)
                .map(Some)
                .map_err(|e| GitHubError::ValidationError(e.to_string())),
            Self::CreatePullRequest(req) => serde_json::to_vec(req)
                .map(Some)
                .map_err(|e| GitHubError::ValidationError(e.to_string())),
            Self::CreateBranch(req) => serde_json::to_vec(req)
                .map(Some)
                .map_err(|e| GitHubError::ValidationError(e.to_string())),
        }
    }
}
