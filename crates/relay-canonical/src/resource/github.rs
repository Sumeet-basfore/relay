//! Canonical GitHub resource normalization.
//!
//! Enforces:
//! - Case-insensitivity normalization for host, owner, and repository
//! - URL, SSH, and shorthand format unification
//! - Sub-resource classification (Pull Request, Issue, Ref)
//! - Removal of `.git` suffixes and path traversal components
//! - Deterministic `github://` canonical URI formatting

use relay_domain::{CanonicalizationError, ResourceUri};
use serde::{Deserialize, Serialize};

/// GitHub sub-resource classification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubSubResource {
    PullRequest(u64),
    Issue(u64),
    Ref(String),
}

/// Authoritative canonical GitHub resource
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedGitHubResource {
    pub host: String,
    pub owner: String,
    pub repo: String,
    pub sub_resource: Option<GitHubSubResource>,
    pub canonical_uri: ResourceUri,
}

/// Normalizer for GitHub repository and sub-resource identifiers
pub struct GitHubNormalizer;

impl GitHubNormalizer {
    /// Parses and normalizes any valid GitHub resource reference
    pub fn parse(raw: &str) -> Result<NormalizedGitHubResource, CanonicalizationError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(CanonicalizationError::InvalidResource(
                raw.to_string(),
                "GitHub resource string cannot be empty".to_string(),
            ));
        }

        // Strip protocols and prefixes
        let without_proto = if let Some(stripped) = trimmed.strip_prefix("https://") {
            stripped
        } else if let Some(stripped) = trimmed.strip_prefix("http://") {
            stripped
        } else if let Some(stripped) = trimmed.strip_prefix("git@github.com:") {
            stripped
        } else if let Some(stripped) = trimmed.strip_prefix("github://") {
            stripped
        } else if let Some(stripped) = trimmed.strip_prefix("ssh://git@github.com/") {
            stripped
        } else {
            trimmed
        };

        // Strip host if present
        let after_host = if let Some(stripped) = without_proto.strip_prefix("github.com/") {
            stripped
        } else {
            without_proto
        };

        // Path traversal rejection
        if after_host.contains("..") || after_host.contains("//") {
            return Err(CanonicalizationError::InvalidResource(
                raw.to_string(),
                format!("Path traversal or invalid slashes in GitHub resource: '{raw}'"),
            ));
        }

        // Handle shorthand sub-resources: owner/repo#123 or owner/repo@ref
        let (repo_path, shorthand_sub) = if let Some((base, num_str)) = after_host.split_once('#') {
            let num = num_str.parse::<u64>().map_err(|_| {
                CanonicalizationError::InvalidResource(
                    raw.to_string(),
                    format!("Invalid issue/PR number in '{raw}'"),
                )
            })?;
            (base, Some(GitHubSubResource::Issue(num)))
        } else if let Some((base, git_ref)) = after_host.split_once('@') {
            (base, Some(GitHubSubResource::Ref(git_ref.to_string())))
        } else {
            (after_host, None)
        };

        let parts: Vec<&str> = repo_path.split('/').filter(|p| !p.is_empty()).collect();
        if parts.len() < 2 {
            return Err(CanonicalizationError::InvalidResource(
                raw.to_string(),
                format!("Invalid GitHub repository identifier '{raw}'; expected 'owner/repo'"),
            ));
        }

        let owner = parts[0].to_lowercase();
        let raw_repo = parts[1].to_lowercase();
        let repo = raw_repo
            .strip_suffix(".git")
            .unwrap_or(&raw_repo)
            .to_string();

        let is_valid_ident = |s: &str| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        };

        if !is_valid_ident(&owner) {
            return Err(CanonicalizationError::InvalidResource(
                raw.to_string(),
                format!("Invalid characters in GitHub owner '{owner}'"),
            ));
        }
        if !is_valid_ident(&repo) {
            return Err(CanonicalizationError::InvalidResource(
                raw.to_string(),
                format!("Invalid characters in GitHub repo '{repo}'"),
            ));
        }

        let mut sub_resource = shorthand_sub;

        if sub_resource.is_none() && parts.len() >= 4 {
            match parts[2] {
                "pull" => {
                    let num = parts[3].parse::<u64>().map_err(|_| {
                        CanonicalizationError::InvalidResource(
                            raw.to_string(),
                            format!("Invalid pull request number '{}' in '{raw}'", parts[3]),
                        )
                    })?;
                    sub_resource = Some(GitHubSubResource::PullRequest(num));
                }
                "issues" => {
                    let num = parts[3].parse::<u64>().map_err(|_| {
                        CanonicalizationError::InvalidResource(
                            raw.to_string(),
                            format!("Invalid issue number '{}' in '{raw}'", parts[3]),
                        )
                    })?;
                    sub_resource = Some(GitHubSubResource::Issue(num));
                }
                "tree" | "commits" | "releases" => {
                    let ref_name = parts[3..].join("/");
                    sub_resource = Some(GitHubSubResource::Ref(ref_name));
                }
                _ => {}
            }
        }

        let host = "github.com".to_string();
        let uri_str = match &sub_resource {
            Some(GitHubSubResource::PullRequest(num)) => {
                format!("github://{host}/{owner}/{repo}/pull/{num}")
            }
            Some(GitHubSubResource::Issue(num)) => {
                format!("github://{host}/{owner}/{repo}/issues/{num}")
            }
            Some(GitHubSubResource::Ref(r)) => {
                format!("github://{host}/{owner}/{repo}/refs/{r}")
            }
            None => format!("github://{host}/{owner}/{repo}"),
        };

        let canonical_uri = ResourceUri::parse(&uri_str)
            .map_err(|e| CanonicalizationError::InvalidResource(uri_str.clone(), e.to_string()))?;

        Ok(NormalizedGitHubResource {
            host,
            owner,
            repo,
            sub_resource,
            canonical_uri,
        })
    }
}
