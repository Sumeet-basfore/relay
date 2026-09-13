//! Default resource resolver implementing the `ResourceResolver` domain contract.

use relay_domain::{CanonicalizationError, ResourceResolver, ResourceUri};
use serde_json::Value;
use std::path::PathBuf;

use super::fs::FilesystemNormalizer;
use super::github::GitHubNormalizer;
use super::sql::SqlNormalizer;

/// Default resource resolver routing tool namespaces to domain normalizers
#[derive(Debug, Clone)]
pub struct DefaultResourceResolver {
    fs_normalizer: FilesystemNormalizer,
}

impl Default for DefaultResourceResolver {
    fn default() -> Self {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        Self::new(cwd)
    }
}

impl DefaultResourceResolver {
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            fs_normalizer: FilesystemNormalizer::new(base_dir, false),
        }
    }

    pub fn with_boundary_enforcement(base_dir: PathBuf, enforce: bool) -> Self {
        Self {
            fs_normalizer: FilesystemNormalizer::new(base_dir, enforce),
        }
    }
}

impl ResourceResolver for DefaultResourceResolver {
    fn resolve_resource(
        &self,
        tool_namespace: &str,
        tool_name: &str,
        args: &Value,
    ) -> Result<ResourceUri, CanonicalizationError> {
        match tool_namespace {
            "fs" | "file" | "filesystem" => {
                let raw_path = args
                    .get("path")
                    .or_else(|| args.get("file"))
                    .or_else(|| args.get("filepath"))
                    .or_else(|| args.get("dir"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        CanonicalizationError::InvalidResource(
                            format!("{tool_namespace}.{tool_name}"),
                            "Filesystem tool missing required 'path' argument".to_string(),
                        )
                    })?;

                let normalized = self.fs_normalizer.resolve_path(raw_path)?;
                normalized.to_resource_uri()
            }
            "postgres" | "sql" | "db" => {
                if let Some(query_str) = args
                    .get("query")
                    .or_else(|| args.get("sql"))
                    .and_then(|v| v.as_str())
                {
                    let host = args
                        .get("host")
                        .and_then(|v| v.as_str())
                        .unwrap_or("localhost");
                    let db = args
                        .get("database")
                        .and_then(|v| v.as_str())
                        .unwrap_or("db");
                    let normalized_sql = SqlNormalizer::normalize(query_str)?;
                    normalized_sql.to_resource_uri(host, db)
                } else if let Some(table) = args.get("table").and_then(|v| v.as_str()) {
                    let host = args
                        .get("host")
                        .and_then(|v| v.as_str())
                        .unwrap_or("localhost");
                    let db = args
                        .get("database")
                        .and_then(|v| v.as_str())
                        .unwrap_or("db");
                    let uri_str = format!("postgres://{host}/{db}/public.{table}");
                    ResourceUri::parse(&uri_str).map_err(|e| {
                        CanonicalizationError::InvalidResource(uri_str.clone(), e.to_string())
                    })
                } else {
                    Err(CanonicalizationError::InvalidResource(
                        format!("{tool_namespace}.{tool_name}"),
                        "Postgres tool missing required 'query' or 'table' argument".to_string(),
                    ))
                }
            }
            "github" | "gh" => {
                let repo_ident = args
                    .get("repo")
                    .or_else(|| args.get("repository"))
                    .or_else(|| args.get("url"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        CanonicalizationError::InvalidResource(
                            format!("{tool_namespace}.{tool_name}"),
                            "GitHub tool missing required 'repo' or 'repository' argument"
                                .to_string(),
                        )
                    })?;

                let normalized = GitHubNormalizer::parse(repo_ident)?;
                Ok(normalized.canonical_uri)
            }
            _ => {
                let uri_str = format!("tool://{tool_namespace}/{tool_name}");
                ResourceUri::parse(&uri_str).map_err(|e| {
                    CanonicalizationError::InvalidResource(uri_str.clone(), e.to_string())
                })
            }
        }
    }
}
