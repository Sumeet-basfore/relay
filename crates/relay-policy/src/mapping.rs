//! Mapping between Relay Domain types (`AuthorizationRequest`) and Cedar PARC representations.
//!
//! Principal: `Relay::Agent::"<principal_id>"`
//! Action:    `Relay::Action::"<namespace>.<name>"`
//! Resource:  `Relay::File::"<path>"`, `Relay::Table::"<table>"`, `Relay::Repository::"<owner>/<repo>"`, `Relay::Resource::"<uri>"`
//! Context:   `ActionContext` carrying operational metadata.

use cedar_policy::{Context, EntityUid};
use relay_domain::{AuthorizationRequest, PolicyError};
use serde_json::{json, Value};
use std::str::FromStr;

/// Escapes double quotes and backslashes for Cedar entity IDs.
fn escape_cedar_eid(raw: &str) -> String {
    raw.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Converts a domain `AuthorizationRequest` into Cedar `(EntityUid, EntityUid, EntityUid, Context)`.
pub fn map_authorization_request(
    request: &AuthorizationRequest,
) -> Result<(EntityUid, EntityUid, EntityUid, Context), PolicyError> {
    // 1. Principal: Relay::Agent::"<principal_id>"
    let principal_eid = escape_cedar_eid(request.principal.as_str());
    let principal_str = format!("Relay::Agent::\"{principal_eid}\"");
    let principal = EntityUid::from_str(&principal_str).map_err(|e| {
        PolicyError::EvaluationFailed(format!("Failed to construct Cedar principal: {e}"))
    })?;

    // 2. Action: Relay::Action::"<namespace>.<name>"
    let normalized_action = request.action.replace(':', ".");
    let action_eid = escape_cedar_eid(&normalized_action);
    let action_str = format!("Relay::Action::\"{action_eid}\"");
    let action = EntityUid::from_str(&action_str).map_err(|e| {
        PolicyError::EvaluationFailed(format!("Failed to construct Cedar action: {e}"))
    })?;

    // 3. Resource: Relay::<Type>::"<canonical_id>"
    let resource_uri = &request.resource;
    let resource = match resource_uri.scheme() {
        "file" => {
            let path_eid = escape_cedar_eid(resource_uri.path());
            let res_str = format!("Relay::File::\"{path_eid}\"");
            EntityUid::from_str(&res_str)
        }
        "postgres" => {
            let path = resource_uri.path();
            let table_target = path.rsplit('/').next().unwrap_or(path);
            let table_eid = escape_cedar_eid(table_target);
            let res_str = format!("Relay::Table::\"{table_eid}\"");
            EntityUid::from_str(&res_str)
        }
        "github" => {
            let mut path = resource_uri.path();
            if let Some(stripped) = path.strip_prefix("github.com/") {
                path = stripped;
            }
            let mut parts = path.split('/');
            let repo_target = match (parts.next(), parts.next()) {
                (Some(owner), Some(repo)) => format!("{owner}/{repo}"),
                _ => path.to_string(),
            };
            let repo_eid = escape_cedar_eid(&repo_target);
            let res_str = format!("Relay::Repository::\"{repo_eid}\"");
            EntityUid::from_str(&res_str)
        }
        _ => {
            let uri_eid = escape_cedar_eid(resource_uri.as_str());
            let res_str = format!("Relay::Resource::\"{uri_eid}\"");
            EntityUid::from_str(&res_str)
        }
    }
    .map_err(|e| {
        PolicyError::EvaluationFailed(format!("Failed to construct Cedar resource: {e}"))
    })?;

    // 4. Context: ActionContext
    let mut context_map = serde_json::Map::new();

    // Context path
    if let Some(path_val) = request
        .arguments
        .get("path")
        .or_else(|| request.arguments.get("file"))
        .or_else(|| request.arguments.get("filepath"))
        .and_then(|v| v.as_str())
    {
        context_map.insert("path".to_string(), json!(path_val));
    } else if resource_uri.scheme() == "file" {
        context_map.insert("path".to_string(), json!(resource_uri.path()));
    }

    // Context query
    if let Some(query_val) = request
        .arguments
        .get("query")
        .or_else(|| request.arguments.get("sql"))
        .and_then(|v| v.as_str())
    {
        context_map.insert("query".to_string(), json!(query_val));
    }

    // Context table
    if let Some(table_val) = request.arguments.get("table").and_then(|v| v.as_str()) {
        context_map.insert("table".to_string(), json!(table_val));
    } else if resource_uri.scheme() == "postgres" {
        let path = resource_uri.path();
        let table_target = path.rsplit('/').next().unwrap_or(path);
        context_map.insert("table".to_string(), json!(table_target));
    }

    // Context repo
    if let Some(repo_val) = request
        .arguments
        .get("repo")
        .or_else(|| request.arguments.get("repository"))
        .and_then(|v| v.as_str())
    {
        context_map.insert("repo".to_string(), json!(repo_val));
    }

    // Working directory
    context_map.insert(
        "working_directory".to_string(),
        json!(request.working_directory),
    );

    // ActionHash
    let action_hash = request.compute_action_hash();
    context_map.insert("action_hash".to_string(), json!(action_hash.to_hex()));

    // SchemaDigest
    if let Some(sd) = request
        .arguments
        .get("schema_digest")
        .and_then(|v| v.as_str())
    {
        context_map.insert("schema_digest".to_string(), json!(sd));
    }

    // Tool
    context_map.insert("tool".to_string(), json!(normalized_action));

    // Operation
    if let Some(op) = request.arguments.get("operation").and_then(|v| v.as_str()) {
        context_map.insert("operation".to_string(), json!(op));
    }

    // Is destructive
    if let Some(is_dest) = request
        .arguments
        .get("is_destructive")
        .and_then(|v| v.as_bool())
    {
        context_map.insert("is_destructive".to_string(), json!(is_dest));
    } else if normalized_action.contains("delete")
        || normalized_action.contains("drop")
        || normalized_action.contains("truncate")
    {
        context_map.insert("is_destructive".to_string(), json!(true));
    }

    let context_val = Value::Object(context_map);
    let context = Context::from_json_value(context_val, None).map_err(|e| {
        PolicyError::EvaluationFailed(format!("Failed to build Cedar context: {e}"))
    })?;

    Ok((principal, action, resource, context))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use relay_domain::{PrincipalId, ResourceUri, SessionId, ToolId};

    #[test]
    fn test_map_fs_request() {
        let req = AuthorizationRequest {
            principal: PrincipalId::new("principal:agent:default").unwrap(),
            action: "fs.read".to_string(),
            resource: ResourceUri::parse("file:///workspace/test.txt").unwrap(),
            session_id: SessionId::new_v7(),
            tool: ToolId::new("fs", "read").unwrap(),
            arguments: json!({ "path": "/workspace/test.txt" }),
            working_directory: "/workspace".to_string(),
            timestamp: Utc::now(),
            action_hash: None,
        };

        let (p, a, r, _ctx) = map_authorization_request(&req).unwrap();
        assert_eq!(p.to_string(), "Relay::Agent::\"principal:agent:default\"");
        assert_eq!(a.to_string(), "Relay::Action::\"fs.read\"");
        assert_eq!(r.to_string(), "Relay::File::\"/workspace/test.txt\"");
    }

    #[test]
    fn test_map_postgres_request() {
        let req = AuthorizationRequest {
            principal: PrincipalId::new("principal:agent:default").unwrap(),
            action: "postgres:query".to_string(),
            resource: ResourceUri::parse("postgres://localhost/db/public.users").unwrap(),
            session_id: SessionId::new_v7(),
            tool: ToolId::new("postgres", "query").unwrap(),
            arguments: json!({ "query": "SELECT * FROM users;" }),
            working_directory: "/workspace".to_string(),
            timestamp: Utc::now(),
            action_hash: None,
        };

        let (p, a, r, _ctx) = map_authorization_request(&req).unwrap();
        assert_eq!(p.to_string(), "Relay::Agent::\"principal:agent:default\"");
        assert_eq!(a.to_string(), "Relay::Action::\"postgres.query\"");
        assert_eq!(r.to_string(), "Relay::Table::\"public.users\"");
    }

    #[test]
    fn test_map_github_request() {
        let req = AuthorizationRequest {
            principal: PrincipalId::new("principal:agent:default").unwrap(),
            action: "github.read".to_string(),
            resource: ResourceUri::parse("github://github.com/org/repo").unwrap(),
            session_id: SessionId::new_v7(),
            tool: ToolId::new("github", "read").unwrap(),
            arguments: json!({ "repo": "org/repo" }),
            working_directory: "/workspace".to_string(),
            timestamp: Utc::now(),
            action_hash: None,
        };

        let (_p, a, r, _ctx) = map_authorization_request(&req).unwrap();
        assert_eq!(a.to_string(), "Relay::Action::\"github.read\"");
        assert_eq!(r.to_string(), "Relay::Repository::\"org/repo\"");
    }
}
