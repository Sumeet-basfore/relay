//! Resource scope and search_path enforcement for PostgreSQL execution.

use relay_canonical::{NormalizedSql, SqlOperation};

use super::error::PostgresError;
use super::resource::PostgresResource;

/// Dangerous PostgreSQL constructs rejected at execution boundary (defense in depth).
const FORBIDDEN_KEYWORDS: &[&str] = &[
    "copy ",
    "copy\n",
    "copy\t",
    "do ",
    "do\n",
    "do\t",
    "call ",
    "call\n",
    "call\t",
    "create extension",
    "alter system",
    "set search_path",
    "set role",
    "set session authorization",
    "set time zone",
    "reset search_path",
    "reset all",
    "dblink",
    "postgres_fdw",
    "file_fdw",
    "lo_import",
    "lo_export",
    "lo_create",
    "lo_unlink",
    "pg_read_file",
    "pg_read_binary_file",
    "pg_write_file",
    "pg_ls_dir",
    "current_setting",
    "set_config",
    "pg_temp",
];

/// Validates that canonical SQL uses only the approved MVP surface.
pub fn validate_supported_surface(canonical_sql: &str) -> Result<(), PostgresError> {
    let trimmed = canonical_sql.trim();
    let lowered = trimmed.to_ascii_lowercase();

    // Check for semicolons that might represent multi-statement injection
    let non_trailing = trimmed.trim_end_matches(';').trim_end();
    if non_trailing.contains(';') {
        return Err(PostgresError::UnsupportedStatement(
            "Multi-statement SQL execution is rejected (SI-007)".to_string(),
        ));
    }

    // Check statement-level commands
    if lowered.starts_with("set ")
        || lowered.starts_with("set\n")
        || lowered.starts_with("set\t")
        || lowered.starts_with("reset ")
        || lowered.starts_with("reset\n")
        || lowered.starts_with("reset\t")
    {
        return Err(PostgresError::UnsupportedStatement(
            "Session configuration statements (SET/RESET) are forbidden".to_string(),
        ));
    }

    for keyword in FORBIDDEN_KEYWORDS {
        if lowered.contains(keyword) {
            return Err(PostgresError::UnsupportedStatement(format!(
                "Forbidden PostgreSQL construct detected: {keyword}"
            )));
        }
    }

    Ok(())
}

/// Validates that referenced tables remain within the authorized canonical resource scope.
pub fn validate_table_scope(
    resource: &PostgresResource,
    normalized: &NormalizedSql,
    fixed_search_path: &str,
) -> Result<(), PostgresError> {
    if resource.allows_any_table() {
        return validate_search_path_qualification(normalized, fixed_search_path);
    }

    for table in &normalized.tables {
        let qualified = qualify_table_reference(table, fixed_search_path);
        if !resource.tables.iter().any(|authorized| {
            let auth_qualified = qualify_table_reference(authorized, fixed_search_path);
            auth_qualified == qualified || *authorized == *table
        }) {
            return Err(PostgresError::ResourceScopeViolation(format!(
                "Table '{table}' is outside authorized scope {:?}",
                resource.tables
            )));
        }
    }

    validate_search_path_qualification(normalized, fixed_search_path)
}

/// Rejects unqualified identifiers when they could resolve differently under another search_path.
fn validate_search_path_qualification(
    normalized: &NormalizedSql,
    fixed_search_path: &str,
) -> Result<(), PostgresError> {
    for table in &normalized.tables {
        if !table.contains('.') && fixed_search_path != "public" {
            return Err(PostgresError::SearchPathAmbiguity(format!(
                "Unqualified table '{table}' rejected under non-public search_path '{fixed_search_path}'"
            )));
        }
    }
    Ok(())
}

fn qualify_table_reference(table: &str, search_path: &str) -> String {
    if table.contains('.') {
        table.to_string()
    } else {
        format!("{search_path}.{table}")
    }
}

/// Maps SQL operation class to Cedar action expectations for the tool name.
pub fn validate_operation_class(
    tool_name: &str,
    operation: SqlOperation,
) -> Result<&'static str, PostgresError> {
    let sql_class = match operation {
        SqlOperation::Select => "read",
        SqlOperation::Insert | SqlOperation::Update | SqlOperation::Delete => "write",
        SqlOperation::Ddl => "ddl",
        SqlOperation::Transaction => "transaction",
    };

    let allowed = match tool_name {
        "read" | "query" | "select" => operation == SqlOperation::Select,
        "write" | "insert" | "update" | "delete" => {
            matches!(
                operation,
                SqlOperation::Insert | SqlOperation::Update | SqlOperation::Delete
            )
        }
        "ddl" | "migrate" => operation == SqlOperation::Ddl,
        other => {
            return Err(PostgresError::UnsupportedStatement(format!(
                "Unknown postgres tool name '{other}'"
            )));
        }
    };

    if !allowed {
        return Err(PostgresError::OperationClassMismatch {
            tool: tool_name.to_string(),
            sql_class: sql_class.to_string(),
        });
    }

    Ok(sql_class)
}

/// Returns true when the SQL operation is mutating and not safe to automatically retry.
pub fn is_mutating_operation(operation: SqlOperation) -> bool {
    matches!(
        operation,
        SqlOperation::Insert | SqlOperation::Update | SqlOperation::Delete | SqlOperation::Ddl
    )
}
