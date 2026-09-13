//! PostgreSQL / SQL AST normalization.
//!
//! Enforces:
//! - Strict single-statement execution (rejects multi-statement injection)
//! - Comment elimination via AST serialization
//! - Statement operation classification (Select, Insert, Update, Delete, Ddl, Transaction)
//! - Destructive operation detection (DROP, TRUNCATE, unconstrained UPDATE/DELETE)
//! - Referenced table extraction with PostgreSQL unquoted identifier lowercasing

use relay_domain::{CanonicalizationError, ResourceUri};
use serde::{Deserialize, Serialize};
use sqlparser::ast::{FromTable, ObjectName, Query, SetExpr, Statement, TableFactor};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

/// Classification of SQL operations for policy evaluation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SqlOperation {
    Select,
    Insert,
    Update,
    Delete,
    Ddl,
    Transaction,
}

/// Normalized SQL AST result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedSql {
    pub canonical_sql: String,
    pub operation: SqlOperation,
    pub tables: Vec<String>,
    pub is_destructive: bool,
}

impl NormalizedSql {
    /// Formats normalized SQL into a canonical PostgreSQL ResourceUri
    pub fn to_resource_uri(
        &self,
        host: &str,
        db: &str,
    ) -> Result<ResourceUri, CanonicalizationError> {
        let table_target = if self.tables.is_empty() {
            "all".to_string()
        } else {
            self.tables.join(",")
        };
        let uri_str = format!("postgres://{host}/{db}/{table_target}");
        ResourceUri::parse(&uri_str)
            .map_err(|e| CanonicalizationError::InvalidResource(uri_str.clone(), e.to_string()))
    }
}

/// SQL normalizer using PostgreSqlDialect AST parser
pub struct SqlNormalizer;

impl SqlNormalizer {
    /// Parses raw SQL and returns canonicalized AST metadata
    pub fn normalize(raw_sql: &str) -> Result<NormalizedSql, CanonicalizationError> {
        let trimmed = raw_sql.trim();
        if trimmed.is_empty() {
            return Err(CanonicalizationError::UnsupportedSql(
                "SQL statement cannot be empty".to_string(),
            ));
        }

        let dialect = PostgreSqlDialect {};
        let ast = Parser::parse_sql(&dialect, trimmed)
            .map_err(|e| CanonicalizationError::UnsupportedSql(e.to_string()))?;

        if ast.is_empty() {
            return Err(CanonicalizationError::UnsupportedSql(
                "No SQL statements found".to_string(),
            ));
        }

        if ast.len() > 1 {
            return Err(CanonicalizationError::MultiStatementSqlNotAllowed { count: ast.len() });
        }

        let stmt = &ast[0];
        let canonical_sql = stmt.to_string();

        let mut tables = Vec::new();
        let (operation, is_destructive) = match stmt {
            Statement::Query(query) => {
                extract_tables_from_query(query, &mut tables);
                (SqlOperation::Select, false)
            }
            Statement::Insert(insert) => {
                tables.push(normalize_object_name(&insert.table_name));
                (SqlOperation::Insert, false)
            }
            Statement::Update {
                table, selection, ..
            } => {
                extract_table_factor(&table.relation, &mut tables);
                let destructive = selection.is_none();
                (SqlOperation::Update, destructive)
            }
            Statement::Delete(delete) => {
                match &delete.from {
                    FromTable::WithFromKeyword(from_tables)
                    | FromTable::WithoutKeyword(from_tables) => {
                        for twj in from_tables {
                            extract_table_factor(&twj.relation, &mut tables);
                        }
                    }
                }
                for tbl in &delete.tables {
                    tables.push(normalize_object_name(tbl));
                }
                let destructive = delete.selection.is_none();
                (SqlOperation::Delete, destructive)
            }
            Statement::CreateTable { name, .. } => {
                tables.push(normalize_object_name(name));
                (SqlOperation::Ddl, false)
            }
            Statement::Drop { names, .. } => {
                for name in names {
                    tables.push(normalize_object_name(name));
                }
                (SqlOperation::Ddl, true)
            }
            Statement::Truncate { table_name, .. } => {
                tables.push(normalize_object_name(table_name));
                (SqlOperation::Ddl, true)
            }
            Statement::AlterTable { name, .. } => {
                tables.push(normalize_object_name(name));
                (SqlOperation::Ddl, true)
            }
            Statement::StartTransaction { .. }
            | Statement::Commit { .. }
            | Statement::Rollback { .. } => (SqlOperation::Transaction, false),
            other => {
                return Err(CanonicalizationError::UnsupportedSql(format!(
                    "Unsupported SQL statement type: {other:?}"
                )));
            }
        };

        tables.sort();
        tables.dedup();

        Ok(NormalizedSql {
            canonical_sql,
            operation,
            tables,
            is_destructive,
        })
    }
}

fn normalize_object_name(name: &ObjectName) -> String {
    name.0
        .iter()
        .map(|ident| {
            if ident.quote_style.is_some() {
                format!("\"{}\"", ident.value)
            } else {
                ident.value.to_lowercase()
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn extract_tables_from_query(query: &Query, tables: &mut Vec<String>) {
    extract_set_expr(&query.body, tables);
}

fn extract_set_expr(body: &SetExpr, tables: &mut Vec<String>) {
    match body {
        SetExpr::Select(select) => {
            for twj in &select.from {
                extract_table_factor(&twj.relation, tables);
                for join in &twj.joins {
                    extract_table_factor(&join.relation, tables);
                }
            }
        }
        SetExpr::Query(q) => extract_tables_from_query(q, tables),
        SetExpr::SetOperation { left, right, .. } => {
            extract_set_expr(left, tables);
            extract_set_expr(right, tables);
        }
        _ => {}
    }
}

fn extract_table_factor(relation: &TableFactor, tables: &mut Vec<String>) {
    match relation {
        TableFactor::Table { name, .. } => {
            tables.push(normalize_object_name(name));
        }
        TableFactor::Derived { subquery, .. } => {
            extract_tables_from_query(subquery, tables);
        }
        _ => {}
    }
}
