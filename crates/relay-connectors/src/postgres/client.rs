//! Governed PostgreSQL protocol client.
//!
//! Enforces:
//! - Per-action connections (no cross-authority pooling in MVP)
//! - Exact canonical SQL execution (no independent re-authorization parsing)
//! - Fixed search_path and bounded result materialization
//! - Secure TLS for remote targets; plaintext only on loopback test harness

use std::sync::Arc;

use postgres_rustls::{MakeTlsConnector, set_postgresql_alpn};
use rustls::ClientConfig;
use tokio::time::timeout;
use tokio_postgres::{Client, NoTls, Row};

use super::config::PostgresClientConfig;
use super::error::PostgresError;
use super::resource::{PostgresCredentials, PostgresResource};
use relay_canonical::SqlOperation;

/// Response from a governed PostgreSQL query execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresResponse {
    pub body: Vec<u8>,
    pub row_count: usize,
    pub command_tag: String,
}

/// Governed PostgreSQL client encapsulating connection lifecycle and execution.
pub struct PostgresClient {
    config: PostgresClientConfig,
    tls_connector: Option<MakeTlsConnector>,
}

impl PostgresClient {
    pub fn new(config: PostgresClientConfig) -> Result<Self, PostgresError> {
        let tls_connector = if config.allow_no_tls_loopback {
            None
        } else {
            Some(build_rustls_connector()?)
        };

        Ok(Self {
            config,
            tls_connector,
        })
    }

    pub fn config(&self) -> &PostgresClientConfig {
        &self.config
    }

    /// Executes canonical SQL against the trusted target derived from the canonical resource.
    pub async fn execute_statement(
        &self,
        resource: &PostgresResource,
        credentials: &PostgresCredentials,
        canonical_sql: &str,
        operation: SqlOperation,
        operation_name: &str,
        is_mutating: bool,
    ) -> Result<PostgresResponse, PostgresError> {
        self.config.validate_host(&resource.host)?;

        let port = self.config.default_port;
        let connect_timeout = self.config.connect_timeout;
        let query_timeout = self.config.query_timeout;

        let connect_fut = async {
            let mut config = tokio_postgres::Config::new();
            config.host(&resource.host);
            config.port(port);
            config.dbname(&resource.database);
            config.user(&credentials.username);
            config.password(&credentials.password);
            config.application_name("relay-postgres-connector");

            if self.config.allows_plaintext(&resource.host) {
                let (client, connection) = config.connect(NoTls).await.map_err(map_connect_error)?;
                tokio::spawn(async move {
                    if let Err(err) = connection.await {
                        tracing::debug!(error = %err, "PostgreSQL connection driver task ended");
                    }
                });
                Ok(client)
            } else {
                let connector = self
                    .tls_connector
                    .as_ref()
                    .ok_or_else(|| PostgresError::TlsFailure(
                        "TLS connector not configured for remote PostgreSQL target".to_string(),
                    ))?;
                let (client, connection) = config
                    .connect(connector.clone())
                    .await
                    .map_err(map_connect_error)?;
                tokio::spawn(async move {
                    if let Err(err) = connection.await {
                        tracing::debug!(error = %err, "PostgreSQL TLS connection driver task ended");
                    }
                });
                Ok(client)
            }
        };

        let client: Client = match timeout(connect_timeout, connect_fut).await {
            Ok(Ok(client)) => client,
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                if is_mutating {
                    return Err(PostgresError::AmbiguousMutationOutcome {
                        operation: operation_name.to_string(),
                        reason: format!("Connection timed out after {connect_timeout:?}"),
                    });
                }
                return Err(PostgresError::Timeout {
                    timeout_ms: connect_timeout.as_millis() as u64,
                });
            }
        };

        // Pin search_path before executing authorized SQL (search_path security boundary).
        let search_path_sql = format!(
            "SET search_path TO {}",
            sanitize_identifier(&self.config.fixed_search_path)
        );
        client
            .execute(&search_path_sql, &[])
            .await
            .map_err(|e| PostgresError::QueryError(format!("Failed to set search_path: {e}")))?;

        let exec_fut = async {
            match operation {
                SqlOperation::Select => self.execute_select(&client, canonical_sql).await,
                SqlOperation::Insert | SqlOperation::Update | SqlOperation::Delete | SqlOperation::Ddl => {
                    self.execute_mutating(&client, canonical_sql).await
                }
                SqlOperation::Transaction => Err(PostgresError::UnsupportedStatement(
                    "Transaction control statements are not supported in MVP".to_string(),
                )),
            }
        };

        match timeout(query_timeout, exec_fut).await {
            Ok(result) => result,
            Err(_) => {
                if is_mutating {
                    Err(PostgresError::AmbiguousMutationOutcome {
                        operation: operation_name.to_string(),
                        reason: format!("Query timed out after {query_timeout:?}; mutation may have committed"),
                    })
                } else {
                    Err(PostgresError::Timeout {
                        timeout_ms: query_timeout.as_millis() as u64,
                    })
                }
            }
        }
    }

    async fn execute_select(
        &self,
        client: &Client,
        canonical_sql: &str,
    ) -> Result<PostgresResponse, PostgresError> {
        let rows = client
            .query(canonical_sql, &[])
            .await
            .map_err(map_query_error)?;

        if rows.len() > self.config.max_result_rows {
            return Err(PostgresError::ResultRowLimitExceeded {
                rows: rows.len(),
                limit: self.config.max_result_rows,
            });
        }

        let body = serialize_rows_to_json(&rows, self.config.max_result_columns)?;
        if body.len() > self.config.max_result_bytes {
            return Err(PostgresError::ResultTooLarge {
                size: body.len(),
                limit: self.config.max_result_bytes,
            });
        }

        Ok(PostgresResponse {
            body,
            row_count: rows.len(),
            command_tag: format!("SELECT {}" , rows.len()),
        })
    }

    async fn execute_mutating(
        &self,
        client: &Client,
        canonical_sql: &str,
    ) -> Result<PostgresResponse, PostgresError> {
        let affected = client
            .execute(canonical_sql, &[])
            .await
            .map_err(map_query_error)?;

        let body = serde_json::json!({
            "rows_affected": affected,
            "command_tag": format!("OK {}", affected),
        });
        let body_bytes = serde_json::to_vec(&body).map_err(|e| PostgresError::QueryError(e.to_string()))?;

        Ok(PostgresResponse {
            body: body_bytes,
            row_count: affected as usize,
            command_tag: format!("OK {}", affected),
        })
    }
}

fn sanitize_identifier(identifier: &str) -> String {
    if identifier
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        identifier.to_string()
    } else {
        "public".to_string()
    }
}

fn serialize_rows_to_json(
    rows: &[Row],
    max_columns: usize,
) -> Result<Vec<u8>, PostgresError> {
    let mut output = Vec::with_capacity(rows.len());
    for row in rows {
        if row.len() > max_columns {
            return Err(PostgresError::ResultTooLarge {
                size: row.len(),
                limit: max_columns,
            });
        }

        let mut obj = serde_json::Map::new();
        for (idx, column) in row.columns().iter().enumerate() {
            let name = column.name();
            let val: serde_json::Value = match column.type_().name() {
                "bool" => row.try_get::<_, bool>(idx).map(serde_json::Value::from).unwrap_or(serde_json::Value::Null),
                "int2" | "int4" => row.try_get::<_, i32>(idx).map(|v| serde_json::Value::from(v as i64)).unwrap_or(serde_json::Value::Null),
                "int8" => row.try_get::<_, i64>(idx).map(serde_json::Value::from).unwrap_or(serde_json::Value::Null),
                "float4" | "float8" | "numeric" => row.try_get::<_, f64>(idx).map(serde_json::Value::from).unwrap_or(serde_json::Value::Null),
                "text" | "varchar" | "bpchar" | "name" => row
                    .try_get::<_, String>(idx)
                    .map(serde_json::Value::from)
                    .unwrap_or(serde_json::Value::Null),
                _ => row
                    .try_get::<_, String>(idx)
                    .map(serde_json::Value::from)
                    .unwrap_or(serde_json::Value::Null),
            };
            obj.insert(name.to_string(), val);
        }
        output.push(serde_json::Value::Object(obj));
    }

    serde_json::to_vec(&output).map_err(|e| PostgresError::QueryError(e.to_string()))
}

fn map_connect_error(err: tokio_postgres::Error) -> PostgresError {
    if let Some(db_err) = err.as_db_error() {
        let code = db_err.code().code();
        let message = db_err.message();
        if code == "28P01" {
            return PostgresError::AuthenticationFailed;
        }
        if code == "42501" {
            return PostgresError::AuthorizationFailed(message.to_string());
        }
        return PostgresError::ConnectionFailure(format!("{code}: {message}"));
    }

    if err.to_string().to_ascii_lowercase().contains("tls") {
        return PostgresError::TlsFailure(err.to_string());
    }

    PostgresError::ConnectionFailure(err.to_string())
}

fn map_query_error(err: tokio_postgres::Error) -> PostgresError {
    if let Some(db_err) = err.as_db_error() {
        let code = db_err.code().code();
        let message = db_err.message();
        return match code {
            "28P01" => PostgresError::AuthenticationFailed,
            "42501" => PostgresError::AuthorizationFailed(message.to_string()),
            "23505" | "23503" | "23514" | "23502" => {
                PostgresError::ConstraintViolation(format!("{code}: {message}"))
            }
            "40001" | "40P01" => PostgresError::SerializationConflict(format!("{code}: {message}")),
            _ => PostgresError::QueryError(format!("{code}: {message}")),
        };
    }

    PostgresError::QueryError(err.to_string())
}

fn build_rustls_connector() -> Result<MakeTlsConnector, PostgresError> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    set_postgresql_alpn(&mut config);

    Ok(MakeTlsConnector::new(Arc::new(config).into()))
}
