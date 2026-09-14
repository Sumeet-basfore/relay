//! Native PostgreSQL Connector implementing in-process governed SQL execution.
//!
//! Enforces:
//! - Complete mediation: MUST NOT be reachable without prior Cedar ALLOW and CredentialBroker lease
//! - ActionHash binding (SI-006): Verifies canonical action hash matches policy decision and credential lease
//! - Single-use lease consumption and per-action connections
//! - Exact canonical SQL execution without independent authorization parsing

use async_trait::async_trait;
use std::sync::Arc;

use relay_canonical::{CanonicalAction, SqlNormalizer};
use relay_domain::{
    ActionReceipt, Approval, ApprovalState, CredentialBroker, CredentialProviderType,
    CredentialRequest, ExecutionError, ExecutionId, ExecutionObservationStatus, ExecutionResult,
    ExecutionRoute, NativeConnector, OutputHash, PolicyDecision, PolicyDecisionType, SecretBuffer,
};
use relay_receipts::{ActionReceiptBuilder, Ed25519ReceiptSigner};

use super::client::PostgresClient;
use super::config::PostgresClientConfig;
use super::error::PostgresError;
use super::resource::{PostgresCredentials, PostgresResource};
use super::scope::{
    is_mutating_operation, validate_operation_class, validate_supported_surface,
    validate_table_scope,
};

/// Production-ready Native PostgreSQL Connector for Relay.
#[derive(Clone)]
pub struct PostgresConnector {
    client: Arc<PostgresClient>,
    default_key_alias: String,
}

impl PostgresConnector {
    pub fn new(client: Arc<PostgresClient>, default_key_alias: impl Into<String>) -> Self {
        Self {
            client,
            default_key_alias: default_key_alias.into(),
        }
    }

    pub fn default_production() -> Result<Self, PostgresError> {
        let client = Arc::new(PostgresClient::new(PostgresClientConfig::default())?);
        Ok(Self::new(client, "postgres_password"))
    }

    pub fn loopback_test() -> Result<Self, PostgresError> {
        let client = Arc::new(PostgresClient::new(PostgresClientConfig::loopback_test())?);
        Ok(Self::new(client, "postgres_password"))
    }

    pub fn client(&self) -> &Arc<PostgresClient> {
        &self.client
    }

    pub fn extract_execution_plan(
        canonical_action: &CanonicalAction,
    ) -> Result<
        (
            PostgresResource,
            String,
            relay_canonical::NormalizedSql,
            String,
            bool,
        ),
        PostgresError,
    > {
        if canonical_action.tool.namespace != "postgres" {
            return Err(PostgresError::UnsupportedStatement(format!(
                "Non-PostgreSQL tool namespace '{}'",
                canonical_action.tool.namespace
            )));
        }

        let resource = PostgresResource::parse(canonical_action.resource.as_str())?;

        let canonical_sql = canonical_action
            .canonical_arguments
            .get("query")
            .or_else(|| canonical_action.canonical_arguments.get("sql"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| PostgresError::InvalidArguments {
                operation: canonical_action.tool.name.clone(),
                reason: "Missing required 'query' argument in canonical arguments".to_string(),
            })?;

        // Re-derive metadata from canonical SQL only (not raw MCP input).
        let normalized = SqlNormalizer::normalize(canonical_sql).map_err(|e| {
            PostgresError::UnsupportedStatement(format!("Canonical SQL invalid at execution: {e}"))
        })?;

        if normalized.canonical_sql != canonical_sql {
            return Err(PostgresError::UnsupportedStatement(
                "Canonical SQL divergence detected between stored arguments and AST metadata"
                    .to_string(),
            ));
        }

        validate_supported_surface(canonical_sql)?;
        validate_operation_class(&canonical_action.tool.name, normalized.operation)?;

        // Cross-validate host/database arguments cannot redirect execution.
        if let Some(arg_host) = canonical_action
            .canonical_arguments
            .get("host")
            .and_then(|v| v.as_str())
        {
            if arg_host != resource.host {
                return Err(PostgresError::ResourceMismatch {
                    action_target: canonical_action.resource.as_str().to_string(),
                    op_target: format!(
                        "host argument '{arg_host}' diverges from canonical resource"
                    ),
                });
            }
        }
        if let Some(arg_db) = canonical_action
            .canonical_arguments
            .get("database")
            .and_then(|v| v.as_str())
        {
            if arg_db != resource.database {
                return Err(PostgresError::ResourceMismatch {
                    action_target: canonical_action.resource.as_str().to_string(),
                    op_target: format!(
                        "database argument '{arg_db}' diverges from canonical resource"
                    ),
                });
            }
        }

        let op_name = format!("postgres.{}", canonical_action.tool.name);
        let is_mutating = is_mutating_operation(normalized.operation);

        Ok((
            resource,
            canonical_sql.to_string(),
            normalized,
            op_name,
            is_mutating,
        ))
    }

    pub async fn execute_governed(
        &self,
        canonical_action: &CanonicalAction,
        decision: &PolicyDecision,
        credential_broker: &dyn CredentialBroker,
    ) -> Result<ExecutionResult, ExecutionError> {
        self.execute_governed_with_approval(canonical_action, decision, None, credential_broker)
            .await
    }

    pub async fn execute_governed_with_approval(
        &self,
        canonical_action: &CanonicalAction,
        decision: &PolicyDecision,
        approval: Option<&Approval>,
        credential_broker: &dyn CredentialBroker,
    ) -> Result<ExecutionResult, ExecutionError> {
        if decision.decision == PolicyDecisionType::ApprovalRequired {
            match approval {
                Some(appr) => {
                    if appr.action_hash != canonical_action.action_hash {
                        return Err(PostgresError::ActionHashMismatch {
                            expected: canonical_action.action_hash.to_hex(),
                            actual: appr.action_hash.to_hex(),
                        }
                        .into());
                    }
                    if appr.state != ApprovalState::Approved {
                        return Err(PostgresError::UnauthorizedExecution.into());
                    }
                    if appr.is_expired() {
                        return Err(PostgresError::UnauthorizedExecution.into());
                    }
                }
                None => {
                    return Err(PostgresError::UnauthorizedExecution.into());
                }
            }
        } else if decision.decision != PolicyDecisionType::Allow {
            return Err(PostgresError::UnauthorizedExecution.into());
        }

        let effective_decision =
            if decision.decision == PolicyDecisionType::ApprovalRequired && approval.is_some() {
                let mut d = decision.clone();
                d.decision = PolicyDecisionType::Allow;
                d
            } else {
                decision.clone()
            };

        if canonical_action.action_hash != decision.action_hash {
            return Err(PostgresError::ActionHashMismatch {
                expected: decision.action_hash.to_hex(),
                actual: canonical_action.action_hash.to_hex(),
            }
            .into());
        }

        let (resource, canonical_sql, normalized, op_name, is_mutating) =
            Self::extract_execution_plan(canonical_action)?;

        validate_table_scope(
            &resource,
            &normalized,
            &self.client.config().fixed_search_path,
        )?;

        let cred_req = CredentialRequest::new(
            canonical_action.action_hash,
            canonical_action.principal.clone(),
            canonical_action.resource.clone(),
            CredentialProviderType::KeyringStatic,
            self.default_key_alias.clone(),
            "postgres",
            canonical_action.resource.as_str(),
            60,
        );

        let (lease, secret) = credential_broker
            .acquire_lease(&cred_req, &effective_decision)
            .await
            .map_err(|e| PostgresError::CredentialError(e.to_string()))?;

        if let Err(err) = Self::validate_lease(canonical_action, &lease) {
            let _ = credential_broker.consume_lease(&lease.lease_id).await;
            return Err(err.into());
        }

        let credentials = match PostgresCredentials::from_secret_bytes(secret.as_bytes()) {
            Ok(creds) => creds,
            Err(err) => {
                let _ = credential_broker.consume_lease(&lease.lease_id).await;
                return Err(err.into());
            }
        };

        let dispatch_result = self
            .client
            .execute_statement(
                &resource,
                &credentials,
                &canonical_sql,
                normalized.operation,
                &op_name,
                is_mutating,
            )
            .await;

        let _ = credential_broker.consume_lease(&lease.lease_id).await;
        drop(secret);

        match dispatch_result {
            Ok(resp) => {
                let preview = format!(
                    "PostgreSQL {} on {}/{} succeeded ({} rows)",
                    op_name, resource.host, resource.database, resp.row_count
                );
                Ok(ExecutionResult::success(&resp.body, preview))
            }
            Err(err) => {
                tracing::warn!(operation = %op_name, error = %err, "PostgreSQL connector operation failed");
                Err(err.into())
            }
        }
    }

    pub async fn execute_governed_with_receipt(
        &self,
        canonical_action: &CanonicalAction,
        decision: &PolicyDecision,
        approval: Option<&Approval>,
        credential_broker: &dyn CredentialBroker,
        signer: &Ed25519ReceiptSigner,
    ) -> Result<(ExecutionResult, ActionReceipt), (ExecutionError, Option<ActionReceipt>)> {
        if decision.decision == PolicyDecisionType::ApprovalRequired {
            match approval {
                Some(appr) => {
                    if appr.action_hash != canonical_action.action_hash {
                        return Err((
                            PostgresError::ActionHashMismatch {
                                expected: canonical_action.action_hash.to_hex(),
                                actual: appr.action_hash.to_hex(),
                            }
                            .into(),
                            None,
                        ));
                    }
                    if appr.state != ApprovalState::Approved {
                        return Err((PostgresError::UnauthorizedExecution.into(), None));
                    }
                    if appr.is_expired() {
                        return Err((PostgresError::UnauthorizedExecution.into(), None));
                    }
                }
                None => {
                    return Err((PostgresError::UnauthorizedExecution.into(), None));
                }
            }
        } else if decision.decision != PolicyDecisionType::Allow {
            return Err((PostgresError::UnauthorizedExecution.into(), None));
        }

        let effective_decision =
            if decision.decision == PolicyDecisionType::ApprovalRequired && approval.is_some() {
                let mut d = decision.clone();
                d.decision = PolicyDecisionType::Allow;
                d
            } else {
                decision.clone()
            };

        if canonical_action.action_hash != decision.action_hash {
            return Err((
                PostgresError::ActionHashMismatch {
                    expected: decision.action_hash.to_hex(),
                    actual: canonical_action.action_hash.to_hex(),
                }
                .into(),
                None,
            ));
        }

        let (resource, canonical_sql, normalized, op_name, is_mutating) =
            match Self::extract_execution_plan(canonical_action) {
                Ok(plan) => plan,
                Err(err) => return Err((err.into(), None)),
            };

        if let Err(err) = validate_table_scope(
            &resource,
            &normalized,
            &self.client.config().fixed_search_path,
        ) {
            return Err((err.into(), None));
        }

        let cred_req = CredentialRequest::new(
            canonical_action.action_hash,
            canonical_action.principal.clone(),
            canonical_action.resource.clone(),
            CredentialProviderType::KeyringStatic,
            self.default_key_alias.clone(),
            "postgres",
            canonical_action.resource.as_str(),
            60,
        );

        let (lease, secret) = match credential_broker
            .acquire_lease(&cred_req, &effective_decision)
            .await
        {
            Ok(pair) => pair,
            Err(e) => return Err((PostgresError::CredentialError(e.to_string()).into(), None)),
        };

        if let Err(err) = Self::validate_lease(canonical_action, &lease) {
            let _ = credential_broker.consume_lease(&lease.lease_id).await;
            return Err((err.into(), None));
        }

        let credentials = match PostgresCredentials::from_secret_bytes(secret.as_bytes()) {
            Ok(creds) => creds,
            Err(err) => {
                let _ = credential_broker.consume_lease(&lease.lease_id).await;
                return Err((err.into(), None));
            }
        };

        let execution_id = ExecutionId::new_v7();
        let started_at = chrono::Utc::now();
        let start_instant = std::time::Instant::now();
        let endpoint = format!("postgres://{}/{}", resource.host, resource.database);

        let dispatch_result = self
            .client
            .execute_statement(
                &resource,
                &credentials,
                &canonical_sql,
                normalized.operation,
                &op_name,
                is_mutating,
            )
            .await;

        let completed_at = chrono::Utc::now();
        let duration_ms = start_instant.elapsed().as_millis() as u64;
        let _ = credential_broker.consume_lease(&lease.lease_id).await;
        drop(secret);

        let (
            obs_status,
            exit_code,
            stdout_digest,
            byte_count,
            preview,
            is_ambiguous,
            retry_class,
            error_class,
            exec_outcome,
        ) = match dispatch_result {
            Ok(resp) => {
                let digest = OutputHash::compute(&resp.body);
                let count = resp.body.len();
                let prev = format!(
                    "PostgreSQL {} on {}/{} succeeded ({})",
                    op_name, resource.host, resource.database, resp.command_tag
                );
                let exec_res = ExecutionResult::success(&resp.body, prev.clone());
                (
                    ExecutionObservationStatus::Success,
                    0,
                    digest,
                    count,
                    prev,
                    false,
                    "IdempotentSafeToRetry".to_string(),
                    None,
                    Ok(exec_res),
                )
            }
            Err(err) => {
                let exec_err: ExecutionError = err.clone().into();
                match &err {
                    PostgresError::AmbiguousMutationOutcome { operation, reason } => (
                        ExecutionObservationStatus::AmbiguousMutation,
                        1,
                        OutputHash::compute(b""),
                        0,
                        format!("Ambiguous mutation for {operation}: {reason}"),
                        true,
                        "AmbiguousRequiresVerification".to_string(),
                        Some("AmbiguousMutationOutcome".to_string()),
                        Err(exec_err),
                    ),
                    PostgresError::Timeout { timeout_ms } => (
                        ExecutionObservationStatus::TransportError,
                        1,
                        OutputHash::compute(b""),
                        0,
                        format!("Query timed out after {timeout_ms}ms"),
                        false,
                        if is_mutating {
                            "AmbiguousRequiresVerification".to_string()
                        } else {
                            "IdempotentSafeToRetry".to_string()
                        },
                        Some("Timeout".to_string()),
                        Err(exec_err),
                    ),
                    PostgresError::AuthenticationFailed => (
                        ExecutionObservationStatus::TargetError,
                        1,
                        OutputHash::compute(b""),
                        0,
                        "PostgreSQL authentication failed".to_string(),
                        false,
                        "NonRetryableFatal".to_string(),
                        Some("AuthenticationFailed".to_string()),
                        Err(exec_err),
                    ),
                    PostgresError::AuthorizationFailed(msg) => (
                        ExecutionObservationStatus::TargetError,
                        1,
                        OutputHash::compute(msg.as_bytes()),
                        msg.len(),
                        format!("PostgreSQL permission denied: {msg}"),
                        false,
                        "NonRetryableFatal".to_string(),
                        Some("AuthorizationFailed".to_string()),
                        Err(exec_err),
                    ),
                    other => (
                        ExecutionObservationStatus::TargetError,
                        1,
                        OutputHash::compute(b""),
                        0,
                        other.to_string(),
                        false,
                        "NonRetryableFatal".to_string(),
                        Some("TargetError".to_string()),
                        Err(exec_err),
                    ),
                }
            }
        };

        let builder = ActionReceiptBuilder::new(canonical_action, &effective_decision)
            .with_approval(approval)
            .with_credential_lease(Some(&lease))
            .with_execution_metadata(
                execution_id,
                ExecutionRoute::Native,
                "postgres",
                &canonical_action.tool.name,
                canonical_action.resource.as_str(),
                Some("SQL".to_string()),
                Some(endpoint),
                started_at,
                Some(completed_at),
                Some(duration_ms),
            )
            .with_observation(
                obs_status,
                exit_code,
                stdout_digest,
                None,
                byte_count,
                None,
                preview,
                is_ambiguous,
                retry_class,
                error_class,
            );

        let receipt = match builder.build_and_sign(signer) {
            Ok(r) => r,
            Err(e) => {
                return Err((
                    ExecutionError::ConnectorFailed {
                        connector: "postgres".to_string(),
                        reason: format!("Failed to sign receipt: {e}"),
                    },
                    None,
                ));
            }
        };

        match exec_outcome {
            Ok(exec_res) => Ok((exec_res, receipt)),
            Err(err) => Err((err, Some(receipt))),
        }
    }

    fn validate_lease(
        canonical_action: &CanonicalAction,
        lease: &relay_domain::CredentialLease,
    ) -> Result<(), PostgresError> {
        if lease.action_hash != canonical_action.action_hash {
            return Err(PostgresError::ActionHashMismatch {
                expected: canonical_action.action_hash.to_hex(),
                actual: lease.action_hash.to_hex(),
            });
        }
        if lease.principal != canonical_action.principal {
            return Err(PostgresError::PrincipalMismatch {
                lease_principal: lease.principal.as_str().to_string(),
                action_principal: canonical_action.principal.as_str().to_string(),
            });
        }
        if lease.scoped_resource != canonical_action.resource.as_str() {
            return Err(PostgresError::ResourceMismatch {
                action_target: canonical_action.resource.as_str().to_string(),
                op_target: lease.scoped_resource.clone(),
            });
        }
        if !lease.is_active() || lease.is_expired() {
            return Err(PostgresError::InvalidLease(
                "Credential lease is inactive or expired".to_string(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl NativeConnector for PostgresConnector {
    fn namespace(&self) -> &'static str {
        "postgres"
    }

    async fn execute(
        &self,
        _tool_name: &str,
        _canonical_args: &serde_json::Value,
        _secret: Option<&SecretBuffer>,
    ) -> Result<ExecutionResult, ExecutionError> {
        Err(ExecutionError::ConnectorFailed {
            connector: "postgres".to_string(),
            reason: "Direct NativeConnector::execute is forbidden; use execute_governed pipeline"
                .to_string(),
        })
    }
}
