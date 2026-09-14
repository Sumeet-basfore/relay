//! Native GitHub Connector implementing in-process governed tool execution.
//!
//! Enforces:
//! - Complete mediation: MUST NOT be reachable without prior Cedar ALLOW and CredentialBroker lease
//! - ActionHash binding (SI-006): Verifies canonical action hash matches policy decision and credential lease
//! - Single-use lease consumption: Consumes the ephemeral credential lease immediately after dispatch
//! - Zero credentials passed to child processes or agent contexts (SI-001)
//! - Bounded semantic operations: No arbitrary HTTP request passthrough

use async_trait::async_trait;
use std::sync::Arc;

use super::client::{GitHubClient, GitHubClientConfig};
use super::error::GitHubError;
use super::operations::GitHubOperation;

use relay_canonical::{CanonicalAction, GitHubNormalizer, ToolIdentity};
use relay_domain::{
    ActionReceipt, Approval, ApprovalState, CredentialBroker, CredentialProviderType,
    CredentialRequest, ExecutionError, ExecutionId, ExecutionObservationStatus, ExecutionResult,
    ExecutionRoute, NativeConnector, OutputHash, PolicyDecision, PolicyDecisionType, SecretBuffer,
};
use relay_receipts::{ActionReceiptBuilder, Ed25519ReceiptSigner};

/// Production-ready Native GitHub Connector for Relay.
#[derive(Clone)]
pub struct GitHubConnector {
    client: Arc<GitHubClient>,
    default_key_alias: String,
}

impl GitHubConnector {
    /// Creates a new GitHubConnector with custom client and secret key alias.
    pub fn new(client: Arc<GitHubClient>, default_key_alias: impl Into<String>) -> Self {
        Self {
            client,
            default_key_alias: default_key_alias.into(),
        }
    }

    /// Creates a production connector pointing to official GitHub API.
    pub fn default_production() -> Result<Self, GitHubError> {
        let client = Arc::new(GitHubClient::new(GitHubClientConfig::default())?);
        Ok(Self::new(client, "github_token"))
    }

    /// Returns the underlying HTTP client.
    pub fn client(&self) -> &Arc<GitHubClient> {
        &self.client
    }

    /// Executes an already-authorized CanonicalAction using the CredentialBroker pipeline.
    ///
    /// The complete governed sequence:
    /// 1. Validate policy decision (MUST be Allow; Deny and ApprovalRequired fail closed)
    /// 2. Verify ActionHash binding: `canonical_action.action_hash == decision.action_hash`
    /// 3. Verify namespace is "github"
    /// 4. Normalize and validate repository target from canonical `ResourceUri`
    /// 5. Parse and validate strongly typed `GitHubOperation`
    /// 6. Acquire ephemeral credential lease from `CredentialBroker`
    /// 7. Verify lease properties (`action_hash`, `principal`, `scope`, `is_active`)
    /// 8. Dispatch HTTP request with JIT header injection
    /// 9. Consume lease immediately (single-action bound) and zeroize secret
    /// 10. Return governed `ExecutionResult`
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
        // 1. Validate policy authorization
        if decision.decision == PolicyDecisionType::ApprovalRequired {
            match approval {
                Some(appr) => {
                    if appr.action_hash != canonical_action.action_hash {
                        return Err(GitHubError::ActionHashMismatch {
                            expected: canonical_action.action_hash.to_hex(),
                            actual: appr.action_hash.to_hex(),
                        }
                        .into());
                    }
                    if appr.state != ApprovalState::Approved {
                        return Err(GitHubError::UnauthorizedExecution.into());
                    }
                    if appr.is_expired() {
                        return Err(GitHubError::UnauthorizedExecution.into());
                    }
                }
                None => {
                    return Err(GitHubError::UnauthorizedExecution.into());
                }
            }
        } else if decision.decision != PolicyDecisionType::Allow {
            tracing::warn!(
                action_hash = %decision.action_hash.to_hex(),
                decision = ?decision.decision,
                "GitHub connector called without PolicyDecision::Allow; rejecting execution (SI-002)"
            );
            return Err(GitHubError::UnauthorizedExecution.into());
        }

        let effective_decision =
            if decision.decision == PolicyDecisionType::ApprovalRequired && approval.is_some() {
                let mut d = decision.clone();
                d.decision = PolicyDecisionType::Allow;
                d
            } else {
                decision.clone()
            };

        // 2. Enforce ActionHash equivalence (SI-005, SI-006)
        if canonical_action.action_hash != decision.action_hash {
            tracing::error!(
                action_hash = %canonical_action.action_hash.to_hex(),
                decision_hash = %decision.action_hash.to_hex(),
                "ActionHash divergence between CanonicalAction and PolicyDecision (SI-005)"
            );
            return Err(GitHubError::ActionHashMismatch {
                expected: decision.action_hash.to_hex(),
                actual: canonical_action.action_hash.to_hex(),
            }
            .into());
        }

        // 3. Verify namespace
        if canonical_action.tool.namespace != "github" {
            return Err(GitHubError::UnsupportedOperation(format!(
                "Non-GitHub tool namespace '{}'",
                canonical_action.tool.namespace
            ))
            .into());
        }

        // 4. Extract and validate repository identity from canonical ResourceUri
        let norm_res =
            GitHubNormalizer::parse(canonical_action.resource.as_str()).map_err(|e| {
                GitHubError::ResourceMismatch {
                    action_target: canonical_action.resource.as_str().to_string(),
                    op_target: format!("Invalid canonical GitHub resource: {e}"),
                }
            })?;

        let owner = norm_res.owner;
        let repo = norm_res.repo;

        // Verify that if repo/repository is specified in canonical_arguments, it matches the resource
        if let Some(arg_repo) = canonical_action
            .canonical_arguments
            .get("repo")
            .or_else(|| canonical_action.canonical_arguments.get("repository"))
            .and_then(|v| v.as_str())
        {
            if let Ok(arg_norm) = GitHubNormalizer::parse(arg_repo) {
                if arg_norm.owner != owner || arg_norm.repo != repo {
                    return Err(GitHubError::ResourceMismatch {
                        action_target: canonical_action.resource.as_str().to_string(),
                        op_target: format!("{}/{}", arg_norm.owner, arg_norm.repo),
                    }
                    .into());
                }
            }
        }

        // 5. Parse and validate typed operation
        let operation = GitHubOperation::from_canonical_action(canonical_action)?;
        let method = operation.http_method();
        let path = operation.endpoint_path(&owner, &repo);
        let body = operation.serialize_body()?;
        let is_mutating = operation.is_mutating();
        let op_name = operation.operation_name();

        // 6. Acquire ephemeral credential lease from CredentialBroker (SI-006)
        let cred_req = CredentialRequest::new(
            canonical_action.action_hash,
            canonical_action.principal.clone(),
            canonical_action.resource.clone(),
            CredentialProviderType::KeyringStatic,
            self.default_key_alias.clone(),
            "github",
            canonical_action.resource.as_str(),
            60, // 60s single-action TTL
        );

        let (lease, secret) = credential_broker
            .acquire_lease(&cred_req, &effective_decision)
            .await
            .map_err(|e| GitHubError::CredentialError(e.to_string()))?;

        // 7. Validate in-flight lease invariants
        if lease.action_hash != canonical_action.action_hash {
            let _ = credential_broker.consume_lease(&lease.lease_id).await;
            return Err(GitHubError::ActionHashMismatch {
                expected: canonical_action.action_hash.to_hex(),
                actual: lease.action_hash.to_hex(),
            }
            .into());
        }

        if lease.principal != canonical_action.principal {
            let _ = credential_broker.consume_lease(&lease.lease_id).await;
            return Err(GitHubError::PrincipalMismatch {
                lease_principal: lease.principal.as_str().to_string(),
                action_principal: canonical_action.principal.as_str().to_string(),
            }
            .into());
        }

        if lease.scoped_resource != canonical_action.resource.as_str() {
            let _ = credential_broker.consume_lease(&lease.lease_id).await;
            return Err(GitHubError::ResourceMismatch {
                action_target: canonical_action.resource.as_str().to_string(),
                op_target: lease.scoped_resource,
            }
            .into());
        }

        if !lease.is_active() || lease.is_expired() {
            let _ = credential_broker.consume_lease(&lease.lease_id).await;
            return Err(GitHubError::InvalidLease(
                "Credential lease is inactive or expired".to_string(),
            )
            .into());
        }

        // 8. Execute HTTP network request with JIT credential injection
        let dispatch_result = self
            .client
            .execute_request(method, &path, body, &secret, is_mutating, op_name)
            .await;

        // 9. Consume lease immediately post-execution (SI-006 single-action destruction)
        let _ = credential_broker.consume_lease(&lease.lease_id).await;
        drop(secret); // Memory zeroized and unlocked

        // 10. Map response into ExecutionResult
        match dispatch_result {
            Ok(resp) => {
                let preview = format!(
                    "GitHub {} on {}/{} succeeded (HTTP {})",
                    op_name,
                    owner,
                    repo,
                    resp.status.as_u16()
                );
                Ok(ExecutionResult::success(&resp.body, preview))
            }
            Err(err) => {
                tracing::warn!(
                    operation = op_name,
                    error = %err,
                    "GitHub connector operation failed"
                );
                Err(err.into())
            }
        }
    }

    /// Executes an already-authorized CanonicalAction using the CredentialBroker pipeline
    /// and generates a cryptographically signed ActionReceipt with DSSE envelope.
    ///
    /// Returns:
    /// - `Ok((ExecutionResult, ActionReceipt))` on successful execution and observation.
    /// - `Err((ExecutionError, Some(ActionReceipt)))` when the request was dispatched to the
    ///   network and failed (e.g. HTTP 4xx/5xx error, timeout, or AmbiguousMutation). The receipt
    ///   cryptographically attests to the dispatched attempt and observed outcome.
    /// - `Err((ExecutionError, None))` when execution was aborted pre-dispatch (e.g. policy Deny,
    ///   ActionHash mismatch, lease failure).
    pub async fn execute_governed_with_receipt(
        &self,
        canonical_action: &CanonicalAction,
        decision: &PolicyDecision,
        approval: Option<&Approval>,
        credential_broker: &dyn CredentialBroker,
        signer: &Ed25519ReceiptSigner,
    ) -> Result<(ExecutionResult, ActionReceipt), (ExecutionError, Option<ActionReceipt>)> {
        // 1. Validate policy authorization (fails closed on Deny / ApprovalRequired without approval)
        if decision.decision == PolicyDecisionType::ApprovalRequired {
            match approval {
                Some(appr) => {
                    if appr.action_hash != canonical_action.action_hash {
                        return Err((
                            GitHubError::ActionHashMismatch {
                                expected: canonical_action.action_hash.to_hex(),
                                actual: appr.action_hash.to_hex(),
                            }
                            .into(),
                            None,
                        ));
                    }
                    if appr.state != ApprovalState::Approved {
                        return Err((GitHubError::UnauthorizedExecution.into(), None));
                    }
                    if appr.is_expired() {
                        return Err((GitHubError::UnauthorizedExecution.into(), None));
                    }
                }
                None => {
                    return Err((GitHubError::UnauthorizedExecution.into(), None));
                }
            }
        } else if decision.decision != PolicyDecisionType::Allow {
            tracing::warn!(
                action_hash = %decision.action_hash.to_hex(),
                decision = ?decision.decision,
                "GitHub connector called without PolicyDecision::Allow; rejecting execution (SI-002)"
            );
            return Err((GitHubError::UnauthorizedExecution.into(), None));
        }

        let effective_decision =
            if decision.decision == PolicyDecisionType::ApprovalRequired && approval.is_some() {
                let mut d = decision.clone();
                d.decision = PolicyDecisionType::Allow;
                d
            } else {
                decision.clone()
            };

        // 2. Enforce ActionHash equivalence (SI-005, SI-006)
        if canonical_action.action_hash != decision.action_hash {
            tracing::error!(
                action_hash = %canonical_action.action_hash.to_hex(),
                decision_hash = %decision.action_hash.to_hex(),
                "ActionHash divergence between CanonicalAction and PolicyDecision (SI-005)"
            );
            return Err((
                GitHubError::ActionHashMismatch {
                    expected: decision.action_hash.to_hex(),
                    actual: canonical_action.action_hash.to_hex(),
                }
                .into(),
                None,
            ));
        }

        // 4. Verify namespace
        if canonical_action.tool.namespace != "github" {
            return Err((
                GitHubError::UnsupportedOperation(format!(
                    "Non-GitHub tool namespace '{}'",
                    canonical_action.tool.namespace
                ))
                .into(),
                None,
            ));
        }

        // 5. Extract and validate repository identity from canonical ResourceUri
        let norm_res = match GitHubNormalizer::parse(canonical_action.resource.as_str()) {
            Ok(nr) => nr,
            Err(e) => {
                return Err((
                    GitHubError::ResourceMismatch {
                        action_target: canonical_action.resource.as_str().to_string(),
                        op_target: format!("Invalid canonical GitHub resource: {e}"),
                    }
                    .into(),
                    None,
                ));
            }
        };

        let owner = norm_res.owner;
        let repo = norm_res.repo;

        // Verify that if repo/repository is specified in canonical_arguments, it matches the resource
        if let Some(arg_repo) = canonical_action
            .canonical_arguments
            .get("repo")
            .or_else(|| canonical_action.canonical_arguments.get("repository"))
            .and_then(|v| v.as_str())
        {
            if let Ok(arg_norm) = GitHubNormalizer::parse(arg_repo) {
                if arg_norm.owner != owner || arg_norm.repo != repo {
                    return Err((
                        GitHubError::ResourceMismatch {
                            action_target: canonical_action.resource.as_str().to_string(),
                            op_target: format!("{}/{}", arg_norm.owner, arg_norm.repo),
                        }
                        .into(),
                        None,
                    ));
                }
            }
        }

        // 6. Parse and validate typed operation
        let operation = match GitHubOperation::from_canonical_action(canonical_action) {
            Ok(op) => op,
            Err(e) => return Err((e.into(), None)),
        };
        let method = operation.http_method();
        let path = operation.endpoint_path(&owner, &repo);
        let body = match operation.serialize_body() {
            Ok(b) => b,
            Err(e) => return Err((e.into(), None)),
        };
        let is_mutating = operation.is_mutating();
        let op_name = operation.operation_name();

        // 7. Acquire ephemeral credential lease from CredentialBroker (SI-006)
        let cred_req = CredentialRequest::new(
            canonical_action.action_hash,
            canonical_action.principal.clone(),
            canonical_action.resource.clone(),
            CredentialProviderType::KeyringStatic,
            self.default_key_alias.clone(),
            "github",
            canonical_action.resource.as_str(),
            60, // 60s single-action TTL
        );

        let (lease, secret) = match credential_broker
            .acquire_lease(&cred_req, &effective_decision)
            .await
        {
            Ok(pair) => pair,
            Err(e) => return Err((GitHubError::CredentialError(e.to_string()).into(), None)),
        };

        // 8. Validate in-flight lease invariants
        if lease.action_hash != canonical_action.action_hash {
            let _ = credential_broker.consume_lease(&lease.lease_id).await;
            return Err((
                GitHubError::ActionHashMismatch {
                    expected: canonical_action.action_hash.to_hex(),
                    actual: lease.action_hash.to_hex(),
                }
                .into(),
                None,
            ));
        }

        if lease.principal != canonical_action.principal {
            let _ = credential_broker.consume_lease(&lease.lease_id).await;
            return Err((
                GitHubError::PrincipalMismatch {
                    lease_principal: lease.principal.as_str().to_string(),
                    action_principal: canonical_action.principal.as_str().to_string(),
                }
                .into(),
                None,
            ));
        }

        if lease.scoped_resource != canonical_action.resource.as_str() {
            let _ = credential_broker.consume_lease(&lease.lease_id).await;
            return Err((
                GitHubError::ResourceMismatch {
                    action_target: canonical_action.resource.as_str().to_string(),
                    op_target: lease.scoped_resource,
                }
                .into(),
                None,
            ));
        }

        if !lease.is_active() || lease.is_expired() {
            let _ = credential_broker.consume_lease(&lease.lease_id).await;
            return Err((
                GitHubError::InvalidLease("Credential lease is inactive or expired".to_string())
                    .into(),
                None,
            ));
        }

        // 9. Execute HTTP network request with JIT credential injection
        let execution_id = ExecutionId::new_v7();
        let started_at = chrono::Utc::now();
        let start_instant = std::time::Instant::now();
        let endpoint_url = format!(
            "{}{}",
            self.client.config().base_url.trim_end_matches('/'),
            path
        );

        let dispatch_result = self
            .client
            .execute_request(method.clone(), &path, body, &secret, is_mutating, op_name)
            .await;

        let completed_at = chrono::Utc::now();
        let duration_ms = start_instant.elapsed().as_millis() as u64;

        // 10. Consume lease immediately post-execution (SI-006 single-action destruction)
        let _ = credential_broker.consume_lease(&lease.lease_id).await;
        drop(secret); // Memory zeroized and unlocked

        // 11. Classify observation evidence and execution outcome
        let (
            obs_status,
            exit_code,
            stdout_digest,
            byte_count,
            http_code,
            preview,
            is_ambiguous,
            retry_class,
            error_class,
            exec_outcome,
        ) = match dispatch_result {
            Ok(resp) => {
                let digest = OutputHash::compute(&resp.body);
                let count = resp.body.len();
                let status_code = resp.status.as_u16();
                let prev = format!(
                    "GitHub {} on {}/{} succeeded (HTTP {})",
                    op_name, owner, repo, status_code
                );
                let exec_res = ExecutionResult::success(&resp.body, prev.clone());
                (
                    ExecutionObservationStatus::Success,
                    0,
                    digest,
                    count,
                    Some(status_code),
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
                    GitHubError::AmbiguousMutationOutcome { operation, reason } => (
                        ExecutionObservationStatus::AmbiguousMutation,
                        1,
                        OutputHash::compute(b""),
                        0,
                        None,
                        format!("Ambiguous mutation for {operation}: {reason}"),
                        true,
                        "AmbiguousRequiresVerification".to_string(),
                        Some("AmbiguousMutationOutcome".to_string()),
                        Err(exec_err),
                    ),
                    GitHubError::Timeout { timeout_ms } => (
                        ExecutionObservationStatus::TransportError,
                        1,
                        OutputHash::compute(b""),
                        0,
                        None,
                        format!("Request timed out after {timeout_ms}ms"),
                        false,
                        "IdempotentSafeToRetry".to_string(),
                        Some("Timeout".to_string()),
                        Err(exec_err),
                    ),
                    GitHubError::NetworkFailure(msg) => (
                        ExecutionObservationStatus::TransportError,
                        1,
                        OutputHash::compute(b""),
                        0,
                        None,
                        format!("Network failure: {msg}"),
                        false,
                        "IdempotentSafeToRetry".to_string(),
                        Some("NetworkFailure".to_string()),
                        Err(exec_err),
                    ),
                    GitHubError::TlsFailure(msg) => (
                        ExecutionObservationStatus::TransportError,
                        1,
                        OutputHash::compute(b""),
                        0,
                        None,
                        format!("TLS failure: {msg}"),
                        false,
                        "NonRetryableFatal".to_string(),
                        Some("TlsFailure".to_string()),
                        Err(exec_err),
                    ),
                    GitHubError::AuthenticationFailed => (
                        ExecutionObservationStatus::TargetError,
                        1,
                        OutputHash::compute(b""),
                        0,
                        Some(401),
                        "Authentication failed: Bad credentials or expired token".to_string(),
                        false,
                        "NonRetryableFatal".to_string(),
                        Some("AuthenticationFailed".to_string()),
                        Err(exec_err),
                    ),
                    GitHubError::AuthorizationFailed(body) => (
                        ExecutionObservationStatus::TargetError,
                        1,
                        OutputHash::compute(body.as_bytes()),
                        body.len(),
                        Some(403),
                        format!("Authorization failed: {body}"),
                        false,
                        "NonRetryableFatal".to_string(),
                        Some("AuthorizationFailed".to_string()),
                        Err(exec_err),
                    ),
                    GitHubError::NotFound(body) => (
                        ExecutionObservationStatus::TargetError,
                        1,
                        OutputHash::compute(body.as_bytes()),
                        body.len(),
                        Some(404),
                        format!("Resource not found: {body}"),
                        false,
                        "NonRetryableFatal".to_string(),
                        Some("NotFound".to_string()),
                        Err(exec_err),
                    ),
                    GitHubError::Conflict(body) => (
                        ExecutionObservationStatus::TargetError,
                        1,
                        OutputHash::compute(body.as_bytes()),
                        body.len(),
                        Some(409),
                        format!("Conflict: {body}"),
                        false,
                        "StateConflictManualResolution".to_string(),
                        Some("Conflict".to_string()),
                        Err(exec_err),
                    ),
                    GitHubError::ValidationError(body) => (
                        ExecutionObservationStatus::TargetError,
                        1,
                        OutputHash::compute(body.as_bytes()),
                        body.len(),
                        Some(422),
                        format!("Validation error: {body}"),
                        false,
                        "NonRetryableFatal".to_string(),
                        Some("ValidationError".to_string()),
                        Err(exec_err),
                    ),
                    GitHubError::RateLimited { message, .. } => (
                        ExecutionObservationStatus::TargetError,
                        1,
                        OutputHash::compute(message.as_bytes()),
                        message.len(),
                        Some(429),
                        format!("Rate limited: {message}"),
                        false,
                        "BackoffAndRetry".to_string(),
                        Some("RateLimited".to_string()),
                        Err(exec_err),
                    ),
                    GitHubError::ServerError { status, message } => (
                        ExecutionObservationStatus::TargetError,
                        1,
                        OutputHash::compute(message.as_bytes()),
                        message.len(),
                        Some(*status),
                        format!("Server error (HTTP {status}): {message}"),
                        false,
                        "TransientServerRetry".to_string(),
                        Some("ServerError".to_string()),
                        Err(exec_err),
                    ),
                    other => (
                        ExecutionObservationStatus::TargetError,
                        1,
                        OutputHash::compute(b""),
                        0,
                        None,
                        other.to_string(),
                        false,
                        "NonRetryableFatal".to_string(),
                        Some("TargetError".to_string()),
                        Err(exec_err),
                    ),
                }
            }
        };

        // 12. Build and sign ActionReceipt
        let builder = ActionReceiptBuilder::new(canonical_action, &effective_decision)
            .with_approval(approval)
            .with_credential_lease(Some(&lease))
            .with_execution_metadata(
                execution_id,
                ExecutionRoute::Native,
                "github",
                op_name,
                canonical_action.resource.as_str(),
                Some(method.as_str().to_string()),
                Some(endpoint_url),
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
                http_code,
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
                        connector: "github".to_string(),
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
}

#[async_trait]
impl NativeConnector for GitHubConnector {
    fn namespace(&self) -> &'static str {
        "github"
    }

    async fn execute(
        &self,
        tool_name: &str,
        canonical_args: &serde_json::Value,
        secret: Option<&SecretBuffer>,
    ) -> Result<ExecutionResult, ExecutionError> {
        let secret = secret.ok_or_else(|| ExecutionError::ConnectorFailed {
            connector: "github".to_string(),
            reason: "GitHub connector execution requires authenticated SecretBuffer".to_string(),
        })?;

        // Extract repository identity
        let repo_val = canonical_args
            .get("repo")
            .or_else(|| canonical_args.get("repository"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| ExecutionError::ConnectorFailed {
                connector: "github".to_string(),
                reason: "Missing 'repo' argument in canonical arguments".to_string(),
            })?;

        let norm_res =
            GitHubNormalizer::parse(repo_val).map_err(|e| ExecutionError::ConnectorFailed {
                connector: "github".to_string(),
                reason: format!("Invalid repository identifier: {e}"),
            })?;

        let owner = norm_res.owner;
        let repo = norm_res.repo;

        // Construct synthetic CanonicalAction for operation resolution
        let full_uri = format!("github://github.com/{owner}/{repo}");
        let resource = relay_domain::ResourceUri::parse(&full_uri).map_err(|e| {
            ExecutionError::ConnectorFailed {
                connector: "github".to_string(),
                reason: e.to_string(),
            }
        })?;

        let dummy_action = CanonicalAction {
            action_id: relay_domain::ActionId::new_v7(),
            session_id: relay_domain::SessionId::new_v7(),
            principal: relay_domain::PrincipalId::new("principal:agent:default").unwrap(),
            mcp_method: "tools/call".to_string(),
            tool: ToolIdentity::parse(&format!("github.{tool_name}")).map_err(|e| {
                ExecutionError::ConnectorFailed {
                    connector: "github".to_string(),
                    reason: e.to_string(),
                }
            })?,
            resource,
            canonical_arguments: canonical_args.clone(),
            schema_digest: relay_domain::SchemaDigest::compute(b"{}"),
            environment: relay_domain::ExecutionEnvironment::current(),
            action_hash: relay_domain::ActionHash::compute(b"dummy"),
            canonical_bytes: Vec::new(),
            created_at: chrono::Utc::now(),
        };

        let operation = GitHubOperation::from_canonical_action(&dummy_action)?;
        let method = operation.http_method();
        let path = operation.endpoint_path(&owner, &repo);
        let body = operation.serialize_body()?;
        let is_mutating = operation.is_mutating();
        let op_name = operation.operation_name();

        let resp = self
            .client
            .execute_request(method, &path, body, secret, is_mutating, op_name)
            .await?;

        let preview = format!(
            "GitHub {} on {}/{} succeeded (HTTP {})",
            op_name,
            owner,
            repo,
            resp.status.as_u16()
        );
        Ok(ExecutionResult::success(&resp.body, preview))
    }
}
