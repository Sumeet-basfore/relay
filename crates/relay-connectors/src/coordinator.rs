//! Golden Lifecycle Coordinator for Governed Native Actions.
//!
//! Enforces the canonical Relay execution lifecycle:
//! ```text
//! raw MCP tools/call (or CanonicalAction)
//!       ↓
//! strict parsing / validation
//!       ↓
//! CanonicalAction
//!       ↓
//! Cedar PEP
//!       ↓
//! PolicyDecision
//!       ↓
//! approval provider if required
//!       ↓
//! CredentialBroker if required
//!       ↓
//! NativeConnector
//!       ↓
//! ExecutionResult
//!       ↓
//! ActionReceipt (Ed25519 DSSE)
//!       ↓
//! SQLite Ledger (Append-Only)
//! ```

use std::sync::Arc;

use relay_canonical::CanonicalAction;
use relay_domain::{
    Action, ActionHash, ActionId, ActionReceipt, ActionState, Approval, ApprovalError, ApprovalId,
    ApprovalMechanism, ApprovalProvider, CredentialBroker, CredentialError, DomainError,
    ExecutionError, ExecutionId, ExecutionResult, Ledger, LedgerEntry, PolicyDecision,
    PolicyDecisionType, PolicyEngine, PolicyError, RequestedAction, ToolId,
};
use relay_receipts::Ed25519ReceiptSigner;

use crate::fs::FilesystemConnector;
use crate::github::GitHubConnector;
use crate::postgres::PostgresConnector;

/// Execution target classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionTarget {
    NativeGitHub,
    NativePostgres,
    NativeFilesystem,
    /// Clean architectural boundary reserved for future tier-1 MCP egress proxy.
    ExternalMcp,
}

/// The outcome of an end-to-end governed action execution.
#[derive(Debug, Clone)]
pub struct GovernedExecutionOutcome {
    pub action_id: ActionId,
    pub action_hash: ActionHash,
    pub decision: PolicyDecision,
    pub approval: Option<Approval>,
    pub execution_result: ExecutionResult,
    pub receipt: ActionReceipt,
    pub ledger_entry: Option<LedgerEntry>,
    pub ledger_error: Option<String>,
    pub state_history: Vec<ActionState>,
}

/// Strongly-typed errors that can occur during governed action execution.
#[derive(Debug, thiserror::Error)]
pub enum GovernedActionError {
    #[error("Policy denied action: {reason:?}")]
    PolicyDenied {
        decision: Box<PolicyDecision>,
        reason: Option<String>,
    },

    #[error("Policy evaluation failed: {0}")]
    PolicyEvaluationFailed(#[from] PolicyError),

    #[error("Approval required but denied: {0}")]
    ApprovalDenied(String),

    #[error("Approval required but timed out after {timeout_secs}s")]
    ApprovalTimedOut { timeout_secs: u64 },

    #[error("Approval required but failed closed in non-interactive/headless mode")]
    ApprovalHeadlessBlocked,

    #[error("Approval cancelled or failed: {0}")]
    ApprovalFailed(#[from] ApprovalError),

    #[error("Credential acquisition failed: {0}")]
    CredentialFailed(#[from] CredentialError),

    #[error("Unsupported connector namespace: {0}")]
    UnsupportedNamespace(String),

    #[error("Connector '{0}' is not registered")]
    ConnectorNotRegistered(String),

    #[error("Connector execution failed: {error}")]
    ExecutionFailed {
        error: ExecutionError,
        receipt: Option<Box<ActionReceipt>>,
        ledger_entry: Option<Box<LedgerEntry>>,
    },

    #[error("Ambiguous mutation occurred: {error}")]
    AmbiguousMutation {
        error: ExecutionError,
        receipt: Option<Box<ActionReceipt>>,
        ledger_entry: Option<Box<LedgerEntry>>,
    },

    #[error("Action canonicalization error: {0}")]
    CanonicalizationFailed(String),

    #[error("Receipt signing failed: {0}")]
    ReceiptSigningFailed(String),

    #[error("Domain error: {0}")]
    Domain(#[from] DomainError),
}

impl GovernedActionError {
    /// Formats the error into an agent-facing JSON-RPC error response object.
    pub fn to_jsonrpc_error_parts(&self) -> (i32, String, Option<serde_json::Value>) {
        match self {
            GovernedActionError::PolicyDenied { decision, reason } => {
                let r = reason
                    .as_deref()
                    .unwrap_or("Action not permitted by policy");
                let data = serde_json::json!({
                    "action_hash": decision.action_hash.to_hex(),
                    "decision_id": decision.decision_id.to_string(),
                    "determining_policies": decision.determining_policies,
                });
                (-32003, format!("Action Forbidden: {r}"), Some(data))
            }
            GovernedActionError::PolicyEvaluationFailed(err) => {
                let data = serde_json::json!({ "error": err.to_string() });
                (-32002, "Policy evaluation failed".to_string(), Some(data))
            }
            GovernedActionError::ApprovalDenied(reason) => {
                let data = serde_json::json!({ "reason": reason, "denied_by_human": true });
                (
                    -32001,
                    format!("Action rejected by operator approval policy: {reason}"),
                    Some(data),
                )
            }
            GovernedActionError::ApprovalHeadlessBlocked => {
                let data = serde_json::json!({
                    "headless_blocked": true,
                    "exit_code": relay_domain::ExitCode::EXIT_APPROVAL_REQUIRED,
                });
                (
                    -32005,
                    "Approval Required: Action requires human approval but gateway is running in headless mode".to_string(),
                    Some(data),
                )
            }
            GovernedActionError::ApprovalTimedOut { timeout_secs } => {
                let data = serde_json::json!({ "timed_out": true, "timeout_secs": timeout_secs });
                (
                    -32005,
                    format!("Approval Timed Out: Operator did not respond within {timeout_secs}s"),
                    Some(data),
                )
            }
            GovernedActionError::ApprovalFailed(err) => {
                let data = serde_json::json!({ "reason": err.to_string(), "cancelled": true });
                (-32001, format!("Approval Cancelled: {err}"), Some(data))
            }
            GovernedActionError::CredentialFailed(err) => {
                let data = serde_json::json!({ "error": err.to_string() });
                (
                    -32002,
                    "Credential acquisition failed".to_string(),
                    Some(data),
                )
            }
            GovernedActionError::UnsupportedNamespace(ns) => {
                let data = serde_json::json!({ "namespace": ns });
                (
                    -32602,
                    format!("Unsupported connector namespace: {ns}"),
                    Some(data),
                )
            }
            GovernedActionError::ConnectorNotRegistered(name) => {
                let data = serde_json::json!({ "connector": name });
                (
                    -32000,
                    format!("Connector '{name}' is not registered"),
                    Some(data),
                )
            }
            GovernedActionError::AmbiguousMutation { error, .. } => {
                let data = serde_json::json!({
                    "ambiguous_mutation": true,
                    "error": error.to_string(),
                });
                (-32010, format!("Ambiguous Mutation: {error}"), Some(data))
            }
            GovernedActionError::ExecutionFailed { error, .. } => {
                let data = serde_json::json!({ "error": error.to_string() });
                (-32000, format!("Execution Failed: {error}"), Some(data))
            }
            GovernedActionError::CanonicalizationFailed(err) => {
                (-32602, format!("Invalid params: {err}"), None)
            }
            GovernedActionError::ReceiptSigningFailed(err) => {
                let data = serde_json::json!({ "error": err });
                (-32000, "Receipt signing failed".to_string(), Some(data))
            }
            GovernedActionError::Domain(err) => {
                let data = serde_json::json!({ "error": err.to_string() });
                (-32000, format!("Domain error: {err}"), Some(data))
            }
        }
    }
}

/// The central coordinator for Relay governed actions.
#[derive(Clone)]
pub struct GovernedActionRunner {
    policy_engine: Arc<dyn PolicyEngine>,
    approval_provider: Arc<dyn ApprovalProvider>,
    credential_broker: Arc<dyn CredentialBroker>,
    receipt_signer: Arc<Ed25519ReceiptSigner>,
    ledger: Arc<dyn Ledger>,
    github_connector: Option<Arc<GitHubConnector>>,
    postgres_connector: Option<Arc<PostgresConnector>>,
    fs_connector: Option<Arc<FilesystemConnector>>,
}

impl GovernedActionRunner {
    /// Creates a new builder for `GovernedActionRunner`.
    pub fn builder() -> GovernedActionRunnerBuilder {
        GovernedActionRunnerBuilder::default()
    }

    /// Access the underlying policy engine.
    pub fn policy_engine(&self) -> &Arc<dyn PolicyEngine> {
        &self.policy_engine
    }

    /// Access the underlying approval provider.
    pub fn approval_provider(&self) -> &Arc<dyn ApprovalProvider> {
        &self.approval_provider
    }

    /// Access the underlying credential broker.
    pub fn credential_broker(&self) -> &Arc<dyn CredentialBroker> {
        &self.credential_broker
    }

    /// Access the underlying receipt signer.
    pub fn receipt_signer(&self) -> &Arc<Ed25519ReceiptSigner> {
        &self.receipt_signer
    }

    /// Access the underlying audit ledger.
    pub fn ledger(&self) -> &Arc<dyn Ledger> {
        &self.ledger
    }

    /// Checks if a tool namespace corresponds to a registered native connector.
    pub fn is_native_tool(&self, namespace: &str) -> bool {
        match namespace {
            "github" => self.github_connector.is_some(),
            "postgres" => self.postgres_connector.is_some(),
            "fs" | "file" | "filesystem" => self.fs_connector.is_some(),
            _ => false,
        }
    }

    /// Checks if a canonical action targets a registered native connector.
    pub fn is_native_action(&self, action: &CanonicalAction) -> bool {
        self.is_native_tool(&action.tool.namespace)
    }

    /// Resolves the route for a given namespace.
    pub fn resolve_route(&self, namespace: &str) -> Result<ExecutionTarget, GovernedActionError> {
        match namespace {
            "github" => Ok(ExecutionTarget::NativeGitHub),
            "postgres" => Ok(ExecutionTarget::NativePostgres),
            "fs" | "file" | "filesystem" => Ok(ExecutionTarget::NativeFilesystem),
            other => Err(GovernedActionError::UnsupportedNamespace(other.to_string())),
        }
    }

    /// Executes the full governed lifecycle for a canonical action:
    /// Cedar PEP -> Approval -> Credential -> Connector -> Receipt -> Ledger.
    pub async fn run_action(
        &self,
        canonical_action: &CanonicalAction,
    ) -> Result<GovernedExecutionOutcome, GovernedActionError> {
        // 1. Initialize Action aggregate and state history
        let tool_id = ToolId::new(
            &canonical_action.tool.namespace,
            &canonical_action.tool.name,
        )
        .map_err(GovernedActionError::Domain)?;
        let requested = RequestedAction {
            method: "tools/call".to_string(),
            tool_name: canonical_action.tool.to_string(),
            raw_arguments: canonical_action.canonical_arguments.clone(),
        };
        let mut action = Action::new(canonical_action.session_id, tool_id, requested);
        let mut state_history = vec![ActionState::Proposed];

        // 2. Validate namespace is supported and registered (fails closed)
        if !self.is_native_tool(&canonical_action.tool.namespace) {
            return Err(GovernedActionError::UnsupportedNamespace(
                canonical_action.tool.namespace.clone(),
            ));
        }

        // 3. Policy Evaluation: Cedar PEP (SI-002, SI-014)
        let auth_req = canonical_action
            .to_authorization_request()
            .map_err(|e| GovernedActionError::CanonicalizationFailed(e.to_string()))?;

        let decision = self
            .policy_engine
            .evaluate(&auth_req)
            .await
            .map_err(GovernedActionError::PolicyEvaluationFailed)?;

        // Invariant: ActionHash must match between CanonicalAction and PolicyDecision
        if decision.action_hash != canonical_action.action_hash {
            return Err(GovernedActionError::ExecutionFailed {
                error: ExecutionError::ConnectorFailed {
                    connector: "governed_runner".to_string(),
                    reason: format!(
                        "ActionHash mismatch: expected {}, actual {}",
                        canonical_action.action_hash.to_hex(),
                        decision.action_hash.to_hex()
                    ),
                },
                receipt: None,
                ledger_entry: None,
            });
        }

        // 4. Decision Branching: ALLOW, APPROVAL_REQUIRED, or DENY
        let (effective_decision, approval_evidence) = match decision.decision {
            PolicyDecisionType::Deny => {
                let _ = action.mark_rejected();
                let _ = action.settle();
                state_history.push(ActionState::Rejected);
                state_history.push(ActionState::Settled);
                let reason = decision.reason.clone();
                return Err(GovernedActionError::PolicyDenied {
                    decision: Box::new(decision),
                    reason,
                });
            }
            PolicyDecisionType::ApprovalRequired => {
                let approval_id = ApprovalId::new_v7();
                action.mark_awaiting_approval(
                    canonical_action.action_hash,
                    decision.decision_id,
                    approval_id,
                )?;
                state_history.push(ActionState::AwaitingApproval);

                let summary = format!(
                    "Execute {} on {}",
                    canonical_action.tool, canonical_action.resource
                );
                let mut approval = Approval::new_with_context(
                    canonical_action.action_hash,
                    decision.decision_id,
                    summary,
                    None,
                    30,
                    canonical_action.tool.to_string(),
                    canonical_action.principal.clone(),
                    canonical_action.resource.as_str(),
                    decision.policy_digest,
                    ApprovalMechanism::TtyInteractive,
                )
                .with_parameters_preview(canonical_action.canonical_arguments.clone());

                match self.approval_provider.request_approval(&mut approval).await {
                    Ok(()) => {
                        action.mark_approved()?;
                        state_history.push(ActionState::Approved);

                        let mut eff = decision.clone();
                        eff.decision = PolicyDecisionType::Allow;
                        (eff, Some(approval))
                    }
                    Err(ApprovalError::DeniedByHuman(reason)) => {
                        let _ = action.mark_rejected();
                        let _ = action.settle();
                        state_history.push(ActionState::Rejected);
                        state_history.push(ActionState::Settled);
                        return Err(GovernedActionError::ApprovalDenied(reason));
                    }
                    Err(ApprovalError::NonInteractiveMode) => {
                        let _ = action.mark_rejected();
                        let _ = action.settle();
                        state_history.push(ActionState::Rejected);
                        state_history.push(ActionState::Settled);
                        return Err(GovernedActionError::ApprovalHeadlessBlocked);
                    }
                    Err(ApprovalError::TimedOut { timeout_secs }) => {
                        let _ = action.mark_rejected();
                        let _ = action.settle();
                        state_history.push(ActionState::Rejected);
                        state_history.push(ActionState::Settled);
                        return Err(GovernedActionError::ApprovalTimedOut { timeout_secs });
                    }
                    Err(err) => {
                        let _ = action.mark_rejected();
                        let _ = action.settle();
                        state_history.push(ActionState::Rejected);
                        state_history.push(ActionState::Settled);
                        return Err(GovernedActionError::ApprovalFailed(err));
                    }
                }
            }
            PolicyDecisionType::Allow => {
                action.mark_authorized(canonical_action.action_hash, decision.decision_id)?;
                state_history.push(ActionState::Authorized);
                (decision.clone(), None)
            }
        };

        // 5. Executing state transition
        let execution_id = ExecutionId::new_v7();
        action.mark_executing(execution_id)?;
        state_history.push(ActionState::Executing);

        // 6. Connector Dispatch & Cryptographic Receipt Generation
        let dispatch_result = match canonical_action.tool.namespace.as_str() {
            "github" => {
                let conn = self.github_connector.as_ref().ok_or_else(|| {
                    GovernedActionError::ConnectorNotRegistered("github".to_string())
                })?;
                conn.execute_governed_with_receipt(
                    canonical_action,
                    &effective_decision,
                    approval_evidence.as_ref(),
                    self.credential_broker.as_ref(),
                    &self.receipt_signer,
                )
                .await
            }
            "postgres" => {
                let conn = self.postgres_connector.as_ref().ok_or_else(|| {
                    GovernedActionError::ConnectorNotRegistered("postgres".to_string())
                })?;
                conn.execute_governed_with_receipt(
                    canonical_action,
                    &effective_decision,
                    approval_evidence.as_ref(),
                    self.credential_broker.as_ref(),
                    &self.receipt_signer,
                )
                .await
            }
            "fs" | "file" | "filesystem" => {
                let conn = self
                    .fs_connector
                    .as_ref()
                    .ok_or_else(|| GovernedActionError::ConnectorNotRegistered("fs".to_string()))?;
                // Local filesystem explicitly does not require a credential broker lease
                conn.execute_governed_with_receipt(
                    canonical_action,
                    &effective_decision,
                    approval_evidence.as_ref(),
                    &self.receipt_signer,
                )
                .await
            }
            unknown => {
                return Err(GovernedActionError::UnsupportedNamespace(
                    unknown.to_string(),
                ));
            }
        };

        // 7. Settle Execution Outcome and Commit to Ledger
        match dispatch_result {
            Ok((execution_result, receipt)) => {
                action.mark_executed()?;
                state_history.push(ActionState::Executed);

                // Append signed receipt to durable audit ledger
                let (ledger_entry, ledger_error) = match self.ledger.append(&receipt).await {
                    Ok(entry) => (Some(entry), None),
                    Err(err) => {
                        tracing::error!(
                            error = %err,
                            action_hash = %canonical_action.action_hash.to_hex(),
                            "Action executed and receipt signed, but ledger append failed"
                        );
                        (None, Some(err.to_string()))
                    }
                };

                let _ = action.settle();
                state_history.push(ActionState::Settled);

                Ok(GovernedExecutionOutcome {
                    action_id: action.action_id,
                    action_hash: canonical_action.action_hash,
                    decision,
                    approval: approval_evidence,
                    execution_result,
                    receipt,
                    ledger_entry,
                    ledger_error,
                    state_history,
                })
            }
            Err((exec_err, maybe_receipt)) => {
                let _ = action.mark_execution_failed();
                state_history.push(ActionState::ExecutionFailed);

                let mut ledger_entry = None;
                if let Some(ref receipt) = maybe_receipt {
                    if let Ok(entry) = self.ledger.append(receipt).await {
                        ledger_entry = Some(Box::new(entry));
                    }
                }

                let _ = action.settle();
                state_history.push(ActionState::Settled);

                let is_ambiguous = exec_err.to_string().to_lowercase().contains("ambiguous");
                let is_cred_failure = match &exec_err {
                    relay_domain::ExecutionError::ConnectorFailed { reason, .. } => {
                        reason.contains("Credential broker error")
                            || reason.contains("Secret not found")
                    }
                    _ => false,
                };

                if is_cred_failure {
                    Err(GovernedActionError::CredentialFailed(
                        relay_domain::CredentialError::KeyringUnavailable {
                            reason: exec_err.to_string(),
                        },
                    ))
                } else if is_ambiguous {
                    Err(GovernedActionError::AmbiguousMutation {
                        error: exec_err,
                        receipt: maybe_receipt.map(Box::new),
                        ledger_entry,
                    })
                } else {
                    Err(GovernedActionError::ExecutionFailed {
                        error: exec_err,
                        receipt: maybe_receipt.map(Box::new),
                        ledger_entry,
                    })
                }
            }
        }
    }
}

/// Builder for `GovernedActionRunner`.
#[derive(Default)]
pub struct GovernedActionRunnerBuilder {
    policy_engine: Option<Arc<dyn PolicyEngine>>,
    approval_provider: Option<Arc<dyn ApprovalProvider>>,
    credential_broker: Option<Arc<dyn CredentialBroker>>,
    receipt_signer: Option<Arc<Ed25519ReceiptSigner>>,
    ledger: Option<Arc<dyn Ledger>>,
    github_connector: Option<Arc<GitHubConnector>>,
    postgres_connector: Option<Arc<PostgresConnector>>,
    fs_connector: Option<Arc<FilesystemConnector>>,
}

impl GovernedActionRunnerBuilder {
    pub fn policy_engine(mut self, engine: Arc<dyn PolicyEngine>) -> Self {
        self.policy_engine = Some(engine);
        self
    }

    pub fn approval_provider(mut self, provider: Arc<dyn ApprovalProvider>) -> Self {
        self.approval_provider = Some(provider);
        self
    }

    pub fn credential_broker(mut self, broker: Arc<dyn CredentialBroker>) -> Self {
        self.credential_broker = Some(broker);
        self
    }

    pub fn receipt_signer(mut self, signer: Arc<Ed25519ReceiptSigner>) -> Self {
        self.receipt_signer = Some(signer);
        self
    }

    pub fn ledger(mut self, ledger: Arc<dyn Ledger>) -> Self {
        self.ledger = Some(ledger);
        self
    }

    pub fn github_connector(mut self, connector: Arc<GitHubConnector>) -> Self {
        self.github_connector = Some(connector);
        self
    }

    pub fn postgres_connector(mut self, connector: Arc<PostgresConnector>) -> Self {
        self.postgres_connector = Some(connector);
        self
    }

    pub fn fs_connector(mut self, connector: Arc<FilesystemConnector>) -> Self {
        self.fs_connector = Some(connector);
        self
    }

    pub fn build(self) -> Result<GovernedActionRunner, GovernedActionError> {
        let policy_engine = self.policy_engine.ok_or_else(|| {
            GovernedActionError::Domain(DomainError::PolicyViolation(
                "GovernedActionRunner requires PolicyEngine".to_string(),
            ))
        })?;
        let approval_provider = self.approval_provider.ok_or_else(|| {
            GovernedActionError::Domain(DomainError::PolicyViolation(
                "GovernedActionRunner requires ApprovalProvider".to_string(),
            ))
        })?;
        let credential_broker = self.credential_broker.ok_or_else(|| {
            GovernedActionError::Domain(DomainError::PolicyViolation(
                "GovernedActionRunner requires CredentialBroker".to_string(),
            ))
        })?;
        let receipt_signer = self.receipt_signer.ok_or_else(|| {
            GovernedActionError::Domain(DomainError::PolicyViolation(
                "GovernedActionRunner requires ReceiptSigner".to_string(),
            ))
        })?;
        let ledger = self.ledger.ok_or_else(|| {
            GovernedActionError::Domain(DomainError::PolicyViolation(
                "GovernedActionRunner requires Ledger".to_string(),
            ))
        })?;

        Ok(GovernedActionRunner {
            policy_engine,
            approval_provider,
            credential_broker,
            receipt_signer,
            ledger,
            github_connector: self.github_connector,
            postgres_connector: self.postgres_connector,
            fs_connector: self.fs_connector,
        })
    }
}
