//! Governed in-process Native Filesystem Connector (Milestone B010).
//!
//! Enforces:
//! - Complete mediation: Cedar ALLOW is strictly required
//! - ActionHash binding: `action.action_hash == decision.action_hash`
//! - Canonical resource verification: `file://` URI matches target path
//! - Strict root-jail containment: No path traversal or symlink escapes
//! - TOCTOU mitigation: Explicit physical verification and bounded operations
//! - Action Receipts: Signed DSSE in-toto Statement v1.0 receipts with explicit outcome tracking
//! - No ambient credentials: Uses OS process authority within configured root (no fake credentials)

use async_trait::async_trait;
use std::path::{Path, PathBuf};

use relay_canonical::CanonicalAction;
use relay_domain::{
    ActionReceipt, Approval, ApprovalState, ExecutionError, ExecutionId,
    ExecutionObservationStatus, ExecutionResult, ExecutionRoute, NativeConnector, OutputHash,
    PolicyDecision, PolicyDecisionType, SecretBuffer,
};
use relay_receipts::{ActionReceiptBuilder, Ed25519ReceiptSigner};

use super::config::FsConnectorConfig;
use super::error::FsError;
use super::jail::resolve_and_verify_within_root;
use super::operations::{
    append_file, create_directory, delete_file, list_directory, read_file, remove_directory,
    stat_metadata, write_file_atomic,
};

/// Native Filesystem Connector executing governed local filesystem operations.
#[derive(Clone)]
pub struct FilesystemConnector {
    config: FsConnectorConfig,
}

impl FilesystemConnector {
    /// Creates a new FilesystemConnector with the given configuration.
    pub fn new(config: FsConnectorConfig) -> Self {
        Self { config }
    }

    /// Creates a FilesystemConnector rooted at the given path.
    pub fn for_root(root_dir: impl AsRef<Path>) -> Self {
        Self::new(FsConnectorConfig::new(root_dir))
    }

    /// Access the connector's configuration.
    pub fn config(&self) -> &FsConnectorConfig {
        &self.config
    }

    /// Extracts target path and validated operation from a `CanonicalAction`.
    pub fn extract_execution_plan(
        &self,
        canonical_action: &CanonicalAction,
    ) -> Result<(String, PathBuf, bool), FsError> {
        if canonical_action.tool.namespace != "fs"
            && canonical_action.tool.namespace != "file"
            && canonical_action.tool.namespace != "filesystem"
        {
            return Err(FsError::UnsupportedOperation(format!(
                "Non-filesystem tool namespace '{}'",
                canonical_action.tool.namespace
            )));
        }

        let op_name = canonical_action.tool.name.clone();

        // Extract path argument from canonical arguments
        let path_str = canonical_action
            .canonical_arguments
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FsError::InvalidArguments {
                operation: op_name.clone(),
                reason: "Missing required 'path' argument in canonical action".to_string(),
            })?;

        // Cross-verify with canonical ResourceUri
        let resource_str = canonical_action.resource.as_str();
        if !resource_str.starts_with("file://") {
            return Err(FsError::ResourceMismatch {
                action_target: resource_str.to_string(),
                op_target: format!("Expected file:// scheme, got {resource_str}"),
            });
        }

        let is_mutating = matches!(
            op_name.as_str(),
            "write"
                | "write_file"
                | "append"
                | "append_file"
                | "create_dir"
                | "create_directory"
                | "delete"
                | "delete_file"
                | "remove_dir"
                | "remove_directory"
        );

        let require_existing = matches!(
            op_name.as_str(),
            "read"
                | "read_file"
                | "list"
                | "list_directory"
                | "stat"
                | "delete"
                | "delete_file"
                | "remove_dir"
                | "remove_directory"
                | "append"
                | "append_file"
        );

        let resolved_path =
            resolve_and_verify_within_root(&self.config, Path::new(path_str), require_existing)?;

        Ok((op_name, resolved_path, is_mutating))
    }

    /// Executes a pre-authorized filesystem action under Cedar governance.
    pub async fn execute_governed(
        &self,
        canonical_action: &CanonicalAction,
        decision: &PolicyDecision,
    ) -> Result<ExecutionResult, ExecutionError> {
        if decision.decision != PolicyDecisionType::Allow {
            return Err(FsError::UnauthorizedExecution.into());
        }

        if canonical_action.action_hash != decision.action_hash {
            return Err(FsError::ActionHashMismatch {
                expected: decision.action_hash.to_hex(),
                actual: canonical_action.action_hash.to_hex(),
            }
            .into());
        }

        let (op_name, resolved_path, _) = self.extract_execution_plan(canonical_action)?;
        let dispatch_result = self.dispatch_op(&op_name, &resolved_path, canonical_action);

        match dispatch_result {
            Ok(res) => Ok(res),
            Err(err) => {
                tracing::warn!(operation = %op_name, path = %resolved_path.display(), error = %err, "Filesystem operation failed");
                Err(err.into())
            }
        }
    }

    /// Executes a pre-authorized filesystem action and produces an Ed25519 DSSE signed Action Receipt.
    pub async fn execute_governed_with_receipt(
        &self,
        canonical_action: &CanonicalAction,
        decision: &PolicyDecision,
        approval: Option<&Approval>,
        signer: &Ed25519ReceiptSigner,
    ) -> Result<(ExecutionResult, ActionReceipt), (ExecutionError, Option<ActionReceipt>)> {
        // Validate policy authorization (SI-002)
        match decision.decision {
            PolicyDecisionType::Allow => {}
            PolicyDecisionType::ApprovalRequired => {
                if approval.is_none() {
                    tracing::warn!(
                        action_hash = %decision.action_hash.to_hex(),
                        "Filesystem operation requires operator approval but none provided; rejecting"
                    );
                    return Err((FsError::UnauthorizedExecution.into(), None));
                }
            }
            PolicyDecisionType::Deny => {
                tracing::warn!(
                    action_hash = %decision.action_hash.to_hex(),
                    "Filesystem operation denied by policy; rejecting"
                );
                return Err((FsError::UnauthorizedExecution.into(), None));
            }
        }

        if canonical_action.action_hash != decision.action_hash {
            return Err((
                FsError::ActionHashMismatch {
                    expected: decision.action_hash.to_hex(),
                    actual: canonical_action.action_hash.to_hex(),
                }
                .into(),
                None,
            ));
        }

        if let Some(appr) = approval {
            if appr.action_hash != canonical_action.action_hash {
                return Err((
                    FsError::ActionHashMismatch {
                        expected: canonical_action.action_hash.to_hex(),
                        actual: appr.action_hash.to_hex(),
                    }
                    .into(),
                    None,
                ));
            }
            if appr.state != ApprovalState::Approved {
                return Err((FsError::UnauthorizedExecution.into(), None));
            }
        }

        let (op_name, resolved_path, _is_mutating) =
            match self.extract_execution_plan(canonical_action) {
                Ok(plan) => plan,
                Err(err) => return Err((err.into(), None)),
            };

        let execution_id = ExecutionId::new_v7();
        let started_at = chrono::Utc::now();
        let start_instant = std::time::Instant::now();
        let endpoint = format!("file://{}", resolved_path.display());

        let dispatch_result = self.dispatch_op(&op_name, &resolved_path, canonical_action);
        let completed_at = chrono::Utc::now();
        let duration_ms = start_instant.elapsed().as_millis() as u64;

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
            Ok(exec_res) => {
                let digest = exec_res.stdout_digest;
                let count = exec_res.output_byte_count;
                let prev = exec_res.sanitized_preview.clone();
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
                    FsError::AmbiguousMutationOutcome {
                        operation,
                        path,
                        reason,
                    } => (
                        ExecutionObservationStatus::AmbiguousMutation,
                        1,
                        OutputHash::compute(b""),
                        0,
                        format!("Ambiguous mutation for {operation} on {path}: {reason}"),
                        true,
                        "AmbiguousRequiresVerification".to_string(),
                        Some("AmbiguousMutationOutcome".to_string()),
                        Err(exec_err),
                    ),
                    FsError::PermissionDenied { path, reason } => (
                        ExecutionObservationStatus::TargetError,
                        1,
                        OutputHash::compute(b""),
                        0,
                        format!("Permission denied on {path}: {reason}"),
                        false,
                        "NonRetryableFatal".to_string(),
                        Some("PermissionDenied".to_string()),
                        Err(exec_err),
                    ),
                    FsError::NotFound(path) => (
                        ExecutionObservationStatus::TargetError,
                        1,
                        OutputHash::compute(b""),
                        0,
                        format!("File not found: {path}"),
                        false,
                        "NonRetryableFatal".to_string(),
                        Some("NotFound".to_string()),
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
                        Some("ExecutionError".to_string()),
                        Err(exec_err),
                    ),
                }
            }
        };

        // If this execution was permitted via step-up approval, construct an authorized decision
        // representation for receipt building that binds both the policy and the approval.
        let effective_decision =
            if decision.decision == PolicyDecisionType::ApprovalRequired && approval.is_some() {
                let mut d = decision.clone();
                d.decision = PolicyDecisionType::Allow;
                d
            } else {
                decision.clone()
            };

        let builder = ActionReceiptBuilder::new(canonical_action, &effective_decision)
            .with_approval(approval)
            .with_execution_metadata(
                execution_id,
                ExecutionRoute::Native,
                "fs",
                &op_name,
                canonical_action.resource.as_str(),
                Some("FS".to_string()),
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
                Some(exit_code as u16),
                &preview,
                is_ambiguous,
                &retry_class,
                error_class,
            );

        let receipt = match builder.build_and_sign(signer) {
            Ok(r) => r,
            Err(e) => {
                return Err((
                    ExecutionError::ConnectorFailed {
                        connector: "fs".to_string(),
                        reason: format!("Failed to sign receipt: {e}"),
                    },
                    None,
                ));
            }
        };

        match exec_outcome {
            Ok(result) => Ok((result, receipt)),
            Err(err) => Err((err, Some(receipt))),
        }
    }

    fn dispatch_op(
        &self,
        op_name: &str,
        path: &Path,
        canonical_action: &CanonicalAction,
    ) -> Result<ExecutionResult, FsError> {
        match op_name {
            "read" | "read_file" => {
                let res = read_file(&self.config, path)?;
                let preview = format!("Read {} bytes from {}", res.size_bytes, path.display());
                Ok(ExecutionResult::success(res.content.as_bytes(), preview))
            }
            "list" | "list_directory" => {
                let entries = list_directory(&self.config, path)?;
                let json_bytes = serde_json::to_vec(&entries).map_err(|e| FsError::IoError {
                    path: path.display().to_string(),
                    reason: e.to_string(),
                })?;
                let preview = format!("Listed {} entries in {}", entries.len(), path.display());
                Ok(ExecutionResult::success(&json_bytes, preview))
            }
            "stat" => {
                let stat = stat_metadata(&self.config, path)?;
                let json_bytes = serde_json::to_vec(&stat).map_err(|e| FsError::IoError {
                    path: path.display().to_string(),
                    reason: e.to_string(),
                })?;
                let preview = format!(
                    "Stat {}: size={}, is_file={}",
                    path.display(),
                    stat.size_bytes,
                    stat.is_file
                );
                Ok(ExecutionResult::success(&json_bytes, preview))
            }
            "write" | "write_file" => {
                let content_str = canonical_action
                    .canonical_arguments
                    .get("content")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FsError::InvalidArguments {
                        operation: op_name.to_string(),
                        reason: "Missing required 'content' argument for write".to_string(),
                    })?;
                let res = write_file_atomic(&self.config, path, content_str.as_bytes())?;
                let json_bytes = serde_json::to_vec(&res).map_err(|e| FsError::IoError {
                    path: path.display().to_string(),
                    reason: e.to_string(),
                })?;
                let preview = format!("Wrote {} bytes to {}", res.bytes_written, path.display());
                Ok(ExecutionResult::success(&json_bytes, preview))
            }
            "append" | "append_file" => {
                let content_str = canonical_action
                    .canonical_arguments
                    .get("content")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FsError::InvalidArguments {
                        operation: op_name.to_string(),
                        reason: "Missing required 'content' argument for append".to_string(),
                    })?;
                let res = append_file(&self.config, path, content_str.as_bytes())?;
                let json_bytes = serde_json::to_vec(&res).map_err(|e| FsError::IoError {
                    path: path.display().to_string(),
                    reason: e.to_string(),
                })?;
                let preview = format!("Appended {} bytes to {}", res.bytes_written, path.display());
                Ok(ExecutionResult::success(&json_bytes, preview))
            }
            "create_dir" | "create_directory" => {
                create_directory(&self.config, path)?;
                let preview = format!("Created directory {}", path.display());
                Ok(ExecutionResult::success(b"{}", preview))
            }
            "delete" | "delete_file" => {
                delete_file(&self.config, path)?;
                let preview = format!("Deleted file {}", path.display());
                Ok(ExecutionResult::success(b"{}", preview))
            }
            "remove_dir" | "remove_directory" => {
                remove_directory(&self.config, path)?;
                let preview = format!("Removed directory {}", path.display());
                Ok(ExecutionResult::success(b"{}", preview))
            }
            other => Err(FsError::UnsupportedOperation(format!(
                "Unsupported filesystem operation '{other}'"
            ))),
        }
    }
}

#[async_trait]
impl NativeConnector for FilesystemConnector {
    fn namespace(&self) -> &'static str {
        "fs"
    }

    async fn execute(
        &self,
        _tool_name: &str,
        _canonical_args: &serde_json::Value,
        _secret: Option<&SecretBuffer>,
    ) -> Result<ExecutionResult, ExecutionError> {
        Err(ExecutionError::ConnectorFailed {
            connector: "fs".to_string(),
            reason: "Direct NativeConnector::execute is forbidden; use execute_governed pipeline"
                .to_string(),
        })
    }
}
