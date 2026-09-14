//! Relay Domain Models, State Machines, and Contracts
//!
//! This crate contains pure domain entities, strongly typed identifiers,
//! state machines, error taxonomy, security wrappers, and trait definitions.
//! It has zero I/O, network, or database dependencies.

pub mod action;
pub mod approval;
pub mod authorization;
pub mod credential;
pub mod egress;
pub mod error;
pub mod execution;
pub mod exit_code;
pub mod id;
pub mod ledger;
pub mod principal;
pub mod receipt;
pub mod resource;
pub mod security;
pub mod session;
pub mod tool;
pub mod traits;

pub use action::{Action, ActionState, ExecutionEnvironment, RequestedAction};
pub use approval::{
    Approval, ApprovalMechanism, ApprovalRequest, ApprovalState, HeadlessApprovalProvider,
    MockApprovalProvider,
};
pub use authorization::{AuthorizationRequest, PolicyDecision, PolicyDecisionType};
pub use credential::{CredentialLease, CredentialProviderType, CredentialRequest, LeaseState};
pub use egress::{
    EgressDecision, EgressOutcome, EgressRequest, NetworkEndpoint, ProxyLease, ProxySessionId,
    ProxySessionState,
};
pub use error::{
    ApprovalError, CanonicalizationError, CredentialError, CryptoError, DomainError,
    ExecutionError, InvariantViolationError, LedgerError, PolicyError, ProtocolError, RelayError,
    ValidationError,
};
pub use execution::{Execution, ExecutionResult, ExecutionRoute, ExecutionState};
pub use exit_code::ExitCode;
pub use id::{
    ActionHash, ActionId, AgentId, ApprovalId, DecisionId, Digest, ExecutionId, LeaseId,
    OutputHash, PolicySetDigest, PrincipalId, ReceiptId, SchemaDigest, SequenceNumber, SessionId,
    ToolId,
};
pub use ledger::LedgerEntry;
pub use principal::{Agent, AgentPrincipal, Principal, UserPrincipal};
pub use receipt::{
    ActionReceipt, ActionReceiptPredicate, ApprovalEvidence, CredentialLeaseEvidence,
    DomainActionReceipt, DsseEnvelope, DsseSignature, EpistemologyEvidence, ExecutionEvidence,
    ExecutionObservationStatus, InTotoStatement, InTotoSubject, ObservationEvidence,
    PolicyEvidence, ProposalEvidence, SignedActionReceipt,
};
pub use resource::{Resource, ResourceUri};
pub use security::{CredentialLeaseGuard, RedactedSecret, SecretBuffer};
pub use session::{Session, SessionState};
pub use tool::{Tool, ToolIdentity, ToolRoute, ToolSchema, ToolTrustClassification};
pub use traits::{
    ApprovalProvider, Canonicalizer, CredentialBroker, CredentialProvider, ExecutionDispatcher,
    Ledger, NativeConnector, PolicyEngine, ReceiptSigner, ResourceResolver,
};
