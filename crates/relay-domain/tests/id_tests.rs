use relay_domain::id::*;
use std::str::FromStr;

#[test]
fn test_typed_id_generation_and_prefix() {
    let action_id = ActionId::new_v7();
    assert!(action_id.to_string().starts_with("act_"));
    assert_eq!(action_id.to_string(), action_id.to_prefixed_string());

    let session_id = SessionId::new_v7();
    assert!(session_id.to_string().starts_with("sess_"));

    let decision_id = DecisionId::new_v7();
    assert!(decision_id.to_string().starts_with("dec_"));

    let approval_id = ApprovalId::new_v7();
    assert!(approval_id.to_string().starts_with("appr_"));

    let lease_id = LeaseId::new_v7();
    assert!(lease_id.to_string().starts_with("lease_"));

    let exec_id = ExecutionId::new_v7();
    assert!(exec_id.to_string().starts_with("exec_"));

    let rcpt_id = ReceiptId::new_v7();
    assert!(rcpt_id.to_string().starts_with("rcpt_"));
}

#[test]
fn test_typed_id_parsing_and_validation() {
    let action_id = ActionId::new_v7();
    let id_str = action_id.to_string();
    let parsed = ActionId::from_str(&id_str).expect("Should parse valid ActionId");
    assert_eq!(action_id, parsed);

    // Malformed string (invalid UUID body)
    let malformed = "act_not-a-valid-uuid";
    assert!(ActionId::from_str(malformed).is_err());
}

#[test]
fn test_typed_id_serialization() {
    let action_id = ActionId::new_v7();
    let json = serde_json::to_string(&action_id).expect("Serialization failed");
    assert_eq!(json, format!("\"{}\"", action_id));

    let deserialized: ActionId = serde_json::from_str(&json).expect("Deserialization failed");
    assert_eq!(action_id, deserialized);
}

#[test]
fn test_string_ids() {
    let tool_id = ToolId::new("github", "create_issue").expect("Valid tool id");
    assert_eq!(tool_id.as_str(), "github.create_issue");
    assert_eq!(tool_id.namespace(), "github");
    assert_eq!(tool_id.tool_name(), "create_issue");

    let parsed_tool = ToolId::parse("postgres.execute_query").expect("Valid parse");
    assert_eq!(parsed_tool.as_str(), "postgres.execute_query");

    assert!(
        ToolId::new("", "foo").is_err(),
        "Empty tool ID should be rejected"
    );
    assert!(ToolId::parse("invalid-format").is_err());

    let agent_id = AgentId::new("agent:swe:1").expect("Valid agent id");
    assert_eq!(agent_id.as_str(), "agent:swe:1");
    assert!(AgentId::new("invalid-prefix").is_err());

    let principal_id = PrincipalId::new("principal:user:local").expect("Valid principal id");
    assert_eq!(principal_id.as_str(), "principal:user:local");
    assert!(PrincipalId::new("invalid-prefix").is_err());
}

#[test]
fn test_digest_and_hashes() {
    let valid_hex = "a".repeat(64);
    let digest = Digest::from_hex(&valid_hex).expect("Valid 64-char hex");
    assert_eq!(digest.to_hex(), valid_hex);
    assert_eq!(digest.as_bytes().len(), 32);

    let action_hash = ActionHash::from_hex(&valid_hex).expect("Valid action hash");
    assert_eq!(action_hash.to_hex(), valid_hex);

    // Invalid length
    assert!(Digest::from_hex("abc").is_err());
    assert!(Digest::from_hex(&"a".repeat(63)).is_err());
    assert!(Digest::from_hex(&"a".repeat(65)).is_err());

    // Non-hex chars
    let invalid_hex_str = "z".repeat(64);
    assert!(Digest::from_hex(&invalid_hex_str).is_err());
}
