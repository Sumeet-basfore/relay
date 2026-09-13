use relay_domain::error::*;

#[test]
fn test_error_conversions_and_display() {
    let domain_err = DomainError::InvalidIdentifier("Missing identifier prefix".to_string());
    let relay_err: RelayError = domain_err.into();
    assert!(format!("{}", relay_err).contains("Missing identifier prefix"));

    let proto_err = ProtocolError::FrameTooLarge {
        size_bytes: 20_000_000,
        max_bytes: 16_777_216,
    };
    let relay_proto: RelayError = proto_err.clone().into();
    assert!(format!("{}", relay_proto).contains("Frame too large: size 20000000 exceeds limit"));
    assert_eq!(proto_err.jsonrpc_code(), -32600);

    let inv_err = InvariantViolationError::AmbientCredentialLeak;
    let relay_inv: RelayError = inv_err.into();
    assert!(format!("{}", relay_inv).contains("Invariant SI-001 violation"));
}
