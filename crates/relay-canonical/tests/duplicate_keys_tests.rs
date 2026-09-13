//! Tests for strict JSON parsing rejecting duplicate keys, NaN, and Infinity.

use relay_canonical::{parse_json_bytes_strictly, parse_json_strictly};
use relay_domain::CanonicalizationError;

#[test]
fn test_rejects_top_level_duplicate_key() {
    let json_str = r#"{"path": "/safe/file", "path": "/etc/passwd"}"#;
    let err = parse_json_strictly(json_str).expect_err("must reject duplicate key");

    match err {
        CanonicalizationError::DuplicateKey(key) => assert_eq!(key, "path"),
        other => panic!("expected DuplicateKey, got: {other:?}"),
    }
}

#[test]
fn test_rejects_nested_duplicate_key() {
    let json_str = r#"{
        "outer": {
            "sub": {
                "target": "first",
                "target": "second"
            }
        }
    }"#;
    let err = parse_json_strictly(json_str).expect_err("must reject nested duplicate key");

    match err {
        CanonicalizationError::DuplicateKey(key) => assert_eq!(key, "target"),
        other => panic!("expected DuplicateKey, got: {other:?}"),
    }
}

#[test]
fn test_rejects_duplicate_key_in_array() {
    let json_str = r#"[
        {"id": 1},
        {"key": "a", "key": "b"}
    ]"#;
    let err = parse_json_strictly(json_str).expect_err("must reject duplicate key in array");

    match err {
        CanonicalizationError::DuplicateKey(key) => assert_eq!(key, "key"),
        other => panic!("expected DuplicateKey, got: {other:?}"),
    }
}

#[test]
fn test_rejects_duplicate_key_with_escapes() {
    // \u0061 is 'a'
    let json_str = r#"{"a": 1, "\u0061": 2}"#;
    let err = parse_json_strictly(json_str).expect_err("must reject duplicate key with escape");

    match err {
        CanonicalizationError::DuplicateKey(key) => assert_eq!(key, "a"),
        other => panic!("expected DuplicateKey, got: {other:?}"),
    }
}

#[test]
fn test_allows_non_duplicate_similar_keys() {
    let json_str = r#"{"path": "/safe", "path2": "/other", "PATH": "/caps"}"#;
    let val = parse_json_strictly(json_str).expect("valid JSON with distinct keys");
    assert!(val.is_object());
}

#[test]
fn test_rejects_nan_and_infinity() {
    // In strict JSON, NaN and Infinity are not valid tokens
    let nan_json = r#"{"value": NaN}"#;
    assert!(parse_json_strictly(nan_json).is_err());

    let inf_json = r#"{"value": Infinity}"#;
    assert!(parse_json_strictly(inf_json).is_err());
}

#[test]
fn test_rejects_trailing_characters() {
    let json_str = r#"{"valid": true} trailing_junk"#;
    let err = parse_json_strictly(json_str).expect_err("must reject trailing junk");
    assert!(matches!(err, CanonicalizationError::MalformedJson(_)));
}

#[test]
fn test_rejects_invalid_utf8() {
    let invalid_bytes = b"{\"key\": \"\xFF\xFE\"}";
    let err = parse_json_bytes_strictly(invalid_bytes).expect_err("must reject invalid UTF-8");
    assert!(matches!(err, CanonicalizationError::UnsupportedEncoding(_)));
}
