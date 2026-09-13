//! Standards conformance tests for RFC 8785 JSON Canonicalization Scheme (JCS).

use relay_canonical::{canonicalize_json_str, canonicalize_value_to_string};
use serde_json::json;

#[test]
fn test_jcs_key_sorting() {
    let input = json!({
        "b": 2,
        "a": 1,
        "c": 3,
        "1": "numeric_key",
        "_": "underscore"
    });

    let canonical = canonicalize_value_to_string(&input).expect("canonicalize");
    // Keys sorted: "1", "_", "a", "b", "c"
    assert_eq!(
        canonical,
        r#"{"1":"numeric_key","_":"underscore","a":1,"b":2,"c":3}"#
    );
}

#[test]
fn test_jcs_nested_key_sorting() {
    let input = json!({
        "z": {
            "beta": "two",
            "alpha": "one"
        },
        "a": [
            {
                "y": 2,
                "x": 1
            }
        ]
    });

    let canonical = canonicalize_value_to_string(&input).expect("canonicalize");
    assert_eq!(
        canonical,
        r#"{"a":[{"x":1,"y":2}],"z":{"alpha":"one","beta":"two"}}"#
    );
}

#[test]
fn test_jcs_number_formatting() {
    // RFC 8785 requires numbers with integer values to be formatted without decimals
    let v1 = canonicalize_json_str("1.0").expect("1.0");
    assert_eq!(std::str::from_utf8(&v1).unwrap(), "1");

    let v2 = canonicalize_json_str("1e0").expect("1e0");
    assert_eq!(std::str::from_utf8(&v2).unwrap(), "1");

    let v3 = canonicalize_json_str("-0").expect("-0");
    assert_eq!(std::str::from_utf8(&v3).unwrap(), "0");

    let v4 = canonicalize_json_str("100.5").expect("100.5");
    assert_eq!(std::str::from_utf8(&v4).unwrap(), "100.5");
}

#[test]
fn test_jcs_whitespace_elimination() {
    let raw = r#"{
        "name" :   "relay",
        "active" :  true ,
        "list" : [ 1 , 2 , 3 ]
    }"#;

    let canonical = canonicalize_json_str(raw).expect("canonicalize");
    assert_eq!(
        std::str::from_utf8(&canonical).unwrap(),
        r#"{"active":true,"list":[1,2,3],"name":"relay"}"#
    );
}

#[test]
fn test_jcs_string_escaping() {
    // Only ", \, and control characters (0x00-0x1F) are escaped.
    // Literal UTF-8 characters must remain unescaped.
    let input = json!({
        "escapes": "quote: \", backslash: \\, newline: \n, tab: \t",
        "unicode": "hello 🌍 and 日本語 and €"
    });

    let canonical = canonicalize_value_to_string(&input).expect("canonicalize");
    assert!(canonical.contains(r#""quote: \", backslash: \\, newline: \n, tab: \t""#));
    assert!(canonical.contains("hello 🌍 and 日本語 and €"));
}

#[test]
fn test_jcs_determinism_across_encodings() {
    let raw1 = r#"{"a": 1, "b": 2}"#;
    let raw2 = r#"{"b":2,"a":1}"#;
    let raw3 = "{\n  \"b\": 2,\n  \"a\": 1\n}";

    let c1 = canonicalize_json_str(raw1).unwrap();
    let c2 = canonicalize_json_str(raw2).unwrap();
    let c3 = canonicalize_json_str(raw3).unwrap();

    assert_eq!(c1, c2);
    assert_eq!(c2, c3);
    assert_eq!(c1, br#"{"a":1,"b":2}"#);
}
