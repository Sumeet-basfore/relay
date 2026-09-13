//! Strict JSON parser that rejects duplicate keys at any depth, NaN, and Infinity.
//!
//! Standard JSON parsers (including default `serde_json::from_str`) often use
//! last-write-wins semantics for duplicate object keys, which enables authorization
//! bypass attacks (e.g. `{"path": "/safe", "path": "/etc/passwd"}`).
//! Relay strictly forbids duplicate object keys anywhere in the payload.

use relay_domain::CanonicalizationError;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

/// Maximum allowed bytes for raw JSON inputs before canonicalization (10 MB per A001/A010)
pub const MAX_CANONICAL_BYTES: usize = 10 * 1024 * 1024;

/// Marker prefix embedded into custom serde error to transport duplicate key name
const DUPLICATE_KEY_PREFIX: &str = "__RELAY_DUPLICATE_KEY__:";

/// Parses a JSON string strictly, ensuring:
/// 1. Payload does not exceed `MAX_CANONICAL_BYTES`.
/// 2. No duplicate keys exist in any JSON object at any nesting depth.
/// 3. No `NaN` or `Infinity` floating point values exist.
/// 4. No trailing non-whitespace characters exist.
pub fn parse_json_strictly(raw: &str) -> Result<Value, CanonicalizationError> {
    if raw.len() > MAX_CANONICAL_BYTES {
        return Err(CanonicalizationError::OversizedCanonicalRepresentation {
            size: raw.len(),
            limit: MAX_CANONICAL_BYTES,
        });
    }

    let mut deserializer = serde_json::Deserializer::from_str(raw);
    let value = StrictValueSeed
        .deserialize(&mut deserializer)
        .map_err(|e| map_serde_error(e.to_string()))?;

    deserializer
        .end()
        .map_err(|e| CanonicalizationError::MalformedJson(e.to_string()))?;

    Ok(value)
}

/// Parses raw JSON bytes strictly after validating UTF-8 encoding.
pub fn parse_json_bytes_strictly(bytes: &[u8]) -> Result<Value, CanonicalizationError> {
    let s = std::str::from_utf8(bytes)
        .map_err(|e| CanonicalizationError::UnsupportedEncoding(e.to_string()))?;
    parse_json_strictly(s)
}

fn map_serde_error(msg: String) -> CanonicalizationError {
    if let Some(idx) = msg.find(DUPLICATE_KEY_PREFIX) {
        let rest = &msg[idx + DUPLICATE_KEY_PREFIX.len()..];
        // Serde error may append " at line X column Y"
        let key = if let Some(end) = rest.find(" at line ") {
            &rest[..end]
        } else {
            rest.trim()
        };
        CanonicalizationError::DuplicateKey(key.to_string())
    } else {
        CanonicalizationError::MalformedJson(msg)
    }
}

#[derive(Clone, Copy)]
struct StrictValueSeed;

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a valid JSON value without duplicate keys")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_i128<E>(self, v: i128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if let Ok(val) = i64::try_from(v) {
            Ok(Value::Number(val.into()))
        } else {
            Err(de::Error::custom("integer exceeds 64-bit bounds"))
        }
    }

    fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if let Ok(val) = u64::try_from(v) {
            Ok(Value::Number(val.into()))
        } else {
            Err(de::Error::custom("integer exceeds 64-bit bounds"))
        }
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.is_nan() || v.is_infinite() {
            return Err(de::Error::custom("NaN or Infinity not allowed in JSON"));
        }
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| de::Error::custom("invalid float value"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
        Ok(Value::String(v))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<S>(self, mut access: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        let mut seq = Vec::new();
        while let Some(elem) = access.next_element_seed(StrictValueSeed)? {
            seq.push(elem);
        }
        Ok(Value::Array(seq))
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map = serde_json::Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if map.contains_key(&key) {
                return Err(de::Error::custom(format!("{DUPLICATE_KEY_PREFIX}{key}")));
            }
            let value = access.next_value_seed(StrictValueSeed)?;
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }
}
