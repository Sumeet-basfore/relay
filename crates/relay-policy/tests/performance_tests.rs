//! In-memory Cedar policy evaluation performance benchmarks.
//!
//! Enforces architecture target from A001 / A010: Cedar policy evaluation < 2.0 ms.

use chrono::Utc;
use relay_domain::{
    AuthorizationRequest, PolicyDecisionType, PolicyEngine, PrincipalId, ResourceUri, SessionId,
    ToolId,
};
use relay_policy::CedarPolicyEngine;
use serde_json::json;
use std::time::Instant;

#[tokio::test]
async fn test_cedar_evaluation_latency_under_2ms() {
    let engine = CedarPolicyEngine::default_engine().expect("default engine");

    let req = AuthorizationRequest {
        principal: PrincipalId::new("principal:agent:default").unwrap(),
        action: "fs.read".to_string(),
        resource: ResourceUri::parse("file:///workspace/crates/relay-policy/src/lib.rs").unwrap(),
        session_id: SessionId::new_v7(),
        tool: ToolId::new("fs", "read").unwrap(),
        arguments: json!({ "path": "/workspace/crates/relay-policy/src/lib.rs" }),
        working_directory: "/workspace".to_string(),
        timestamp: Utc::now(),
        action_hash: Some(relay_domain::ActionHash::compute(b"bench_action")),
    };

    // Warm-up run
    let warmup = engine.evaluate(&req).await.expect("warmup");
    assert_eq!(warmup.decision, PolicyDecisionType::Allow);

    let iterations = 1000;
    let start = Instant::now();

    for _ in 0..iterations {
        let dec = engine.evaluate(&req).await.expect("evaluate");
        assert_eq!(dec.decision, PolicyDecisionType::Allow);
    }

    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() as f64 / iterations as f64;
    let avg_millis = avg_micros / 1000.0;

    println!(
        "Completed {iterations} Cedar evaluations in {:?} (Average: {:.3} ms / {:.1} µs per decision)",
        elapsed, avg_millis, avg_micros
    );

    // Architectural target: < 2.0 ms in release mode (unoptimized debug test target: < 5.0 ms)
    let max_allowed = if cfg!(debug_assertions) { 5.0 } else { 2.0 };
    assert!(
        avg_millis < max_allowed,
        "Average evaluation latency ({avg_millis:.3} ms) exceeded {max_allowed} ms SLA target"
    );
}
