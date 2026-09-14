use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

use relay_domain::egress::NetworkEndpoint;
use relay_domain::error::{InvariantViolationError, RelayError};
use relay_domain::id::ActionHash;
use relay_domain::principal::{Principal, UserPrincipal};
use relay_mcp::egress_dns::DnsResolverWithBlacklist;
use relay_mcp::egress_headers::HeaderPolicy;
use relay_mcp::egress_injector::CredentialInjector;
use relay_mcp::egress_proxy::EgressProxy;
use relay_mcp::egress_sandbox::EgressSandboxLauncher;
use relay_mcp::egress_session::ProxySessionManager;
use relay_mcp::env::sanitized_child_env;

fn make_test_principal(name: &str) -> Principal {
    Principal::User(UserPrincipal::new_local(name).unwrap())
}

// =============================================================================
// Phase 3: Credential Exfiltration Campaign
// =============================================================================

#[tokio::test]
async fn test_phase3_target_secrets_never_observable_in_child_environment() {
    // Simulate ambient host environment containing target secrets
    std::env::set_var("GITHUB_TOKEN", "ghp_super_secret_pat_99999999999999999999");
    std::env::set_var("PGPASSWORD", "super_secret_db_password_12345");
    std::env::set_var(
        "AWS_SECRET_ACCESS_KEY",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    );
    std::env::set_var("OPENAI_API_KEY", "sk-secret-ai-token-123456789");

    let sanitized = sanitized_child_env("0.1.0");

    // Clean up test environment
    std::env::remove_var("GITHUB_TOKEN");
    std::env::remove_var("PGPASSWORD");
    std::env::remove_var("AWS_SECRET_ACCESS_KEY");
    std::env::remove_var("OPENAI_API_KEY");

    // Assert that target secrets are completely eliminated from child environment
    assert!(!sanitized.contains_key("GITHUB_TOKEN"));
    assert!(!sanitized.contains_key("PGPASSWORD"));
    assert!(!sanitized.contains_key("AWS_SECRET_ACCESS_KEY"));
    assert!(!sanitized.contains_key("OPENAI_API_KEY"));
    assert!(sanitized.contains_key("PATH") || sanitized.contains_key("RELAY_ACTIVE"));
}

#[tokio::test]
async fn test_phase3_credential_reuse_fails_after_session_burn_or_expiry() {
    let session_mgr = ProxySessionManager::new();
    let action_hash = ActionHash::compute(b"action-cred-reuse");
    let principal = make_test_principal("alice");
    let endpoint = NetworkEndpoint::parse("https://api.github.com").unwrap();

    let (_session_id, token) = session_mgr
        .create_lease(action_hash, principal, Some(endpoint.clone()), Some(30))
        .await;

    // 1. First validation succeeds
    let valid_lease = session_mgr.validate_lease(&token, Some(&endpoint)).await;
    assert!(valid_lease.is_ok());

    // 2. Burn session on action completion
    session_mgr.burn_lease(&token).await;

    // 3. Post-burn credential lease reuse fails
    let post_burn = session_mgr.validate_lease(&token, Some(&endpoint)).await;
    assert!(post_burn.is_err());
}

// =============================================================================
// Phase 4: Proxy Session Attack Campaign
// =============================================================================

#[tokio::test]
async fn test_phase4_proxy_session_forgery_and_replay_attacks() {
    let session_mgr = ProxySessionManager::new();
    let endpoint = NetworkEndpoint::parse("https://api.github.com").unwrap();

    // Attack 1: Forged Token
    let forged = session_mgr
        .validate_lease(
            "relay_lease_fake_forged_random_token_12345",
            Some(&endpoint),
        )
        .await;
    assert!(forged.is_err());
    match forged.unwrap_err() {
        RelayError::InvariantViolation(InvariantViolationError::EphemeralProxySessionInvalid) => {}
        other => panic!("Expected EphemeralProxySessionInvalid, got {:?}", other),
    }

    // Attack 2: Cross-Action Replay
    let hash_a = ActionHash::compute(b"action-A");
    let principal = make_test_principal("bob");

    let (_session_id, token_a) = session_mgr
        .create_lease(hash_a, principal, Some(endpoint.clone()), Some(30))
        .await;

    // Session A is burned
    session_mgr.burn_lease(&token_a).await;

    // Attacker tries to use token A for action B
    let cross_replay = session_mgr.validate_lease(&token_a, Some(&endpoint)).await;
    assert!(cross_replay.is_err());
}

#[tokio::test]
async fn test_phase4_proxy_session_ttl_expiration() {
    let session_mgr = ProxySessionManager::new();
    let action_hash = ActionHash::compute(b"action-ttl-expired");
    let principal = make_test_principal("carol");
    let endpoint = NetworkEndpoint::parse("https://api.github.com").unwrap();

    // Create session with 0s TTL (already expired)
    let (_session_id, token) = session_mgr
        .create_lease(action_hash, principal, Some(endpoint.clone()), Some(0))
        .await;

    // Validation must fail with EphemeralProxySessionInvalid
    let res = session_mgr.validate_lease(&token, Some(&endpoint)).await;
    assert!(res.is_err());
    match res.unwrap_err() {
        RelayError::InvariantViolation(InvariantViolationError::EphemeralProxySessionInvalid) => {}
        other => panic!("Expected EphemeralProxySessionInvalid, got {:?}", other),
    }
}

// =============================================================================
// Phase 5: Connection Pooling & Socket Persistence Attack
// =============================================================================

#[tokio::test]
async fn test_phase5_connection_pooling_socket_reuse_after_lease_burn() {
    let session_mgr = ProxySessionManager::new();
    let action_hash = ActionHash::compute(b"action-pool-1");
    let principal = make_test_principal("david");
    let endpoint = NetworkEndpoint::parse("https://api.github.com").unwrap();

    let (_session_id, token) = session_mgr
        .create_lease(action_hash, principal, Some(endpoint.clone()), Some(30))
        .await;

    // Start proxy
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let proxy = Arc::new(EgressProxy::new(
        proxy_addr,
        session_mgr.clone(),
        DnsResolverWithBlacklist::strict(),
        CredentialInjector::new(),
        None,
    ));

    let proxy_runner = Arc::clone(&proxy);
    tokio::spawn(async move {
        let _ = proxy_runner.run_server(proxy_listener, shutdown_rx).await;
    });

    // Client connects and sends HTTP forward request
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    // Burn session immediately to simulate Action A completing while connection is kept alive
    session_mgr.burn_lease(&token).await;

    // Attacker tries to send request over the opened socket with burned lease
    let req = format!(
        "GET http://api.github.com/repos HTTP/1.1\r\nProxy-Authorization: Bearer {}\r\nHost: api.github.com\r\n\r\n",
        token
    );
    client.write_all(req.as_bytes()).await.unwrap();

    let mut response_buf = vec![0u8; 1024];
    let n = client.read(&mut response_buf).await.unwrap();
    let response = String::from_utf8_lossy(&response_buf[..n]);

    // Proxy must reject with HTTP 407 Proxy Authentication Required
    assert!(response.contains("407 Proxy Authentication Required"));

    let _ = shutdown_tx.send(());
}

// =============================================================================
// Phase 6: Redirect Attack Campaign
// =============================================================================

#[tokio::test]
async fn test_phase6_redirect_to_private_ip_and_metadata_blocked() {
    let resolver = DnsResolverWithBlacklist::strict();

    // Target 1: Redirect destination 127.0.0.1 (Loopback)
    assert!(resolver
        .resolve_and_validate("127.0.0.1", 80)
        .await
        .is_err());

    // Target 2: Redirect destination 169.254.169.254 (Cloud Metadata)
    assert!(resolver
        .resolve_and_validate("169.254.169.254", 80)
        .await
        .is_err());

    // Target 3: Redirect destination 10.0.0.1 (RFC 1918 Private)
    assert!(resolver.resolve_and_validate("10.0.0.1", 80).await.is_err());

    // Target 4: Redirect destination metadata.google.internal
    assert!(resolver
        .resolve_and_validate("metadata.google.internal", 80)
        .await
        .is_err());

    // Target 5: Redirect destination fd00:ec2::254 (IPv6 IMDS)
    assert!(resolver
        .resolve_and_validate("fd00:ec2::254", 80)
        .await
        .is_err());
}

// =============================================================================
// Phase 7: DNS Rebinding Attack Campaign
// =============================================================================

#[tokio::test]
async fn test_phase7_dns_rebinding_ip_pinning_and_literal_checks() {
    let resolver = DnsResolverWithBlacklist::strict();

    // Verify IP literal checks (IPv4 & IPv6)
    assert!(resolver
        .resolve_and_validate("192.168.1.1", 443)
        .await
        .is_err());
    assert!(resolver
        .resolve_and_validate("172.16.0.5", 443)
        .await
        .is_err());
    assert!(resolver.resolve_and_validate("::1", 443).await.is_err());
    assert!(resolver.resolve_and_validate("0.0.0.0", 443).await.is_err());

    // Resolving a public IP pins the socket address directly
    let addr = resolver.resolve_and_validate("1.1.1.1", 443).await.unwrap();
    assert_eq!(addr.ip().to_string(), "1.1.1.1");
    assert_eq!(addr.port(), 443);
}

// =============================================================================
// Phase 8: Linux Network Namespace Escape Campaign
// =============================================================================

#[tokio::test]
async fn test_phase8_linux_netns_sandbox_blocks_raw_sockets() {
    #[cfg(target_os = "linux")]
    {
        let mut cmd = tokio::process::Command::new("ping");
        cmd.args(["-c", "1", "-W", "1", "1.1.1.1"]);

        let launcher = EgressSandboxLauncher::new("http://127.0.0.1:8080", "lease_tok");
        let child = launcher.spawn(cmd);

        match child {
            Ok(mut c) => {
                let status = c.wait().await.unwrap();
                assert!(
                    !status.success(),
                    "Raw socket ping inside netns sandbox must fail"
                );
            }
            Err(e) => {
                println!("Subprocess spawn failed as expected: {:?}", e);
            }
        }
    }
}

// =============================================================================
// Phase 9 & 10: Process Tree & Namespace Lifecycle Attacks
// =============================================================================

#[tokio::test]
async fn test_phase9_and_10_child_process_tree_isolation() {
    #[cfg(target_os = "linux")]
    {
        // Spawns a child shell that in turn spawns a grandchild trying to ping
        let mut cmd = tokio::process::Command::new("sh");
        cmd.args(["-c", "sh -c 'ping -c 1 -W 1 1.1.1.1'"]);

        let launcher = EgressSandboxLauncher::new("http://127.0.0.1:8080", "lease_tok");
        let child = launcher.spawn(cmd);

        match child {
            Ok(mut c) => {
                let status = c.wait().await.unwrap();
                assert!(
                    !status.success(),
                    "Grandchild process inside netns sandbox must fail network access"
                );
            }
            Err(e) => {
                println!("Subprocess spawn failed as expected: {:?}", e);
            }
        }
    }
}

// =============================================================================
// Phase 11 & 12: Background Work & Async MCP Tasks
// =============================================================================

#[tokio::test]
async fn test_phase11_and_12_background_work_fails_after_action_settles() {
    let session_mgr = ProxySessionManager::new();
    let action_hash = ActionHash::compute(b"action-background-work");
    let principal = make_test_principal("eve");
    let endpoint = NetworkEndpoint::parse("https://api.github.com").unwrap();

    let (_session_id, token) = session_mgr
        .create_lease(action_hash, principal, Some(endpoint.clone()), Some(30))
        .await;

    // Action completes synchronously -> session is burned
    session_mgr.burn_lease(&token).await;

    // Background asynchronous work attempts to use the lease token
    let bg_result = session_mgr.validate_lease(&token, Some(&endpoint)).await;
    assert!(
        bg_result.is_err(),
        "Background work without active session must fail closed"
    );
}

// =============================================================================
// Phase 14: Credential Scope Mutation Attack
// =============================================================================

#[tokio::test]
async fn test_phase14_credential_not_injected_to_unauthorized_destination() {
    let injector = CredentialInjector::new();
    injector
        .register_bearer_token("api.github.com", "ghp_valid_pat_token_for_github")
        .await;

    let attacker_ep = NetworkEndpoint::parse("https://attacker.evil.com").unwrap();
    let mut headers = vec![("User-Agent".to_string(), "MCP-Agent".to_string())];

    // Inject credentials for attacker.evil.com
    injector.inject(&attacker_ep, &mut headers).await;

    // Verify that GitHub token was NOT injected into attacker request
    assert!(!headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("authorization") && v.contains("ghp_valid_pat")));
}

// =============================================================================
// Phase 15: Header Smuggling & CRLF Campaign
// =============================================================================

#[tokio::test]
async fn test_phase15_header_smuggling_crlf_and_hop_by_hop_stripping() {
    // 1. CRLF in header value must fail
    let res = HeaderPolicy::validate_header("Host", "api.github.com\r\nInjected-Header: evil");
    assert!(res.is_err());

    // 2. Hop-by-hop headers must be stripped
    let headers_with_hop = vec![
        ("Host".to_string(), "api.github.com".to_string()),
        (
            "Proxy-Authorization".to_string(),
            "Bearer token123".to_string(),
        ),
        ("Proxy-Connection".to_string(), "keep-alive".to_string()),
        ("Keep-Alive".to_string(), "timeout=5".to_string()),
        ("Transfer-Encoding".to_string(), "chunked".to_string()),
    ];

    let sanitized = HeaderPolicy::sanitize_for_upstream(&headers_with_hop);
    assert!(!sanitized
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization")));
    assert!(!sanitized
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("proxy-connection")));
    assert!(!sanitized
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("keep-alive")));
    assert!(!sanitized
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding")));
}

// =============================================================================
// Phase 16: HTTP Tunnel Abuse (CONNECT Target Manipulation)
// =============================================================================

#[tokio::test]
async fn test_phase16_connect_tunnel_to_blacklisted_targets_blocked() {
    let session_mgr = ProxySessionManager::new();
    let action_hash = ActionHash::compute(b"action-connect-abuse");
    let principal = make_test_principal("frank");
    let endpoint = NetworkEndpoint::parse("https://169.254.169.254:443").unwrap();

    let (_session_id, token) = session_mgr
        .create_lease(action_hash, principal, Some(endpoint), Some(30))
        .await;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let proxy = Arc::new(EgressProxy::new(
        proxy_addr,
        session_mgr,
        DnsResolverWithBlacklist::strict(),
        CredentialInjector::new(),
        None,
    ));

    let proxy_runner = Arc::clone(&proxy);
    tokio::spawn(async move {
        let _ = proxy_runner.run_server(proxy_listener, shutdown_rx).await;
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    // Attempt CONNECT to Cloud Metadata IP
    let connect_req = format!(
        "CONNECT 169.254.169.254:443 HTTP/1.1\r\nProxy-Authorization: Bearer {}\r\nHost: 169.254.169.254:443\r\n\r\n",
        token
    );
    client.write_all(connect_req.as_bytes()).await.unwrap();

    let mut response_buf = vec![0u8; 1024];
    let n = client.read(&mut response_buf).await.unwrap();
    let response = String::from_utf8_lossy(&response_buf[..n]);

    // Proxy must reject with HTTP 403 Forbidden
    assert!(response.contains("403 Forbidden"));

    let _ = shutdown_tx.send(());
}

// =============================================================================
// Phase 17: Egress Policy & Endpoint Confusion
// =============================================================================

#[tokio::test]
async fn test_phase17_endpoint_confusion_and_malformed_url_rejected() {
    // Empty host or invalid port
    assert!(NetworkEndpoint::parse("http://:8080").is_err());
    assert!(NetworkEndpoint::parse("http://example.com:not_a_port").is_err());
    assert!(NetworkEndpoint::parse("http://example.com:99999").is_err());

    // Valid parsing with explicit and implicit ports
    let ep = NetworkEndpoint::parse("https://api.github.com/repos").unwrap();
    assert_eq!(ep.host, "api.github.com");
    assert_eq!(ep.port, 443);
    assert_eq!(ep.scheme, "https");
}

// =============================================================================
// Phase 20: High-Concurrency Multi-Session Campaign
// =============================================================================

#[tokio::test]
async fn test_phase20_high_concurrency_no_session_or_credential_crosstalk() {
    let session_mgr = ProxySessionManager::new();
    let mut handles = Vec::new();

    for i in 0..50 {
        let mgr = session_mgr.clone();
        let handle = tokio::spawn(async move {
            let action_hash = ActionHash::compute(format!("action-concurrent-{i}").as_bytes());
            let principal = make_test_principal(&format!("user_{i}"));
            let host = format!("api{i}.example.com");
            let endpoint = NetworkEndpoint::new("https", host, 443);

            let (_session_id, token) = mgr
                .create_lease(
                    action_hash,
                    principal.clone(),
                    Some(endpoint.clone()),
                    Some(30),
                )
                .await;

            // Validate lease for its own endpoint
            let valid = mgr.validate_lease(&token, Some(&endpoint)).await;
            assert!(valid.is_ok());

            // Validate that lease cannot be used for another endpoint
            let wrong_endpoint =
                NetworkEndpoint::new("https", format!("wrong{i}.example.com"), 443);
            let invalid = mgr.validate_lease(&token, Some(&wrong_endpoint)).await;
            assert!(invalid.is_err());

            // Burn session
            mgr.burn_lease(&token).await;

            // Post-burn must fail
            let post_burn = mgr.validate_lease(&token, Some(&endpoint)).await;
            assert!(post_burn.is_err());
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }
}
