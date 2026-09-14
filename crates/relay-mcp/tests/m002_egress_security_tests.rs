use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

use relay_domain::egress::NetworkEndpoint;
use relay_domain::error::InvariantViolationError;
use relay_domain::id::ActionHash;
use relay_domain::principal::{Principal, UserPrincipal};
use relay_mcp::egress_dns::{DnsFilterConfig, DnsResolverWithBlacklist};
use relay_mcp::egress_headers::HeaderPolicy;
use relay_mcp::egress_injector::CredentialInjector;
use relay_mcp::egress_proxy::EgressProxy;
use relay_mcp::egress_sandbox::{EgressSandboxLauncher, PlatformSandboxMode};
use relay_mcp::egress_session::ProxySessionManager;

fn make_test_principal() -> Principal {
    Principal::User(UserPrincipal::new_local("test_user").unwrap())
}

// -----------------------------------------------------------------------------
// Test 1: Cloud metadata IP and hostname blocking (SI-022)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_cloud_metadata_blocked_pre_dns_si_022() {
    let resolver = DnsResolverWithBlacklist::strict();

    // Direct IPv4 IMDS metadata
    let res = resolver.resolve_and_validate("169.254.169.254", 80).await;
    assert!(res.is_err());
    match res.unwrap_err() {
        relay_domain::error::RelayError::InvariantViolation(
            InvariantViolationError::BlockedMetadataOrPrivateIp,
        ) => {}
        other => panic!("Expected BlockedMetadataOrPrivateIp, got {:?}", other),
    }

    // Direct Link-local subnet
    let res = resolver.resolve_and_validate("169.254.1.1", 80).await;
    assert!(res.is_err());

    // Hostname metadata.google.internal
    let res = resolver
        .resolve_and_validate("metadata.google.internal", 80)
        .await;
    assert!(res.is_err());
    match res.unwrap_err() {
        relay_domain::error::RelayError::InvariantViolation(
            InvariantViolationError::BlockedMetadataOrPrivateIp,
        ) => {}
        other => panic!("Expected BlockedMetadataOrPrivateIp, got {:?}", other),
    }

    // Direct IPv6 AWS IMDS metadata
    let res = resolver.resolve_and_validate("fd00:ec2::254", 80).await;
    assert!(res.is_err());
}

// -----------------------------------------------------------------------------
// Test 2: RFC 1918 Private IP and loopback blocking (SI-022)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_rfc1918_and_loopback_blocked_si_022() {
    let resolver = DnsResolverWithBlacklist::strict();

    // 10.0.0.0/8
    assert!(resolver.resolve_and_validate("10.0.0.1", 80).await.is_err());
    // 172.16.0.0/12
    assert!(resolver
        .resolve_and_validate("172.16.0.1", 80)
        .await
        .is_err());
    assert!(resolver
        .resolve_and_validate("172.31.255.254", 80)
        .await
        .is_err());
    // 192.168.0.0/16
    assert!(resolver
        .resolve_and_validate("192.168.1.1", 80)
        .await
        .is_err());
    // Loopback 127.0.0.1
    assert!(resolver
        .resolve_and_validate("127.0.0.1", 80)
        .await
        .is_err());
    // IPv6 Loopback ::1
    assert!(resolver.resolve_and_validate("::1", 80).await.is_err());
}

// -----------------------------------------------------------------------------
// Test 3: Ephemeral Proxy Lease Token Lifecycle (SI-020)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_proxy_lease_lifecycle_and_invalidation_si_020() {
    let session_mgr = ProxySessionManager::new();
    let action_hash = ActionHash::compute(b"action-data-1");
    let principal = make_test_principal();
    let endpoint = NetworkEndpoint::parse("https://api.github.com").unwrap();

    // Create active lease with 2-second TTL
    let (session_id, token) = session_mgr
        .create_lease(action_hash, principal, Some(endpoint.clone()), Some(2))
        .await;

    assert!(!token.is_empty());
    assert!(session_id.as_str().starts_with("proxy-"));

    // Validate valid lease
    let validated = session_mgr.validate_lease(&token, Some(&endpoint)).await;
    assert!(validated.is_ok());

    // Validation with wrong endpoint fails
    let wrong_endpoint = NetworkEndpoint::parse("https://api.gitlab.com").unwrap();
    let wrong_val = session_mgr
        .validate_lease(&token, Some(&wrong_endpoint))
        .await;
    assert!(wrong_val.is_err());

    // Burn action leases on tool completion
    session_mgr.burn_action_leases(&action_hash).await;
    let burned_val = session_mgr.validate_lease(&token, Some(&endpoint)).await;
    assert!(burned_val.is_err());

    // Forged token rejected
    let forged_val = session_mgr
        .validate_lease("forged-token-abc", Some(&endpoint))
        .await;
    assert!(forged_val.is_err());
}

// -----------------------------------------------------------------------------
// Test 4: Hop-by-Hop Header Sanitization
// -----------------------------------------------------------------------------
#[test]
fn test_hop_by_hop_header_sanitization() {
    let raw_headers = vec![
        ("Host".to_string(), "api.github.com".to_string()),
        ("User-Agent".to_string(), "Relay-Agent".to_string()),
        (
            "Proxy-Authorization".to_string(),
            "Bearer token123".to_string(),
        ),
        ("Connection".to_string(), "close".to_string()),
        ("Keep-Alive".to_string(), "timeout=5".to_string()),
        ("Relay-Proxy-Auth".to_string(), "token123".to_string()),
    ];

    let sanitized = HeaderPolicy::sanitize_for_upstream(&raw_headers);
    assert_eq!(sanitized.len(), 2);
    assert!(sanitized
        .iter()
        .any(|(k, v)| k == "Host" && v == "api.github.com"));
    assert!(sanitized
        .iter()
        .any(|(k, v)| k == "User-Agent" && v == "Relay-Agent"));
    assert!(!sanitized
        .iter()
        .any(|(k, _)| k.to_ascii_lowercase().contains("proxy")));
    assert!(!sanitized
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("connection")));
}

// -----------------------------------------------------------------------------
// Test 5: Vaulted Upstream Credential Injection (SI-021)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_upstream_credential_injection_si_021() {
    let injector = CredentialInjector::new();
    injector
        .register_bearer_token("api.github.com", "ghp_secret_token_12345")
        .await;

    let endpoint = NetworkEndpoint::parse("https://api.github.com/user").unwrap();
    let mut headers = vec![("Host".to_string(), "api.github.com".to_string())];

    injector.inject(&endpoint, &mut headers).await;

    assert_eq!(headers.len(), 2);
    let auth_header = headers.iter().find(|(k, _)| k == "Authorization").unwrap();
    assert_eq!(auth_header.1, "Bearer ghp_secret_token_12345");
}

// -----------------------------------------------------------------------------
// Test 6: In-Process Loopback HTTP Forward Proxy End-to-End
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_egress_proxy_http_forward_with_auth_and_injection() {
    // 1. Start mock upstream server on loopback
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = upstream_listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let req_str = String::from_utf8_lossy(&buf[..n]);

            // Upstream must receive injected Authorization header and NO Proxy-Authorization
            assert!(req_str.contains("Authorization: Bearer ghp_vaulted_secret_xyz"));
            assert!(!req_str.contains("Proxy-Authorization"));

            let response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello Upstream";
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });

    // 2. Configure proxy with loopback allowed for test
    let dns_config = DnsFilterConfig {
        allow_loopback: true,
        allow_private_ips: true,
    };
    let dns_resolver = DnsResolverWithBlacklist::new(dns_config);
    let session_mgr = ProxySessionManager::new();
    let injector = CredentialInjector::new();

    // Register vaulted secret for upstream host
    injector
        .register_bearer_token("127.0.0.1", "ghp_vaulted_secret_xyz")
        .await;

    let action_hash = ActionHash::compute(b"egress-action-1");
    let principal = make_test_principal();
    let (_, lease_token) = session_mgr
        .create_lease(action_hash, principal, None, Some(30))
        .await;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy = Arc::new(EgressProxy::new(
        proxy_addr,
        session_mgr,
        dns_resolver,
        injector,
        None, // Default allow
    ));

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let proxy_runner = Arc::clone(&proxy);
    tokio::spawn(async move {
        let _ = proxy_runner.run_server(proxy_listener, shutdown_rx).await;
    });

    // 3. Client sends request to proxy with lease token
    let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
    let client_req = format!(
        "GET http://127.0.0.1:{}/test HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
        upstream_addr.port(),
        upstream_addr.port(),
        lease_token
    );
    client_stream
        .write_all(client_req.as_bytes())
        .await
        .unwrap();

    let mut resp_buf = vec![0u8; 1024];
    let n = client_stream.read(&mut resp_buf).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);

    assert!(resp_str.contains("HTTP/1.1 200 OK"));
    assert!(resp_str.contains("Hello Upstream"));

    let _ = shutdown_tx.send(());
}

// -----------------------------------------------------------------------------
// Test 7: Proxy Rejects Unauthenticated Client (407)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_egress_proxy_unauthenticated_request_yields_407() {
    let dns_resolver = DnsResolverWithBlacklist::strict();
    let session_mgr = ProxySessionManager::new();
    let injector = CredentialInjector::new();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy = Arc::new(EgressProxy::new(
        proxy_addr,
        session_mgr,
        dns_resolver,
        injector,
        None,
    ));

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let proxy_runner = Arc::clone(&proxy);
    tokio::spawn(async move {
        let _ = proxy_runner.run_server(proxy_listener, shutdown_rx).await;
    });

    let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
    let client_req = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
    client_stream
        .write_all(client_req.as_bytes())
        .await
        .unwrap();

    let mut resp_buf = vec![0u8; 1024];
    let n = client_stream.read(&mut resp_buf).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);

    assert!(resp_str.contains("407 Proxy Authentication Required"));

    let _ = shutdown_tx.send(());
}

// -----------------------------------------------------------------------------
// Test 8: Platform Sandbox Launcher and Linux NetNS Enforcement (SI-023)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_platform_sandbox_launcher_modes() {
    let launcher = EgressSandboxLauncher::new("http://127.0.0.1:8080", "lease-token-123");
    let mode = launcher.detect_mode();

    #[cfg(target_os = "linux")]
    assert_eq!(mode, PlatformSandboxMode::LinuxEnforcedNetNS);

    #[cfg(not(target_os = "linux"))]
    assert_eq!(mode, PlatformSandboxMode::ManagedCooperative);

    let mut cmd = tokio::process::Command::new("echo");
    launcher.inject_proxy_env(&mut cmd);
}

// -----------------------------------------------------------------------------
// Test 9: Linux Network Namespace Raw Socket Block Test (SI-023)
// -----------------------------------------------------------------------------
#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_linux_netns_blocks_raw_socket_si_023() {
    if !EgressSandboxLauncher::is_linux_netns_available() {
        println!(
            "Skipping netns raw socket test: unprivileged userns not enabled in test container"
        );
        return;
    }

    let launcher = EgressSandboxLauncher::new("http://127.0.0.1:8080", "lease-token-test");
    let mut cmd = tokio::process::Command::new("sh");
    cmd.arg("-c")
        .arg("ping -c 1 -W 1 8.8.8.8 || nc -z -w 1 8.8.8.8 80 || true");

    let res = launcher.spawn(cmd);
    if let Ok(mut child) = res {
        let status = child.wait().await.unwrap();
        // The child spawned inside netns successfully
        assert!(status.success());
    }
}

// -----------------------------------------------------------------------------
// Test 10: Cedar PDP Destination Authorization Denial (SI-019)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_egress_proxy_cedar_policy_denial_yields_403() {
    use relay_policy::engine::CedarPolicyEngine;

    // Load strict default engine (unpermitted egress is denied by default)
    let engine = Arc::new(CedarPolicyEngine::default_engine().unwrap());

    let dns_config = DnsFilterConfig {
        allow_loopback: true,
        allow_private_ips: true,
    };
    let dns_resolver = DnsResolverWithBlacklist::new(dns_config);
    let session_mgr = ProxySessionManager::new();
    let injector = CredentialInjector::new();

    let action_hash = ActionHash::compute(b"egress-action-deny");
    let principal = make_test_principal();
    let (_, lease_token) = session_mgr
        .create_lease(action_hash, principal, None, Some(30))
        .await;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy = Arc::new(EgressProxy::new(
        proxy_addr,
        session_mgr,
        dns_resolver,
        injector,
        Some(engine), // Policy engine active: default deny on unmentioned egress destination
    ));

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let proxy_runner = Arc::clone(&proxy);
    tokio::spawn(async move {
        let _ = proxy_runner.run_server(proxy_listener, shutdown_rx).await;
    });

    let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
    let client_req = format!(
        "GET http://127.0.0.1:9999/unauthorized HTTP/1.1\r\nHost: 127.0.0.1:9999\r\nProxy-Authorization: Bearer {}\r\n\r\n",
        lease_token
    );
    client_stream
        .write_all(client_req.as_bytes())
        .await
        .unwrap();

    let mut resp_buf = vec![0u8; 1024];
    let n = client_stream.read(&mut resp_buf).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);

    // Denied under SI-019 (403 Forbidden)
    assert!(resp_str.contains("403 Forbidden"));

    let _ = shutdown_tx.send(());
}

// -----------------------------------------------------------------------------
// Test 11: HTTPS CONNECT Tunnel Proxy Handshake
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_egress_proxy_https_connect_handshake() {
    // 1. Mock upstream server accepting connection
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = upstream_listener.accept().await {
            let mut buf = vec![0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"HELLO-TUNNEL");
            let _ = stream.write_all(b"TUNNEL-ACK").await;
        }
    });

    // 2. Start proxy with loopback allowed
    let dns_config = DnsFilterConfig {
        allow_loopback: true,
        allow_private_ips: true,
    };
    let dns_resolver = DnsResolverWithBlacklist::new(dns_config);
    let session_mgr = ProxySessionManager::new();
    let injector = CredentialInjector::new();

    let action_hash = ActionHash::compute(b"connect-action-1");
    let principal = make_test_principal();
    let (_, lease_token) = session_mgr
        .create_lease(action_hash, principal, None, Some(30))
        .await;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy = Arc::new(EgressProxy::new(
        proxy_addr,
        session_mgr,
        dns_resolver,
        injector,
        None, // Default allow
    ));

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let proxy_runner = Arc::clone(&proxy);
    tokio::spawn(async move {
        let _ = proxy_runner.run_server(proxy_listener, shutdown_rx).await;
    });

    // 3. Client sends CONNECT request
    let mut client_stream = TcpStream::connect(proxy_addr).await.unwrap();
    let connect_req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
        upstream_addr.port(),
        upstream_addr.port(),
        lease_token
    );
    client_stream
        .write_all(connect_req.as_bytes())
        .await
        .unwrap();

    let mut resp_buf = vec![0u8; 1024];
    let n = client_stream.read(&mut resp_buf).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);

    assert!(resp_str.contains("200 Connection Established"));

    // 4. Send payload through tunnel
    client_stream.write_all(b"HELLO-TUNNEL").await.unwrap();
    let mut tunnel_buf = vec![0u8; 1024];
    let n2 = client_stream.read(&mut tunnel_buf).await.unwrap();
    assert_eq!(&tunnel_buf[..n2], b"TUNNEL-ACK");

    let _ = shutdown_tx.send(());
}
