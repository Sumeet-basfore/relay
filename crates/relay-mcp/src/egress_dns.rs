use relay_domain::error::{InvariantViolationError, RelayError};
use std::net::{IpAddr, SocketAddr};
use tracing::{debug, warn};

/// Configuration options for DNS resolver and IP destination filter
#[derive(Debug, Clone, Default)]
pub struct DnsFilterConfig {
    pub allow_loopback: bool,
    pub allow_private_ips: bool,
}

/// Secure DNS Resolver with strict IP blacklisting and pinning (SI-022)
#[derive(Debug, Clone)]
pub struct DnsResolverWithBlacklist {
    config: DnsFilterConfig,
}

impl DnsResolverWithBlacklist {
    pub fn new(config: DnsFilterConfig) -> Self {
        Self { config }
    }

    pub fn strict() -> Self {
        Self::new(DnsFilterConfig::default())
    }

    /// Check if a hostname string itself matches well-known cloud metadata domains
    pub fn is_forbidden_hostname(host: &str) -> bool {
        let lower = host.to_ascii_lowercase();
        let trimmed = lower.trim_end_matches('.');
        trimmed == "metadata.google.internal"
            || trimmed == "metadata"
            || trimmed == "instance-data"
            || trimmed.ends_with(".internal")
            || trimmed.contains("169.254.169.254")
    }

    /// Check if an IP address is in a prohibited range (cloud metadata, link-local, loopback, private)
    pub fn is_forbidden_ip(&self, ip: IpAddr) -> Result<(), &'static str> {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();

                // 0.0.0.0/8 (unspecified)
                if octets[0] == 0 {
                    return Err("Unspecified IPv4 address (0.0.0.0/8) is forbidden");
                }

                // 127.0.0.0/8 (loopback)
                if v4.is_loopback() && !self.config.allow_loopback {
                    return Err("Loopback address (127.0.0.0/8) is forbidden");
                }

                // 169.254.0.0/16 (Link-local & AWS/Azure/GCP Cloud Metadata IMDS 169.254.169.254)
                if octets[0] == 169 && octets[1] == 254 {
                    return Err("Cloud metadata / Link-local address (169.254.0.0/16) is strictly forbidden (SI-022)");
                }

                // RFC 1918 Private subnets
                if !self.config.allow_private_ips {
                    // 10.0.0.0/8
                    if octets[0] == 10 {
                        return Err("RFC 1918 private subnet (10.0.0.0/8) is forbidden");
                    }
                    // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
                    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                        return Err("RFC 1918 private subnet (172.16.0.0/12) is forbidden");
                    }
                    // 192.168.0.0/16
                    if octets[0] == 192 && octets[1] == 168 {
                        return Err("RFC 1918 private subnet (192.168.0.0/16) is forbidden");
                    }
                }

                // 255.255.255.255 / Broadcast
                if v4.is_broadcast() {
                    return Err("Broadcast address is forbidden");
                }

                // 224.0.0.0/4 Multicast
                if v4.is_multicast() {
                    return Err("Multicast IPv4 address is forbidden");
                }
            }
            IpAddr::V6(v6) => {
                // IPv4-mapped IPv6 (::ffff:a.b.c.d) or IPv4-compatible IPv6 (::a.b.c.d)
                if let Some(v4) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4()) {
                    return self.is_forbidden_ip(IpAddr::V4(v4));
                }

                let segments = v6.segments();

                // ::1 (loopback)
                if v6.is_loopback() && !self.config.allow_loopback {
                    return Err("Loopback address (::1) is forbidden");
                }

                // ff00::/8 (multicast)
                if v6.is_multicast() {
                    return Err("Multicast IPv6 address is forbidden");
                }

                // :: (unspecified)
                if v6.is_unspecified() {
                    return Err("Unspecified IPv6 address is forbidden");
                }

                // fe80::/10 (Link-local)
                if (segments[0] & 0xffc0) == 0xfe80 {
                    return Err("IPv6 link-local address (fe80::/10) is forbidden");
                }

                // AWS IPv6 IMDS metadata: fd00:ec2::254
                if segments[0] == 0xfd00 && segments[1] == 0x0ec2 && segments[7] == 0x0254 {
                    return Err("AWS IPv6 Cloud Metadata address (fd00:ec2::254) is strictly forbidden (SI-022)");
                }

                // Unique Local Addresses / RFC 4193: fc00::/7 (fc00 - fdff)
                if !self.config.allow_private_ips && (segments[0] & 0xfe00) == 0xfc00 {
                    return Err("RFC 4193 Unique Local IPv6 subnet (fc00::/7) is forbidden");
                }
            }
        }

        Ok(())
    }

    /// Resolve hostname and validate every resolved IP against security blacklists.
    /// Returns the first validated SocketAddr for IP pinning.
    pub async fn resolve_and_validate(
        &self,
        host: &str,
        port: u16,
    ) -> Result<SocketAddr, RelayError> {
        if Self::is_forbidden_hostname(host) {
            warn!(
                host = host,
                "Cloud metadata hostname lookup rejected under SI-022"
            );
            return Err(RelayError::InvariantViolation(
                InvariantViolationError::BlockedMetadataOrPrivateIp,
            ));
        }

        // Check if host is direct IP literal
        if let Ok(ip) = host.parse::<IpAddr>() {
            if let Err(reason) = self.is_forbidden_ip(ip) {
                warn!(ip = %ip, reason = reason, "Direct IP connection rejected under SI-022");
                return Err(RelayError::InvariantViolation(
                    InvariantViolationError::BlockedMetadataOrPrivateIp,
                ));
            }
            return Ok(SocketAddr::new(ip, port));
        }

        // Perform DNS resolution
        let host_port = format!("{}:{}", host, port);
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&host_port)
            .await
            .map_err(|e| {
                RelayError::Execution(relay_domain::error::ExecutionError::EgressProxyError(
                    format!("DNS resolution failed for '{host_port}': {e}"),
                ))
            })?
            .collect();

        if addrs.is_empty() {
            return Err(RelayError::Execution(
                relay_domain::error::ExecutionError::EgressProxyError(format!(
                    "No DNS records resolved for '{host}'"
                )),
            ));
        }

        // Validate ALL resolved addresses (SI-022: Prevent multi-homed / rebinding attacks)
        for addr in &addrs {
            if let Err(reason) = self.is_forbidden_ip(addr.ip()) {
                warn!(host = host, ip = %addr.ip(), reason = reason, "DNS resolution resolved to blacklisted IP under SI-022");
                return Err(RelayError::InvariantViolation(
                    InvariantViolationError::BlockedMetadataOrPrivateIp,
                ));
            }
        }

        debug!(host = host, pinned_ip = %addrs[0].ip(), "DNS resolved and pinned successfully");
        Ok(addrs[0])
    }
}
