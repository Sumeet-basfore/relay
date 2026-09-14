use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use relay_domain::egress::NetworkEndpoint;
use relay_domain::security::RedactedSecret;
use tracing::debug;

pub type EndpointCredentialMap = HashMap<String, Vec<(String, String)>>;

/// Upstream credential injector for mediating authorized outbound requests (SI-021)
#[derive(Debug, Clone, Default)]
pub struct CredentialInjector {
    /// Maps endpoint hostname (e.g. "api.github.com") to header name and secret value
    credentials: Arc<RwLock<EndpointCredentialMap>>,
}

impl CredentialInjector {
    pub fn new() -> Self {
        Self {
            credentials: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register vaulted credentials for an upstream endpoint host (SI-021)
    pub async fn register_bearer_token(&self, host: impl Into<String>, token: impl Into<String>) {
        let host_str = host.into().to_ascii_lowercase();
        let auth_val = format!("Bearer {}", token.into());
        let mut lock = self.credentials.write().await;
        lock.entry(host_str)
            .or_default()
            .push(("Authorization".to_string(), auth_val));
    }

    /// Register arbitrary custom vaulted header (e.g. "X-API-Key") for an endpoint host
    pub async fn register_header(
        &self,
        host: impl Into<String>,
        header_name: impl Into<String>,
        header_value: impl Into<String>,
    ) {
        let host_str = host.into().to_ascii_lowercase();
        let mut lock = self.credentials.write().await;
        lock.entry(host_str)
            .or_default()
            .push((header_name.into(), header_value.into()));
    }

    /// Inject vaulted credentials into outgoing upstream headers if host matches (SI-021)
    pub async fn inject(&self, endpoint: &NetworkEndpoint, headers: &mut Vec<(String, String)>) {
        let host_key = endpoint.host.to_ascii_lowercase();
        let lock = self.credentials.read().await;

        if let Some(creds) = lock.get(&host_key) {
            for (header_name, header_val) in creds {
                // Replace or append the header
                let mut replaced = false;
                for (name, val) in headers.iter_mut() {
                    if name.eq_ignore_ascii_case(header_name) {
                        *val = header_val.clone();
                        replaced = true;
                        break;
                    }
                }
                if !replaced {
                    headers.push((header_name.clone(), header_val.clone()));
                }
                debug!(
                    host = %endpoint.host,
                    header = %header_name,
                    redacted = %RedactedSecret::new(header_val.to_string()).to_string(),
                    "Injected vaulted credential into upstream request"
                );
            }
        }
    }
}
