//! Typed registry for native connectors.
//!
//! Enforces:
//! - Complete mediation: Unknown connector namespaces fail closed
//! - Extensibility for future PostgreSQL and Filesystem connectors
//! - Thread-safe concurrency (Send + Sync)

use std::collections::HashMap;
use std::sync::Arc;

use relay_domain::NativeConnector;

/// Typed registry managing available native in-process connectors.
#[derive(Clone, Default)]
pub struct ConnectorRegistry {
    connectors: HashMap<String, Arc<dyn NativeConnector>>,
}

impl ConnectorRegistry {
    /// Creates an empty connector registry.
    pub fn new() -> Self {
        Self {
            connectors: HashMap::new(),
        }
    }

    /// Registers a native connector under its namespace.
    pub fn register(&mut self, connector: Arc<dyn NativeConnector>) {
        self.connectors
            .insert(connector.namespace().to_string(), connector);
    }

    /// Retrieves a connector by its namespace (e.g. "github").
    pub fn get(&self, namespace: &str) -> Option<Arc<dyn NativeConnector>> {
        self.connectors.get(namespace).cloned()
    }

    /// Returns whether the given namespace corresponds to a registered native connector.
    pub fn is_native(&self, namespace: &str) -> bool {
        self.connectors.contains_key(namespace)
    }

    /// Returns a list of all registered connector namespaces.
    pub fn registered_namespaces(&self) -> Vec<String> {
        let mut namespaces: Vec<String> = self.connectors.keys().cloned().collect();
        namespaces.sort();
        namespaces
    }
}
