//! Native PostgreSQL connector module for Relay.

pub mod client;
pub mod config;
pub mod connector;
pub mod error;
pub mod resource;
pub mod scope;

pub use client::{PostgresClient, PostgresResponse};
pub use config::PostgresClientConfig;
pub use connector::PostgresConnector;
pub use error::PostgresError;
pub use resource::{PostgresCredentials, PostgresResource};
pub use scope::{is_mutating_operation, validate_supported_surface};
