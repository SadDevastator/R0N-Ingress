//! TCP Router error types.

use std::net::SocketAddr;
use thiserror::Error;

/// Errors that can occur in the TCP router module.
#[derive(Debug, Error)]
pub enum TcpRouterError {
    /// Failed to bind to the specified address.
    #[error("failed to bind to {address}: {source}")]
    BindError {
        /// The address that failed to bind.
        address: SocketAddr,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to accept a connection.
    #[error("failed to accept connection: {0}")]
    AcceptError(#[source] std::io::Error),

    /// Failed to connect to backend.
    #[error("failed to connect to backend {address}: {source}")]
    BackendConnectError {
        /// The backend address.
        address: SocketAddr,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// No healthy backends available.
    #[error("no healthy backends available for route '{route}'")]
    NoHealthyBackends {
        /// The route name.
        route: String,
    },

    /// Route not found.
    #[error("no route found for connection from {peer}")]
    RouteNotFound {
        /// Source address of the connection.
        peer: SocketAddr,
    },

    /// Connection pool exhausted.
    #[error("connection pool exhausted for backend {address}")]
    PoolExhausted {
        /// The backend address.
        address: SocketAddr,
    },

    /// Connection timeout.
    #[error("connection timeout to {address}")]
    ConnectionTimeout {
        /// The backend address.
        address: SocketAddr,
    },

    /// Invalid configuration.
    #[error("invalid configuration: {message}")]
    ConfigError {
        /// Error message.
        message: String,
    },

    /// IO error during data transfer.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Module is not running.
    #[error("module is not running")]
    NotRunning,

    /// Module is already running.
    #[error("module is already running")]
    AlreadyRunning,
}

/// Result type for TCP router operations.
pub type TcpRouterResult<T> = Result<T, TcpRouterError>;
