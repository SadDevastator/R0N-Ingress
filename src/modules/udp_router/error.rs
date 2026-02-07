//! UDP Router error types.

use std::net::SocketAddr;
use thiserror::Error;

/// Errors that can occur in the UDP router module.
#[derive(Debug, Error)]
pub enum UdpRouterError {
    /// Failed to bind to the specified address.
    #[error("failed to bind to {address}: {source}")]
    BindError {
        /// The address that failed to bind.
        address: SocketAddr,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to send datagram.
    #[error("failed to send datagram to {address}: {source}")]
    SendError {
        /// The destination address.
        address: SocketAddr,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to receive datagram.
    #[error("failed to receive datagram: {0}")]
    RecvError(#[source] std::io::Error),

    /// No healthy backends available.
    #[error("no healthy backends available for route '{route}'")]
    NoHealthyBackends {
        /// The route name.
        route: String,
    },

    /// Route not found.
    #[error("no route found for datagram from {peer}")]
    RouteNotFound {
        /// Source address of the datagram.
        peer: SocketAddr,
    },

    /// Session expired.
    #[error("session {session_id} expired")]
    SessionExpired {
        /// The expired session ID.
        session_id: String,
    },

    /// Invalid configuration.
    #[error("invalid configuration: {message}")]
    ConfigError {
        /// Error message.
        message: String,
    },

    /// IO error.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Module is not running.
    #[error("module is not running")]
    NotRunning,

    /// Module is already running.
    #[error("module is already running")]
    AlreadyRunning,
}

/// Result type alias for UDP router operations.
pub type UdpRouterResult<T> = Result<T, UdpRouterError>;
