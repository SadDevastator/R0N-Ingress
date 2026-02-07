//! Error types for the L4 Passthrough module.

use std::io;
use thiserror::Error;

/// Result type for L4 passthrough operations.
pub type L4Result<T> = Result<T, L4Error>;

/// Errors that can occur during L4 passthrough operations.
#[derive(Debug, Error)]
pub enum L4Error {
    /// IO error during network operations.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Connection to backend failed.
    #[error("Backend connection failed: {0}")]
    BackendConnection(String),

    /// No backend available.
    #[error("No backend available for: {0}")]
    NoBackend(String),

    /// Backend health check failed.
    #[error("Backend health check failed: {0}")]
    HealthCheckFailed(String),

    /// Connection timeout.
    #[error("Connection timeout: {0}")]
    Timeout(String),

    /// Connection limit exceeded.
    #[error("Connection limit exceeded: {limit} connections")]
    ConnectionLimitExceeded {
        /// Maximum allowed connections.
        limit: usize,
    },

    /// Invalid configuration.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Bind address already in use.
    #[error("Bind address in use: {0}")]
    AddressInUse(String),

    /// Connection closed unexpectedly.
    #[error("Connection closed: {0}")]
    ConnectionClosed(String),

    /// Protocol error.
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Session not found.
    #[error("Session not found: {0}")]
    SessionNotFound(String),

    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl L4Error {
    /// Check if this error is recoverable.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            L4Error::Io(_)
                | L4Error::BackendConnection(_)
                | L4Error::Timeout(_)
                | L4Error::ConnectionClosed(_)
        )
    }

    /// Check if this error should trigger a backend health check.
    pub fn should_check_health(&self) -> bool {
        matches!(
            self,
            L4Error::BackendConnection(_) | L4Error::HealthCheckFailed(_) | L4Error::Timeout(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = L4Error::NoBackend("mysql".to_string());
        assert!(err.to_string().contains("mysql"));

        let err = L4Error::ConnectionLimitExceeded { limit: 100 };
        assert!(err.to_string().contains("100"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let l4_err: L4Error = io_err.into();
        assert!(matches!(l4_err, L4Error::Io(_)));
    }

    #[test]
    fn test_is_recoverable() {
        assert!(L4Error::Io(io::Error::new(io::ErrorKind::Other, "test")).is_recoverable());
        assert!(L4Error::BackendConnection("test".to_string()).is_recoverable());
        assert!(L4Error::Timeout("test".to_string()).is_recoverable());
        assert!(L4Error::ConnectionClosed("test".to_string()).is_recoverable());

        assert!(!L4Error::InvalidConfig("test".to_string()).is_recoverable());
        assert!(!L4Error::NoBackend("test".to_string()).is_recoverable());
    }

    #[test]
    fn test_should_check_health() {
        assert!(L4Error::BackendConnection("test".to_string()).should_check_health());
        assert!(L4Error::HealthCheckFailed("test".to_string()).should_check_health());
        assert!(L4Error::Timeout("test".to_string()).should_check_health());

        assert!(!L4Error::Io(io::Error::new(io::ErrorKind::Other, "test")).should_check_health());
        assert!(!L4Error::InvalidConfig("test".to_string()).should_check_health());
    }
}
