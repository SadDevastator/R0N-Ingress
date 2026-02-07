//! Load balancer error types.

use std::net::SocketAddr;
use thiserror::Error;

/// Errors that can occur in the load balancer module.
#[derive(Debug, Error)]
pub enum LoadBalancerError {
    /// No backends available in the pool.
    #[error("no backends available in pool '{0}'")]
    NoBackendsAvailable(String),

    /// No healthy backends available.
    #[error("no healthy backends available in pool '{0}'")]
    NoHealthyBackends(String),

    /// Backend not found.
    #[error("backend {0} not found in pool '{1}'")]
    BackendNotFound(SocketAddr, String),

    /// Pool not found.
    #[error("pool '{0}' not found")]
    PoolNotFound(String),

    /// Pool already exists.
    #[error("pool '{0}' already exists")]
    PoolAlreadyExists(String),

    /// Health check failed.
    #[error("health check failed for {0}: {1}")]
    HealthCheckFailed(SocketAddr, String),

    /// Connection failed.
    #[error("connection to {0} failed: {1}")]
    ConnectionFailed(SocketAddr, String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    ConfigError(String),

    /// Invalid strategy.
    #[error("invalid strategy: {0}")]
    InvalidStrategy(String),

    /// IO error.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Module not running.
    #[error("load balancer not running")]
    NotRunning,

    /// Module already running.
    #[error("load balancer already running")]
    AlreadyRunning,
}

/// Result type for load balancer operations.
pub type LoadBalancerResult<T> = Result<T, LoadBalancerError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = LoadBalancerError::NoBackendsAvailable("web".to_string());
        assert_eq!(err.to_string(), "no backends available in pool 'web'");

        let err = LoadBalancerError::PoolNotFound("api".to_string());
        assert_eq!(err.to_string(), "pool 'api' not found");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let err: LoadBalancerError = io_err.into();
        assert!(matches!(err, LoadBalancerError::IoError(_)));
    }
}
