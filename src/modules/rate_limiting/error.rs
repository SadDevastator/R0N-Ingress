//! Error types for rate limiting.

use std::fmt;

/// Result type for rate limiting operations.
pub type RateLimitResult<T> = Result<T, RateLimitError>;

/// Errors that can occur during rate limiting.
#[derive(Debug)]
pub enum RateLimitError {
    /// Invalid configuration.
    InvalidConfig(String),

    /// Redis connection error.
    RedisError(String),

    /// Bucket not found.
    BucketNotFound(String),

    /// Invalid key format.
    InvalidKey(String),

    /// Operation timed out.
    Timeout(String),

    /// Distributed state synchronization error.
    SyncError(String),

    /// Internal error.
    Internal(String),
}

impl fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid configuration: {msg}"),
            Self::RedisError(msg) => write!(f, "redis error: {msg}"),
            Self::BucketNotFound(key) => write!(f, "bucket not found: {key}"),
            Self::InvalidKey(key) => write!(f, "invalid key format: {key}"),
            Self::Timeout(msg) => write!(f, "operation timed out: {msg}"),
            Self::SyncError(msg) => write!(f, "sync error: {msg}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for RateLimitError {}

impl RateLimitError {
    /// Check if the error is recoverable.
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::Timeout(_) | Self::SyncError(_) | Self::RedisError(_)
        )
    }

    /// Check if the error indicates a configuration problem.
    #[must_use]
    pub fn is_config_error(&self) -> bool {
        matches!(self, Self::InvalidConfig(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = RateLimitError::InvalidConfig("bad value".to_string());
        assert_eq!(err.to_string(), "invalid configuration: bad value");

        let err = RateLimitError::RedisError("connection refused".to_string());
        assert_eq!(err.to_string(), "redis error: connection refused");

        let err = RateLimitError::BucketNotFound("user:123".to_string());
        assert_eq!(err.to_string(), "bucket not found: user:123");
    }

    #[test]
    fn test_is_recoverable() {
        assert!(RateLimitError::Timeout("test".to_string()).is_recoverable());
        assert!(RateLimitError::SyncError("test".to_string()).is_recoverable());
        assert!(RateLimitError::RedisError("test".to_string()).is_recoverable());

        assert!(!RateLimitError::InvalidConfig("test".to_string()).is_recoverable());
        assert!(!RateLimitError::BucketNotFound("test".to_string()).is_recoverable());
    }

    #[test]
    fn test_is_config_error() {
        assert!(RateLimitError::InvalidConfig("test".to_string()).is_config_error());
        assert!(!RateLimitError::Timeout("test".to_string()).is_config_error());
    }
}
