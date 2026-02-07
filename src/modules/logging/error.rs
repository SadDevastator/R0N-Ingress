//! Logging error types

use std::fmt;
use std::io;

/// Result type for logging operations
pub type LogResult<T> = Result<T, LogError>;

/// Logging errors
#[derive(Debug)]
pub enum LogError {
    /// Configuration error
    Config(String),

    /// IO error
    Io(io::Error),

    /// Serialization error
    Serialization(String),

    /// Rotation error
    Rotation(String),

    /// Output error
    Output(String),

    /// Buffer full
    BufferFull,

    /// Channel closed
    ChannelClosed,

    /// Invalid format
    InvalidFormat(String),

    /// Path error
    PathError(String),

    /// Permission denied
    PermissionDenied(String),

    /// Internal error
    Internal(String),
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "configuration error: {}", msg),
            Self::Io(err) => write!(f, "IO error: {}", err),
            Self::Serialization(msg) => write!(f, "serialization error: {}", msg),
            Self::Rotation(msg) => write!(f, "rotation error: {}", msg),
            Self::Output(msg) => write!(f, "output error: {}", msg),
            Self::BufferFull => write!(f, "log buffer full"),
            Self::ChannelClosed => write!(f, "log channel closed"),
            Self::InvalidFormat(msg) => write!(f, "invalid format: {}", msg),
            Self::PathError(msg) => write!(f, "path error: {}", msg),
            Self::PermissionDenied(msg) => write!(f, "permission denied: {}", msg),
            Self::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for LogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for LogError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for LogError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = LogError::Config("bad config".to_string());
        assert!(err.to_string().contains("configuration error"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let log_err: LogError = io_err.into();
        assert!(matches!(log_err, LogError::Io(_)));
    }

    #[test]
    fn test_buffer_full_error() {
        let err = LogError::BufferFull;
        assert_eq!(err.to_string(), "log buffer full");
    }
}
