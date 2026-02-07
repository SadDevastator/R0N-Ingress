//! Tracing error types

use std::fmt;

/// Tracing error types
#[derive(Debug)]
pub enum TracingError {
    /// Configuration error
    Config(String),

    /// Invalid trace ID
    InvalidTraceId(String),

    /// Invalid span ID
    InvalidSpanId(String),

    /// Propagation error
    Propagation(String),

    /// Export error
    Export(String),

    /// Span not found
    SpanNotFound(String),

    /// Span already ended
    SpanAlreadyEnded(String),

    /// Sampling error
    Sampling(String),

    /// Context error
    Context(String),

    /// IO error
    Io(std::io::Error),

    /// Serialization error
    Serialization(String),

    /// Internal error
    Internal(String),
}

impl fmt::Display for TracingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "tracing config error: {}", msg),
            Self::InvalidTraceId(msg) => write!(f, "invalid trace ID: {}", msg),
            Self::InvalidSpanId(msg) => write!(f, "invalid span ID: {}", msg),
            Self::Propagation(msg) => write!(f, "propagation error: {}", msg),
            Self::Export(msg) => write!(f, "export error: {}", msg),
            Self::SpanNotFound(msg) => write!(f, "span not found: {}", msg),
            Self::SpanAlreadyEnded(msg) => write!(f, "span already ended: {}", msg),
            Self::Sampling(msg) => write!(f, "sampling error: {}", msg),
            Self::Context(msg) => write!(f, "context error: {}", msg),
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::Serialization(msg) => write!(f, "serialization error: {}", msg),
            Self::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for TracingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for TracingError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for TracingError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

/// Result type for tracing operations
pub type TracingResult<T> = Result<T, TracingError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = TracingError::Config("invalid config".to_string());
        assert!(err.to_string().contains("config error"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let err: TracingError = io_err.into();
        assert!(matches!(err, TracingError::Io(_)));
    }

    #[test]
    fn test_tracing_result() {
        let result: TracingResult<()> = Ok(());
        assert!(result.is_ok());

        let err_result: TracingResult<()> = Err(TracingError::Internal("test".to_string()));
        assert!(err_result.is_err());
    }
}
