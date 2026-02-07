//! Error types for the HTTP handler module.

use std::io;
use thiserror::Error;

/// Errors that can occur in HTTP handling.
#[derive(Debug, Error)]
pub enum HttpError {
    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// HTTP parsing error.
    #[error("Parse error: {0}")]
    Parse(String),

    /// Invalid HTTP method.
    #[error("Invalid method: {0}")]
    InvalidMethod(String),

    /// Invalid HTTP version.
    #[error("Invalid HTTP version: {0}")]
    InvalidVersion(String),

    /// Invalid header.
    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    /// Invalid URI.
    #[error("Invalid URI: {0}")]
    InvalidUri(String),

    /// Request too large.
    #[error("Request too large: {size} bytes (max: {max})")]
    RequestTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Header too large.
    #[error("Header too large: {size} bytes (max: {max})")]
    HeaderTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Too many headers.
    #[error("Too many headers: {count} (max: {max})")]
    TooManyHeaders {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Timeout error.
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Connection closed.
    #[error("Connection closed")]
    ConnectionClosed,

    /// Protocol error.
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// HTTP/2 specific error.
    #[error("HTTP/2 error: {0}")]
    Http2(String),

    /// Routing error.
    #[error("Routing error: {0}")]
    Routing(String),

    /// No route found for request.
    #[error("No route found for {method} {path}")]
    NoRoute {
        /// HTTP method.
        method: String,
        /// Request path.
        path: String,
    },

    /// Backend error.
    #[error("Backend error: {0}")]
    Backend(String),

    /// Middleware error.
    #[error("Middleware error: {0}")]
    Middleware(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Result type for HTTP operations.
pub type HttpResult<T> = Result<T, HttpError>;

impl From<httparse::Error> for HttpError {
    fn from(err: httparse::Error) -> Self {
        HttpError::Parse(err.to_string())
    }
}

impl From<http::Error> for HttpError {
    fn from(err: http::Error) -> Self {
        HttpError::Protocol(err.to_string())
    }
}

impl From<http::uri::InvalidUri> for HttpError {
    fn from(err: http::uri::InvalidUri) -> Self {
        HttpError::InvalidUri(err.to_string())
    }
}

impl From<http::method::InvalidMethod> for HttpError {
    fn from(err: http::method::InvalidMethod) -> Self {
        HttpError::InvalidMethod(err.to_string())
    }
}

impl From<http::header::InvalidHeaderName> for HttpError {
    fn from(err: http::header::InvalidHeaderName) -> Self {
        HttpError::InvalidHeader(err.to_string())
    }
}

impl From<http::header::InvalidHeaderValue> for HttpError {
    fn from(err: http::header::InvalidHeaderValue) -> Self {
        HttpError::InvalidHeader(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = HttpError::NoRoute {
            method: "GET".to_string(),
            path: "/api/users".to_string(),
        };
        assert_eq!(err.to_string(), "No route found for GET /api/users");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let http_err = HttpError::from(io_err);
        assert!(matches!(http_err, HttpError::Io(_)));
    }

    #[test]
    fn test_request_too_large() {
        let err = HttpError::RequestTooLarge {
            size: 10_000_000,
            max: 1_000_000,
        };
        assert!(err.to_string().contains("10000000"));
    }
}
