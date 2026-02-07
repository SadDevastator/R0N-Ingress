//! WebSocket error types.

use std::fmt;
use std::io;

/// Result type for WebSocket operations.
pub type WebSocketResult<T> = Result<T, WebSocketError>;

/// Errors that can occur during WebSocket handling.
#[derive(Debug)]
pub enum WebSocketError {
    /// I/O error.
    Io(io::Error),

    /// Protocol error.
    Protocol(String),

    /// Invalid upgrade request.
    InvalidUpgrade(String),

    /// Invalid WebSocket key.
    InvalidKey,

    /// Invalid frame.
    InvalidFrame(String),

    /// Frame too large.
    FrameTooLarge {
        /// Maximum allowed size.
        max: usize,
        /// Actual size.
        actual: usize,
    },

    /// Connection closed.
    ConnectionClosed,

    /// Invalid UTF-8 in text message.
    InvalidUtf8,

    /// Invalid close code.
    InvalidCloseCode(u16),

    /// Subprotocol negotiation failed.
    SubprotocolMismatch {
        /// Requested subprotocols.
        requested: Vec<String>,
        /// Available subprotocols.
        available: Vec<String>,
    },

    /// Origin not allowed.
    OriginNotAllowed(String),

    /// Backend connection failed.
    BackendConnection(String),

    /// Configuration error.
    Config(String),

    /// Timeout.
    Timeout,

    /// Tungstenite error.
    Tungstenite(tokio_tungstenite::tungstenite::Error),
}

impl fmt::Display for WebSocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Protocol(msg) => write!(f, "Protocol error: {msg}"),
            Self::InvalidUpgrade(msg) => write!(f, "Invalid upgrade request: {msg}"),
            Self::InvalidKey => write!(f, "Invalid WebSocket key"),
            Self::InvalidFrame(msg) => write!(f, "Invalid frame: {msg}"),
            Self::FrameTooLarge { max, actual } => {
                write!(f, "Frame too large: {actual} bytes (max {max})")
            },
            Self::ConnectionClosed => write!(f, "Connection closed"),
            Self::InvalidUtf8 => write!(f, "Invalid UTF-8 in text message"),
            Self::InvalidCloseCode(code) => write!(f, "Invalid close code: {code}"),
            Self::SubprotocolMismatch {
                requested,
                available,
            } => {
                write!(
                    f,
                    "Subprotocol mismatch: requested {:?}, available {:?}",
                    requested, available
                )
            },
            Self::OriginNotAllowed(origin) => write!(f, "Origin not allowed: {origin}"),
            Self::BackendConnection(msg) => write!(f, "Backend connection failed: {msg}"),
            Self::Config(msg) => write!(f, "Configuration error: {msg}"),
            Self::Timeout => write!(f, "Operation timed out"),
            Self::Tungstenite(e) => write!(f, "WebSocket error: {e}"),
        }
    }
}

impl std::error::Error for WebSocketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Tungstenite(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for WebSocketError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for WebSocketError {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::Tungstenite(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = WebSocketError::Protocol("test error".to_string());
        assert!(err.to_string().contains("Protocol error"));

        let err = WebSocketError::InvalidKey;
        assert!(err.to_string().contains("Invalid WebSocket key"));

        let err = WebSocketError::FrameTooLarge {
            max: 1024,
            actual: 2048,
        };
        assert!(err.to_string().contains("2048"));
        assert!(err.to_string().contains("1024"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let ws_err: WebSocketError = io_err.into();
        assert!(matches!(ws_err, WebSocketError::Io(_)));
    }

    #[test]
    fn test_frame_too_large() {
        let err = WebSocketError::FrameTooLarge {
            max: 65536,
            actual: 100000,
        };
        let msg = err.to_string();
        assert!(msg.contains("Frame too large"));
        assert!(msg.contains("100000"));
    }

    #[test]
    fn test_subprotocol_mismatch() {
        let err = WebSocketError::SubprotocolMismatch {
            requested: vec!["graphql".to_string()],
            available: vec!["json".to_string()],
        };
        let msg = err.to_string();
        assert!(msg.contains("graphql"));
        assert!(msg.contains("json"));
    }
}
