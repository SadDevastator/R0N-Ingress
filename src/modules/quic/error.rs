//! QUIC error types

use std::fmt;
use std::io;

/// QUIC-specific errors
#[derive(Debug)]
pub enum QuicError {
    /// Connection closed
    ConnectionClosed(String),

    /// Connection refused
    ConnectionRefused(String),

    /// Connection timeout
    ConnectionTimeout,

    /// Connection reset
    ConnectionReset,

    /// Stream error
    Stream(String),

    /// Stream closed
    StreamClosed(u64),

    /// Invalid stream ID
    InvalidStreamId(u64),

    /// Flow control error
    FlowControl(String),

    /// TLS/Crypto error
    Crypto(String),

    /// Handshake failed
    HandshakeFailed(String),

    /// Certificate error
    Certificate(String),

    /// Protocol error
    Protocol(String),

    /// Frame encoding error
    FrameEncoding(String),

    /// Configuration error
    Config(String),

    /// Transport parameter error
    TransportParameter(String),

    /// Application error with code
    Application(u64, String),

    /// Version negotiation failed
    VersionNegotiation,

    /// No available connection IDs
    NoConnectionIds,

    /// Address validation failed
    AddressValidation,

    /// 0-RTT rejected
    ZeroRttRejected,

    /// IO error
    Io(io::Error),

    /// Internal error
    Internal(String),
}

impl fmt::Display for QuicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionClosed(msg) => write!(f, "connection closed: {}", msg),
            Self::ConnectionRefused(msg) => write!(f, "connection refused: {}", msg),
            Self::ConnectionTimeout => write!(f, "connection timeout"),
            Self::ConnectionReset => write!(f, "connection reset"),
            Self::Stream(msg) => write!(f, "stream error: {}", msg),
            Self::StreamClosed(id) => write!(f, "stream {} closed", id),
            Self::InvalidStreamId(id) => write!(f, "invalid stream ID: {}", id),
            Self::FlowControl(msg) => write!(f, "flow control error: {}", msg),
            Self::Crypto(msg) => write!(f, "crypto error: {}", msg),
            Self::HandshakeFailed(msg) => write!(f, "handshake failed: {}", msg),
            Self::Certificate(msg) => write!(f, "certificate error: {}", msg),
            Self::Protocol(msg) => write!(f, "protocol error: {}", msg),
            Self::FrameEncoding(msg) => write!(f, "frame encoding error: {}", msg),
            Self::Config(msg) => write!(f, "configuration error: {}", msg),
            Self::TransportParameter(msg) => write!(f, "transport parameter error: {}", msg),
            Self::Application(code, msg) => write!(f, "application error {}: {}", code, msg),
            Self::VersionNegotiation => write!(f, "version negotiation failed"),
            Self::NoConnectionIds => write!(f, "no available connection IDs"),
            Self::AddressValidation => write!(f, "address validation failed"),
            Self::ZeroRttRejected => write!(f, "0-RTT rejected"),
            Self::Io(err) => write!(f, "IO error: {}", err),
            Self::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for QuicError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for QuicError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// Result type for QUIC operations
pub type QuicResult<T> = Result<T, QuicError>;

/// QUIC transport error codes (RFC 9000)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum TransportErrorCode {
    /// No error
    NoError = 0x00,

    /// Internal error
    InternalError = 0x01,

    /// Connection refused
    ConnectionRefused = 0x02,

    /// Flow control error
    FlowControlError = 0x03,

    /// Stream limit error
    StreamLimitError = 0x04,

    /// Stream state error
    StreamStateError = 0x05,

    /// Final size error
    FinalSizeError = 0x06,

    /// Frame encoding error
    FrameEncodingError = 0x07,

    /// Transport parameter error
    TransportParameterError = 0x08,

    /// Connection ID limit error
    ConnectionIdLimitError = 0x09,

    /// Protocol violation
    ProtocolViolation = 0x0a,

    /// Invalid token
    InvalidToken = 0x0b,

    /// Application error
    ApplicationError = 0x0c,

    /// Crypto buffer exceeded
    CryptoBufferExceeded = 0x0d,

    /// Key update error
    KeyUpdateError = 0x0e,

    /// AEAD limit reached
    AeadLimitReached = 0x0f,

    /// No viable path
    NoViablePath = 0x10,

    /// Crypto error (0x100-0x1ff range)
    CryptoError = 0x100,
}

impl TransportErrorCode {
    /// Get the error code value
    pub fn code(&self) -> u64 {
        *self as u64
    }

    /// Create from a u64 code
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0x00 => Some(Self::NoError),
            0x01 => Some(Self::InternalError),
            0x02 => Some(Self::ConnectionRefused),
            0x03 => Some(Self::FlowControlError),
            0x04 => Some(Self::StreamLimitError),
            0x05 => Some(Self::StreamStateError),
            0x06 => Some(Self::FinalSizeError),
            0x07 => Some(Self::FrameEncodingError),
            0x08 => Some(Self::TransportParameterError),
            0x09 => Some(Self::ConnectionIdLimitError),
            0x0a => Some(Self::ProtocolViolation),
            0x0b => Some(Self::InvalidToken),
            0x0c => Some(Self::ApplicationError),
            0x0d => Some(Self::CryptoBufferExceeded),
            0x0e => Some(Self::KeyUpdateError),
            0x0f => Some(Self::AeadLimitReached),
            0x10 => Some(Self::NoViablePath),
            c if (0x100..=0x1ff).contains(&c) => Some(Self::CryptoError),
            _ => None,
        }
    }

    /// Check if this is a crypto error
    pub fn is_crypto_error(&self) -> bool {
        matches!(self, Self::CryptoError)
    }
}

impl fmt::Display for TransportErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoError => write!(f, "NO_ERROR"),
            Self::InternalError => write!(f, "INTERNAL_ERROR"),
            Self::ConnectionRefused => write!(f, "CONNECTION_REFUSED"),
            Self::FlowControlError => write!(f, "FLOW_CONTROL_ERROR"),
            Self::StreamLimitError => write!(f, "STREAM_LIMIT_ERROR"),
            Self::StreamStateError => write!(f, "STREAM_STATE_ERROR"),
            Self::FinalSizeError => write!(f, "FINAL_SIZE_ERROR"),
            Self::FrameEncodingError => write!(f, "FRAME_ENCODING_ERROR"),
            Self::TransportParameterError => write!(f, "TRANSPORT_PARAMETER_ERROR"),
            Self::ConnectionIdLimitError => write!(f, "CONNECTION_ID_LIMIT_ERROR"),
            Self::ProtocolViolation => write!(f, "PROTOCOL_VIOLATION"),
            Self::InvalidToken => write!(f, "INVALID_TOKEN"),
            Self::ApplicationError => write!(f, "APPLICATION_ERROR"),
            Self::CryptoBufferExceeded => write!(f, "CRYPTO_BUFFER_EXCEEDED"),
            Self::KeyUpdateError => write!(f, "KEY_UPDATE_ERROR"),
            Self::AeadLimitReached => write!(f, "AEAD_LIMIT_REACHED"),
            Self::NoViablePath => write!(f, "NO_VIABLE_PATH"),
            Self::CryptoError => write!(f, "CRYPTO_ERROR"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = QuicError::ConnectionClosed("peer closed".to_string());
        assert!(err.to_string().contains("peer closed"));

        let err = QuicError::StreamClosed(42);
        assert!(err.to_string().contains("42"));
    }

    #[test]
    fn test_transport_error_code() {
        assert_eq!(TransportErrorCode::NoError.code(), 0x00);
        assert_eq!(TransportErrorCode::FlowControlError.code(), 0x03);

        let parsed = TransportErrorCode::from_code(0x03);
        assert_eq!(parsed, Some(TransportErrorCode::FlowControlError));
    }

    #[test]
    fn test_crypto_error_range() {
        let code = TransportErrorCode::from_code(0x150);
        assert_eq!(code, Some(TransportErrorCode::CryptoError));
        assert!(code.unwrap().is_crypto_error());
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let quic_err: QuicError = io_err.into();
        assert!(matches!(quic_err, QuicError::Io(_)));
    }
}
