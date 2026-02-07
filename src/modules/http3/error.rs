//! HTTP/3 errors

use std::fmt;

/// HTTP/3 error type
#[derive(Debug, Clone)]
pub enum Http3Error {
    /// No error
    NoError,

    /// General protocol error
    GeneralProtocolError,

    /// Internal error
    InternalError,

    /// Stream creation error
    StreamCreationError,

    /// Closed critical stream
    ClosedCriticalStream,

    /// Frame unexpected
    FrameUnexpected,

    /// Frame error
    FrameError,

    /// Excessive load
    ExcessiveLoad,

    /// ID error
    IdError,

    /// Settings error
    SettingsError,

    /// Missing settings
    MissingSettings,

    /// Request rejected
    RequestRejected,

    /// Request cancelled
    RequestCancelled,

    /// Request incomplete
    RequestIncomplete,

    /// Message error
    MessageError,

    /// Connect error
    ConnectError,

    /// Version fallback
    VersionFallback,

    /// QPACK decompression failed
    QpackDecompressionFailed,

    /// QPACK encoder stream error
    QpackEncoderStreamError,

    /// QPACK decoder stream error
    QpackDecoderStreamError,

    /// Connection timeout
    ConnectionTimeout,

    /// Configuration error
    Config(String),

    /// I/O error
    Io(String),

    /// QUIC transport error
    Transport(String),

    /// Application error with code
    Application(u64, String),
}

impl Http3Error {
    /// Get HTTP/3 error code
    pub fn code(&self) -> u64 {
        match self {
            Self::NoError => 0x100,
            Self::GeneralProtocolError => 0x101,
            Self::InternalError => 0x102,
            Self::StreamCreationError => 0x103,
            Self::ClosedCriticalStream => 0x104,
            Self::FrameUnexpected => 0x105,
            Self::FrameError => 0x106,
            Self::ExcessiveLoad => 0x107,
            Self::IdError => 0x108,
            Self::SettingsError => 0x109,
            Self::MissingSettings => 0x10a,
            Self::RequestRejected => 0x10b,
            Self::RequestCancelled => 0x10c,
            Self::RequestIncomplete => 0x10d,
            Self::MessageError => 0x10e,
            Self::ConnectError => 0x10f,
            Self::VersionFallback => 0x110,
            Self::QpackDecompressionFailed => 0x200,
            Self::QpackEncoderStreamError => 0x201,
            Self::QpackDecoderStreamError => 0x202,
            Self::ConnectionTimeout => 0xffff_0001,
            Self::Config(_) => 0xffff_0002,
            Self::Io(_) => 0xffff_0003,
            Self::Transport(_) => 0xffff_0004,
            Self::Application(code, _) => *code,
        }
    }

    /// Create from error code
    pub fn from_code(code: u64) -> Self {
        match code {
            0x100 => Self::NoError,
            0x101 => Self::GeneralProtocolError,
            0x102 => Self::InternalError,
            0x103 => Self::StreamCreationError,
            0x104 => Self::ClosedCriticalStream,
            0x105 => Self::FrameUnexpected,
            0x106 => Self::FrameError,
            0x107 => Self::ExcessiveLoad,
            0x108 => Self::IdError,
            0x109 => Self::SettingsError,
            0x10a => Self::MissingSettings,
            0x10b => Self::RequestRejected,
            0x10c => Self::RequestCancelled,
            0x10d => Self::RequestIncomplete,
            0x10e => Self::MessageError,
            0x10f => Self::ConnectError,
            0x110 => Self::VersionFallback,
            0x200 => Self::QpackDecompressionFailed,
            0x201 => Self::QpackEncoderStreamError,
            0x202 => Self::QpackDecoderStreamError,
            _ => Self::Application(code, String::new()),
        }
    }

    /// Check if this is a connection-level error
    pub fn is_connection_error(&self) -> bool {
        matches!(
            self,
            Self::GeneralProtocolError
                | Self::InternalError
                | Self::ClosedCriticalStream
                | Self::SettingsError
                | Self::MissingSettings
                | Self::QpackDecompressionFailed
                | Self::QpackEncoderStreamError
                | Self::QpackDecoderStreamError
        )
    }

    /// Check if request can be retried
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RequestRejected
                | Self::RequestCancelled
                | Self::ExcessiveLoad
                | Self::ConnectionTimeout
        )
    }
}

impl fmt::Display for Http3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoError => write!(f, "no error"),
            Self::GeneralProtocolError => write!(f, "general protocol error"),
            Self::InternalError => write!(f, "internal error"),
            Self::StreamCreationError => write!(f, "stream creation error"),
            Self::ClosedCriticalStream => write!(f, "closed critical stream"),
            Self::FrameUnexpected => write!(f, "frame unexpected"),
            Self::FrameError => write!(f, "frame error"),
            Self::ExcessiveLoad => write!(f, "excessive load"),
            Self::IdError => write!(f, "ID error"),
            Self::SettingsError => write!(f, "settings error"),
            Self::MissingSettings => write!(f, "missing settings"),
            Self::RequestRejected => write!(f, "request rejected"),
            Self::RequestCancelled => write!(f, "request cancelled"),
            Self::RequestIncomplete => write!(f, "request incomplete"),
            Self::MessageError => write!(f, "message error"),
            Self::ConnectError => write!(f, "connect error"),
            Self::VersionFallback => write!(f, "version fallback"),
            Self::QpackDecompressionFailed => write!(f, "QPACK decompression failed"),
            Self::QpackEncoderStreamError => write!(f, "QPACK encoder stream error"),
            Self::QpackDecoderStreamError => write!(f, "QPACK decoder stream error"),
            Self::ConnectionTimeout => write!(f, "connection timeout"),
            Self::Config(msg) => write!(f, "configuration error: {}", msg),
            Self::Io(msg) => write!(f, "I/O error: {}", msg),
            Self::Transport(msg) => write!(f, "transport error: {}", msg),
            Self::Application(code, msg) => {
                if msg.is_empty() {
                    write!(f, "application error: 0x{:x}", code)
                } else {
                    write!(f, "application error 0x{:x}: {}", code, msg)
                }
            },
        }
    }
}

impl std::error::Error for Http3Error {}

impl From<std::io::Error> for Http3Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

impl From<super::super::quic::error::QuicError> for Http3Error {
    fn from(err: super::super::quic::error::QuicError) -> Self {
        Self::Transport(err.to_string())
    }
}

/// HTTP/3 result type
pub type Http3Result<T> = Result<T, Http3Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        assert_eq!(Http3Error::NoError.code(), 0x100);
        assert_eq!(Http3Error::GeneralProtocolError.code(), 0x101);
        assert_eq!(Http3Error::QpackDecompressionFailed.code(), 0x200);
    }

    #[test]
    fn test_error_from_code() {
        assert!(matches!(Http3Error::from_code(0x100), Http3Error::NoError));
        assert!(matches!(
            Http3Error::from_code(0x101),
            Http3Error::GeneralProtocolError
        ));
        assert!(matches!(
            Http3Error::from_code(0x999),
            Http3Error::Application(0x999, _)
        ));
    }

    #[test]
    fn test_connection_error() {
        assert!(Http3Error::GeneralProtocolError.is_connection_error());
        assert!(Http3Error::ClosedCriticalStream.is_connection_error());
        assert!(!Http3Error::RequestRejected.is_connection_error());
    }

    #[test]
    fn test_retryable() {
        assert!(Http3Error::RequestRejected.is_retryable());
        assert!(Http3Error::ExcessiveLoad.is_retryable());
        assert!(!Http3Error::InternalError.is_retryable());
    }

    #[test]
    fn test_display() {
        assert_eq!(Http3Error::NoError.to_string(), "no error");
        assert_eq!(
            Http3Error::Config("bad config".to_string()).to_string(),
            "configuration error: bad config"
        );
    }
}
