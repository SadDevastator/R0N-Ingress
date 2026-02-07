//! Error types for the MQTT handler module.

use std::io;
use thiserror::Error;

/// Errors that can occur in MQTT handling.
#[derive(Debug, Error)]
pub enum MqttError {
    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Protocol error.
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Invalid packet type.
    #[error("Invalid packet type: {0}")]
    InvalidPacketType(u8),

    /// Invalid packet.
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    /// Malformed remaining length.
    #[error("Malformed remaining length")]
    MalformedRemainingLength,

    /// Packet too large.
    #[error("Packet too large: {size} bytes (max: {max})")]
    PacketTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Invalid topic name.
    #[error("Invalid topic name: {0}")]
    InvalidTopicName(String),

    /// Invalid topic filter.
    #[error("Invalid topic filter: {0}")]
    InvalidTopicFilter(String),

    /// Invalid QoS level.
    #[error("Invalid QoS level: {0}")]
    InvalidQoS(u8),

    /// Invalid protocol version.
    #[error("Invalid protocol version: {0}")]
    InvalidProtocolVersion(u8),

    /// Invalid UTF-8 string.
    #[error("Invalid UTF-8 string: {0}")]
    InvalidUtf8(String),

    /// Connection refused.
    #[error("Connection refused: {0}")]
    ConnectionRefused(String),

    /// Session error.
    #[error("Session error: {0}")]
    Session(String),

    /// Not authorized.
    #[error("Not authorized: {0}")]
    NotAuthorized(String),

    /// Routing error.
    #[error("Routing error: {0}")]
    Routing(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Timeout error.
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Incomplete packet.
    #[error("Incomplete packet: need more data")]
    IncompletePacket,
}

/// Result type for MQTT operations.
pub type MqttResult<T> = Result<T, MqttError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = MqttError::InvalidTopicName("/invalid#topic".to_string());
        assert!(err.to_string().contains("/invalid#topic"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let mqtt_err = MqttError::from(io_err);
        assert!(matches!(mqtt_err, MqttError::Io(_)));
    }

    #[test]
    fn test_packet_too_large() {
        let err = MqttError::PacketTooLarge {
            size: 1_000_000,
            max: 256_000,
        };
        assert!(err.to_string().contains("1000000"));
    }
}
