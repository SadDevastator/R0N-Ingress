//! IPC message types and protocol definitions.

use serde::{Deserialize, Serialize};

/// Control commands that can be sent to modules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ControlCommand {
    /// Initialize module with configuration.
    Init {
        /// Configuration data as MessagePack bytes.
        config: Vec<u8>,
    },

    /// Start the module.
    Start,

    /// Stop the module gracefully.
    Stop,

    /// Pause the module (stop accepting new work).
    Pause,

    /// Resume the module after pause.
    Resume,

    /// Reload configuration.
    Reload {
        /// New configuration data as MessagePack bytes.
        config: Vec<u8>,
    },

    /// Request current status.
    Status,

    /// Request current metrics.
    Metrics,

    /// Heartbeat/ping request.
    Heartbeat,

    /// Request contract version.
    Version,

    /// Shutdown the module process.
    Shutdown,
}

/// A control message sent over IPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlMessage {
    /// Unique message ID for correlation.
    pub id: u64,

    /// The command to execute.
    pub command: ControlCommand,

    /// Timestamp when the message was created (Unix epoch milliseconds).
    pub timestamp: u64,
}

impl ControlMessage {
    /// Creates a new control message with the given command.
    #[inline]
    #[must_use]
    pub fn new(id: u64, command: ControlCommand) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            id,
            command,
            timestamp,
        }
    }

    /// Creates a new control message with a pre-computed timestamp.
    #[inline]
    #[must_use]
    pub fn with_timestamp(id: u64, command: ControlCommand, timestamp: u64) -> Self {
        Self {
            id,
            command,
            timestamp,
        }
    }

    /// Serializes the message to MessagePack bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    #[inline]
    pub fn to_bytes(&self) -> Result<Vec<u8>, rmp_serde::encode::Error> {
        rmp_serde::to_vec(self)
    }

    /// Serializes the message into an existing buffer, avoiding allocation.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_bytes_into(&self, buf: &mut Vec<u8>) -> Result<(), rmp_serde::encode::Error> {
        buf.clear();
        rmp_serde::encode::write(buf, self)
    }

    /// Deserializes a message from MessagePack bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, rmp_serde::decode::Error> {
        rmp_serde::from_slice(bytes)
    }
}

/// Response status codes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponseStatus {
    /// Command executed successfully.
    Ok = 0,

    /// Command failed.
    Error = 1,

    /// Module is busy, try again later.
    Busy = 2,

    /// Command not supported.
    NotSupported = 3,

    /// Invalid state for the command.
    InvalidState = 4,

    /// Configuration error.
    ConfigError = 5,

    /// Timeout waiting for operation.
    Timeout = 6,
}

impl ResponseStatus {
    /// Returns `true` if the status indicates success.
    #[inline]
    #[must_use]
    pub fn is_success(self) -> bool {
        matches!(self, Self::Ok)
    }
}

/// A response to a control message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResponse {
    /// Message ID this is responding to.
    pub request_id: u64,

    /// Response status.
    pub status: ResponseStatus,

    /// Optional payload data (status info, metrics, etc.).
    pub payload: Option<Vec<u8>>,

    /// Optional error message.
    pub error: Option<String>,

    /// Timestamp when the response was created.
    pub timestamp: u64,
}

impl ControlResponse {
    /// Creates a successful response.
    #[inline]
    #[must_use]
    pub fn ok(request_id: u64) -> Self {
        Self::with_status(request_id, ResponseStatus::Ok)
    }

    /// Creates a successful response with payload.
    #[inline]
    #[must_use]
    pub fn ok_with_payload(request_id: u64, payload: Vec<u8>) -> Self {
        let mut response = Self::ok(request_id);
        response.payload = Some(payload);
        response
    }

    /// Creates an error response.
    #[inline]
    #[must_use]
    pub fn error(request_id: u64, message: impl Into<String>) -> Self {
        let mut response = Self::with_status(request_id, ResponseStatus::Error);
        response.error = Some(message.into());
        response
    }

    /// Creates a response with a specific status.
    #[inline]
    #[must_use]
    pub fn with_status(request_id: u64, status: ResponseStatus) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            request_id,
            status,
            payload: None,
            error: None,
            timestamp,
        }
    }

    /// Serializes the response to MessagePack bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    #[inline]
    pub fn to_bytes(&self) -> Result<Vec<u8>, rmp_serde::encode::Error> {
        rmp_serde::to_vec(self)
    }

    /// Serializes the response into an existing buffer, avoiding allocation.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_bytes_into(&self, buf: &mut Vec<u8>) -> Result<(), rmp_serde::encode::Error> {
        buf.clear();
        rmp_serde::encode::write(buf, self)
    }

    /// Deserializes a response from MessagePack bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, rmp_serde::decode::Error> {
        rmp_serde::from_slice(bytes)
    }
}

/// Frame header for length-prefixed messages.
///
/// Each message is prefixed with a 4-byte length header (big-endian u32).
#[cfg(unix)]
pub const FRAME_HEADER_SIZE: usize = 4;

/// Maximum message size (16 MB).
#[cfg(unix)]
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Encodes a message with length prefix.
#[cfg(unix)]
#[must_use]
pub fn encode_frame(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u32;
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + data.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

/// Decodes the length from a frame header.
///
/// # Errors
///
/// Returns `None` if the header is invalid or the message is too large.
#[cfg(unix)]
#[must_use]
pub fn decode_frame_length(header: &[u8; FRAME_HEADER_SIZE]) -> Option<usize> {
    let len = u32::from_be_bytes(*header) as usize;
    if len <= MAX_MESSAGE_SIZE {
        Some(len)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_message_serialization() {
        let msg = ControlMessage::new(1, ControlCommand::Status);
        let bytes = msg.to_bytes().unwrap();
        let decoded = ControlMessage::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.id, 1);
        assert_eq!(decoded.command, ControlCommand::Status);
    }

    #[test]
    fn test_control_response_serialization() {
        let response = ControlResponse::ok(42);
        let bytes = response.to_bytes().unwrap();
        let decoded = ControlResponse::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.request_id, 42);
        assert!(decoded.status.is_success());
    }

    #[test]
    #[cfg(unix)]
    fn test_frame_encoding() {
        let data = b"hello world";
        let frame = encode_frame(data);

        assert_eq!(frame.len(), FRAME_HEADER_SIZE + data.len());

        let mut header = [0u8; FRAME_HEADER_SIZE];
        header.copy_from_slice(&frame[..FRAME_HEADER_SIZE]);

        let len = decode_frame_length(&header).unwrap();
        assert_eq!(len, data.len());
    }
}
