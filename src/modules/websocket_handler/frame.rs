//! WebSocket frame types and utilities.
//!
//! This module wraps tokio-tungstenite types and provides additional utilities
//! for frame handling and message processing.

use tokio_tungstenite::tungstenite::protocol::CloseFrame;
pub use tokio_tungstenite::tungstenite::Message;

/// WebSocket operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    /// Continuation frame.
    Continuation,
    /// Text frame.
    Text,
    /// Binary frame.
    Binary,
    /// Close frame.
    Close,
    /// Ping frame.
    Ping,
    /// Pong frame.
    Pong,
}

impl OpCode {
    /// Check if this is a control frame.
    pub fn is_control(&self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }

    /// Check if this is a data frame.
    pub fn is_data(&self) -> bool {
        matches!(self, Self::Text | Self::Binary | Self::Continuation)
    }
}

impl From<u8> for OpCode {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Continuation,
            1 => Self::Text,
            2 => Self::Binary,
            8 => Self::Close,
            9 => Self::Ping,
            10 => Self::Pong,
            _ => Self::Binary, // Default to binary for unknown
        }
    }
}

impl From<OpCode> for u8 {
    fn from(value: OpCode) -> Self {
        match value {
            OpCode::Continuation => 0,
            OpCode::Text => 1,
            OpCode::Binary => 2,
            OpCode::Close => 8,
            OpCode::Ping => 9,
            OpCode::Pong => 10,
        }
    }
}

/// WebSocket close codes as defined in RFC 6455.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseCode {
    /// Normal closure.
    Normal,
    /// Endpoint going away.
    GoingAway,
    /// Protocol error.
    Protocol,
    /// Unsupported data type.
    Unsupported,
    /// No status received.
    NoStatus,
    /// Abnormal closure.
    Abnormal,
    /// Invalid frame payload data.
    InvalidData,
    /// Policy violation.
    PolicyViolation,
    /// Message too big.
    MessageTooBig,
    /// Missing extension.
    MissingExtension,
    /// Internal server error.
    InternalError,
    /// TLS handshake failure.
    TlsHandshake,
    /// Custom close code.
    Custom(u16),
}

impl CloseCode {
    /// Check if this is a valid close code per RFC 6455.
    pub fn is_valid(&self) -> bool {
        let code: u16 = (*self).into();
        // Valid ranges: 1000-1011, 3000-3999, 4000-4999
        matches!(code, 1000..=1011 | 3000..=3999 | 4000..=4999)
    }

    /// Check if this is a reserved close code.
    pub fn is_reserved(&self) -> bool {
        let code: u16 = (*self).into();
        matches!(code, 1004 | 1005 | 1006 | 1015)
    }
}

impl From<u16> for CloseCode {
    fn from(value: u16) -> Self {
        match value {
            1000 => Self::Normal,
            1001 => Self::GoingAway,
            1002 => Self::Protocol,
            1003 => Self::Unsupported,
            1005 => Self::NoStatus,
            1006 => Self::Abnormal,
            1007 => Self::InvalidData,
            1008 => Self::PolicyViolation,
            1009 => Self::MessageTooBig,
            1010 => Self::MissingExtension,
            1011 => Self::InternalError,
            1015 => Self::TlsHandshake,
            code => Self::Custom(code),
        }
    }
}

impl From<CloseCode> for u16 {
    fn from(value: CloseCode) -> Self {
        match value {
            CloseCode::Normal => 1000,
            CloseCode::GoingAway => 1001,
            CloseCode::Protocol => 1002,
            CloseCode::Unsupported => 1003,
            CloseCode::NoStatus => 1005,
            CloseCode::Abnormal => 1006,
            CloseCode::InvalidData => 1007,
            CloseCode::PolicyViolation => 1008,
            CloseCode::MessageTooBig => 1009,
            CloseCode::MissingExtension => 1010,
            CloseCode::InternalError => 1011,
            CloseCode::TlsHandshake => 1015,
            CloseCode::Custom(code) => code,
        }
    }
}

/// Extension trait for Message to provide additional utilities.
#[allow(dead_code)]
pub trait MessageExt {
    /// Get the opcode for this message.
    fn opcode(&self) -> OpCode;

    /// Get the payload as bytes.
    fn payload(&self) -> &[u8];

    /// Check if this is a control message.
    fn is_control(&self) -> bool;

    /// Get close frame details if this is a close message.
    fn close_frame(&self) -> Option<(CloseCode, &str)>;
}

impl MessageExt for Message {
    fn opcode(&self) -> OpCode {
        match self {
            Message::Text(_) => OpCode::Text,
            Message::Binary(_) => OpCode::Binary,
            Message::Ping(_) => OpCode::Ping,
            Message::Pong(_) => OpCode::Pong,
            Message::Close(_) => OpCode::Close,
            Message::Frame(_) => OpCode::Binary, // Raw frame, treat as binary
        }
    }

    fn payload(&self) -> &[u8] {
        match self {
            Message::Text(s) => s.as_bytes(),
            Message::Binary(b) => b,
            Message::Ping(b) => b,
            Message::Pong(b) => b,
            Message::Close(Some(frame)) => frame.reason.as_bytes(),
            Message::Close(None) => &[],
            Message::Frame(f) => f.payload(),
        }
    }

    fn is_control(&self) -> bool {
        self.opcode().is_control()
    }

    #[allow(dead_code)]
    fn close_frame(&self) -> Option<(CloseCode, &str)> {
        match self {
            Message::Close(Some(CloseFrame { code, reason })) => {
                Some((CloseCode::from(u16::from(*code)), reason.as_ref()))
            },
            _ => None,
        }
    }
}

/// Create a close message with code and reason.
#[allow(dead_code)]
pub fn close_message(code: CloseCode, reason: &str) -> Message {
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode as TungsteniteCode;

    Message::Close(Some(CloseFrame {
        code: TungsteniteCode::from(u16::from(code)),
        reason: reason.to_string().into(),
    }))
}

/// Create a ping message.
#[allow(dead_code)]
pub fn ping_message(payload: Vec<u8>) -> Message {
    Message::Ping(payload.into())
}

/// Create a pong message.
#[allow(dead_code)]
pub fn pong_message(payload: Vec<u8>) -> Message {
    Message::Pong(payload.into())
}

/// Create a text message.
#[allow(dead_code)]
pub fn text_message(text: impl Into<String>) -> Message {
    let s: String = text.into();
    Message::Text(s.into())
}

/// Create a binary message.
#[allow(dead_code)]
pub fn binary_message(data: Vec<u8>) -> Message {
    Message::Binary(data.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_conversion() {
        assert_eq!(OpCode::from(0), OpCode::Continuation);
        assert_eq!(OpCode::from(1), OpCode::Text);
        assert_eq!(OpCode::from(2), OpCode::Binary);
        assert_eq!(OpCode::from(8), OpCode::Close);
        assert_eq!(OpCode::from(9), OpCode::Ping);
        assert_eq!(OpCode::from(10), OpCode::Pong);
    }

    #[test]
    fn test_opcode_is_control() {
        assert!(OpCode::Close.is_control());
        assert!(OpCode::Ping.is_control());
        assert!(OpCode::Pong.is_control());
        assert!(!OpCode::Text.is_control());
        assert!(!OpCode::Binary.is_control());
    }

    #[test]
    fn test_opcode_is_data() {
        assert!(OpCode::Text.is_data());
        assert!(OpCode::Binary.is_data());
        assert!(OpCode::Continuation.is_data());
        assert!(!OpCode::Close.is_data());
        assert!(!OpCode::Ping.is_data());
    }

    #[test]
    fn test_close_code_conversion() {
        assert_eq!(CloseCode::from(1000), CloseCode::Normal);
        assert_eq!(CloseCode::from(1001), CloseCode::GoingAway);
        assert_eq!(CloseCode::from(1002), CloseCode::Protocol);
        assert_eq!(CloseCode::from(1003), CloseCode::Unsupported);
        assert_eq!(CloseCode::from(1011), CloseCode::InternalError);

        assert_eq!(u16::from(CloseCode::Normal), 1000);
        assert_eq!(u16::from(CloseCode::GoingAway), 1001);
    }

    #[test]
    fn test_close_code_valid() {
        assert!(CloseCode::Normal.is_valid());
        assert!(CloseCode::GoingAway.is_valid());
        assert!(CloseCode::Custom(3000).is_valid());
        assert!(CloseCode::Custom(4000).is_valid());
        assert!(!CloseCode::Custom(999).is_valid());
        assert!(!CloseCode::Custom(2000).is_valid());
    }

    #[test]
    fn test_close_code_reserved() {
        assert!(CloseCode::NoStatus.is_reserved());
        assert!(CloseCode::Abnormal.is_reserved());
        assert!(CloseCode::TlsHandshake.is_reserved());
        assert!(!CloseCode::Normal.is_reserved());
        assert!(!CloseCode::Protocol.is_reserved());
    }

    #[test]
    fn test_message_opcode() {
        let text = Message::Text("hello".to_string().into());
        assert_eq!(text.opcode(), OpCode::Text);

        let binary = Message::Binary(vec![1, 2, 3].into());
        assert_eq!(binary.opcode(), OpCode::Binary);

        let ping = Message::Ping(vec![].into());
        assert_eq!(ping.opcode(), OpCode::Ping);
    }

    #[test]
    fn test_message_payload() {
        let text = Message::Text("hello".to_string().into());
        assert_eq!(text.payload(), b"hello");

        let binary = Message::Binary(vec![1, 2, 3].into());
        assert_eq!(binary.payload(), &[1, 2, 3]);
    }

    #[test]
    fn test_message_is_control() {
        let text = Message::Text("hello".to_string().into());
        assert!(!text.is_control());

        let ping = Message::Ping(vec![].into());
        assert!(ping.is_control());
    }

    #[test]
    fn test_close_message() {
        let msg = close_message(CloseCode::Normal, "goodbye");
        assert!(matches!(msg, Message::Close(_)));
    }

    #[test]
    fn test_ping_pong_messages() {
        let ping = ping_message(vec![1, 2, 3]);
        assert!(matches!(ping, Message::Ping(_)));

        let pong = pong_message(vec![1, 2, 3]);
        assert!(matches!(pong, Message::Pong(_)));
    }

    #[test]
    fn test_text_binary_messages() {
        let text = text_message("hello");
        assert!(matches!(text, Message::Text(_)));

        let binary = binary_message(vec![1, 2, 3]);
        assert!(matches!(binary, Message::Binary(_)));
    }
}
