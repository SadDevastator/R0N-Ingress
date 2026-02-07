//! HTTP/3 frames (RFC 9114 Section 7)

use super::error::{Http3Error, Http3Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Frame type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameType {
    /// DATA frame (0x00)
    Data,

    /// HEADERS frame (0x01)
    Headers,

    /// CANCEL_PUSH frame (0x03) - reserved in HTTP/3
    CancelPush,

    /// SETTINGS frame (0x04)
    Settings,

    /// PUSH_PROMISE frame (0x05)
    PushPromise,

    /// GOAWAY frame (0x07)
    GoAway,

    /// MAX_PUSH_ID frame (0x0d)
    MaxPushId,

    /// Reserved frame type (0x02, 0x06, 0x08, 0x09)
    Reserved(u64),

    /// Unknown frame type
    Unknown(u64),
}

impl FrameType {
    /// Get frame type value
    pub fn value(&self) -> u64 {
        match self {
            Self::Data => 0x00,
            Self::Headers => 0x01,
            Self::CancelPush => 0x03,
            Self::Settings => 0x04,
            Self::PushPromise => 0x05,
            Self::GoAway => 0x07,
            Self::MaxPushId => 0x0d,
            Self::Reserved(v) => *v,
            Self::Unknown(v) => *v,
        }
    }

    /// Create from value
    pub fn from_value(value: u64) -> Self {
        match value {
            0x00 => Self::Data,
            0x01 => Self::Headers,
            0x03 => Self::CancelPush,
            0x04 => Self::Settings,
            0x05 => Self::PushPromise,
            0x07 => Self::GoAway,
            0x0d => Self::MaxPushId,
            // Reserved types from HTTP/2 that are invalid in HTTP/3
            0x02 | 0x06 | 0x08 | 0x09 => Self::Reserved(value),
            _ => Self::Unknown(value),
        }
    }

    /// Check if this frame type is reserved
    pub fn is_reserved(&self) -> bool {
        matches!(self, Self::Reserved(_))
    }

    /// Check if frame is allowed on control stream
    pub fn is_control_stream_frame(&self) -> bool {
        matches!(
            self,
            Self::Settings | Self::GoAway | Self::MaxPushId | Self::CancelPush
        )
    }

    /// Check if frame is allowed on request stream
    pub fn is_request_stream_frame(&self) -> bool {
        matches!(self, Self::Data | Self::Headers | Self::PushPromise)
    }
}

impl std::fmt::Display for FrameType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Data => write!(f, "DATA"),
            Self::Headers => write!(f, "HEADERS"),
            Self::CancelPush => write!(f, "CANCEL_PUSH"),
            Self::Settings => write!(f, "SETTINGS"),
            Self::PushPromise => write!(f, "PUSH_PROMISE"),
            Self::GoAway => write!(f, "GOAWAY"),
            Self::MaxPushId => write!(f, "MAX_PUSH_ID"),
            Self::Reserved(v) => write!(f, "RESERVED(0x{:x})", v),
            Self::Unknown(v) => write!(f, "UNKNOWN(0x{:x})", v),
        }
    }
}

/// HTTP/3 frame
#[derive(Debug, Clone)]
pub enum Frame {
    /// DATA frame - carries request/response body
    Data(DataPayload),

    /// HEADERS frame - carries encoded headers
    Headers(HeadersPayload),

    /// SETTINGS frame - carries connection settings
    Settings(Settings),

    /// GOAWAY frame - graceful shutdown
    GoAway(GoAwayPayload),

    /// MAX_PUSH_ID frame - maximum push ID
    MaxPushId(u64),

    /// CANCEL_PUSH frame - cancel server push
    CancelPush(u64),

    /// PUSH_PROMISE frame - server push
    PushPromise(PushPromisePayload),

    /// Unknown frame (should be ignored)
    Unknown(UnknownFrame),
}

impl Frame {
    /// Get frame type
    pub fn frame_type(&self) -> FrameType {
        match self {
            Self::Data(_) => FrameType::Data,
            Self::Headers(_) => FrameType::Headers,
            Self::Settings(_) => FrameType::Settings,
            Self::GoAway(_) => FrameType::GoAway,
            Self::MaxPushId(_) => FrameType::MaxPushId,
            Self::CancelPush(_) => FrameType::CancelPush,
            Self::PushPromise(_) => FrameType::PushPromise,
            Self::Unknown(f) => FrameType::Unknown(f.frame_type),
        }
    }

    /// Check if this is a DATA frame
    pub fn is_data(&self) -> bool {
        matches!(self, Self::Data(_))
    }

    /// Check if this is a HEADERS frame
    pub fn is_headers(&self) -> bool {
        matches!(self, Self::Headers(_))
    }

    /// Check if this is a SETTINGS frame
    pub fn is_settings(&self) -> bool {
        matches!(self, Self::Settings(_))
    }

    /// Encode frame to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        match self {
            Self::Data(data) => {
                encode_varint(&mut buf, FrameType::Data.value());
                encode_varint(&mut buf, data.data.len() as u64);
                buf.extend_from_slice(&data.data);
            },
            Self::Headers(headers) => {
                encode_varint(&mut buf, FrameType::Headers.value());
                encode_varint(&mut buf, headers.encoded_headers.len() as u64);
                buf.extend_from_slice(&headers.encoded_headers);
            },
            Self::Settings(settings) => {
                let payload = settings.encode();
                encode_varint(&mut buf, FrameType::Settings.value());
                encode_varint(&mut buf, payload.len() as u64);
                buf.extend_from_slice(&payload);
            },
            Self::GoAway(goaway) => {
                let mut payload = Vec::new();
                encode_varint(&mut payload, goaway.stream_id);
                encode_varint(&mut buf, FrameType::GoAway.value());
                encode_varint(&mut buf, payload.len() as u64);
                buf.extend_from_slice(&payload);
            },
            Self::MaxPushId(id) => {
                let mut payload = Vec::new();
                encode_varint(&mut payload, *id);
                encode_varint(&mut buf, FrameType::MaxPushId.value());
                encode_varint(&mut buf, payload.len() as u64);
                buf.extend_from_slice(&payload);
            },
            Self::CancelPush(id) => {
                let mut payload = Vec::new();
                encode_varint(&mut payload, *id);
                encode_varint(&mut buf, FrameType::CancelPush.value());
                encode_varint(&mut buf, payload.len() as u64);
                buf.extend_from_slice(&payload);
            },
            Self::PushPromise(pp) => {
                let mut payload = Vec::new();
                encode_varint(&mut payload, pp.push_id);
                payload.extend_from_slice(&pp.encoded_headers);
                encode_varint(&mut buf, FrameType::PushPromise.value());
                encode_varint(&mut buf, payload.len() as u64);
                buf.extend_from_slice(&payload);
            },
            Self::Unknown(f) => {
                encode_varint(&mut buf, f.frame_type);
                encode_varint(&mut buf, f.payload.len() as u64);
                buf.extend_from_slice(&f.payload);
            },
        }

        buf
    }

    /// Decode frame from bytes
    pub fn decode(buf: &[u8]) -> Http3Result<(Self, usize)> {
        let mut offset = 0;

        let (frame_type, n) = decode_varint(&buf[offset..])?;
        offset += n;

        let (length, n) = decode_varint(&buf[offset..])?;
        offset += n;

        // Guard against oversized frames (16 MB limit)
        const MAX_FRAME_SIZE: u64 = 16 * 1024 * 1024;
        if length > MAX_FRAME_SIZE {
            return Err(Http3Error::FrameError);
        }

        if buf.len() < offset + length as usize {
            return Err(Http3Error::FrameError);
        }

        let payload = &buf[offset..offset + length as usize];
        offset += length as usize;

        let frame = match FrameType::from_value(frame_type) {
            FrameType::Data => Frame::Data(DataPayload {
                data: payload.to_vec(),
            }),
            FrameType::Headers => Frame::Headers(HeadersPayload {
                encoded_headers: payload.to_vec(),
            }),
            FrameType::Settings => Frame::Settings(Settings::decode(payload)?),
            FrameType::GoAway => {
                let (stream_id, _) = decode_varint(payload)?;
                Frame::GoAway(GoAwayPayload { stream_id })
            },
            FrameType::MaxPushId => {
                let (push_id, _) = decode_varint(payload)?;
                Frame::MaxPushId(push_id)
            },
            FrameType::CancelPush => {
                let (push_id, _) = decode_varint(payload)?;
                Frame::CancelPush(push_id)
            },
            FrameType::PushPromise => {
                let (push_id, n) = decode_varint(payload)?;
                Frame::PushPromise(PushPromisePayload {
                    push_id,
                    encoded_headers: payload[n..].to_vec(),
                })
            },
            FrameType::Reserved(_) => {
                return Err(Http3Error::FrameError);
            },
            FrameType::Unknown(ft) => Frame::Unknown(UnknownFrame {
                frame_type: ft,
                payload: payload.to_vec(),
            }),
        };

        Ok((frame, offset))
    }
}

/// DATA frame payload
#[derive(Debug, Clone)]
pub struct DataPayload {
    /// Raw data
    pub data: Vec<u8>,
}

/// HEADERS frame payload
#[derive(Debug, Clone)]
pub struct HeadersPayload {
    /// QPACK-encoded headers
    pub encoded_headers: Vec<u8>,
}

/// GOAWAY frame payload
#[derive(Debug, Clone)]
pub struct GoAwayPayload {
    /// Stream ID
    pub stream_id: u64,
}

/// PUSH_PROMISE frame payload
#[derive(Debug, Clone)]
pub struct PushPromisePayload {
    /// Push ID
    pub push_id: u64,

    /// QPACK-encoded headers
    pub encoded_headers: Vec<u8>,
}

/// Unknown frame
#[derive(Debug, Clone)]
pub struct UnknownFrame {
    /// Frame type value
    pub frame_type: u64,

    /// Raw payload
    pub payload: Vec<u8>,
}

/// HTTP/3 settings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Settings {
    /// Maximum header list size (default: unlimited)
    pub max_field_section_size: Option<u64>,

    /// QPACK max table capacity
    pub qpack_max_table_capacity: Option<u64>,

    /// QPACK blocked streams
    pub qpack_blocked_streams: Option<u64>,

    /// Enable connect protocol (WebSocket over HTTP/3)
    pub enable_connect_protocol: Option<bool>,

    /// Enable WebTransport
    pub enable_webtransport: Option<bool>,

    /// Additional settings
    #[serde(flatten)]
    pub other: HashMap<u64, u64>,
}

impl Settings {
    /// Setting identifiers
    pub const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
    /// Maximum header list size setting identifier
    pub const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
    /// QPACK blocked streams setting identifier
    pub const QPACK_BLOCKED_STREAMS: u64 = 0x07;
    /// Enable connect protocol setting identifier (RFC 9220)
    pub const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
    /// Enable WebTransport setting identifier
    pub const ENABLE_WEBTRANSPORT: u64 = 0x2b603742;

    /// Create default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Set max field section size
    pub fn with_max_field_section_size(mut self, size: u64) -> Self {
        self.max_field_section_size = Some(size);
        self
    }

    /// Set QPACK max table capacity
    pub fn with_qpack_max_table_capacity(mut self, capacity: u64) -> Self {
        self.qpack_max_table_capacity = Some(capacity);
        self
    }

    /// Set QPACK blocked streams
    pub fn with_qpack_blocked_streams(mut self, blocked: u64) -> Self {
        self.qpack_blocked_streams = Some(blocked);
        self
    }

    /// Enable connect protocol
    pub fn with_connect_protocol(mut self, enabled: bool) -> Self {
        self.enable_connect_protocol = Some(enabled);
        self
    }

    /// Enable WebTransport
    pub fn with_webtransport(mut self, enabled: bool) -> Self {
        self.enable_webtransport = Some(enabled);
        self
    }

    /// Encode settings to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        if let Some(size) = self.max_field_section_size {
            encode_varint(&mut buf, Self::MAX_FIELD_SECTION_SIZE);
            encode_varint(&mut buf, size);
        }

        if let Some(capacity) = self.qpack_max_table_capacity {
            encode_varint(&mut buf, Self::QPACK_MAX_TABLE_CAPACITY);
            encode_varint(&mut buf, capacity);
        }

        if let Some(blocked) = self.qpack_blocked_streams {
            encode_varint(&mut buf, Self::QPACK_BLOCKED_STREAMS);
            encode_varint(&mut buf, blocked);
        }

        if let Some(enabled) = self.enable_connect_protocol {
            if enabled {
                encode_varint(&mut buf, Self::ENABLE_CONNECT_PROTOCOL);
                encode_varint(&mut buf, 1);
            }
        }

        if let Some(enabled) = self.enable_webtransport {
            if enabled {
                encode_varint(&mut buf, Self::ENABLE_WEBTRANSPORT);
                encode_varint(&mut buf, 1);
            }
        }

        for (id, value) in &self.other {
            encode_varint(&mut buf, *id);
            encode_varint(&mut buf, *value);
        }

        buf
    }

    /// Decode settings from bytes
    pub fn decode(buf: &[u8]) -> Http3Result<Self> {
        let mut settings = Self::default();
        let mut offset = 0;

        while offset < buf.len() {
            let (id, n) = decode_varint(&buf[offset..])?;
            offset += n;

            let (value, n) = decode_varint(&buf[offset..])?;
            offset += n;

            match id {
                Self::MAX_FIELD_SECTION_SIZE => {
                    settings.max_field_section_size = Some(value);
                },
                Self::QPACK_MAX_TABLE_CAPACITY => {
                    settings.qpack_max_table_capacity = Some(value);
                },
                Self::QPACK_BLOCKED_STREAMS => {
                    settings.qpack_blocked_streams = Some(value);
                },
                Self::ENABLE_CONNECT_PROTOCOL => {
                    settings.enable_connect_protocol = Some(value != 0);
                },
                Self::ENABLE_WEBTRANSPORT => {
                    settings.enable_webtransport = Some(value != 0);
                },
                _ => {
                    settings.other.insert(id, value);
                },
            }
        }

        Ok(settings)
    }

    /// Merge with another settings (other takes precedence)
    pub fn merge(&mut self, other: &Settings) {
        if other.max_field_section_size.is_some() {
            self.max_field_section_size = other.max_field_section_size;
        }
        if other.qpack_max_table_capacity.is_some() {
            self.qpack_max_table_capacity = other.qpack_max_table_capacity;
        }
        if other.qpack_blocked_streams.is_some() {
            self.qpack_blocked_streams = other.qpack_blocked_streams;
        }
        if other.enable_connect_protocol.is_some() {
            self.enable_connect_protocol = other.enable_connect_protocol;
        }
        if other.enable_webtransport.is_some() {
            self.enable_webtransport = other.enable_webtransport;
        }
        for (id, value) in &other.other {
            self.other.insert(*id, *value);
        }
    }
}

/// Encode a variable-length integer (QUIC RFC 9000 Section 16)
pub fn encode_varint(buf: &mut Vec<u8>, value: u64) {
    if value < 64 {
        buf.push(value as u8);
    } else if value < 16384 {
        buf.push(0x40 | ((value >> 8) as u8));
        buf.push(value as u8);
    } else if value < 1_073_741_824 {
        buf.push(0x80 | ((value >> 24) as u8));
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    } else {
        buf.push(0xc0 | ((value >> 56) as u8));
        buf.push((value >> 48) as u8);
        buf.push((value >> 40) as u8);
        buf.push((value >> 32) as u8);
        buf.push((value >> 24) as u8);
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    }
}

/// Decode a variable-length integer
pub fn decode_varint(buf: &[u8]) -> Http3Result<(u64, usize)> {
    if buf.is_empty() {
        return Err(Http3Error::FrameError);
    }

    let prefix = buf[0] >> 6;
    let length = 1 << prefix;

    if buf.len() < length {
        return Err(Http3Error::FrameError);
    }

    let mut value = (buf[0] & 0x3f) as u64;

    for byte in buf[1..length].iter() {
        value = (value << 8) | (*byte as u64);
    }

    Ok((value, length))
}

/// Stream type for control/push streams
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    /// Control stream (0x00)
    Control,

    /// Push stream (0x01)
    Push,

    /// QPACK encoder stream (0x02)
    QpackEncoder,

    /// QPACK decoder stream (0x03)
    QpackDecoder,

    /// Unknown stream type
    Unknown(u64),
}

impl StreamType {
    /// Get stream type value
    pub fn value(&self) -> u64 {
        match self {
            Self::Control => 0x00,
            Self::Push => 0x01,
            Self::QpackEncoder => 0x02,
            Self::QpackDecoder => 0x03,
            Self::Unknown(v) => *v,
        }
    }

    /// Create from value
    pub fn from_value(value: u64) -> Self {
        match value {
            0x00 => Self::Control,
            0x01 => Self::Push,
            0x02 => Self::QpackEncoder,
            0x03 => Self::QpackDecoder,
            v => Self::Unknown(v),
        }
    }

    /// Check if this is a critical stream type
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::Control | Self::QpackEncoder | Self::QpackDecoder
        )
    }
}

impl std::fmt::Display for StreamType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Control => write!(f, "control"),
            Self::Push => write!(f, "push"),
            Self::QpackEncoder => write!(f, "qpack-encoder"),
            Self::QpackDecoder => write!(f, "qpack-decoder"),
            Self::Unknown(v) => write!(f, "unknown(0x{:x})", v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_type() {
        assert_eq!(FrameType::Data.value(), 0x00);
        assert_eq!(FrameType::Headers.value(), 0x01);
        assert_eq!(FrameType::Settings.value(), 0x04);

        assert_eq!(FrameType::from_value(0x00), FrameType::Data);
        assert!(FrameType::from_value(0x02).is_reserved());
    }

    #[test]
    fn test_frame_encode_decode_data() {
        let frame = Frame::Data(DataPayload {
            data: b"hello world".to_vec(),
        });

        let encoded = frame.encode();
        let (decoded, len) = Frame::decode(&encoded).unwrap();

        assert_eq!(len, encoded.len());
        assert!(decoded.is_data());

        if let Frame::Data(payload) = decoded {
            assert_eq!(payload.data, b"hello world");
        }
    }

    #[test]
    fn test_frame_encode_decode_settings() {
        let settings = Settings::new()
            .with_max_field_section_size(16384)
            .with_qpack_max_table_capacity(4096);

        let frame = Frame::Settings(settings);
        let encoded = frame.encode();
        let (decoded, _) = Frame::decode(&encoded).unwrap();

        if let Frame::Settings(s) = decoded {
            assert_eq!(s.max_field_section_size, Some(16384));
            assert_eq!(s.qpack_max_table_capacity, Some(4096));
        } else {
            panic!("expected Settings frame");
        }
    }

    #[test]
    fn test_varint_encode_decode() {
        let test_values = [0, 63, 64, 16383, 16384, 1073741823, 1073741824];

        for value in test_values {
            let mut buf = Vec::new();
            encode_varint(&mut buf, value);

            let (decoded, _) = decode_varint(&buf).unwrap();
            assert_eq!(decoded, value, "failed for value {}", value);
        }
    }

    #[test]
    fn test_settings_encode_decode() {
        let settings = Settings::new()
            .with_max_field_section_size(8192)
            .with_qpack_blocked_streams(100)
            .with_connect_protocol(true);

        let encoded = settings.encode();
        let decoded = Settings::decode(&encoded).unwrap();

        assert_eq!(decoded.max_field_section_size, Some(8192));
        assert_eq!(decoded.qpack_blocked_streams, Some(100));
        assert_eq!(decoded.enable_connect_protocol, Some(true));
    }

    #[test]
    fn test_stream_type() {
        assert_eq!(StreamType::Control.value(), 0x00);
        assert!(StreamType::Control.is_critical());
        assert!(!StreamType::Push.is_critical());
    }

    #[test]
    fn test_frame_goaway() {
        let frame = Frame::GoAway(GoAwayPayload { stream_id: 4 });
        let encoded = frame.encode();
        let (decoded, _) = Frame::decode(&encoded).unwrap();

        if let Frame::GoAway(payload) = decoded {
            assert_eq!(payload.stream_id, 4);
        } else {
            panic!("expected GoAway frame");
        }
    }

    #[test]
    fn test_frame_max_push_id() {
        let frame = Frame::MaxPushId(100);
        let encoded = frame.encode();
        let (decoded, _) = Frame::decode(&encoded).unwrap();

        if let Frame::MaxPushId(id) = decoded {
            assert_eq!(id, 100);
        } else {
            panic!("expected MaxPushId frame");
        }
    }
}
