//! MQTT packet types and parsing.
//!
//! This module implements parsing and serialization for MQTT 3.1.1 and MQTT 5.0 packets.

use crate::modules::mqtt_handler::error::{MqttError, MqttResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::str;

/// Quality of Service level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum QoS {
    /// At most once delivery (fire and forget).
    #[default]
    AtMostOnce = 0,
    /// At least once delivery (acknowledged).
    AtLeastOnce = 1,
    /// Exactly once delivery (assured).
    ExactlyOnce = 2,
}

impl QoS {
    /// Create QoS from byte value.
    pub fn from_u8(value: u8) -> MqttResult<Self> {
        match value {
            0 => Ok(Self::AtMostOnce),
            1 => Ok(Self::AtLeastOnce),
            2 => Ok(Self::ExactlyOnce),
            _ => Err(MqttError::InvalidQoS(value)),
        }
    }
}

/// MQTT packet types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// Connection request.
    Connect = 1,
    /// Connection acknowledgment.
    ConnAck = 2,
    /// Publish message.
    Publish = 3,
    /// Publish acknowledgment (QoS 1).
    PubAck = 4,
    /// Publish received (QoS 2, step 1).
    PubRec = 5,
    /// Publish release (QoS 2, step 2).
    PubRel = 6,
    /// Publish complete (QoS 2, step 3).
    PubComp = 7,
    /// Subscribe request.
    Subscribe = 8,
    /// Subscribe acknowledgment.
    SubAck = 9,
    /// Unsubscribe request.
    Unsubscribe = 10,
    /// Unsubscribe acknowledgment.
    UnsubAck = 11,
    /// Ping request.
    PingReq = 12,
    /// Ping response.
    PingResp = 13,
    /// Disconnect notification.
    Disconnect = 14,
    /// Authentication exchange (MQTT 5.0).
    Auth = 15,
}

impl PacketType {
    /// Create packet type from byte value.
    pub fn from_u8(value: u8) -> MqttResult<Self> {
        match value {
            1 => Ok(Self::Connect),
            2 => Ok(Self::ConnAck),
            3 => Ok(Self::Publish),
            4 => Ok(Self::PubAck),
            5 => Ok(Self::PubRec),
            6 => Ok(Self::PubRel),
            7 => Ok(Self::PubComp),
            8 => Ok(Self::Subscribe),
            9 => Ok(Self::SubAck),
            10 => Ok(Self::Unsubscribe),
            11 => Ok(Self::UnsubAck),
            12 => Ok(Self::PingReq),
            13 => Ok(Self::PingResp),
            14 => Ok(Self::Disconnect),
            15 => Ok(Self::Auth),
            _ => Err(MqttError::InvalidPacketType(value)),
        }
    }
}

/// Connect reason code (MQTT 5.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectReasonCode {
    /// Connection accepted.
    Success = 0x00,
    /// Unspecified error.
    UnspecifiedError = 0x80,
    /// Malformed packet.
    MalformedPacket = 0x81,
    /// Protocol error.
    ProtocolError = 0x82,
    /// Implementation specific error.
    ImplementationSpecificError = 0x83,
    /// Unsupported protocol version.
    UnsupportedProtocolVersion = 0x84,
    /// Client identifier not valid.
    ClientIdentifierNotValid = 0x85,
    /// Bad username or password.
    BadUserNameOrPassword = 0x86,
    /// Not authorized.
    NotAuthorized = 0x87,
    /// Server unavailable.
    ServerUnavailable = 0x88,
    /// Server busy.
    ServerBusy = 0x89,
    /// Banned.
    Banned = 0x8A,
    /// Bad authentication method.
    BadAuthenticationMethod = 0x8C,
    /// Topic name invalid.
    TopicNameInvalid = 0x90,
    /// Packet too large.
    PacketTooLarge = 0x95,
    /// Quota exceeded.
    QuotaExceeded = 0x97,
    /// Payload format invalid.
    PayloadFormatInvalid = 0x99,
    /// Retain not supported.
    RetainNotSupported = 0x9A,
    /// QoS not supported.
    QoSNotSupported = 0x9B,
    /// Use another server.
    UseAnotherServer = 0x9C,
    /// Server moved.
    ServerMoved = 0x9D,
    /// Connection rate exceeded.
    ConnectionRateExceeded = 0x9F,
}

impl ConnectReasonCode {
    /// Check if connection was successful.
    pub fn is_success(&self) -> bool {
        *self == Self::Success
    }

    /// Create from byte value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Success),
            0x80 => Some(Self::UnspecifiedError),
            0x81 => Some(Self::MalformedPacket),
            0x82 => Some(Self::ProtocolError),
            0x83 => Some(Self::ImplementationSpecificError),
            0x84 => Some(Self::UnsupportedProtocolVersion),
            0x85 => Some(Self::ClientIdentifierNotValid),
            0x86 => Some(Self::BadUserNameOrPassword),
            0x87 => Some(Self::NotAuthorized),
            0x88 => Some(Self::ServerUnavailable),
            0x89 => Some(Self::ServerBusy),
            0x8A => Some(Self::Banned),
            0x8C => Some(Self::BadAuthenticationMethod),
            0x90 => Some(Self::TopicNameInvalid),
            0x95 => Some(Self::PacketTooLarge),
            0x97 => Some(Self::QuotaExceeded),
            0x99 => Some(Self::PayloadFormatInvalid),
            0x9A => Some(Self::RetainNotSupported),
            0x9B => Some(Self::QoSNotSupported),
            0x9C => Some(Self::UseAnotherServer),
            0x9D => Some(Self::ServerMoved),
            0x9F => Some(Self::ConnectionRateExceeded),
            _ => None,
        }
    }
}

/// MQTT 5.0 properties.
#[derive(Debug, Clone, Default)]
pub struct Properties {
    /// Property values.
    pub values: HashMap<PropertyId, PropertyValue>,
}

impl Properties {
    /// Create empty properties.
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Get session expiry interval.
    pub fn session_expiry_interval(&self) -> Option<u32> {
        self.values
            .get(&PropertyId::SessionExpiryInterval)
            .and_then(|v| v.as_u32())
    }

    /// Get receive maximum.
    pub fn receive_maximum(&self) -> Option<u16> {
        self.values
            .get(&PropertyId::ReceiveMaximum)
            .and_then(|v| v.as_u16())
    }

    /// Get maximum packet size.
    pub fn maximum_packet_size(&self) -> Option<u32> {
        self.values
            .get(&PropertyId::MaximumPacketSize)
            .and_then(|v| v.as_u32())
    }

    /// Get topic alias maximum.
    pub fn topic_alias_maximum(&self) -> Option<u16> {
        self.values
            .get(&PropertyId::TopicAliasMaximum)
            .and_then(|v| v.as_u16())
    }

    /// Set a property.
    pub fn set(&mut self, id: PropertyId, value: PropertyValue) {
        self.values.insert(id, value);
    }

    /// Parse properties from bytes.
    pub fn parse(buf: &mut impl Buf) -> MqttResult<Self> {
        let length = read_variable_int(buf)?;
        let mut remaining = length as usize;
        let mut props = Properties::new();

        while remaining > 0 {
            if buf.remaining() == 0 {
                return Err(MqttError::IncompletePacket);
            }

            let id_byte = buf.get_u8();
            remaining -= 1;

            let id = PropertyId::from_u8(id_byte).ok_or_else(|| {
                MqttError::InvalidPacket(format!("Unknown property ID: {}", id_byte))
            })?;

            let value = PropertyValue::parse(id, buf, &mut remaining)?;
            props.values.insert(id, value);
        }

        Ok(props)
    }

    /// Serialize properties to bytes.
    pub fn serialize(&self, buf: &mut BytesMut) {
        if self.is_empty() {
            write_variable_int(buf, 0);
            return;
        }

        let mut props_buf = BytesMut::new();
        for (id, value) in &self.values {
            props_buf.put_u8(*id as u8);
            value.serialize(&mut props_buf);
        }

        write_variable_int(buf, props_buf.len() as u32);
        buf.extend_from_slice(&props_buf);
    }
}

/// Property identifiers (MQTT 5.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PropertyId {
    /// Payload format indicator.
    PayloadFormatIndicator = 0x01,
    /// Message expiry interval.
    MessageExpiryInterval = 0x02,
    /// Content type.
    ContentType = 0x03,
    /// Response topic.
    ResponseTopic = 0x08,
    /// Correlation data.
    CorrelationData = 0x09,
    /// Subscription identifier.
    SubscriptionIdentifier = 0x0B,
    /// Session expiry interval.
    SessionExpiryInterval = 0x11,
    /// Assigned client identifier.
    AssignedClientIdentifier = 0x12,
    /// Server keep alive.
    ServerKeepAlive = 0x13,
    /// Authentication method.
    AuthenticationMethod = 0x15,
    /// Authentication data.
    AuthenticationData = 0x16,
    /// Request problem information.
    RequestProblemInformation = 0x17,
    /// Will delay interval.
    WillDelayInterval = 0x18,
    /// Request response information.
    RequestResponseInformation = 0x19,
    /// Response information.
    ResponseInformation = 0x1A,
    /// Server reference.
    ServerReference = 0x1C,
    /// Reason string.
    ReasonString = 0x1F,
    /// Receive maximum.
    ReceiveMaximum = 0x21,
    /// Topic alias maximum.
    TopicAliasMaximum = 0x22,
    /// Topic alias.
    TopicAlias = 0x23,
    /// Maximum QoS.
    MaximumQoS = 0x24,
    /// Retain available.
    RetainAvailable = 0x25,
    /// User property.
    UserProperty = 0x26,
    /// Maximum packet size.
    MaximumPacketSize = 0x27,
    /// Wildcard subscription available.
    WildcardSubscriptionAvailable = 0x28,
    /// Subscription identifiers available.
    SubscriptionIdentifiersAvailable = 0x29,
    /// Shared subscription available.
    SharedSubscriptionAvailable = 0x2A,
}

impl PropertyId {
    /// Create from byte value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::PayloadFormatIndicator),
            0x02 => Some(Self::MessageExpiryInterval),
            0x03 => Some(Self::ContentType),
            0x08 => Some(Self::ResponseTopic),
            0x09 => Some(Self::CorrelationData),
            0x0B => Some(Self::SubscriptionIdentifier),
            0x11 => Some(Self::SessionExpiryInterval),
            0x12 => Some(Self::AssignedClientIdentifier),
            0x13 => Some(Self::ServerKeepAlive),
            0x15 => Some(Self::AuthenticationMethod),
            0x16 => Some(Self::AuthenticationData),
            0x17 => Some(Self::RequestProblemInformation),
            0x18 => Some(Self::WillDelayInterval),
            0x19 => Some(Self::RequestResponseInformation),
            0x1A => Some(Self::ResponseInformation),
            0x1C => Some(Self::ServerReference),
            0x1F => Some(Self::ReasonString),
            0x21 => Some(Self::ReceiveMaximum),
            0x22 => Some(Self::TopicAliasMaximum),
            0x23 => Some(Self::TopicAlias),
            0x24 => Some(Self::MaximumQoS),
            0x25 => Some(Self::RetainAvailable),
            0x26 => Some(Self::UserProperty),
            0x27 => Some(Self::MaximumPacketSize),
            0x28 => Some(Self::WildcardSubscriptionAvailable),
            0x29 => Some(Self::SubscriptionIdentifiersAvailable),
            0x2A => Some(Self::SharedSubscriptionAvailable),
            _ => None,
        }
    }
}

/// Property value.
#[derive(Debug, Clone)]
pub enum PropertyValue {
    /// Byte value.
    Byte(u8),
    /// Two-byte integer.
    TwoByteInteger(u16),
    /// Four-byte integer.
    FourByteInteger(u32),
    /// Variable byte integer.
    VariableByteInteger(u32),
    /// UTF-8 string.
    String(String),
    /// Binary data.
    Binary(Bytes),
    /// String pair.
    StringPair(String, String),
}

impl PropertyValue {
    /// Get as u8.
    pub fn as_u8(&self) -> Option<u8> {
        match self {
            Self::Byte(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as u16.
    pub fn as_u16(&self) -> Option<u16> {
        match self {
            Self::TwoByteInteger(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as u32.
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Self::FourByteInteger(v) | Self::VariableByteInteger(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(v) => Some(v),
            _ => None,
        }
    }

    /// Parse property value.
    fn parse(id: PropertyId, buf: &mut impl Buf, remaining: &mut usize) -> MqttResult<Self> {
        match id {
            PropertyId::PayloadFormatIndicator
            | PropertyId::RequestProblemInformation
            | PropertyId::RequestResponseInformation
            | PropertyId::MaximumQoS
            | PropertyId::RetainAvailable
            | PropertyId::WildcardSubscriptionAvailable
            | PropertyId::SubscriptionIdentifiersAvailable
            | PropertyId::SharedSubscriptionAvailable => {
                if buf.remaining() < 1 {
                    return Err(MqttError::IncompletePacket);
                }
                *remaining -= 1;
                Ok(Self::Byte(buf.get_u8()))
            },
            PropertyId::ReceiveMaximum
            | PropertyId::TopicAliasMaximum
            | PropertyId::TopicAlias
            | PropertyId::ServerKeepAlive => {
                if buf.remaining() < 2 {
                    return Err(MqttError::IncompletePacket);
                }
                *remaining -= 2;
                Ok(Self::TwoByteInteger(buf.get_u16()))
            },
            PropertyId::MessageExpiryInterval
            | PropertyId::SessionExpiryInterval
            | PropertyId::WillDelayInterval
            | PropertyId::MaximumPacketSize => {
                if buf.remaining() < 4 {
                    return Err(MqttError::IncompletePacket);
                }
                *remaining -= 4;
                Ok(Self::FourByteInteger(buf.get_u32()))
            },
            PropertyId::SubscriptionIdentifier => {
                let value = read_variable_int(buf)?;
                // Variable int can be 1-4 bytes
                let encoded_len = variable_int_len(value);
                *remaining -= encoded_len;
                Ok(Self::VariableByteInteger(value))
            },
            PropertyId::ContentType
            | PropertyId::ResponseTopic
            | PropertyId::AssignedClientIdentifier
            | PropertyId::AuthenticationMethod
            | PropertyId::ResponseInformation
            | PropertyId::ServerReference
            | PropertyId::ReasonString => {
                let s = read_string(buf)?;
                *remaining -= 2 + s.len();
                Ok(Self::String(s))
            },
            PropertyId::CorrelationData | PropertyId::AuthenticationData => {
                let data = read_binary(buf)?;
                *remaining -= 2 + data.len();
                Ok(Self::Binary(data))
            },
            PropertyId::UserProperty => {
                let key = read_string(buf)?;
                let value = read_string(buf)?;
                *remaining -= 4 + key.len() + value.len();
                Ok(Self::StringPair(key, value))
            },
        }
    }

    /// Serialize property value.
    fn serialize(&self, buf: &mut BytesMut) {
        match self {
            Self::Byte(v) => buf.put_u8(*v),
            Self::TwoByteInteger(v) => buf.put_u16(*v),
            Self::FourByteInteger(v) => buf.put_u32(*v),
            Self::VariableByteInteger(v) => write_variable_int(buf, *v),
            Self::String(v) => write_string(buf, v),
            Self::Binary(v) => {
                buf.put_u16(v.len() as u16);
                buf.extend_from_slice(v);
            },
            Self::StringPair(k, v) => {
                write_string(buf, k);
                write_string(buf, v);
            },
        }
    }
}

/// MQTT packet.
#[derive(Debug, Clone)]
pub enum MqttPacket {
    /// CONNECT packet.
    Connect(Connect),
    /// CONNACK packet.
    ConnAck(ConnAck),
    /// PUBLISH packet.
    Publish(Publish),
    /// PUBACK packet.
    PubAck(PubAck),
    /// PUBREC packet.
    PubRec(PubRec),
    /// PUBREL packet.
    PubRel(PubRel),
    /// PUBCOMP packet.
    PubComp(PubComp),
    /// SUBSCRIBE packet.
    Subscribe(Subscribe),
    /// SUBACK packet.
    SubAck(SubAck),
    /// UNSUBSCRIBE packet.
    Unsubscribe(Unsubscribe),
    /// UNSUBACK packet.
    UnsubAck(UnsubAck),
    /// PINGREQ packet.
    PingReq,
    /// PINGRESP packet.
    PingResp,
    /// DISCONNECT packet.
    Disconnect(Disconnect),
    /// AUTH packet (MQTT 5.0).
    Auth(Auth),
}

impl MqttPacket {
    /// Get the packet type.
    pub fn packet_type(&self) -> PacketType {
        match self {
            Self::Connect(_) => PacketType::Connect,
            Self::ConnAck(_) => PacketType::ConnAck,
            Self::Publish(_) => PacketType::Publish,
            Self::PubAck(_) => PacketType::PubAck,
            Self::PubRec(_) => PacketType::PubRec,
            Self::PubRel(_) => PacketType::PubRel,
            Self::PubComp(_) => PacketType::PubComp,
            Self::Subscribe(_) => PacketType::Subscribe,
            Self::SubAck(_) => PacketType::SubAck,
            Self::Unsubscribe(_) => PacketType::Unsubscribe,
            Self::UnsubAck(_) => PacketType::UnsubAck,
            Self::PingReq => PacketType::PingReq,
            Self::PingResp => PacketType::PingResp,
            Self::Disconnect(_) => PacketType::Disconnect,
            Self::Auth(_) => PacketType::Auth,
        }
    }

    /// Parse a packet from bytes.
    ///
    /// Returns the packet and the number of bytes consumed.
    pub fn parse(buf: &mut impl Buf, protocol_version: u8) -> MqttResult<Self> {
        if buf.remaining() < 2 {
            return Err(MqttError::IncompletePacket);
        }

        let first_byte = buf.get_u8();
        let packet_type_byte = first_byte >> 4;
        let flags = first_byte & 0x0F;

        let remaining_length = read_variable_int(buf)?;

        if buf.remaining() < remaining_length as usize {
            return Err(MqttError::IncompletePacket);
        }

        let packet_type = PacketType::from_u8(packet_type_byte)?;

        match packet_type {
            PacketType::Connect => Ok(Self::Connect(Connect::parse(buf)?)),
            PacketType::ConnAck => Ok(Self::ConnAck(ConnAck::parse(buf, protocol_version)?)),
            PacketType::Publish => Ok(Self::Publish(Publish::parse(
                buf,
                flags,
                remaining_length,
                protocol_version,
            )?)),
            PacketType::PubAck => Ok(Self::PubAck(PubAck::parse(
                buf,
                remaining_length,
                protocol_version,
            )?)),
            PacketType::PubRec => Ok(Self::PubRec(PubRec::parse(
                buf,
                remaining_length,
                protocol_version,
            )?)),
            PacketType::PubRel => Ok(Self::PubRel(PubRel::parse(
                buf,
                remaining_length,
                protocol_version,
            )?)),
            PacketType::PubComp => Ok(Self::PubComp(PubComp::parse(
                buf,
                remaining_length,
                protocol_version,
            )?)),
            PacketType::Subscribe => Ok(Self::Subscribe(Subscribe::parse(
                buf,
                remaining_length,
                protocol_version,
            )?)),
            PacketType::SubAck => Ok(Self::SubAck(SubAck::parse(
                buf,
                remaining_length,
                protocol_version,
            )?)),
            PacketType::Unsubscribe => Ok(Self::Unsubscribe(Unsubscribe::parse(
                buf,
                remaining_length,
                protocol_version,
            )?)),
            PacketType::UnsubAck => Ok(Self::UnsubAck(UnsubAck::parse(
                buf,
                remaining_length,
                protocol_version,
            )?)),
            PacketType::PingReq => Ok(Self::PingReq),
            PacketType::PingResp => Ok(Self::PingResp),
            PacketType::Disconnect => Ok(Self::Disconnect(Disconnect::parse(
                buf,
                remaining_length,
                protocol_version,
            )?)),
            PacketType::Auth => Ok(Self::Auth(Auth::parse(buf, remaining_length)?)),
        }
    }

    /// Serialize the packet to bytes.
    pub fn serialize(&self, protocol_version: u8) -> BytesMut {
        match self {
            Self::Connect(p) => p.serialize(),
            Self::ConnAck(p) => p.serialize(protocol_version),
            Self::Publish(p) => p.serialize(protocol_version),
            Self::PubAck(p) => p.serialize(protocol_version),
            Self::PubRec(p) => p.serialize(protocol_version),
            Self::PubRel(p) => p.serialize(protocol_version),
            Self::PubComp(p) => p.serialize(protocol_version),
            Self::Subscribe(p) => p.serialize(protocol_version),
            Self::SubAck(p) => p.serialize(protocol_version),
            Self::Unsubscribe(p) => p.serialize(protocol_version),
            Self::UnsubAck(p) => p.serialize(protocol_version),
            Self::PingReq => serialize_simple_packet(PacketType::PingReq),
            Self::PingResp => serialize_simple_packet(PacketType::PingResp),
            Self::Disconnect(p) => p.serialize(protocol_version),
            Self::Auth(p) => p.serialize(),
        }
    }
}

/// CONNECT packet.
#[derive(Debug, Clone)]
pub struct Connect {
    /// Protocol name.
    pub protocol_name: String,
    /// Protocol level/version.
    pub protocol_level: u8,
    /// Clean session/start flag.
    pub clean_session: bool,
    /// Will flag.
    pub will: Option<Will>,
    /// Username.
    pub username: Option<String>,
    /// Password.
    pub password: Option<Bytes>,
    /// Keep alive interval in seconds.
    pub keep_alive: u16,
    /// Client identifier.
    pub client_id: String,
    /// Properties (MQTT 5.0).
    pub properties: Properties,
}

impl Connect {
    /// Parse a CONNECT packet.
    pub fn parse(buf: &mut impl Buf) -> MqttResult<Self> {
        // Protocol name
        let protocol_name = read_string(buf)?;
        if protocol_name != "MQTT" && protocol_name != "MQIsdp" {
            return Err(MqttError::Protocol(format!(
                "Unknown protocol: {}",
                protocol_name
            )));
        }

        // Protocol level
        if buf.remaining() < 4 {
            return Err(MqttError::IncompletePacket);
        }
        let protocol_level = buf.get_u8();

        // Connect flags
        let flags = buf.get_u8();
        let clean_session = (flags & 0x02) != 0;
        let will_flag = (flags & 0x04) != 0;
        let will_qos = (flags >> 3) & 0x03;
        let will_retain = (flags & 0x20) != 0;
        let password_flag = (flags & 0x40) != 0;
        let username_flag = (flags & 0x80) != 0;

        // Keep alive
        let keep_alive = buf.get_u16();

        // Properties (MQTT 5.0)
        let properties = if protocol_level >= 5 {
            Properties::parse(buf)?
        } else {
            Properties::new()
        };

        // Client ID
        let client_id = read_string(buf)?;

        // Will properties and payload
        let will = if will_flag {
            let will_properties = if protocol_level >= 5 {
                Properties::parse(buf)?
            } else {
                Properties::new()
            };
            let topic = read_string(buf)?;
            let payload = read_binary(buf)?;
            Some(Will {
                topic,
                payload,
                qos: QoS::from_u8(will_qos)?,
                retain: will_retain,
                properties: will_properties,
            })
        } else {
            None
        };

        // Username
        let username = if username_flag {
            Some(read_string(buf)?)
        } else {
            None
        };

        // Password
        let password = if password_flag {
            Some(read_binary(buf)?)
        } else {
            None
        };

        Ok(Self {
            protocol_name,
            protocol_level,
            clean_session,
            will,
            username,
            password,
            keep_alive,
            client_id,
            properties,
        })
    }

    /// Serialize a CONNECT packet.
    pub fn serialize(&self) -> BytesMut {
        let mut payload = BytesMut::new();

        // Protocol name
        write_string(&mut payload, &self.protocol_name);

        // Protocol level
        payload.put_u8(self.protocol_level);

        // Connect flags
        let mut flags: u8 = 0;
        if self.clean_session {
            flags |= 0x02;
        }
        if let Some(ref will) = self.will {
            flags |= 0x04;
            flags |= (will.qos as u8) << 3;
            if will.retain {
                flags |= 0x20;
            }
        }
        if self.password.is_some() {
            flags |= 0x40;
        }
        if self.username.is_some() {
            flags |= 0x80;
        }
        payload.put_u8(flags);

        // Keep alive
        payload.put_u16(self.keep_alive);

        // Properties (MQTT 5.0)
        if self.protocol_level >= 5 {
            self.properties.serialize(&mut payload);
        }

        // Client ID
        write_string(&mut payload, &self.client_id);

        // Will
        if let Some(ref will) = self.will {
            if self.protocol_level >= 5 {
                will.properties.serialize(&mut payload);
            }
            write_string(&mut payload, &will.topic);
            payload.put_u16(will.payload.len() as u16);
            payload.extend_from_slice(&will.payload);
        }

        // Username
        if let Some(ref username) = self.username {
            write_string(&mut payload, username);
        }

        // Password
        if let Some(ref password) = self.password {
            payload.put_u16(password.len() as u16);
            payload.extend_from_slice(password);
        }

        build_packet(PacketType::Connect, 0, &payload)
    }
}

/// Will message.
#[derive(Debug, Clone)]
pub struct Will {
    /// Topic.
    pub topic: String,
    /// Payload.
    pub payload: Bytes,
    /// QoS level.
    pub qos: QoS,
    /// Retain flag.
    pub retain: bool,
    /// Properties (MQTT 5.0).
    pub properties: Properties,
}

/// CONNACK packet.
#[derive(Debug, Clone)]
pub struct ConnAck {
    /// Session present flag.
    pub session_present: bool,
    /// Return/reason code.
    pub reason_code: u8,
    /// Properties (MQTT 5.0).
    pub properties: Properties,
}

impl ConnAck {
    /// Create a success CONNACK.
    pub fn success(session_present: bool) -> Self {
        Self {
            session_present,
            reason_code: 0,
            properties: Properties::new(),
        }
    }

    /// Create an error CONNACK.
    pub fn error(reason_code: ConnectReasonCode) -> Self {
        Self {
            session_present: false,
            reason_code: reason_code as u8,
            properties: Properties::new(),
        }
    }

    /// Parse a CONNACK packet.
    pub fn parse(buf: &mut impl Buf, protocol_version: u8) -> MqttResult<Self> {
        if buf.remaining() < 2 {
            return Err(MqttError::IncompletePacket);
        }

        let flags = buf.get_u8();
        let session_present = (flags & 0x01) != 0;
        let reason_code = buf.get_u8();

        let properties = if protocol_version >= 5 && buf.has_remaining() {
            Properties::parse(buf)?
        } else {
            Properties::new()
        };

        Ok(Self {
            session_present,
            reason_code,
            properties,
        })
    }

    /// Serialize a CONNACK packet.
    pub fn serialize(&self, protocol_version: u8) -> BytesMut {
        let mut payload = BytesMut::new();

        let flags = if self.session_present { 0x01 } else { 0x00 };
        payload.put_u8(flags);
        payload.put_u8(self.reason_code);

        if protocol_version >= 5 {
            self.properties.serialize(&mut payload);
        }

        build_packet(PacketType::ConnAck, 0, &payload)
    }
}

/// PUBLISH packet.
#[derive(Debug, Clone)]
pub struct Publish {
    /// Duplicate delivery flag.
    pub dup: bool,
    /// QoS level.
    pub qos: QoS,
    /// Retain flag.
    pub retain: bool,
    /// Topic name.
    pub topic: String,
    /// Packet identifier (for QoS > 0).
    pub packet_id: Option<u16>,
    /// Payload.
    pub payload: Bytes,
    /// Properties (MQTT 5.0).
    pub properties: Properties,
}

impl Publish {
    /// Create a new PUBLISH packet.
    pub fn new(topic: impl Into<String>, payload: impl Into<Bytes>) -> Self {
        Self {
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            topic: topic.into(),
            packet_id: None,
            payload: payload.into(),
            properties: Properties::new(),
        }
    }

    /// Set QoS and packet ID.
    pub fn with_qos(mut self, qos: QoS, packet_id: u16) -> Self {
        self.qos = qos;
        if qos != QoS::AtMostOnce {
            self.packet_id = Some(packet_id);
        }
        self
    }

    /// Set retain flag.
    pub fn with_retain(mut self, retain: bool) -> Self {
        self.retain = retain;
        self
    }

    /// Parse a PUBLISH packet.
    pub fn parse(
        buf: &mut impl Buf,
        flags: u8,
        remaining_length: u32,
        protocol_version: u8,
    ) -> MqttResult<Self> {
        let dup = (flags & 0x08) != 0;
        let qos = QoS::from_u8((flags >> 1) & 0x03)?;
        let retain = (flags & 0x01) != 0;

        let topic = read_string(buf)?;
        let mut consumed = 2 + topic.len();

        let packet_id = if qos != QoS::AtMostOnce {
            if buf.remaining() < 2 {
                return Err(MqttError::IncompletePacket);
            }
            consumed += 2;
            Some(buf.get_u16())
        } else {
            None
        };

        let properties = if protocol_version >= 5 {
            let start = buf.remaining();
            let props = Properties::parse(buf)?;
            consumed += start - buf.remaining();
            props
        } else {
            Properties::new()
        };

        let payload_len = remaining_length as usize - consumed;
        if buf.remaining() < payload_len {
            return Err(MqttError::IncompletePacket);
        }

        let payload = buf.copy_to_bytes(payload_len);

        Ok(Self {
            dup,
            qos,
            retain,
            topic,
            packet_id,
            payload,
            properties,
        })
    }

    /// Serialize a PUBLISH packet.
    pub fn serialize(&self, protocol_version: u8) -> BytesMut {
        let mut payload = BytesMut::new();

        write_string(&mut payload, &self.topic);

        if self.qos != QoS::AtMostOnce {
            if let Some(id) = self.packet_id {
                payload.put_u16(id);
            }
        }

        if protocol_version >= 5 {
            self.properties.serialize(&mut payload);
        }

        payload.extend_from_slice(&self.payload);

        let mut flags: u8 = 0;
        if self.dup {
            flags |= 0x08;
        }
        flags |= (self.qos as u8) << 1;
        if self.retain {
            flags |= 0x01;
        }

        build_packet(PacketType::Publish, flags, &payload)
    }
}

/// PUBACK packet.
#[derive(Debug, Clone)]
pub struct PubAck {
    /// Packet identifier.
    pub packet_id: u16,
    /// Reason code (MQTT 5.0).
    pub reason_code: u8,
    /// Properties (MQTT 5.0).
    pub properties: Properties,
}

impl PubAck {
    /// Create a new PUBACK.
    pub fn new(packet_id: u16) -> Self {
        Self {
            packet_id,
            reason_code: 0,
            properties: Properties::new(),
        }
    }

    /// Parse a PUBACK packet.
    pub fn parse(
        buf: &mut impl Buf,
        remaining_length: u32,
        protocol_version: u8,
    ) -> MqttResult<Self> {
        if buf.remaining() < 2 {
            return Err(MqttError::IncompletePacket);
        }

        let packet_id = buf.get_u16();

        let (reason_code, properties) = if remaining_length > 2 && protocol_version >= 5 {
            let rc = buf.get_u8();
            let props = if remaining_length > 3 {
                Properties::parse(buf)?
            } else {
                Properties::new()
            };
            (rc, props)
        } else {
            (0, Properties::new())
        };

        Ok(Self {
            packet_id,
            reason_code,
            properties,
        })
    }

    /// Serialize a PUBACK packet.
    pub fn serialize(&self, protocol_version: u8) -> BytesMut {
        let mut payload = BytesMut::new();
        payload.put_u16(self.packet_id);

        if protocol_version >= 5 && (self.reason_code != 0 || !self.properties.is_empty()) {
            payload.put_u8(self.reason_code);
            self.properties.serialize(&mut payload);
        }

        build_packet(PacketType::PubAck, 0, &payload)
    }
}

/// PUBREC packet (QoS 2, step 1).
#[derive(Debug, Clone)]
pub struct PubRec {
    /// Packet identifier.
    pub packet_id: u16,
    /// Reason code (MQTT 5.0).
    pub reason_code: u8,
    /// Properties (MQTT 5.0).
    pub properties: Properties,
}

impl PubRec {
    /// Create a new PUBREC.
    pub fn new(packet_id: u16) -> Self {
        Self {
            packet_id,
            reason_code: 0,
            properties: Properties::new(),
        }
    }

    /// Parse a PUBREC packet.
    pub fn parse(
        buf: &mut impl Buf,
        remaining_length: u32,
        protocol_version: u8,
    ) -> MqttResult<Self> {
        if buf.remaining() < 2 {
            return Err(MqttError::IncompletePacket);
        }

        let packet_id = buf.get_u16();

        let (reason_code, properties) = if remaining_length > 2 && protocol_version >= 5 {
            let rc = buf.get_u8();
            let props = if remaining_length > 3 {
                Properties::parse(buf)?
            } else {
                Properties::new()
            };
            (rc, props)
        } else {
            (0, Properties::new())
        };

        Ok(Self {
            packet_id,
            reason_code,
            properties,
        })
    }

    /// Serialize a PUBREC packet.
    pub fn serialize(&self, protocol_version: u8) -> BytesMut {
        let mut payload = BytesMut::new();
        payload.put_u16(self.packet_id);

        if protocol_version >= 5 && (self.reason_code != 0 || !self.properties.is_empty()) {
            payload.put_u8(self.reason_code);
            self.properties.serialize(&mut payload);
        }

        build_packet(PacketType::PubRec, 0, &payload)
    }
}

/// PUBREL packet (QoS 2, step 2).
#[derive(Debug, Clone)]
pub struct PubRel {
    /// Packet identifier.
    pub packet_id: u16,
    /// Reason code (MQTT 5.0).
    pub reason_code: u8,
    /// Properties (MQTT 5.0).
    pub properties: Properties,
}

impl PubRel {
    /// Create a new PUBREL.
    pub fn new(packet_id: u16) -> Self {
        Self {
            packet_id,
            reason_code: 0,
            properties: Properties::new(),
        }
    }

    /// Parse a PUBREL packet.
    pub fn parse(
        buf: &mut impl Buf,
        remaining_length: u32,
        protocol_version: u8,
    ) -> MqttResult<Self> {
        if buf.remaining() < 2 {
            return Err(MqttError::IncompletePacket);
        }

        let packet_id = buf.get_u16();

        let (reason_code, properties) = if remaining_length > 2 && protocol_version >= 5 {
            let rc = buf.get_u8();
            let props = if remaining_length > 3 {
                Properties::parse(buf)?
            } else {
                Properties::new()
            };
            (rc, props)
        } else {
            (0, Properties::new())
        };

        Ok(Self {
            packet_id,
            reason_code,
            properties,
        })
    }

    /// Serialize a PUBREL packet.
    pub fn serialize(&self, protocol_version: u8) -> BytesMut {
        let mut payload = BytesMut::new();
        payload.put_u16(self.packet_id);

        if protocol_version >= 5 && (self.reason_code != 0 || !self.properties.is_empty()) {
            payload.put_u8(self.reason_code);
            self.properties.serialize(&mut payload);
        }

        // PUBREL has fixed flags 0x02
        build_packet(PacketType::PubRel, 0x02, &payload)
    }
}

/// PUBCOMP packet (QoS 2, step 3).
#[derive(Debug, Clone)]
pub struct PubComp {
    /// Packet identifier.
    pub packet_id: u16,
    /// Reason code (MQTT 5.0).
    pub reason_code: u8,
    /// Properties (MQTT 5.0).
    pub properties: Properties,
}

impl PubComp {
    /// Create a new PUBCOMP.
    pub fn new(packet_id: u16) -> Self {
        Self {
            packet_id,
            reason_code: 0,
            properties: Properties::new(),
        }
    }

    /// Parse a PUBCOMP packet.
    pub fn parse(
        buf: &mut impl Buf,
        remaining_length: u32,
        protocol_version: u8,
    ) -> MqttResult<Self> {
        if buf.remaining() < 2 {
            return Err(MqttError::IncompletePacket);
        }

        let packet_id = buf.get_u16();

        let (reason_code, properties) = if remaining_length > 2 && protocol_version >= 5 {
            let rc = buf.get_u8();
            let props = if remaining_length > 3 {
                Properties::parse(buf)?
            } else {
                Properties::new()
            };
            (rc, props)
        } else {
            (0, Properties::new())
        };

        Ok(Self {
            packet_id,
            reason_code,
            properties,
        })
    }

    /// Serialize a PUBCOMP packet.
    pub fn serialize(&self, protocol_version: u8) -> BytesMut {
        let mut payload = BytesMut::new();
        payload.put_u16(self.packet_id);

        if protocol_version >= 5 && (self.reason_code != 0 || !self.properties.is_empty()) {
            payload.put_u8(self.reason_code);
            self.properties.serialize(&mut payload);
        }

        build_packet(PacketType::PubComp, 0, &payload)
    }
}

/// Subscription options (MQTT 5.0).
#[derive(Debug, Clone, Copy, Default)]
pub struct SubscriptionOptions {
    /// Maximum QoS.
    pub qos: QoS,
    /// No local flag.
    pub no_local: bool,
    /// Retain as published flag.
    pub retain_as_published: bool,
    /// Retain handling.
    pub retain_handling: u8,
}

impl SubscriptionOptions {
    /// Parse from byte.
    pub fn from_byte(byte: u8) -> MqttResult<Self> {
        Ok(Self {
            qos: QoS::from_u8(byte & 0x03)?,
            no_local: (byte & 0x04) != 0,
            retain_as_published: (byte & 0x08) != 0,
            retain_handling: (byte >> 4) & 0x03,
        })
    }

    /// Convert to byte.
    pub fn to_byte(&self) -> u8 {
        let mut byte = self.qos as u8;
        if self.no_local {
            byte |= 0x04;
        }
        if self.retain_as_published {
            byte |= 0x08;
        }
        byte |= (self.retain_handling & 0x03) << 4;
        byte
    }
}

/// Subscription in a SUBSCRIBE packet.
#[derive(Debug, Clone)]
pub struct Subscription {
    /// Topic filter.
    pub topic_filter: String,
    /// Options.
    pub options: SubscriptionOptions,
}

/// SUBSCRIBE packet.
#[derive(Debug, Clone)]
pub struct Subscribe {
    /// Packet identifier.
    pub packet_id: u16,
    /// Subscriptions.
    pub subscriptions: Vec<Subscription>,
    /// Properties (MQTT 5.0).
    pub properties: Properties,
}

impl Subscribe {
    /// Parse a SUBSCRIBE packet.
    pub fn parse(
        buf: &mut impl Buf,
        remaining_length: u32,
        protocol_version: u8,
    ) -> MqttResult<Self> {
        if buf.remaining() < 2 {
            return Err(MqttError::IncompletePacket);
        }

        let packet_id = buf.get_u16();
        let mut consumed = 2usize;

        let properties = if protocol_version >= 5 {
            let start = buf.remaining();
            let props = Properties::parse(buf)?;
            consumed += start - buf.remaining();
            props
        } else {
            Properties::new()
        };

        let mut subscriptions = Vec::new();
        while consumed < remaining_length as usize {
            let topic_filter = read_string(buf)?;
            consumed += 2 + topic_filter.len();

            if buf.remaining() < 1 {
                return Err(MqttError::IncompletePacket);
            }
            let options_byte = buf.get_u8();
            consumed += 1;

            let options = SubscriptionOptions::from_byte(options_byte)?;
            subscriptions.push(Subscription {
                topic_filter,
                options,
            });
        }

        Ok(Self {
            packet_id,
            subscriptions,
            properties,
        })
    }

    /// Serialize a SUBSCRIBE packet.
    pub fn serialize(&self, protocol_version: u8) -> BytesMut {
        let mut payload = BytesMut::new();
        payload.put_u16(self.packet_id);

        if protocol_version >= 5 {
            self.properties.serialize(&mut payload);
        }

        for sub in &self.subscriptions {
            write_string(&mut payload, &sub.topic_filter);
            payload.put_u8(sub.options.to_byte());
        }

        // SUBSCRIBE has fixed flags 0x02
        build_packet(PacketType::Subscribe, 0x02, &payload)
    }
}

/// SUBACK packet.
#[derive(Debug, Clone)]
pub struct SubAck {
    /// Packet identifier.
    pub packet_id: u16,
    /// Reason codes.
    pub reason_codes: Vec<u8>,
    /// Properties (MQTT 5.0).
    pub properties: Properties,
}

impl SubAck {
    /// Parse a SUBACK packet.
    pub fn parse(
        buf: &mut impl Buf,
        remaining_length: u32,
        protocol_version: u8,
    ) -> MqttResult<Self> {
        if buf.remaining() < 2 {
            return Err(MqttError::IncompletePacket);
        }

        let packet_id = buf.get_u16();
        let mut consumed = 2usize;

        let properties = if protocol_version >= 5 {
            let start = buf.remaining();
            let props = Properties::parse(buf)?;
            consumed += start - buf.remaining();
            props
        } else {
            Properties::new()
        };

        let codes_len = remaining_length as usize - consumed;
        if buf.remaining() < codes_len {
            return Err(MqttError::IncompletePacket);
        }

        let mut reason_codes = Vec::with_capacity(codes_len);
        for _ in 0..codes_len {
            reason_codes.push(buf.get_u8());
        }

        Ok(Self {
            packet_id,
            reason_codes,
            properties,
        })
    }

    /// Serialize a SUBACK packet.
    pub fn serialize(&self, protocol_version: u8) -> BytesMut {
        let mut payload = BytesMut::new();
        payload.put_u16(self.packet_id);

        if protocol_version >= 5 {
            self.properties.serialize(&mut payload);
        }

        for code in &self.reason_codes {
            payload.put_u8(*code);
        }

        build_packet(PacketType::SubAck, 0, &payload)
    }
}

/// UNSUBSCRIBE packet.
#[derive(Debug, Clone)]
pub struct Unsubscribe {
    /// Packet identifier.
    pub packet_id: u16,
    /// Topic filters.
    pub topic_filters: Vec<String>,
    /// Properties (MQTT 5.0).
    pub properties: Properties,
}

impl Unsubscribe {
    /// Parse an UNSUBSCRIBE packet.
    pub fn parse(
        buf: &mut impl Buf,
        remaining_length: u32,
        protocol_version: u8,
    ) -> MqttResult<Self> {
        if buf.remaining() < 2 {
            return Err(MqttError::IncompletePacket);
        }

        let packet_id = buf.get_u16();
        let mut consumed = 2usize;

        let properties = if protocol_version >= 5 {
            let start = buf.remaining();
            let props = Properties::parse(buf)?;
            consumed += start - buf.remaining();
            props
        } else {
            Properties::new()
        };

        let mut topic_filters = Vec::new();
        while consumed < remaining_length as usize {
            let topic_filter = read_string(buf)?;
            consumed += 2 + topic_filter.len();
            topic_filters.push(topic_filter);
        }

        Ok(Self {
            packet_id,
            topic_filters,
            properties,
        })
    }

    /// Serialize an UNSUBSCRIBE packet.
    pub fn serialize(&self, protocol_version: u8) -> BytesMut {
        let mut payload = BytesMut::new();
        payload.put_u16(self.packet_id);

        if protocol_version >= 5 {
            self.properties.serialize(&mut payload);
        }

        for filter in &self.topic_filters {
            write_string(&mut payload, filter);
        }

        // UNSUBSCRIBE has fixed flags 0x02
        build_packet(PacketType::Unsubscribe, 0x02, &payload)
    }
}

/// UNSUBACK packet.
#[derive(Debug, Clone)]
pub struct UnsubAck {
    /// Packet identifier.
    pub packet_id: u16,
    /// Reason codes (MQTT 5.0).
    pub reason_codes: Vec<u8>,
    /// Properties (MQTT 5.0).
    pub properties: Properties,
}

impl UnsubAck {
    /// Parse an UNSUBACK packet.
    pub fn parse(
        buf: &mut impl Buf,
        remaining_length: u32,
        protocol_version: u8,
    ) -> MqttResult<Self> {
        if buf.remaining() < 2 {
            return Err(MqttError::IncompletePacket);
        }

        let packet_id = buf.get_u16();

        let (reason_codes, properties) = if protocol_version >= 5 {
            let mut consumed = 2usize;
            let start = buf.remaining();
            let props = Properties::parse(buf)?;
            consumed += start - buf.remaining();

            let codes_len = remaining_length as usize - consumed;
            let mut codes = Vec::with_capacity(codes_len);
            for _ in 0..codes_len {
                codes.push(buf.get_u8());
            }
            (codes, props)
        } else {
            (Vec::new(), Properties::new())
        };

        Ok(Self {
            packet_id,
            reason_codes,
            properties,
        })
    }

    /// Serialize an UNSUBACK packet.
    pub fn serialize(&self, protocol_version: u8) -> BytesMut {
        let mut payload = BytesMut::new();
        payload.put_u16(self.packet_id);

        if protocol_version >= 5 {
            self.properties.serialize(&mut payload);
            for code in &self.reason_codes {
                payload.put_u8(*code);
            }
        }

        build_packet(PacketType::UnsubAck, 0, &payload)
    }
}

/// DISCONNECT packet.
#[derive(Debug, Clone)]
pub struct Disconnect {
    /// Reason code (MQTT 5.0).
    pub reason_code: u8,
    /// Properties (MQTT 5.0).
    pub properties: Properties,
}

impl Default for Disconnect {
    fn default() -> Self {
        Self {
            reason_code: 0,
            properties: Properties::new(),
        }
    }
}

impl Disconnect {
    /// Parse a DISCONNECT packet.
    pub fn parse(
        buf: &mut impl Buf,
        remaining_length: u32,
        protocol_version: u8,
    ) -> MqttResult<Self> {
        if protocol_version >= 5 && remaining_length > 0 {
            let reason_code = buf.get_u8();
            let properties = if remaining_length > 1 {
                Properties::parse(buf)?
            } else {
                Properties::new()
            };
            Ok(Self {
                reason_code,
                properties,
            })
        } else {
            Ok(Self::default())
        }
    }

    /// Serialize a DISCONNECT packet.
    pub fn serialize(&self, protocol_version: u8) -> BytesMut {
        let mut payload = BytesMut::new();

        if protocol_version >= 5 && (self.reason_code != 0 || !self.properties.is_empty()) {
            payload.put_u8(self.reason_code);
            self.properties.serialize(&mut payload);
        }

        build_packet(PacketType::Disconnect, 0, &payload)
    }
}

/// AUTH packet (MQTT 5.0).
#[derive(Debug, Clone)]
pub struct Auth {
    /// Reason code.
    pub reason_code: u8,
    /// Properties.
    pub properties: Properties,
}

impl Auth {
    /// Parse an AUTH packet.
    pub fn parse(buf: &mut impl Buf, remaining_length: u32) -> MqttResult<Self> {
        let reason_code = if remaining_length > 0 {
            buf.get_u8()
        } else {
            0
        };

        let properties = if remaining_length > 1 {
            Properties::parse(buf)?
        } else {
            Properties::new()
        };

        Ok(Self {
            reason_code,
            properties,
        })
    }

    /// Serialize an AUTH packet.
    pub fn serialize(&self) -> BytesMut {
        let mut payload = BytesMut::new();

        if self.reason_code != 0 || !self.properties.is_empty() {
            payload.put_u8(self.reason_code);
            self.properties.serialize(&mut payload);
        }

        build_packet(PacketType::Auth, 0, &payload)
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Read a variable byte integer.
pub fn read_variable_int(buf: &mut impl Buf) -> MqttResult<u32> {
    let mut value: u32 = 0;
    let mut shift: u32 = 0;

    loop {
        if !buf.has_remaining() {
            return Err(MqttError::IncompletePacket);
        }

        let byte = buf.get_u8();
        value |= ((byte & 0x7F) as u32) << shift;

        if (byte & 0x80) == 0 {
            break;
        }

        shift += 7;
        if shift > 21 {
            return Err(MqttError::MalformedRemainingLength);
        }
    }

    Ok(value)
}

/// Write a variable byte integer.
pub fn write_variable_int(buf: &mut BytesMut, mut value: u32) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;

        if value > 0 {
            byte |= 0x80;
        }

        buf.put_u8(byte);

        if value == 0 {
            break;
        }
    }
}

/// Get the length of a variable byte integer.
pub fn variable_int_len(value: u32) -> usize {
    match value {
        0..=127 => 1,
        128..=16383 => 2,
        16384..=2097151 => 3,
        _ => 4,
    }
}

/// Read a UTF-8 string.
pub fn read_string(buf: &mut impl Buf) -> MqttResult<String> {
    if buf.remaining() < 2 {
        return Err(MqttError::IncompletePacket);
    }

    let len = buf.get_u16() as usize;

    if buf.remaining() < len {
        return Err(MqttError::IncompletePacket);
    }

    let bytes = buf.copy_to_bytes(len);
    String::from_utf8(bytes.to_vec()).map_err(|e| MqttError::InvalidUtf8(e.to_string()))
}

/// Write a UTF-8 string.
pub fn write_string(buf: &mut BytesMut, s: &str) {
    buf.put_u16(s.len() as u16);
    buf.extend_from_slice(s.as_bytes());
}

/// Read binary data.
pub fn read_binary(buf: &mut impl Buf) -> MqttResult<Bytes> {
    if buf.remaining() < 2 {
        return Err(MqttError::IncompletePacket);
    }

    let len = buf.get_u16() as usize;

    if buf.remaining() < len {
        return Err(MqttError::IncompletePacket);
    }

    Ok(buf.copy_to_bytes(len))
}

/// Build a packet with header.
fn build_packet(packet_type: PacketType, flags: u8, payload: &[u8]) -> BytesMut {
    let mut buf = BytesMut::new();

    let first_byte = ((packet_type as u8) << 4) | (flags & 0x0F);
    buf.put_u8(first_byte);

    write_variable_int(&mut buf, payload.len() as u32);
    buf.extend_from_slice(payload);

    buf
}

/// Serialize a simple packet (PINGREQ/PINGRESP).
fn serialize_simple_packet(packet_type: PacketType) -> BytesMut {
    let mut buf = BytesMut::new();
    buf.put_u8((packet_type as u8) << 4);
    buf.put_u8(0); // remaining length = 0
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qos_from_u8() {
        assert_eq!(QoS::from_u8(0).unwrap(), QoS::AtMostOnce);
        assert_eq!(QoS::from_u8(1).unwrap(), QoS::AtLeastOnce);
        assert_eq!(QoS::from_u8(2).unwrap(), QoS::ExactlyOnce);
        assert!(QoS::from_u8(3).is_err());
    }

    #[test]
    fn test_packet_type_from_u8() {
        assert_eq!(PacketType::from_u8(1).unwrap(), PacketType::Connect);
        assert_eq!(PacketType::from_u8(3).unwrap(), PacketType::Publish);
        assert_eq!(PacketType::from_u8(14).unwrap(), PacketType::Disconnect);
        assert!(PacketType::from_u8(0).is_err());
        assert!(PacketType::from_u8(16).is_err());
    }

    #[test]
    fn test_variable_int() {
        let mut buf = BytesMut::new();

        // Test small values
        write_variable_int(&mut buf, 0);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], 0);

        buf.clear();
        write_variable_int(&mut buf, 127);
        assert_eq!(buf.len(), 1);

        buf.clear();
        write_variable_int(&mut buf, 128);
        assert_eq!(buf.len(), 2);

        buf.clear();
        write_variable_int(&mut buf, 16383);
        assert_eq!(buf.len(), 2);

        buf.clear();
        write_variable_int(&mut buf, 16384);
        assert_eq!(buf.len(), 3);

        // Round-trip test
        buf.clear();
        write_variable_int(&mut buf, 268435455);
        let mut reader = buf.freeze();
        assert_eq!(read_variable_int(&mut reader).unwrap(), 268435455);
    }

    #[test]
    fn test_string_round_trip() {
        let mut buf = BytesMut::new();
        write_string(&mut buf, "hello/world");
        let mut reader = buf.freeze();
        assert_eq!(read_string(&mut reader).unwrap(), "hello/world");
    }

    #[test]
    fn test_connect_packet() {
        let connect = Connect {
            protocol_name: "MQTT".to_string(),
            protocol_level: 4,
            clean_session: true,
            will: None,
            username: Some("user".to_string()),
            password: Some(Bytes::from("pass")),
            keep_alive: 60,
            client_id: "test-client".to_string(),
            properties: Properties::new(),
        };

        let bytes = connect.serialize();
        let mut buf = bytes.freeze();

        // Skip fixed header
        let _ = buf.get_u8();
        let _ = read_variable_int(&mut buf).unwrap();

        let parsed = Connect::parse(&mut buf).unwrap();
        assert_eq!(parsed.protocol_name, "MQTT");
        assert_eq!(parsed.protocol_level, 4);
        assert!(parsed.clean_session);
        assert_eq!(parsed.username, Some("user".to_string()));
        assert_eq!(parsed.client_id, "test-client");
    }

    #[test]
    fn test_connack_packet() {
        let connack = ConnAck::success(true);
        let bytes = connack.serialize(4);
        let mut buf = bytes.freeze();

        // Skip fixed header
        let _ = buf.get_u8();
        let _ = read_variable_int(&mut buf).unwrap();

        let parsed = ConnAck::parse(&mut buf, 4).unwrap();
        assert!(parsed.session_present);
        assert_eq!(parsed.reason_code, 0);
    }

    #[test]
    fn test_publish_packet() {
        let publish = Publish::new("test/topic", "hello world")
            .with_qos(QoS::AtLeastOnce, 123)
            .with_retain(true);

        let bytes = publish.serialize(4);
        let mut buf = bytes.freeze();

        let first_byte = buf.get_u8();
        let flags = first_byte & 0x0F;
        let remaining_length = read_variable_int(&mut buf).unwrap();

        let parsed = Publish::parse(&mut buf, flags, remaining_length, 4).unwrap();
        assert_eq!(parsed.topic, "test/topic");
        assert_eq!(parsed.qos, QoS::AtLeastOnce);
        assert_eq!(parsed.packet_id, Some(123));
        assert!(parsed.retain);
        assert_eq!(&parsed.payload[..], b"hello world");
    }

    #[test]
    fn test_subscribe_packet() {
        let subscribe = Subscribe {
            packet_id: 1,
            subscriptions: vec![
                Subscription {
                    topic_filter: "test/#".to_string(),
                    options: SubscriptionOptions {
                        qos: QoS::AtLeastOnce,
                        ..Default::default()
                    },
                },
                Subscription {
                    topic_filter: "sensor/+/temp".to_string(),
                    options: SubscriptionOptions {
                        qos: QoS::ExactlyOnce,
                        ..Default::default()
                    },
                },
            ],
            properties: Properties::new(),
        };

        let bytes = subscribe.serialize(4);
        let mut buf = bytes.freeze();

        let first_byte = buf.get_u8();
        assert_eq!(first_byte >> 4, PacketType::Subscribe as u8);
        let remaining_length = read_variable_int(&mut buf).unwrap();

        let parsed = Subscribe::parse(&mut buf, remaining_length, 4).unwrap();
        assert_eq!(parsed.packet_id, 1);
        assert_eq!(parsed.subscriptions.len(), 2);
        assert_eq!(parsed.subscriptions[0].topic_filter, "test/#");
        assert_eq!(parsed.subscriptions[1].topic_filter, "sensor/+/temp");
    }

    #[test]
    fn test_pingreq_pingresp() {
        let pingreq = serialize_simple_packet(PacketType::PingReq);
        assert_eq!(pingreq.len(), 2);
        assert_eq!(pingreq[0], 0xC0);
        assert_eq!(pingreq[1], 0x00);

        let pingresp = serialize_simple_packet(PacketType::PingResp);
        assert_eq!(pingresp.len(), 2);
        assert_eq!(pingresp[0], 0xD0);
        assert_eq!(pingresp[1], 0x00);
    }

    #[test]
    fn test_mqtt5_properties() {
        let mut props = Properties::new();
        props.set(
            PropertyId::SessionExpiryInterval,
            PropertyValue::FourByteInteger(3600),
        );
        props.set(
            PropertyId::ReceiveMaximum,
            PropertyValue::TwoByteInteger(100),
        );

        let mut buf = BytesMut::new();
        props.serialize(&mut buf);

        let mut reader = buf.freeze();
        let parsed = Properties::parse(&mut reader).unwrap();

        assert_eq!(parsed.session_expiry_interval(), Some(3600));
        assert_eq!(parsed.receive_maximum(), Some(100));
    }

    #[test]
    fn test_disconnect_packet_v5() {
        let disconnect = Disconnect {
            reason_code: 0x04, // Disconnect with will
            ..Disconnect::default()
        };

        let bytes = disconnect.serialize(5);
        let mut buf = bytes.freeze();

        let first_byte = buf.get_u8();
        assert_eq!(first_byte >> 4, PacketType::Disconnect as u8);
        let remaining_length = read_variable_int(&mut buf).unwrap();

        let parsed = Disconnect::parse(&mut buf, remaining_length, 5).unwrap();
        assert_eq!(parsed.reason_code, 0x04);
    }

    #[test]
    fn test_subscription_options() {
        let opts = SubscriptionOptions {
            qos: QoS::ExactlyOnce,
            no_local: true,
            retain_as_published: true,
            retain_handling: 2,
        };

        let byte = opts.to_byte();
        let parsed = SubscriptionOptions::from_byte(byte).unwrap();

        assert_eq!(parsed.qos, QoS::ExactlyOnce);
        assert!(parsed.no_local);
        assert!(parsed.retain_as_published);
        assert_eq!(parsed.retain_handling, 2);
    }

    #[test]
    fn test_variable_int_len() {
        assert_eq!(variable_int_len(0), 1);
        assert_eq!(variable_int_len(127), 1);
        assert_eq!(variable_int_len(128), 2);
        assert_eq!(variable_int_len(16383), 2);
        assert_eq!(variable_int_len(16384), 3);
        assert_eq!(variable_int_len(2097151), 3);
        assert_eq!(variable_int_len(2097152), 4);
    }
}
