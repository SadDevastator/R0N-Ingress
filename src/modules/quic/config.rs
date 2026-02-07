//! QUIC configuration

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// QUIC endpoint configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    /// Enable QUIC transport
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Bind address for QUIC server
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// TLS certificate path
    pub cert_path: Option<PathBuf>,

    /// TLS private key path
    pub key_path: Option<PathBuf>,

    /// ALPN protocols (e.g., ["h3", "h3-29"])
    #[serde(default = "default_alpn")]
    pub alpn_protocols: Vec<String>,

    /// Maximum idle timeout
    #[serde(default = "default_idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,

    /// Maximum concurrent bidirectional streams
    #[serde(default = "default_max_bidi_streams")]
    pub max_bidirectional_streams: u64,

    /// Maximum concurrent unidirectional streams
    #[serde(default = "default_max_uni_streams")]
    pub max_unidirectional_streams: u64,

    /// Initial maximum data (connection-level flow control)
    #[serde(default = "default_max_data")]
    pub max_data: u64,

    /// Initial maximum stream data for bidirectional streams
    #[serde(default = "default_max_stream_data_bidi")]
    pub max_stream_data_bidi_local: u64,

    /// Initial maximum stream data for remote-initiated bidirectional streams
    #[serde(default = "default_max_stream_data_bidi")]
    pub max_stream_data_bidi_remote: u64,

    /// Initial maximum stream data for unidirectional streams
    #[serde(default = "default_max_stream_data_uni")]
    pub max_stream_data_uni: u64,

    /// Enable 0-RTT (early data)
    #[serde(default = "default_zero_rtt")]
    pub enable_0rtt: bool,

    /// Maximum 0-RTT data size
    #[serde(default = "default_max_0rtt_data")]
    pub max_0rtt_data: u64,

    /// Connection migration settings
    #[serde(default)]
    pub migration: MigrationConfig,

    /// Congestion control algorithm
    #[serde(default)]
    pub congestion_control: CongestionControl,

    /// Keep-alive interval
    #[serde(default = "default_keep_alive", with = "humantime_serde")]
    pub keep_alive_interval: Option<Duration>,

    /// Maximum UDP payload size
    #[serde(default = "default_max_udp_payload")]
    pub max_udp_payload_size: u16,

    /// Active connection ID limit
    #[serde(default = "default_connection_id_limit")]
    pub active_connection_id_limit: u64,

    /// Disable active migration
    #[serde(default)]
    pub disable_active_migration: bool,

    /// ACK delay exponent
    #[serde(default = "default_ack_delay_exponent")]
    pub ack_delay_exponent: u8,

    /// Maximum ACK delay
    #[serde(default = "default_max_ack_delay", with = "humantime_serde")]
    pub max_ack_delay: Duration,
}

fn default_enabled() -> bool {
    true
}

fn default_bind_address() -> String {
    "[::]:443".to_string()
}

fn default_alpn() -> Vec<String> {
    vec!["h3".to_string()]
}

fn default_idle_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_max_bidi_streams() -> u64 {
    100
}

fn default_max_uni_streams() -> u64 {
    100
}

fn default_max_data() -> u64 {
    10 * 1024 * 1024 // 10 MB
}

fn default_max_stream_data_bidi() -> u64 {
    1024 * 1024 // 1 MB
}

fn default_max_stream_data_uni() -> u64 {
    1024 * 1024 // 1 MB
}

fn default_zero_rtt() -> bool {
    true
}

fn default_max_0rtt_data() -> u64 {
    16 * 1024 // 16 KB
}

fn default_keep_alive() -> Option<Duration> {
    Some(Duration::from_secs(15))
}

fn default_max_udp_payload() -> u16 {
    1350
}

fn default_connection_id_limit() -> u64 {
    8
}

fn default_ack_delay_exponent() -> u8 {
    3
}

fn default_max_ack_delay() -> Duration {
    Duration::from_millis(25)
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            bind_address: default_bind_address(),
            cert_path: None,
            key_path: None,
            alpn_protocols: default_alpn(),
            idle_timeout: default_idle_timeout(),
            max_bidirectional_streams: default_max_bidi_streams(),
            max_unidirectional_streams: default_max_uni_streams(),
            max_data: default_max_data(),
            max_stream_data_bidi_local: default_max_stream_data_bidi(),
            max_stream_data_bidi_remote: default_max_stream_data_bidi(),
            max_stream_data_uni: default_max_stream_data_uni(),
            enable_0rtt: default_zero_rtt(),
            max_0rtt_data: default_max_0rtt_data(),
            migration: MigrationConfig::default(),
            congestion_control: CongestionControl::default(),
            keep_alive_interval: default_keep_alive(),
            max_udp_payload_size: default_max_udp_payload(),
            active_connection_id_limit: default_connection_id_limit(),
            disable_active_migration: false,
            ack_delay_exponent: default_ack_delay_exponent(),
            max_ack_delay: default_max_ack_delay(),
        }
    }
}

/// Connection migration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationConfig {
    /// Allow connection migration
    #[serde(default = "default_allow_migration")]
    pub allow_migration: bool,

    /// Path validation timeout
    #[serde(default = "default_path_validation_timeout", with = "humantime_serde")]
    pub path_validation_timeout: Duration,

    /// Maximum path challenges
    #[serde(default = "default_max_path_challenges")]
    pub max_path_challenges: u32,
}

fn default_allow_migration() -> bool {
    true
}

fn default_path_validation_timeout() -> Duration {
    Duration::from_secs(3)
}

fn default_max_path_challenges() -> u32 {
    3
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            allow_migration: default_allow_migration(),
            path_validation_timeout: default_path_validation_timeout(),
            max_path_challenges: default_max_path_challenges(),
        }
    }
}

/// Congestion control algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CongestionControl {
    /// New Reno (RFC 9002)
    #[default]
    NewReno,

    /// CUBIC
    Cubic,

    /// BBR (Bottleneck Bandwidth and RTT)
    Bbr,

    /// BBRv2
    Bbr2,
}

impl CongestionControl {
    /// Get algorithm name
    pub fn name(&self) -> &'static str {
        match self {
            Self::NewReno => "new_reno",
            Self::Cubic => "cubic",
            Self::Bbr => "bbr",
            Self::Bbr2 => "bbr2",
        }
    }
}

/// QUIC version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QuicVersion(u32);

impl QuicVersion {
    /// QUIC v1 (RFC 9000)
    pub const V1: Self = Self(0x00000001);

    /// QUIC v2 (RFC 9369)
    pub const V2: Self = Self(0x6b3343cf);

    /// Version negotiation
    pub const NEGOTIATION: Self = Self(0x00000000);

    /// Draft-29 (for testing)
    pub const DRAFT_29: Self = Self(0xff00001d);

    /// Create from raw value
    pub fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// Get raw value
    pub fn as_u32(&self) -> u32 {
        self.0
    }

    /// Check if this is a supported version
    pub fn is_supported(&self) -> bool {
        matches!(*self, Self::V1 | Self::V2 | Self::DRAFT_29)
    }

    /// Get list of supported versions
    pub fn supported_versions() -> Vec<Self> {
        vec![Self::V1, Self::V2]
    }
}

impl Default for QuicVersion {
    fn default() -> Self {
        Self::V1
    }
}

impl std::fmt::Display for QuicVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::V1 => write!(f, "QUICv1"),
            Self::V2 => write!(f, "QUICv2"),
            Self::NEGOTIATION => write!(f, "Negotiation"),
            Self::DRAFT_29 => write!(f, "Draft-29"),
            Self(v) => write!(f, "0x{:08x}", v),
        }
    }
}

/// Transport parameters (RFC 9000 Section 18.2)
#[derive(Debug, Clone, Default)]
pub struct TransportParameters {
    /// Original destination connection ID
    pub original_destination_connection_id: Option<Vec<u8>>,

    /// Maximum idle timeout (milliseconds)
    pub max_idle_timeout: u64,

    /// Stateless reset token
    pub stateless_reset_token: Option<[u8; 16]>,

    /// Max UDP payload size
    pub max_udp_payload_size: u64,

    /// Initial max data
    pub initial_max_data: u64,

    /// Initial max stream data (bidi local)
    pub initial_max_stream_data_bidi_local: u64,

    /// Initial max stream data (bidi remote)
    pub initial_max_stream_data_bidi_remote: u64,

    /// Initial max stream data (uni)
    pub initial_max_stream_data_uni: u64,

    /// Initial max streams (bidi)
    pub initial_max_streams_bidi: u64,

    /// Initial max streams (uni)
    pub initial_max_streams_uni: u64,

    /// ACK delay exponent
    pub ack_delay_exponent: u64,

    /// Max ACK delay
    pub max_ack_delay: u64,

    /// Disable active migration
    pub disable_active_migration: bool,

    /// Preferred address
    pub preferred_address: Option<PreferredAddress>,

    /// Active connection ID limit
    pub active_connection_id_limit: u64,

    /// Initial source connection ID
    pub initial_source_connection_id: Option<Vec<u8>>,

    /// Retry source connection ID
    pub retry_source_connection_id: Option<Vec<u8>>,
}

impl TransportParameters {
    /// Create from config
    pub fn from_config(config: &QuicConfig) -> Self {
        Self {
            max_idle_timeout: config.idle_timeout.as_millis() as u64,
            max_udp_payload_size: config.max_udp_payload_size as u64,
            initial_max_data: config.max_data,
            initial_max_stream_data_bidi_local: config.max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: config.max_stream_data_bidi_remote,
            initial_max_stream_data_uni: config.max_stream_data_uni,
            initial_max_streams_bidi: config.max_bidirectional_streams,
            initial_max_streams_uni: config.max_unidirectional_streams,
            ack_delay_exponent: config.ack_delay_exponent as u64,
            max_ack_delay: config.max_ack_delay.as_millis() as u64,
            disable_active_migration: config.disable_active_migration,
            active_connection_id_limit: config.active_connection_id_limit,
            ..Default::default()
        }
    }
}

/// Preferred address for migration
#[derive(Debug, Clone)]
pub struct PreferredAddress {
    /// IPv4 address
    pub ipv4_address: Option<SocketAddr>,

    /// IPv6 address
    pub ipv6_address: Option<SocketAddr>,

    /// Connection ID
    pub connection_id: Vec<u8>,

    /// Stateless reset token
    pub stateless_reset_token: [u8; 16],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = QuicConfig::default();
        assert!(config.enabled);
        assert!(config.enable_0rtt);
        assert_eq!(config.max_bidirectional_streams, 100);
        assert_eq!(config.congestion_control, CongestionControl::NewReno);
    }

    #[test]
    fn test_quic_version() {
        assert!(QuicVersion::V1.is_supported());
        assert!(QuicVersion::V2.is_supported());
        assert!(!QuicVersion::from_u32(0x12345678).is_supported());

        assert_eq!(QuicVersion::V1.to_string(), "QUICv1");
    }

    #[test]
    fn test_congestion_control() {
        assert_eq!(CongestionControl::NewReno.name(), "new_reno");
        assert_eq!(CongestionControl::Bbr.name(), "bbr");
    }

    #[test]
    fn test_transport_parameters() {
        let config = QuicConfig::default();
        let params = TransportParameters::from_config(&config);

        assert_eq!(params.initial_max_streams_bidi, 100);
        assert_eq!(params.max_udp_payload_size, 1350);
    }

    #[test]
    fn test_migration_config() {
        let config = MigrationConfig::default();
        assert!(config.allow_migration);
    }
}
