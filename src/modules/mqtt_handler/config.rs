//! Configuration types for the MQTT handler module.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;

/// MQTT handler configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MqttHandlerConfig {
    /// Whether the handler is enabled.
    pub enabled: bool,

    /// Listeners for MQTT connections.
    pub listeners: Vec<ListenerConfig>,

    /// Topic routing rules.
    pub routes: Vec<RouteConfig>,

    /// Default backend if no route matches.
    pub default_backend: Option<BackendConfig>,

    /// Protocol settings.
    pub protocol: ProtocolConfig,

    /// Session settings.
    pub session: SessionConfig,

    /// Security settings.
    pub security: SecurityConfig,

    /// Limits.
    pub limits: LimitsConfig,
}

impl Default for MqttHandlerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listeners: vec![ListenerConfig::default()],
            routes: Vec::new(),
            default_backend: None,
            protocol: ProtocolConfig::default(),
            session: SessionConfig::default(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
        }
    }
}

/// Listener configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ListenerConfig {
    /// Address to bind to.
    pub address: String,

    /// Port to listen on.
    pub port: u16,

    /// Whether TLS is enabled.
    pub tls: bool,

    /// Whether WebSocket transport is enabled.
    pub websocket: bool,

    /// Name for logging.
    pub name: Option<String>,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0".to_string(),
            port: 1883,
            tls: false,
            websocket: false,
            name: None,
        }
    }
}

impl ListenerConfig {
    /// Get the socket address.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        format!("{}:{}", self.address, self.port).parse().ok()
    }
}

/// Topic routing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Route name.
    pub name: String,

    /// Topic filter pattern (supports +, #).
    pub topic_filter: String,

    /// Backend to route to.
    pub backend: BackendConfig,

    /// Priority (higher = checked first).
    #[serde(default)]
    pub priority: i32,

    /// Whether to transform topic before forwarding.
    #[serde(default)]
    pub topic_transform: Option<String>,
}

/// Backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Backend address.
    pub address: String,

    /// Backend port.
    pub port: u16,

    /// Whether to use TLS.
    #[serde(default)]
    pub tls: bool,

    /// Client ID prefix for backend connection.
    #[serde(default)]
    pub client_id_prefix: Option<String>,

    /// Connection timeout.
    #[serde(default, with = "humantime_serde")]
    pub connect_timeout: Option<Duration>,
}

impl BackendConfig {
    /// Get the socket address.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        format!("{}:{}", self.address, self.port).parse().ok()
    }
}

/// Protocol configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtocolConfig {
    /// Supported protocol versions.
    pub versions: Vec<ProtocolVersion>,

    /// Keep-alive interval in seconds (0 = disabled).
    pub keep_alive: u16,

    /// Maximum QoS level supported.
    pub max_qos: u8,

    /// Whether retained messages are supported.
    pub retain_available: bool,

    /// Whether wildcard subscriptions are allowed.
    pub wildcard_subscription: bool,

    /// Whether subscription identifiers are supported (MQTT 5.0).
    pub subscription_identifiers: bool,

    /// Whether shared subscriptions are supported (MQTT 5.0).
    pub shared_subscriptions: bool,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            versions: vec![ProtocolVersion::V311, ProtocolVersion::V5],
            keep_alive: 60,
            max_qos: 2,
            retain_available: true,
            wildcard_subscription: true,
            subscription_identifiers: true,
            shared_subscriptions: true,
        }
    }
}

/// MQTT protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolVersion {
    /// MQTT 3.1
    #[serde(rename = "3.1")]
    V31,
    /// MQTT 3.1.1
    #[serde(rename = "3.1.1")]
    V311,
    /// MQTT 5.0
    #[serde(rename = "5.0")]
    V5,
}

impl ProtocolVersion {
    /// Get the protocol level byte.
    #[must_use]
    pub fn level(&self) -> u8 {
        match self {
            Self::V31 => 3,
            Self::V311 => 4,
            Self::V5 => 5,
        }
    }

    /// Create from protocol level byte.
    pub fn from_level(level: u8) -> Option<Self> {
        match level {
            3 => Some(Self::V31),
            4 => Some(Self::V311),
            5 => Some(Self::V5),
            _ => None,
        }
    }
}

/// Session configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionConfig {
    /// Session expiry interval in seconds (0 = expire on disconnect).
    pub expiry_interval: u32,

    /// Maximum sessions per client ID.
    pub max_sessions: usize,

    /// Receive maximum (max in-flight QoS 1/2 messages).
    pub receive_maximum: u16,

    /// Maximum stored messages per session.
    pub max_queued_messages: usize,

    /// Message expiry interval in seconds.
    pub message_expiry: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            expiry_interval: 0,
            max_sessions: 10_000,
            receive_maximum: 65535,
            max_queued_messages: 1000,
            message_expiry: 3600,
        }
    }
}

/// Security configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Whether authentication is required.
    pub require_auth: bool,

    /// Whether anonymous connections are allowed.
    pub allow_anonymous: bool,

    /// Authentication method (none, password, token).
    pub auth_method: AuthMethod,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            require_auth: false,
            allow_anonymous: true,
            auth_method: AuthMethod::None,
        }
    }
}

/// Authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    /// No authentication.
    None,
    /// Username/password authentication.
    Password,
    /// Token-based authentication.
    Token,
}

/// Limits configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    /// Maximum packet size.
    pub max_packet_size: usize,

    /// Maximum client ID length.
    pub max_client_id_len: usize,

    /// Maximum topic length.
    pub max_topic_len: usize,

    /// Maximum subscriptions per client.
    pub max_subscriptions: usize,

    /// Maximum topic aliases (MQTT 5.0).
    pub max_topic_alias: u16,

    /// Connect timeout.
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,

    /// Idle timeout.
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_packet_size: 256 * 1024, // 256KB
            max_client_id_len: 256,
            max_topic_len: 65535,
            max_subscriptions: 100,
            max_topic_alias: 65535,
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MqttHandlerConfig::default();
        assert!(config.enabled);
        assert_eq!(config.listeners.len(), 1);
        assert_eq!(config.listeners[0].port, 1883);
    }

    #[test]
    fn test_listener_socket_addr() {
        let listener = ListenerConfig {
            address: "127.0.0.1".to_string(),
            port: 1883,
            ..Default::default()
        };
        let addr = listener.socket_addr().unwrap();
        assert_eq!(addr.port(), 1883);
    }

    #[test]
    fn test_protocol_version() {
        assert_eq!(ProtocolVersion::V311.level(), 4);
        assert_eq!(ProtocolVersion::V5.level(), 5);
        assert_eq!(ProtocolVersion::from_level(4), Some(ProtocolVersion::V311));
        assert_eq!(ProtocolVersion::from_level(5), Some(ProtocolVersion::V5));
        assert_eq!(ProtocolVersion::from_level(99), None);
    }

    #[test]
    fn test_deserialize_config() {
        let toml = r#"
            enabled = true
            
            [[listeners]]
            address = "0.0.0.0"
            port = 1883
            
            [[listeners]]
            address = "0.0.0.0"
            port = 8883
            tls = true
            
            [[routes]]
            name = "sensors"
            topic_filter = "sensors/#"
            
            [routes.backend]
            address = "127.0.0.1"
            port = 1884
            
            [protocol]
            keep_alive = 120
            max_qos = 2
            
            [limits]
            max_packet_size = 524288
        "#;

        let config: MqttHandlerConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.listeners.len(), 2);
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.protocol.keep_alive, 120);
        assert_eq!(config.limits.max_packet_size, 524288);
    }

    #[test]
    fn test_session_config() {
        let config = SessionConfig::default();
        assert_eq!(config.receive_maximum, 65535);
        assert_eq!(config.max_queued_messages, 1000);
    }
}
