//! WebSocket handler configuration.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;

/// WebSocket handler configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebSocketHandlerConfig {
    /// Whether the handler is enabled.
    pub enabled: bool,

    /// Listener configurations.
    pub listeners: Vec<ListenerConfig>,

    /// Route configurations.
    pub routes: Vec<RouteConfig>,

    /// Default backend for unmatched routes.
    pub default_backend: Option<BackendConfig>,

    /// Protocol settings.
    pub protocol: ProtocolConfig,

    /// Security settings.
    pub security: SecurityConfig,

    /// Resource limits.
    pub limits: LimitsConfig,
}

impl Default for WebSocketHandlerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listeners: vec![ListenerConfig::default()],
            routes: Vec::new(),
            default_backend: None,
            protocol: ProtocolConfig::default(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
        }
    }
}

/// Listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ListenerConfig {
    /// Listen address.
    pub address: String,

    /// Listen port.
    pub port: u16,

    /// Path prefix for WebSocket connections (e.g., "/ws").
    #[serde(default)]
    pub path: Option<String>,

    /// Whether TLS is enabled for this listener.
    #[serde(default)]
    pub tls: bool,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0".to_string(),
            port: 8080,
            path: None,
            tls: false,
        }
    }
}

impl ListenerConfig {
    /// Get the socket address.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        format!("{}:{}", self.address, self.port).parse().ok()
    }
}

/// Route configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Route name for identification.
    pub name: String,

    /// Path pattern to match.
    pub path: String,

    /// Backend to forward connections to.
    pub backend: BackendConfig,

    /// Subprotocols supported by this route.
    #[serde(default)]
    pub subprotocols: Vec<String>,

    /// Route priority (higher = checked first).
    #[serde(default)]
    pub priority: i32,
}

/// Backend server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Backend address.
    pub address: String,

    /// Backend port.
    pub port: u16,

    /// Whether to use TLS for backend connection.
    #[serde(default)]
    pub tls: bool,

    /// Connection timeout.
    #[serde(default = "default_connect_timeout", with = "humantime_serde")]
    pub connect_timeout: Duration,
}

fn default_connect_timeout() -> Duration {
    Duration::from_secs(10)
}

impl BackendConfig {
    /// Get the socket address.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        format!("{}:{}", self.address, self.port).parse().ok()
    }
}

/// Protocol settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtocolConfig {
    /// Supported WebSocket versions (13 is RFC 6455).
    pub versions: Vec<u8>,

    /// Ping interval for keep-alive.
    #[serde(with = "humantime_serde")]
    pub ping_interval: Duration,

    /// Pong timeout after sending ping.
    #[serde(with = "humantime_serde")]
    pub pong_timeout: Duration,

    /// Whether to automatically respond to pings.
    pub auto_pong: bool,

    /// Whether to forward pings to backend.
    pub forward_pings: bool,

    /// Enable per-message compression.
    pub compression: bool,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            versions: vec![13], // RFC 6455
            ping_interval: Duration::from_secs(30),
            pong_timeout: Duration::from_secs(10),
            auto_pong: true,
            forward_pings: false,
            compression: false,
        }
    }
}

/// Security settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Allowed origins (empty = all allowed).
    pub allowed_origins: Vec<String>,

    /// Required headers.
    pub required_headers: Vec<String>,

    /// Whether to validate Sec-WebSocket-Key.
    pub validate_key: bool,

    /// Maximum handshake request size.
    pub max_handshake_size: usize,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            required_headers: Vec::new(),
            validate_key: true,
            max_handshake_size: 8192,
        }
    }
}

/// Resource limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    /// Maximum frame payload size.
    pub max_frame_size: usize,

    /// Maximum message size (across multiple frames).
    pub max_message_size: usize,

    /// Maximum number of concurrent connections.
    pub max_connections: usize,

    /// Maximum connections per IP.
    pub max_connections_per_ip: usize,

    /// Read buffer size.
    pub read_buffer_size: usize,

    /// Write buffer size.
    pub write_buffer_size: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_frame_size: 16 * 1024 * 1024,   // 16 MB
            max_message_size: 64 * 1024 * 1024, // 64 MB
            max_connections: 10000,
            max_connections_per_ip: 100,
            read_buffer_size: 64 * 1024,  // 64 KB
            write_buffer_size: 64 * 1024, // 64 KB
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = WebSocketHandlerConfig::default();
        assert!(config.enabled);
        assert_eq!(config.listeners.len(), 1);
        assert!(config.routes.is_empty());
        assert!(config.default_backend.is_none());
    }

    #[test]
    fn test_listener_socket_addr() {
        let listener = ListenerConfig {
            address: "127.0.0.1".to_string(),
            port: 8080,
            path: Some("/ws".to_string()),
            tls: false,
        };
        let addr = listener.socket_addr().unwrap();
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_backend_socket_addr() {
        let backend = BackendConfig {
            address: "localhost".to_string(),
            port: 9000,
            tls: false,
            connect_timeout: Duration::from_secs(5),
        };
        // localhost may not parse directly
        let backend2 = BackendConfig {
            address: "192.168.1.1".to_string(),
            port: 9000,
            tls: false,
            connect_timeout: Duration::from_secs(5),
        };
        let addr = backend2.socket_addr().unwrap();
        assert_eq!(addr.port(), 9000);
        assert!(backend.socket_addr().is_none()); // localhost isn't a valid IP
    }

    #[test]
    fn test_protocol_config_defaults() {
        let config = ProtocolConfig::default();
        assert_eq!(config.versions, vec![13]);
        assert!(config.auto_pong);
        assert!(!config.forward_pings);
        assert!(!config.compression);
    }

    #[test]
    fn test_security_config_defaults() {
        let config = SecurityConfig::default();
        assert!(config.allowed_origins.is_empty());
        assert!(config.validate_key);
        assert_eq!(config.max_handshake_size, 8192);
    }

    #[test]
    fn test_limits_config_defaults() {
        let config = LimitsConfig::default();
        assert_eq!(config.max_frame_size, 16 * 1024 * 1024);
        assert_eq!(config.max_message_size, 64 * 1024 * 1024);
        assert_eq!(config.max_connections, 10000);
    }

    #[test]
    fn test_deserialize_config() {
        let toml = r#"
            enabled = true
            
            [[listeners]]
            address = "0.0.0.0"
            port = 8080
            path = "/ws"
            
            [[routes]]
            name = "chat"
            path = "/ws/chat"
            subprotocols = ["graphql-ws"]
            priority = 10
            
            [routes.backend]
            address = "127.0.0.1"
            port = 9000
            
            [protocol]
            ping_interval = "30s"
            pong_timeout = "10s"
            auto_pong = true
            
            [security]
            allowed_origins = ["https://example.com"]
            validate_key = true
            
            [limits]
            max_frame_size = 1048576
            max_connections = 5000
        "#;

        let config: WebSocketHandlerConfig = toml::from_str(toml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.listeners.len(), 1);
        assert_eq!(config.listeners[0].path, Some("/ws".to_string()));
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].name, "chat");
        assert_eq!(config.routes[0].subprotocols, vec!["graphql-ws"]);
        assert_eq!(config.security.allowed_origins, vec!["https://example.com"]);
        assert_eq!(config.limits.max_connections, 5000);
    }
}
