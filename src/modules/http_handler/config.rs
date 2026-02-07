//! Configuration types for the HTTP handler module.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

/// HTTP handler configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpHandlerConfig {
    /// Whether the handler is enabled.
    pub enabled: bool,

    /// Listeners for HTTP connections.
    pub listeners: Vec<ListenerConfig>,

    /// Routes for request handling.
    pub routes: Vec<RouteConfig>,

    /// Default backend if no route matches.
    pub default_backend: Option<BackendConfig>,

    /// Request limits.
    pub limits: LimitsConfig,

    /// Timeout configuration.
    pub timeouts: TimeoutConfig,

    /// HTTP/2 specific settings.
    pub http2: Http2Config,

    /// Keep-alive settings.
    pub keep_alive: KeepAliveConfig,

    /// Header manipulation rules.
    pub headers: HeaderConfig,

    /// Middleware configuration.
    pub middleware: Vec<MiddlewareConfig>,

    /// Access log settings.
    pub access_log: AccessLogConfig,
}

impl Default for HttpHandlerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listeners: vec![ListenerConfig::default()],
            routes: Vec::new(),
            default_backend: None,
            limits: LimitsConfig::default(),
            timeouts: TimeoutConfig::default(),
            http2: Http2Config::default(),
            keep_alive: KeepAliveConfig::default(),
            headers: HeaderConfig::default(),
            middleware: Vec::new(),
            access_log: AccessLogConfig::default(),
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

    /// Whether TLS is enabled for this listener.
    pub tls: bool,

    /// Whether HTTP/2 is enabled.
    pub http2_enabled: bool,

    /// Name for logging purposes.
    pub name: Option<String>,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0".to_string(),
            port: 8080,
            tls: false,
            http2_enabled: true,
            name: None,
        }
    }
}

impl ListenerConfig {
    /// Get the socket address for this listener.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        format!("{}:{}", self.address, self.port).parse().ok()
    }
}

/// Route configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Route name for identification.
    pub name: String,

    /// Path pattern to match (supports wildcards).
    #[serde(default)]
    pub path: String,

    /// HTTP methods to match (empty = all methods).
    #[serde(default)]
    pub methods: Vec<String>,

    /// Host header pattern to match.
    #[serde(default)]
    pub host: Option<String>,

    /// Headers that must be present.
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Backend to forward requests to.
    pub backend: BackendConfig,

    /// Route priority (higher = checked first).
    #[serde(default)]
    pub priority: i32,

    /// Whether to strip the matched path prefix.
    #[serde(default)]
    pub strip_prefix: bool,

    /// Path rewrite pattern.
    #[serde(default)]
    pub rewrite: Option<String>,

    /// Route-specific middleware.
    #[serde(default)]
    pub middleware: Vec<String>,
}

/// Backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Backend address.
    pub address: String,

    /// Backend port.
    pub port: u16,

    /// Whether to use TLS to connect to backend.
    #[serde(default)]
    pub tls: bool,

    /// Whether to verify backend TLS certificate.
    #[serde(default = "default_true")]
    pub verify_tls: bool,

    /// Connection timeout.
    #[serde(default, with = "humantime_serde")]
    pub connect_timeout: Option<Duration>,

    /// Request timeout.
    #[serde(default, with = "humantime_serde")]
    pub request_timeout: Option<Duration>,
}

fn default_true() -> bool {
    true
}

impl BackendConfig {
    /// Get the socket address for this backend.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        format!("{}:{}", self.address, self.port).parse().ok()
    }
}

/// Request limits configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    /// Maximum request body size in bytes.
    pub max_body_size: usize,

    /// Maximum header size in bytes.
    pub max_header_size: usize,

    /// Maximum number of headers.
    pub max_headers: usize,

    /// Maximum URI length.
    pub max_uri_length: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_body_size: 10 * 1024 * 1024, // 10MB
            max_header_size: 16 * 1024,      // 16KB
            max_headers: 100,
            max_uri_length: 8192,
        }
    }
}

/// Timeout configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TimeoutConfig {
    /// Read timeout for client connections.
    #[serde(with = "humantime_serde")]
    pub read_timeout: Duration,

    /// Write timeout for client connections.
    #[serde(with = "humantime_serde")]
    pub write_timeout: Duration,

    /// Timeout for connecting to backend.
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,

    /// Timeout for receiving response from backend.
    #[serde(with = "humantime_serde")]
    pub response_timeout: Duration,

    /// Idle timeout for keep-alive connections.
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            response_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(60),
        }
    }
}

/// HTTP/2 configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Http2Config {
    /// Whether HTTP/2 is enabled.
    pub enabled: bool,

    /// Initial window size.
    pub initial_window_size: u32,

    /// Maximum frame size.
    pub max_frame_size: u32,

    /// Maximum concurrent streams.
    pub max_concurrent_streams: u32,

    /// Header table size.
    pub header_table_size: u32,

    /// Enable push promises.
    pub enable_push: bool,
}

impl Default for Http2Config {
    fn default() -> Self {
        Self {
            enabled: true,
            initial_window_size: 65_535,
            max_frame_size: 16_384,
            max_concurrent_streams: 100,
            header_table_size: 4096,
            enable_push: false,
        }
    }
}

/// Keep-alive configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct KeepAliveConfig {
    /// Whether keep-alive is enabled.
    pub enabled: bool,

    /// Maximum requests per connection.
    pub max_requests: u32,

    /// Timeout for keep-alive connections.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_requests: 1000,
            timeout: Duration::from_secs(60),
        }
    }
}

/// Header manipulation configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HeaderConfig {
    /// Headers to add to requests.
    pub request_add: HashMap<String, String>,

    /// Headers to remove from requests.
    pub request_remove: Vec<String>,

    /// Headers to add to responses.
    pub response_add: HashMap<String, String>,

    /// Headers to remove from responses.
    pub response_remove: Vec<String>,

    /// Whether to add X-Forwarded-* headers.
    pub add_forwarded_headers: bool,

    /// Whether to add X-Request-ID header.
    pub add_request_id: bool,
}

/// Middleware configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiddlewareConfig {
    /// Middleware name.
    pub name: String,

    /// Middleware type.
    #[serde(rename = "type")]
    pub middleware_type: MiddlewareType,

    /// Middleware-specific configuration.
    #[serde(default)]
    pub config: HashMap<String, toml::Value>,
}

/// Types of middleware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MiddlewareType {
    /// Request logging.
    Logger,
    /// Request/response compression.
    Compression,
    /// CORS handling.
    Cors,
    /// Authentication.
    Auth,
    /// Rate limiting.
    RateLimit,
    /// Request ID generation.
    RequestId,
    /// Request timing.
    Timing,
    /// Custom middleware.
    Custom,
}

/// Access log configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessLogConfig {
    /// Whether access logging is enabled.
    pub enabled: bool,

    /// Log format (combined, common, json).
    pub format: String,

    /// Fields to include in log.
    pub fields: Vec<String>,
}

impl Default for AccessLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            format: "combined".to_string(),
            fields: vec![
                "timestamp".to_string(),
                "method".to_string(),
                "path".to_string(),
                "status".to_string(),
                "duration".to_string(),
                "bytes".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = HttpHandlerConfig::default();
        assert!(config.enabled);
        assert_eq!(config.listeners.len(), 1);
        assert_eq!(config.listeners[0].port, 8080);
    }

    #[test]
    fn test_listener_socket_addr() {
        let listener = ListenerConfig {
            address: "127.0.0.1".to_string(),
            port: 8080,
            ..Default::default()
        };
        let addr = listener.socket_addr().unwrap();
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_deserialize_config() {
        let toml = r#"
            enabled = true
            
            [[listeners]]
            address = "0.0.0.0"
            port = 80
            tls = false
            
            [[listeners]]
            address = "0.0.0.0"
            port = 443
            tls = true
            
            [[routes]]
            name = "api"
            path = "/api/*"
            methods = ["GET", "POST"]
            
            [routes.backend]
            address = "127.0.0.1"
            port = 3000
            
            [limits]
            max_body_size = 5242880
            
            [timeouts]
            read_timeout = "30s"
            connect_timeout = "5s"
        "#;

        let config: HttpHandlerConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.listeners.len(), 2);
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].name, "api");
        assert_eq!(config.limits.max_body_size, 5242880);
    }

    #[test]
    fn test_http2_config_defaults() {
        let config = Http2Config::default();
        assert!(config.enabled);
        assert_eq!(config.max_concurrent_streams, 100);
        assert!(!config.enable_push);
    }

    #[test]
    fn test_keep_alive_config() {
        let config = KeepAliveConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_requests, 1000);
    }
}
