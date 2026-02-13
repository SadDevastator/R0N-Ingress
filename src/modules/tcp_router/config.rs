//! TCP Router configuration types.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Configuration for the TCP router module.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TcpRouterConfig {
    /// TCP listeners to bind.
    pub listeners: Vec<ListenerConfig>,

    /// Routes for matching and forwarding traffic.
    pub routes: Vec<RouteConfig>,

    /// Connection pool settings.
    pub pool: PoolSettings,

    /// Health check settings.
    pub health_check: HealthCheckSettings,

    /// Maximum concurrent connections (0 = unlimited).
    pub max_connections: usize,

    /// Connection timeout in seconds.
    pub connect_timeout_secs: u64,

    /// Read/write timeout in seconds (0 = no timeout).
    pub io_timeout_secs: u64,

    /// Buffer size for data transfer.
    pub buffer_size: usize,
}

impl Default for TcpRouterConfig {
    fn default() -> Self {
        Self {
            listeners: Vec::new(),
            routes: Vec::new(),
            pool: PoolSettings::default(),
            health_check: HealthCheckSettings::default(),
            max_connections: 10000,
            connect_timeout_secs: 10,
            io_timeout_secs: 0,
            buffer_size: 16384,
        }
    }
}

impl TcpRouterConfig {
    /// Get the connection timeout as a Duration.
    #[must_use]
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_secs)
    }

    /// Get the IO timeout as an `Option<Duration>`.
    #[must_use]
    pub fn io_timeout(&self) -> Option<Duration> {
        if self.io_timeout_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(self.io_timeout_secs))
        }
    }
}

/// Configuration for a TCP listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    /// Bind address.
    #[serde(default = "default_bind_address")]
    pub address: IpAddr,

    /// Listen port.
    pub port: u16,

    /// Optional name for identification.
    #[serde(default)]
    pub name: Option<String>,

    /// Enable TCP keepalive.
    #[serde(default = "default_true")]
    pub tcp_keepalive: bool,

    /// TCP nodelay (disable Nagle's algorithm).
    #[serde(default = "default_true")]
    pub tcp_nodelay: bool,
}

fn default_bind_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
}

fn default_true() -> bool {
    true
}

impl ListenerConfig {
    /// Create a new listener config.
    #[inline]
    #[must_use]
    pub fn new(port: u16) -> Self {
        Self {
            address: default_bind_address(),
            port,
            name: None,
            tcp_keepalive: true,
            tcp_nodelay: true,
        }
    }

    /// Set the bind address.
    #[inline]
    #[must_use]
    pub fn with_address(mut self, address: IpAddr) -> Self {
        self.address = address;
        self
    }

    /// Set the listener name.
    #[inline]
    #[must_use]
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Get the socket address.
    #[inline]
    #[must_use]
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}

/// Configuration for a route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Route name for identification.
    pub name: String,

    /// Match criteria for this route.
    #[serde(rename = "match")]
    pub match_criteria: MatchCriteria,

    /// Backend servers for this route.
    pub backends: Vec<BackendConfig>,

    /// Load balancing strategy.
    #[serde(default)]
    pub load_balance: LoadBalanceStrategy,
}

impl RouteConfig {
    /// Create a new route config.
    #[inline]
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            match_criteria: MatchCriteria::default(),
            backends: Vec::new(),
            load_balance: LoadBalanceStrategy::default(),
        }
    }

    /// Set match criteria.
    #[inline]
    #[must_use]
    pub fn with_match(mut self, criteria: MatchCriteria) -> Self {
        self.match_criteria = criteria;
        self
    }

    /// Add a backend.
    #[inline]
    #[must_use]
    pub fn with_backend(mut self, backend: BackendConfig) -> Self {
        self.backends.push(backend);
        self
    }
}

/// Match criteria for routing.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MatchCriteria {
    /// Match by destination port.
    #[serde(default)]
    pub port: Option<u16>,

    /// Match by destination address.
    #[serde(default)]
    pub address: Option<String>,

    /// Match by source IP prefix (CIDR notation).
    #[serde(default)]
    pub source_cidr: Option<String>,

    /// Match all traffic (catch-all).
    #[serde(default)]
    pub catch_all: bool,
}

impl MatchCriteria {
    /// Create a port-based match.
    #[inline]
    #[must_use]
    pub fn port(port: u16) -> Self {
        Self {
            port: Some(port),
            address: None,
            source_cidr: None,
            catch_all: false,
        }
    }

    /// Create a catch-all match.
    #[inline]
    #[must_use]
    pub fn catch_all() -> Self {
        Self {
            port: None,
            address: None,
            source_cidr: None,
            catch_all: true,
        }
    }
}

/// Backend server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Backend address.
    pub address: IpAddr,

    /// Backend port.
    pub port: u16,

    /// Weight for load balancing (higher = more traffic).
    #[serde(default = "default_weight")]
    pub weight: u32,

    /// Maximum connections to this backend.
    #[serde(default)]
    pub max_connections: Option<usize>,
}

fn default_weight() -> u32 {
    1
}

impl BackendConfig {
    /// Create a new backend config.
    #[inline]
    #[must_use]
    pub fn new(address: IpAddr, port: u16) -> Self {
        Self {
            address,
            port,
            weight: 1,
            max_connections: None,
        }
    }

    /// Set the weight.
    #[inline]
    #[must_use]
    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    /// Get the socket address.
    #[inline]
    #[must_use]
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}

/// Load balancing strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    /// Round-robin selection.
    #[default]
    RoundRobin,

    /// Least connections.
    LeastConnections,

    /// Random selection.
    Random,

    /// IP hash (sticky sessions).
    IpHash,
}

/// Connection pool settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PoolSettings {
    /// Enable connection pooling.
    pub enabled: bool,

    /// Minimum idle connections per backend.
    pub min_idle: usize,

    /// Maximum connections per backend.
    pub max_size: usize,

    /// Idle timeout in seconds.
    pub idle_timeout_secs: u64,
}

impl Default for PoolSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            min_idle: 0,
            max_size: 100,
            idle_timeout_secs: 60,
        }
    }
}

impl PoolSettings {
    /// Get idle timeout as Duration.
    #[must_use]
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }
}

/// Health check settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HealthCheckSettings {
    /// Enable health checks.
    pub enabled: bool,

    /// Interval between health checks in seconds.
    pub interval_secs: u64,

    /// Timeout for health check connections in seconds.
    pub timeout_secs: u64,

    /// Number of failures before marking unhealthy.
    pub unhealthy_threshold: u32,

    /// Number of successes before marking healthy.
    pub healthy_threshold: u32,
}

impl Default for HealthCheckSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 10,
            timeout_secs: 5,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        }
    }
}

impl HealthCheckSettings {
    /// Get interval as Duration.
    #[must_use]
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval_secs)
    }

    /// Get timeout as Duration.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TcpRouterConfig::default();
        assert!(config.listeners.is_empty());
        assert!(config.routes.is_empty());
        assert_eq!(config.max_connections, 10000);
        assert_eq!(config.buffer_size, 16384);
    }

    #[test]
    fn test_listener_config() {
        let listener = ListenerConfig::new(8080)
            .with_address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .with_name("http");

        assert_eq!(listener.port, 8080);
        assert_eq!(listener.address, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(listener.name, Some("http".to_string()));
    }

    #[test]
    fn test_route_config() {
        let route = RouteConfig::new("web")
            .with_match(MatchCriteria::port(8080))
            .with_backend(BackendConfig::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                3000,
            ));

        assert_eq!(route.name, "web");
        assert_eq!(route.match_criteria.port, Some(8080));
        assert_eq!(route.backends.len(), 1);
    }

    #[test]
    fn test_backend_socket_addr() {
        let backend = BackendConfig::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        let addr = backend.socket_addr();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_deserialize_config() {
        let toml_str = r#"
            max_connections = 5000
            buffer_size = 8192
            
            [[listeners]]
            address = "0.0.0.0"
            port = 8080
            name = "http"
            
            [[routes]]
            name = "web"
            load_balance = "round_robin"
            
            [routes.match]
            port = 8080
            
            [[routes.backends]]
            address = "127.0.0.1"
            port = 3000
            weight = 1
        "#;

        let config: TcpRouterConfig = toml::from_str(toml_str).expect("Failed to parse");
        assert_eq!(config.max_connections, 5000);
        assert_eq!(config.listeners.len(), 1);
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].backends.len(), 1);
    }
}
