//! UDP Router configuration types.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Configuration for the UDP router module.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UdpRouterConfig {
    /// UDP listeners to bind.
    pub listeners: Vec<ListenerConfig>,

    /// Routes for matching and forwarding traffic.
    pub routes: Vec<RouteConfig>,

    /// Session tracking settings.
    pub session: SessionSettings,

    /// Maximum datagram size.
    pub max_datagram_size: usize,

    /// Receive buffer size per socket.
    pub recv_buffer_size: usize,

    /// Send buffer size per socket.
    pub send_buffer_size: usize,
}

impl Default for UdpRouterConfig {
    fn default() -> Self {
        Self {
            listeners: Vec::new(),
            routes: Vec::new(),
            session: SessionSettings::default(),
            max_datagram_size: 65535,
            recv_buffer_size: 1048576, // 1MB
            send_buffer_size: 1048576, // 1MB
        }
    }
}

/// Configuration for a UDP listener.
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

    /// Enable SO_REUSEADDR.
    #[serde(default = "default_true")]
    pub reuse_addr: bool,

    /// Enable SO_REUSEPORT (Linux only).
    #[serde(default)]
    pub reuse_port: bool,
}

fn default_bind_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
}

fn default_true() -> bool {
    true
}

impl ListenerConfig {
    /// Create a new listener config.
    #[must_use]
    pub fn new(port: u16) -> Self {
        Self {
            address: default_bind_address(),
            port,
            name: None,
            reuse_addr: true,
            reuse_port: false,
        }
    }

    /// Set the bind address.
    #[must_use]
    pub fn with_address(mut self, address: IpAddr) -> Self {
        self.address = address;
        self
    }

    /// Set the listener name.
    #[must_use]
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Get the socket address.
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

    /// Enable session affinity (sticky sessions).
    #[serde(default)]
    pub session_affinity: bool,
}

impl RouteConfig {
    /// Create a new route config.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            match_criteria: MatchCriteria::default(),
            backends: Vec::new(),
            load_balance: LoadBalanceStrategy::default(),
            session_affinity: false,
        }
    }

    /// Set match criteria.
    #[must_use]
    pub fn with_match(mut self, criteria: MatchCriteria) -> Self {
        self.match_criteria = criteria;
        self
    }

    /// Add a backend.
    #[must_use]
    pub fn with_backend(mut self, backend: BackendConfig) -> Self {
        self.backends.push(backend);
        self
    }

    /// Enable session affinity.
    #[must_use]
    pub fn with_session_affinity(mut self) -> Self {
        self.session_affinity = true;
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
}

fn default_weight() -> u32 {
    1
}

impl BackendConfig {
    /// Create a new backend config.
    #[must_use]
    pub fn new(address: IpAddr, port: u16) -> Self {
        Self {
            address,
            port,
            weight: 1,
        }
    }

    /// Set the weight.
    #[must_use]
    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    /// Get the socket address.
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

    /// Random selection.
    Random,

    /// Source IP hash (sticky sessions).
    IpHash,

    /// Weighted random selection.
    WeightedRandom,
}

/// Session tracking settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionSettings {
    /// Enable session tracking.
    pub enabled: bool,

    /// Session timeout in seconds.
    pub timeout_secs: u64,

    /// Maximum number of concurrent sessions.
    pub max_sessions: usize,

    /// Session cleanup interval in seconds.
    pub cleanup_interval_secs: u64,
}

impl Default for SessionSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_secs: 60,
            max_sessions: 100_000,
            cleanup_interval_secs: 10,
        }
    }
}

impl SessionSettings {
    /// Get session timeout as Duration.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }

    /// Get cleanup interval as Duration.
    #[must_use]
    pub fn cleanup_interval(&self) -> Duration {
        Duration::from_secs(self.cleanup_interval_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = UdpRouterConfig::default();
        assert!(config.listeners.is_empty());
        assert!(config.routes.is_empty());
        assert_eq!(config.max_datagram_size, 65535);
        assert!(config.session.enabled);
    }

    #[test]
    fn test_listener_config() {
        let listener = ListenerConfig::new(5353)
            .with_address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .with_name("dns");

        assert_eq!(listener.port, 5353);
        assert_eq!(listener.name, Some("dns".to_string()));
        assert_eq!(
            listener.socket_addr(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5353)
        );
    }

    #[test]
    fn test_route_config() {
        let route = RouteConfig::new("dns-route")
            .with_match(MatchCriteria::port(5353))
            .with_backend(BackendConfig::new(
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                53,
            ))
            .with_session_affinity();

        assert_eq!(route.name, "dns-route");
        assert!(route.session_affinity);
        assert_eq!(route.backends.len(), 1);
    }

    #[test]
    fn test_backend_socket_addr() {
        let backend = BackendConfig::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        assert_eq!(
            backend.socket_addr(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)
        );
    }

    #[test]
    fn test_deserialize_config() {
        let json = r#"{
            "listeners": [{"port": 5353}],
            "routes": [{
                "name": "dns",
                "match": {"port": 5353},
                "backends": [{"address": "8.8.8.8", "port": 53}]
            }]
        }"#;

        let config: UdpRouterConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.listeners.len(), 1);
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].backends[0].port, 53);
    }
}
