//! Load balancer configuration types.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Configuration for the load balancer module.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LoadBalancerConfig {
    /// Backend pools configuration.
    pub pools: Vec<PoolConfig>,

    /// Default load balancing strategy.
    #[serde(default = "default_strategy")]
    pub default_strategy: StrategyType,

    /// Global health check settings (can be overridden per pool).
    pub health_check: HealthCheckConfig,
}

/// Configuration for a backend pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Pool name (unique identifier).
    pub name: String,

    /// Backends in this pool.
    pub backends: Vec<BackendConfig>,

    /// Load balancing strategy (overrides default).
    pub strategy: Option<StrategyType>,

    /// Health check configuration (overrides global).
    pub health_check: Option<HealthCheckConfig>,

    /// Sticky session configuration.
    pub sticky: Option<StickyConfig>,
}

/// Configuration for a single backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Backend address.
    pub address: IpAddr,

    /// Backend port.
    pub port: u16,

    /// Backend weight (for weighted strategies).
    #[serde(default = "default_weight")]
    pub weight: u32,

    /// Maximum connections to this backend.
    pub max_connections: Option<u32>,

    /// Whether this backend is initially enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

impl BackendConfig {
    /// Get the socket address for this backend.
    #[must_use]
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}

/// Load balancing strategy types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StrategyType {
    /// Round-robin distribution.
    #[default]
    RoundRobin,
    /// Least connections.
    LeastConnections,
    /// Weighted round-robin.
    WeightedRoundRobin,
    /// IP hash (sticky by client IP).
    IpHash,
    /// Header hash (sticky by header value).
    HeaderHash,
    /// Random selection.
    Random,
}

/// Health check configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HealthCheckConfig {
    /// Enable health checks.
    pub enabled: bool,

    /// Health check interval.
    #[serde(with = "humantime_serde")]
    pub interval: Duration,

    /// Health check timeout.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,

    /// Number of failures before marking unhealthy.
    pub unhealthy_threshold: u32,

    /// Number of successes before marking healthy.
    pub healthy_threshold: u32,

    /// Health check type.
    pub check_type: HealthCheckType,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(5),
            unhealthy_threshold: 3,
            healthy_threshold: 2,
            check_type: HealthCheckType::default(),
        }
    }
}

/// Type of health check to perform.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthCheckType {
    /// TCP connection check.
    #[default]
    Tcp,
    /// HTTP health check.
    Http {
        /// Path to check.
        path: String,
        /// Expected status codes.
        expected_status: Vec<u16>,
    },
    /// Custom command check.
    Command {
        /// Command to execute.
        command: String,
    },
}

/// Sticky session configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StickyConfig {
    /// Enable sticky sessions.
    pub enabled: bool,

    /// Sticky session TTL.
    #[serde(with = "humantime_serde")]
    pub ttl: Duration,

    /// Hash key for sticky sessions.
    pub hash_key: StickyHashKey,
}

impl Default for StickyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl: Duration::from_secs(3600),
            hash_key: StickyHashKey::ClientIp,
        }
    }
}

/// Key to use for sticky session hashing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StickyHashKey {
    /// Hash by client IP.
    ClientIp,
    /// Hash by specific header.
    Header(String),
    /// Hash by cookie value.
    Cookie(String),
}

fn default_strategy() -> StrategyType {
    StrategyType::RoundRobin
}

fn default_weight() -> u32 {
    1
}

fn default_enabled() -> bool {
    true
}

#[allow(dead_code)]
fn default_bind_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = LoadBalancerConfig::default();
        assert!(config.pools.is_empty());
        assert_eq!(config.default_strategy, StrategyType::RoundRobin);
        assert!(config.health_check.enabled);
    }

    #[test]
    fn test_backend_socket_addr() {
        let backend = BackendConfig {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: 8080,
            weight: 1,
            max_connections: None,
            enabled: true,
        };
        assert_eq!(backend.socket_addr(), "10.0.0.1:8080".parse().unwrap());
    }

    #[test]
    fn test_strategy_types() {
        assert_eq!(StrategyType::default(), StrategyType::RoundRobin);

        let strategies = vec![
            StrategyType::RoundRobin,
            StrategyType::LeastConnections,
            StrategyType::WeightedRoundRobin,
            StrategyType::IpHash,
            StrategyType::Random,
        ];

        for s in strategies {
            assert_eq!(s, s); // Eq trait works
        }
    }

    #[test]
    fn test_health_check_config_default() {
        let config = HealthCheckConfig::default();
        assert!(config.enabled);
        assert_eq!(config.interval, Duration::from_secs(10));
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert_eq!(config.unhealthy_threshold, 3);
        assert_eq!(config.healthy_threshold, 2);
    }

    #[test]
    fn test_deserialize_config() {
        let toml = r#"
            default_strategy = "least-connections"

            [[pools]]
            name = "web"
            strategy = "round-robin"

            [[pools.backends]]
            address = "10.0.0.1"
            port = 8080
            weight = 2

            [[pools.backends]]
            address = "10.0.0.2"
            port = 8080
            weight = 1
            enabled = false

            [health_check]
            enabled = true
            interval = "30s"
            timeout = "10s"
        "#;

        let config: LoadBalancerConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.default_strategy, StrategyType::LeastConnections);
        assert_eq!(config.pools.len(), 1);
        assert_eq!(config.pools[0].name, "web");
        assert_eq!(config.pools[0].backends.len(), 2);
        assert_eq!(config.pools[0].backends[0].weight, 2);
        assert!(!config.pools[0].backends[1].enabled);
        assert_eq!(config.health_check.interval, Duration::from_secs(30));
    }
}
