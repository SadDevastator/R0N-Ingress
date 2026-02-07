//! Configuration types for the L4 Passthrough module.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Main configuration for L4 passthrough.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L4PassthroughConfig {
    /// Module name.
    #[serde(default = "default_name")]
    pub name: String,

    /// Listener configurations.
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,

    /// Backend configurations.
    #[serde(default)]
    pub backends: Vec<BackendConfig>,

    /// Global connection limits.
    #[serde(default)]
    pub limits: LimitsConfig,

    /// Connection tracking settings.
    #[serde(default)]
    pub tracking: TrackingConfig,
}

fn default_name() -> String {
    "l4-passthrough".to_string()
}

impl Default for L4PassthroughConfig {
    fn default() -> Self {
        Self {
            name: default_name(),
            listeners: Vec::new(),
            backends: Vec::new(),
            limits: LimitsConfig::default(),
            tracking: TrackingConfig::default(),
        }
    }
}

/// Listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    /// Protocol (tcp or udp).
    pub protocol: Protocol,

    /// Bind address (e.g., "0.0.0.0:3306").
    pub bind: String,

    /// Backend name to forward to.
    pub backend: String,

    /// Optional listener name.
    #[serde(default)]
    pub name: Option<String>,

    /// Per-listener connection limit (0 = unlimited).
    #[serde(default)]
    pub max_connections: usize,

    /// Connection timeout.
    #[serde(default = "default_connect_timeout", with = "humantime_serde")]
    pub connect_timeout: Duration,

    /// Idle timeout for connections.
    #[serde(default = "default_idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,
}

fn default_connect_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_idle_timeout() -> Duration {
    Duration::from_secs(300)
}

/// Protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// TCP protocol.
    Tcp,
    /// UDP protocol.
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

/// Backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Backend name.
    pub name: String,

    /// Backend addresses.
    pub addresses: Vec<String>,

    /// Load balancing strategy.
    #[serde(default)]
    pub load_balance: LoadBalanceStrategy,

    /// Health check configuration.
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,

    /// Connection pool size per backend (TCP only).
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
}

fn default_pool_size() -> usize {
    10
}

/// Load balancing strategy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    /// Round-robin distribution.
    #[default]
    RoundRobin,
    /// Least connections.
    LeastConnections,
    /// Random selection.
    Random,
    /// IP hash (sticky sessions).
    IpHash,
}

/// Health check configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Health check interval.
    #[serde(default = "default_health_interval", with = "humantime_serde")]
    pub interval: Duration,

    /// Health check timeout.
    #[serde(default = "default_health_timeout", with = "humantime_serde")]
    pub timeout: Duration,

    /// Number of failures before marking unhealthy.
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,

    /// Number of successes before marking healthy.
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
}

fn default_health_interval() -> Duration {
    Duration::from_secs(10)
}

fn default_health_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_unhealthy_threshold() -> u32 {
    3
}

fn default_healthy_threshold() -> u32 {
    2
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            interval: default_health_interval(),
            timeout: default_health_timeout(),
            unhealthy_threshold: default_unhealthy_threshold(),
            healthy_threshold: default_healthy_threshold(),
        }
    }
}

/// Connection limits configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Maximum total connections (0 = unlimited).
    #[serde(default)]
    pub max_connections: usize,

    /// Maximum connections per IP (0 = unlimited).
    #[serde(default)]
    pub max_connections_per_ip: usize,

    /// TCP buffer size.
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Maximum UDP packet size.
    #[serde(default = "default_udp_buffer_size")]
    pub udp_buffer_size: usize,
}

fn default_buffer_size() -> usize {
    64 * 1024 // 64KB
}

fn default_udp_buffer_size() -> usize {
    65535 // Max UDP packet size
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 0,
            max_connections_per_ip: 0,
            buffer_size: default_buffer_size(),
            udp_buffer_size: default_udp_buffer_size(),
        }
    }
}

/// Connection tracking configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackingConfig {
    /// Enable connection tracking.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// UDP session timeout.
    #[serde(default = "default_udp_session_timeout", with = "humantime_serde")]
    pub udp_session_timeout: Duration,

    /// Cleanup interval for expired sessions.
    #[serde(default = "default_cleanup_interval", with = "humantime_serde")]
    pub cleanup_interval: Duration,
}

fn default_enabled() -> bool {
    true
}

fn default_udp_session_timeout() -> Duration {
    Duration::from_secs(60)
}

fn default_cleanup_interval() -> Duration {
    Duration::from_secs(30)
}

impl Default for TrackingConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            udp_session_timeout: default_udp_session_timeout(),
            cleanup_interval: default_cleanup_interval(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = L4PassthroughConfig::default();
        assert_eq!(config.name, "l4-passthrough");
        assert!(config.listeners.is_empty());
        assert!(config.backends.is_empty());
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(Protocol::Tcp.to_string(), "tcp");
        assert_eq!(Protocol::Udp.to_string(), "udp");
    }

    #[test]
    fn test_load_balance_strategy_default() {
        let strategy = LoadBalanceStrategy::default();
        assert_eq!(strategy, LoadBalanceStrategy::RoundRobin);
    }

    #[test]
    fn test_listener_config_defaults() {
        let listener = ListenerConfig {
            protocol: Protocol::Tcp,
            bind: "0.0.0.0:3306".to_string(),
            backend: "mysql".to_string(),
            name: None,
            max_connections: 0,
            connect_timeout: default_connect_timeout(),
            idle_timeout: default_idle_timeout(),
        };

        assert_eq!(listener.connect_timeout, Duration::from_secs(10));
        assert_eq!(listener.idle_timeout, Duration::from_secs(300));
    }

    #[test]
    fn test_backend_config() {
        let backend = BackendConfig {
            name: "mysql".to_string(),
            addresses: vec!["10.0.0.1:3306".to_string(), "10.0.0.2:3306".to_string()],
            load_balance: LoadBalanceStrategy::LeastConnections,
            health_check: Some(HealthCheckConfig::default()),
            pool_size: 20,
        };

        assert_eq!(backend.addresses.len(), 2);
        assert_eq!(backend.pool_size, 20);
    }

    #[test]
    fn test_limits_config_defaults() {
        let limits = LimitsConfig::default();
        assert_eq!(limits.max_connections, 0);
        assert_eq!(limits.buffer_size, 64 * 1024);
        assert_eq!(limits.udp_buffer_size, 65535);
    }

    #[test]
    fn test_tracking_config_defaults() {
        let tracking = TrackingConfig::default();
        assert!(tracking.enabled);
        assert_eq!(tracking.udp_session_timeout, Duration::from_secs(60));
        assert_eq!(tracking.cleanup_interval, Duration::from_secs(30));
    }

    #[test]
    fn test_config_serialization() {
        let config = L4PassthroughConfig {
            name: "test".to_string(),
            listeners: vec![ListenerConfig {
                protocol: Protocol::Tcp,
                bind: "0.0.0.0:3306".to_string(),
                backend: "mysql".to_string(),
                name: Some("mysql-listener".to_string()),
                max_connections: 1000,
                connect_timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(60),
            }],
            backends: vec![BackendConfig {
                name: "mysql".to_string(),
                addresses: vec!["10.0.0.1:3306".to_string()],
                load_balance: LoadBalanceStrategy::RoundRobin,
                health_check: None,
                pool_size: 10,
            }],
            limits: LimitsConfig::default(),
            tracking: TrackingConfig::default(),
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: L4PassthroughConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test");
        assert_eq!(parsed.listeners.len(), 1);
        assert_eq!(parsed.backends.len(), 1);
    }
}
