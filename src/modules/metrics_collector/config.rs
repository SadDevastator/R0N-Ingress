//! Metrics collector configuration.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Configuration for the metrics collector module.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsCollectorConfig {
    /// Enable metrics collection.
    pub enabled: bool,

    /// Prometheus exporter configuration.
    pub exporter: ExporterConfig,

    /// Metric retention configuration.
    pub retention: RetentionConfig,

    /// Global metric prefix (e.g., "r0n_gateway").
    pub prefix: String,

    /// Default labels applied to all metrics.
    pub default_labels: Vec<(String, String)>,

    /// Metric collection interval.
    #[serde(with = "humantime_serde")]
    pub collection_interval: Duration,
}

impl Default for MetricsCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            exporter: ExporterConfig::default(),
            retention: RetentionConfig::default(),
            prefix: "r0n_gateway".to_string(),
            default_labels: Vec::new(),
            collection_interval: Duration::from_secs(15),
        }
    }
}

impl MetricsCollectorConfig {
    /// Get the exporter bind address.
    #[must_use]
    pub fn bind_addr(&self) -> SocketAddr {
        self.exporter.socket_addr()
    }
}

/// Prometheus exporter HTTP server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ExporterConfig {
    /// Enable the Prometheus HTTP exporter.
    pub enabled: bool,

    /// IP address to bind to.
    pub address: IpAddr,

    /// Port to listen on.
    pub port: u16,

    /// Metrics endpoint path.
    pub path: String,

    /// Enable gzip compression.
    pub compression: bool,

    /// Basic authentication (optional).
    pub auth: Option<AuthConfig>,
}

impl Default for ExporterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            port: 9090,
            path: "/metrics".to_string(),
            compression: false,
            auth: None,
        }
    }
}

impl ExporterConfig {
    /// Get the socket address.
    #[must_use]
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}

/// Basic authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Username for basic auth.
    pub username: String,
    /// Password for basic auth.
    pub password: String,
}

/// Metric retention configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RetentionConfig {
    /// How long to keep histogram data.
    #[serde(with = "humantime_serde")]
    pub histogram_ttl: Duration,

    /// Maximum number of histogram buckets.
    pub max_buckets: usize,

    /// Enable metric cardinality limits.
    pub cardinality_limit: Option<usize>,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            histogram_ttl: Duration::from_secs(300),
            max_buckets: 10,
            cardinality_limit: Some(10000),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MetricsCollectorConfig::default();
        assert!(config.enabled);
        assert_eq!(config.prefix, "r0n_gateway");
        assert_eq!(config.exporter.port, 9090);
        assert_eq!(config.exporter.path, "/metrics");
    }

    #[test]
    fn test_bind_addr() {
        let config = MetricsCollectorConfig::default();
        let addr = config.bind_addr();
        assert_eq!(addr.port(), 9090);
    }

    #[test]
    fn test_deserialize_config() {
        let toml_str = r#"
            enabled = true
            prefix = "myapp"
            collection_interval = "30s"
            
            [exporter]
            enabled = true
            port = 8080
            path = "/prom"
            
            [retention]
            histogram_ttl = "5m"
            max_buckets = 20
        "#;

        let config: MetricsCollectorConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.prefix, "myapp");
        assert_eq!(config.collection_interval, Duration::from_secs(30));
        assert_eq!(config.exporter.port, 8080);
        assert_eq!(config.exporter.path, "/prom");
        assert_eq!(config.retention.max_buckets, 20);
    }

    #[test]
    fn test_auth_config() {
        let toml_str = r#"
            [exporter]
            enabled = true
            
            [exporter.auth]
            username = "admin"
            password = "secret"
        "#;

        let config: MetricsCollectorConfig = toml::from_str(toml_str).unwrap();
        let auth = config.exporter.auth.unwrap();
        assert_eq!(auth.username, "admin");
        assert_eq!(auth.password, "secret");
    }
}
