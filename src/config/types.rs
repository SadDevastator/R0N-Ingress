//! Configuration type definitions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

/// Root configuration structure for R0N Gateway.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct GatewayConfig {
    /// Gateway identity and binding configuration.
    pub gateway: GatewaySection,

    /// Logging configuration.
    pub logging: LoggingConfig,

    /// Metrics configuration.
    pub metrics: MetricsConfig,

    /// Module configurations.
    #[serde(default)]
    pub modules: Vec<ModuleEntry>,
}

/// Gateway section configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewaySection {
    /// Gateway instance name.
    pub name: String,

    /// Bind address for control socket.
    pub bind_address: IpAddr,

    /// Control port (for metrics, health, etc.).
    pub control_port: u16,

    /// Path to the Unix socket for IPC.
    pub socket_path: PathBuf,

    /// Working directory.
    pub work_dir: PathBuf,

    /// PID file location.
    pub pid_file: Option<PathBuf>,
}

impl Default for GatewaySection {
    fn default() -> Self {
        Self {
            name: "r0n-gateway".to_string(),
            bind_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            control_port: 9000,
            socket_path: PathBuf::from("/var/run/r0n-gateway/control.sock"),
            work_dir: PathBuf::from("/var/lib/r0n-gateway"),
            pid_file: Some(PathBuf::from("/var/run/r0n-gateway/gateway.pid")),
        }
    }
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error).
    pub level: LogLevel,

    /// Log format (json, pretty, compact).
    pub format: LogFormat,

    /// Output destination.
    pub output: LogOutput,

    /// Log file path (when output is "file").
    pub file_path: Option<PathBuf>,

    /// Maximum log file size in MB before rotation.
    pub max_file_size_mb: u32,

    /// Number of rotated files to keep.
    pub max_files: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Pretty,
            output: LogOutput::Stdout,
            file_path: None,
            max_file_size_mb: 100,
            max_files: 5,
        }
    }
}

/// Log level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Trace level (most verbose).
    Trace,
    /// Debug level.
    Debug,
    /// Info level (default).
    #[default]
    Info,
    /// Warning level.
    Warn,
    /// Error level (least verbose).
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trace => write!(f, "trace"),
            Self::Debug => write!(f, "debug"),
            Self::Info => write!(f, "info"),
            Self::Warn => write!(f, "warn"),
            Self::Error => write!(f, "error"),
        }
    }
}

/// Log format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// JSON format (machine-readable).
    Json,
    /// Pretty format with colors (default).
    #[default]
    Pretty,
    /// Compact single-line format.
    Compact,
}

/// Log output destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogOutput {
    /// Standard output (default).
    #[default]
    Stdout,
    /// Standard error.
    Stderr,
    /// File output.
    File,
}

/// Metrics configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// Enable Prometheus metrics endpoint.
    pub enabled: bool,

    /// Metrics endpoint path.
    pub path: String,

    /// Include default runtime metrics.
    pub include_runtime: bool,

    /// Custom labels to add to all metrics.
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: "/metrics".to_string(),
            include_runtime: true,
            labels: HashMap::new(),
        }
    }
}

/// Module entry in configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleEntry {
    /// Module name (used for identification).
    pub name: String,

    /// Module type (e.g., "tcp-router", "tls-terminator").
    #[serde(rename = "type")]
    pub module_type: String,

    /// Whether the module is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Module-specific configuration.
    #[serde(default)]
    pub config: toml::Table,
}

fn default_true() -> bool {
    true
}

impl ModuleEntry {
    /// Create a new module entry.
    pub fn new(name: &str, module_type: &str) -> Self {
        Self {
            name: name.to_string(),
            module_type: module_type.to_string(),
            enabled: true,
            config: toml::Table::new(),
        }
    }

    /// Set the enabled state.
    #[must_use]
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Add a configuration value.
    #[must_use]
    pub fn with_config(mut self, key: &str, value: impl Into<toml::Value>) -> Self {
        self.config.insert(key.to_string(), value.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_gateway_config() {
        let config = GatewayConfig::default();
        assert_eq!(config.gateway.name, "r0n-gateway");
        assert_eq!(config.logging.level, LogLevel::Info);
        assert!(config.metrics.enabled);
        assert!(config.modules.is_empty());
    }

    #[test]
    fn test_parse_minimal_config() {
        let toml_str = r#"
            [gateway]
            name = "test-gateway"
        "#;

        let config: GatewayConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.gateway.name, "test-gateway");
    }

    #[test]
    fn test_parse_full_config() {
        let toml_str = r#"
            [gateway]
            name = "full-gateway"
            bind_address = "0.0.0.0"
            control_port = 9001

            [logging]
            level = "debug"
            format = "json"
            output = "file"
            file_path = "/var/log/gateway.log"

            [metrics]
            enabled = true
            path = "/prometheus"

            [[modules]]
            name = "my-router"
            type = "tcp-router"
            enabled = true

            [modules.config]
            listen_port = 8080
        "#;

        let config: GatewayConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.gateway.name, "full-gateway");
        assert_eq!(config.gateway.control_port, 9001);
        assert_eq!(config.logging.level, LogLevel::Debug);
        assert_eq!(config.logging.format, LogFormat::Json);
        assert_eq!(config.modules.len(), 1);
        assert_eq!(config.modules[0].name, "my-router");
        assert_eq!(config.modules[0].module_type, "tcp-router");
    }

    #[test]
    fn test_module_entry_builder() {
        let entry = ModuleEntry::new("test", "tcp-router")
            .enabled(true)
            .with_config("port", 8080i64);

        assert_eq!(entry.name, "test");
        assert_eq!(entry.module_type, "tcp-router");
        assert!(entry.enabled);
        assert_eq!(entry.config.get("port").unwrap().as_integer(), Some(8080));
    }
}
