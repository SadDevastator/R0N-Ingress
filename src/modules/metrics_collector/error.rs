//! Metrics collector error types.

use std::fmt;
use std::io;

/// Result type for metrics operations.
pub type MetricsResult<T> = Result<T, MetricsError>;

/// Errors that can occur in the metrics collector module.
#[derive(Debug)]
pub enum MetricsError {
    /// Metric already registered.
    MetricAlreadyExists(String),
    /// Metric not found.
    MetricNotFound(String),
    /// Module not registered.
    ModuleNotFound(String),
    /// Invalid metric name.
    InvalidMetricName(String),
    /// Invalid label name.
    InvalidLabelName(String),
    /// Server bind error.
    BindError(String),
    /// Server error.
    ServerError(String),
    /// Collector not running.
    NotRunning,
    /// Collector already running.
    AlreadyRunning,
    /// Configuration error.
    ConfigError(String),
    /// I/O error.
    IoError(io::Error),
}

impl fmt::Display for MetricsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MetricAlreadyExists(name) => write!(f, "Metric already exists: {name}"),
            Self::MetricNotFound(name) => write!(f, "Metric not found: {name}"),
            Self::ModuleNotFound(name) => write!(f, "Module not found: {name}"),
            Self::InvalidMetricName(name) => write!(f, "Invalid metric name: {name}"),
            Self::InvalidLabelName(name) => write!(f, "Invalid label name: {name}"),
            Self::BindError(msg) => write!(f, "Failed to bind server: {msg}"),
            Self::ServerError(msg) => write!(f, "Server error: {msg}"),
            Self::NotRunning => write!(f, "Metrics collector is not running"),
            Self::AlreadyRunning => write!(f, "Metrics collector is already running"),
            Self::ConfigError(msg) => write!(f, "Configuration error: {msg}"),
            Self::IoError(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for MetricsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for MetricsError {
    fn from(err: io::Error) -> Self {
        Self::IoError(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = MetricsError::MetricNotFound("test_metric".to_string());
        assert!(err.to_string().contains("test_metric"));

        let err = MetricsError::NotRunning;
        assert!(err.to_string().contains("not running"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::other("test");
        let err: MetricsError = io_err.into();
        assert!(matches!(err, MetricsError::IoError(_)));
    }
}
