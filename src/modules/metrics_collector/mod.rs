//! Metrics Collector Module
//!
//! Provides Prometheus-compatible metrics collection and export for R0N Gateway.
//! Supports per-module metric aggregation and custom metric registration.

mod collector;
mod config;
mod error;
mod exporter;
mod registry;

pub use collector::MetricsCollector;
pub use config::{ExporterConfig, MetricsCollectorConfig, RetentionConfig};
pub use error::{MetricsError, MetricsResult};
pub use exporter::PrometheusExporter;
pub use registry::{MetricDescriptor, MetricType, MetricsRegistry, ModuleMetrics};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all public types are accessible
        let _config = MetricsCollectorConfig::default();
    }
}
