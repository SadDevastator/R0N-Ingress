//! Metrics collector implementing ModuleContract.

use super::config::MetricsCollectorConfig;
use super::error::{MetricsError, MetricsResult};
use super::exporter::PrometheusExporter;
use super::registry::{MetricDescriptor, MetricsRegistry, ModuleMetrics};
use crate::module::{
    Capability, MetricsPayload, ModuleConfig, ModuleContract, ModuleError, ModuleManifest,
    ModuleResult, ModuleStatus,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Metrics collector module.
///
/// Collects and exports metrics from all R0N Gateway modules in
/// Prometheus-compatible format.
#[derive(Debug)]
pub struct MetricsCollector {
    /// Configuration.
    config: MetricsCollectorConfig,
    /// Metrics registry.
    registry: Arc<MetricsRegistry>,
    /// Prometheus exporter.
    exporter: PrometheusExporter,
    /// Current status.
    status: ModuleStatus,
    /// Collection task shutdown sender.
    collection_shutdown: Option<mpsc::Sender<()>>,
    /// Internal metrics.
    internal_metrics: Option<Arc<ModuleMetrics>>,
}

impl MetricsCollector {
    /// Create a new metrics collector.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(MetricsCollectorConfig::default())
    }

    /// Create a metrics collector with custom configuration.
    #[must_use]
    pub fn with_config(config: MetricsCollectorConfig) -> Self {
        let registry = Arc::new(MetricsRegistry::new(&config.prefix));
        let exporter = PrometheusExporter::new(config.exporter.clone(), Arc::clone(&registry));

        Self {
            config,
            registry,
            exporter,
            status: ModuleStatus::Stopped,
            collection_shutdown: None,
            internal_metrics: None,
        }
    }

    /// Get the metrics registry.
    #[must_use]
    pub fn registry(&self) -> &Arc<MetricsRegistry> {
        &self.registry
    }

    /// Register a module for metrics collection.
    pub fn register_module(&self, name: impl Into<String>) -> MetricsResult<Arc<ModuleMetrics>> {
        self.registry.register_module(name)
    }

    /// Get a module's metrics.
    #[must_use]
    pub fn get_module(&self, name: &str) -> Option<Arc<ModuleMetrics>> {
        self.registry.get_module(name)
    }

    /// Unregister a module.
    pub fn unregister_module(&self, name: &str) -> MetricsResult<()> {
        self.registry.unregister_module(name)
    }

    /// Get all metrics in Prometheus format.
    #[must_use]
    pub fn encode_prometheus(&self) -> String {
        self.registry.encode_prometheus()
    }

    /// Import metrics from a MetricsPayload.
    ///
    /// This allows modules using the legacy MetricsPayload API to
    /// integrate with the new registry-based system.
    pub fn import_payload(&self, module_name: &str, payload: &MetricsPayload) -> MetricsResult<()> {
        let module = self
            .registry
            .get_module(module_name)
            .ok_or_else(|| MetricsError::ModuleNotFound(module_name.to_string()))?;

        // Import counters
        for (name, value) in &payload.counters {
            // Register if not exists
            if module.get_counter(name).is_none() {
                let desc = MetricDescriptor::counter(name, format!("Imported counter: {name}"));
                let _ = module.register_counter(desc);
            }
            // Set value (counters are additive, so we'd need to track deltas in production)
            let current = module.get_counter(name).unwrap_or(0);
            if *value > current {
                let _ = module.add_counter(name, value - current);
            }
        }

        // Import gauges
        for (name, value) in &payload.gauges {
            if module.get_gauge(name).is_none() {
                let desc = MetricDescriptor::gauge(name, format!("Imported gauge: {name}"));
                let _ = module.register_gauge(desc);
            }
            let _ = module.set_gauge(name, *value);
        }

        Ok(())
    }

    /// Initialize internal metrics.
    fn init_internal_metrics(&mut self) -> MetricsResult<()> {
        let metrics = self.registry.register_module("metrics_collector")?;

        // Register internal metrics
        metrics.register_counter(MetricDescriptor::counter(
            "collections_total",
            "Total number of metric collection cycles",
        ))?;

        metrics.register_counter(MetricDescriptor::counter(
            "scrapes_total",
            "Total number of Prometheus scrapes",
        ))?;

        metrics.register_gauge(MetricDescriptor::gauge(
            "registered_modules",
            "Number of registered modules",
        ))?;

        metrics.register_gauge(MetricDescriptor::gauge(
            "total_metrics",
            "Total number of registered metrics",
        ))?;

        self.internal_metrics = Some(metrics);
        Ok(())
    }

    /// Update internal metrics.
    fn update_internal_metrics(&self) {
        if let Some(ref metrics) = self.internal_metrics {
            let _ = metrics.set_gauge(
                "registered_modules",
                self.registry.module_names().len() as f64,
            );
            let _ = metrics.set_gauge("total_metrics", self.registry.total_metric_count() as f64);
        }
    }

    /// Start the collection task.
    fn start_collection_task(&mut self) {
        let (tx, mut rx) = mpsc::channel::<()>(1);
        self.collection_shutdown = Some(tx);

        let interval = self.config.collection_interval;
        let internal_metrics = self.internal_metrics.clone();

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);

            loop {
                tokio::select! {
                    _ = interval_timer.tick() => {
                        if let Some(ref metrics) = internal_metrics {
                            let _ = metrics.inc_counter("collections_total");
                        }
                        debug!("Metric collection cycle complete");
                    }
                    _ = rx.recv() => {
                        debug!("Collection task shutting down");
                        break;
                    }
                }
            }
        });
    }

    /// Stop the collection task.
    #[allow(dead_code)]
    async fn stop_collection_task(&mut self) {
        if let Some(tx) = self.collection_shutdown.take() {
            let _ = tx.send(()).await;
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleContract for MetricsCollector {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("metrics-collector")
            .description("Prometheus-compatible metrics collection and export")
            .version(1, 0, 0)
            .author("R0N Team")
            .capability(Capability::Custom("prometheus-export".to_string()))
            .capability(Capability::Custom("metric-aggregation".to_string()))
            .build()
    }

    fn init(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        if self.status != ModuleStatus::Stopped {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Stopped".to_string(),
            });
        }

        // Parse configuration if provided via config_toml
        if let Some(config_toml) = config.get_string("config_toml") {
            self.config = toml::from_str(config_toml)
                .map_err(|e| ModuleError::ConfigError(format!("Invalid config: {e}")))?;

            // Recreate registry with new prefix
            self.registry = Arc::new(MetricsRegistry::new(&self.config.prefix));
            self.exporter =
                PrometheusExporter::new(self.config.exporter.clone(), Arc::clone(&self.registry));
        }

        // Initialize internal metrics
        self.init_internal_metrics()
            .map_err(|e| ModuleError::ConfigError(e.to_string()))?;

        self.status = ModuleStatus::Initializing;
        info!(
            prefix = %self.config.prefix,
            exporter_enabled = %self.config.exporter.enabled,
            exporter_port = %self.config.exporter.port,
            "Metrics collector initialized"
        );

        Ok(())
    }

    fn start(&mut self) -> ModuleResult<()> {
        if self.status != ModuleStatus::Initializing && self.status != ModuleStatus::Stopped {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Initializing or Stopped".to_string(),
            });
        }

        // Check we have a runtime available
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(ModuleError::ConfigError(
                "No tokio runtime available".to_string(),
            ));
        }

        // Spawn exporter start in a separate task to avoid blocking
        // The exporter handles its own async operations internally
        if self.config.exporter.enabled {
            let exporter_config = self.config.exporter.clone();
            let registry = Arc::clone(&self.registry);
            let mut exporter = PrometheusExporter::new(exporter_config, registry);

            tokio::spawn(async move {
                if let Err(e) = exporter.start().await {
                    tracing::error!(error = %e, "Failed to start metrics exporter");
                }
            });
        }

        // Start collection task
        self.start_collection_task();

        self.status = ModuleStatus::Running;
        info!("Metrics collector started");

        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        if self.status != ModuleStatus::Running {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Running".to_string(),
            });
        }

        // Signal collection task to stop
        if let Some(tx) = self.collection_shutdown.take() {
            // Spawn a task to send shutdown signal
            tokio::spawn(async move {
                let _ = tx.send(()).await;
            });
        }

        // Note: The spawned exporter task will be cleaned up when the runtime shuts down
        // or when the collector is dropped. For graceful shutdown, the exporter
        // should implement its own shutdown mechanism.

        self.status = ModuleStatus::Stopped;
        info!("Metrics collector stopped");

        Ok(())
    }

    fn reload(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        if self.status != ModuleStatus::Running {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Running".to_string(),
            });
        }

        // Parse new configuration
        if let Some(config_toml) = config.get_string("config_toml") {
            let new_config: MetricsCollectorConfig = toml::from_str(config_toml)
                .map_err(|e| ModuleError::ConfigError(format!("Invalid config: {e}")))?;

            // Check if exporter config changed
            let exporter_changed = new_config.exporter.port != self.config.exporter.port
                || new_config.exporter.address != self.config.exporter.address
                || new_config.exporter.enabled != self.config.exporter.enabled;

            if exporter_changed {
                warn!("Exporter configuration changed - requires restart");
            }

            self.config = new_config;
        }

        info!("Metrics collector configuration reloaded");
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    fn metrics(&self) -> MetricsPayload {
        self.update_internal_metrics();

        let mut payload = MetricsPayload::new();

        // Export internal metrics
        if let Some(ref metrics) = self.internal_metrics {
            if let Some(v) = metrics.get_counter("collections_total") {
                payload.counter("collections_total", v);
            }
            if let Some(v) = metrics.get_counter("scrapes_total") {
                payload.counter("scrapes_total", v);
            }
            if let Some(v) = metrics.get_gauge("registered_modules") {
                payload.gauge("registered_modules", v);
            }
            if let Some(v) = metrics.get_gauge("total_metrics") {
                payload.gauge("total_metrics", v);
            }
        }

        payload.gauge(
            "exporter_running",
            if self.exporter.is_running() { 1.0 } else { 0.0 },
        );

        payload
    }

    fn heartbeat(&self) -> bool {
        if self.status != ModuleStatus::Running {
            return false;
        }

        // Check if exporter is healthy
        if self.config.exporter.enabled && !self.exporter.is_running() {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_creation() {
        let collector = MetricsCollector::new();
        assert_eq!(collector.status(), ModuleStatus::Stopped);
    }

    #[test]
    fn test_collector_manifest() {
        let collector = MetricsCollector::new();
        let manifest = collector.manifest();

        assert_eq!(manifest.name, "metrics-collector");
        assert_eq!(manifest.version.to_string(), "1.0.0");
    }

    #[test]
    fn test_collector_init() {
        let mut collector = MetricsCollector::new();
        let config = ModuleConfig::new();

        collector.init(config).unwrap();
        assert_eq!(collector.status(), ModuleStatus::Initializing);
    }

    #[test]
    fn test_collector_init_with_config() {
        let mut collector = MetricsCollector::new();
        let mut config = ModuleConfig::new();
        config.set_string(
            "config_toml",
            r#"
            enabled = true
            prefix = "test_app"
            
            [exporter]
            enabled = false
            port = 19090
        "#,
        );

        collector.init(config).unwrap();
        assert_eq!(collector.config.prefix, "test_app");
        assert!(!collector.config.exporter.enabled);
    }

    #[tokio::test]
    async fn test_collector_start_stop() {
        let mut collector = MetricsCollector::new();

        // Disable exporter for test
        collector.config.exporter.enabled = false;

        let config = ModuleConfig::new();

        collector.init(config).unwrap();
        collector.start().unwrap();
        assert_eq!(collector.status(), ModuleStatus::Running);

        collector.stop().unwrap();
        assert_eq!(collector.status(), ModuleStatus::Stopped);
    }

    #[test]
    fn test_collector_metrics() {
        let mut collector = MetricsCollector::new();
        collector.config.exporter.enabled = false;

        let config = ModuleConfig::new();

        collector.init(config).unwrap();

        let metrics = collector.metrics();
        assert!(metrics.gauges.contains_key("exporter_running"));
    }

    #[test]
    fn test_register_module() {
        let collector = MetricsCollector::new();

        let module = collector.register_module("test").unwrap();
        assert_eq!(module.name(), "test");

        assert!(collector.get_module("test").is_some());
        assert!(collector.get_module("nonexistent").is_none());
    }

    #[test]
    fn test_import_payload() {
        let collector = MetricsCollector::new();
        collector.register_module("test").unwrap();

        let mut payload = MetricsPayload::new();
        payload.counter("requests", 100);
        payload.gauge("connections", 5.0);

        collector.import_payload("test", &payload).unwrap();

        let module = collector.get_module("test").unwrap();
        assert_eq!(module.get_counter("requests"), Some(100));
        assert!((module.get_gauge("connections").unwrap() - 5.0).abs() < 0.001);
    }

    #[test]
    fn test_encode_prometheus() {
        let collector = MetricsCollector::new();
        let module = collector.register_module("test").unwrap();

        module
            .register_counter(MetricDescriptor::counter("hits", "Cache hits"))
            .unwrap();
        module.add_counter("hits", 42).unwrap();

        let output = collector.encode_prometheus();
        assert!(output.contains("r0n_gateway_test_hits 42"));
    }

    #[test]
    fn test_heartbeat_not_running() {
        let collector = MetricsCollector::new();
        assert!(!collector.heartbeat());
    }
}
