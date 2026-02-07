//! Metrics registry for custom metric registration and aggregation.

use super::error::{MetricsError, MetricsResult};
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};

/// Type of metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricType {
    /// Monotonically increasing counter.
    Counter,
    /// Value that can go up or down.
    Gauge,
    /// Distribution of values (histogram).
    Histogram,
}

/// Descriptor for a metric.
#[derive(Debug, Clone)]
pub struct MetricDescriptor {
    /// Metric name.
    pub name: String,
    /// Help text describing the metric.
    pub help: String,
    /// Metric type.
    pub metric_type: MetricType,
    /// Label names for this metric.
    pub labels: Vec<String>,
    /// Unit of measurement (optional).
    pub unit: Option<String>,
}

impl MetricDescriptor {
    /// Create a new counter descriptor.
    #[must_use]
    pub fn counter(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            metric_type: MetricType::Counter,
            labels: Vec::new(),
            unit: None,
        }
    }

    /// Create a new gauge descriptor.
    #[must_use]
    pub fn gauge(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            metric_type: MetricType::Gauge,
            labels: Vec::new(),
            unit: None,
        }
    }

    /// Create a new histogram descriptor.
    #[must_use]
    pub fn histogram(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            metric_type: MetricType::Histogram,
            labels: Vec::new(),
            unit: None,
        }
    }

    /// Add labels to the metric.
    #[must_use]
    pub fn with_labels(mut self, labels: Vec<String>) -> Self {
        self.labels = labels;
        self
    }

    /// Set the unit of measurement.
    #[must_use]
    pub fn with_unit(mut self, unit: impl Into<String>) -> Self {
        self.unit = Some(unit.into());
        self
    }
}

/// Default labels applied to all metrics.
#[allow(dead_code)]
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DefaultLabels {
    /// Module name.
    pub module: String,
}

/// Per-module metrics storage.
#[derive(Debug)]
pub struct ModuleMetrics {
    /// Module name.
    name: String,
    /// Counter metrics.
    counters: RwLock<HashMap<String, Counter<u64, AtomicU64>>>,
    /// Gauge metrics.
    gauges: RwLock<HashMap<String, Gauge<f64, AtomicU64>>>,
    /// Histogram metrics.
    histograms: RwLock<HashMap<String, Histogram>>,
    /// Metric descriptors.
    descriptors: RwLock<HashMap<String, MetricDescriptor>>,
}

impl ModuleMetrics {
    /// Create new module metrics.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            counters: RwLock::new(HashMap::new()),
            gauges: RwLock::new(HashMap::new()),
            histograms: RwLock::new(HashMap::new()),
            descriptors: RwLock::new(HashMap::new()),
        }
    }

    /// Get the module name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Register a counter metric.
    pub fn register_counter(&self, desc: MetricDescriptor) -> MetricsResult<()> {
        let name = desc.name.clone();
        validate_metric_name(&name)?;

        let mut counters = self.counters.write().expect("counters lock poisoned");
        let mut descriptors = self.descriptors.write().expect("descriptors lock poisoned");

        if descriptors.contains_key(&name) {
            return Err(MetricsError::MetricAlreadyExists(name));
        }

        counters.insert(name.clone(), Counter::default());
        descriptors.insert(name, desc);
        Ok(())
    }

    /// Register a gauge metric.
    pub fn register_gauge(&self, desc: MetricDescriptor) -> MetricsResult<()> {
        let name = desc.name.clone();
        validate_metric_name(&name)?;

        let mut gauges = self.gauges.write().expect("gauges lock poisoned");
        let mut descriptors = self.descriptors.write().expect("descriptors lock poisoned");

        if descriptors.contains_key(&name) {
            return Err(MetricsError::MetricAlreadyExists(name));
        }

        gauges.insert(name.clone(), Gauge::default());
        descriptors.insert(name, desc);
        Ok(())
    }

    /// Register a histogram metric with custom buckets.
    pub fn register_histogram(&self, desc: MetricDescriptor, buckets: &[f64]) -> MetricsResult<()> {
        let name = desc.name.clone();
        validate_metric_name(&name)?;

        let mut histograms = self.histograms.write().expect("histograms lock poisoned");
        let mut descriptors = self.descriptors.write().expect("descriptors lock poisoned");

        if descriptors.contains_key(&name) {
            return Err(MetricsError::MetricAlreadyExists(name));
        }

        let bucket_iter = buckets.iter().copied();
        histograms.insert(name.clone(), Histogram::new(bucket_iter));
        descriptors.insert(name, desc);
        Ok(())
    }

    /// Increment a counter.
    pub fn inc_counter(&self, name: &str) -> MetricsResult<()> {
        let counters = self.counters.read().expect("counters lock poisoned");
        let counter = counters
            .get(name)
            .ok_or_else(|| MetricsError::MetricNotFound(name.to_string()))?;
        counter.inc();
        Ok(())
    }

    /// Add to a counter.
    pub fn add_counter(&self, name: &str, value: u64) -> MetricsResult<()> {
        let counters = self.counters.read().expect("counters lock poisoned");
        let counter = counters
            .get(name)
            .ok_or_else(|| MetricsError::MetricNotFound(name.to_string()))?;
        counter.inc_by(value);
        Ok(())
    }

    /// Set a gauge value.
    pub fn set_gauge(&self, name: &str, value: f64) -> MetricsResult<()> {
        let gauges = self.gauges.read().expect("gauges lock poisoned");
        let gauge = gauges
            .get(name)
            .ok_or_else(|| MetricsError::MetricNotFound(name.to_string()))?;
        gauge.set(value);
        Ok(())
    }

    /// Increment a gauge.
    pub fn inc_gauge(&self, name: &str) -> MetricsResult<()> {
        let gauges = self.gauges.read().expect("gauges lock poisoned");
        let gauge = gauges
            .get(name)
            .ok_or_else(|| MetricsError::MetricNotFound(name.to_string()))?;
        gauge.inc();
        Ok(())
    }

    /// Decrement a gauge.
    pub fn dec_gauge(&self, name: &str) -> MetricsResult<()> {
        let gauges = self.gauges.read().expect("gauges lock poisoned");
        let gauge = gauges
            .get(name)
            .ok_or_else(|| MetricsError::MetricNotFound(name.to_string()))?;
        gauge.dec();
        Ok(())
    }

    /// Observe a histogram value.
    pub fn observe_histogram(&self, name: &str, value: f64) -> MetricsResult<()> {
        let histograms = self.histograms.read().expect("histograms lock poisoned");
        let histogram = histograms
            .get(name)
            .ok_or_else(|| MetricsError::MetricNotFound(name.to_string()))?;
        histogram.observe(value);
        Ok(())
    }

    /// Get the current value of a counter.
    #[must_use]
    pub fn get_counter(&self, name: &str) -> Option<u64> {
        let counters = self.counters.read().expect("counters lock poisoned");
        counters.get(name).map(Counter::get)
    }

    /// Get the current value of a gauge.
    #[must_use]
    pub fn get_gauge(&self, name: &str) -> Option<f64> {
        let gauges = self.gauges.read().expect("gauges lock poisoned");
        gauges.get(name).map(|g| g.get())
    }

    /// Get all metric descriptors.
    #[must_use]
    pub fn descriptors(&self) -> Vec<MetricDescriptor> {
        let descriptors = self.descriptors.read().expect("descriptors lock poisoned");
        descriptors.values().cloned().collect()
    }

    /// Get the number of registered metrics.
    #[must_use]
    pub fn metric_count(&self) -> usize {
        let descriptors = self.descriptors.read().expect("descriptors lock poisoned");
        descriptors.len()
    }
}

/// Central metrics registry for all modules.
#[derive(Debug)]
pub struct MetricsRegistry {
    /// Prometheus registry.
    registry: Registry,
    /// Per-module metrics.
    modules: RwLock<HashMap<String, Arc<ModuleMetrics>>>,
    /// Global metric prefix.
    prefix: String,
}

impl MetricsRegistry {
    /// Create a new metrics registry.
    #[must_use]
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            registry: Registry::default(),
            modules: RwLock::new(HashMap::new()),
            prefix: prefix.into(),
        }
    }

    /// Get the Prometheus registry.
    #[must_use]
    pub fn prometheus_registry(&self) -> &Registry {
        &self.registry
    }

    /// Register a module.
    pub fn register_module(&self, name: impl Into<String>) -> MetricsResult<Arc<ModuleMetrics>> {
        let name = name.into();
        let mut modules = self.modules.write().expect("modules lock poisoned");

        if modules.contains_key(&name) {
            return Err(MetricsError::ModuleNotFound(format!(
                "Module {} already registered",
                name
            )));
        }

        let metrics = Arc::new(ModuleMetrics::new(&name));
        modules.insert(name, Arc::clone(&metrics));
        Ok(metrics)
    }

    /// Get a module's metrics.
    #[must_use]
    pub fn get_module(&self, name: &str) -> Option<Arc<ModuleMetrics>> {
        let modules = self.modules.read().expect("modules lock poisoned");
        modules.get(name).cloned()
    }

    /// Unregister a module.
    pub fn unregister_module(&self, name: &str) -> MetricsResult<()> {
        let mut modules = self.modules.write().expect("modules lock poisoned");
        modules
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| MetricsError::ModuleNotFound(name.to_string()))
    }

    /// Get all registered module names.
    #[must_use]
    pub fn module_names(&self) -> Vec<String> {
        let modules = self.modules.read().expect("modules lock poisoned");
        modules.keys().cloned().collect()
    }

    /// Get the total number of metrics across all modules.
    #[must_use]
    pub fn total_metric_count(&self) -> usize {
        let modules = self.modules.read().expect("modules lock poisoned");
        modules.values().map(|m| m.metric_count()).sum()
    }

    /// Get the metric prefix.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Encode all metrics in Prometheus text format.
    #[must_use]
    pub fn encode_prometheus(&self) -> String {
        let modules = self.modules.read().expect("modules lock poisoned");
        let mut output = String::new();

        for (module_name, module) in modules.iter() {
            let prefix = format!("{}_{}", self.prefix, module_name);

            // Encode counters
            let counters = module.counters.read().expect("counters lock poisoned");
            let descriptors = module
                .descriptors
                .read()
                .expect("descriptors lock poisoned");

            for (name, counter) in counters.iter() {
                if let Some(desc) = descriptors.get(name) {
                    output.push_str(&format!("# HELP {}_{} {}\n", prefix, name, desc.help));
                    output.push_str(&format!("# TYPE {}_{} counter\n", prefix, name));
                }
                output.push_str(&format!("{}_{} {}\n", prefix, name, counter.get()));
            }

            // Encode gauges
            let gauges = module.gauges.read().expect("gauges lock poisoned");
            for (name, gauge) in gauges.iter() {
                if let Some(desc) = descriptors.get(name) {
                    output.push_str(&format!("# HELP {}_{} {}\n", prefix, name, desc.help));
                    output.push_str(&format!("# TYPE {}_{} gauge\n", prefix, name));
                }
                let value = gauge.get();
                output.push_str(&format!("{}_{} {}\n", prefix, name, value));
            }
        }

        output
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new("r0n_gateway")
    }
}

/// Validate a metric name follows Prometheus naming conventions.
fn validate_metric_name(name: &str) -> MetricsResult<()> {
    if name.is_empty() {
        return Err(MetricsError::InvalidMetricName(
            "Metric name cannot be empty".to_string(),
        ));
    }

    // Must start with a letter or underscore
    let first = name.chars().next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(MetricsError::InvalidMetricName(format!(
            "Metric name must start with a letter or underscore: {name}"
        )));
    }

    // Rest must be alphanumeric or underscore
    for ch in name.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '_' {
            return Err(MetricsError::InvalidMetricName(format!(
                "Metric name contains invalid character '{ch}': {name}"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metric_descriptor_counter() {
        let desc = MetricDescriptor::counter("requests_total", "Total requests");
        assert_eq!(desc.name, "requests_total");
        assert_eq!(desc.metric_type, MetricType::Counter);
    }

    #[test]
    fn test_metric_descriptor_with_labels() {
        let desc = MetricDescriptor::gauge("connections", "Active connections")
            .with_labels(vec!["protocol".to_string(), "backend".to_string()]);
        assert_eq!(desc.labels.len(), 2);
    }

    #[test]
    fn test_module_metrics_register() {
        let metrics = ModuleMetrics::new("test");

        let desc = MetricDescriptor::counter("requests", "Request count");
        metrics.register_counter(desc).unwrap();

        assert_eq!(metrics.metric_count(), 1);

        // Duplicate should fail
        let desc = MetricDescriptor::counter("requests", "Request count");
        assert!(metrics.register_counter(desc).is_err());
    }

    #[test]
    fn test_counter_operations() {
        let metrics = ModuleMetrics::new("test");

        let desc = MetricDescriptor::counter("count", "A counter");
        metrics.register_counter(desc).unwrap();

        assert_eq!(metrics.get_counter("count"), Some(0));

        metrics.inc_counter("count").unwrap();
        assert_eq!(metrics.get_counter("count"), Some(1));

        metrics.add_counter("count", 5).unwrap();
        assert_eq!(metrics.get_counter("count"), Some(6));
    }

    #[test]
    fn test_gauge_operations() {
        let metrics = ModuleMetrics::new("test");

        let desc = MetricDescriptor::gauge("temp", "Temperature");
        metrics.register_gauge(desc).unwrap();

        metrics.set_gauge("temp", 25.5).unwrap();
        let value = metrics.get_gauge("temp").unwrap();
        assert!((value - 25.5).abs() < 0.001);

        metrics.inc_gauge("temp").unwrap();
        metrics.dec_gauge("temp").unwrap();
    }

    #[test]
    fn test_histogram_operations() {
        let metrics = ModuleMetrics::new("test");

        let desc = MetricDescriptor::histogram("latency", "Request latency");
        let buckets = vec![0.001, 0.01, 0.1, 1.0, 10.0];
        metrics.register_histogram(desc, &buckets).unwrap();

        metrics.observe_histogram("latency", 0.05).unwrap();
        metrics.observe_histogram("latency", 0.5).unwrap();
    }

    #[test]
    fn test_registry_module_registration() {
        let registry = MetricsRegistry::new("test");

        let module = registry.register_module("tcp").unwrap();
        assert_eq!(module.name(), "tcp");

        assert!(registry.get_module("tcp").is_some());
        assert!(registry.get_module("udp").is_none());

        assert_eq!(registry.module_names().len(), 1);
    }

    #[test]
    fn test_validate_metric_name() {
        assert!(validate_metric_name("requests_total").is_ok());
        assert!(validate_metric_name("_private").is_ok());
        assert!(validate_metric_name("http2_connections").is_ok());

        assert!(validate_metric_name("").is_err());
        assert!(validate_metric_name("123abc").is_err());
        assert!(validate_metric_name("name-with-dash").is_err());
    }

    #[test]
    fn test_prometheus_encoding() {
        let registry = MetricsRegistry::new("app");
        let module = registry.register_module("test").unwrap();

        let desc = MetricDescriptor::counter("requests", "Total requests");
        module.register_counter(desc).unwrap();
        module.add_counter("requests", 100).unwrap();

        let output = registry.encode_prometheus();
        assert!(output.contains("app_test_requests 100"));
        assert!(output.contains("# TYPE app_test_requests counter"));
    }
}
