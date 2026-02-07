//! Tracing configuration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    /// Whether tracing is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Service name for traces
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Service version
    #[serde(default)]
    pub service_version: Option<String>,

    /// Environment (e.g., production, staging)
    #[serde(default)]
    pub environment: Option<String>,

    /// Sampling configuration
    #[serde(default)]
    pub sampling: SamplingConfig,

    /// Propagation format
    #[serde(default)]
    pub propagation: PropagationFormat,

    /// Exporter configuration
    #[serde(default)]
    pub exporter: ExporterConfig,

    /// Resource attributes
    #[serde(default)]
    pub resource_attributes: HashMap<String, String>,

    /// Maximum number of attributes per span
    #[serde(default = "default_max_attributes")]
    pub max_attributes_per_span: usize,

    /// Maximum number of events per span
    #[serde(default = "default_max_events")]
    pub max_events_per_span: usize,

    /// Maximum number of links per span
    #[serde(default = "default_max_links")]
    pub max_links_per_span: usize,

    /// Batch export configuration
    #[serde(default)]
    pub batch: BatchConfig,
}

fn default_enabled() -> bool {
    true
}

fn default_service_name() -> String {
    "r0n-gateway".to_string()
}

fn default_max_attributes() -> usize {
    128
}

fn default_max_events() -> usize {
    128
}

fn default_max_links() -> usize {
    128
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            service_name: default_service_name(),
            service_version: None,
            environment: None,
            sampling: SamplingConfig::default(),
            propagation: PropagationFormat::default(),
            exporter: ExporterConfig::default(),
            resource_attributes: HashMap::new(),
            max_attributes_per_span: default_max_attributes(),
            max_events_per_span: default_max_events(),
            max_links_per_span: default_max_links(),
            batch: BatchConfig::default(),
        }
    }
}

/// Sampling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingConfig {
    /// Sampling strategy
    #[serde(default)]
    pub strategy: SamplingStrategy,

    /// Sample ratio (0.0 to 1.0) for ratio-based sampling
    #[serde(default = "default_sample_ratio")]
    pub ratio: f64,

    /// Rate limit (samples per second) for rate limiting
    #[serde(default)]
    pub rate_limit: Option<u32>,
}

fn default_sample_ratio() -> f64 {
    1.0
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            strategy: SamplingStrategy::default(),
            ratio: default_sample_ratio(),
            rate_limit: None,
        }
    }
}

/// Sampling strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SamplingStrategy {
    /// Always sample
    #[default]
    AlwaysOn,

    /// Never sample
    AlwaysOff,

    /// Sample based on ratio
    Ratio,

    /// Follow parent span's sampling decision
    ParentBased,

    /// Rate-limited sampling
    RateLimited,
}

impl SamplingStrategy {
    /// Parse from string
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "always_on" | "alwayson" | "always" => Some(Self::AlwaysOn),
            "always_off" | "alwaysoff" | "never" => Some(Self::AlwaysOff),
            "ratio" | "probability" => Some(Self::Ratio),
            "parent_based" | "parentbased" | "parent" => Some(Self::ParentBased),
            "rate_limited" | "ratelimited" | "rate" => Some(Self::RateLimited),
            _ => None,
        }
    }
}

/// Propagation format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PropagationFormat {
    /// W3C Trace Context (traceparent, tracestate)
    #[default]
    W3C,

    /// B3 single header format
    B3Single,

    /// B3 multi-header format
    B3Multi,

    /// Jaeger format
    Jaeger,

    /// AWS X-Ray format
    XRay,

    /// Composite (try multiple formats)
    Composite,
}

impl PropagationFormat {
    /// Get header names for this format
    pub fn header_names(&self) -> Vec<&'static str> {
        match self {
            Self::W3C => vec!["traceparent", "tracestate"],
            Self::B3Single => vec!["b3"],
            Self::B3Multi => vec![
                "x-b3-traceid",
                "x-b3-spanid",
                "x-b3-parentspanid",
                "x-b3-sampled",
                "x-b3-flags",
            ],
            Self::Jaeger => vec!["uber-trace-id"],
            Self::XRay => vec!["x-amzn-trace-id"],
            Self::Composite => vec![
                "traceparent",
                "tracestate",
                "b3",
                "x-b3-traceid",
                "uber-trace-id",
            ],
        }
    }
}

/// Exporter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExporterConfig {
    /// Exporter type
    #[serde(default)]
    pub exporter_type: ExporterType,

    /// Endpoint URL
    #[serde(default)]
    pub endpoint: Option<String>,

    /// Additional headers for HTTP exporters
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Timeout for export operations
    #[serde(default = "default_timeout_ms", with = "humantime_serde")]
    pub timeout: Duration,

    /// Compression (gzip, none)
    #[serde(default)]
    pub compression: Option<String>,
}

fn default_timeout_ms() -> Duration {
    Duration::from_secs(10)
}

impl Default for ExporterConfig {
    fn default() -> Self {
        Self {
            exporter_type: ExporterType::default(),
            endpoint: None,
            headers: HashMap::new(),
            timeout: default_timeout_ms(),
            compression: None,
        }
    }
}

/// Exporter type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExporterType {
    /// No export (for testing)
    #[default]
    None,

    /// Console/stdout export
    Console,

    /// OTLP (OpenTelemetry Protocol) over gRPC
    OtlpGrpc,

    /// OTLP over HTTP
    OtlpHttp,

    /// Jaeger format
    Jaeger,

    /// Zipkin format
    Zipkin,

    /// In-memory (for testing)
    Memory,
}

impl ExporterType {
    /// Get default endpoint for this exporter type
    pub fn default_endpoint(&self) -> Option<&'static str> {
        match self {
            Self::OtlpGrpc => Some("http://localhost:4317"),
            Self::OtlpHttp => Some("http://localhost:4318/v1/traces"),
            Self::Jaeger => Some("http://localhost:14268/api/traces"),
            Self::Zipkin => Some("http://localhost:9411/api/v2/spans"),
            _ => None,
        }
    }
}

/// Batch export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    /// Maximum batch size
    #[serde(default = "default_batch_size")]
    pub max_batch_size: usize,

    /// Maximum queue size
    #[serde(default = "default_queue_size")]
    pub max_queue_size: usize,

    /// Scheduled delay between exports
    #[serde(default = "default_scheduled_delay", with = "humantime_serde")]
    pub scheduled_delay: Duration,

    /// Export timeout
    #[serde(default = "default_export_timeout", with = "humantime_serde")]
    pub export_timeout: Duration,
}

fn default_batch_size() -> usize {
    512
}

fn default_queue_size() -> usize {
    2048
}

fn default_scheduled_delay() -> Duration {
    Duration::from_secs(5)
}

fn default_export_timeout() -> Duration {
    Duration::from_secs(30)
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: default_batch_size(),
            max_queue_size: default_queue_size(),
            scheduled_delay: default_scheduled_delay(),
            export_timeout: default_export_timeout(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TracingConfig::default();
        assert!(config.enabled);
        assert_eq!(config.service_name, "r0n-gateway");
        assert_eq!(config.sampling.strategy, SamplingStrategy::AlwaysOn);
        assert_eq!(config.propagation, PropagationFormat::W3C);
    }

    #[test]
    fn test_sampling_strategy_parse() {
        assert_eq!(
            SamplingStrategy::parse("always_on"),
            Some(SamplingStrategy::AlwaysOn)
        );
        assert_eq!(
            SamplingStrategy::parse("ratio"),
            Some(SamplingStrategy::Ratio)
        );
        assert_eq!(
            SamplingStrategy::parse("parent"),
            Some(SamplingStrategy::ParentBased)
        );
        assert_eq!(SamplingStrategy::parse("invalid"), None);
    }

    #[test]
    fn test_propagation_headers() {
        let w3c = PropagationFormat::W3C;
        let headers = w3c.header_names();
        assert!(headers.contains(&"traceparent"));
        assert!(headers.contains(&"tracestate"));

        let b3 = PropagationFormat::B3Multi;
        let headers = b3.header_names();
        assert!(headers.contains(&"x-b3-traceid"));
    }

    #[test]
    fn test_exporter_default_endpoints() {
        assert_eq!(
            ExporterType::OtlpGrpc.default_endpoint(),
            Some("http://localhost:4317")
        );
        assert_eq!(
            ExporterType::Zipkin.default_endpoint(),
            Some("http://localhost:9411/api/v2/spans")
        );
        assert_eq!(ExporterType::None.default_endpoint(), None);
    }

    #[test]
    fn test_batch_config() {
        let config = BatchConfig::default();
        assert_eq!(config.max_batch_size, 512);
        assert_eq!(config.max_queue_size, 2048);
    }

    #[test]
    fn test_config_serialization() {
        let config = TracingConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("r0n-gateway"));

        let parsed: TracingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.service_name, config.service_name);
    }
}
