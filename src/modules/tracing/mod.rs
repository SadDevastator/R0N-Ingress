//! # Distributed Tracing Module
//!
//! OpenTelemetry-compatible distributed tracing for R0N Gateway
//! with trace context propagation and span management.
//!
//! ## Features
//!
//! - OpenTelemetry-compatible trace/span model
//! - W3C Trace Context propagation (traceparent, tracestate)
//! - B3 propagation format support
//! - Span creation with attributes and events
//! - Multiple exporters (Jaeger, Zipkin, OTLP)
//! - Sampling strategies (always, never, ratio, parent-based)
//! - Baggage propagation for cross-service context

pub mod config;
pub mod context;
pub mod error;
pub mod exporter;
pub mod handler;
pub mod propagation;
pub mod sampler;
pub mod span;

pub use config::*;
pub use context::*;
pub use error::*;
pub use exporter::*;
pub use handler::*;
pub use propagation::*;
pub use sampler::*;
pub use span::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify key types are exported
        let _config = TracingConfig::default();
        let _id = TraceId::generate();
        let _span_id = SpanId::generate();
    }
}
