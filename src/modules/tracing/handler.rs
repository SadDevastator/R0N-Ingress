//! Tracing module handler

use super::config::TracingConfig;
use super::context::{SpanContext, TraceFlags};
use super::error::{TracingError, TracingResult};
use super::exporter::{create_exporter, BatchSpanProcessor, SpanExporter};
use super::propagation::{CompositePropagator, Extractor, Injector, Propagator};
use super::sampler::{create_sampler, Sampler, SamplingParameters};
use super::span::{Span, SpanBuilder, SpanId, SpanKind, TraceId};
use crate::module::{
    Capability, MetricsPayload, ModuleConfig, ModuleContract, ModuleError, ModuleManifest,
    ModuleResult, ModuleStatus,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Active span registry for tracking in-flight spans
#[derive(Default)]
struct SpanRegistry {
    /// Active spans by span ID
    spans: HashMap<SpanId, Span>,
}

impl SpanRegistry {
    fn new() -> Self {
        Self {
            spans: HashMap::new(),
        }
    }

    fn insert(&mut self, span: Span) {
        self.spans.insert(span.span_id, span);
    }

    fn remove(&mut self, span_id: &SpanId) -> Option<Span> {
        self.spans.remove(span_id)
    }

    fn get(&self, span_id: &SpanId) -> Option<&Span> {
        self.spans.get(span_id)
    }

    fn get_mut(&mut self, span_id: &SpanId) -> Option<&mut Span> {
        self.spans.get_mut(span_id)
    }

    fn count(&self) -> usize {
        self.spans.len()
    }
}

/// Tracer for creating and managing spans
pub struct Tracer {
    /// Service name
    service_name: String,

    /// Sampler
    sampler: Arc<dyn Sampler>,

    /// Propagator
    propagator: Arc<dyn Propagator>,

    /// Batch processor
    processor: Arc<BatchSpanProcessor>,

    /// Active spans
    registry: Mutex<SpanRegistry>,

    /// Statistics
    spans_started: AtomicU64,
    spans_ended: AtomicU64,
    spans_sampled: AtomicU64,
    spans_dropped: AtomicU64,
}

impl Tracer {
    /// Create a new tracer
    pub fn new(
        service_name: String,
        sampler: Arc<dyn Sampler>,
        propagator: Arc<dyn Propagator>,
        exporter: Arc<dyn SpanExporter>,
        max_batch_size: usize,
        max_queue_size: usize,
    ) -> Self {
        Self {
            service_name,
            sampler,
            propagator,
            processor: Arc::new(BatchSpanProcessor::new(
                exporter,
                max_batch_size,
                max_queue_size,
            )),
            registry: Mutex::new(SpanRegistry::new()),
            spans_started: AtomicU64::new(0),
            spans_ended: AtomicU64::new(0),
            spans_sampled: AtomicU64::new(0),
            spans_dropped: AtomicU64::new(0),
        }
    }

    /// Get service name
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Start a new span builder
    pub fn start_span(&self, name: impl Into<String>) -> SpanBuilder {
        SpanBuilder::new(name)
    }

    /// Create and register a span
    pub fn create_span(&self, name: impl Into<String>) -> TracingResult<SpanId> {
        let name = name.into();
        let trace_id = TraceId::generate();
        self.create_span_with_trace(name, trace_id, None, SpanKind::Internal)
    }

    /// Create a span with parent context
    pub fn create_child_span(
        &self,
        name: impl Into<String>,
        parent_span_id: SpanId,
    ) -> TracingResult<SpanId> {
        let name = name.into();

        // Get parent to inherit trace ID
        let parent_trace_id = {
            let registry = self
                .registry
                .lock()
                .map_err(|_| TracingError::Internal("lock poisoned".to_string()))?;
            registry.get(&parent_span_id).map(|s| s.trace_id)
        };

        let trace_id = parent_trace_id.unwrap_or_else(TraceId::generate);
        self.create_span_with_trace(name, trace_id, Some(parent_span_id), SpanKind::Internal)
    }

    /// Create a span from extracted context
    pub fn create_span_from_context(
        &self,
        name: impl Into<String>,
        span_context: &SpanContext,
        kind: SpanKind,
    ) -> TracingResult<SpanId> {
        let name = name.into();
        let trace_id = span_context.trace_id;
        let parent_span_id = Some(span_context.span_id);
        let is_remote = span_context.is_remote;

        self.create_span_with_trace_full(name, trace_id, parent_span_id, kind, is_remote)
    }

    fn create_span_with_trace(
        &self,
        name: String,
        trace_id: TraceId,
        parent_span_id: Option<SpanId>,
        kind: SpanKind,
    ) -> TracingResult<SpanId> {
        self.create_span_with_trace_full(name, trace_id, parent_span_id, kind, false)
    }

    fn create_span_with_trace_full(
        &self,
        name: String,
        trace_id: TraceId,
        parent_span_id: Option<SpanId>,
        kind: SpanKind,
        is_remote_parent: bool,
    ) -> TracingResult<SpanId> {
        // Check sampling
        let parent_context = parent_span_id.and_then(|id| {
            self.registry.lock().ok().and_then(|reg| {
                reg.get(&id).map(|s| SpanContext {
                    trace_id: s.trace_id,
                    span_id: s.span_id,
                    trace_flags: if s.is_sampled {
                        TraceFlags::SAMPLED
                    } else {
                        TraceFlags::NONE
                    },
                    trace_state: Default::default(),
                    is_remote: is_remote_parent,
                })
            })
        });

        let kind_str = match kind {
            SpanKind::Internal => "internal",
            SpanKind::Server => "server",
            SpanKind::Client => "client",
            SpanKind::Producer => "producer",
            SpanKind::Consumer => "consumer",
        };

        let params = SamplingParameters {
            parent_context: parent_context.as_ref(),
            trace_id,
            name: &name,
            kind: kind_str,
            attributes: &[],
        };

        let sampling_result = self.sampler.should_sample(&params);
        let is_sampled = sampling_result.decision.is_sampled();

        self.spans_started.fetch_add(1, Ordering::Relaxed);

        if is_sampled {
            self.spans_sampled.fetch_add(1, Ordering::Relaxed);
        }

        let mut span = SpanBuilder::new(&name)
            .trace_id(trace_id)
            .kind(kind)
            .sampled(is_sampled)
            .build();

        span.parent_span_id = parent_span_id;
        let span_id = span.span_id;

        // Add sampling attributes
        for (key, value) in sampling_result.attributes {
            span.set_attribute(key, value);
        }

        let mut registry = self
            .registry
            .lock()
            .map_err(|_| TracingError::Internal("lock poisoned".to_string()))?;

        registry.insert(span);

        Ok(span_id)
    }

    /// End a span
    pub fn end_span(&self, span_id: SpanId) -> TracingResult<()> {
        let span = {
            let mut registry = self
                .registry
                .lock()
                .map_err(|_| TracingError::Internal("lock poisoned".to_string()))?;

            let mut span = registry
                .remove(&span_id)
                .ok_or(TracingError::SpanNotFound(span_id.to_hex()))?;
            span.end();
            span
        };

        self.spans_ended.fetch_add(1, Ordering::Relaxed);

        // Only export if sampled
        if span.is_sampled {
            self.processor.on_end(span)?;
        } else {
            self.spans_dropped.fetch_add(1, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Set an attribute on a span
    pub fn set_attribute(
        &self,
        span_id: SpanId,
        key: impl Into<String>,
        value: impl Into<super::span::AttributeValue>,
    ) -> TracingResult<()> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| TracingError::Internal("lock poisoned".to_string()))?;

        let span = registry
            .get_mut(&span_id)
            .ok_or(TracingError::SpanNotFound(span_id.to_hex()))?;

        span.set_attribute(key, value);
        Ok(())
    }

    /// Add an event to a span
    pub fn add_event(&self, span_id: SpanId, name: impl Into<String>) -> TracingResult<()> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| TracingError::Internal("lock poisoned".to_string()))?;

        let span = registry
            .get_mut(&span_id)
            .ok_or(TracingError::SpanNotFound(span_id.to_hex()))?;

        span.add_event_simple(name);
        Ok(())
    }

    /// Record an error on a span
    pub fn record_error(&self, span_id: SpanId, error: &str) -> TracingResult<()> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| TracingError::Internal("lock poisoned".to_string()))?;

        let span = registry
            .get_mut(&span_id)
            .ok_or(TracingError::SpanNotFound(span_id.to_hex()))?;

        span.set_error(error);
        Ok(())
    }

    /// Extract span context from carrier
    pub fn extract<C: Extractor>(&self, carrier: &C) -> Option<SpanContext> {
        self.propagator.extract(carrier)
    }

    /// Inject span context into carrier
    pub fn inject<C: Injector>(&self, span_context: &SpanContext, carrier: &mut C) {
        self.propagator.inject(span_context, carrier);
    }

    /// Get span context for a span
    pub fn get_span_context(&self, span_id: SpanId) -> TracingResult<SpanContext> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| TracingError::Internal("lock poisoned".to_string()))?;

        let span = registry
            .get(&span_id)
            .ok_or(TracingError::SpanNotFound(span_id.to_hex()))?;

        Ok(SpanContext {
            trace_id: span.trace_id,
            span_id: span.span_id,
            trace_flags: if span.is_sampled {
                TraceFlags::SAMPLED
            } else {
                TraceFlags::NONE
            },
            trace_state: Default::default(),
            is_remote: false,
        })
    }

    /// Flush pending spans
    pub fn flush(&self) -> TracingResult<()> {
        self.processor.flush()
    }

    /// Shutdown the tracer
    pub fn shutdown(&self) -> TracingResult<()> {
        self.processor.shutdown()
    }

    /// Get statistics
    pub fn stats(&self) -> TracerStats {
        TracerStats {
            spans_started: self.spans_started.load(Ordering::Relaxed),
            spans_ended: self.spans_ended.load(Ordering::Relaxed),
            spans_sampled: self.spans_sampled.load(Ordering::Relaxed),
            spans_dropped: self.spans_dropped.load(Ordering::Relaxed),
            spans_active: self.registry.lock().map(|r| r.count()).unwrap_or(0) as u64,
            pending_export: self.processor.pending_count() as u64,
        }
    }
}

/// Tracer statistics
#[derive(Debug, Clone, Default)]
pub struct TracerStats {
    /// Total spans started
    pub spans_started: u64,
    /// Total spans ended
    pub spans_ended: u64,
    /// Spans that were sampled
    pub spans_sampled: u64,
    /// Spans that were dropped (not sampled)
    pub spans_dropped: u64,
    /// Currently active spans
    pub spans_active: u64,
    /// Spans pending export
    pub pending_export: u64,
}

/// Tracing handler implementing ModuleContract
pub struct TracingHandler {
    /// Configuration
    config: TracingConfig,

    /// Module status
    status: ModuleStatus,

    /// Tracer instance
    tracer: Option<Arc<Tracer>>,
}

impl TracingHandler {
    /// Create a new tracing handler
    pub fn new(config: TracingConfig) -> Self {
        Self {
            config,
            status: ModuleStatus::Stopped,
            tracer: None,
        }
    }

    /// Get the tracer
    pub fn tracer(&self) -> Option<&Arc<Tracer>> {
        self.tracer.as_ref()
    }

    /// Start a span (convenience method)
    pub fn start_span(&self, name: impl Into<String>) -> TracingResult<SpanId> {
        let tracer = self
            .tracer
            .as_ref()
            .ok_or(TracingError::Internal("tracer not initialized".to_string()))?;
        tracer.create_span(name)
    }

    /// End a span (convenience method)
    pub fn end_span(&self, span_id: SpanId) -> TracingResult<()> {
        let tracer = self
            .tracer
            .as_ref()
            .ok_or(TracingError::Internal("tracer not initialized".to_string()))?;
        tracer.end_span(span_id)
    }
}

impl Default for TracingHandler {
    fn default() -> Self {
        Self::new(TracingConfig::default())
    }
}

impl ModuleContract for TracingHandler {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("tracing")
            .description("Distributed tracing with OpenTelemetry-compatible context propagation")
            .version(1, 0, 0)
            .capability(Capability::Custom("DistributedTracing".to_string()))
            .capability(Capability::Custom("W3CTraceContext".to_string()))
            .capability(Capability::Custom("OpenTelemetry".to_string()))
            .build()
    }

    fn init(&mut self, _config: ModuleConfig) -> ModuleResult<()> {
        if self.status != ModuleStatus::Stopped {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Stopped".to_string(),
            });
        }

        self.status = ModuleStatus::Initializing;
        Ok(())
    }

    fn start(&mut self) -> ModuleResult<()> {
        if self.status != ModuleStatus::Initializing {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Initializing".to_string(),
            });
        }

        if !self.config.enabled {
            self.status = ModuleStatus::Running;
            return Ok(());
        }

        // Create sampler
        let sampler = create_sampler(
            self.config.sampling.strategy,
            self.config.sampling.ratio,
            self.config.sampling.rate_limit,
        );

        // Create propagator
        let propagator = Arc::new(CompositePropagator::default_propagators());

        // Create exporter
        let exporter = create_exporter(self.config.exporter.exporter_type);

        // Create tracer
        let tracer = Arc::new(Tracer::new(
            self.config.service_name.clone(),
            Arc::from(sampler),
            propagator,
            exporter,
            self.config.batch.max_batch_size,
            self.config.batch.max_queue_size,
        ));

        self.tracer = Some(tracer);
        self.status = ModuleStatus::Running;
        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        if self.status != ModuleStatus::Running {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Running".to_string(),
            });
        }

        // Shutdown tracer
        if let Some(tracer) = &self.tracer {
            tracer.shutdown().map_err(|e| {
                ModuleError::StopFailed(format!("Failed to shutdown tracer: {}", e))
            })?;
        }

        self.tracer = None;
        self.status = ModuleStatus::Stopped;
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    fn metrics(&self) -> MetricsPayload {
        let mut payload = MetricsPayload::new();

        if let Some(tracer) = &self.tracer {
            let stats = tracer.stats();
            payload.counter("spans_started", stats.spans_started);
            payload.counter("spans_ended", stats.spans_ended);
            payload.counter("spans_sampled", stats.spans_sampled);
            payload.counter("spans_dropped", stats.spans_dropped);
            payload.counter("spans_active", stats.spans_active);
            payload.counter("pending_export", stats.pending_export);
        }

        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::tracing::exporter::InMemoryExporter;

    fn create_test_tracer() -> Arc<Tracer> {
        use crate::modules::tracing::sampler::AlwaysOnSampler;

        let exporter = Arc::new(InMemoryExporter::new());
        Arc::new(Tracer::new(
            "test-service".to_string(),
            Arc::new(AlwaysOnSampler::new()),
            Arc::new(CompositePropagator::default_propagators()),
            exporter,
            10,
            100,
        ))
    }

    #[test]
    fn test_tracer_create_span() {
        let tracer = create_test_tracer();
        let span_id = tracer.create_span("test-span").unwrap();
        assert!(span_id.is_valid());
    }

    #[test]
    fn test_tracer_end_span() {
        let tracer = create_test_tracer();
        let span_id = tracer.create_span("test-span").unwrap();
        tracer.end_span(span_id).unwrap();
    }

    #[test]
    fn test_tracer_child_span() {
        let tracer = create_test_tracer();
        let parent_id = tracer.create_span("parent").unwrap();
        let child_id = tracer.create_child_span("child", parent_id).unwrap();

        tracer.end_span(child_id).unwrap();
        tracer.end_span(parent_id).unwrap();
    }

    #[test]
    fn test_tracer_set_attribute() {
        let tracer = create_test_tracer();
        let span_id = tracer.create_span("test-span").unwrap();
        tracer.set_attribute(span_id, "key", "value").unwrap();
        tracer.end_span(span_id).unwrap();
    }

    #[test]
    fn test_tracer_add_event() {
        let tracer = create_test_tracer();
        let span_id = tracer.create_span("test-span").unwrap();
        tracer.add_event(span_id, "test-event").unwrap();
        tracer.end_span(span_id).unwrap();
    }

    #[test]
    fn test_tracer_record_error() {
        let tracer = create_test_tracer();
        let span_id = tracer.create_span("test-span").unwrap();
        tracer
            .record_error(span_id, "something went wrong")
            .unwrap();
        tracer.end_span(span_id).unwrap();
    }

    #[test]
    fn test_tracer_stats() {
        let tracer = create_test_tracer();

        let span1 = tracer.create_span("span-1").unwrap();
        let span2 = tracer.create_span("span-2").unwrap();

        let stats = tracer.stats();
        assert_eq!(stats.spans_started, 2);
        assert_eq!(stats.spans_active, 2);

        tracer.end_span(span1).unwrap();
        let stats = tracer.stats();
        assert_eq!(stats.spans_ended, 1);
        assert_eq!(stats.spans_active, 1);

        tracer.end_span(span2).unwrap();
    }

    #[test]
    fn test_tracer_context_injection_extraction() {
        let tracer = create_test_tracer();
        let span_id = tracer.create_span("test-span").unwrap();

        let span_context = tracer.get_span_context(span_id).unwrap();

        let mut carrier: HashMap<String, String> = HashMap::new();
        tracer.inject(&span_context, &mut carrier);

        assert!(carrier.contains_key("traceparent"));

        let extracted = tracer.extract(&carrier).unwrap();
        assert_eq!(extracted.trace_id, span_context.trace_id);

        tracer.end_span(span_id).unwrap();
    }

    #[test]
    fn test_handler_manifest() {
        let handler = TracingHandler::default();
        let manifest = handler.manifest();

        assert_eq!(manifest.name, "tracing");
    }

    #[test]
    fn test_handler_lifecycle() {
        let mut handler = TracingHandler::new(TracingConfig {
            enabled: true,
            service_name: "test-service".to_string(),
            ..Default::default()
        });

        // Init
        handler.init(ModuleConfig::new()).unwrap();
        assert_eq!(handler.status(), ModuleStatus::Initializing);

        // Start
        handler.start().unwrap();
        assert_eq!(handler.status(), ModuleStatus::Running);
        assert!(handler.tracer().is_some());

        // Stop
        handler.stop().unwrap();
        assert_eq!(handler.status(), ModuleStatus::Stopped);
        assert!(handler.tracer().is_none());
    }

    #[test]
    fn test_handler_tracing_operations() {
        let mut handler = TracingHandler::new(TracingConfig {
            enabled: true,
            service_name: "test".to_string(),
            ..Default::default()
        });

        handler.init(ModuleConfig::new()).unwrap();
        handler.start().unwrap();

        let span_id = handler.start_span("test-op").unwrap();
        handler.end_span(span_id).unwrap();

        let metrics = handler.metrics();
        assert!(*metrics.counters.get("spans_started").unwrap_or(&0) >= 1);

        handler.stop().unwrap();
    }

    #[test]
    fn test_handler_disabled() {
        let mut handler = TracingHandler::new(TracingConfig {
            enabled: false,
            ..Default::default()
        });

        handler.init(ModuleConfig::new()).unwrap();
        handler.start().unwrap();
        assert!(handler.tracer().is_none());
    }
}
