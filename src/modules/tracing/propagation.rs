//! Trace context propagation

use super::context::{Baggage, SpanContext, TraceFlags, TraceState};
use super::error::{TracingError, TracingResult};
use super::span::{SpanId, TraceId};
use std::collections::HashMap;

/// Trait for extracting trace context from carriers (e.g., HTTP headers)
pub trait Extractor {
    /// Get a value by key
    fn get(&self, key: &str) -> Option<&str>;

    /// Get all keys
    fn keys(&self) -> Vec<&str>;
}

/// Trait for injecting trace context into carriers
pub trait Injector {
    /// Set a value
    fn set(&mut self, key: &str, value: String);
}

/// HashMap implementation of Extractor
impl Extractor for HashMap<String, String> {
    fn get(&self, key: &str) -> Option<&str> {
        self.get(key).map(|s| s.as_str())
    }

    fn keys(&self) -> Vec<&str> {
        self.keys().map(|s| s.as_str()).collect()
    }
}

/// HashMap implementation of Injector
impl Injector for HashMap<String, String> {
    fn set(&mut self, key: &str, value: String) {
        self.insert(key.to_string(), value);
    }
}

/// Trait for context propagators
pub trait Propagator: Send + Sync {
    /// Extract span context from carrier
    fn extract(&self, carrier: &dyn Extractor) -> Option<SpanContext>;

    /// Inject span context into carrier
    fn inject(&self, context: &SpanContext, carrier: &mut dyn Injector);

    /// Get the propagation fields
    fn fields(&self) -> Vec<&'static str>;
}

/// W3C Trace Context propagator
#[derive(Debug, Default)]
pub struct W3CTraceContextPropagator;

impl W3CTraceContextPropagator {
    /// Header name for traceparent
    pub const TRACEPARENT: &'static str = "traceparent";

    /// Header name for tracestate
    pub const TRACESTATE: &'static str = "tracestate";

    /// Create a new propagator
    pub fn new() -> Self {
        Self
    }

    /// Parse traceparent header
    /// Format: {version}-{trace-id}-{span-id}-{trace-flags}
    /// Example: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
    pub fn parse_traceparent(header: &str) -> TracingResult<(TraceId, SpanId, TraceFlags)> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() != 4 {
            return Err(TracingError::Propagation(
                "traceparent must have 4 parts".to_string(),
            ));
        }

        // Version (should be 00)
        let version = parts[0];
        if version != "00" {
            return Err(TracingError::Propagation(format!(
                "unsupported traceparent version: {}",
                version
            )));
        }

        // Trace ID (32 hex chars)
        let trace_id = TraceId::from_hex(parts[1])?;

        // Span ID (16 hex chars)
        let span_id = SpanId::from_hex(parts[2])?;

        // Trace flags (2 hex chars)
        let flags = TraceFlags::from_hex(parts[3])
            .ok_or_else(|| TracingError::Propagation("invalid trace flags".to_string()))?;

        Ok((trace_id, span_id, flags))
    }

    /// Format traceparent header
    pub fn format_traceparent(trace_id: &TraceId, span_id: &SpanId, flags: &TraceFlags) -> String {
        format!(
            "00-{}-{}-{}",
            trace_id.to_hex(),
            span_id.to_hex(),
            flags.to_hex()
        )
    }
}

impl Propagator for W3CTraceContextPropagator {
    fn extract(&self, carrier: &dyn Extractor) -> Option<SpanContext> {
        let traceparent = carrier.get(Self::TRACEPARENT)?;

        let (trace_id, span_id, flags) = Self::parse_traceparent(traceparent).ok()?;

        let trace_state = carrier
            .get(Self::TRACESTATE)
            .map(TraceState::from_header)
            .unwrap_or_default();

        Some(
            SpanContext::new(trace_id, span_id)
                .with_sampled(flags.is_sampled())
                .with_trace_state(trace_state)
                .with_remote(true),
        )
    }

    fn inject(&self, context: &SpanContext, carrier: &mut dyn Injector) {
        if !context.is_valid() {
            return;
        }

        let traceparent =
            Self::format_traceparent(&context.trace_id, &context.span_id, &context.trace_flags);
        carrier.set(Self::TRACEPARENT, traceparent);

        if !context.trace_state.is_empty() {
            carrier.set(Self::TRACESTATE, context.trace_state.to_header());
        }
    }

    fn fields(&self) -> Vec<&'static str> {
        vec![Self::TRACEPARENT, Self::TRACESTATE]
    }
}

/// B3 Single Header propagator
#[derive(Debug, Default)]
pub struct B3SinglePropagator;

impl B3SinglePropagator {
    /// Header name
    pub const B3: &'static str = "b3";

    /// Create a new propagator
    pub fn new() -> Self {
        Self
    }

    /// Parse B3 single header
    /// Format: {trace-id}-{span-id}-{sampling}-{parent-span-id}
    /// Or just: {trace-id}-{span-id}
    /// Or just: 0 (not sampled) or d (debug)
    pub fn parse_b3(header: &str) -> TracingResult<(TraceId, SpanId, bool, Option<SpanId>)> {
        // Handle special cases
        if header == "0" {
            return Err(TracingError::Propagation("not sampled".to_string()));
        }
        if header == "d" || header == "1" {
            return Err(TracingError::Propagation(
                "debug/sampled flag only".to_string(),
            ));
        }

        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() < 2 {
            return Err(TracingError::Propagation(
                "b3 header must have at least trace-id and span-id".to_string(),
            ));
        }

        // Trace ID (16 or 32 hex chars)
        let trace_id = if parts[0].len() == 16 {
            // 64-bit trace ID, pad to 128-bit
            TraceId::new(
                0,
                u64::from_str_radix(parts[0], 16)
                    .map_err(|e| TracingError::InvalidTraceId(e.to_string()))?,
            )
        } else {
            TraceId::from_hex(parts[0])?
        };

        // Span ID (16 hex chars)
        let span_id = SpanId::from_hex(parts[1])?;

        // Sampling (optional)
        let sampled = parts.get(2).map_or(true, |s| *s == "1" || *s == "d");

        // Parent span ID (optional)
        let parent_span_id = if parts.len() > 3 {
            Some(SpanId::from_hex(parts[3])?)
        } else {
            None
        };

        Ok((trace_id, span_id, sampled, parent_span_id))
    }

    /// Format B3 single header
    pub fn format_b3(
        trace_id: &TraceId,
        span_id: &SpanId,
        sampled: bool,
        parent_span_id: Option<&SpanId>,
    ) -> String {
        let sampling = if sampled { "1" } else { "0" };

        if let Some(parent) = parent_span_id {
            format!(
                "{}-{}-{}-{}",
                trace_id.to_hex(),
                span_id.to_hex(),
                sampling,
                parent.to_hex()
            )
        } else {
            format!("{}-{}-{}", trace_id.to_hex(), span_id.to_hex(), sampling)
        }
    }
}

impl Propagator for B3SinglePropagator {
    fn extract(&self, carrier: &dyn Extractor) -> Option<SpanContext> {
        let b3 = carrier.get(Self::B3)?;

        let (trace_id, span_id, sampled, _parent) = Self::parse_b3(b3).ok()?;

        Some(
            SpanContext::new(trace_id, span_id)
                .with_sampled(sampled)
                .with_remote(true),
        )
    }

    fn inject(&self, context: &SpanContext, carrier: &mut dyn Injector) {
        if !context.is_valid() {
            return;
        }

        let b3 = Self::format_b3(
            &context.trace_id,
            &context.span_id,
            context.is_sampled(),
            None,
        );
        carrier.set(Self::B3, b3);
    }

    fn fields(&self) -> Vec<&'static str> {
        vec![Self::B3]
    }
}

/// B3 Multi-Header propagator
#[derive(Debug, Default)]
pub struct B3MultiPropagator;

impl B3MultiPropagator {
    /// Header name for trace ID
    pub const TRACE_ID: &'static str = "x-b3-traceid";
    /// Header name for span ID
    pub const SPAN_ID: &'static str = "x-b3-spanid";
    /// Header name for parent span ID
    pub const PARENT_SPAN_ID: &'static str = "x-b3-parentspanid";
    /// Header name for sampled flag
    pub const SAMPLED: &'static str = "x-b3-sampled";
    /// Header name for debug flags
    pub const FLAGS: &'static str = "x-b3-flags";

    /// Create a new propagator
    pub fn new() -> Self {
        Self
    }
}

impl Propagator for B3MultiPropagator {
    fn extract(&self, carrier: &dyn Extractor) -> Option<SpanContext> {
        let trace_id_str = carrier.get(Self::TRACE_ID)?;
        let span_id_str = carrier.get(Self::SPAN_ID)?;

        // Parse trace ID (16 or 32 hex chars)
        let trace_id = if trace_id_str.len() == 16 {
            TraceId::new(0, u64::from_str_radix(trace_id_str, 16).ok()?)
        } else {
            TraceId::from_hex(trace_id_str).ok()?
        };

        let span_id = SpanId::from_hex(span_id_str).ok()?;

        // Check debug flag first (takes precedence)
        let sampled = if carrier.get(Self::FLAGS) == Some("1") {
            true
        } else {
            carrier
                .get(Self::SAMPLED)
                .map_or(true, |s| s == "1" || s == "true")
        };

        Some(
            SpanContext::new(trace_id, span_id)
                .with_sampled(sampled)
                .with_remote(true),
        )
    }

    fn inject(&self, context: &SpanContext, carrier: &mut dyn Injector) {
        if !context.is_valid() {
            return;
        }

        carrier.set(Self::TRACE_ID, context.trace_id.to_hex());
        carrier.set(Self::SPAN_ID, context.span_id.to_hex());
        carrier.set(
            Self::SAMPLED,
            if context.is_sampled() { "1" } else { "0" }.to_string(),
        );
    }

    fn fields(&self) -> Vec<&'static str> {
        vec![
            Self::TRACE_ID,
            Self::SPAN_ID,
            Self::PARENT_SPAN_ID,
            Self::SAMPLED,
            Self::FLAGS,
        ]
    }
}

/// Jaeger propagator
#[derive(Debug, Default)]
pub struct JaegerPropagator;

impl JaegerPropagator {
    /// Header name
    pub const UBER_TRACE_ID: &'static str = "uber-trace-id";

    /// Create a new propagator
    pub fn new() -> Self {
        Self
    }

    /// Parse uber-trace-id header
    /// Format: {trace-id}:{span-id}:{parent-span-id}:{flags}
    pub fn parse_uber_trace_id(
        header: &str,
    ) -> TracingResult<(TraceId, SpanId, Option<SpanId>, u8)> {
        let parts: Vec<&str> = header.split(':').collect();
        if parts.len() != 4 {
            return Err(TracingError::Propagation(
                "uber-trace-id must have 4 parts".to_string(),
            ));
        }

        // Trace ID (variable length hex)
        let trace_id = if parts[0].len() <= 16 {
            TraceId::new(
                0,
                u64::from_str_radix(parts[0], 16)
                    .map_err(|e| TracingError::InvalidTraceId(e.to_string()))?,
            )
        } else {
            // Pad to 32 chars
            let padded = format!("{:0>32}", parts[0]);
            TraceId::from_hex(&padded)?
        };

        // Span ID
        let span_id = SpanId::new(
            u64::from_str_radix(parts[1], 16)
                .map_err(|e| TracingError::InvalidSpanId(e.to_string()))?,
        );

        // Parent span ID (0 means no parent)
        let parent_span_id = if parts[2] != "0" {
            Some(SpanId::new(
                u64::from_str_radix(parts[2], 16)
                    .map_err(|e| TracingError::InvalidSpanId(e.to_string()))?,
            ))
        } else {
            None
        };

        // Flags
        let flags = u8::from_str_radix(parts[3], 16).unwrap_or(0);

        Ok((trace_id, span_id, parent_span_id, flags))
    }

    /// Format uber-trace-id header
    pub fn format_uber_trace_id(
        trace_id: &TraceId,
        span_id: &SpanId,
        parent_span_id: Option<&SpanId>,
        flags: u8,
    ) -> String {
        let parent = parent_span_id
            .map(|p| format!("{:x}", p.value()))
            .unwrap_or_else(|| "0".to_string());

        format!(
            "{:x}:{:x}:{}:{:x}",
            trace_id.low(),
            span_id.value(),
            parent,
            flags
        )
    }
}

impl Propagator for JaegerPropagator {
    fn extract(&self, carrier: &dyn Extractor) -> Option<SpanContext> {
        let header = carrier.get(Self::UBER_TRACE_ID)?;

        let (trace_id, span_id, _parent, flags) = Self::parse_uber_trace_id(header).ok()?;

        let sampled = (flags & 0x01) != 0;

        Some(
            SpanContext::new(trace_id, span_id)
                .with_sampled(sampled)
                .with_remote(true),
        )
    }

    fn inject(&self, context: &SpanContext, carrier: &mut dyn Injector) {
        if !context.is_valid() {
            return;
        }

        let flags = if context.is_sampled() { 0x01 } else { 0x00 };

        let header = Self::format_uber_trace_id(&context.trace_id, &context.span_id, None, flags);
        carrier.set(Self::UBER_TRACE_ID, header);
    }

    fn fields(&self) -> Vec<&'static str> {
        vec![Self::UBER_TRACE_ID]
    }
}

/// Baggage propagator
#[derive(Debug, Default)]
pub struct BaggagePropagator;

impl BaggagePropagator {
    /// Header name
    pub const BAGGAGE: &'static str = "baggage";

    /// Create a new propagator
    pub fn new() -> Self {
        Self
    }

    /// Extract baggage from carrier
    pub fn extract_baggage(&self, carrier: &dyn Extractor) -> Baggage {
        carrier
            .get(Self::BAGGAGE)
            .map(Baggage::from_header)
            .unwrap_or_default()
    }

    /// Inject baggage into carrier
    pub fn inject_baggage(&self, baggage: &Baggage, carrier: &mut dyn Injector) {
        if !baggage.is_empty() {
            carrier.set(Self::BAGGAGE, baggage.to_header());
        }
    }
}

/// Composite propagator that tries multiple formats
#[derive(Default)]
pub struct CompositePropagator {
    propagators: Vec<Box<dyn Propagator>>,
}

impl CompositePropagator {
    /// Create a new composite propagator
    pub fn new() -> Self {
        Self {
            propagators: Vec::new(),
        }
    }

    /// Create with default propagators (W3C, B3, Jaeger)
    pub fn default_propagators() -> Self {
        let mut composite = Self::new();
        composite.add(Box::new(W3CTraceContextPropagator::new()));
        composite.add(Box::new(B3SinglePropagator::new()));
        composite.add(Box::new(JaegerPropagator::new()));
        composite
    }

    /// Add a propagator
    pub fn add(&mut self, propagator: Box<dyn Propagator>) {
        self.propagators.push(propagator);
    }
}

impl Propagator for CompositePropagator {
    fn extract(&self, carrier: &dyn Extractor) -> Option<SpanContext> {
        // Try each propagator in order
        for propagator in &self.propagators {
            if let Some(context) = propagator.extract(carrier) {
                return Some(context);
            }
        }
        None
    }

    fn inject(&self, context: &SpanContext, carrier: &mut dyn Injector) {
        // Inject using all propagators
        for propagator in &self.propagators {
            propagator.inject(context, carrier);
        }
    }

    fn fields(&self) -> Vec<&'static str> {
        let mut fields = Vec::new();
        for propagator in &self.propagators {
            fields.extend(propagator.fields());
        }
        fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_w3c_traceparent_parse() {
        let header = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        let (trace_id, span_id, flags) =
            W3CTraceContextPropagator::parse_traceparent(header).unwrap();

        assert!(trace_id.is_valid());
        assert!(span_id.is_valid());
        assert!(flags.is_sampled());
    }

    #[test]
    fn test_w3c_traceparent_format() {
        let trace_id = TraceId::from_hex("0af7651916cd43dd8448eb211c80319c").unwrap();
        let span_id = SpanId::from_hex("b7ad6b7169203331").unwrap();
        let flags = TraceFlags::SAMPLED;

        let header = W3CTraceContextPropagator::format_traceparent(&trace_id, &span_id, &flags);
        assert_eq!(
            header,
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        );
    }

    #[test]
    fn test_w3c_extract_inject() {
        let propagator = W3CTraceContextPropagator::new();

        let mut carrier = HashMap::new();
        carrier.insert(
            "traceparent".to_string(),
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".to_string(),
        );

        let context = propagator.extract(&carrier).unwrap();
        assert!(context.is_valid());
        assert!(context.is_sampled());
        assert!(context.is_remote);

        // Inject back
        let mut new_carrier = HashMap::new();
        propagator.inject(&context, &mut new_carrier);
        assert!(new_carrier.contains_key("traceparent"));
    }

    #[test]
    fn test_b3_single_parse() {
        let header = "80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1";
        let (trace_id, span_id, sampled, parent) = B3SinglePropagator::parse_b3(header).unwrap();

        assert!(trace_id.is_valid());
        assert!(span_id.is_valid());
        assert!(sampled);
        assert!(parent.is_none());
    }

    #[test]
    fn test_b3_single_extract_inject() {
        let propagator = B3SinglePropagator::new();

        let mut carrier = HashMap::new();
        carrier.insert(
            "b3".to_string(),
            "80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1".to_string(),
        );

        let context = propagator.extract(&carrier).unwrap();
        assert!(context.is_valid());

        let mut new_carrier = HashMap::new();
        propagator.inject(&context, &mut new_carrier);
        assert!(new_carrier.contains_key("b3"));
    }

    #[test]
    fn test_b3_multi_extract() {
        let propagator = B3MultiPropagator::new();

        let mut carrier = HashMap::new();
        carrier.insert(
            "x-b3-traceid".to_string(),
            "80f198ee56343ba864fe8b2a57d3eff7".to_string(),
        );
        carrier.insert("x-b3-spanid".to_string(), "e457b5a2e4d86bd1".to_string());
        carrier.insert("x-b3-sampled".to_string(), "1".to_string());

        let context = propagator.extract(&carrier).unwrap();
        assert!(context.is_valid());
        assert!(context.is_sampled());
    }

    #[test]
    fn test_jaeger_extract() {
        let propagator = JaegerPropagator::new();

        let mut carrier = HashMap::new();
        carrier.insert(
            "uber-trace-id".to_string(),
            "3a29f6f5e7d8c1b2:456def:0:1".to_string(),
        );

        let context = propagator.extract(&carrier).unwrap();
        assert!(context.is_valid());
        assert!(context.is_sampled());
    }

    #[test]
    fn test_composite_propagator() {
        let propagator = CompositePropagator::default_propagators();

        // Test W3C format
        let mut carrier = HashMap::new();
        carrier.insert(
            "traceparent".to_string(),
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".to_string(),
        );

        let context = propagator.extract(&carrier).unwrap();
        assert!(context.is_valid());

        // Test B3 format
        let mut carrier = HashMap::new();
        carrier.insert(
            "b3".to_string(),
            "80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1".to_string(),
        );

        let context = propagator.extract(&carrier).unwrap();
        assert!(context.is_valid());
    }

    #[test]
    fn test_baggage_propagator() {
        let propagator = BaggagePropagator::new();

        let mut carrier = HashMap::new();
        carrier.insert(
            "baggage".to_string(),
            "user_id=12345,session=abc".to_string(),
        );

        let baggage = propagator.extract_baggage(&carrier);
        assert_eq!(baggage.get("user_id"), Some("12345"));
        assert_eq!(baggage.get("session"), Some("abc"));
    }
}
