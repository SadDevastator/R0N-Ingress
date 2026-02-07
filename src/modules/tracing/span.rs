//! Span types and management

use super::error::{TracingError, TracingResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// 128-bit trace identifier
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceId {
    high: u64,
    low: u64,
}

impl TraceId {
    /// Create a new trace ID from high and low parts
    pub fn new(high: u64, low: u64) -> Self {
        Self { high, low }
    }

    /// Generate a random trace ID
    pub fn generate() -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);

        // Create a more random low value by hashing multiple sources
        let mut hasher = DefaultHasher::new();
        std::thread::current().id().hash(&mut hasher);
        counter.hash(&mut hasher);
        timestamp.hash(&mut hasher);
        std::process::id().hash(&mut hasher);
        let random_low = hasher.finish();

        Self {
            high: timestamp,
            low: random_low,
        }
    }

    /// Create an invalid (zero) trace ID
    pub fn invalid() -> Self {
        Self { high: 0, low: 0 }
    }

    /// Check if this trace ID is valid (non-zero)
    pub fn is_valid(&self) -> bool {
        self.high != 0 || self.low != 0
    }

    /// Get the high 64 bits
    pub fn high(&self) -> u64 {
        self.high
    }

    /// Get the low 64 bits
    pub fn low(&self) -> u64 {
        self.low
    }

    /// Convert to bytes (big-endian)
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&self.high.to_be_bytes());
        bytes[8..].copy_from_slice(&self.low.to_be_bytes());
        bytes
    }

    /// Create from bytes (big-endian)
    pub fn from_bytes(bytes: &[u8; 16]) -> Self {
        let high = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        let low = u64::from_be_bytes(bytes[8..].try_into().unwrap());
        Self { high, low }
    }

    /// Parse from hex string (32 characters)
    pub fn from_hex(hex: &str) -> TracingResult<Self> {
        if hex.len() != 32 {
            return Err(TracingError::InvalidTraceId(format!(
                "expected 32 hex chars, got {}",
                hex.len()
            )));
        }

        let high = u64::from_str_radix(&hex[..16], 16)
            .map_err(|e| TracingError::InvalidTraceId(format!("invalid hex: {}", e)))?;

        let low = u64::from_str_radix(&hex[16..], 16)
            .map_err(|e| TracingError::InvalidTraceId(format!("invalid hex: {}", e)))?;

        Ok(Self { high, low })
    }

    /// Convert to hex string (32 characters)
    pub fn to_hex(&self) -> String {
        format!("{:016x}{:016x}", self.high, self.low)
    }
}

impl fmt::Debug for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TraceId({})", self.to_hex())
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// 64-bit span identifier
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpanId(u64);

impl SpanId {
    /// Create a new span ID
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Generate a random span ID
    pub fn generate() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        Self((timestamp << 16) | (counter & 0xFFFF))
    }

    /// Create an invalid (zero) span ID
    pub fn invalid() -> Self {
        Self(0)
    }

    /// Check if this span ID is valid (non-zero)
    pub fn is_valid(&self) -> bool {
        self.0 != 0
    }

    /// Get the raw value
    pub fn value(&self) -> u64 {
        self.0
    }

    /// Convert to bytes (big-endian)
    pub fn to_bytes(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Create from bytes (big-endian)
    pub fn from_bytes(bytes: &[u8; 8]) -> Self {
        Self(u64::from_be_bytes(*bytes))
    }

    /// Parse from hex string (16 characters)
    pub fn from_hex(hex: &str) -> TracingResult<Self> {
        if hex.len() != 16 {
            return Err(TracingError::InvalidSpanId(format!(
                "expected 16 hex chars, got {}",
                hex.len()
            )));
        }

        let id = u64::from_str_radix(hex, 16)
            .map_err(|e| TracingError::InvalidSpanId(format!("invalid hex: {}", e)))?;

        Ok(Self(id))
    }

    /// Convert to hex string (16 characters)
    pub fn to_hex(&self) -> String {
        format!("{:016x}", self.0)
    }
}

impl fmt::Debug for SpanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SpanId({})", self.to_hex())
    }
}

impl fmt::Display for SpanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Span kind (role in the trace)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SpanKind {
    /// Internal operation (default)
    #[default]
    Internal,

    /// Server-side of a synchronous RPC
    Server,

    /// Client-side of a synchronous RPC
    Client,

    /// Producer of an async message
    Producer,

    /// Consumer of an async message
    Consumer,
}

impl SpanKind {
    /// Parse from string
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "INTERNAL" => Some(Self::Internal),
            "SERVER" => Some(Self::Server),
            "CLIENT" => Some(Self::Client),
            "PRODUCER" => Some(Self::Producer),
            "CONSUMER" => Some(Self::Consumer),
            _ => None,
        }
    }
}

/// Span status code
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StatusCode {
    /// Unset (default)
    #[default]
    Unset,

    /// Operation completed successfully
    Ok,

    /// Operation failed with an error
    Error,
}

/// Span status
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpanStatus {
    /// Status code
    pub code: StatusCode,

    /// Optional error message
    pub message: Option<String>,
}

impl SpanStatus {
    /// Create an OK status
    pub fn ok() -> Self {
        Self {
            code: StatusCode::Ok,
            message: None,
        }
    }

    /// Create an error status
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            code: StatusCode::Error,
            message: Some(message.into()),
        }
    }

    /// Create an unset status
    pub fn unset() -> Self {
        Self::default()
    }
}

/// Attribute value types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttributeValue {
    /// String value
    String(String),

    /// Boolean value
    Bool(bool),

    /// Integer value
    Int(i64),

    /// Float value
    Float(f64),

    /// String array
    StringArray(Vec<String>),

    /// Boolean array
    BoolArray(Vec<bool>),

    /// Integer array
    IntArray(Vec<i64>),

    /// Float array
    FloatArray(Vec<f64>),
}

impl From<String> for AttributeValue {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<&str> for AttributeValue {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

impl From<bool> for AttributeValue {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

impl From<i64> for AttributeValue {
    fn from(i: i64) -> Self {
        Self::Int(i)
    }
}

impl From<i32> for AttributeValue {
    fn from(i: i32) -> Self {
        Self::Int(i as i64)
    }
}

impl From<f64> for AttributeValue {
    fn from(f: f64) -> Self {
        Self::Float(f)
    }
}

/// Span event (timestamped annotation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanEvent {
    /// Event name
    pub name: String,

    /// Event timestamp
    pub timestamp: DateTime<Utc>,

    /// Event attributes
    pub attributes: HashMap<String, AttributeValue>,
}

impl SpanEvent {
    /// Create a new event
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            timestamp: Utc::now(),
            attributes: HashMap::new(),
        }
    }

    /// Add an attribute
    pub fn with_attribute(
        mut self,
        key: impl Into<String>,
        value: impl Into<AttributeValue>,
    ) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }
}

/// Link to another span
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanLink {
    /// Trace ID of the linked span
    pub trace_id: TraceId,

    /// Span ID of the linked span
    pub span_id: SpanId,

    /// Link attributes
    pub attributes: HashMap<String, AttributeValue>,
}

impl SpanLink {
    /// Create a new link
    pub fn new(trace_id: TraceId, span_id: SpanId) -> Self {
        Self {
            trace_id,
            span_id,
            attributes: HashMap::new(),
        }
    }

    /// Add an attribute
    pub fn with_attribute(
        mut self,
        key: impl Into<String>,
        value: impl Into<AttributeValue>,
    ) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }
}

/// A trace span representing a single operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Span {
    /// Span name
    pub name: String,

    /// Trace ID
    pub trace_id: TraceId,

    /// Span ID
    pub span_id: SpanId,

    /// Parent span ID (if any)
    pub parent_span_id: Option<SpanId>,

    /// Span kind
    pub kind: SpanKind,

    /// Start time
    pub start_time: DateTime<Utc>,

    /// End time (None if still active)
    pub end_time: Option<DateTime<Utc>>,

    /// Span status
    pub status: SpanStatus,

    /// Span attributes
    pub attributes: HashMap<String, AttributeValue>,

    /// Span events
    pub events: Vec<SpanEvent>,

    /// Links to other spans
    pub links: Vec<SpanLink>,

    /// Whether this span was sampled
    pub is_sampled: bool,

    /// Whether this span is recording
    pub is_recording: bool,
}

impl Span {
    /// Create a new span
    pub fn new(name: impl Into<String>, trace_id: TraceId) -> Self {
        Self {
            name: name.into(),
            trace_id,
            span_id: SpanId::generate(),
            parent_span_id: None,
            kind: SpanKind::Internal,
            start_time: Utc::now(),
            end_time: None,
            status: SpanStatus::default(),
            attributes: HashMap::new(),
            events: Vec::new(),
            links: Vec::new(),
            is_sampled: true,
            is_recording: true,
        }
    }

    /// Create a child span
    pub fn child(&self, name: impl Into<String>) -> Self {
        let mut child = Span::new(name, self.trace_id);
        child.parent_span_id = Some(self.span_id);
        child.is_sampled = self.is_sampled;
        child
    }

    /// Set the span kind
    pub fn with_kind(mut self, kind: SpanKind) -> Self {
        self.kind = kind;
        self
    }

    /// Set the parent span
    pub fn with_parent(mut self, parent_span_id: SpanId) -> Self {
        self.parent_span_id = Some(parent_span_id);
        self
    }

    /// Add an attribute
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<AttributeValue>) {
        if self.is_recording {
            self.attributes.insert(key.into(), value.into());
        }
    }

    /// Add an event
    pub fn add_event(&mut self, event: SpanEvent) {
        if self.is_recording {
            self.events.push(event);
        }
    }

    /// Add a simple event
    pub fn add_event_simple(&mut self, name: impl Into<String>) {
        self.add_event(SpanEvent::new(name));
    }

    /// Add a link
    pub fn add_link(&mut self, link: SpanLink) {
        if self.is_recording {
            self.links.push(link);
        }
    }

    /// Set the status
    pub fn set_status(&mut self, status: SpanStatus) {
        self.status = status;
    }

    /// Set OK status
    pub fn set_ok(&mut self) {
        self.status = SpanStatus::ok();
    }

    /// Set error status
    pub fn set_error(&mut self, message: impl Into<String>) {
        self.status = SpanStatus::error(message);
    }

    /// End the span
    pub fn end(&mut self) {
        if self.end_time.is_none() {
            self.end_time = Some(Utc::now());
            self.is_recording = false;
        }
    }

    /// Check if the span has ended
    pub fn is_ended(&self) -> bool {
        self.end_time.is_some()
    }

    /// Get the duration of the span
    pub fn duration(&self) -> Option<chrono::Duration> {
        self.end_time.map(|end| end - self.start_time)
    }

    /// Get duration in milliseconds
    pub fn duration_ms(&self) -> Option<i64> {
        self.duration().map(|d| d.num_milliseconds())
    }
}

/// Builder for creating spans with fluent API
pub struct SpanBuilder {
    name: String,
    trace_id: Option<TraceId>,
    parent_span_id: Option<SpanId>,
    kind: SpanKind,
    attributes: HashMap<String, AttributeValue>,
    links: Vec<SpanLink>,
    is_sampled: bool,
}

impl SpanBuilder {
    /// Create a new span builder
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            trace_id: None,
            parent_span_id: None,
            kind: SpanKind::Internal,
            attributes: HashMap::new(),
            links: Vec::new(),
            is_sampled: true,
        }
    }

    /// Set the trace ID
    pub fn trace_id(mut self, trace_id: TraceId) -> Self {
        self.trace_id = Some(trace_id);
        self
    }

    /// Set the parent span ID
    pub fn parent(mut self, parent_span_id: SpanId) -> Self {
        self.parent_span_id = Some(parent_span_id);
        self
    }

    /// Set the span kind
    pub fn kind(mut self, kind: SpanKind) -> Self {
        self.kind = kind;
        self
    }

    /// Add an attribute
    pub fn attribute(mut self, key: impl Into<String>, value: impl Into<AttributeValue>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Add a link
    pub fn link(mut self, link: SpanLink) -> Self {
        self.links.push(link);
        self
    }

    /// Set sampling decision
    pub fn sampled(mut self, sampled: bool) -> Self {
        self.is_sampled = sampled;
        self
    }

    /// Build the span
    pub fn build(self) -> Span {
        let trace_id = self.trace_id.unwrap_or_else(TraceId::generate);
        let mut span = Span::new(self.name, trace_id);
        span.parent_span_id = self.parent_span_id;
        span.kind = self.kind;
        span.attributes = self.attributes;
        span.links = self.links;
        span.is_sampled = self.is_sampled;
        span.is_recording = self.is_sampled;
        span
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_id_generate() {
        let id1 = TraceId::generate();
        let id2 = TraceId::generate();
        assert!(id1.is_valid());
        assert!(id2.is_valid());
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_trace_id_hex() {
        let id = TraceId::new(0x0123456789abcdef, 0xfedcba9876543210);
        let hex = id.to_hex();
        assert_eq!(hex, "0123456789abcdeffedcba9876543210");

        let parsed = TraceId::from_hex(&hex).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn test_trace_id_invalid() {
        let id = TraceId::invalid();
        assert!(!id.is_valid());
    }

    #[test]
    fn test_span_id_generate() {
        let id1 = SpanId::generate();
        let id2 = SpanId::generate();
        assert!(id1.is_valid());
        assert!(id2.is_valid());
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_span_id_hex() {
        let id = SpanId::new(0x0123456789abcdef);
        let hex = id.to_hex();
        assert_eq!(hex, "0123456789abcdef");

        let parsed = SpanId::from_hex(&hex).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn test_span_creation() {
        let span = Span::new("test-span", TraceId::generate());
        assert_eq!(span.name, "test-span");
        assert!(span.span_id.is_valid());
        assert!(span.is_recording);
        assert!(!span.is_ended());
    }

    #[test]
    fn test_span_child() {
        let parent = Span::new("parent", TraceId::generate());
        let child = parent.child("child");

        assert_eq!(child.trace_id, parent.trace_id);
        assert_eq!(child.parent_span_id, Some(parent.span_id));
        assert_ne!(child.span_id, parent.span_id);
    }

    #[test]
    fn test_span_attributes() {
        let mut span = Span::new("test", TraceId::generate());
        span.set_attribute("string_key", "value");
        span.set_attribute("int_key", 42i64);
        span.set_attribute("bool_key", true);

        assert!(span.attributes.contains_key("string_key"));
        assert!(span.attributes.contains_key("int_key"));
        assert!(span.attributes.contains_key("bool_key"));
    }

    #[test]
    fn test_span_events() {
        let mut span = Span::new("test", TraceId::generate());
        span.add_event_simple("event1");
        span.add_event(SpanEvent::new("event2").with_attribute("key", "value"));

        assert_eq!(span.events.len(), 2);
        assert_eq!(span.events[0].name, "event1");
        assert_eq!(span.events[1].name, "event2");
    }

    #[test]
    fn test_span_end() {
        let mut span = Span::new("test", TraceId::generate());
        assert!(!span.is_ended());

        span.end();
        assert!(span.is_ended());
        assert!(span.duration().is_some());
    }

    #[test]
    fn test_span_status() {
        let mut span = Span::new("test", TraceId::generate());
        assert_eq!(span.status.code, StatusCode::Unset);

        span.set_ok();
        assert_eq!(span.status.code, StatusCode::Ok);

        span.set_error("something failed");
        assert_eq!(span.status.code, StatusCode::Error);
        assert_eq!(span.status.message, Some("something failed".to_string()));
    }

    #[test]
    fn test_span_builder() {
        let span = SpanBuilder::new("test-span")
            .kind(SpanKind::Server)
            .attribute("http.method", "GET")
            .attribute("http.url", "/api/test")
            .sampled(true)
            .build();

        assert_eq!(span.name, "test-span");
        assert_eq!(span.kind, SpanKind::Server);
        assert!(span.attributes.contains_key("http.method"));
    }

    #[test]
    fn test_span_kind_parse() {
        assert_eq!(SpanKind::parse("SERVER"), Some(SpanKind::Server));
        assert_eq!(SpanKind::parse("client"), Some(SpanKind::Client));
        assert_eq!(SpanKind::parse("invalid"), None);
    }

    #[test]
    fn test_span_link() {
        let link = SpanLink::new(TraceId::generate(), SpanId::generate())
            .with_attribute("reason", "caused_by");

        assert!(link.trace_id.is_valid());
        assert!(link.attributes.contains_key("reason"));
    }
}
