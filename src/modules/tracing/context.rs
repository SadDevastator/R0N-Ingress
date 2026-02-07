//! Trace context and propagation context

use super::span::{SpanId, TraceId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Trace flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TraceFlags(u8);

impl TraceFlags {
    /// No flags set
    pub const NONE: Self = Self(0);

    /// Sampled flag
    pub const SAMPLED: Self = Self(0x01);

    /// Create new trace flags
    pub fn new(flags: u8) -> Self {
        Self(flags)
    }

    /// Check if sampled flag is set
    pub fn is_sampled(&self) -> bool {
        (self.0 & 0x01) != 0
    }

    /// Set the sampled flag
    pub fn set_sampled(&mut self, sampled: bool) {
        if sampled {
            self.0 |= 0x01;
        } else {
            self.0 &= !0x01;
        }
    }

    /// Get the raw flags value
    pub fn value(&self) -> u8 {
        self.0
    }

    /// Convert to hex string (2 chars)
    pub fn to_hex(&self) -> String {
        format!("{:02x}", self.0)
    }

    /// Parse from hex string
    pub fn from_hex(hex: &str) -> Option<Self> {
        u8::from_str_radix(hex, 16).ok().map(Self)
    }
}

/// Span context containing trace identity
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpanContext {
    /// Trace ID
    pub trace_id: TraceId,

    /// Span ID
    pub span_id: SpanId,

    /// Trace flags
    pub trace_flags: TraceFlags,

    /// Trace state (vendor-specific data)
    pub trace_state: TraceState,

    /// Whether this is a remote context
    pub is_remote: bool,
}

impl SpanContext {
    /// Create a new span context
    pub fn new(trace_id: TraceId, span_id: SpanId) -> Self {
        Self {
            trace_id,
            span_id,
            trace_flags: TraceFlags::SAMPLED,
            trace_state: TraceState::new(),
            is_remote: false,
        }
    }

    /// Create an invalid span context
    pub fn invalid() -> Self {
        Self {
            trace_id: TraceId::invalid(),
            span_id: SpanId::invalid(),
            trace_flags: TraceFlags::NONE,
            trace_state: TraceState::new(),
            is_remote: false,
        }
    }

    /// Check if this context is valid
    pub fn is_valid(&self) -> bool {
        self.trace_id.is_valid() && self.span_id.is_valid()
    }

    /// Check if this span should be sampled
    pub fn is_sampled(&self) -> bool {
        self.trace_flags.is_sampled()
    }

    /// Set sampled flag
    pub fn with_sampled(mut self, sampled: bool) -> Self {
        self.trace_flags.set_sampled(sampled);
        self
    }

    /// Set as remote context
    pub fn with_remote(mut self, remote: bool) -> Self {
        self.is_remote = remote;
        self
    }

    /// Set trace state
    pub fn with_trace_state(mut self, trace_state: TraceState) -> Self {
        self.trace_state = trace_state;
        self
    }
}

impl Default for SpanContext {
    fn default() -> Self {
        Self::invalid()
    }
}

/// Trace state (W3C tracestate header content)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceState {
    entries: Vec<(String, String)>,
}

impl TraceState {
    /// Maximum entries allowed
    pub const MAX_ENTRIES: usize = 32;

    /// Create a new empty trace state
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Parse from header value
    pub fn from_header(header: &str) -> Self {
        let mut entries = Vec::new();

        for part in header.split(',') {
            let part = part.trim();
            if let Some(eq_pos) = part.find('=') {
                let key = part[..eq_pos].trim().to_string();
                let value = part[eq_pos + 1..].trim().to_string();
                if !key.is_empty() && entries.len() < Self::MAX_ENTRIES {
                    entries.push((key, value));
                }
            }
        }

        Self { entries }
    }

    /// Convert to header value
    pub fn to_header(&self) -> String {
        self.entries
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Get a value by key
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Insert or update a value
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();

        // Remove existing entry with same key
        self.entries.retain(|(k, _)| k != &key);

        // Insert at the beginning (most recent first)
        if self.entries.len() < Self::MAX_ENTRIES {
            self.entries.insert(0, (key, value));
        }
    }

    /// Remove a key
    pub fn remove(&mut self, key: &str) {
        self.entries.retain(|(k, _)| k != key);
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Iterate over entries
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

/// Baggage for propagating key-value pairs across service boundaries
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Baggage {
    items: HashMap<String, BaggageEntry>,
}

/// Single baggage entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaggageEntry {
    /// Value
    pub value: String,

    /// Metadata
    pub metadata: Option<String>,
}

impl Baggage {
    /// Maximum items allowed
    pub const MAX_ITEMS: usize = 180;

    /// Maximum total size in bytes
    pub const MAX_SIZE: usize = 8192;

    /// Create new empty baggage
    pub fn new() -> Self {
        Self {
            items: HashMap::new(),
        }
    }

    /// Get a value
    pub fn get(&self, key: &str) -> Option<&str> {
        self.items.get(key).map(|e| e.value.as_str())
    }

    /// Get an entry with metadata
    pub fn get_entry(&self, key: &str) -> Option<&BaggageEntry> {
        self.items.get(key)
    }

    /// Set a value
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        if self.items.len() < Self::MAX_ITEMS {
            self.items.insert(
                key.into(),
                BaggageEntry {
                    value: value.into(),
                    metadata: None,
                },
            );
        }
    }

    /// Set a value with metadata
    pub fn set_with_metadata(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
        metadata: impl Into<String>,
    ) {
        if self.items.len() < Self::MAX_ITEMS {
            self.items.insert(
                key.into(),
                BaggageEntry {
                    value: value.into(),
                    metadata: Some(metadata.into()),
                },
            );
        }
    }

    /// Remove a key
    pub fn remove(&mut self, key: &str) -> Option<BaggageEntry> {
        self.items.remove(key)
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Get number of items
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Iterate over items
    pub fn iter(&self) -> impl Iterator<Item = (&str, &BaggageEntry)> {
        self.items.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Parse from header value
    pub fn from_header(header: &str) -> Self {
        let mut baggage = Self::new();

        for part in header.split(',') {
            let part = part.trim();
            if let Some(eq_pos) = part.find('=') {
                let key = part[..eq_pos].trim();
                let rest = &part[eq_pos + 1..];

                // Check for metadata (separated by ;)
                let (value, metadata) = if let Some(semi_pos) = rest.find(';') {
                    (rest[..semi_pos].trim(), Some(rest[semi_pos + 1..].trim()))
                } else {
                    (rest.trim(), None)
                };

                if !key.is_empty() {
                    if let Some(meta) = metadata {
                        baggage.set_with_metadata(key, value, meta);
                    } else {
                        baggage.set(key, value);
                    }
                }
            }
        }

        baggage
    }

    /// Convert to header value
    pub fn to_header(&self) -> String {
        self.items
            .iter()
            .map(|(k, v)| {
                if let Some(ref meta) = v.metadata {
                    format!("{}={};{}", k, v.value, meta)
                } else {
                    format!("{}={}", k, v.value)
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Context for trace propagation
#[derive(Debug, Clone, Default)]
pub struct Context {
    /// Span context
    span_context: Option<SpanContext>,

    /// Baggage
    baggage: Baggage,

    /// Additional values
    values: HashMap<String, String>,
}

impl Context {
    /// Create a new empty context
    pub fn new() -> Self {
        Self::default()
    }

    /// Create context with span context
    pub fn with_span_context(span_context: SpanContext) -> Self {
        Self {
            span_context: Some(span_context),
            baggage: Baggage::new(),
            values: HashMap::new(),
        }
    }

    /// Get the span context
    pub fn span_context(&self) -> Option<&SpanContext> {
        self.span_context.as_ref()
    }

    /// Set the span context
    pub fn set_span_context(&mut self, span_context: SpanContext) {
        self.span_context = Some(span_context);
    }

    /// Get the baggage
    pub fn baggage(&self) -> &Baggage {
        &self.baggage
    }

    /// Get mutable baggage
    pub fn baggage_mut(&mut self) -> &mut Baggage {
        &mut self.baggage
    }

    /// Set baggage
    pub fn set_baggage(&mut self, baggage: Baggage) {
        self.baggage = baggage;
    }

    /// Get a custom value
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(|s| s.as_str())
    }

    /// Set a custom value
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.values.insert(key.into(), value.into());
    }

    /// Check if context has a valid span
    pub fn has_valid_span(&self) -> bool {
        self.span_context.as_ref().is_some_and(|c| c.is_valid())
    }
}

/// Thread-local context storage
pub type SharedContext = Arc<RwLock<Context>>;

/// Create a new shared context
pub fn new_shared_context() -> SharedContext {
    Arc::new(RwLock::new(Context::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_flags() {
        let mut flags = TraceFlags::NONE;
        assert!(!flags.is_sampled());

        flags.set_sampled(true);
        assert!(flags.is_sampled());

        let hex = flags.to_hex();
        assert_eq!(hex, "01");

        let parsed = TraceFlags::from_hex(&hex).unwrap();
        assert_eq!(parsed, flags);
    }

    #[test]
    fn test_span_context() {
        let ctx = SpanContext::new(TraceId::generate(), SpanId::generate());
        assert!(ctx.is_valid());
        assert!(ctx.is_sampled());
        assert!(!ctx.is_remote);
    }

    #[test]
    fn test_span_context_invalid() {
        let ctx = SpanContext::invalid();
        assert!(!ctx.is_valid());
    }

    #[test]
    fn test_trace_state() {
        let mut state = TraceState::new();
        state.insert("vendor1", "value1");
        state.insert("vendor2", "value2");

        assert_eq!(state.get("vendor1"), Some("value1"));
        assert_eq!(state.len(), 2);

        let header = state.to_header();
        assert!(header.contains("vendor1=value1"));
    }

    #[test]
    fn test_trace_state_parse() {
        let state = TraceState::from_header("vendor1=value1,vendor2=value2");
        assert_eq!(state.get("vendor1"), Some("value1"));
        assert_eq!(state.get("vendor2"), Some("value2"));
    }

    #[test]
    fn test_baggage() {
        let mut baggage = Baggage::new();
        baggage.set("user_id", "12345");
        baggage.set_with_metadata("session", "abc", "expires=3600");

        assert_eq!(baggage.get("user_id"), Some("12345"));
        assert!(baggage.get_entry("session").unwrap().metadata.is_some());
    }

    #[test]
    fn test_baggage_header() {
        let mut baggage = Baggage::new();
        baggage.set("key1", "value1");
        baggage.set("key2", "value2");

        let header = baggage.to_header();
        assert!(header.contains("key1=value1"));

        let parsed = Baggage::from_header(&header);
        assert_eq!(parsed.get("key1"), Some("value1"));
    }

    #[test]
    fn test_context() {
        let mut ctx = Context::new();
        assert!(!ctx.has_valid_span());

        let span_ctx = SpanContext::new(TraceId::generate(), SpanId::generate());
        ctx.set_span_context(span_ctx);
        assert!(ctx.has_valid_span());

        ctx.baggage_mut().set("key", "value");
        assert_eq!(ctx.baggage().get("key"), Some("value"));
    }

    #[test]
    fn test_shared_context() {
        let shared = new_shared_context();

        {
            let mut ctx = shared.write().unwrap();
            ctx.set("request_id", "12345");
        }

        {
            let ctx = shared.read().unwrap();
            assert_eq!(ctx.get("request_id"), Some("12345"));
        }
    }
}
