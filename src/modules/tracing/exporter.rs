//! Trace exporters

use super::config::ExporterType;
use super::error::{TracingError, TracingResult};
use super::span::Span;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Trait for span exporters
pub trait SpanExporter: Send + Sync {
    /// Export a batch of spans
    fn export(&self, spans: &[Span]) -> TracingResult<()>;

    /// Shutdown the exporter
    fn shutdown(&self) -> TracingResult<()>;

    /// Force flush any buffered spans
    fn force_flush(&self) -> TracingResult<()>;
}

/// No-op exporter (does nothing)
#[derive(Debug, Default)]
pub struct NoopExporter;

impl NoopExporter {
    /// Create a new no-op exporter
    pub fn new() -> Self {
        Self
    }
}

impl SpanExporter for NoopExporter {
    fn export(&self, _spans: &[Span]) -> TracingResult<()> {
        Ok(())
    }

    fn shutdown(&self) -> TracingResult<()> {
        Ok(())
    }

    fn force_flush(&self) -> TracingResult<()> {
        Ok(())
    }
}

/// Console exporter (writes to stdout)
#[derive(Debug, Default)]
pub struct ConsoleExporter {
    /// Pretty print JSON
    pretty: bool,
}

impl ConsoleExporter {
    /// Create a new console exporter
    pub fn new() -> Self {
        Self { pretty: false }
    }

    /// Create a pretty-printing console exporter
    pub fn pretty() -> Self {
        Self { pretty: true }
    }
}

impl SpanExporter for ConsoleExporter {
    fn export(&self, spans: &[Span]) -> TracingResult<()> {
        for span in spans {
            let json = if self.pretty {
                serde_json::to_string_pretty(span)?
            } else {
                serde_json::to_string(span)?
            };
            println!("{}", json);
        }
        Ok(())
    }

    fn shutdown(&self) -> TracingResult<()> {
        Ok(())
    }

    fn force_flush(&self) -> TracingResult<()> {
        Ok(())
    }
}

/// In-memory exporter (for testing)
#[derive(Debug, Default)]
pub struct InMemoryExporter {
    /// Stored spans
    spans: Mutex<Vec<Span>>,

    /// Maximum spans to store
    max_spans: usize,
}

impl InMemoryExporter {
    /// Create a new in-memory exporter
    pub fn new() -> Self {
        Self {
            spans: Mutex::new(Vec::new()),
            max_spans: 10000,
        }
    }

    /// Create with a maximum span limit
    pub fn with_max_spans(max_spans: usize) -> Self {
        Self {
            spans: Mutex::new(Vec::new()),
            max_spans,
        }
    }

    /// Get all exported spans
    pub fn get_spans(&self) -> Vec<Span> {
        self.spans.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// Get span count
    pub fn span_count(&self) -> usize {
        self.spans.lock().map(|s| s.len()).unwrap_or(0)
    }

    /// Clear all spans
    pub fn clear(&self) {
        if let Ok(mut spans) = self.spans.lock() {
            spans.clear();
        }
    }

    /// Find spans by name
    pub fn find_by_name(&self, name: &str) -> Vec<Span> {
        self.spans
            .lock()
            .map(|spans| spans.iter().filter(|s| s.name == name).cloned().collect())
            .unwrap_or_default()
    }
}

impl SpanExporter for InMemoryExporter {
    fn export(&self, spans: &[Span]) -> TracingResult<()> {
        let mut stored = self
            .spans
            .lock()
            .map_err(|_| TracingError::Export("lock poisoned".to_string()))?;

        for span in spans {
            if stored.len() < self.max_spans {
                stored.push(span.clone());
            }
        }

        Ok(())
    }

    fn shutdown(&self) -> TracingResult<()> {
        Ok(())
    }

    fn force_flush(&self) -> TracingResult<()> {
        Ok(())
    }
}

/// OTLP span data format
#[derive(Debug, Clone, Serialize)]
pub struct OtlpSpan {
    /// Trace ID (hex)
    #[serde(rename = "traceId")]
    pub trace_id: String,

    /// Span ID (hex)
    #[serde(rename = "spanId")]
    pub span_id: String,

    /// Parent span ID (hex, optional)
    #[serde(rename = "parentSpanId", skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,

    /// Span name
    pub name: String,

    /// Span kind
    pub kind: u8,

    /// Start time (nanoseconds since epoch)
    #[serde(rename = "startTimeUnixNano")]
    pub start_time_unix_nano: u64,

    /// End time (nanoseconds since epoch)
    #[serde(rename = "endTimeUnixNano")]
    pub end_time_unix_nano: u64,

    /// Attributes
    pub attributes: Vec<OtlpAttribute>,

    /// Events
    pub events: Vec<OtlpEvent>,

    /// Status
    pub status: OtlpStatus,
}

/// OTLP attribute
#[derive(Debug, Clone, Serialize)]
pub struct OtlpAttribute {
    /// Key
    pub key: String,

    /// Value
    pub value: OtlpValue,
}

/// OTLP value
#[derive(Debug, Clone, Serialize)]
pub struct OtlpValue {
    /// String value
    #[serde(rename = "stringValue", skip_serializing_if = "Option::is_none")]
    pub string_value: Option<String>,

    /// Int value
    #[serde(rename = "intValue", skip_serializing_if = "Option::is_none")]
    pub int_value: Option<i64>,

    /// Bool value
    #[serde(rename = "boolValue", skip_serializing_if = "Option::is_none")]
    pub bool_value: Option<bool>,

    /// Double value
    #[serde(rename = "doubleValue", skip_serializing_if = "Option::is_none")]
    pub double_value: Option<f64>,
}

/// OTLP event
#[derive(Debug, Clone, Serialize)]
pub struct OtlpEvent {
    /// Name
    pub name: String,

    /// Time (nanoseconds since epoch)
    #[serde(rename = "timeUnixNano")]
    pub time_unix_nano: u64,

    /// Attributes
    pub attributes: Vec<OtlpAttribute>,
}

/// OTLP status
#[derive(Debug, Clone, Serialize)]
pub struct OtlpStatus {
    /// Status code (0=Unset, 1=Ok, 2=Error)
    pub code: u8,

    /// Status message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl From<&Span> for OtlpSpan {
    fn from(span: &Span) -> Self {
        use super::span::{AttributeValue, SpanKind, StatusCode};

        let kind = match span.kind {
            SpanKind::Internal => 0,
            SpanKind::Server => 1,
            SpanKind::Client => 2,
            SpanKind::Producer => 3,
            SpanKind::Consumer => 4,
        };

        let status_code = match span.status.code {
            StatusCode::Unset => 0,
            StatusCode::Ok => 1,
            StatusCode::Error => 2,
        };

        let attributes: Vec<OtlpAttribute> = span
            .attributes
            .iter()
            .map(|(k, v)| {
                let value = match v {
                    AttributeValue::String(s) => OtlpValue {
                        string_value: Some(s.clone()),
                        int_value: None,
                        bool_value: None,
                        double_value: None,
                    },
                    AttributeValue::Int(i) => OtlpValue {
                        string_value: None,
                        int_value: Some(*i),
                        bool_value: None,
                        double_value: None,
                    },
                    AttributeValue::Bool(b) => OtlpValue {
                        string_value: None,
                        int_value: None,
                        bool_value: Some(*b),
                        double_value: None,
                    },
                    AttributeValue::Float(f) => OtlpValue {
                        string_value: None,
                        int_value: None,
                        bool_value: None,
                        double_value: Some(*f),
                    },
                    _ => OtlpValue {
                        string_value: Some(format!("{:?}", v)),
                        int_value: None,
                        bool_value: None,
                        double_value: None,
                    },
                };
                OtlpAttribute {
                    key: k.clone(),
                    value,
                }
            })
            .collect();

        let events: Vec<OtlpEvent> = span
            .events
            .iter()
            .map(|e| OtlpEvent {
                name: e.name.clone(),
                time_unix_nano: e.timestamp.timestamp_nanos_opt().unwrap_or(0) as u64,
                attributes: e
                    .attributes
                    .iter()
                    .map(|(k, v)| OtlpAttribute {
                        key: k.clone(),
                        value: OtlpValue {
                            string_value: Some(format!("{:?}", v)),
                            int_value: None,
                            bool_value: None,
                            double_value: None,
                        },
                    })
                    .collect(),
            })
            .collect();

        Self {
            trace_id: span.trace_id.to_hex(),
            span_id: span.span_id.to_hex(),
            parent_span_id: span.parent_span_id.map(|id| id.to_hex()),
            name: span.name.clone(),
            kind,
            start_time_unix_nano: span.start_time.timestamp_nanos_opt().unwrap_or(0) as u64,
            end_time_unix_nano: span
                .end_time
                .and_then(|t| t.timestamp_nanos_opt())
                .unwrap_or(0) as u64,
            attributes,
            events,
            status: OtlpStatus {
                code: status_code,
                message: span.status.message.clone(),
            },
        }
    }
}

/// Jaeger span format
#[derive(Debug, Clone, Serialize)]
pub struct JaegerSpan {
    /// Trace ID (hex)
    #[serde(rename = "traceID")]
    pub trace_id: String,

    /// Span ID (hex)
    #[serde(rename = "spanID")]
    pub span_id: String,

    /// Parent span ID (hex)
    #[serde(rename = "parentSpanID")]
    pub parent_span_id: String,

    /// Operation name
    #[serde(rename = "operationName")]
    pub operation_name: String,

    /// References
    pub references: Vec<JaegerReference>,

    /// Flags
    pub flags: u8,

    /// Start time (microseconds)
    #[serde(rename = "startTime")]
    pub start_time: u64,

    /// Duration (microseconds)
    pub duration: u64,

    /// Tags
    pub tags: Vec<JaegerTag>,

    /// Logs
    pub logs: Vec<JaegerLog>,
}

/// Jaeger reference
#[derive(Debug, Clone, Serialize)]
pub struct JaegerReference {
    /// Trace ID
    #[serde(rename = "traceID")]
    pub trace_id: String,

    /// Span ID
    #[serde(rename = "spanID")]
    pub span_id: String,

    /// Reference type
    #[serde(rename = "refType")]
    pub ref_type: String,
}

/// Jaeger tag
#[derive(Debug, Clone, Serialize)]
pub struct JaegerTag {
    /// Key
    pub key: String,

    /// Type
    #[serde(rename = "type")]
    pub tag_type: String,

    /// Value
    pub value: serde_json::Value,
}

/// Jaeger log entry
#[derive(Debug, Clone, Serialize)]
pub struct JaegerLog {
    /// Timestamp (microseconds)
    pub timestamp: u64,

    /// Fields
    pub fields: Vec<JaegerTag>,
}

impl From<&Span> for JaegerSpan {
    fn from(span: &Span) -> Self {
        use super::span::AttributeValue;

        let tags: Vec<JaegerTag> = span
            .attributes
            .iter()
            .map(|(k, v)| {
                let (tag_type, value) = match v {
                    AttributeValue::String(s) => ("string", serde_json::json!(s)),
                    AttributeValue::Bool(b) => ("bool", serde_json::json!(b)),
                    AttributeValue::Int(i) => ("int64", serde_json::json!(i)),
                    AttributeValue::Float(f) => ("float64", serde_json::json!(f)),
                    _ => ("string", serde_json::json!(format!("{:?}", v))),
                };
                JaegerTag {
                    key: k.clone(),
                    tag_type: tag_type.to_string(),
                    value,
                }
            })
            .collect();

        let logs: Vec<JaegerLog> = span
            .events
            .iter()
            .map(|e| JaegerLog {
                timestamp: e.timestamp.timestamp_micros() as u64,
                fields: vec![JaegerTag {
                    key: "event".to_string(),
                    tag_type: "string".to_string(),
                    value: serde_json::json!(e.name),
                }],
            })
            .collect();

        let duration = span
            .end_time
            .map(|end| (end - span.start_time).num_microseconds().unwrap_or(0) as u64)
            .unwrap_or(0);

        Self {
            trace_id: span.trace_id.to_hex(),
            span_id: span.span_id.to_hex(),
            parent_span_id: span
                .parent_span_id
                .map(|id| id.to_hex())
                .unwrap_or_else(|| "0".to_string()),
            operation_name: span.name.clone(),
            references: Vec::new(),
            flags: if span.is_sampled { 1 } else { 0 },
            start_time: span.start_time.timestamp_micros() as u64,
            duration,
            tags,
            logs,
        }
    }
}

/// Zipkin span format
#[derive(Debug, Clone, Serialize)]
pub struct ZipkinSpan {
    /// Trace ID (hex)
    #[serde(rename = "traceId")]
    pub trace_id: String,

    /// Span ID (hex)
    pub id: String,

    /// Parent ID (hex)
    #[serde(rename = "parentId", skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,

    /// Name
    pub name: String,

    /// Kind
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    /// Timestamp (microseconds)
    pub timestamp: u64,

    /// Duration (microseconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u64>,

    /// Local endpoint
    #[serde(rename = "localEndpoint", skip_serializing_if = "Option::is_none")]
    pub local_endpoint: Option<ZipkinEndpoint>,

    /// Tags
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub tags: std::collections::HashMap<String, String>,

    /// Annotations
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub annotations: Vec<ZipkinAnnotation>,
}

/// Zipkin endpoint
#[derive(Debug, Clone, Serialize)]
pub struct ZipkinEndpoint {
    /// Service name
    #[serde(rename = "serviceName")]
    pub service_name: String,

    /// IPv4 address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<String>,

    /// Port
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// Zipkin annotation
#[derive(Debug, Clone, Serialize)]
pub struct ZipkinAnnotation {
    /// Timestamp (microseconds)
    pub timestamp: u64,

    /// Value
    pub value: String,
}

impl ZipkinSpan {
    /// Create from span with service name
    pub fn from_span(span: &Span, service_name: &str) -> Self {
        use super::span::{AttributeValue, SpanKind};

        let kind = match span.kind {
            SpanKind::Server => Some("SERVER"),
            SpanKind::Client => Some("CLIENT"),
            SpanKind::Producer => Some("PRODUCER"),
            SpanKind::Consumer => Some("CONSUMER"),
            SpanKind::Internal => None,
        };

        let tags: std::collections::HashMap<String, String> = span
            .attributes
            .iter()
            .map(|(k, v)| {
                let val = match v {
                    AttributeValue::String(s) => s.clone(),
                    AttributeValue::Bool(b) => b.to_string(),
                    AttributeValue::Int(i) => i.to_string(),
                    AttributeValue::Float(f) => f.to_string(),
                    _ => format!("{:?}", v),
                };
                (k.clone(), val)
            })
            .collect();

        let annotations: Vec<ZipkinAnnotation> = span
            .events
            .iter()
            .map(|e| ZipkinAnnotation {
                timestamp: e.timestamp.timestamp_micros() as u64,
                value: e.name.clone(),
            })
            .collect();

        let duration = span
            .end_time
            .map(|end| (end - span.start_time).num_microseconds().unwrap_or(0) as u64);

        Self {
            trace_id: span.trace_id.to_hex(),
            id: span.span_id.to_hex(),
            parent_id: span.parent_span_id.map(|id| id.to_hex()),
            name: span.name.clone(),
            kind: kind.map(String::from),
            timestamp: span.start_time.timestamp_micros() as u64,
            duration,
            local_endpoint: Some(ZipkinEndpoint {
                service_name: service_name.to_string(),
                ipv4: None,
                port: None,
            }),
            tags,
            annotations,
        }
    }
}

/// Batch span processor
pub struct BatchSpanProcessor {
    /// Exporter
    exporter: Arc<dyn SpanExporter>,

    /// Pending spans
    pending: Mutex<VecDeque<Span>>,

    /// Maximum batch size
    max_batch_size: usize,

    /// Maximum queue size
    max_queue_size: usize,
}

impl BatchSpanProcessor {
    /// Create a new batch processor
    pub fn new(
        exporter: Arc<dyn SpanExporter>,
        max_batch_size: usize,
        max_queue_size: usize,
    ) -> Self {
        Self {
            exporter,
            pending: Mutex::new(VecDeque::new()),
            max_batch_size,
            max_queue_size,
        }
    }

    /// Add a span to the queue
    pub fn on_end(&self, span: Span) -> TracingResult<()> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| TracingError::Export("lock poisoned".to_string()))?;

        // Drop oldest if queue is full
        while pending.len() >= self.max_queue_size {
            pending.pop_front();
        }

        pending.push_back(span);

        // Export if we have a full batch
        if pending.len() >= self.max_batch_size {
            let batch: Vec<Span> = pending.drain(..self.max_batch_size).collect();
            drop(pending); // Release lock before export
            self.exporter.export(&batch)?;
        }

        Ok(())
    }

    /// Flush all pending spans
    pub fn flush(&self) -> TracingResult<()> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| TracingError::Export("lock poisoned".to_string()))?;

        if !pending.is_empty() {
            let batch: Vec<Span> = pending.drain(..).collect();
            drop(pending);
            self.exporter.export(&batch)?;
        }

        self.exporter.force_flush()
    }

    /// Shutdown the processor
    pub fn shutdown(&self) -> TracingResult<()> {
        self.flush()?;
        self.exporter.shutdown()
    }

    /// Get pending span count
    pub fn pending_count(&self) -> usize {
        self.pending.lock().map(|p| p.len()).unwrap_or(0)
    }
}

/// Create an exporter from configuration
pub fn create_exporter(exporter_type: ExporterType) -> Arc<dyn SpanExporter> {
    match exporter_type {
        ExporterType::None => Arc::new(NoopExporter::new()),
        ExporterType::Console => Arc::new(ConsoleExporter::new()),
        ExporterType::Memory => Arc::new(InMemoryExporter::new()),
        // TODO: Implement HTTP-based exporters
        ExporterType::OtlpGrpc
        | ExporterType::OtlpHttp
        | ExporterType::Jaeger
        | ExporterType::Zipkin => Arc::new(NoopExporter::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::tracing::span::TraceId;

    fn create_test_span() -> Span {
        let mut span = Span::new("test-span", TraceId::generate());
        span.set_attribute("test.key", "test.value");
        span.add_event_simple("test-event");
        span.end();
        span
    }

    #[test]
    fn test_noop_exporter() {
        let exporter = NoopExporter::new();
        let span = create_test_span();

        exporter.export(&[span]).unwrap();
        exporter.force_flush().unwrap();
        exporter.shutdown().unwrap();
    }

    #[test]
    fn test_in_memory_exporter() {
        let exporter = InMemoryExporter::new();
        let span = create_test_span();

        exporter.export(std::slice::from_ref(&span)).unwrap();
        assert_eq!(exporter.span_count(), 1);

        let spans = exporter.get_spans();
        assert_eq!(spans[0].name, span.name);

        exporter.clear();
        assert_eq!(exporter.span_count(), 0);
    }

    #[test]
    fn test_in_memory_exporter_find() {
        let exporter = InMemoryExporter::new();

        let mut span1 = Span::new("span-a", TraceId::generate());
        span1.end();
        let mut span2 = Span::new("span-b", TraceId::generate());
        span2.end();
        let mut span3 = Span::new("span-a", TraceId::generate());
        span3.end();

        exporter.export(&[span1, span2, span3]).unwrap();

        let found = exporter.find_by_name("span-a");
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn test_otlp_span_conversion() {
        let span = create_test_span();
        let otlp: OtlpSpan = (&span).into();

        assert_eq!(otlp.trace_id, span.trace_id.to_hex());
        assert_eq!(otlp.span_id, span.span_id.to_hex());
        assert_eq!(otlp.name, span.name);
    }

    #[test]
    fn test_jaeger_span_conversion() {
        let span = create_test_span();
        let jaeger: JaegerSpan = (&span).into();

        assert_eq!(jaeger.trace_id, span.trace_id.to_hex());
        assert_eq!(jaeger.operation_name, span.name);
    }

    #[test]
    fn test_zipkin_span_conversion() {
        let span = create_test_span();
        let zipkin = ZipkinSpan::from_span(&span, "test-service");

        assert_eq!(zipkin.trace_id, span.trace_id.to_hex());
        assert_eq!(zipkin.name, span.name);
        assert_eq!(
            zipkin.local_endpoint.as_ref().unwrap().service_name,
            "test-service"
        );
    }

    #[test]
    fn test_batch_processor() {
        let exporter = Arc::new(InMemoryExporter::new());
        let processor = BatchSpanProcessor::new(exporter.clone(), 5, 100);

        // Add spans below batch size
        for i in 0..3 {
            let mut span = Span::new(format!("span-{}", i), TraceId::generate());
            span.end();
            processor.on_end(span).unwrap();
        }

        // Should still be pending
        assert_eq!(processor.pending_count(), 3);
        assert_eq!(exporter.span_count(), 0);

        // Add more to trigger batch export
        for i in 3..6 {
            let mut span = Span::new(format!("span-{}", i), TraceId::generate());
            span.end();
            processor.on_end(span).unwrap();
        }

        // First 5 should be exported
        assert_eq!(exporter.span_count(), 5);
        assert_eq!(processor.pending_count(), 1);

        // Flush remaining
        processor.flush().unwrap();
        assert_eq!(exporter.span_count(), 6);
        assert_eq!(processor.pending_count(), 0);
    }

    #[test]
    fn test_create_exporter() {
        let exporter = create_exporter(ExporterType::Memory);
        let span = create_test_span();
        exporter.export(&[span]).unwrap();
    }
}
