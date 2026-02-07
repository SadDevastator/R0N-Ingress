//! Log formatting and structured log entries

use super::config::{LogFormat, LogLevel};
use super::error::LogResult;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A structured log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Timestamp of the log entry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,

    /// Log level
    pub level: LogLevel,

    /// Log message
    pub message: String,

    /// Target/module name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,

    /// Source file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,

    /// Source line number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,

    /// Additional structured fields
    #[serde(flatten)]
    pub fields: HashMap<String, serde_json::Value>,

    /// Request ID for correlation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    /// Trace ID for distributed tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,

    /// Span ID for distributed tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
}

impl LogEntry {
    /// Create a new log entry
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            timestamp: Some(Utc::now()),
            level,
            message: message.into(),
            target: None,
            file: None,
            line: None,
            fields: HashMap::new(),
            request_id: None,
            trace_id: None,
            span_id: None,
        }
    }

    /// Create an info entry
    pub fn info(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Info, message)
    }

    /// Create a debug entry
    pub fn debug(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Debug, message)
    }

    /// Create a warn entry
    pub fn warn(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Warn, message)
    }

    /// Create an error entry
    pub fn error(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Error, message)
    }

    /// Create a trace entry
    pub fn trace(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Trace, message)
    }

    /// Builder: set target
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Builder: set source location
    pub fn with_location(mut self, file: impl Into<String>, line: u32) -> Self {
        self.file = Some(file.into());
        self.line = Some(line);
        self
    }

    /// Builder: add a field
    pub fn with_field(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.fields.insert(key.into(), v);
        }
        self
    }

    /// Builder: set request ID
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Builder: set trace context
    pub fn with_trace(mut self, trace_id: impl Into<String>, span_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self.span_id = Some(span_id.into());
        self
    }

    /// Add multiple fields
    pub fn with_fields(mut self, fields: HashMap<String, serde_json::Value>) -> Self {
        self.fields.extend(fields);
        self
    }
}

/// Log formatter trait
pub trait LogFormatter: Send + Sync {
    /// Format a log entry to string
    fn format(&self, entry: &LogEntry, timestamp_format: &str) -> LogResult<String>;

    /// Get the format type
    fn format_type(&self) -> LogFormat;
}

/// JSON log formatter
#[derive(Debug, Default)]
pub struct JsonFormatter {
    /// Pretty print
    pretty: bool,
}

impl JsonFormatter {
    /// Create a new JSON formatter
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a pretty-printing formatter
    pub fn pretty() -> Self {
        Self { pretty: true }
    }
}

impl LogFormatter for JsonFormatter {
    fn format(&self, entry: &LogEntry, _timestamp_format: &str) -> LogResult<String> {
        let json = if self.pretty {
            serde_json::to_string_pretty(entry)?
        } else {
            serde_json::to_string(entry)?
        };
        Ok(json)
    }

    fn format_type(&self) -> LogFormat {
        LogFormat::Json
    }
}

/// Plain text log formatter
#[derive(Debug, Default)]
pub struct TextFormatter {
    /// Include colors (ANSI)
    colors: bool,
}

impl TextFormatter {
    /// Create a new text formatter
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a formatter with colors
    pub fn with_colors() -> Self {
        Self { colors: true }
    }

    fn level_color(&self, level: LogLevel) -> &'static str {
        if !self.colors {
            return "";
        }
        match level {
            LogLevel::Trace => "\x1b[35m", // magenta
            LogLevel::Debug => "\x1b[36m", // cyan
            LogLevel::Info => "\x1b[32m",  // green
            LogLevel::Warn => "\x1b[33m",  // yellow
            LogLevel::Error => "\x1b[31m", // red
        }
    }

    fn reset(&self) -> &'static str {
        if self.colors {
            "\x1b[0m"
        } else {
            ""
        }
    }
}

impl LogFormatter for TextFormatter {
    fn format(&self, entry: &LogEntry, timestamp_format: &str) -> LogResult<String> {
        let mut parts = Vec::new();

        // Timestamp
        if let Some(ts) = &entry.timestamp {
            parts.push(ts.format(timestamp_format).to_string());
        }

        // Level
        parts.push(format!(
            "{}{}{}",
            self.level_color(entry.level),
            entry.level.as_str(),
            self.reset()
        ));

        // Target
        if let Some(target) = &entry.target {
            parts.push(format!("[{}]", target));
        }

        // Message
        parts.push(entry.message.clone());

        // Fields
        if !entry.fields.is_empty() {
            let fields: Vec<String> = entry
                .fields
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            parts.push(fields.join(" "));
        }

        // Request/Trace IDs
        if let Some(req_id) = &entry.request_id {
            parts.push(format!("request_id={}", req_id));
        }
        if let Some(trace_id) = &entry.trace_id {
            parts.push(format!("trace_id={}", trace_id));
        }

        Ok(parts.join(" "))
    }

    fn format_type(&self) -> LogFormat {
        LogFormat::Text
    }
}

/// Compact text formatter (minimal output)
#[derive(Debug, Default)]
pub struct CompactFormatter;

impl CompactFormatter {
    /// Create a new compact formatter
    pub fn new() -> Self {
        Self
    }
}

impl LogFormatter for CompactFormatter {
    fn format(&self, entry: &LogEntry, _timestamp_format: &str) -> LogResult<String> {
        let level_char = match entry.level {
            LogLevel::Trace => 'T',
            LogLevel::Debug => 'D',
            LogLevel::Info => 'I',
            LogLevel::Warn => 'W',
            LogLevel::Error => 'E',
        };

        let target = entry
            .target
            .as_ref()
            .map(|t| format!("[{}] ", t))
            .unwrap_or_default();

        Ok(format!("{} {}{}", level_char, target, entry.message))
    }

    fn format_type(&self) -> LogFormat {
        LogFormat::Compact
    }
}

/// Logfmt formatter (key=value pairs)
#[derive(Debug, Default)]
pub struct LogfmtFormatter;

impl LogfmtFormatter {
    /// Create a new logfmt formatter
    pub fn new() -> Self {
        Self
    }

    fn escape_value(value: &str) -> String {
        if value.contains(' ') || value.contains('"') || value.contains('=') {
            format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
        } else {
            value.to_string()
        }
    }
}

impl LogFormatter for LogfmtFormatter {
    fn format(&self, entry: &LogEntry, timestamp_format: &str) -> LogResult<String> {
        let mut parts = Vec::new();

        // Timestamp
        if let Some(ts) = &entry.timestamp {
            parts.push(format!("ts={}", ts.format(timestamp_format)));
        }

        // Level
        parts.push(format!("level={}", entry.level.as_str().to_lowercase()));

        // Message
        parts.push(format!("msg={}", Self::escape_value(&entry.message)));

        // Target
        if let Some(target) = &entry.target {
            parts.push(format!("target={}", Self::escape_value(target)));
        }

        // Location
        if let (Some(file), Some(line)) = (&entry.file, entry.line) {
            parts.push(format!("file={}", Self::escape_value(file)));
            parts.push(format!("line={}", line));
        }

        // Request/Trace IDs
        if let Some(req_id) = &entry.request_id {
            parts.push(format!("request_id={}", Self::escape_value(req_id)));
        }
        if let Some(trace_id) = &entry.trace_id {
            parts.push(format!("trace_id={}", Self::escape_value(trace_id)));
        }
        if let Some(span_id) = &entry.span_id {
            parts.push(format!("span_id={}", Self::escape_value(span_id)));
        }

        // Additional fields
        for (key, value) in &entry.fields {
            let value_str = match value {
                serde_json::Value::String(s) => Self::escape_value(s),
                other => other.to_string(),
            };
            parts.push(format!("{}={}", key, value_str));
        }

        Ok(parts.join(" "))
    }

    fn format_type(&self) -> LogFormat {
        LogFormat::Logfmt
    }
}

/// Create a formatter for the given format type
pub fn create_formatter(format: LogFormat) -> Box<dyn LogFormatter> {
    match format {
        LogFormat::Json => Box::new(JsonFormatter::new()),
        LogFormat::Text => Box::new(TextFormatter::new()),
        LogFormat::Compact => Box::new(CompactFormatter::new()),
        LogFormat::Logfmt => Box::new(LogfmtFormatter::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry::new(LogLevel::Info, "test message");
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.message, "test message");
        assert!(entry.timestamp.is_some());
    }

    #[test]
    fn test_log_entry_builders() {
        let entry = LogEntry::info("test")
            .with_target("mymodule")
            .with_field("count", 42)
            .with_request_id("req-123");

        assert_eq!(entry.target, Some("mymodule".to_string()));
        assert_eq!(entry.request_id, Some("req-123".to_string()));
        assert!(entry.fields.contains_key("count"));
    }

    #[test]
    fn test_log_entry_convenience() {
        assert_eq!(LogEntry::debug("x").level, LogLevel::Debug);
        assert_eq!(LogEntry::info("x").level, LogLevel::Info);
        assert_eq!(LogEntry::warn("x").level, LogLevel::Warn);
        assert_eq!(LogEntry::error("x").level, LogLevel::Error);
        assert_eq!(LogEntry::trace("x").level, LogLevel::Trace);
    }

    #[test]
    fn test_json_formatter() {
        let formatter = JsonFormatter::new();
        let entry = LogEntry::info("test message")
            .with_target("test")
            .with_field("key", "value");

        let result = formatter.format(&entry, "%Y-%m-%d").unwrap();
        assert!(result.contains("test message"));
        assert!(result.contains("info")); // serde serializes as lowercase
    }

    #[test]
    fn test_text_formatter() {
        let formatter = TextFormatter::new();
        let entry = LogEntry::info("test message").with_target("test");

        let result = formatter.format(&entry, "%Y-%m-%d").unwrap();
        assert!(result.contains("INFO"));
        assert!(result.contains("test message"));
        assert!(result.contains("[test]"));
    }

    #[test]
    fn test_compact_formatter() {
        let formatter = CompactFormatter::new();
        let entry = LogEntry::warn("warning message");

        let result = formatter.format(&entry, "%Y-%m-%d").unwrap();
        assert!(result.starts_with('W'));
        assert!(result.contains("warning message"));
    }

    #[test]
    fn test_logfmt_formatter() {
        let formatter = LogfmtFormatter::new();
        let entry = LogEntry::info("test message")
            .with_target("myapp")
            .with_field("user", "john");

        let result = formatter.format(&entry, "%Y-%m-%d").unwrap();
        assert!(result.contains("level=info"));
        assert!(result.contains("msg="));
        assert!(result.contains("target=myapp"));
    }

    #[test]
    fn test_logfmt_escape() {
        let escaped = LogfmtFormatter::escape_value("hello world");
        assert!(escaped.starts_with('"'));
        assert!(escaped.ends_with('"'));

        let no_escape = LogfmtFormatter::escape_value("simple");
        assert_eq!(no_escape, "simple");
    }

    #[test]
    fn test_create_formatter() {
        let json = create_formatter(LogFormat::Json);
        assert_eq!(json.format_type(), LogFormat::Json);

        let text = create_formatter(LogFormat::Text);
        assert_eq!(text.format_type(), LogFormat::Text);
    }

    #[test]
    fn test_entry_with_trace() {
        let entry = LogEntry::info("traced").with_trace("trace-123", "span-456");

        assert_eq!(entry.trace_id, Some("trace-123".to_string()));
        assert_eq!(entry.span_id, Some("span-456".to_string()));
    }
}
