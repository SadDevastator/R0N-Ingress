//! Logging configuration

use super::error::{LogError, LogResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Whether logging is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Minimum log level
    #[serde(default)]
    pub level: LogLevel,

    /// Log output format
    #[serde(default)]
    pub format: LogFormat,

    /// Output targets
    #[serde(default)]
    pub outputs: Vec<OutputConfig>,

    /// Redaction configuration
    #[serde(default)]
    pub redaction: RedactionConfig,

    /// Include timestamps
    #[serde(default = "default_true")]
    pub include_timestamp: bool,

    /// Timestamp format (strftime)
    #[serde(default = "default_timestamp_format")]
    pub timestamp_format: String,

    /// Include source location (file:line)
    #[serde(default)]
    pub include_location: bool,

    /// Include module path
    #[serde(default = "default_true")]
    pub include_module: bool,

    /// Buffer size for async logging
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Flush interval in milliseconds
    #[serde(default = "default_flush_interval")]
    pub flush_interval_ms: u64,

    /// Global context fields to include in all logs
    #[serde(default)]
    pub context: std::collections::HashMap<String, String>,
}

fn default_enabled() -> bool {
    true
}

fn default_true() -> bool {
    true
}

fn default_timestamp_format() -> String {
    "%Y-%m-%dT%H:%M:%S%.3fZ".to_string()
}

fn default_buffer_size() -> usize {
    10000
}

fn default_flush_interval() -> u64 {
    100
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            level: LogLevel::Info,
            format: LogFormat::Json,
            outputs: vec![OutputConfig::default()],
            redaction: RedactionConfig::default(),
            include_timestamp: true,
            timestamp_format: default_timestamp_format(),
            include_location: false,
            include_module: true,
            buffer_size: default_buffer_size(),
            flush_interval_ms: default_flush_interval(),
            context: std::collections::HashMap::new(),
        }
    }
}

impl LoggingConfig {
    /// Create a new default configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set log level
    pub fn with_level(mut self, level: LogLevel) -> Self {
        self.level = level;
        self
    }

    /// Builder: set format
    pub fn with_format(mut self, format: LogFormat) -> Self {
        self.format = format;
        self
    }

    /// Builder: add output
    pub fn with_output(mut self, output: OutputConfig) -> Self {
        self.outputs.push(output);
        self
    }

    /// Builder: set redaction config
    pub fn with_redaction(mut self, redaction: RedactionConfig) -> Self {
        self.redaction = redaction;
        self
    }

    /// Builder: add context field
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> LogResult<()> {
        for output in &self.outputs {
            output.validate()?;
        }
        Ok(())
    }
}

/// Log level
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Most verbose - trace execution flow
    Trace,
    /// Debug information
    Debug,
    /// General information
    #[serde(alias = "INFO")]
    #[default]
    Info,
    /// Warnings
    Warn,
    /// Errors
    Error,
}

impl LogLevel {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }

    /// Parse from string
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "trace" => Some(Self::Trace),
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "warn" | "warning" => Some(Self::Warn),
            "error" => Some(Self::Error),
            _ => None,
        }
    }

    /// Check if this level should be logged given a minimum level
    pub fn should_log(&self, min_level: LogLevel) -> bool {
        *self >= min_level
    }
}

/// Log output format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// JSON format (structured)
    #[default]
    Json,
    /// Plain text format
    Text,
    /// Compact text format
    Compact,
    /// Logfmt format (key=value pairs)
    Logfmt,
}

impl LogFormat {
    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Text => "text",
            Self::Compact => "compact",
            Self::Logfmt => "logfmt",
        }
    }
}

/// Output target configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Output type
    #[serde(default)]
    pub output_type: OutputType,

    /// Minimum level for this output
    pub level: Option<LogLevel>,

    /// Format override for this output
    pub format: Option<LogFormat>,

    /// File path (for file output)
    pub path: Option<PathBuf>,

    /// Rotation configuration
    pub rotation: Option<RotationConfig>,

    /// Whether to append to file
    #[serde(default = "default_true")]
    pub append: bool,

    /// Buffer writes
    #[serde(default = "default_true")]
    pub buffered: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            output_type: OutputType::Stdout,
            level: None,
            format: None,
            path: None,
            rotation: None,
            append: true,
            buffered: true,
        }
    }
}

impl OutputConfig {
    /// Create stdout output
    pub fn stdout() -> Self {
        Self {
            output_type: OutputType::Stdout,
            ..Default::default()
        }
    }

    /// Create stderr output
    pub fn stderr() -> Self {
        Self {
            output_type: OutputType::Stderr,
            ..Default::default()
        }
    }

    /// Create file output
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self {
            output_type: OutputType::File,
            path: Some(path.into()),
            rotation: Some(RotationConfig::default()),
            ..Default::default()
        }
    }

    /// Builder: set level filter
    pub fn with_level(mut self, level: LogLevel) -> Self {
        self.level = Some(level);
        self
    }

    /// Builder: set format
    pub fn with_format(mut self, format: LogFormat) -> Self {
        self.format = Some(format);
        self
    }

    /// Builder: set rotation
    pub fn with_rotation(mut self, rotation: RotationConfig) -> Self {
        self.rotation = Some(rotation);
        self
    }

    /// Validate the output configuration
    pub fn validate(&self) -> LogResult<()> {
        if self.output_type == OutputType::File && self.path.is_none() {
            return Err(LogError::Config("file output requires path".to_string()));
        }
        Ok(())
    }
}

/// Output type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputType {
    /// Standard output
    #[default]
    Stdout,
    /// Standard error
    Stderr,
    /// File output
    File,
    /// Syslog
    Syslog,
    /// Network (UDP)
    Network,
}

/// Log rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    /// Rotation strategy
    #[serde(default)]
    pub strategy: RotationStrategy,

    /// Maximum file size in bytes (for size-based rotation)
    #[serde(default = "default_max_size")]
    pub max_size_bytes: u64,

    /// Maximum age in days (for time-based rotation)
    #[serde(default = "default_max_age")]
    pub max_age_days: u32,

    /// Maximum number of backup files to keep
    #[serde(default = "default_max_backups")]
    pub max_backups: u32,

    /// Compress rotated files
    #[serde(default)]
    pub compress: bool,

    /// Rotation time (for daily rotation, hour of day)
    #[serde(default)]
    pub rotation_hour: u8,
}

fn default_max_size() -> u64 {
    100 * 1024 * 1024 // 100 MB
}

fn default_max_age() -> u32 {
    30
}

fn default_max_backups() -> u32 {
    10
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            strategy: RotationStrategy::Size,
            max_size_bytes: default_max_size(),
            max_age_days: default_max_age(),
            max_backups: default_max_backups(),
            compress: false,
            rotation_hour: 0,
        }
    }
}

impl RotationConfig {
    /// Create size-based rotation
    pub fn by_size(max_bytes: u64) -> Self {
        Self {
            strategy: RotationStrategy::Size,
            max_size_bytes: max_bytes,
            ..Default::default()
        }
    }

    /// Create daily rotation
    pub fn daily() -> Self {
        Self {
            strategy: RotationStrategy::Daily,
            ..Default::default()
        }
    }

    /// Create hourly rotation
    pub fn hourly() -> Self {
        Self {
            strategy: RotationStrategy::Hourly,
            ..Default::default()
        }
    }

    /// Builder: set max backups
    pub fn with_max_backups(mut self, count: u32) -> Self {
        self.max_backups = count;
        self
    }

    /// Builder: enable compression
    pub fn with_compression(mut self) -> Self {
        self.compress = true;
        self
    }
}

/// Rotation strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RotationStrategy {
    /// Rotate when file exceeds size limit
    #[default]
    Size,
    /// Rotate daily
    Daily,
    /// Rotate hourly
    Hourly,
    /// Never rotate
    Never,
}

/// Sensitive data redaction configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionConfig {
    /// Whether redaction is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Fields to redact (exact match)
    #[serde(default = "default_redact_fields")]
    pub fields: Vec<String>,

    /// Patterns to redact (regex)
    #[serde(default = "default_redact_patterns")]
    pub patterns: Vec<String>,

    /// Replacement string
    #[serde(default = "default_replacement")]
    pub replacement: String,

    /// Redact in values only (not keys)
    #[serde(default = "default_true")]
    pub values_only: bool,

    /// Case insensitive matching
    #[serde(default = "default_true")]
    pub case_insensitive: bool,
}

fn default_redact_fields() -> Vec<String> {
    vec![
        "password".to_string(),
        "passwd".to_string(),
        "secret".to_string(),
        "token".to_string(),
        "api_key".to_string(),
        "apikey".to_string(),
        "api-key".to_string(),
        "authorization".to_string(),
        "auth".to_string(),
        "credential".to_string(),
        "credentials".to_string(),
        "private_key".to_string(),
        "privatekey".to_string(),
        "private-key".to_string(),
        "access_token".to_string(),
        "refresh_token".to_string(),
        "session_id".to_string(),
        "sessionid".to_string(),
        "cookie".to_string(),
        "x-api-key".to_string(),
    ]
}

fn default_redact_patterns() -> Vec<String> {
    vec![
        // Credit card numbers (basic pattern)
        r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b".to_string(),
        // SSN
        r"\b\d{3}-\d{2}-\d{4}\b".to_string(),
        // Bearer tokens
        r"Bearer\s+[A-Za-z0-9\-_]+\.?[A-Za-z0-9\-_]*\.?[A-Za-z0-9\-_]*".to_string(),
        // Basic auth
        r"Basic\s+[A-Za-z0-9+/=]+".to_string(),
    ]
}

fn default_replacement() -> String {
    "[REDACTED]".to_string()
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            fields: default_redact_fields(),
            patterns: default_redact_patterns(),
            replacement: default_replacement(),
            values_only: true,
            case_insensitive: true,
        }
    }
}

impl RedactionConfig {
    /// Create with no redaction
    pub fn none() -> Self {
        Self {
            enabled: false,
            fields: Vec::new(),
            patterns: Vec::new(),
            replacement: default_replacement(),
            values_only: true,
            case_insensitive: true,
        }
    }

    /// Create with default sensitive fields
    pub fn standard() -> Self {
        Self::default()
    }

    /// Builder: add field to redact
    pub fn with_field(mut self, field: impl Into<String>) -> Self {
        self.fields.push(field.into());
        self
    }

    /// Builder: add pattern to redact
    pub fn with_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.patterns.push(pattern.into());
        self
    }

    /// Builder: set replacement string
    pub fn with_replacement(mut self, replacement: impl Into<String>) -> Self {
        self.replacement = replacement.into();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = LoggingConfig::default();
        assert!(config.enabled);
        assert_eq!(config.level, LogLevel::Info);
        assert_eq!(config.format, LogFormat::Json);
        assert!(!config.outputs.is_empty());
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn test_log_level_should_log() {
        assert!(LogLevel::Error.should_log(LogLevel::Info));
        assert!(LogLevel::Info.should_log(LogLevel::Info));
        assert!(!LogLevel::Debug.should_log(LogLevel::Info));
        assert!(!LogLevel::Trace.should_log(LogLevel::Info));
    }

    #[test]
    fn test_log_level_parse() {
        assert_eq!(LogLevel::parse("info"), Some(LogLevel::Info));
        assert_eq!(LogLevel::parse("INFO"), Some(LogLevel::Info));
        assert_eq!(LogLevel::parse("warning"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::parse("unknown"), None);
    }

    #[test]
    fn test_output_config_stdout() {
        let output = OutputConfig::stdout();
        assert_eq!(output.output_type, OutputType::Stdout);
        assert!(output.validate().is_ok());
    }

    #[test]
    fn test_output_config_file() {
        let output = OutputConfig::file("/var/log/app.log");
        assert_eq!(output.output_type, OutputType::File);
        assert!(output.path.is_some());
        assert!(output.rotation.is_some());
        assert!(output.validate().is_ok());
    }

    #[test]
    fn test_output_config_file_no_path() {
        let output = OutputConfig {
            output_type: OutputType::File,
            path: None,
            ..Default::default()
        };
        assert!(output.validate().is_err());
    }

    #[test]
    fn test_rotation_config() {
        let rotation = RotationConfig::by_size(50 * 1024 * 1024);
        assert_eq!(rotation.strategy, RotationStrategy::Size);
        assert_eq!(rotation.max_size_bytes, 50 * 1024 * 1024);
    }

    #[test]
    fn test_rotation_daily() {
        let rotation = RotationConfig::daily();
        assert_eq!(rotation.strategy, RotationStrategy::Daily);
    }

    #[test]
    fn test_redaction_config() {
        let config = RedactionConfig::default();
        assert!(config.enabled);
        assert!(!config.fields.is_empty());
        assert!(config.fields.contains(&"password".to_string()));
    }

    #[test]
    fn test_redaction_none() {
        let config = RedactionConfig::none();
        assert!(!config.enabled);
        assert!(config.fields.is_empty());
    }

    #[test]
    fn test_config_builder() {
        let config = LoggingConfig::new()
            .with_level(LogLevel::Debug)
            .with_format(LogFormat::Text)
            .with_context("app", "gateway");

        assert_eq!(config.level, LogLevel::Debug);
        assert_eq!(config.format, LogFormat::Text);
        assert_eq!(config.context.get("app"), Some(&"gateway".to_string()));
    }

    #[test]
    fn test_log_format_as_str() {
        assert_eq!(LogFormat::Json.as_str(), "json");
        assert_eq!(LogFormat::Text.as_str(), "text");
        assert_eq!(LogFormat::Logfmt.as_str(), "logfmt");
    }
}
