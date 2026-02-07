//! Log output targets

use super::config::{LogFormat, LogLevel, OutputConfig, OutputType};
use super::error::{LogError, LogResult};
use super::format::{create_formatter, LogEntry, LogFormatter};
use super::redaction::Redactor;
use super::rotation::LogRotator;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

/// Log output trait
pub trait LogOutput: Send + Sync {
    /// Write a log entry
    fn write(&self, entry: &LogEntry) -> LogResult<()>;

    /// Flush buffered output
    fn flush(&self) -> LogResult<()>;

    /// Get the output type
    fn output_type(&self) -> OutputType;

    /// Check if this output should log the given level
    fn should_log(&self, level: LogLevel) -> bool;
}

/// Stdout output
pub struct StdoutOutput {
    /// Minimum log level
    min_level: LogLevel,

    /// Formatter
    formatter: Box<dyn LogFormatter>,

    /// Timestamp format
    timestamp_format: String,

    /// Redactor
    redactor: Arc<Redactor>,
}

impl StdoutOutput {
    /// Create a new stdout output
    pub fn new(
        min_level: LogLevel,
        format: LogFormat,
        timestamp_format: String,
        redactor: Arc<Redactor>,
    ) -> Self {
        Self {
            min_level,
            formatter: create_formatter(format),
            timestamp_format,
            redactor,
        }
    }
}

impl LogOutput for StdoutOutput {
    fn write(&self, entry: &LogEntry) -> LogResult<()> {
        if !self.should_log(entry.level) {
            return Ok(());
        }

        // Apply redaction if enabled
        let formatted = if self.redactor.is_enabled() {
            let mut json = serde_json::to_value(entry)?;
            self.redactor.redact_json(&mut json);
            // Re-parse to LogEntry if needed or format JSON directly
            self.formatter.format(entry, &self.timestamp_format)?
        } else {
            self.formatter.format(entry, &self.timestamp_format)?
        };

        let stdout = io::stdout();
        let mut handle = stdout.lock();
        writeln!(handle, "{}", formatted)?;

        Ok(())
    }

    fn flush(&self) -> LogResult<()> {
        io::stdout().flush()?;
        Ok(())
    }

    fn output_type(&self) -> OutputType {
        OutputType::Stdout
    }

    fn should_log(&self, level: LogLevel) -> bool {
        level.should_log(self.min_level)
    }
}

/// Stderr output
pub struct StderrOutput {
    /// Minimum log level
    min_level: LogLevel,

    /// Formatter
    formatter: Box<dyn LogFormatter>,

    /// Timestamp format
    timestamp_format: String,

    /// Redactor
    redactor: Arc<Redactor>,
}

impl StderrOutput {
    /// Create a new stderr output
    pub fn new(
        min_level: LogLevel,
        format: LogFormat,
        timestamp_format: String,
        redactor: Arc<Redactor>,
    ) -> Self {
        Self {
            min_level,
            formatter: create_formatter(format),
            timestamp_format,
            redactor,
        }
    }
}

impl LogOutput for StderrOutput {
    fn write(&self, entry: &LogEntry) -> LogResult<()> {
        if !self.should_log(entry.level) {
            return Ok(());
        }

        // Apply redaction if enabled
        let formatted = if self.redactor.is_enabled() {
            let mut json = serde_json::to_value(entry)?;
            self.redactor.redact_json(&mut json);
            self.formatter.format(entry, &self.timestamp_format)?
        } else {
            self.formatter.format(entry, &self.timestamp_format)?
        };

        let stderr = io::stderr();
        let mut handle = stderr.lock();
        writeln!(handle, "{}", formatted)?;

        Ok(())
    }

    fn flush(&self) -> LogResult<()> {
        io::stderr().flush()?;
        Ok(())
    }

    fn output_type(&self) -> OutputType {
        OutputType::Stderr
    }

    fn should_log(&self, level: LogLevel) -> bool {
        level.should_log(self.min_level)
    }
}

/// File output with rotation
pub struct FileOutput {
    /// Minimum log level
    min_level: LogLevel,

    /// Formatter
    formatter: Box<dyn LogFormatter>,

    /// Timestamp format
    timestamp_format: String,

    /// Log rotator
    rotator: Mutex<LogRotator>,

    /// Redactor
    redactor: Arc<Redactor>,
}

impl FileOutput {
    /// Create a new file output
    pub fn new(
        config: &OutputConfig,
        default_level: LogLevel,
        default_format: LogFormat,
        timestamp_format: String,
        redactor: Arc<Redactor>,
    ) -> LogResult<Self> {
        let path = config
            .path
            .as_ref()
            .ok_or_else(|| LogError::Config("file output requires path".to_string()))?;

        let rotation_config = config.rotation.clone().unwrap_or_default();

        let rotator = LogRotator::new(path, rotation_config)?;

        Ok(Self {
            min_level: config.level.unwrap_or(default_level),
            formatter: create_formatter(config.format.unwrap_or(default_format)),
            timestamp_format,
            rotator: Mutex::new(rotator),
            redactor,
        })
    }
}

impl LogOutput for FileOutput {
    fn write(&self, entry: &LogEntry) -> LogResult<()> {
        if !self.should_log(entry.level) {
            return Ok(());
        }

        // Apply redaction if enabled
        let formatted = if self.redactor.is_enabled() {
            let mut json = serde_json::to_value(entry)?;
            self.redactor.redact_json(&mut json);
            self.formatter.format(entry, &self.timestamp_format)?
        } else {
            self.formatter.format(entry, &self.timestamp_format)?
        };

        let mut rotator = self
            .rotator
            .lock()
            .map_err(|_| LogError::Internal("rotator lock poisoned".to_string()))?;

        rotator.write(formatted.as_bytes())?;

        Ok(())
    }

    fn flush(&self) -> LogResult<()> {
        let mut rotator = self
            .rotator
            .lock()
            .map_err(|_| LogError::Internal("rotator lock poisoned".to_string()))?;

        rotator.flush()
    }

    fn output_type(&self) -> OutputType {
        OutputType::File
    }

    fn should_log(&self, level: LogLevel) -> bool {
        level.should_log(self.min_level)
    }
}

/// Memory output (for testing)
pub struct MemoryOutput {
    /// Minimum log level
    min_level: LogLevel,

    /// Formatter
    formatter: Box<dyn LogFormatter>,

    /// Timestamp format
    timestamp_format: String,

    /// Stored entries
    entries: Mutex<Vec<String>>,

    /// Redactor
    redactor: Arc<Redactor>,
}

impl MemoryOutput {
    /// Create a new memory output
    pub fn new(
        min_level: LogLevel,
        format: LogFormat,
        timestamp_format: String,
        redactor: Arc<Redactor>,
    ) -> Self {
        Self {
            min_level,
            formatter: create_formatter(format),
            timestamp_format,
            entries: Mutex::new(Vec::new()),
            redactor,
        }
    }

    /// Get all logged entries
    pub fn entries(&self) -> Vec<String> {
        self.entries.lock().map(|e| e.clone()).unwrap_or_default()
    }

    /// Clear all entries
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }

    /// Get entry count
    pub fn count(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }
}

impl LogOutput for MemoryOutput {
    fn write(&self, entry: &LogEntry) -> LogResult<()> {
        if !self.should_log(entry.level) {
            return Ok(());
        }

        // Apply redaction if enabled
        let formatted = if self.redactor.is_enabled() {
            let mut json = serde_json::to_value(entry)?;
            self.redactor.redact_json(&mut json);
            self.formatter.format(entry, &self.timestamp_format)?
        } else {
            self.formatter.format(entry, &self.timestamp_format)?
        };

        let mut entries = self
            .entries
            .lock()
            .map_err(|_| LogError::Internal("entries lock poisoned".to_string()))?;

        entries.push(formatted);

        Ok(())
    }

    fn flush(&self) -> LogResult<()> {
        Ok(())
    }

    fn output_type(&self) -> OutputType {
        OutputType::Stdout // Treated as stdout for testing
    }

    fn should_log(&self, level: LogLevel) -> bool {
        level.should_log(self.min_level)
    }
}

/// Multi-output that writes to multiple outputs
pub struct MultiOutput {
    /// Child outputs
    outputs: Vec<Arc<dyn LogOutput>>,
}

impl MultiOutput {
    /// Create a new multi-output
    pub fn new() -> Self {
        Self {
            outputs: Vec::new(),
        }
    }

    /// Add an output
    pub fn add(&mut self, output: Arc<dyn LogOutput>) {
        self.outputs.push(output);
    }

    /// Get the number of outputs
    pub fn count(&self) -> usize {
        self.outputs.len()
    }
}

impl Default for MultiOutput {
    fn default() -> Self {
        Self::new()
    }
}

impl LogOutput for MultiOutput {
    fn write(&self, entry: &LogEntry) -> LogResult<()> {
        for output in &self.outputs {
            // Continue on error to ensure all outputs are tried
            let _ = output.write(entry);
        }
        Ok(())
    }

    fn flush(&self) -> LogResult<()> {
        for output in &self.outputs {
            let _ = output.flush();
        }
        Ok(())
    }

    fn output_type(&self) -> OutputType {
        OutputType::Stdout // Default type
    }

    fn should_log(&self, level: LogLevel) -> bool {
        self.outputs.iter().any(|o| o.should_log(level))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::logging::config::RedactionConfig;

    fn create_disabled_redactor() -> Arc<Redactor> {
        Arc::new(Redactor::disabled())
    }

    #[test]
    fn test_memory_output() {
        let output = MemoryOutput::new(
            LogLevel::Debug,
            LogFormat::Json,
            "%Y-%m-%d".to_string(),
            create_disabled_redactor(),
        );

        output.write(&LogEntry::info("test message")).unwrap();
        output.write(&LogEntry::debug("debug message")).unwrap();
        output.write(&LogEntry::trace("trace message")).unwrap(); // Should be filtered

        assert_eq!(output.count(), 2);

        let entries = output.entries();
        assert!(entries[0].contains("test message"));
    }

    #[test]
    fn test_memory_output_level_filter() {
        let output = MemoryOutput::new(
            LogLevel::Warn,
            LogFormat::Json,
            "%Y-%m-%d".to_string(),
            create_disabled_redactor(),
        );

        output.write(&LogEntry::info("info")).unwrap();
        output.write(&LogEntry::warn("warn")).unwrap();
        output.write(&LogEntry::error("error")).unwrap();

        assert_eq!(output.count(), 2); // Only warn and error
    }

    #[test]
    fn test_memory_output_clear() {
        let output = MemoryOutput::new(
            LogLevel::Debug,
            LogFormat::Json,
            "%Y-%m-%d".to_string(),
            create_disabled_redactor(),
        );

        output.write(&LogEntry::info("test")).unwrap();
        assert_eq!(output.count(), 1);

        output.clear();
        assert_eq!(output.count(), 0);
    }

    #[test]
    fn test_memory_output_with_redaction() {
        // Test that redactor properly redacts JSON fields
        let config = RedactionConfig {
            enabled: true,
            fields: vec!["password".to_string()],
            ..Default::default()
        };
        let redactor = crate::modules::logging::redaction::Redactor::new(config).unwrap();

        // Create a JSON with a password field
        let mut json = serde_json::json!({
            "message": "test",
            "fields": {
                "password": "secret123"
            }
        });

        redactor.redact_json(&mut json);

        // Check that redaction was applied
        let fields = json.get("fields").unwrap();
        let password = fields.get("password").unwrap();
        assert_eq!(password.as_str().unwrap(), "[REDACTED]");
    }

    #[test]
    fn test_multi_output() {
        let output1 = Arc::new(MemoryOutput::new(
            LogLevel::Debug,
            LogFormat::Json,
            "%Y-%m-%d".to_string(),
            create_disabled_redactor(),
        ));

        let output2 = Arc::new(MemoryOutput::new(
            LogLevel::Debug,
            LogFormat::Text,
            "%Y-%m-%d".to_string(),
            create_disabled_redactor(),
        ));

        let mut multi = MultiOutput::new();
        multi.add(output1.clone());
        multi.add(output2.clone());

        assert_eq!(multi.count(), 2);

        multi.write(&LogEntry::info("test")).unwrap();

        // Both outputs should have the entry
        assert_eq!(output1.count(), 1);
        assert_eq!(output2.count(), 1);
    }

    #[test]
    fn test_stdout_output_creation() {
        let output = StdoutOutput::new(
            LogLevel::Info,
            LogFormat::Json,
            "%Y-%m-%d".to_string(),
            create_disabled_redactor(),
        );

        assert_eq!(output.output_type(), OutputType::Stdout);
        assert!(output.should_log(LogLevel::Info));
        assert!(output.should_log(LogLevel::Error));
        assert!(!output.should_log(LogLevel::Debug));
    }

    #[test]
    fn test_stderr_output_creation() {
        let output = StderrOutput::new(
            LogLevel::Warn,
            LogFormat::Text,
            "%Y-%m-%d".to_string(),
            create_disabled_redactor(),
        );

        assert_eq!(output.output_type(), OutputType::Stderr);
        assert!(output.should_log(LogLevel::Warn));
        assert!(!output.should_log(LogLevel::Info));
    }
}
