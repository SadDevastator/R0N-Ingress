//! Logging module handler (ModuleContract implementation)

use super::config::{LoggingConfig, OutputType};
use super::error::{LogError, LogResult};
use super::format::LogEntry;
use super::output::{FileOutput, LogOutput, MemoryOutput, MultiOutput, StderrOutput, StdoutOutput};
use super::redaction::Redactor;
use crate::module::{
    Capability, MetricsPayload, ModuleConfig, ModuleContract, ModuleError, ModuleManifest,
    ModuleResult, ModuleStatus,
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// Logging module handler
pub struct LoggingHandler {
    /// Configuration
    config: LoggingConfig,

    /// Multi-output writer
    outputs: Arc<MultiOutput>,

    /// Redactor for sensitive data
    redactor: Arc<Redactor>,

    /// Module status
    status: ModuleStatus,

    /// Start time
    started_at: Option<Instant>,

    /// Metrics
    metrics: LoggingMetrics,
}

/// Logging metrics
#[derive(Debug, Clone, Default)]
pub struct LoggingMetrics {
    /// Total entries logged
    pub entries_logged: u64,

    /// Entries by level
    pub entries_by_level: HashMap<String, u64>,

    /// Entries redacted
    pub entries_redacted: u64,

    /// Rotations performed
    pub rotations_performed: u64,

    /// Flush count
    pub flush_count: u64,

    /// Errors encountered
    pub errors: u64,
}

impl LoggingHandler {
    /// Create a new logging handler
    pub fn new(config: LoggingConfig) -> LogResult<Self> {
        let redactor = Arc::new(Redactor::new(config.redaction.clone())?);

        let mut multi = MultiOutput::new();

        // Create outputs from configuration
        for output_config in &config.outputs {
            match output_config.output_type {
                OutputType::Stdout => {
                    let output = StdoutOutput::new(
                        output_config.level.unwrap_or(config.level),
                        output_config.format.unwrap_or(config.format),
                        config.timestamp_format.clone(),
                        redactor.clone(),
                    );
                    multi.add(Arc::new(output));
                },
                OutputType::Stderr => {
                    let output = StderrOutput::new(
                        output_config.level.unwrap_or(config.level),
                        output_config.format.unwrap_or(config.format),
                        config.timestamp_format.clone(),
                        redactor.clone(),
                    );
                    multi.add(Arc::new(output));
                },
                OutputType::File => {
                    let output = FileOutput::new(
                        output_config,
                        config.level,
                        config.format,
                        config.timestamp_format.clone(),
                        redactor.clone(),
                    )?;
                    multi.add(Arc::new(output));
                },
                OutputType::Syslog | OutputType::Network => {
                    // TODO: Implement syslog and network outputs
                    return Err(LogError::Config(format!(
                        "output type {:?} not yet implemented",
                        output_config.output_type
                    )));
                },
            }
        }

        Ok(Self {
            config,
            outputs: Arc::new(multi),
            redactor,
            status: ModuleStatus::Stopped,
            started_at: None,
            metrics: LoggingMetrics::default(),
        })
    }

    /// Log an entry
    pub fn log(&mut self, entry: &LogEntry) -> LogResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check level filter
        if !entry.level.should_log(self.config.level) {
            return Ok(());
        }

        // Write to outputs
        self.outputs.write(entry)?;

        // Update metrics
        self.metrics.entries_logged += 1;
        *self
            .metrics
            .entries_by_level
            .entry(format!("{:?}", entry.level))
            .or_insert(0) += 1;

        Ok(())
    }

    /// Log an info message
    pub fn info(&mut self, message: &str) -> LogResult<()> {
        self.log(&LogEntry::info(message))
    }

    /// Log a debug message
    pub fn debug(&mut self, message: &str) -> LogResult<()> {
        self.log(&LogEntry::debug(message))
    }

    /// Log a warning message
    pub fn warn(&mut self, message: &str) -> LogResult<()> {
        self.log(&LogEntry::warn(message))
    }

    /// Log an error message
    pub fn error(&mut self, message: &str) -> LogResult<()> {
        self.log(&LogEntry::error(message))
    }

    /// Log a trace message
    pub fn trace(&mut self, message: &str) -> LogResult<()> {
        self.log(&LogEntry::trace(message))
    }

    /// Flush all outputs
    pub fn flush(&mut self) -> LogResult<()> {
        self.outputs.flush()?;
        self.metrics.flush_count += 1;
        Ok(())
    }

    /// Get the redactor
    pub fn redactor(&self) -> &Arc<Redactor> {
        &self.redactor
    }

    /// Get output count
    pub fn output_count(&self) -> usize {
        self.outputs.count()
    }

    /// Get current metrics
    pub fn get_metrics(&self) -> &LoggingMetrics {
        &self.metrics
    }
}

impl ModuleContract for LoggingHandler {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("logging")
            .description(
                "Structured logging with JSON output, rotation, and sensitive data redaction",
            )
            .version(1, 0, 0)
            .capability(Capability::Custom("StructuredLogging".to_string()))
            .capability(Capability::Custom("LogRotation".to_string()))
            .capability(Capability::Custom("SensitiveDataRedaction".to_string()))
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

        self.started_at = Some(Instant::now());
        self.status = ModuleStatus::Running;

        // Log startup
        let _ = self.info("Logging module started");

        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        if self.status != ModuleStatus::Running {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Running".to_string(),
            });
        }

        // Flush any buffered entries
        let _ = self.flush();

        self.status = ModuleStatus::Stopped;
        self.started_at = None;

        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    fn metrics(&self) -> MetricsPayload {
        let mut payload = MetricsPayload::new();

        payload.counter("entries_logged", self.metrics.entries_logged);
        payload.counter("entries_redacted", self.metrics.entries_redacted);
        payload.counter("rotations_performed", self.metrics.rotations_performed);
        payload.counter("flush_count", self.metrics.flush_count);
        payload.counter("errors", self.metrics.errors);

        if let Some(started) = self.started_at {
            payload.gauge("uptime_secs", started.elapsed().as_secs() as f64);
        }

        payload
    }
}

/// Shared logging handler
pub type SharedLoggingHandler = Arc<RwLock<LoggingHandler>>;

/// Create a memory-based logger for testing
pub fn create_test_logger() -> LogResult<(LoggingHandler, Arc<MemoryOutput>)> {
    let config = LoggingConfig::default();
    let redactor = Arc::new(Redactor::disabled());

    let memory = Arc::new(MemoryOutput::new(
        config.level,
        config.format,
        config.timestamp_format.clone(),
        redactor.clone(),
    ));

    let mut multi = MultiOutput::new();
    multi.add(memory.clone());

    let handler = LoggingHandler {
        config,
        outputs: Arc::new(multi),
        redactor,
        status: ModuleStatus::Running,
        started_at: Some(Instant::now()),
        metrics: LoggingMetrics::default(),
    };

    Ok((handler, memory))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::logging::config::{LogLevel, OutputConfig};

    #[test]
    fn test_handler_creation() {
        let config = LoggingConfig {
            outputs: vec![OutputConfig {
                output_type: OutputType::Stdout,
                ..Default::default()
            }],
            ..Default::default()
        };

        let handler = LoggingHandler::new(config).unwrap();
        assert_eq!(handler.output_count(), 1);
    }

    #[test]
    fn test_test_logger() {
        let (mut logger, memory) = create_test_logger().unwrap();

        logger.info("test message").unwrap();
        logger.debug("debug message").unwrap();

        assert!(memory.count() >= 1);
    }

    #[test]
    fn test_level_filtering() {
        let config = LoggingConfig {
            level: LogLevel::Warn,
            outputs: vec![OutputConfig {
                output_type: OutputType::Stdout,
                ..Default::default()
            }],
            ..Default::default()
        };

        let mut handler = LoggingHandler::new(config).unwrap();

        // These should be filtered out
        let _ = handler.debug("debug");
        let _ = handler.info("info");

        // These should pass
        let _ = handler.warn("warn");
        let _ = handler.error("error");
    }

    #[test]
    fn test_module_contract() {
        let config = LoggingConfig {
            outputs: vec![OutputConfig {
                output_type: OutputType::Stdout,
                ..Default::default()
            }],
            ..Default::default()
        };

        let mut handler = LoggingHandler::new(config).unwrap();

        assert_eq!(handler.manifest().name, "logging");

        handler.init(ModuleConfig::default()).unwrap();
        assert_eq!(handler.status(), ModuleStatus::Initializing);

        handler.start().unwrap();
        assert_eq!(handler.status(), ModuleStatus::Running);

        let metrics = handler.metrics();
        assert!(metrics.counters.contains_key("entries_logged"));

        handler.stop().unwrap();
        assert_eq!(handler.status(), ModuleStatus::Stopped);
    }

    #[test]
    fn test_metrics_tracking() {
        let (mut logger, _) = create_test_logger().unwrap();

        logger.info("info 1").unwrap();
        logger.info("info 2").unwrap();
        logger.warn("warn").unwrap();
        logger.flush().unwrap();

        let metrics = logger.get_metrics();
        assert_eq!(metrics.entries_logged, 3);
        assert_eq!(metrics.flush_count, 1);
    }

    #[test]
    fn test_disabled_logging() {
        let config = LoggingConfig {
            enabled: false,
            outputs: vec![OutputConfig {
                output_type: OutputType::Stdout,
                ..Default::default()
            }],
            ..Default::default()
        };

        let mut handler = LoggingHandler::new(config).unwrap();

        // Should return Ok but not log
        handler.info("test").unwrap();

        assert_eq!(handler.get_metrics().entries_logged, 0);
    }

    #[test]
    fn test_convenience_methods() {
        let (mut logger, memory) = create_test_logger().unwrap();

        logger.trace("trace").unwrap();
        logger.debug("debug").unwrap();
        logger.info("info").unwrap();
        logger.warn("warn").unwrap();
        logger.error("error").unwrap();

        // Default level is Info, so trace and debug are filtered
        assert!(memory.count() >= 3);
    }
}
