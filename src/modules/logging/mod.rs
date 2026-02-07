//! # Logging System Module
//!
//! Structured logging system for R0N Gateway with JSON output,
//! log levels, rotation, and sensitive data redaction.
//!
//! ## Features
//!
//! - Structured JSON logging with customizable fields
//! - Multiple log levels (Trace, Debug, Info, Warn, Error)
//! - Log rotation (size-based and time-based)
//! - Sensitive data redaction (passwords, tokens, etc.)
//! - Multiple output targets (file, stdout, stderr)
//! - Async logging with buffering
//! - Context propagation (request IDs, trace IDs)

pub mod config;
pub mod error;
pub mod format;
pub mod handler;
pub mod output;
pub mod redaction;
pub mod rotation;

pub use config::*;
pub use error::*;
pub use format::*;
pub use handler::*;
pub use output::*;
pub use redaction::*;
pub use rotation::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify key types are exported
        let _config = LoggingConfig::default();
        let _level = LogLevel::Info;
        let _format = LogFormat::Json;
    }
}
