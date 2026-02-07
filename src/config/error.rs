//! Configuration error types.

use std::path::PathBuf;
use thiserror::Error;

/// Configuration-related errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Failed to read configuration file.
    #[error("failed to read configuration file '{path}': {source}")]
    ReadError {
        /// Path to the configuration file.
        path: PathBuf,
        /// Underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to parse TOML content.
    #[error("failed to parse TOML: {0}")]
    ParseError(#[from] toml::de::Error),

    /// Configuration validation failed.
    #[error("configuration validation failed: {0}")]
    ValidationError(String),

    /// Missing required field.
    #[error("missing required field: {field}")]
    MissingField {
        /// Name of the missing field.
        field: String,
    },

    /// Invalid field value.
    #[error("invalid value for field '{field}': {message}")]
    InvalidValue {
        /// Name of the field.
        field: String,
        /// Error message.
        message: String,
    },

    /// Configuration file not found.
    #[error("configuration file not found: {0}")]
    NotFound(PathBuf),

    /// Watch error.
    #[error("configuration watch error: {0}")]
    WatchError(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    SerializeError(#[from] toml::ser::Error),
}

/// Result type for configuration operations.
pub type ConfigResult<T> = Result<T, ConfigError>;
