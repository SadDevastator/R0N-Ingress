//! Module error types and result aliases.

use std::fmt;

/// Result type alias for module operations.
pub type ModuleResult<T> = Result<T, ModuleError>;

/// Errors that can occur during module operations.
#[derive(Debug, Clone)]
pub enum ModuleError {
    /// Module failed to initialize.
    InitializationFailed(String),

    /// Module failed to start.
    StartFailed(String),

    /// Module failed to stop gracefully.
    StopFailed(String),

    /// Configuration error.
    ConfigError(String),

    /// Module is in an invalid state for the requested operation.
    InvalidState {
        /// Current state of the module.
        current: String,
        /// Expected state for the operation.
        expected: String,
    },

    /// IPC communication error.
    IpcError(String),

    /// Timeout waiting for operation.
    Timeout(String),

    /// Generic internal error.
    Internal(String),
}

impl fmt::Display for ModuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitializationFailed(msg) => write!(f, "initialization failed: {msg}"),
            Self::StartFailed(msg) => write!(f, "start failed: {msg}"),
            Self::StopFailed(msg) => write!(f, "stop failed: {msg}"),
            Self::ConfigError(msg) => write!(f, "configuration error: {msg}"),
            Self::InvalidState { current, expected } => {
                write!(f, "invalid state: current={current}, expected={expected}")
            },
            Self::IpcError(msg) => write!(f, "IPC error: {msg}"),
            Self::Timeout(msg) => write!(f, "timeout: {msg}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for ModuleError {}
