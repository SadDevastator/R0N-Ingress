//! Plugin error types.
//!
//! Defines error types for plugin loading, execution, and lifecycle management.

use std::fmt;

/// Result type for plugin operations.
pub type PluginResult<T> = Result<T, PluginError>;

/// Plugin system error.
#[derive(Debug, Clone)]
pub enum PluginError {
    /// Plugin not found.
    NotFound {
        /// Plugin name.
        name: String,
    },

    /// Plugin already exists.
    AlreadyExists {
        /// Plugin name.
        name: String,
    },

    /// Failed to load plugin.
    LoadError {
        /// Plugin path or name.
        source: String,
        /// Error message.
        message: String,
    },

    /// WASM compilation error.
    CompilationError {
        /// Error message.
        message: String,
    },

    /// WASM instantiation error.
    InstantiationError {
        /// Error message.
        message: String,
    },

    /// Plugin execution error.
    ExecutionError {
        /// Function name.
        function: String,
        /// Error message.
        message: String,
    },

    /// Function not found in plugin.
    FunctionNotFound {
        /// Plugin name.
        plugin: String,
        /// Function name.
        function: String,
    },

    /// Invalid function signature.
    InvalidSignature {
        /// Function name.
        function: String,
        /// Expected signature.
        expected: String,
        /// Actual signature.
        actual: String,
    },

    /// Memory access error.
    MemoryError {
        /// Error message.
        message: String,
    },

    /// Resource limit exceeded.
    ResourceLimitExceeded {
        /// Resource type.
        resource: String,
        /// Limit value.
        limit: u64,
        /// Attempted value.
        attempted: u64,
    },

    /// Execution timeout.
    Timeout {
        /// Timeout duration in milliseconds.
        timeout_ms: u64,
    },

    /// Sandbox policy violation.
    PolicyViolation {
        /// Policy that was violated.
        policy: String,
        /// Action that was attempted.
        action: String,
    },

    /// Invalid plugin manifest.
    InvalidManifest {
        /// Error message.
        message: String,
    },

    /// Version mismatch.
    VersionMismatch {
        /// Required version.
        required: String,
        /// Actual version.
        actual: String,
    },

    /// Plugin is in invalid state.
    InvalidState {
        /// Current state.
        current: String,
        /// Expected state.
        expected: String,
    },

    /// Serialization/deserialization error.
    SerializationError {
        /// Error message.
        message: String,
    },

    /// Host function error.
    HostFunctionError {
        /// Function name.
        function: String,
        /// Error message.
        message: String,
    },

    /// Capability not granted.
    CapabilityDenied {
        /// Capability name.
        capability: String,
    },

    /// IO error.
    IoError {
        /// Error message.
        message: String,
    },

    /// Configuration error.
    ConfigError {
        /// Error message.
        message: String,
    },

    /// Internal error.
    Internal {
        /// Error message.
        message: String,
    },
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { name } => {
                write!(f, "Plugin not found: {}", name)
            },
            Self::AlreadyExists { name } => {
                write!(f, "Plugin already exists: {}", name)
            },
            Self::LoadError { source, message } => {
                write!(f, "Failed to load plugin '{}': {}", source, message)
            },
            Self::CompilationError { message } => {
                write!(f, "WASM compilation error: {}", message)
            },
            Self::InstantiationError { message } => {
                write!(f, "WASM instantiation error: {}", message)
            },
            Self::ExecutionError { function, message } => {
                write!(f, "Execution error in '{}': {}", function, message)
            },
            Self::FunctionNotFound { plugin, function } => {
                write!(
                    f,
                    "Function '{}' not found in plugin '{}'",
                    function, plugin
                )
            },
            Self::InvalidSignature {
                function,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Invalid signature for '{}': expected {}, got {}",
                    function, expected, actual
                )
            },
            Self::MemoryError { message } => {
                write!(f, "Memory error: {}", message)
            },
            Self::ResourceLimitExceeded {
                resource,
                limit,
                attempted,
            } => {
                write!(
                    f,
                    "Resource limit exceeded: {} limit is {}, attempted {}",
                    resource, limit, attempted
                )
            },
            Self::Timeout { timeout_ms } => {
                write!(f, "Execution timeout after {}ms", timeout_ms)
            },
            Self::PolicyViolation { policy, action } => {
                write!(f, "Policy violation: {} denied action '{}'", policy, action)
            },
            Self::InvalidManifest { message } => {
                write!(f, "Invalid plugin manifest: {}", message)
            },
            Self::VersionMismatch { required, actual } => {
                write!(f, "Version mismatch: required {}, got {}", required, actual)
            },
            Self::InvalidState { current, expected } => {
                write!(
                    f,
                    "Invalid state: expected {}, currently {}",
                    expected, current
                )
            },
            Self::SerializationError { message } => {
                write!(f, "Serialization error: {}", message)
            },
            Self::HostFunctionError { function, message } => {
                write!(f, "Host function '{}' error: {}", function, message)
            },
            Self::CapabilityDenied { capability } => {
                write!(f, "Capability denied: {}", capability)
            },
            Self::IoError { message } => {
                write!(f, "IO error: {}", message)
            },
            Self::ConfigError { message } => {
                write!(f, "Configuration error: {}", message)
            },
            Self::Internal { message } => {
                write!(f, "Internal error: {}", message)
            },
        }
    }
}

impl std::error::Error for PluginError {}

impl From<std::io::Error> for PluginError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError {
            message: err.to_string(),
        }
    }
}

impl PluginError {
    /// Check if error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Timeout { .. } | Self::ResourceLimitExceeded { .. } | Self::IoError { .. }
        )
    }

    /// Check if error is a security violation.
    pub fn is_security_error(&self) -> bool {
        matches!(
            self,
            Self::PolicyViolation { .. } | Self::CapabilityDenied { .. } | Self::MemoryError { .. }
        )
    }

    /// Check if error indicates plugin is broken.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::CompilationError { .. }
                | Self::InstantiationError { .. }
                | Self::InvalidManifest { .. }
                | Self::VersionMismatch { .. }
        )
    }

    /// Create a load error.
    pub fn load_error(source: impl Into<String>, message: impl Into<String>) -> Self {
        Self::LoadError {
            source: source.into(),
            message: message.into(),
        }
    }

    /// Create an execution error.
    pub fn execution_error(function: impl Into<String>, message: impl Into<String>) -> Self {
        Self::ExecutionError {
            function: function.into(),
            message: message.into(),
        }
    }

    /// Create a function not found error.
    pub fn function_not_found(plugin: impl Into<String>, function: impl Into<String>) -> Self {
        Self::FunctionNotFound {
            plugin: plugin.into(),
            function: function.into(),
        }
    }

    /// Create a timeout error.
    pub fn timeout(timeout_ms: u64) -> Self {
        Self::Timeout { timeout_ms }
    }

    /// Create a policy violation error.
    pub fn policy_violation(policy: impl Into<String>, action: impl Into<String>) -> Self {
        Self::PolicyViolation {
            policy: policy.into(),
            action: action.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = PluginError::NotFound {
            name: "my-plugin".to_string(),
        };
        assert!(err.to_string().contains("my-plugin"));

        let err = PluginError::Timeout { timeout_ms: 5000 };
        assert!(err.to_string().contains("5000"));
    }

    #[test]
    fn test_error_retryable() {
        assert!(PluginError::Timeout { timeout_ms: 100 }.is_retryable());
        assert!(PluginError::IoError {
            message: "".to_string()
        }
        .is_retryable());
        assert!(!PluginError::NotFound {
            name: "".to_string()
        }
        .is_retryable());
    }

    #[test]
    fn test_error_security() {
        assert!(PluginError::PolicyViolation {
            policy: "net".to_string(),
            action: "connect".to_string()
        }
        .is_security_error());
        assert!(PluginError::CapabilityDenied {
            capability: "fs".to_string()
        }
        .is_security_error());
        assert!(!PluginError::Timeout { timeout_ms: 100 }.is_security_error());
    }

    #[test]
    fn test_error_fatal() {
        assert!(PluginError::CompilationError {
            message: "".to_string()
        }
        .is_fatal());
        assert!(PluginError::InvalidManifest {
            message: "".to_string()
        }
        .is_fatal());
        assert!(!PluginError::Timeout { timeout_ms: 100 }.is_fatal());
    }

    #[test]
    fn test_error_constructors() {
        let err = PluginError::load_error("plugin.wasm", "file not found");
        assert!(err.to_string().contains("plugin.wasm"));

        let err = PluginError::execution_error("on_request", "panic");
        assert!(err.to_string().contains("on_request"));

        let err = PluginError::function_not_found("my-plugin", "process");
        assert!(err.to_string().contains("process"));

        let err = PluginError::timeout(3000);
        assert!(err.to_string().contains("3000"));

        let err = PluginError::policy_violation("network", "outbound");
        assert!(err.to_string().contains("network"));
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let plugin_err: PluginError = io_err.into();
        assert!(matches!(plugin_err, PluginError::IoError { .. }));
    }
}
