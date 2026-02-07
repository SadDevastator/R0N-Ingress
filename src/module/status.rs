//! Module status and health reporting.

use std::time::Instant;

/// Represents the current status of a module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleStatus {
    /// Module is initializing.
    Initializing,

    /// Module is running normally.
    Running,

    /// Module is running but with degraded functionality.
    Degraded {
        /// Reason for degradation.
        reason: String,
    },

    /// Module is paused (not accepting new work).
    Paused,

    /// Module is stopped.
    Stopped,

    /// Module encountered an error.
    Error {
        /// Error message.
        message: String,
    },
}

impl ModuleStatus {
    /// Returns `true` if the module is in a healthy state.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Running)
    }

    /// Returns `true` if the module is operational (running, degraded, or paused).
    #[must_use]
    pub fn is_operational(&self) -> bool {
        matches!(self, Self::Running | Self::Degraded { .. } | Self::Paused)
    }

    /// Returns `true` if the module is paused.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        matches!(self, Self::Paused)
    }

    /// Returns `true` if the module is stopped.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        matches!(self, Self::Stopped)
    }

    /// Returns `true` if the module has an error.
    #[must_use]
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }
}

impl std::fmt::Display for ModuleStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initializing => write!(f, "initializing"),
            Self::Running => write!(f, "running"),
            Self::Degraded { reason } => write!(f, "degraded: {reason}"),
            Self::Paused => write!(f, "paused"),
            Self::Stopped => write!(f, "stopped"),
            Self::Error { message } => write!(f, "error: {message}"),
        }
    }
}

/// Health information for a module.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Part of public API, will be used by health check system
pub struct HealthInfo {
    /// Current status.
    pub status: ModuleStatus,

    /// Time since the module started.
    pub uptime: Option<std::time::Duration>,

    /// Last successful health check.
    pub last_health_check: Option<Instant>,

    /// Number of requests/operations processed.
    pub operations_count: u64,

    /// Number of errors encountered.
    pub error_count: u64,
}

impl Default for HealthInfo {
    fn default() -> Self {
        Self {
            status: ModuleStatus::Stopped,
            uptime: None,
            last_health_check: None,
            operations_count: 0,
            error_count: 0,
        }
    }
}
