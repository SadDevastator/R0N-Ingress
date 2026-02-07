//! The core Module Contract trait.
//!
//! All R0N Ingress modules must implement this trait to be managed
//! by the R0N control plane.

use super::{ModuleConfig, ModuleError, ModuleManifest, ModuleResult, ModuleStatus};
use std::collections::HashMap;

/// The current version of the module contract.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion {
    major: 1,
    minor: 1,
    patch: 0,
};

/// Version information for the module contract.
///
/// Used to ensure compatibility between the control plane and modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractVersion {
    /// Major version - breaking changes.
    pub major: u32,
    /// Minor version - new features, backward compatible.
    pub minor: u32,
    /// Patch version - bug fixes.
    pub patch: u32,
}

impl ContractVersion {
    /// Creates a new contract version.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Returns the current contract version.
    #[must_use]
    pub const fn current() -> Self {
        CONTRACT_VERSION
    }

    /// Checks if this version is compatible with another version.
    ///
    /// Versions are compatible if they have the same major version and
    /// this version's minor is >= the other's minor.
    #[must_use]
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major && self.minor >= other.minor
    }
}

impl std::fmt::Display for ContractVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Metrics payload containing module-specific metrics.
#[derive(Debug, Clone, Default)]
pub struct MetricsPayload {
    /// Counter metrics (monotonically increasing).
    pub counters: HashMap<String, u64>,

    /// Gauge metrics (can go up and down).
    pub gauges: HashMap<String, f64>,

    /// Histogram metrics (distribution of values).
    pub histograms: HashMap<String, Vec<f64>>,
}

impl MetricsPayload {
    /// Creates a new empty metrics payload.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a counter metric.
    pub fn counter(&mut self, name: impl Into<String>, value: u64) {
        self.counters.insert(name.into(), value);
    }

    /// Adds a gauge metric.
    pub fn gauge(&mut self, name: impl Into<String>, value: f64) {
        self.gauges.insert(name.into(), value);
    }

    /// Adds a histogram metric.
    pub fn histogram(&mut self, name: impl Into<String>, values: Vec<f64>) {
        self.histograms.insert(name.into(), values);
    }

    /// Formats metrics in Prometheus text format.
    #[must_use]
    pub fn to_prometheus(&self, prefix: &str) -> String {
        let mut output = String::new();

        for (name, value) in &self.counters {
            output.push_str(&format!("{prefix}_{name} {value}\n"));
        }

        for (name, value) in &self.gauges {
            output.push_str(&format!("{prefix}_{name} {value}\n"));
        }

        output
    }
}

/// The core contract that all R0N Ingress modules must implement.
///
/// This trait defines the lifecycle methods and capabilities that
/// the R0N control plane uses to manage modules.
///
/// # Lifecycle
///
/// 1. `manifest()` - Called to discover module capabilities
/// 2. `init()` - Initialize with configuration
/// 3. `start()` - Begin processing
/// 4. `pause()` - Temporarily suspend processing (optional)
/// 5. `resume()` - Resume after pause (optional)
/// 6. `status()` / `metrics()` - Ongoing monitoring
/// 7. `reload()` - Apply new configuration (optional)
/// 8. `stop()` - Graceful shutdown
///
/// # Example
///
/// ```ignore
/// use r0n_ingress::module::*;
///
/// struct MyModule {
///     status: ModuleStatus,
///     config: ModuleConfig,
/// }
///
/// impl ModuleContract for MyModule {
///     fn manifest(&self) -> ModuleManifest {
///         ModuleManifest::builder("my-module")
///             .description("Example module")
///             .version(1, 0, 0)
///             .build()
///     }
///
///     fn init(&mut self, config: ModuleConfig) -> ModuleResult<()> {
///         self.config = config;
///         self.status = ModuleStatus::Initializing;
///         Ok(())
///     }
///
///     fn start(&mut self) -> ModuleResult<()> {
///         self.status = ModuleStatus::Running;
///         Ok(())
///     }
///
///     fn stop(&mut self) -> ModuleResult<()> {
///         self.status = ModuleStatus::Stopped;
///         Ok(())
///     }
///
///     fn status(&self) -> ModuleStatus {
///         self.status.clone()
///     }
///
///     fn metrics(&self) -> MetricsPayload {
///         MetricsPayload::new()
///     }
/// }
/// ```
pub trait ModuleContract: Send + Sync {
    /// Returns the module's manifest describing its identity and capabilities.
    ///
    /// This is called during module discovery to understand what the module
    /// provides and what dependencies it requires.
    fn manifest(&self) -> ModuleManifest;

    /// Initializes the module with the provided configuration.
    ///
    /// This is called once after the module is loaded. The module should
    /// validate the configuration and prepare internal state, but should
    /// not start processing until `start()` is called.
    ///
    /// # Errors
    ///
    /// Returns `ModuleError::ConfigError` if the configuration is invalid.
    /// Returns `ModuleError::InitializationFailed` for other initialization failures.
    fn init(&mut self, config: ModuleConfig) -> ModuleResult<()>;

    /// Starts the module's processing.
    ///
    /// After this call returns successfully, the module should be actively
    /// processing requests or performing its function.
    ///
    /// # Errors
    ///
    /// Returns `ModuleError::StartFailed` if the module cannot start.
    /// Returns `ModuleError::InvalidState` if called before `init()`.
    fn start(&mut self) -> ModuleResult<()>;

    /// Stops the module gracefully.
    ///
    /// The module should complete any in-flight operations and release
    /// resources. After this call, the module should be in a stopped state.
    ///
    /// # Errors
    ///
    /// Returns `ModuleError::StopFailed` if graceful shutdown fails.
    fn stop(&mut self) -> ModuleResult<()>;

    /// Reloads the module's configuration.
    ///
    /// This allows applying new configuration without restarting the module.
    /// The default implementation returns an error indicating hot reload
    /// is not supported.
    ///
    /// # Errors
    ///
    /// Returns `ModuleError::ConfigError` if the new configuration is invalid.
    fn reload(&mut self, _config: ModuleConfig) -> ModuleResult<()> {
        Err(ModuleError::ConfigError(
            "hot reload not supported".to_string(),
        ))
    }

    /// Returns the current status of the module.
    ///
    /// This is called periodically by the control plane for health monitoring.
    fn status(&self) -> ModuleStatus;

    /// Returns the current metrics from the module.
    ///
    /// Metrics are collected and exported in Prometheus-compatible format.
    fn metrics(&self) -> MetricsPayload;

    /// Called periodically for heartbeat/liveness checks.
    ///
    /// The default implementation returns `true` if the module is operational.
    /// Modules can override this for custom health checks.
    fn heartbeat(&self) -> bool {
        self.status().is_operational()
    }

    /// Pauses the module's processing temporarily.
    ///
    /// When paused, the module should stop accepting new work but may
    /// complete in-flight operations. This is useful for maintenance,
    /// configuration changes, or graceful traffic draining.
    ///
    /// The default implementation returns an error indicating pause
    /// is not supported.
    ///
    /// # Errors
    ///
    /// Returns `ModuleError::InvalidState` if the module cannot be paused.
    fn pause(&mut self) -> ModuleResult<()> {
        Err(ModuleError::InvalidState {
            current: "running".to_string(),
            expected: "pausable module".to_string(),
        })
    }

    /// Resumes the module after a pause.
    ///
    /// After this call, the module should resume normal processing.
    ///
    /// The default implementation returns an error indicating resume
    /// is not supported.
    ///
    /// # Errors
    ///
    /// Returns `ModuleError::InvalidState` if the module is not paused.
    fn resume(&mut self) -> ModuleResult<()> {
        Err(ModuleError::InvalidState {
            current: "not paused".to_string(),
            expected: "paused".to_string(),
        })
    }

    /// Returns the module's contract version.
    ///
    /// This allows the control plane to verify compatibility with
    /// different module implementations. The version follows semver.
    ///
    /// The default implementation returns the current contract version.
    fn contract_version(&self) -> ContractVersion {
        ContractVersion::current()
    }
}
