//! Plugin sandboxing.
//!
//! Provides resource limits, capability-based security, and policy enforcement
//! for WASM plugin execution.

use std::collections::HashSet;
use std::time::Duration;

use super::error::{PluginError, PluginResult};

/// Normalize a file path by resolving `.` and `..` components without
/// touching the filesystem. This prevents path traversal attacks like
/// `/data/../etc/passwd`.
fn normalize_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {},
            ".." => {
                parts.pop();
            },
            other => parts.push(other),
        }
    }
    let normalized = parts.join("/");
    if path.starts_with('/') {
        format!("/{}", normalized)
    } else {
        normalized
    }
}

/// Sandbox configuration.
#[derive(Debug, Clone, Default)]
pub struct SandboxConfig {
    /// Resource limits.
    pub limits: ResourceLimits,
    /// Security policy.
    pub policy: SandboxPolicy,
    /// Enabled capabilities.
    pub capabilities: HashSet<Capability>,
}

impl SandboxConfig {
    /// Create a new sandbox configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with resource limits.
    pub fn with_limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Create with security policy.
    pub fn with_policy(mut self, policy: SandboxPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Add a capability.
    pub fn add_capability(mut self, capability: Capability) -> Self {
        self.capabilities.insert(capability);
        self
    }

    /// Add multiple capabilities.
    pub fn add_capabilities(mut self, capabilities: impl IntoIterator<Item = Capability>) -> Self {
        self.capabilities.extend(capabilities);
        self
    }

    /// Check if a capability is enabled.
    pub fn has_capability(&self, capability: &Capability) -> bool {
        self.capabilities.contains(capability)
    }

    /// Validate a capability check.
    pub fn require_capability(&self, capability: &Capability) -> PluginResult<()> {
        if self.has_capability(capability) {
            Ok(())
        } else {
            Err(PluginError::CapabilityDenied {
                capability: format!("{:?}", capability),
            })
        }
    }

    /// Create a restrictive sandbox.
    pub fn restrictive() -> Self {
        Self {
            limits: ResourceLimits::restrictive(),
            policy: SandboxPolicy::strict(),
            capabilities: HashSet::new(),
        }
    }

    /// Create a permissive sandbox (for trusted plugins).
    pub fn permissive() -> Self {
        let mut capabilities = HashSet::new();
        capabilities.insert(Capability::NetworkClient);
        capabilities.insert(Capability::KvStore);
        capabilities.insert(Capability::Logging);
        capabilities.insert(Capability::Metrics);
        capabilities.insert(Capability::Time);
        capabilities.insert(Capability::Random);

        Self {
            limits: ResourceLimits::permissive(),
            policy: SandboxPolicy::permissive(),
            capabilities,
        }
    }
}

/// Resource limits for plugin execution.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum memory in bytes.
    pub max_memory_bytes: u64,
    /// Maximum CPU time per invocation.
    pub max_execution_time: Duration,
    /// Maximum fuel (instruction count).
    pub max_fuel: u64,
    /// Maximum stack size in bytes.
    pub max_stack_size: u64,
    /// Maximum table elements.
    pub max_table_elements: u32,
    /// Maximum instances per module.
    pub max_instances: u32,
    /// Maximum invocations per second.
    pub max_invocations_per_second: u32,
    /// Maximum HTTP request body size.
    pub max_http_body_size: u64,
    /// Maximum KV store entries.
    pub max_kv_entries: u32,
    /// Maximum KV value size.
    pub max_kv_value_size: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 16 * 1024 * 1024, // 16 MB
            max_execution_time: Duration::from_millis(100),
            max_fuel: 10_000_000,
            max_stack_size: 1024 * 1024, // 1 MB
            max_table_elements: 10_000,
            max_instances: 10,
            max_invocations_per_second: 1000,
            max_http_body_size: 1024 * 1024, // 1 MB
            max_kv_entries: 1000,
            max_kv_value_size: 64 * 1024, // 64 KB
        }
    }
}

impl ResourceLimits {
    /// Create restrictive limits.
    pub fn restrictive() -> Self {
        Self {
            max_memory_bytes: 4 * 1024 * 1024, // 4 MB
            max_execution_time: Duration::from_millis(10),
            max_fuel: 1_000_000,
            max_stack_size: 256 * 1024, // 256 KB
            max_table_elements: 1_000,
            max_instances: 2,
            max_invocations_per_second: 100,
            max_http_body_size: 64 * 1024, // 64 KB
            max_kv_entries: 100,
            max_kv_value_size: 4 * 1024, // 4 KB
        }
    }

    /// Create permissive limits.
    pub fn permissive() -> Self {
        Self {
            max_memory_bytes: 256 * 1024 * 1024, // 256 MB
            max_execution_time: Duration::from_secs(30),
            max_fuel: 1_000_000_000,
            max_stack_size: 8 * 1024 * 1024, // 8 MB
            max_table_elements: 100_000,
            max_instances: 100,
            max_invocations_per_second: 100_000,
            max_http_body_size: 100 * 1024 * 1024, // 100 MB
            max_kv_entries: 100_000,
            max_kv_value_size: 10 * 1024 * 1024, // 10 MB
        }
    }

    /// Check if an invocation is allowed.
    pub fn check_invocation(&self) -> PluginResult<()> {
        // In a real implementation, this would check rate limits, etc.
        Ok(())
    }

    /// Check memory allocation.
    pub fn check_memory(&self, requested: u64, current: u64) -> PluginResult<()> {
        if current + requested > self.max_memory_bytes {
            Err(PluginError::ResourceLimitExceeded {
                resource: "memory".to_string(),
                limit: self.max_memory_bytes,
                attempted: current + requested,
            })
        } else {
            Ok(())
        }
    }

    /// Check fuel consumption.
    pub fn check_fuel(&self, consumed: u64) -> PluginResult<()> {
        if consumed > self.max_fuel {
            Err(PluginError::ResourceLimitExceeded {
                resource: "fuel".to_string(),
                limit: self.max_fuel,
                attempted: consumed,
            })
        } else {
            Ok(())
        }
    }

    /// Check execution time.
    pub fn check_execution_time(&self, elapsed: Duration) -> PluginResult<()> {
        if elapsed > self.max_execution_time {
            Err(PluginError::Timeout {
                timeout_ms: self.max_execution_time.as_millis() as u64,
            })
        } else {
            Ok(())
        }
    }
}

/// Security policy for plugin execution.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    /// Allow WASM SIMD instructions.
    pub allow_simd: bool,
    /// Allow WASM threads.
    pub allow_threads: bool,
    /// Allow reference types.
    pub allow_reference_types: bool,
    /// Allow bulk memory operations.
    pub allow_bulk_memory: bool,
    /// Allow multi-value returns.
    pub allow_multi_value: bool,
    /// Allow floating point operations.
    pub allow_float: bool,
    /// Allowed host function modules.
    pub allowed_modules: HashSet<String>,
    /// Denied host functions.
    pub denied_functions: HashSet<String>,
    /// Network access restrictions.
    pub network_policy: NetworkPolicy,
    /// Filesystem access restrictions.
    pub filesystem_policy: FilesystemPolicy,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        let mut allowed_modules = HashSet::new();
        allowed_modules.insert("env".to_string());

        Self {
            allow_simd: false,
            allow_threads: false,
            allow_reference_types: false,
            allow_bulk_memory: true,
            allow_multi_value: true,
            allow_float: true,
            allowed_modules,
            denied_functions: HashSet::new(),
            network_policy: NetworkPolicy::default(),
            filesystem_policy: FilesystemPolicy::default(),
        }
    }
}

impl SandboxPolicy {
    /// Create a strict policy.
    pub fn strict() -> Self {
        Self {
            allow_simd: false,
            allow_threads: false,
            allow_reference_types: false,
            allow_bulk_memory: false,
            allow_multi_value: false,
            allow_float: true,
            allowed_modules: HashSet::new(),
            denied_functions: HashSet::new(),
            network_policy: NetworkPolicy::deny_all(),
            filesystem_policy: FilesystemPolicy::deny_all(),
        }
    }

    /// Create a permissive policy.
    pub fn permissive() -> Self {
        let mut allowed_modules = HashSet::new();
        allowed_modules.insert("env".to_string());
        allowed_modules.insert("http".to_string());
        allowed_modules.insert("kv".to_string());

        Self {
            allow_simd: true,
            allow_threads: false, // Still dangerous
            allow_reference_types: true,
            allow_bulk_memory: true,
            allow_multi_value: true,
            allow_float: true,
            allowed_modules,
            denied_functions: HashSet::new(),
            network_policy: NetworkPolicy::allow_all(),
            filesystem_policy: FilesystemPolicy::deny_all(),
        }
    }

    /// Check if a module is allowed.
    pub fn is_module_allowed(&self, module: &str) -> bool {
        self.allowed_modules.is_empty() || self.allowed_modules.contains(module)
    }

    /// Check if a function is denied.
    pub fn is_function_denied(&self, function: &str) -> bool {
        self.denied_functions.contains(function)
    }

    /// Validate an import.
    pub fn validate_import(&self, module: &str, function: &str) -> PluginResult<()> {
        if !self.is_module_allowed(module) {
            return Err(PluginError::PolicyViolation {
                policy: format!("module '{}' not allowed", module),
                action: "import".to_string(),
            });
        }

        if self.is_function_denied(function) {
            return Err(PluginError::PolicyViolation {
                policy: format!("function '{}' denied", function),
                action: "import".to_string(),
            });
        }

        Ok(())
    }
}

/// Network access policy.
#[derive(Debug, Clone)]
pub struct NetworkPolicy {
    /// Allow outbound connections.
    pub allow_outbound: bool,
    /// Allowed hosts (empty = all allowed if outbound allowed).
    pub allowed_hosts: HashSet<String>,
    /// Denied hosts.
    pub denied_hosts: HashSet<String>,
    /// Allowed ports (empty = all ports).
    pub allowed_ports: HashSet<u16>,
    /// Maximum connections per instance.
    pub max_connections: u32,
    /// Maximum request rate.
    pub max_requests_per_minute: u32,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            allow_outbound: false,
            allowed_hosts: HashSet::new(),
            denied_hosts: HashSet::new(),
            allowed_ports: HashSet::new(),
            max_connections: 10,
            max_requests_per_minute: 60,
        }
    }
}

impl NetworkPolicy {
    /// Deny all network access.
    pub fn deny_all() -> Self {
        Self {
            allow_outbound: false,
            ..Default::default()
        }
    }

    /// Allow all network access.
    pub fn allow_all() -> Self {
        Self {
            allow_outbound: true,
            max_connections: 100,
            max_requests_per_minute: 10000,
            ..Default::default()
        }
    }

    /// Check if a host is allowed.
    pub fn is_host_allowed(&self, host: &str) -> bool {
        if !self.allow_outbound {
            return false;
        }

        if self.denied_hosts.contains(host) {
            return false;
        }

        self.allowed_hosts.is_empty() || self.allowed_hosts.contains(host)
    }

    /// Check if a port is allowed.
    pub fn is_port_allowed(&self, port: u16) -> bool {
        self.allowed_ports.is_empty() || self.allowed_ports.contains(&port)
    }

    /// Validate a network request.
    pub fn validate_request(&self, host: &str, port: u16) -> PluginResult<()> {
        if !self.allow_outbound {
            return Err(PluginError::PolicyViolation {
                policy: "outbound network access denied".to_string(),
                action: "network_request".to_string(),
            });
        }

        if !self.is_host_allowed(host) {
            return Err(PluginError::PolicyViolation {
                policy: format!("host '{}' not allowed", host),
                action: "network_request".to_string(),
            });
        }

        if !self.is_port_allowed(port) {
            return Err(PluginError::PolicyViolation {
                policy: format!("port {} not allowed", port),
                action: "network_request".to_string(),
            });
        }

        Ok(())
    }
}

/// Filesystem access policy.
#[derive(Debug, Clone)]
pub struct FilesystemPolicy {
    /// Allow filesystem access.
    pub allow_access: bool,
    /// Allowed paths (read).
    pub read_paths: HashSet<String>,
    /// Allowed paths (write).
    pub write_paths: HashSet<String>,
    /// Maximum file size.
    pub max_file_size: u64,
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            allow_access: false,
            read_paths: HashSet::new(),
            write_paths: HashSet::new(),
            max_file_size: 10 * 1024 * 1024, // 10 MB
        }
    }
}

impl FilesystemPolicy {
    /// Deny all filesystem access.
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Check if read is allowed for path.
    ///
    /// Normalizes the path to prevent traversal attacks before checking
    /// against the allowed read paths (prefix match).
    pub fn can_read(&self, path: &str) -> bool {
        if !self.allow_access {
            return false;
        }
        if self.read_paths.is_empty() {
            return true;
        }
        let normalized = normalize_path(path);
        self.read_paths
            .iter()
            .any(|allowed| normalized.starts_with(allowed))
    }

    /// Check if write is allowed for path.
    ///
    /// Normalizes the path to prevent traversal attacks before checking
    /// against the allowed write paths (prefix match).
    pub fn can_write(&self, path: &str) -> bool {
        if !self.allow_access {
            return false;
        }
        let normalized = normalize_path(path);
        self.write_paths
            .iter()
            .any(|allowed| normalized.starts_with(allowed))
    }
}

/// Plugin capability.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Can make outbound HTTP requests.
    NetworkClient,
    /// Can listen for connections.
    NetworkServer,
    /// Can access key-value store.
    KvStore,
    /// Can read configuration.
    Config,
    /// Can emit logs.
    Logging,
    /// Can emit metrics.
    Metrics,
    /// Can access time functions.
    Time,
    /// Can generate random numbers.
    Random,
    /// Can access crypto functions.
    Crypto,
    /// Can access filesystem.
    Filesystem,
    /// Can spawn threads.
    Threads,
    /// Custom capability.
    Custom(String),
}

impl Capability {
    /// Get capability name.
    pub fn name(&self) -> &str {
        match self {
            Self::NetworkClient => "network:client",
            Self::NetworkServer => "network:server",
            Self::KvStore => "kv",
            Self::Config => "config",
            Self::Logging => "logging",
            Self::Metrics => "metrics",
            Self::Time => "time",
            Self::Random => "random",
            Self::Crypto => "crypto",
            Self::Filesystem => "filesystem",
            Self::Threads => "threads",
            Self::Custom(name) => name,
        }
    }

    /// Parse capability from string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "network:client" => Some(Self::NetworkClient),
            "network:server" => Some(Self::NetworkServer),
            "kv" => Some(Self::KvStore),
            "config" => Some(Self::Config),
            "logging" => Some(Self::Logging),
            "metrics" => Some(Self::Metrics),
            "time" => Some(Self::Time),
            "random" => Some(Self::Random),
            "crypto" => Some(Self::Crypto),
            "filesystem" => Some(Self::Filesystem),
            "threads" => Some(Self::Threads),
            other => Some(Self::Custom(other.to_string())),
        }
    }
}

/// Sandbox enforcer for runtime checks.
#[derive(Debug)]
pub struct SandboxEnforcer {
    /// Configuration.
    config: SandboxConfig,
    /// Current memory usage.
    memory_used: u64,
    /// Fuel consumed.
    fuel_consumed: u64,
    /// Request count for rate limiting.
    request_count: u32,
}

impl SandboxEnforcer {
    /// Create a new enforcer.
    pub fn new(config: SandboxConfig) -> Self {
        Self {
            config,
            memory_used: 0,
            fuel_consumed: 0,
            request_count: 0,
        }
    }

    /// Check and consume memory.
    pub fn allocate_memory(&mut self, bytes: u64) -> PluginResult<()> {
        self.config.limits.check_memory(bytes, self.memory_used)?;
        self.memory_used += bytes;
        Ok(())
    }

    /// Release memory.
    pub fn release_memory(&mut self, bytes: u64) {
        self.memory_used = self.memory_used.saturating_sub(bytes);
    }

    /// Check and consume fuel.
    pub fn consume_fuel(&mut self, fuel: u64) -> PluginResult<()> {
        self.fuel_consumed += fuel;
        self.config.limits.check_fuel(self.fuel_consumed)
    }

    /// Check capability.
    pub fn require_capability(&self, capability: &Capability) -> PluginResult<()> {
        self.config.require_capability(capability)
    }

    /// Validate network request.
    pub fn validate_network_request(&mut self, host: &str, port: u16) -> PluginResult<()> {
        self.config.require_capability(&Capability::NetworkClient)?;
        self.config
            .policy
            .network_policy
            .validate_request(host, port)?;

        self.request_count += 1;
        if self.request_count > self.config.policy.network_policy.max_requests_per_minute {
            return Err(PluginError::ResourceLimitExceeded {
                resource: "requests_per_minute".to_string(),
                limit: self.config.policy.network_policy.max_requests_per_minute as u64,
                attempted: self.request_count as u64,
            });
        }

        Ok(())
    }

    /// Get current memory usage.
    pub fn memory_used(&self) -> u64 {
        self.memory_used
    }

    /// Get fuel consumed.
    pub fn fuel_consumed(&self) -> u64 {
        self.fuel_consumed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_config_default() {
        let config = SandboxConfig::default();
        assert!(config.capabilities.is_empty());
    }

    #[test]
    fn test_sandbox_config_add_capability() {
        let config = SandboxConfig::new()
            .add_capability(Capability::Logging)
            .add_capability(Capability::Metrics);

        assert!(config.has_capability(&Capability::Logging));
        assert!(config.has_capability(&Capability::Metrics));
        assert!(!config.has_capability(&Capability::NetworkClient));
    }

    #[test]
    fn test_require_capability() {
        let config = SandboxConfig::new().add_capability(Capability::Logging);

        assert!(config.require_capability(&Capability::Logging).is_ok());
        assert!(config
            .require_capability(&Capability::NetworkClient)
            .is_err());
    }

    #[test]
    fn test_restrictive_sandbox() {
        let config = SandboxConfig::restrictive();
        assert!(config.capabilities.is_empty());
        assert_eq!(config.limits.max_memory_bytes, 4 * 1024 * 1024);
    }

    #[test]
    fn test_permissive_sandbox() {
        let config = SandboxConfig::permissive();
        assert!(config.has_capability(&Capability::Logging));
        assert!(config.has_capability(&Capability::NetworkClient));
    }

    #[test]
    fn test_resource_limits_check_memory() {
        let limits = ResourceLimits::default();

        assert!(limits.check_memory(1024, 0).is_ok());
        assert!(limits.check_memory(limits.max_memory_bytes + 1, 0).is_err());
    }

    #[test]
    fn test_resource_limits_check_fuel() {
        let limits = ResourceLimits::default();

        assert!(limits.check_fuel(1000).is_ok());
        assert!(limits.check_fuel(limits.max_fuel + 1).is_err());
    }

    #[test]
    fn test_resource_limits_check_execution_time() {
        let limits = ResourceLimits::default();

        assert!(limits
            .check_execution_time(Duration::from_millis(10))
            .is_ok());
        assert!(limits
            .check_execution_time(Duration::from_secs(10))
            .is_err());
    }

    #[test]
    fn test_sandbox_policy_validate_import() {
        let policy = SandboxPolicy::default();

        assert!(policy.validate_import("env", "log_info").is_ok());
        assert!(policy.validate_import("forbidden", "function").is_err());
    }

    #[test]
    fn test_network_policy_deny_all() {
        let policy = NetworkPolicy::deny_all();

        assert!(!policy.is_host_allowed("example.com"));
        assert!(policy.validate_request("example.com", 80).is_err());
    }

    #[test]
    fn test_network_policy_allow_all() {
        let policy = NetworkPolicy::allow_all();

        assert!(policy.is_host_allowed("example.com"));
        assert!(policy.validate_request("example.com", 80).is_ok());
    }

    #[test]
    fn test_network_policy_denied_hosts() {
        let mut policy = NetworkPolicy::allow_all();
        policy.denied_hosts.insert("evil.com".to_string());

        assert!(!policy.is_host_allowed("evil.com"));
        assert!(policy.validate_request("evil.com", 80).is_err());
    }

    #[test]
    fn test_filesystem_policy() {
        let policy = FilesystemPolicy::deny_all();

        assert!(!policy.can_read("/etc/passwd"));
        assert!(!policy.can_write("/tmp/file"));
    }

    #[test]
    fn test_capability_name() {
        assert_eq!(Capability::Logging.name(), "logging");
        assert_eq!(Capability::NetworkClient.name(), "network:client");
        assert_eq!(Capability::Custom("my_cap".to_string()).name(), "my_cap");
    }

    #[test]
    fn test_capability_from_str() {
        assert_eq!(Capability::parse("logging"), Some(Capability::Logging));
        assert_eq!(
            Capability::parse("custom"),
            Some(Capability::Custom("custom".to_string()))
        );
    }

    #[test]
    fn test_sandbox_enforcer_memory() {
        let config = SandboxConfig::default();
        let mut enforcer = SandboxEnforcer::new(config);

        assert!(enforcer.allocate_memory(1024).is_ok());
        assert_eq!(enforcer.memory_used(), 1024);

        enforcer.release_memory(512);
        assert_eq!(enforcer.memory_used(), 512);
    }

    #[test]
    fn test_sandbox_enforcer_fuel() {
        let config = SandboxConfig::default();
        let mut enforcer = SandboxEnforcer::new(config);

        assert!(enforcer.consume_fuel(1000).is_ok());
        assert_eq!(enforcer.fuel_consumed(), 1000);
    }

    #[test]
    fn test_sandbox_enforcer_capability() {
        let config = SandboxConfig::new().add_capability(Capability::Logging);
        let enforcer = SandboxEnforcer::new(config);

        assert!(enforcer.require_capability(&Capability::Logging).is_ok());
        assert!(enforcer
            .require_capability(&Capability::NetworkClient)
            .is_err());
    }

    #[test]
    fn test_sandbox_enforcer_network() {
        let config = SandboxConfig::permissive();
        let mut enforcer = SandboxEnforcer::new(config);

        assert!(enforcer.validate_network_request("example.com", 80).is_ok());
    }
}
