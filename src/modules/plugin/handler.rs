//! Plugin handler.
//!
//! Implements the ModuleContract for the plugin system, providing
//! module lifecycle management and metrics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::module::{
    Capability, Dependency, MetricsPayload, ModuleConfig, ModuleContract, ModuleError,
    ModuleManifest, ModuleResult, ModuleStatus,
};

use super::error::{PluginError, PluginResult};
use super::registry::{PluginInfo, PluginRegistry, PluginState, PluginType};
use super::runtime::{PluginRuntime, RuntimeConfig, WasmValue};
use super::sandbox::SandboxConfig;

/// Plugin handler implementing ModuleContract.
#[derive(Debug)]
pub struct PluginHandler {
    /// Plugin runtime.
    runtime: PluginRuntime,
    /// Plugin registry.
    registry: PluginRegistry,
    /// Handler configuration.
    config: PluginHandlerConfig,
    /// Running state.
    running: bool,
    /// Start time.
    started_at: Option<Instant>,
    /// Handler statistics.
    stats: PluginHandlerStats,
}

impl Default for PluginHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginHandler {
    /// Create a new plugin handler.
    pub fn new() -> Self {
        Self {
            runtime: PluginRuntime::new(),
            registry: PluginRegistry::new(),
            config: PluginHandlerConfig::default(),
            running: false,
            started_at: None,
            stats: PluginHandlerStats::default(),
        }
    }

    /// Create with configuration.
    pub fn with_config(config: PluginHandlerConfig) -> Self {
        Self {
            runtime: PluginRuntime::with_config(config.runtime.clone()),
            config,
            ..Self::new()
        }
    }

    /// Get the plugin runtime.
    pub fn runtime(&self) -> &PluginRuntime {
        &self.runtime
    }

    /// Get mutable runtime.
    pub fn runtime_mut(&mut self) -> &mut PluginRuntime {
        &mut self.runtime
    }

    /// Get the plugin registry.
    pub fn registry(&self) -> &PluginRegistry {
        &self.registry
    }

    /// Get mutable registry.
    pub fn registry_mut(&mut self) -> &mut PluginRegistry {
        &mut self.registry
    }

    /// Load and register a plugin.
    pub fn load_plugin(
        &mut self,
        name: impl Into<String>,
        wasm_bytes: &[u8],
        info: PluginInfo,
        sandbox: SandboxConfig,
    ) -> PluginResult<()> {
        let name = name.into();
        let plugin_name = info.name.clone();

        // Load module into runtime (uses provided name for WASM module)
        self.runtime.load_module(&name, wasm_bytes)?;

        // Register in registry (uses PluginInfo.name)
        self.registry.register(info, sandbox)?;

        // Update state using registry name
        self.registry
            .update_state(&plugin_name, PluginState::Ready)?;

        self.stats.plugins_loaded.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Unload a plugin.
    pub fn unload_plugin(&mut self, name: &str) -> PluginResult<()> {
        // Unload from runtime
        self.runtime.unload_module(name)?;

        // Unregister
        self.registry.unregister(name)?;

        self.stats.plugins_unloaded.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Start a plugin instance.
    pub fn start_plugin(&mut self, name: &str) -> PluginResult<u64> {
        let entry = self
            .registry
            .get(name)
            .ok_or_else(|| PluginError::NotFound {
                name: name.to_string(),
            })?;

        if !entry.state.can_start() {
            return Err(PluginError::InvalidState {
                current: format!("{:?}", entry.state),
                expected: "Ready or Stopped".to_string(),
            });
        }

        let sandbox = entry.sandbox.clone();

        // Create instance
        let instance_id = self.runtime.create_instance(name, sandbox)?;

        // Initialize
        self.runtime.init_instance(instance_id)?;

        // Start
        self.runtime.start_instance(instance_id)?;

        // Update registry state
        self.registry.update_state(name, PluginState::Running)?;

        self.stats.plugins_started.fetch_add(1, Ordering::SeqCst);
        Ok(instance_id)
    }

    /// Stop a plugin instance.
    pub fn stop_plugin(&mut self, instance_id: u64) -> PluginResult<()> {
        let instance =
            self.runtime
                .get_instance(instance_id)
                .ok_or_else(|| PluginError::NotFound {
                    name: format!("instance:{}", instance_id),
                })?;

        let module_name = instance.module_name.clone();

        // Stop and terminate
        self.runtime.stop_instance(instance_id)?;
        self.runtime.terminate_instance(instance_id)?;

        // Update registry state
        self.registry
            .update_state(&module_name, PluginState::Stopped)?;

        self.stats.plugins_stopped.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Invoke a plugin function.
    pub fn invoke(
        &mut self,
        instance_id: u64,
        function: &str,
        args: &[WasmValue],
    ) -> PluginResult<Vec<WasmValue>> {
        self.stats.invocations.fetch_add(1, Ordering::SeqCst);
        self.runtime.invoke(instance_id, function, args)
    }

    /// List all plugins.
    pub fn list_plugins(&self) -> Vec<PluginSummary> {
        self.registry
            .list()
            .map(|entry| PluginSummary {
                name: entry.info.name.clone(),
                version: entry.info.version.clone(),
                plugin_type: entry.info.plugin_type,
                state: entry.state,
                description: entry.info.description.clone(),
            })
            .collect()
    }

    /// Get plugin details.
    pub fn get_plugin(&self, name: &str) -> Option<&super::registry::PluginEntry> {
        self.registry.get(name)
    }

    /// Get handler statistics.
    pub fn stats(&self) -> &PluginHandlerStats {
        &self.stats
    }
}

impl ModuleContract for PluginHandler {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("plugin")
            .description("WASM plugin runtime for extending gateway functionality")
            .version(0, 1, 0)
            .capability(Capability::Custom("WasmRuntime".to_string()))
            .capability(Capability::Custom("PluginRegistry".to_string()))
            .capability(Capability::Custom("Sandboxing".to_string()))
            .dependency(Dependency::optional("http-handler"))
            .build()
    }

    fn init(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        // Configure from ModuleConfig
        if let Some(initial_pages) = config.get_string("initial_memory_pages") {
            if let Ok(pages) = initial_pages.parse::<u32>() {
                self.config.runtime.initial_memory_pages = pages;
            }
        }

        if let Some(max_pages) = config.get_string("max_memory_pages") {
            if let Ok(pages) = max_pages.parse::<u32>() {
                self.config.runtime.max_memory_pages = pages;
            }
        }

        if let Some(fuel) = config.get_string("fuel_limit") {
            if let Ok(limit) = fuel.parse::<u64>() {
                self.config.runtime.fuel_limit = limit;
            }
        }

        // Add plugin search paths
        if let Some(paths) = config.get_string("plugin_paths") {
            for path in paths.split(':') {
                self.registry.add_search_path(path);
            }
        }

        // Auto-discover plugins
        if config.get_bool("auto_discover").unwrap_or(false) {
            let _ = self.registry.discover();
        }

        Ok(())
    }

    fn start(&mut self) -> ModuleResult<()> {
        self.running = true;
        self.started_at = Some(Instant::now());

        // Auto-start registered plugins
        if self.config.auto_start_plugins {
            let plugin_names: Vec<String> = self
                .registry
                .list_by_state(PluginState::Ready)
                .map(|e| e.info.name.clone())
                .collect();

            for name in plugin_names {
                if let Err(e) = self.start_plugin(&name) {
                    // Log error but continue
                    eprintln!("Failed to auto-start plugin {}: {:?}", name, e);
                }
            }
        }

        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        // Stop all running plugins
        let running_plugins: Vec<String> = self
            .registry
            .list_by_state(PluginState::Running)
            .map(|e| e.info.name.clone())
            .collect();

        for name in running_plugins {
            // Find instance for this plugin
            // In a real implementation, we'd track instance IDs per plugin
            self.registry
                .update_state(&name, PluginState::Stopped)
                .map_err(|e| {
                    ModuleError::StopFailed(format!("Failed to stop plugin {}: {}", name, e))
                })?;
        }

        self.running = false;
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        if self.running {
            ModuleStatus::Running
        } else {
            ModuleStatus::Stopped
        }
    }

    fn metrics(&self) -> MetricsPayload {
        let mut payload = MetricsPayload::new();

        // Runtime metrics
        let runtime_stats = self.runtime.stats();
        payload.counter(
            "plugin_modules_loaded",
            runtime_stats.modules_loaded.load(Ordering::SeqCst),
        );
        payload.counter(
            "plugin_instances_created",
            runtime_stats.instances_created.load(Ordering::SeqCst),
        );
        payload.gauge(
            "plugin_instances_running",
            runtime_stats.instances_running.load(Ordering::SeqCst) as f64,
        );
        payload.counter(
            "plugin_invocations",
            runtime_stats.invocations.load(Ordering::SeqCst),
        );

        // Handler metrics
        payload.counter(
            "plugin_handler_plugins_loaded",
            self.stats.plugins_loaded.load(Ordering::SeqCst),
        );
        payload.counter(
            "plugin_handler_plugins_started",
            self.stats.plugins_started.load(Ordering::SeqCst),
        );
        payload.counter(
            "plugin_handler_plugins_stopped",
            self.stats.plugins_stopped.load(Ordering::SeqCst),
        );
        payload.counter(
            "plugin_handler_invocations",
            self.stats.invocations.load(Ordering::SeqCst),
        );
        payload.counter(
            "plugin_handler_errors",
            self.stats.errors.load(Ordering::SeqCst),
        );

        // Registry metrics
        payload.gauge("plugin_registry_count", self.registry.len() as f64);

        // Uptime
        if let Some(started) = self.started_at {
            payload.gauge(
                "plugin_handler_uptime_seconds",
                started.elapsed().as_secs_f64(),
            );
        }

        payload
    }
}

/// Plugin handler configuration.
#[derive(Debug, Clone)]
pub struct PluginHandlerConfig {
    /// Runtime configuration.
    pub runtime: RuntimeConfig,
    /// Default sandbox configuration.
    pub default_sandbox: SandboxConfig,
    /// Auto-start plugins on handler start.
    pub auto_start_plugins: bool,
    /// Enable plugin hot-reload.
    pub hot_reload: bool,
    /// Maximum concurrent invocations.
    pub max_concurrent_invocations: u32,
}

impl Default for PluginHandlerConfig {
    fn default() -> Self {
        Self {
            runtime: RuntimeConfig::default(),
            default_sandbox: SandboxConfig::default(),
            auto_start_plugins: false,
            hot_reload: false,
            max_concurrent_invocations: 100,
        }
    }
}

/// Plugin summary for listing.
#[derive(Debug, Clone)]
pub struct PluginSummary {
    /// Plugin name.
    pub name: String,
    /// Plugin version.
    pub version: String,
    /// Plugin type.
    pub plugin_type: PluginType,
    /// Current state.
    pub state: PluginState,
    /// Description.
    pub description: Option<String>,
}

/// Handler statistics.
#[derive(Debug, Default)]
pub struct PluginHandlerStats {
    /// Plugins loaded.
    pub plugins_loaded: AtomicU64,
    /// Plugins unloaded.
    pub plugins_unloaded: AtomicU64,
    /// Plugins started.
    pub plugins_started: AtomicU64,
    /// Plugins stopped.
    pub plugins_stopped: AtomicU64,
    /// Total invocations.
    pub invocations: AtomicU64,
    /// Errors.
    pub errors: AtomicU64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid minimal WASM module
    const MINIMAL_WASM: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, // magic: \0asm
        0x01, 0x00, 0x00, 0x00, // version: 1
    ];

    fn test_plugin_info() -> PluginInfo {
        PluginInfo::new("test-plugin", "1.0.0")
            .with_description("A test plugin")
            .with_type(PluginType::RequestHandler)
    }

    #[test]
    fn test_handler_new() {
        let handler = PluginHandler::new();
        assert!(!handler.running);
        assert!(handler.registry.is_empty());
    }

    #[test]
    fn test_load_plugin() {
        let mut handler = PluginHandler::new();
        let info = test_plugin_info(); // name is "test-plugin"

        let result =
            handler.load_plugin("test-plugin", MINIMAL_WASM, info, SandboxConfig::default());

        assert!(result.is_ok());
        assert!(handler.registry.get("test-plugin").is_some());
    }

    #[test]
    fn test_unload_plugin() {
        let mut handler = PluginHandler::new();

        handler
            .load_plugin(
                "test-plugin",
                MINIMAL_WASM,
                test_plugin_info(),
                SandboxConfig::default(),
            )
            .unwrap();

        assert!(handler.unload_plugin("test-plugin").is_ok());
        assert!(handler.registry.get("test-plugin").is_none());
    }

    #[test]
    fn test_start_plugin() {
        let mut handler = PluginHandler::new();

        handler
            .load_plugin(
                "test-plugin",
                MINIMAL_WASM,
                test_plugin_info(),
                SandboxConfig::default(),
            )
            .unwrap();

        let instance_id = handler.start_plugin("test-plugin");
        assert!(instance_id.is_ok());

        let entry = handler.registry.get("test-plugin").unwrap();
        assert_eq!(entry.state, PluginState::Running);
    }

    #[test]
    fn test_stop_plugin() {
        let mut handler = PluginHandler::new();

        handler
            .load_plugin(
                "test-plugin",
                MINIMAL_WASM,
                test_plugin_info(),
                SandboxConfig::default(),
            )
            .unwrap();

        let instance_id = handler.start_plugin("test-plugin").unwrap();
        assert!(handler.stop_plugin(instance_id).is_ok());

        let entry = handler.registry.get("test-plugin").unwrap();
        assert_eq!(entry.state, PluginState::Stopped);
    }

    #[test]
    fn test_list_plugins() {
        let mut handler = PluginHandler::new();

        handler
            .load_plugin(
                "test-plugin",
                MINIMAL_WASM,
                test_plugin_info(),
                SandboxConfig::default(),
            )
            .unwrap();

        let plugins = handler.list_plugins();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "test-plugin");
    }

    #[test]
    fn test_module_contract_manifest() {
        let handler = PluginHandler::new();
        let manifest = handler.manifest();

        assert_eq!(manifest.name, "plugin");
    }

    #[test]
    fn test_module_contract_lifecycle() {
        let mut handler = PluginHandler::new();
        let config = ModuleConfig::new();

        assert!(handler.init(config).is_ok());
        assert!(handler.start().is_ok());
        assert_eq!(handler.status(), ModuleStatus::Running);

        assert!(handler.stop().is_ok());
        assert_eq!(handler.status(), ModuleStatus::Stopped);
    }

    #[test]
    fn test_module_contract_metrics() {
        let mut handler = PluginHandler::new();

        handler
            .load_plugin(
                "test-plugin",
                MINIMAL_WASM,
                test_plugin_info(),
                SandboxConfig::default(),
            )
            .unwrap();

        let config = ModuleConfig::new();
        handler.init(config).unwrap();
        handler.start().unwrap();

        let metrics = handler.metrics();
        // Metrics should have some values
        assert!(!metrics.counters.is_empty() || !metrics.gauges.is_empty());
    }

    #[test]
    fn test_handler_stats() {
        let mut handler = PluginHandler::new();

        handler
            .load_plugin(
                "test-plugin",
                MINIMAL_WASM,
                test_plugin_info(),
                SandboxConfig::default(),
            )
            .unwrap();

        assert_eq!(handler.stats().plugins_loaded.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_invoke() {
        let mut handler = PluginHandler::new();

        handler
            .load_plugin(
                "test-plugin",
                MINIMAL_WASM,
                test_plugin_info(),
                SandboxConfig::default(),
            )
            .unwrap();

        let instance_id = handler.start_plugin("test-plugin").unwrap();

        let result = handler.invoke(instance_id, "plugin_init", &[]);
        assert!(result.is_ok());
        assert_eq!(handler.stats().invocations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_handler_with_config() {
        let config = PluginHandlerConfig {
            auto_start_plugins: true,
            hot_reload: true,
            ..Default::default()
        };

        let handler = PluginHandler::with_config(config);
        assert!(handler.config.auto_start_plugins);
        assert!(handler.config.hot_reload);
    }
}
