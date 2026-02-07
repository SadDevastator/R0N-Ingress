//! WASM plugin runtime.
//!
//! Provides the WebAssembly runtime for loading, compiling, and executing plugins.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::api::{PluginAction, PluginApi, PluginContext, ValueType};
use super::error::{PluginError, PluginResult};
use super::sandbox::SandboxConfig;

/// WASM plugin runtime.
#[derive(Debug)]
pub struct PluginRuntime {
    /// Runtime configuration.
    config: RuntimeConfig,
    /// Loaded modules.
    modules: HashMap<String, WasmModule>,
    /// Active instances.
    instances: HashMap<u64, PluginInstance>,
    /// Instance counter.
    instance_counter: AtomicU64,
    /// Plugin API definition.
    api: PluginApi,
    /// Runtime statistics.
    stats: RuntimeStats,
}

impl Default for PluginRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRuntime {
    /// Create a new plugin runtime.
    pub fn new() -> Self {
        Self {
            config: RuntimeConfig::default(),
            modules: HashMap::new(),
            instances: HashMap::new(),
            instance_counter: AtomicU64::new(1),
            api: PluginApi::new(),
            stats: RuntimeStats::default(),
        }
    }

    /// Create a runtime with configuration.
    pub fn with_config(config: RuntimeConfig) -> Self {
        Self {
            config,
            ..Self::new()
        }
    }

    /// Load a WASM module from bytes.
    pub fn load_module(&mut self, name: impl Into<String>, wasm_bytes: &[u8]) -> PluginResult<()> {
        let name = name.into();

        if self.modules.contains_key(&name) {
            return Err(PluginError::AlreadyExists { name });
        }

        // Validate WASM magic number
        if wasm_bytes.len() < 8 {
            return Err(PluginError::CompilationError {
                message: "Invalid WASM: too short".to_string(),
            });
        }

        // Check WASM magic number: \0asm
        if &wasm_bytes[0..4] != b"\0asm" {
            return Err(PluginError::CompilationError {
                message: "Invalid WASM: bad magic number".to_string(),
            });
        }

        // Parse WASM version
        let version =
            u32::from_le_bytes([wasm_bytes[4], wasm_bytes[5], wasm_bytes[6], wasm_bytes[7]]);

        if version != 1 {
            return Err(PluginError::CompilationError {
                message: format!("Unsupported WASM version: {}", version),
            });
        }

        // Create module
        let module = WasmModule {
            name: name.clone(),
            bytes: wasm_bytes.to_vec(),
            exports: self.parse_exports(wasm_bytes),
            imports: self.parse_imports(wasm_bytes),
            compiled: true,
            size_bytes: wasm_bytes.len(),
        };

        self.modules.insert(name, module);
        self.stats.modules_loaded.fetch_add(1, Ordering::SeqCst);

        Ok(())
    }

    /// Load a WASM module from file.
    pub fn load_module_file(
        &mut self,
        name: impl Into<String>,
        path: impl AsRef<Path>,
    ) -> PluginResult<()> {
        let bytes = std::fs::read(path.as_ref())?;
        self.load_module(name, &bytes)
    }

    /// Unload a module.
    pub fn unload_module(&mut self, name: &str) -> PluginResult<()> {
        // First terminate all instances of this module
        let instance_ids: Vec<u64> = self
            .instances
            .iter()
            .filter(|(_, i)| i.module_name == name)
            .map(|(id, _)| *id)
            .collect();

        for id in instance_ids {
            self.terminate_instance(id)?;
        }

        self.modules
            .remove(name)
            .ok_or_else(|| PluginError::NotFound {
                name: name.to_string(),
            })?;

        Ok(())
    }

    /// Get a loaded module.
    pub fn get_module(&self, name: &str) -> Option<&WasmModule> {
        self.modules.get(name)
    }

    /// List loaded modules.
    pub fn list_modules(&self) -> impl Iterator<Item = &WasmModule> {
        self.modules.values()
    }

    /// Create a new instance of a module.
    pub fn create_instance(
        &mut self,
        module_name: &str,
        sandbox: SandboxConfig,
    ) -> PluginResult<u64> {
        let module = self
            .modules
            .get(module_name)
            .ok_or_else(|| PluginError::NotFound {
                name: module_name.to_string(),
            })?;

        let instance_id = self.instance_counter.fetch_add(1, Ordering::SeqCst);

        let instance = PluginInstance {
            id: instance_id,
            module_name: module_name.to_string(),
            state: InstanceState::Created,
            sandbox,
            memory: InstanceMemory::new(self.config.initial_memory_pages),
            stats: InstanceStats::default(),
            created_at: Instant::now(),
            exports: module.exports.clone(),
        };

        self.instances.insert(instance_id, instance);
        self.stats.instances_created.fetch_add(1, Ordering::SeqCst);

        Ok(instance_id)
    }

    /// Initialize an instance.
    pub fn init_instance(&mut self, instance_id: u64) -> PluginResult<()> {
        let instance =
            self.instances
                .get_mut(&instance_id)
                .ok_or_else(|| PluginError::NotFound {
                    name: format!("instance:{}", instance_id),
                })?;

        if instance.state != InstanceState::Created {
            return Err(PluginError::InvalidState {
                current: format!("{:?}", instance.state),
                expected: "Created".to_string(),
            });
        }

        // Call plugin_init if it exists
        if instance.exports.contains_key("plugin_init") {
            // In a real implementation, this would call the WASM function
            // For now, we simulate success
        }

        instance.state = InstanceState::Initialized;
        Ok(())
    }

    /// Start an instance.
    pub fn start_instance(&mut self, instance_id: u64) -> PluginResult<()> {
        let instance =
            self.instances
                .get_mut(&instance_id)
                .ok_or_else(|| PluginError::NotFound {
                    name: format!("instance:{}", instance_id),
                })?;

        if instance.state != InstanceState::Initialized {
            return Err(PluginError::InvalidState {
                current: format!("{:?}", instance.state),
                expected: "Initialized".to_string(),
            });
        }

        // Call plugin_start if it exists
        if instance.exports.contains_key("plugin_start") {
            // In a real implementation, this would call the WASM function
        }

        instance.state = InstanceState::Running;
        self.stats.instances_running.fetch_add(1, Ordering::SeqCst);

        Ok(())
    }

    /// Stop an instance.
    pub fn stop_instance(&mut self, instance_id: u64) -> PluginResult<()> {
        let instance =
            self.instances
                .get_mut(&instance_id)
                .ok_or_else(|| PluginError::NotFound {
                    name: format!("instance:{}", instance_id),
                })?;

        if instance.state != InstanceState::Running {
            return Err(PluginError::InvalidState {
                current: format!("{:?}", instance.state),
                expected: "Running".to_string(),
            });
        }

        // Call plugin_stop if it exists
        if instance.exports.contains_key("plugin_stop") {
            // In a real implementation, this would call the WASM function
        }

        instance.state = InstanceState::Stopped;
        self.stats.instances_running.fetch_sub(1, Ordering::SeqCst);

        Ok(())
    }

    /// Terminate an instance.
    pub fn terminate_instance(&mut self, instance_id: u64) -> PluginResult<()> {
        let instance =
            self.instances
                .remove(&instance_id)
                .ok_or_else(|| PluginError::NotFound {
                    name: format!("instance:{}", instance_id),
                })?;

        if instance.state == InstanceState::Running {
            self.stats.instances_running.fetch_sub(1, Ordering::SeqCst);
        }

        Ok(())
    }

    /// Get an instance.
    pub fn get_instance(&self, instance_id: u64) -> Option<&PluginInstance> {
        self.instances.get(&instance_id)
    }

    /// Invoke a function on an instance.
    pub fn invoke(
        &mut self,
        instance_id: u64,
        function: &str,
        _args: &[WasmValue],
    ) -> PluginResult<Vec<WasmValue>> {
        let instance =
            self.instances
                .get_mut(&instance_id)
                .ok_or_else(|| PluginError::NotFound {
                    name: format!("instance:{}", instance_id),
                })?;

        if instance.state != InstanceState::Running {
            return Err(PluginError::InvalidState {
                current: format!("{:?}", instance.state),
                expected: "Running".to_string(),
            });
        }

        // Check if function exists
        if !instance.exports.contains_key(function) {
            return Err(PluginError::FunctionNotFound {
                plugin: instance.module_name.clone(),
                function: function.to_string(),
            });
        }

        // Check resource limits
        instance.sandbox.limits.check_invocation()?;

        let start = Instant::now();

        // In a real implementation, this would:
        // 1. Set up the execution environment
        // 2. Call the WASM function with args
        // 3. Handle any traps or errors
        // 4. Return the result

        // Simulate execution
        let result = vec![WasmValue::I32(0)];

        instance.stats.invocations += 1;
        instance.stats.total_execution_time += start.elapsed();

        self.stats.invocations.fetch_add(1, Ordering::SeqCst);

        Ok(result)
    }

    /// Invoke a request handler.
    pub fn invoke_request_handler(
        &mut self,
        instance_id: u64,
        ctx: &PluginContext,
        request_data: &[u8],
    ) -> PluginResult<(PluginAction, Option<Vec<u8>>)> {
        let instance =
            self.instances
                .get_mut(&instance_id)
                .ok_or_else(|| PluginError::NotFound {
                    name: format!("instance:{}", instance_id),
                })?;

        if !instance.exports.contains_key("on_request") {
            return Ok((PluginAction::Continue, None));
        }

        // Check timeout
        if let Some(deadline) = ctx.deadline {
            if deadline.is_zero() {
                return Err(PluginError::Timeout { timeout_ms: 0 });
            }
        }

        // Allocate memory for request data
        let ptr = instance.memory.allocate(request_data.len())?;
        instance.memory.write(ptr, request_data)?;

        // Invoke the function
        let result = self.invoke(
            instance_id,
            "on_request",
            &[
                WasmValue::I32(ptr as i32),
                WasmValue::I32(request_data.len() as i32),
            ],
        )?;

        // Parse result
        let action = result
            .first()
            .and_then(|v| v.as_i32())
            .map(PluginAction::from_i32)
            .unwrap_or(PluginAction::Continue);

        Ok((action, None))
    }

    /// Parse exports from WASM bytes (simplified).
    fn parse_exports(&self, _wasm_bytes: &[u8]) -> HashMap<String, ExportInfo> {
        // In a real implementation, this would parse the WASM export section
        let mut exports = HashMap::new();
        exports.insert(
            "plugin_init".to_string(),
            ExportInfo {
                name: "plugin_init".to_string(),
                kind: ExportKind::Function,
                index: 0,
            },
        );
        exports.insert(
            "plugin_info".to_string(),
            ExportInfo {
                name: "plugin_info".to_string(),
                kind: ExportKind::Function,
                index: 1,
            },
        );
        exports
    }

    /// Parse imports from WASM bytes (simplified).
    fn parse_imports(&self, _wasm_bytes: &[u8]) -> Vec<ImportInfo> {
        // In a real implementation, this would parse the WASM import section
        Vec::new()
    }

    /// Get runtime statistics.
    pub fn stats(&self) -> &RuntimeStats {
        &self.stats
    }

    /// Get the plugin API.
    pub fn api(&self) -> &PluginApi {
        &self.api
    }
}

/// Runtime configuration.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Initial memory pages (64KB each).
    pub initial_memory_pages: u32,
    /// Maximum memory pages.
    pub max_memory_pages: u32,
    /// Enable WASM SIMD.
    pub enable_simd: bool,
    /// Enable WASM threads.
    pub enable_threads: bool,
    /// Enable WASM bulk memory operations.
    pub enable_bulk_memory: bool,
    /// Enable WASM reference types.
    pub enable_reference_types: bool,
    /// Fuel limit for metering (0 = unlimited).
    pub fuel_limit: u64,
    /// Enable epoch-based interruption.
    pub enable_epoch_interruption: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            initial_memory_pages: 16, // 1MB
            max_memory_pages: 256,    // 16MB
            enable_simd: false,
            enable_threads: false,
            enable_bulk_memory: true,
            enable_reference_types: false,
            fuel_limit: 0,
            enable_epoch_interruption: true,
        }
    }
}

/// WASM module.
#[derive(Debug, Clone)]
pub struct WasmModule {
    /// Module name.
    pub name: String,
    /// WASM bytes.
    bytes: Vec<u8>,
    /// Exported functions/memories/etc.
    pub exports: HashMap<String, ExportInfo>,
    /// Required imports.
    pub imports: Vec<ImportInfo>,
    /// Whether module is compiled.
    pub compiled: bool,
    /// Module size in bytes.
    pub size_bytes: usize,
}

impl WasmModule {
    /// Get the WASM bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Check if module has an export.
    pub fn has_export(&self, name: &str) -> bool {
        self.exports.contains_key(name)
    }

    /// Get export info.
    pub fn get_export(&self, name: &str) -> Option<&ExportInfo> {
        self.exports.get(name)
    }
}

/// Export information.
#[derive(Debug, Clone)]
pub struct ExportInfo {
    /// Export name.
    pub name: String,
    /// Export kind.
    pub kind: ExportKind,
    /// Index in the respective section.
    pub index: u32,
}

/// Export kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportKind {
    /// Function export.
    Function,
    /// Table export.
    Table,
    /// Memory export.
    Memory,
    /// Global export.
    Global,
}

/// Import information.
#[derive(Debug, Clone)]
pub struct ImportInfo {
    /// Module name.
    pub module: String,
    /// Import name.
    pub name: String,
    /// Import kind.
    pub kind: ExportKind,
}

/// Plugin instance.
#[derive(Debug)]
pub struct PluginInstance {
    /// Instance ID.
    pub id: u64,
    /// Module name.
    pub module_name: String,
    /// Instance state.
    pub state: InstanceState,
    /// Sandbox configuration.
    pub sandbox: SandboxConfig,
    /// Instance memory.
    memory: InstanceMemory,
    /// Instance statistics.
    pub stats: InstanceStats,
    /// Creation time.
    created_at: Instant,
    /// Cached exports.
    exports: HashMap<String, ExportInfo>,
}

impl PluginInstance {
    /// Get instance uptime.
    pub fn uptime(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Check if instance is running.
    pub fn is_running(&self) -> bool {
        self.state == InstanceState::Running
    }
}

/// Instance state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceState {
    /// Instance created but not initialized.
    Created,
    /// Instance initialized.
    Initialized,
    /// Instance running.
    Running,
    /// Instance stopped.
    Stopped,
    /// Instance failed.
    Failed,
}

/// Instance memory management.
#[derive(Debug)]
struct InstanceMemory {
    /// Memory pages (64KB each).
    #[allow(dead_code)]
    pages: u32,
    /// Simulated memory.
    data: Vec<u8>,
    /// Allocation pointer.
    alloc_ptr: usize,
}

impl InstanceMemory {
    fn new(pages: u32) -> Self {
        let size = pages as usize * 65536;
        Self {
            pages,
            data: vec![0; size],
            alloc_ptr: 0,
        }
    }

    fn allocate(&mut self, size: usize) -> PluginResult<usize> {
        let ptr = self.alloc_ptr;
        if ptr + size > self.data.len() {
            return Err(PluginError::MemoryError {
                message: format!("Out of memory: need {} bytes", size),
            });
        }
        self.alloc_ptr += size;
        Ok(ptr)
    }

    fn write(&mut self, ptr: usize, data: &[u8]) -> PluginResult<()> {
        if ptr + data.len() > self.data.len() {
            return Err(PluginError::MemoryError {
                message: "Write out of bounds".to_string(),
            });
        }
        self.data[ptr..ptr + data.len()].copy_from_slice(data);
        Ok(())
    }

    #[allow(dead_code)]
    fn read(&self, ptr: usize, len: usize) -> PluginResult<&[u8]> {
        if ptr + len > self.data.len() {
            return Err(PluginError::MemoryError {
                message: "Read out of bounds".to_string(),
            });
        }
        Ok(&self.data[ptr..ptr + len])
    }
}

/// Instance statistics.
#[derive(Debug, Default)]
pub struct InstanceStats {
    /// Number of invocations.
    pub invocations: u64,
    /// Total execution time.
    pub total_execution_time: Duration,
    /// Memory used.
    pub memory_used: u64,
    /// Fuel consumed.
    pub fuel_consumed: u64,
}

/// Runtime statistics.
#[derive(Debug, Default)]
pub struct RuntimeStats {
    /// Modules loaded.
    pub modules_loaded: AtomicU64,
    /// Instances created.
    pub instances_created: AtomicU64,
    /// Instances currently running.
    pub instances_running: AtomicU64,
    /// Total invocations.
    pub invocations: AtomicU64,
    /// Compilation errors.
    pub compilation_errors: AtomicU64,
    /// Execution errors.
    pub execution_errors: AtomicU64,
}

/// WASM value.
#[derive(Debug, Clone)]
pub enum WasmValue {
    /// 32-bit integer.
    I32(i32),
    /// 64-bit integer.
    I64(i64),
    /// 32-bit float.
    F32(f32),
    /// 64-bit float.
    F64(f64),
}

impl WasmValue {
    /// Get as i32.
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Self::I32(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as i64.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::I64(v) => Some(*v),
            _ => None,
        }
    }

    /// Get the value type.
    pub fn value_type(&self) -> ValueType {
        match self {
            Self::I32(_) => ValueType::I32,
            Self::I64(_) => ValueType::I64,
            Self::F32(_) => ValueType::F32,
            Self::F64(_) => ValueType::F64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid minimal WASM module
    const MINIMAL_WASM: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, // magic: \0asm
        0x01, 0x00, 0x00, 0x00, // version: 1
    ];

    #[test]
    fn test_runtime_new() {
        let runtime = PluginRuntime::new();
        assert_eq!(runtime.modules.len(), 0);
        assert_eq!(runtime.instances.len(), 0);
    }

    #[test]
    fn test_load_module() {
        let mut runtime = PluginRuntime::new();

        assert!(runtime.load_module("test", MINIMAL_WASM).is_ok());
        assert!(runtime.get_module("test").is_some());
    }

    #[test]
    fn test_load_module_invalid_magic() {
        let mut runtime = PluginRuntime::new();
        let bad_wasm = &[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];

        let result = runtime.load_module("bad", bad_wasm);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_module_too_short() {
        let mut runtime = PluginRuntime::new();
        let short = &[0x00, 0x61, 0x73, 0x6d];

        let result = runtime.load_module("short", short);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_module_duplicate() {
        let mut runtime = PluginRuntime::new();

        assert!(runtime.load_module("test", MINIMAL_WASM).is_ok());
        assert!(runtime.load_module("test", MINIMAL_WASM).is_err());
    }

    #[test]
    fn test_unload_module() {
        let mut runtime = PluginRuntime::new();

        runtime.load_module("test", MINIMAL_WASM).unwrap();
        assert!(runtime.unload_module("test").is_ok());
        assert!(runtime.get_module("test").is_none());
    }

    #[test]
    fn test_create_instance() {
        let mut runtime = PluginRuntime::new();
        runtime.load_module("test", MINIMAL_WASM).unwrap();

        let instance_id = runtime
            .create_instance("test", SandboxConfig::default())
            .unwrap();
        assert!(runtime.get_instance(instance_id).is_some());
    }

    #[test]
    fn test_instance_lifecycle() {
        let mut runtime = PluginRuntime::new();
        runtime.load_module("test", MINIMAL_WASM).unwrap();

        let id = runtime
            .create_instance("test", SandboxConfig::default())
            .unwrap();

        // Created -> Initialized
        assert!(runtime.init_instance(id).is_ok());
        assert_eq!(
            runtime.get_instance(id).unwrap().state,
            InstanceState::Initialized
        );

        // Initialized -> Running
        assert!(runtime.start_instance(id).is_ok());
        assert_eq!(
            runtime.get_instance(id).unwrap().state,
            InstanceState::Running
        );

        // Running -> Stopped
        assert!(runtime.stop_instance(id).is_ok());
        assert_eq!(
            runtime.get_instance(id).unwrap().state,
            InstanceState::Stopped
        );
    }

    #[test]
    fn test_instance_invalid_state() {
        let mut runtime = PluginRuntime::new();
        runtime.load_module("test", MINIMAL_WASM).unwrap();

        let id = runtime
            .create_instance("test", SandboxConfig::default())
            .unwrap();

        // Cannot start before init
        assert!(runtime.start_instance(id).is_err());

        // Cannot stop before start
        runtime.init_instance(id).unwrap();
        assert!(runtime.stop_instance(id).is_err());
    }

    #[test]
    fn test_terminate_instance() {
        let mut runtime = PluginRuntime::new();
        runtime.load_module("test", MINIMAL_WASM).unwrap();

        let id = runtime
            .create_instance("test", SandboxConfig::default())
            .unwrap();
        assert!(runtime.terminate_instance(id).is_ok());
        assert!(runtime.get_instance(id).is_none());
    }

    #[test]
    fn test_invoke_function() {
        let mut runtime = PluginRuntime::new();
        runtime.load_module("test", MINIMAL_WASM).unwrap();

        let id = runtime
            .create_instance("test", SandboxConfig::default())
            .unwrap();
        runtime.init_instance(id).unwrap();
        runtime.start_instance(id).unwrap();

        let result = runtime.invoke(id, "plugin_init", &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invoke_nonexistent_function() {
        let mut runtime = PluginRuntime::new();
        runtime.load_module("test", MINIMAL_WASM).unwrap();

        let id = runtime
            .create_instance("test", SandboxConfig::default())
            .unwrap();
        runtime.init_instance(id).unwrap();
        runtime.start_instance(id).unwrap();

        let result = runtime.invoke(id, "nonexistent", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_wasm_value() {
        let i32_val = WasmValue::I32(42);
        assert_eq!(i32_val.as_i32(), Some(42));
        assert_eq!(i32_val.value_type(), ValueType::I32);

        let i64_val = WasmValue::I64(100);
        assert_eq!(i64_val.as_i64(), Some(100));
        assert_eq!(i64_val.value_type(), ValueType::I64);
    }

    #[test]
    fn test_runtime_stats() {
        let mut runtime = PluginRuntime::new();

        runtime.load_module("test", MINIMAL_WASM).unwrap();
        assert_eq!(runtime.stats().modules_loaded.load(Ordering::SeqCst), 1);

        let id = runtime
            .create_instance("test", SandboxConfig::default())
            .unwrap();
        assert_eq!(runtime.stats().instances_created.load(Ordering::SeqCst), 1);

        runtime.init_instance(id).unwrap();
        runtime.start_instance(id).unwrap();
        assert_eq!(runtime.stats().instances_running.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_instance_uptime() {
        let mut runtime = PluginRuntime::new();
        runtime.load_module("test", MINIMAL_WASM).unwrap();

        let id = runtime
            .create_instance("test", SandboxConfig::default())
            .unwrap();
        let instance = runtime.get_instance(id).unwrap();

        // Uptime should be positive
        assert!(instance.uptime().as_nanos() > 0);
    }

    #[test]
    fn test_list_modules() {
        let mut runtime = PluginRuntime::new();

        runtime.load_module("mod1", MINIMAL_WASM).unwrap();
        runtime.load_module("mod2", MINIMAL_WASM).unwrap();

        let modules: Vec<_> = runtime.list_modules().collect();
        assert_eq!(modules.len(), 2);
    }
}
