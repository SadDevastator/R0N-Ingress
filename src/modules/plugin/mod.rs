//! # Plugin System
//!
//! WebAssembly-based plugin system for extending R0N Gateway functionality.
//!
//! ## Features
//!
//! - **WASM Runtime**: Execute WebAssembly plugins in a sandboxed environment
//! - **Plugin API**: Well-defined interface for plugin development
//! - **Sandboxing**: Resource limits and capability-based security
//! - **Registry**: Plugin discovery, versioning, and lifecycle management
//!
//! ## Plugin Types
//!
//! - **Request Handlers**: Process HTTP requests/responses
//! - **Transformers**: Modify data in transit
//! - **Authenticators**: Custom authentication logic
//! - **Observers**: Metrics and logging extensions
//!
//! ## Example
//!
//! ```rust,ignore
//! use r0n_gateway::modules::plugin::{PluginRegistry, PluginConfig};
//!
//! let mut registry = PluginRegistry::new();
//! registry.load_plugin("./plugins/my_plugin.wasm", PluginConfig::default())?;
//!
//! let plugin = registry.get("my_plugin")?;
//! let result = plugin.invoke("on_request", &request_data)?;
//! ```

pub mod api;
pub mod error;
pub mod handler;
pub mod registry;
pub mod runtime;
pub mod sandbox;

pub use api::{
    HostFunction, PluginAction, PluginApi, PluginContext, PluginExport, RequestData, ResponseData,
};
pub use error::{PluginError, PluginResult};
pub use handler::{PluginHandler, PluginHandlerConfig, PluginSummary};
pub use registry::{PluginDependency, PluginInfo, PluginRegistry, PluginState, PluginType};
pub use runtime::{PluginInstance, PluginRuntime, RuntimeConfig, WasmModule, WasmValue};
pub use sandbox::{Capability, ResourceLimits, SandboxConfig, SandboxEnforcer, SandboxPolicy};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all public types are accessible
        let _ = PluginRegistry::new();
        let _ = PluginRuntime::new();
        let _ = SandboxConfig::default();
        let _ = ResourceLimits::default();
    }
}
