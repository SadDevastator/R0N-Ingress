//! Plugin API definitions.
//!
//! Defines the interface between the host (R0N Gateway) and plugins,
//! including host functions, plugin exports, and data types.

use std::collections::HashMap;
use std::time::Duration;

/// Plugin API version.
pub const API_VERSION: u32 = 1;

/// Plugin context passed to plugin functions.
#[derive(Debug, Clone)]
pub struct PluginContext {
    /// Request ID (if applicable).
    pub request_id: Option<String>,
    /// Plugin name.
    pub plugin_name: String,
    /// Plugin instance ID.
    pub instance_id: u64,
    /// Execution deadline.
    pub deadline: Option<Duration>,
    /// Context metadata.
    pub metadata: HashMap<String, String>,
    /// Trace context for distributed tracing.
    pub trace_context: Option<TraceContext>,
}

impl PluginContext {
    /// Create a new plugin context.
    pub fn new(plugin_name: impl Into<String>, instance_id: u64) -> Self {
        Self {
            request_id: None,
            plugin_name: plugin_name.into(),
            instance_id,
            deadline: None,
            metadata: HashMap::new(),
            trace_context: None,
        }
    }

    /// Set the request ID.
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Set the execution deadline.
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Add metadata.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Set trace context.
    pub fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace_context = Some(trace);
        self
    }
}

/// Trace context for distributed tracing.
#[derive(Debug, Clone)]
pub struct TraceContext {
    /// Trace ID.
    pub trace_id: String,
    /// Span ID.
    pub span_id: String,
    /// Parent span ID.
    pub parent_span_id: Option<String>,
    /// Trace flags.
    pub flags: u8,
}

/// Plugin API interface definition.
#[derive(Debug, Clone)]
pub struct PluginApi {
    /// API version.
    pub version: u32,
    /// Required exports from plugin.
    pub required_exports: Vec<PluginExport>,
    /// Optional exports from plugin.
    pub optional_exports: Vec<PluginExport>,
    /// Host functions provided to plugin.
    pub host_functions: Vec<HostFunction>,
}

impl Default for PluginApi {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginApi {
    /// Create a new API definition with standard exports.
    pub fn new() -> Self {
        Self {
            version: API_VERSION,
            required_exports: vec![
                PluginExport::new("plugin_init")
                    .returns(ValueType::I32)
                    .description("Initialize plugin, returns 0 on success"),
                PluginExport::new("plugin_info")
                    .returns(ValueType::I32)
                    .description("Get plugin info pointer"),
            ],
            optional_exports: vec![
                // Request lifecycle
                PluginExport::new("on_request")
                    .param("ctx_ptr", ValueType::I32)
                    .param("ctx_len", ValueType::I32)
                    .returns(ValueType::I32)
                    .description("Handle incoming request"),
                PluginExport::new("on_response")
                    .param("ctx_ptr", ValueType::I32)
                    .param("ctx_len", ValueType::I32)
                    .returns(ValueType::I32)
                    .description("Handle outgoing response"),
                // Lifecycle hooks
                PluginExport::new("plugin_start")
                    .returns(ValueType::I32)
                    .description("Called when plugin starts"),
                PluginExport::new("plugin_stop")
                    .returns(ValueType::I32)
                    .description("Called when plugin stops"),
                PluginExport::new("plugin_reload")
                    .param("config_ptr", ValueType::I32)
                    .param("config_len", ValueType::I32)
                    .returns(ValueType::I32)
                    .description("Reload plugin configuration"),
                // Memory management
                PluginExport::new("alloc")
                    .param("size", ValueType::I32)
                    .returns(ValueType::I32)
                    .description("Allocate memory in plugin"),
                PluginExport::new("dealloc")
                    .param("ptr", ValueType::I32)
                    .param("size", ValueType::I32)
                    .description("Deallocate memory in plugin"),
            ],
            host_functions: Self::standard_host_functions(),
        }
    }

    /// Get standard host functions.
    fn standard_host_functions() -> Vec<HostFunction> {
        vec![
            // Logging
            HostFunction::new("log_debug")
                .param("msg_ptr", ValueType::I32)
                .param("msg_len", ValueType::I32)
                .module("env")
                .description("Log debug message"),
            HostFunction::new("log_info")
                .param("msg_ptr", ValueType::I32)
                .param("msg_len", ValueType::I32)
                .module("env")
                .description("Log info message"),
            HostFunction::new("log_warn")
                .param("msg_ptr", ValueType::I32)
                .param("msg_len", ValueType::I32)
                .module("env")
                .description("Log warning message"),
            HostFunction::new("log_error")
                .param("msg_ptr", ValueType::I32)
                .param("msg_len", ValueType::I32)
                .module("env")
                .description("Log error message"),
            // Configuration
            HostFunction::new("config_get")
                .param("key_ptr", ValueType::I32)
                .param("key_len", ValueType::I32)
                .param("buf_ptr", ValueType::I32)
                .param("buf_len", ValueType::I32)
                .returns(ValueType::I32)
                .module("env")
                .description("Get configuration value"),
            // Metrics
            HostFunction::new("metric_counter")
                .param("name_ptr", ValueType::I32)
                .param("name_len", ValueType::I32)
                .param("value", ValueType::I64)
                .module("env")
                .description("Increment counter metric"),
            HostFunction::new("metric_gauge")
                .param("name_ptr", ValueType::I32)
                .param("name_len", ValueType::I32)
                .param("value", ValueType::F64)
                .module("env")
                .description("Set gauge metric"),
            HostFunction::new("metric_histogram")
                .param("name_ptr", ValueType::I32)
                .param("name_len", ValueType::I32)
                .param("value", ValueType::F64)
                .module("env")
                .description("Record histogram observation"),
            // HTTP (requires network capability)
            HostFunction::new("http_request")
                .param("req_ptr", ValueType::I32)
                .param("req_len", ValueType::I32)
                .param("resp_ptr", ValueType::I32)
                .param("resp_len", ValueType::I32)
                .returns(ValueType::I32)
                .module("http")
                .requires_capability("network")
                .description("Make HTTP request"),
            // Key-value store
            HostFunction::new("kv_get")
                .param("key_ptr", ValueType::I32)
                .param("key_len", ValueType::I32)
                .param("val_ptr", ValueType::I32)
                .param("val_len", ValueType::I32)
                .returns(ValueType::I32)
                .module("kv")
                .requires_capability("storage")
                .description("Get value from key-value store"),
            HostFunction::new("kv_set")
                .param("key_ptr", ValueType::I32)
                .param("key_len", ValueType::I32)
                .param("val_ptr", ValueType::I32)
                .param("val_len", ValueType::I32)
                .returns(ValueType::I32)
                .module("kv")
                .requires_capability("storage")
                .description("Set value in key-value store"),
            HostFunction::new("kv_delete")
                .param("key_ptr", ValueType::I32)
                .param("key_len", ValueType::I32)
                .returns(ValueType::I32)
                .module("kv")
                .requires_capability("storage")
                .description("Delete value from key-value store"),
            // Time
            HostFunction::new("time_now")
                .returns(ValueType::I64)
                .module("env")
                .description("Get current timestamp in milliseconds"),
            HostFunction::new("time_sleep")
                .param("ms", ValueType::I64)
                .module("env")
                .description("Sleep for specified milliseconds"),
            // Random
            HostFunction::new("random_bytes")
                .param("buf_ptr", ValueType::I32)
                .param("buf_len", ValueType::I32)
                .returns(ValueType::I32)
                .module("env")
                .description("Fill buffer with random bytes"),
        ]
    }

    /// Check if an export is required.
    pub fn is_required(&self, name: &str) -> bool {
        self.required_exports.iter().any(|e| e.name == name)
    }

    /// Get an export definition by name.
    pub fn get_export(&self, name: &str) -> Option<&PluginExport> {
        self.required_exports
            .iter()
            .chain(self.optional_exports.iter())
            .find(|e| e.name == name)
    }

    /// Get a host function by name.
    pub fn get_host_function(&self, name: &str) -> Option<&HostFunction> {
        self.host_functions.iter().find(|f| f.name == name)
    }
}

/// Plugin export function definition.
#[derive(Debug, Clone)]
pub struct PluginExport {
    /// Function name.
    pub name: String,
    /// Function parameters.
    pub params: Vec<FunctionParam>,
    /// Return type (if any).
    pub returns: Option<ValueType>,
    /// Function description.
    pub description: Option<String>,
}

impl PluginExport {
    /// Create a new export definition.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            params: Vec::new(),
            returns: None,
            description: None,
        }
    }

    /// Add a parameter.
    pub fn param(mut self, name: impl Into<String>, value_type: ValueType) -> Self {
        self.params.push(FunctionParam {
            name: name.into(),
            value_type,
        });
        self
    }

    /// Set return type.
    pub fn returns(mut self, value_type: ValueType) -> Self {
        self.returns = Some(value_type);
        self
    }

    /// Set description.
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Get function signature string.
    pub fn signature(&self) -> String {
        let params: Vec<String> = self
            .params
            .iter()
            .map(|p| format!("{}: {:?}", p.name, p.value_type))
            .collect();
        let ret = self
            .returns
            .as_ref()
            .map(|r| format!(" -> {:?}", r))
            .unwrap_or_default();
        format!("{}({}){}", self.name, params.join(", "), ret)
    }
}

/// Plugin import (host function) definition.
pub type PluginImport = HostFunction;

/// Host function provided to plugins.
#[derive(Debug, Clone)]
pub struct HostFunction {
    /// Function name.
    pub name: String,
    /// Module name (for WASM imports).
    pub module: String,
    /// Function parameters.
    pub params: Vec<FunctionParam>,
    /// Return type (if any).
    pub returns: Option<ValueType>,
    /// Required capability to use this function.
    pub required_capability: Option<String>,
    /// Function description.
    pub description: Option<String>,
}

impl HostFunction {
    /// Create a new host function definition.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            module: "env".to_string(),
            params: Vec::new(),
            returns: None,
            required_capability: None,
            description: None,
        }
    }

    /// Set module name.
    pub fn module(mut self, module: impl Into<String>) -> Self {
        self.module = module.into();
        self
    }

    /// Add a parameter.
    pub fn param(mut self, name: impl Into<String>, value_type: ValueType) -> Self {
        self.params.push(FunctionParam {
            name: name.into(),
            value_type,
        });
        self
    }

    /// Set return type.
    pub fn returns(mut self, value_type: ValueType) -> Self {
        self.returns = Some(value_type);
        self
    }

    /// Set required capability.
    pub fn requires_capability(mut self, cap: impl Into<String>) -> Self {
        self.required_capability = Some(cap.into());
        self
    }

    /// Set description.
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Get function signature string.
    pub fn signature(&self) -> String {
        let params: Vec<String> = self
            .params
            .iter()
            .map(|p| format!("{}: {:?}", p.name, p.value_type))
            .collect();
        let ret = self
            .returns
            .as_ref()
            .map(|r| format!(" -> {:?}", r))
            .unwrap_or_default();
        format!(
            "{}::{}({}){}",
            self.module,
            self.name,
            params.join(", "),
            ret
        )
    }
}

/// Function parameter.
#[derive(Debug, Clone)]
pub struct FunctionParam {
    /// Parameter name.
    pub name: String,
    /// Parameter type.
    pub value_type: ValueType,
}

/// WASM value types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    /// 32-bit integer.
    I32,
    /// 64-bit integer.
    I64,
    /// 32-bit float.
    F32,
    /// 64-bit float.
    F64,
    /// 128-bit vector (SIMD).
    V128,
    /// Function reference.
    FuncRef,
    /// External reference.
    ExternRef,
}

/// Request data passed to plugins.
#[derive(Debug, Clone)]
pub struct RequestData {
    /// HTTP method.
    pub method: String,
    /// Request path.
    pub path: String,
    /// Query string.
    pub query: Option<String>,
    /// Request headers.
    pub headers: HashMap<String, String>,
    /// Request body.
    pub body: Option<Vec<u8>>,
    /// Client address.
    pub client_addr: Option<String>,
    /// Protocol version.
    pub protocol: String,
}

impl RequestData {
    /// Create a new request.
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            query: None,
            headers: HashMap::new(),
            body: None,
            client_addr: None,
            protocol: "HTTP/1.1".to_string(),
        }
    }

    /// Set a header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Set the body.
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Simple serialization format for WASM
        let mut buf = Vec::new();

        // Method
        buf.extend_from_slice(&(self.method.len() as u32).to_le_bytes());
        buf.extend_from_slice(self.method.as_bytes());

        // Path
        buf.extend_from_slice(&(self.path.len() as u32).to_le_bytes());
        buf.extend_from_slice(self.path.as_bytes());

        // Headers count
        buf.extend_from_slice(&(self.headers.len() as u32).to_le_bytes());
        for (key, value) in &self.headers {
            buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
            buf.extend_from_slice(key.as_bytes());
            buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
            buf.extend_from_slice(value.as_bytes());
        }

        // Body
        if let Some(ref body) = self.body {
            buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
            buf.extend_from_slice(body);
        } else {
            buf.extend_from_slice(&0u32.to_le_bytes());
        }

        buf
    }
}

/// Response data returned from plugins.
#[derive(Debug, Clone)]
pub struct ResponseData {
    /// Status code.
    pub status: u16,
    /// Response headers.
    pub headers: HashMap<String, String>,
    /// Response body.
    pub body: Option<Vec<u8>>,
}

impl ResponseData {
    /// Create a new response.
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: HashMap::new(),
            body: None,
        }
    }

    /// Set a header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Set the body.
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }
}

/// Plugin action result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginAction {
    /// Continue processing.
    Continue,
    /// Modify request/response.
    Modify,
    /// Respond immediately (short-circuit).
    Respond,
    /// Reject the request.
    Reject,
    /// Error occurred.
    Error,
}

impl PluginAction {
    /// Parse from i32 return value.
    pub fn from_i32(value: i32) -> Self {
        match value {
            0 => Self::Continue,
            1 => Self::Modify,
            2 => Self::Respond,
            3 => Self::Reject,
            _ => Self::Error,
        }
    }

    /// Convert to i32.
    pub fn to_i32(&self) -> i32 {
        match self {
            Self::Continue => 0,
            Self::Modify => 1,
            Self::Respond => 2,
            Self::Reject => 3,
            Self::Error => -1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_context() {
        let ctx = PluginContext::new("my-plugin", 1)
            .with_request_id("req-123")
            .with_deadline(Duration::from_secs(5))
            .with_metadata("key", "value");

        assert_eq!(ctx.plugin_name, "my-plugin");
        assert_eq!(ctx.request_id, Some("req-123".to_string()));
        assert!(ctx.deadline.is_some());
        assert_eq!(ctx.metadata.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_plugin_api() {
        let api = PluginApi::new();

        assert_eq!(api.version, API_VERSION);
        assert!(!api.required_exports.is_empty());
        assert!(!api.host_functions.is_empty());

        assert!(api.is_required("plugin_init"));
        assert!(!api.is_required("on_request"));
    }

    #[test]
    fn test_plugin_export() {
        let export = PluginExport::new("on_request")
            .param("ctx_ptr", ValueType::I32)
            .param("ctx_len", ValueType::I32)
            .returns(ValueType::I32)
            .description("Handle request");

        assert_eq!(export.name, "on_request");
        assert_eq!(export.params.len(), 2);
        assert_eq!(export.returns, Some(ValueType::I32));

        let sig = export.signature();
        assert!(sig.contains("on_request"));
        assert!(sig.contains("ctx_ptr"));
    }

    #[test]
    fn test_host_function() {
        let func = HostFunction::new("log_info")
            .module("env")
            .param("msg_ptr", ValueType::I32)
            .param("msg_len", ValueType::I32)
            .requires_capability("logging")
            .description("Log info message");

        assert_eq!(func.name, "log_info");
        assert_eq!(func.module, "env");
        assert_eq!(func.required_capability, Some("logging".to_string()));
    }

    #[test]
    fn test_request_data() {
        let req = RequestData::new("GET", "/api/users")
            .with_header("Content-Type", "application/json")
            .with_body(b"{}".to_vec());

        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/users");
        assert!(req.headers.contains_key("Content-Type"));
        assert!(req.body.is_some());
    }

    #[test]
    fn test_request_data_serialize() {
        let req = RequestData::new("POST", "/api")
            .with_header("X-Custom", "value")
            .with_body(b"test".to_vec());

        let bytes = req.to_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_response_data() {
        let resp = ResponseData::new(200)
            .with_header("Content-Type", "text/plain")
            .with_body(b"Hello".to_vec());

        assert_eq!(resp.status, 200);
        assert!(resp.headers.contains_key("Content-Type"));
        assert_eq!(resp.body, Some(b"Hello".to_vec()));
    }

    #[test]
    fn test_plugin_action() {
        assert_eq!(PluginAction::from_i32(0), PluginAction::Continue);
        assert_eq!(PluginAction::from_i32(1), PluginAction::Modify);
        assert_eq!(PluginAction::from_i32(2), PluginAction::Respond);
        assert_eq!(PluginAction::from_i32(3), PluginAction::Reject);
        assert_eq!(PluginAction::from_i32(-1), PluginAction::Error);
        assert_eq!(PluginAction::from_i32(99), PluginAction::Error);

        assert_eq!(PluginAction::Continue.to_i32(), 0);
        assert_eq!(PluginAction::Error.to_i32(), -1);
    }

    #[test]
    fn test_api_get_export() {
        let api = PluginApi::new();

        let export = api.get_export("plugin_init");
        assert!(export.is_some());

        let export = api.get_export("nonexistent");
        assert!(export.is_none());
    }

    #[test]
    fn test_api_get_host_function() {
        let api = PluginApi::new();

        let func = api.get_host_function("log_info");
        assert!(func.is_some());

        let func = api.get_host_function("nonexistent");
        assert!(func.is_none());
    }
}
