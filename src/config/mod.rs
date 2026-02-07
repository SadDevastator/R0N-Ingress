//! # Configuration System
//!
//! This module provides TOML-based configuration management for R0N Gateway.
//! It includes parsing, validation, schema generation, and hot-reload support.
//!
//! ## Features
//!
//! - TOML configuration file parsing
//! - Type-safe configuration with validation
//! - JSON Schema generation for IDE support
//! - Hot-reload infrastructure (disabled by default)
//!
//! ## Example Configuration
//!
//! ```toml
//! [gateway]
//! name = "my-gateway"
//! bind_address = "0.0.0.0"
//! bind_port = 8080
//!
//! [logging]
//! level = "info"
//! format = "json"
//!
//! [[modules]]
//! name = "tcp-router"
//! enabled = true
//!
//! [modules.config]
//! listen_port = 8080
//! ```

mod error;
mod loader;
mod schema;
mod types;
mod validation;
mod watcher;

pub use error::{ConfigError, ConfigResult};
pub use loader::ConfigLoader;
pub use schema::{ConfigSchema, SchemaField, SchemaType};
pub use types::{GatewayConfig, LoggingConfig, ModuleEntry};
pub use validation::{
    BasicValidator, PortConflictValidator, ValidationError, ValidationResult, Validator,
};
pub use watcher::{ConfigWatcher, WatchedConfigBuilder, WatcherConfig};
