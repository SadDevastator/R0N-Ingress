//! # Module Contract
//!
//! This module defines the core contract that all R0N Ingress modules must implement.
//! The contract provides a standardized interface for lifecycle management,
//! configuration, metrics, and health reporting.

mod config;
mod contract;
mod error;
mod manifest;
mod status;

pub use config::ModuleConfig;
pub use contract::{ContractVersion, MetricsPayload, ModuleContract, CONTRACT_VERSION};
pub use error::{ModuleError, ModuleResult};
pub use manifest::{Capability, Dependency, ModuleManifest};
pub use status::ModuleStatus;
