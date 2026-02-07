//! # R0N Gateway
//!
//! A high-performance, protocol-agnostic gateway designed to route, secure,
//! and manage traffic for multiple services and protocols.
//!
//! ## Features
//!
//! - Multi-protocol traffic routing (L4 & L7)
//! - TLS termination and passthrough
//! - Load balancing with multiple strategies
//! - Rate limiting and traffic shaping
//! - Prometheus-compatible metrics
//!
//! ## Architecture
//!
//! R0N Gateway is built with a modular architecture where each component
//! implements the [`module::ModuleContract`] trait for uniform lifecycle management.
//! The gateway is designed to be orchestrated by R0N.
//!
//! ## Modules
//!
//! All gateway functionality is provided through modules that implement
//! the [`module::ModuleContract`] trait. See the [`module`] documentation
//! for details on creating custom modules.

pub mod config;
pub mod ipc;
pub mod module;
pub mod modules;
pub mod perf;
