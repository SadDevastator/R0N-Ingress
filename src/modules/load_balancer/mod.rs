//! # Load Balancer Module
//!
//! This module provides load balancing functionality for distributing traffic
//! across multiple backend servers.
//!
//! ## Features
//!
//! - **Multiple Strategies**: Round-robin, least-connections, and hash-based (sticky)
//! - **Health Checks**: Active and passive health monitoring
//! - **Weighted Backends**: Support for backend weight configuration
//! - **Backend Pools**: Named pools for organizing backends
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐
//! │  Load Balancer  │
//! │                 │
//! │  ┌───────────┐  │      ┌──────────┐
//! │  │ Strategy  │──┼────▶│ Backend1 │
//! │  │ Selector  │  │      └──────────┘
//! │  └───────────┘  │      ┌──────────┐
//! │        │        │────▶│ Backend2 │
//! │  ┌───────────┐  │      └──────────┘
//! │  │  Health   │  │      ┌──────────┐
//! │  │  Checker  │──┼────▶│ Backend3 │
//! │  └───────────┘  │      └──────────┘
//! └─────────────────┘
//! ```

pub mod backend;
pub mod balancer;
pub mod config;
pub mod error;
pub mod health;
pub mod strategy;

pub use backend::{Backend, BackendPool, BackendState, BackendStats};
pub use balancer::LoadBalancer;
pub use config::{HealthCheckConfig, LoadBalancerConfig};
pub use error::{LoadBalancerError, LoadBalancerResult};
pub use health::{HealthCheck, HealthStatus};
pub use strategy::{HashStrategy, LeastConnectionsStrategy, RoundRobinStrategy, Strategy};
