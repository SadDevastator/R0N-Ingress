//! # TCP Router Module
//!
//! A high-performance TCP routing module for R0N Gateway.
//!
//! ## Features
//!
//! - Multi-port TCP listening
//! - Connection pooling to backends
//! - Route matching based on port, SNI, or PROXY protocol
//! - Backend forwarding with health checks
//! - Implements `ModuleContract` for lifecycle management
//!
//! ## Configuration
//!
//! ```toml
//! [[modules]]
//! name = "tcp-router"
//! type = "tcp-router"
//! enabled = true
//!
//! [modules.config]
//! listeners = [
//!     { address = "0.0.0.0", port = 8080 }
//! ]
//!
//! [[modules.config.routes]]
//! name = "web-backend"
//! match = { port = 8080 }
//! backends = [
//!     { address = "127.0.0.1", port = 3000, weight = 1 }
//! ]
//! ```

mod config;
mod connection;
mod error;
mod listener;
mod pool;
mod router;

pub use config::{
    BackendConfig, HealthCheckSettings, ListenerConfig, LoadBalanceStrategy, MatchCriteria,
    PoolSettings, RouteConfig, TcpRouterConfig,
};
pub use connection::{Connection, ConnectionReadHalf, ConnectionWriteHalf};
pub use error::{TcpRouterError, TcpRouterResult};
pub use listener::{Listener, ListenerEvent, ListenerStats};
pub use pool::{ConnectionPool, PoolStats, PooledConnection};
pub use router::{BackendHealth, RouterStats, TcpRouter};
