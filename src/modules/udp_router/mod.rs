//! # UDP Router Module
//!
//! A high-performance UDP routing module for R0N Gateway.
//!
//! ## Features
//!
//! - Multi-port UDP binding
//! - Datagram handling with configurable buffer sizes
//! - Route matching based on port and source IP
//! - Backend forwarding with session tracking
//! - Implements `ModuleContract` for lifecycle management
//!
//! ## Configuration
//!
//! ```toml
//! [[modules]]
//! name = "udp-router"
//! type = "udp-router"
//! enabled = true
//!
//! [modules.config]
//! listeners = [
//!     { address = "0.0.0.0", port = 5353 }
//! ]
//!
//! [[modules.config.routes]]
//! name = "dns-backend"
//! match = { port = 5353 }
//! backends = [
//!     { address = "8.8.8.8", port = 53, weight = 1 }
//! ]
//! ```

mod config;
mod error;
mod router;
mod session;
mod socket;

pub use config::{
    BackendConfig, ListenerConfig, LoadBalanceStrategy, MatchCriteria, RouteConfig,
    SessionSettings, UdpRouterConfig,
};
pub use error::{UdpRouterError, UdpRouterResult};
pub use router::{RouterStats, UdpRouter};
pub use session::{Session, SessionId, SessionManager, SessionStats};
pub use socket::{BoundSocket, SocketStats};
