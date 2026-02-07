//! # Generic L4 Passthrough Module
//!
//! This module provides Layer 4 (transport layer) passthrough functionality
//! for R0N Gateway. It handles raw TCP and UDP forwarding without any
//! protocol-specific processing.
//!
//! ## Features
//!
//! - **Raw TCP forwarding**: Transparent TCP proxying with bidirectional data flow
//! - **Raw UDP forwarding**: Stateless UDP packet forwarding with session tracking
//! - **Connection tracking**: Track active connections for monitoring and cleanup
//! - **Port-based routing**: Route traffic based on listening port
//! - **Backend pooling**: Efficient connection reuse for TCP backends
//!
//! ## Use Cases
//!
//! - Database proxying (MySQL, PostgreSQL, Redis)
//! - Game server proxying
//! - Custom protocol proxying
//! - Legacy application support
//! - Any L4 traffic that doesn't need L7 inspection
//!
//! ## Example Configuration
//!
//! ```toml
//! [l4_passthrough]
//! name = "database-proxy"
//!
//! [[l4_passthrough.listeners]]
//! protocol = "tcp"
//! bind = "0.0.0.0:3306"
//! backend = "mysql-backend"
//!
//! [[l4_passthrough.listeners]]
//! protocol = "udp"
//! bind = "0.0.0.0:53"
//! backend = "dns-backend"
//!
//! [[l4_passthrough.backends]]
//! name = "mysql-backend"
//! addresses = ["10.0.0.10:3306", "10.0.0.11:3306"]
//! load_balance = "round_robin"
//!
//! [[l4_passthrough.backends]]
//! name = "dns-backend"
//! addresses = ["10.0.0.20:53", "10.0.0.21:53"]
//! load_balance = "least_connections"
//! ```

mod config;
mod connection;
mod error;
mod handler;
mod tracker;

pub use config::L4PassthroughConfig;
pub use connection::{ConnectionInfo, ConnectionState};
pub use error::{L4Error, L4Result};
pub use handler::L4PassthroughHandler;
pub use tracker::ConnectionTracker;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all public types are accessible
        let _ = std::any::TypeId::of::<L4PassthroughConfig>();
        let _ = std::any::TypeId::of::<L4PassthroughHandler>();
        let _ = std::any::TypeId::of::<L4Error>();
        let _ = std::any::TypeId::of::<ConnectionInfo>();
        let _ = std::any::TypeId::of::<ConnectionState>();
        let _ = std::any::TypeId::of::<ConnectionTracker>();
    }
}
