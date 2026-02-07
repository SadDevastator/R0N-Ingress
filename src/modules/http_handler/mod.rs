//! # HTTP/HTTPS Handler Module
//!
//! This module provides HTTP/1.1 and HTTP/2 protocol handling for R0N Gateway.
//! It supports path-based routing, header manipulation, and a middleware pipeline.
//!
//! ## Features
//!
//! - HTTP/1.1 parsing and handling
//! - HTTP/2 support via h2 crate
//! - Path-based and host-based routing
//! - Header manipulation (add, remove, modify)
//! - Middleware pipeline (before/after request processing)
//! - Request/response transformation
//! - Keep-alive connection management
//!
//! ## Example
//!
//! ```rust,ignore
//! use r0n_gateway::modules::http_handler::{HttpHandler, HttpHandlerConfig};
//!
//! let config = HttpHandlerConfig::default();
//! let handler = HttpHandler::with_config(config);
//! ```

pub mod config;
pub mod error;
pub mod handler;
pub mod middleware;
pub mod request;
pub mod response;
pub mod router;

pub use config::HttpHandlerConfig;
pub use error::{HttpError, HttpResult};
pub use handler::HttpHandler;
pub use middleware::{Middleware, MiddlewareChain};
pub use router::{Route, Router};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify exports are accessible
        let _ = HttpHandlerConfig::default();
    }
}
