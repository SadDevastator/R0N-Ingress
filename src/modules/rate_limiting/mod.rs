//! # Rate Limiting Module
//!
//! This module provides rate limiting functionality for R0N Gateway.
//! It supports multiple rate limiting strategies and scopes.
//!
//! ## Features
//!
//! - **Token Bucket Algorithm**: Classic rate limiting with burst support
//! - **Per-Route Limits**: Different limits for different routes/endpoints
//! - **Per-IP Limits**: Limit requests per client IP address
//! - **Distributed Rate Limiting**: Share state across gateway instances
//!
//! ## Usage
//!
//! ```ignore
//! use r0n_gateway::modules::rate_limiting::{RateLimiter, RateLimitConfig};
//!
//! let config = RateLimitConfig::default();
//! let mut handler = RateLimitHandler::new();
//! handler.init(config.into())?;
//! handler.start()?;
//!
//! // Check if request should be allowed
//! if handler.check_rate_limit("client_ip", "route_name") {
//!     // Allow request
//! } else {
//!     // Return 429 Too Many Requests
//! }
//! ```

mod bucket;
mod config;
mod distributed;
mod error;
mod handler;
mod limiter;

pub use bucket::{TokenBucket, TokenBucketConfig};
pub use config::DistributedBackend;
pub use config::{DistributedConfig, LimitScope, RateLimitConfig, RateLimitRule, RedisConfig};
pub use distributed::{DistributedState, LocalState, RedisState};
pub use error::{RateLimitError, RateLimitResult};
pub use handler::RateLimitHandler;
pub use limiter::{RateLimitDecision, RateLimiter};
