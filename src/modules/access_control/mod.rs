//! # Access Control Module
//!
//! This module provides access control functionality for R0N Gateway.
//! It supports IP-based filtering, authentication hooks, and authorization policies.
//!
//! ## Features
//!
//! - **IP Allow/Deny Lists**: Block or allow traffic based on client IP
//! - **CIDR Support**: Use network ranges for IP rules
//! - **Authentication Hooks**: Integrate with external auth providers
//! - **Authorization Policies**: Role-based and attribute-based access control
//! - **Policy Engine**: Flexible rule evaluation with multiple strategies
//!
//! ## Usage
//!
//! ```ignore
//! use r0n_gateway::modules::access_control::{AccessControlHandler, AccessControlConfig};
//!
//! let config = AccessControlConfig::default();
//! let mut handler = AccessControlHandler::with_config(config);
//! handler.start()?;
//!
//! // Check access for a request
//! let decision = handler.check_access(&context);
//! if decision.allowed {
//!     // Process request
//! } else {
//!     // Return 403 Forbidden
//! }
//! ```

mod config;
mod error;
mod handler;
mod ip_filter;
mod policy;
mod provider;

pub use config::{
    AccessControlConfig, ApiKeyConfig, AuthConfig, AuthProvider, IpFilterConfig, IpRule,
    PolicyCondition, PolicyConfig, PolicyRule, PolicyStrategy, RouteAccessConfig, RuleAction,
};
pub use error::{AccessControlError, AccessControlResult};
pub use handler::{
    AccessCheckResult, AccessControlHandler, AccessControlStats, CheckContext, DenialReason,
};
pub use ip_filter::{AllowList, DenyList, IpFilter};
pub use policy::{PolicyContext, PolicyDecision, PolicyEngine};
pub use provider::{
    ApiKeyProvider, AuthContext, AuthHook, AuthManager, AuthResult, BasicAuthProvider, JwtProvider,
};
