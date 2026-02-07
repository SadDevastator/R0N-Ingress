//! # MQTT Handler Module
//!
//! This module provides MQTT 3.1.1 and MQTT 5.0 protocol handling for R0N Gateway.
//! It supports topic-based routing, QoS handling, and session management.
//!
//! ## Features
//!
//! - MQTT 3.1.1 protocol support
//! - MQTT 5.0 protocol support
//! - Topic-based routing with wildcards
//! - QoS 0, 1, and 2 handling
//! - Session management
//! - Will message support
//! - Clean session handling
//!
//! ## Example
//!
//! ```rust,ignore
//! use r0n_gateway::modules::mqtt_handler::{MqttHandler, MqttHandlerConfig};
//!
//! let config = MqttHandlerConfig::default();
//! let handler = MqttHandler::with_config(config);
//! ```

pub mod config;
pub mod error;
pub mod handler;
pub mod packet;
pub mod session;
pub mod topic;

pub use config::MqttHandlerConfig;
pub use error::{MqttError, MqttResult};
pub use handler::MqttHandler;
pub use packet::{MqttPacket, QoS};
pub use topic::{TopicFilter, TopicName};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        let _ = MqttHandlerConfig::default();
    }
}
