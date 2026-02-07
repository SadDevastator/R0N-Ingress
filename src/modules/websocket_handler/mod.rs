//! # WebSocket Handler Module
//!
//! Provides WebSocket protocol handling with HTTP upgrade support,
//! frame parsing, and bidirectional message routing.
//!
//! ## Features
//!
//! - RFC 6455 WebSocket protocol support
//! - HTTP/1.1 Upgrade handling
//! - Text and binary message types
//! - Ping/pong for connection keep-alive
//! - Close frame handling with status codes
//! - Per-message compression (permessage-deflate) - future
//! - Subprotocol negotiation
//! - Origin validation
//!
//! ## Example Configuration
//!
//! ```toml
//! [websocket_handler]
//! listeners = [
//!     { address = "0.0.0.0", port = 8080, path = "/ws" }
//! ]
//!
//! [[websocket_handler.routes]]
//! path = "/ws/chat"
//! backend = { address = "127.0.0.1", port = 9000 }
//!
//! [[websocket_handler.routes]]
//! path = "/ws/notifications"
//! backend = { address = "127.0.0.1", port = 9001 }
//! ```

mod config;
mod error;
mod frame;
mod handler;
mod upgrade;

pub use config::WebSocketHandlerConfig;
pub use error::{WebSocketError, WebSocketResult};
pub use frame::{CloseCode, Message, OpCode};
pub use handler::WebSocketHandler;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all public types are accessible
        let _ = std::any::type_name::<WebSocketHandlerConfig>();
        let _ = std::any::type_name::<WebSocketError>();
        let _ = std::any::type_name::<WebSocketHandler>();
        let _ = std::any::type_name::<Message>();
        let _ = std::any::type_name::<OpCode>();
        let _ = std::any::type_name::<CloseCode>();
    }
}
