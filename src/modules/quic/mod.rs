//! # QUIC Transport Module
//!
//! QUIC transport layer implementation for R0N Gateway providing
//! low-latency, multiplexed connections with built-in encryption.
//!
//! ## Features
//!
//! - QUIC transport layer with TLS 1.3
//! - Connection multiplexing (multiple streams per connection)
//! - 0-RTT connection resumption support
//! - Connection migration support
//! - Flow control and congestion control
//! - Stream prioritization

pub mod config;
pub mod connection;
pub mod error;
pub mod stream;
pub mod transport;

pub use config::*;
pub use connection::*;
pub use error::*;
pub use stream::*;
pub use transport::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify key types are exported
        let _config = QuicConfig::default();
        let _err = QuicError::ConnectionClosed("test".to_string());
    }
}
