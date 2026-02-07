//! HTTP/3 protocol handler
//!
//! Implements HTTP/3 over QUIC transport (RFC 9114)

pub mod error;
pub mod frame;
pub mod handler;

pub use error::{Http3Error, Http3Result};
pub use frame::{Frame, FrameType, Settings};
pub use handler::Http3Handler;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify exports are accessible
        let _: FrameType = FrameType::Data;
        let _: Settings = Settings::default();
    }
}
