//! TLS Terminator Module
//!
//! This module provides TLS termination capabilities for the gateway.
//! It supports:
//! - Certificate loading from PEM and DER formats
//! - SNI-based routing to different certificates
//! - TLS passthrough mode
//! - Mutual TLS (mTLS) authentication
//! - Certificate hot-reload

mod certificate;
mod config;
mod connection;
mod error;
mod sni;
mod terminator;

pub use certificate::{CertificateBundle, CertificateStore};
pub use config::TlsTerminatorConfig;
pub use error::{TlsError, TlsResult};
pub use sni::SniRouter;
pub use terminator::TlsTerminator;
