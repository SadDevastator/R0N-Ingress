//! TLS Terminator error types.

use std::net::SocketAddr;
use thiserror::Error;

/// Errors that can occur in the TLS terminator module.
#[derive(Debug, Error)]
pub enum TlsError {
    /// Failed to bind to the specified address.
    #[error("failed to bind to {address}: {source}")]
    BindError {
        /// The address that failed to bind.
        address: SocketAddr,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to load certificate.
    #[error("failed to load certificate from '{path}': {message}")]
    CertificateLoadError {
        /// The certificate path.
        path: String,
        /// Error message.
        message: String,
    },

    /// Failed to load private key.
    #[error("failed to load private key from '{path}': {message}")]
    PrivateKeyLoadError {
        /// The private key path.
        path: String,
        /// Error message.
        message: String,
    },

    /// Invalid certificate chain.
    #[error("invalid certificate chain: {message}")]
    InvalidCertificateChain {
        /// Error message.
        message: String,
    },

    /// SNI mismatch.
    #[error("no certificate found for SNI '{sni}'")]
    SniMismatch {
        /// The requested SNI.
        sni: String,
    },

    /// TLS handshake failed.
    #[error("TLS handshake failed: {message}")]
    HandshakeError {
        /// Error message.
        message: String,
    },

    /// Client certificate required but not provided.
    #[error("client certificate required but not provided")]
    ClientCertRequired,

    /// Client certificate validation failed.
    #[error("client certificate validation failed: {message}")]
    ClientCertValidationError {
        /// Error message.
        message: String,
    },

    /// Configuration error.
    #[error("configuration error: {message}")]
    ConfigError {
        /// Error message.
        message: String,
    },

    /// IO error.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Module is not running.
    #[error("module is not running")]
    NotRunning,

    /// Module is already running.
    #[error("module is already running")]
    AlreadyRunning,
}

/// Result type alias for TLS terminator operations.
pub type TlsResult<T> = Result<T, TlsError>;
