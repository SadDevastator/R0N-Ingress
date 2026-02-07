//! ACME (Automatic Certificate Management Environment) module
//!
//! This module provides automatic TLS certificate provisioning and renewal
//! using the ACME protocol (RFC 8555), with support for Let's Encrypt and
//! other ACME-compatible certificate authorities.
//!
//! # Features
//!
//! - ACME v2 protocol implementation
//! - HTTP-01 and DNS-01 challenge support
//! - Automatic certificate renewal
//! - Let's Encrypt integration
//! - Certificate storage and management
//! - Rate limiting compliance
//!
//! # Example
//!
//! ```ignore
//! use r0n_gateway::modules::acme::{AcmeClient, AcmeConfig};
//!
//! let config = AcmeConfig::letsencrypt_staging();
//! let client = AcmeClient::new(config)?;
//!
//! // Request a certificate
//! let cert = client.obtain_certificate(&["example.com"]).await?;
//! ```

mod account;
mod challenge;
mod client;
mod config;
mod error;
mod handler;
mod order;
mod storage;

pub use account::{Account, AccountCredentials};
pub use challenge::{Challenge, ChallengeToken, ChallengeType, Dns01Challenge, Http01Challenge};
pub use client::AcmeClient;
pub use config::{AcmeConfig, DirectoryUrls, RenewalConfig};
pub use error::{AcmeError, AcmeResult};
pub use handler::AcmeHandler;
pub use order::{Authorization, AuthorizationStatus, Order, OrderStatus};
pub use storage::{Certificate, CertificateStorage, FileCertificateStorage};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all public types are accessible
        let _ = std::any::TypeId::of::<AcmeConfig>();
        let _ = std::any::TypeId::of::<AcmeClient>();
        let _ = std::any::TypeId::of::<AcmeHandler>();
        let _ = std::any::TypeId::of::<AcmeError>();
        let _ = std::any::TypeId::of::<Challenge>();
        let _ = std::any::TypeId::of::<Order>();
    }
}
