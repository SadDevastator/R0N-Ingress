//! Certificate loading and management.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use rustls_pemfile::{certs, private_key};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{debug, info};

use super::config::CertificateConfig;
use super::error::{TlsError, TlsResult};

/// A loaded certificate bundle containing certificate chain and private key.
pub struct CertificateBundle {
    /// Bundle name.
    name: String,

    /// Certificate chain (leaf first, then intermediates).
    certificates: Vec<CertificateDer<'static>>,

    /// Private key.
    private_key: PrivateKeyDer<'static>,

    /// SNI names this certificate matches.
    sni_names: Vec<String>,

    /// When the bundle was loaded.
    loaded_at: Instant,

    /// Whether hot-reload is enabled.
    hot_reload: bool,

    /// Original configuration for reloading.
    config: CertificateConfig,
}

impl std::fmt::Debug for CertificateBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateBundle")
            .field("name", &self.name)
            .field("certificates_count", &self.certificates.len())
            .field("sni_names", &self.sni_names)
            .field("hot_reload", &self.hot_reload)
            .finish()
    }
}

impl CertificateBundle {
    /// Load a certificate bundle from configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate or key cannot be loaded.
    pub fn load(config: &CertificateConfig) -> TlsResult<Self> {
        info!(name = %config.name, cert_path = %config.cert_path.display(), "Loading certificate bundle");

        // Load certificates
        let certificates = Self::load_certificates(&config.cert_path)?;

        // Load optional chain certificates
        let mut all_certs = certificates;
        if let Some(ref chain_path) = config.chain_path {
            let chain_certs = Self::load_certificates(chain_path)?;
            all_certs.extend(chain_certs);
        }

        if all_certs.is_empty() {
            return Err(TlsError::CertificateLoadError {
                path: config.cert_path.display().to_string(),
                message: "No certificates found in file".to_string(),
            });
        }

        // Load private key
        let private_key = Self::load_private_key(&config.key_path)?;

        debug!(
            name = %config.name,
            cert_count = all_certs.len(),
            sni_names = ?config.sni_names,
            "Certificate bundle loaded"
        );

        Ok(Self {
            name: config.name.clone(),
            certificates: all_certs,
            private_key,
            sni_names: config.sni_names.clone(),
            loaded_at: Instant::now(),
            hot_reload: config.hot_reload,
            config: config.clone(),
        })
    }

    /// Load certificates from a PEM file.
    fn load_certificates(path: &Path) -> TlsResult<Vec<CertificateDer<'static>>> {
        let file = File::open(path).map_err(|e| TlsError::CertificateLoadError {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;

        let mut reader = BufReader::new(file);

        let certs_result: Result<Vec<_>, _> = certs(&mut reader).collect();
        let certificates = certs_result.map_err(|e| TlsError::CertificateLoadError {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;

        Ok(certificates)
    }

    /// Load a private key from a PEM file.
    fn load_private_key(path: &Path) -> TlsResult<PrivateKeyDer<'static>> {
        let file = File::open(path).map_err(|e| TlsError::PrivateKeyLoadError {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;

        let mut reader = BufReader::new(file);

        private_key(&mut reader)
            .map_err(|e| TlsError::PrivateKeyLoadError {
                path: path.display().to_string(),
                message: e.to_string(),
            })?
            .ok_or_else(|| TlsError::PrivateKeyLoadError {
                path: path.display().to_string(),
                message: "No private key found in file".to_string(),
            })
    }

    /// Get the bundle name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the certificate chain.
    #[must_use]
    pub fn certificates(&self) -> &[CertificateDer<'static>] {
        &self.certificates
    }

    /// Get the private key.
    #[must_use]
    pub fn private_key(&self) -> &PrivateKeyDer<'static> {
        &self.private_key
    }

    /// Get the SNI names.
    #[must_use]
    pub fn sni_names(&self) -> &[String] {
        &self.sni_names
    }

    /// Check if this bundle matches an SNI name.
    #[must_use]
    pub fn matches_sni(&self, sni: &str) -> bool {
        for pattern in &self.sni_names {
            if Self::sni_matches(pattern, sni) {
                return true;
            }
        }
        false
    }

    /// Check if an SNI pattern matches a hostname.
    fn sni_matches(pattern: &str, hostname: &str) -> bool {
        if pattern == hostname {
            return true;
        }

        // Wildcard matching (*.example.com matches www.example.com but not example.com)
        if let Some(suffix) = pattern.strip_prefix("*.") {
            // Hostname must end with .suffix and have exactly one more label
            if let Some(stripped) = hostname.strip_suffix(suffix) {
                // Check that we stripped a dot and there's at least one character before it
                // and no dots in the remaining part (single-level wildcard)
                if let Some(label) = stripped.strip_suffix('.') {
                    return !label.is_empty() && !label.contains('.');
                }
            }
        }

        false
    }

    /// Check if hot-reload is enabled.
    #[must_use]
    pub fn hot_reload_enabled(&self) -> bool {
        self.hot_reload
    }

    /// Get the time since the bundle was loaded.
    #[must_use]
    pub fn age(&self) -> std::time::Duration {
        self.loaded_at.elapsed()
    }

    /// Reload the certificate bundle.
    ///
    /// # Errors
    ///
    /// Returns an error if reloading fails.
    pub fn reload(&self) -> TlsResult<Self> {
        Self::load(&self.config)
    }
}

/// A store for managing multiple certificate bundles.
pub struct CertificateStore {
    /// Certificate bundles by name.
    bundles: Vec<CertificateBundle>,

    /// Default bundle name.
    default_bundle: Option<String>,
}

impl CertificateStore {
    /// Create a new empty certificate store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bundles: Vec::new(),
            default_bundle: None,
        }
    }

    /// Load certificates from configurations.
    ///
    /// # Errors
    ///
    /// Returns an error if any certificate fails to load.
    pub fn load_all(configs: &[CertificateConfig]) -> TlsResult<Self> {
        let mut store = Self::new();

        for config in configs {
            let bundle = CertificateBundle::load(config)?;
            store.bundles.push(bundle);
        }

        Ok(store)
    }

    /// Set the default bundle.
    pub fn set_default(&mut self, name: &str) {
        self.default_bundle = Some(name.to_string());
    }

    /// Add a bundle to the store.
    pub fn add(&mut self, bundle: CertificateBundle) {
        self.bundles.push(bundle);
    }

    /// Get a bundle by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&CertificateBundle> {
        self.bundles.iter().find(|b| b.name == name)
    }

    /// Find a bundle by SNI name.
    #[must_use]
    pub fn find_by_sni(&self, sni: &str) -> Option<&CertificateBundle> {
        // First try exact/wildcard match
        if let Some(bundle) = self.bundles.iter().find(|b| b.matches_sni(sni)) {
            return Some(bundle);
        }

        // Fall back to default
        self.default_bundle.as_ref().and_then(|name| self.get(name))
    }

    /// Get the default bundle.
    #[must_use]
    pub fn default(&self) -> Option<&CertificateBundle> {
        self.default_bundle.as_ref().and_then(|name| self.get(name))
    }

    /// Get all bundle names.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.bundles.iter().map(|b| b.name.as_str()).collect()
    }

    /// Get the number of bundles.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bundles.len()
    }

    /// Check if the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }

    /// Reload all bundles that have hot-reload enabled.
    ///
    /// # Errors
    ///
    /// Returns errors for bundles that failed to reload.
    pub fn reload_all(&mut self) -> Vec<TlsError> {
        let mut errors = Vec::new();

        for bundle in &mut self.bundles {
            if bundle.hot_reload_enabled() {
                match bundle.reload() {
                    Ok(new_bundle) => {
                        info!(name = %bundle.name, "Certificate reloaded");
                        *bundle = new_bundle;
                    },
                    Err(e) => {
                        errors.push(e);
                    },
                }
            }
        }

        errors
    }
}

impl Default for CertificateStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a rustls `ServerConfig` from a certificate bundle.
///
/// # Errors
///
/// Returns an error if the configuration cannot be built.
#[allow(dead_code)]
pub fn build_server_config(
    bundle: &CertificateBundle,
) -> TlsResult<Arc<tokio_rustls::rustls::ServerConfig>> {
    use tokio_rustls::rustls::ServerConfig;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            bundle.certificates().to_vec(),
            bundle.private_key().clone_key(),
        )
        .map_err(|e| TlsError::InvalidCertificateChain {
            message: e.to_string(),
        })?;

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sni_exact_match() {
        assert!(CertificateBundle::sni_matches("example.com", "example.com"));
        assert!(!CertificateBundle::sni_matches("example.com", "other.com"));
    }

    #[test]
    fn test_sni_wildcard_match() {
        assert!(CertificateBundle::sni_matches(
            "*.example.com",
            "www.example.com"
        ));
        assert!(CertificateBundle::sni_matches(
            "*.example.com",
            "api.example.com"
        ));
        assert!(!CertificateBundle::sni_matches(
            "*.example.com",
            "example.com"
        ));
        assert!(!CertificateBundle::sni_matches(
            "*.example.com",
            "sub.www.example.com"
        ));
    }

    #[test]
    fn test_certificate_store_empty() {
        let store = CertificateStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_certificate_store_find_by_sni() {
        // Note: This test would require actual certificate files
        // For unit testing, we'd mock the certificate loading
        let store = CertificateStore::new();
        assert!(store.find_by_sni("example.com").is_none());
    }
}
