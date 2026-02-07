//! SNI-based routing for TLS termination.

use std::collections::HashMap;
use std::sync::Arc;

use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;
use tracing::{debug, warn};

use super::certificate::CertificateBundle;
use super::config::PassthroughRoute;
use super::error::{TlsError, TlsResult};

/// Result of SNI routing decision.
#[derive(Debug, Clone)]
pub enum SniDecision {
    /// Terminate TLS and use this certificate.
    Terminate {
        /// The certificate bundle to use.
        bundle_name: String,
    },
    /// Pass through encrypted traffic to backend.
    Passthrough {
        /// The backend address.
        backend: std::net::SocketAddr,
    },
}

/// SNI-based router for selecting certificates and routing decisions.
pub struct SniRouter {
    /// Certificate bundles indexed by name.
    bundles: HashMap<String, Arc<CertifiedKey>>,

    /// SNI to bundle name mapping.
    sni_to_bundle: HashMap<String, String>,

    /// Wildcard patterns (suffix -> bundle name).
    wildcard_patterns: Vec<(String, String)>,

    /// Passthrough routes.
    passthrough_routes: Vec<PassthroughRoute>,

    /// Default bundle name.
    default_bundle: Option<String>,
}

impl std::fmt::Debug for SniRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniRouter")
            .field("bundles", &self.bundles.keys().collect::<Vec<_>>())
            .field("sni_mappings", &self.sni_to_bundle.len())
            .field("wildcard_patterns", &self.wildcard_patterns.len())
            .field("passthrough_routes", &self.passthrough_routes.len())
            .field("default_bundle", &self.default_bundle)
            .finish()
    }
}

impl SniRouter {
    /// Create a new SNI router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bundles: HashMap::new(),
            sni_to_bundle: HashMap::new(),
            wildcard_patterns: Vec::new(),
            passthrough_routes: Vec::new(),
            default_bundle: None,
        }
    }

    /// Add a certificate bundle.
    ///
    /// # Errors
    ///
    /// Returns an error if the certified key cannot be created.
    pub fn add_bundle(&mut self, bundle: &CertificateBundle) -> TlsResult<()> {
        use tokio_rustls::rustls::crypto::aws_lc_rs::sign::any_supported_type;

        // Create signing key
        let signing_key = any_supported_type(bundle.private_key()).map_err(|e| {
            TlsError::InvalidCertificateChain {
                message: format!("Failed to create signing key: {e}"),
            }
        })?;

        // Create certified key
        let certified_key = CertifiedKey::new(bundle.certificates().to_vec(), signing_key);

        // Register SNI mappings
        for sni_name in bundle.sni_names() {
            if sni_name.starts_with("*.") {
                // Wildcard pattern
                let suffix = sni_name.strip_prefix("*.").unwrap_or(sni_name);
                self.wildcard_patterns
                    .push((suffix.to_string(), bundle.name().to_string()));
            } else {
                // Exact match
                self.sni_to_bundle
                    .insert(sni_name.clone(), bundle.name().to_string());
            }
        }

        self.bundles
            .insert(bundle.name().to_string(), Arc::new(certified_key));

        debug!(
            name = %bundle.name(),
            sni_names = ?bundle.sni_names(),
            "Added certificate bundle to SNI router"
        );

        Ok(())
    }

    /// Add passthrough routes.
    pub fn add_passthrough_routes(&mut self, routes: Vec<PassthroughRoute>) {
        self.passthrough_routes.extend(routes);
    }

    /// Set the default bundle.
    pub fn set_default(&mut self, name: &str) {
        self.default_bundle = Some(name.to_string());
    }

    /// Resolve SNI to a routing decision.
    #[must_use]
    pub fn resolve(&self, sni: &str) -> Option<SniDecision> {
        // Check passthrough routes first
        for route in &self.passthrough_routes {
            if Self::pattern_matches(&route.sni_pattern, sni) {
                return Some(SniDecision::Passthrough {
                    backend: route.backend.socket_addr(),
                });
            }
        }

        // Check exact matches
        if let Some(bundle_name) = self.sni_to_bundle.get(sni) {
            return Some(SniDecision::Terminate {
                bundle_name: bundle_name.clone(),
            });
        }

        // Check wildcard patterns
        for (suffix, bundle_name) in &self.wildcard_patterns {
            if sni.ends_with(suffix) {
                // Ensure it's a proper subdomain match
                let prefix_len = sni.len() - suffix.len();
                if prefix_len > 0 && sni.as_bytes()[prefix_len - 1] == b'.' {
                    return Some(SniDecision::Terminate {
                        bundle_name: bundle_name.clone(),
                    });
                }
            }
        }

        // Fall back to default
        self.default_bundle
            .as_ref()
            .map(|name| SniDecision::Terminate {
                bundle_name: name.clone(),
            })
    }

    /// Check if a pattern matches an SNI hostname.
    fn pattern_matches(pattern: &str, hostname: &str) -> bool {
        if pattern == hostname {
            return true;
        }

        if let Some(suffix) = pattern.strip_prefix("*.") {
            if hostname.ends_with(suffix) {
                let prefix_len = hostname.len() - suffix.len();
                if prefix_len > 0 && hostname.as_bytes()[prefix_len - 1] == b'.' {
                    return true;
                }
            }
        }

        false
    }

    /// Get a certified key by bundle name.
    #[must_use]
    pub fn get_certified_key(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        self.bundles.get(name).cloned()
    }

    /// Resolve SNI to a certified key.
    fn resolve_to_key(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let sni = sni?;

        match self.resolve(sni) {
            Some(SniDecision::Terminate { bundle_name }) => self.bundles.get(&bundle_name).cloned(),
            Some(SniDecision::Passthrough { .. }) => None, // Passthrough doesn't need a key
            None => {
                warn!(sni = %sni, "No certificate found for SNI");
                None
            },
        }
    }
}

impl Default for SniRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Implements rustls `ResolvesServerCert` for SNI-based certificate selection.
impl ResolvesServerCert for SniRouter {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name();
        self.resolve_to_key(sni)
    }
}

/// Extract SNI from a TLS Client Hello message.
///
/// This is used for passthrough mode where we need to peek at the SNI
/// without fully parsing the TLS handshake.
///
/// # Errors
///
/// Returns an error if the SNI cannot be extracted.
pub fn extract_sni_from_client_hello(data: &[u8]) -> TlsResult<Option<String>> {
    // Minimum TLS record header size
    if data.len() < 5 {
        return Ok(None);
    }

    // Check for TLS handshake record (0x16)
    if data[0] != 0x16 {
        return Ok(None);
    }

    // Skip record header (5 bytes) and handshake header (4 bytes)
    if data.len() < 9 {
        return Ok(None);
    }

    // Check for ClientHello (0x01)
    if data[5] != 0x01 {
        return Ok(None);
    }

    // Skip to extensions
    // This is a simplified parser - a full implementation would
    // properly parse the ClientHello structure
    let mut pos = 43; // Skip fixed-size fields

    if data.len() <= pos {
        return Ok(None);
    }

    // Skip session ID
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;

    if data.len() <= pos + 2 {
        return Ok(None);
    }

    // Skip cipher suites
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    if data.len() <= pos + 1 {
        return Ok(None);
    }

    // Skip compression methods
    let compression_len = data[pos] as usize;
    pos += 1 + compression_len;

    if data.len() <= pos + 2 {
        return Ok(None);
    }

    // Extensions length
    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    if data.len() < extensions_end {
        return Ok(None);
    }

    // Parse extensions looking for SNI (type 0)
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > extensions_end {
            return Ok(None);
        }

        if ext_type == 0 {
            // SNI extension
            if ext_len >= 5 {
                let name_list_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                if name_list_len >= 3 && ext_len >= 2 + name_list_len {
                    let name_type = data[pos + 2];
                    if name_type == 0 {
                        // hostname
                        let name_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
                        if pos + 5 + name_len <= extensions_end {
                            let hostname =
                                String::from_utf8_lossy(&data[pos + 5..pos + 5 + name_len]);
                            return Ok(Some(hostname.to_string()));
                        }
                    }
                }
            }
        }

        pos += ext_len;
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sni_router_empty() {
        let router = SniRouter::new();
        assert!(router.resolve("example.com").is_none());
    }

    #[test]
    fn test_pattern_matching() {
        assert!(SniRouter::pattern_matches("example.com", "example.com"));
        assert!(SniRouter::pattern_matches(
            "*.example.com",
            "www.example.com"
        ));
        assert!(!SniRouter::pattern_matches("*.example.com", "example.com"));
    }

    #[test]
    fn test_extract_sni_empty() {
        let result = extract_sni_from_client_hello(&[]);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_extract_sni_not_tls() {
        let result = extract_sni_from_client_hello(&[0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(result.unwrap().is_none());
    }
}
