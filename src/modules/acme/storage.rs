//! Certificate storage

use super::error::{AcmeError, AcmeResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Certificate with associated metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    /// Domain names covered by this certificate
    pub domains: Vec<String>,

    /// Certificate in PEM format
    pub certificate_pem: String,

    /// Private key in PEM format
    pub private_key_pem: String,

    /// Full certificate chain in PEM format
    pub chain_pem: String,

    /// When the certificate was issued (Unix timestamp)
    pub issued_at: u64,

    /// When the certificate expires (Unix timestamp)
    pub expires_at: u64,

    /// Certificate serial number
    pub serial: String,

    /// Issuer name
    pub issuer: String,
}

impl Certificate {
    /// Create a new certificate
    pub fn new(
        domains: Vec<String>,
        certificate_pem: String,
        private_key_pem: String,
        chain_pem: String,
        expires_at: u64,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            domains,
            certificate_pem,
            private_key_pem,
            chain_pem,
            issued_at: now,
            expires_at,
            serial: String::new(),
            issuer: String::new(),
        }
    }

    /// Check if certificate is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= self.expires_at
    }

    /// Check if certificate needs renewal
    pub fn needs_renewal(&self, days_before_expiry: u32) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let renewal_threshold = self
            .expires_at
            .saturating_sub(days_before_expiry as u64 * 24 * 60 * 60);
        now >= renewal_threshold
    }

    /// Get days until expiry
    pub fn days_until_expiry(&self) -> i64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let diff = self.expires_at as i64 - now as i64;
        diff / (24 * 60 * 60)
    }

    /// Get the primary domain (first in list)
    pub fn primary_domain(&self) -> &str {
        self.domains.first().map(|s| s.as_str()).unwrap_or("")
    }

    /// Check if this certificate covers a domain
    pub fn covers_domain(&self, domain: &str) -> bool {
        for cert_domain in &self.domains {
            if cert_domain == domain {
                return true;
            }
            // Check wildcard match
            // *.example.com matches www.example.com but not example.com or a.b.example.com
            if let Some(base) = cert_domain.strip_prefix("*.") {
                let expected_suffix = format!(".{}", base); // ".example.com"

                if domain.ends_with(&expected_suffix) {
                    // Get the prefix part (e.g., "www" from "www.example.com")
                    let prefix = &domain[..domain.len() - expected_suffix.len()];
                    // Wildcard only matches a single label (no dots in prefix)
                    if !prefix.is_empty() && !prefix.contains('.') {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Get combined certificate with chain
    pub fn full_chain(&self) -> String {
        if self.chain_pem.is_empty() {
            self.certificate_pem.clone()
        } else {
            format!("{}\n{}", self.certificate_pem, self.chain_pem)
        }
    }
}

/// Certificate storage trait
pub trait CertificateStorage: Send + Sync {
    /// Store a certificate
    fn store(&self, cert: &Certificate) -> AcmeResult<()>;

    /// Load a certificate by primary domain
    fn load(&self, domain: &str) -> AcmeResult<Option<Certificate>>;

    /// List all stored certificates
    fn list(&self) -> AcmeResult<Vec<String>>;

    /// Delete a certificate
    fn delete(&self, domain: &str) -> AcmeResult<()>;

    /// Find certificate covering a domain
    fn find_for_domain(&self, domain: &str) -> AcmeResult<Option<Certificate>>;
}

/// File-based certificate storage
#[derive(Debug)]
pub struct FileCertificateStorage {
    /// Base directory for certificate storage
    base_path: PathBuf,

    /// File permissions (Unix)
    file_mode: u32,

    /// In-memory cache
    cache: Arc<RwLock<HashMap<String, Certificate>>>,
}

impl FileCertificateStorage {
    /// Create new file storage
    pub fn new<P: AsRef<Path>>(base_path: P, file_mode: u32) -> AcmeResult<Self> {
        let base_path = base_path.as_ref().to_path_buf();

        // Create directory if it doesn't exist
        if !base_path.exists() {
            fs::create_dir_all(&base_path)?;
        }

        let storage = Self {
            base_path,
            file_mode,
            cache: Arc::new(RwLock::new(HashMap::new())),
        };

        // Load existing certificates into cache
        storage.load_all_to_cache()?;

        Ok(storage)
    }

    /// Get path for a domain's certificate directory
    fn cert_path(&self, domain: &str) -> PathBuf {
        // Sanitize domain for filesystem
        let safe_domain = domain.replace('*', "_wildcard_");
        self.base_path.join(&safe_domain)
    }

    /// Load all certificates into cache
    fn load_all_to_cache(&self) -> AcmeResult<()> {
        let entries = match fs::read_dir(&self.base_path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        let mut cache = self
            .cache
            .write()
            .map_err(|_| AcmeError::Storage("Cache lock poisoned".to_string()))?;

        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let domain = entry.file_name().to_string_lossy().to_string();
                let domain = domain.replace("_wildcard_", "*");

                if let Ok(cert) = self.load_from_disk(&domain) {
                    cache.insert(domain, cert);
                }
            }
        }

        Ok(())
    }

    /// Load certificate from disk
    fn load_from_disk(&self, domain: &str) -> AcmeResult<Certificate> {
        let cert_dir = self.cert_path(domain);

        let cert_pem = fs::read_to_string(cert_dir.join("cert.pem"))?;
        let key_pem = fs::read_to_string(cert_dir.join("key.pem"))?;
        let chain_pem = fs::read_to_string(cert_dir.join("chain.pem")).unwrap_or_default();
        let metadata_json = fs::read_to_string(cert_dir.join("metadata.json"))?;

        let metadata: CertificateMetadata = serde_json::from_str(&metadata_json)?;

        Ok(Certificate {
            domains: metadata.domains,
            certificate_pem: cert_pem,
            private_key_pem: key_pem,
            chain_pem,
            issued_at: metadata.issued_at,
            expires_at: metadata.expires_at,
            serial: metadata.serial,
            issuer: metadata.issuer,
        })
    }

    /// Save certificate to disk
    fn save_to_disk(&self, cert: &Certificate) -> AcmeResult<()> {
        let domain = cert.primary_domain();
        let cert_dir = self.cert_path(domain);

        // Create directory
        fs::create_dir_all(&cert_dir)?;

        // Write certificate files
        fs::write(cert_dir.join("cert.pem"), &cert.certificate_pem)?;
        fs::write(cert_dir.join("key.pem"), &cert.private_key_pem)?;
        if !cert.chain_pem.is_empty() {
            fs::write(cert_dir.join("chain.pem"), &cert.chain_pem)?;
        }
        fs::write(cert_dir.join("fullchain.pem"), cert.full_chain())?;

        // Write metadata
        let metadata = CertificateMetadata {
            domains: cert.domains.clone(),
            issued_at: cert.issued_at,
            expires_at: cert.expires_at,
            serial: cert.serial.clone(),
            issuer: cert.issuer.clone(),
        };
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        fs::write(cert_dir.join("metadata.json"), metadata_json)?;

        // Set file permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let key_path = cert_dir.join("key.pem");
            let permissions = fs::Permissions::from_mode(self.file_mode);
            let _ = fs::set_permissions(key_path, permissions);
        }

        Ok(())
    }
}

impl CertificateStorage for FileCertificateStorage {
    fn store(&self, cert: &Certificate) -> AcmeResult<()> {
        // Save to disk
        self.save_to_disk(cert)?;

        // Update cache
        let mut cache = self
            .cache
            .write()
            .map_err(|_| AcmeError::Storage("Cache lock poisoned".to_string()))?;

        for domain in &cert.domains {
            cache.insert(domain.clone(), cert.clone());
        }

        Ok(())
    }

    fn load(&self, domain: &str) -> AcmeResult<Option<Certificate>> {
        // Check cache first
        let cache = self
            .cache
            .read()
            .map_err(|_| AcmeError::Storage("Cache lock poisoned".to_string()))?;

        if let Some(cert) = cache.get(domain) {
            return Ok(Some(cert.clone()));
        }

        // Try loading from disk
        match self.load_from_disk(domain) {
            Ok(cert) => Ok(Some(cert)),
            Err(AcmeError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn list(&self) -> AcmeResult<Vec<String>> {
        let cache = self
            .cache
            .read()
            .map_err(|_| AcmeError::Storage("Cache lock poisoned".to_string()))?;

        // Return unique primary domains
        let mut domains: Vec<String> = cache
            .values()
            .map(|c| c.primary_domain().to_string())
            .collect();
        domains.sort();
        domains.dedup();
        Ok(domains)
    }

    fn delete(&self, domain: &str) -> AcmeResult<()> {
        // Remove from cache
        let mut cache = self
            .cache
            .write()
            .map_err(|_| AcmeError::Storage("Cache lock poisoned".to_string()))?;
        cache.remove(domain);

        // Remove from disk
        let cert_dir = self.cert_path(domain);
        if cert_dir.exists() {
            fs::remove_dir_all(cert_dir)?;
        }

        Ok(())
    }

    fn find_for_domain(&self, domain: &str) -> AcmeResult<Option<Certificate>> {
        let cache = self
            .cache
            .read()
            .map_err(|_| AcmeError::Storage("Cache lock poisoned".to_string()))?;

        // First try exact match
        if let Some(cert) = cache.get(domain) {
            return Ok(Some(cert.clone()));
        }

        // Then try wildcard match
        for cert in cache.values() {
            if cert.covers_domain(domain) {
                return Ok(Some(cert.clone()));
            }
        }

        Ok(None)
    }
}

/// Certificate metadata for serialization
#[derive(Debug, Serialize, Deserialize)]
struct CertificateMetadata {
    domains: Vec<String>,
    issued_at: u64,
    expires_at: u64,
    serial: String,
    issuer: String,
}

/// In-memory certificate storage (for testing)
#[derive(Debug, Default)]
pub struct MemoryCertificateStorage {
    certs: Arc<RwLock<HashMap<String, Certificate>>>,
}

impl MemoryCertificateStorage {
    /// Create new memory storage
    pub fn new() -> Self {
        Self::default()
    }
}

impl CertificateStorage for MemoryCertificateStorage {
    fn store(&self, cert: &Certificate) -> AcmeResult<()> {
        let mut certs = self
            .certs
            .write()
            .map_err(|_| AcmeError::Storage("Lock poisoned".to_string()))?;

        for domain in &cert.domains {
            certs.insert(domain.clone(), cert.clone());
        }

        Ok(())
    }

    fn load(&self, domain: &str) -> AcmeResult<Option<Certificate>> {
        let certs = self
            .certs
            .read()
            .map_err(|_| AcmeError::Storage("Lock poisoned".to_string()))?;

        Ok(certs.get(domain).cloned())
    }

    fn list(&self) -> AcmeResult<Vec<String>> {
        let certs = self
            .certs
            .read()
            .map_err(|_| AcmeError::Storage("Lock poisoned".to_string()))?;

        let mut domains: Vec<String> = certs
            .values()
            .map(|c| c.primary_domain().to_string())
            .collect();
        domains.sort();
        domains.dedup();
        Ok(domains)
    }

    fn delete(&self, domain: &str) -> AcmeResult<()> {
        let mut certs = self
            .certs
            .write()
            .map_err(|_| AcmeError::Storage("Lock poisoned".to_string()))?;

        certs.remove(domain);
        Ok(())
    }

    fn find_for_domain(&self, domain: &str) -> AcmeResult<Option<Certificate>> {
        let certs = self
            .certs
            .read()
            .map_err(|_| AcmeError::Storage("Lock poisoned".to_string()))?;

        if let Some(cert) = certs.get(domain) {
            return Ok(Some(cert.clone()));
        }

        for cert in certs.values() {
            if cert.covers_domain(domain) {
                return Ok(Some(cert.clone()));
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_cert(domain: &str) -> Certificate {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Certificate {
            domains: vec![domain.to_string()],
            certificate_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
                .to_string(),
            private_key_pem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
                .to_string(),
            chain_pem: "".to_string(),
            issued_at: now,
            expires_at: now + 90 * 24 * 60 * 60, // 90 days
            serial: "123456".to_string(),
            issuer: "Test CA".to_string(),
        }
    }

    #[test]
    fn test_certificate_creation() {
        let cert = Certificate::new(
            vec!["example.com".to_string()],
            "cert".to_string(),
            "key".to_string(),
            "chain".to_string(),
            12345678,
        );

        assert_eq!(cert.primary_domain(), "example.com");
        assert!(cert.is_expired()); // expires_at is in the past
    }

    #[test]
    fn test_certificate_expiry() {
        let mut cert = create_test_cert("example.com");
        assert!(!cert.is_expired());
        assert!(cert.days_until_expiry() > 0);

        // Test expired certificate
        cert.expires_at = 1;
        assert!(cert.is_expired());
        assert!(cert.days_until_expiry() < 0);
    }

    #[test]
    fn test_certificate_renewal_check() {
        let mut cert = create_test_cert("example.com");

        // Should not need renewal yet (90 days validity, 30 day threshold)
        assert!(!cert.needs_renewal(30));

        // Set expiry to 20 days from now
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        cert.expires_at = now + 20 * 24 * 60 * 60;
        assert!(cert.needs_renewal(30));
    }

    #[test]
    fn test_certificate_domain_coverage() {
        let mut cert = create_test_cert("example.com");
        assert!(cert.covers_domain("example.com"));
        assert!(!cert.covers_domain("other.com"));
        assert!(!cert.covers_domain("sub.example.com"));

        // Test wildcard
        cert.domains = vec!["*.example.com".to_string()];
        assert!(cert.covers_domain("www.example.com"));
        assert!(cert.covers_domain("api.example.com"));
        assert!(!cert.covers_domain("example.com"));
        assert!(!cert.covers_domain("deep.sub.example.com"));
    }

    #[test]
    fn test_certificate_full_chain() {
        let mut cert = create_test_cert("example.com");
        assert_eq!(cert.full_chain(), cert.certificate_pem);

        cert.chain_pem = "chain".to_string();
        let full = cert.full_chain();
        assert!(full.contains(&cert.certificate_pem));
        assert!(full.contains(&cert.chain_pem));
    }

    #[test]
    fn test_memory_storage() {
        let storage = MemoryCertificateStorage::new();

        let cert = create_test_cert("example.com");
        storage.store(&cert).unwrap();

        let loaded = storage.load("example.com").unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().primary_domain(), "example.com");

        let list = storage.list().unwrap();
        assert_eq!(list.len(), 1);

        storage.delete("example.com").unwrap();
        let loaded = storage.load("example.com").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_memory_storage_find() {
        let storage = MemoryCertificateStorage::new();

        let mut cert = create_test_cert("*.example.com");
        cert.domains = vec!["*.example.com".to_string()];
        storage.store(&cert).unwrap();

        let found = storage.find_for_domain("www.example.com").unwrap();
        assert!(found.is_some());

        let not_found = storage.find_for_domain("other.com").unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_memory_storage_multiple_domains() {
        let storage = MemoryCertificateStorage::new();

        let mut cert = create_test_cert("example.com");
        cert.domains = vec!["example.com".to_string(), "www.example.com".to_string()];
        storage.store(&cert).unwrap();

        // Both domains should find the certificate
        assert!(storage.load("example.com").unwrap().is_some());
        assert!(storage.load("www.example.com").unwrap().is_some());
    }
}
