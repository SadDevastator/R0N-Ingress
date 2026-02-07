//! ACME configuration types

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// ACME client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// Whether ACME is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// ACME directory URL
    #[serde(default = "DirectoryUrls::letsencrypt_staging")]
    pub directory_url: String,

    /// Contact email addresses for the account
    #[serde(default)]
    pub contact_emails: Vec<String>,

    /// Whether to accept terms of service automatically
    #[serde(default)]
    pub accept_tos: bool,

    /// Domains to obtain certificates for
    #[serde(default)]
    pub domains: Vec<String>,

    /// Preferred challenge type
    #[serde(default)]
    pub preferred_challenge: ChallengePreference,

    /// Certificate storage configuration
    #[serde(default)]
    pub storage: StorageConfig,

    /// Renewal configuration
    #[serde(default)]
    pub renewal: RenewalConfig,

    /// HTTP-01 challenge configuration
    #[serde(default)]
    pub http01: Http01Config,

    /// DNS-01 challenge configuration
    #[serde(default)]
    pub dns01: Dns01Config,

    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Maximum retries for failed requests
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// External account binding (for some CAs)
    #[serde(default)]
    pub external_account: Option<ExternalAccountBinding>,
}

fn default_true() -> bool {
    true
}

fn default_timeout() -> u64 {
    30
}

fn default_max_retries() -> u32 {
    3
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            directory_url: DirectoryUrls::letsencrypt_staging(),
            contact_emails: Vec::new(),
            accept_tos: false,
            domains: Vec::new(),
            preferred_challenge: ChallengePreference::default(),
            storage: StorageConfig::default(),
            renewal: RenewalConfig::default(),
            http01: Http01Config::default(),
            dns01: Dns01Config::default(),
            timeout_secs: 30,
            max_retries: 3,
            external_account: None,
        }
    }
}

impl AcmeConfig {
    /// Create configuration for Let's Encrypt staging
    pub fn letsencrypt_staging() -> Self {
        Self {
            directory_url: DirectoryUrls::letsencrypt_staging(),
            ..Default::default()
        }
    }

    /// Create configuration for Let's Encrypt production
    pub fn letsencrypt_production() -> Self {
        Self {
            directory_url: DirectoryUrls::letsencrypt_production(),
            ..Default::default()
        }
    }

    /// Set contact emails
    pub fn with_contacts(mut self, emails: Vec<String>) -> Self {
        self.contact_emails = emails;
        self
    }

    /// Set domains
    pub fn with_domains(mut self, domains: Vec<String>) -> Self {
        self.domains = domains;
        self
    }

    /// Accept TOS
    pub fn accept_terms(mut self) -> Self {
        self.accept_tos = true;
        self
    }

    /// Get timeout as Duration
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.domains.is_empty() {
            return Err("No domains configured for ACME".to_string());
        }

        if self.enabled && self.contact_emails.is_empty() {
            return Err("No contact emails configured for ACME".to_string());
        }

        if self.enabled && !self.accept_tos {
            return Err("Terms of service must be accepted".to_string());
        }

        for domain in &self.domains {
            if domain.is_empty() {
                return Err("Empty domain name".to_string());
            }
            // Basic domain validation
            if domain.contains(' ') || domain.starts_with('.') || domain.ends_with('.') {
                return Err(format!("Invalid domain: {}", domain));
            }
        }

        for email in &self.contact_emails {
            if !email.contains('@') {
                return Err(format!("Invalid email: {}", email));
            }
        }

        Ok(())
    }
}

/// Well-known ACME directory URLs
pub struct DirectoryUrls;

impl DirectoryUrls {
    /// Let's Encrypt staging environment
    pub fn letsencrypt_staging() -> String {
        "https://acme-staging-v02.api.letsencrypt.org/directory".to_string()
    }

    /// Let's Encrypt production environment
    pub fn letsencrypt_production() -> String {
        "https://acme-v02.api.letsencrypt.org/directory".to_string()
    }

    /// ZeroSSL production
    pub fn zerossl() -> String {
        "https://acme.zerossl.com/v2/DV90".to_string()
    }

    /// Buypass Go SSL (staging)
    pub fn buypass_staging() -> String {
        "https://api.test4.buypass.no/acme/directory".to_string()
    }

    /// Buypass Go SSL (production)
    pub fn buypass_production() -> String {
        "https://api.buypass.com/acme/directory".to_string()
    }
}

/// Challenge type preference
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChallengePreference {
    /// Prefer HTTP-01 challenge
    #[default]
    Http01,
    /// Prefer DNS-01 challenge
    Dns01,
    /// Prefer TLS-ALPN-01 challenge
    TlsAlpn01,
}

/// Certificate storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage type
    #[serde(default)]
    pub storage_type: StorageType,

    /// Base path for file storage
    #[serde(default = "default_storage_path")]
    pub path: PathBuf,

    /// File permissions (Unix)
    #[serde(default = "default_file_mode")]
    pub file_mode: u32,
}

fn default_storage_path() -> PathBuf {
    PathBuf::from("/var/lib/r0n-gateway/acme")
}

fn default_file_mode() -> u32 {
    0o600
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            storage_type: StorageType::default(),
            path: default_storage_path(),
            file_mode: default_file_mode(),
        }
    }
}

/// Storage type for certificates
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageType {
    /// Store in filesystem
    #[default]
    File,
    /// Store in memory (testing only)
    Memory,
}

/// Certificate renewal configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalConfig {
    /// Whether automatic renewal is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Days before expiry to attempt renewal
    #[serde(default = "default_renewal_days")]
    pub days_before_expiry: u32,

    /// Check interval in seconds
    #[serde(default = "default_check_interval")]
    pub check_interval_secs: u64,

    /// Maximum renewal attempts
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,

    /// Backoff multiplier for retries
    #[serde(default = "default_backoff_multiplier")]
    pub backoff_multiplier: f64,
}

fn default_renewal_days() -> u32 {
    30
}

fn default_check_interval() -> u64 {
    12 * 60 * 60 // 12 hours
}

fn default_max_attempts() -> u32 {
    5
}

fn default_backoff_multiplier() -> f64 {
    2.0
}

impl Default for RenewalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            days_before_expiry: 30,
            check_interval_secs: 12 * 60 * 60,
            max_attempts: 5,
            backoff_multiplier: 2.0,
        }
    }
}

impl RenewalConfig {
    /// Get check interval as Duration
    pub fn check_interval(&self) -> Duration {
        Duration::from_secs(self.check_interval_secs)
    }
}

/// HTTP-01 challenge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http01Config {
    /// Whether HTTP-01 challenge is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Port to listen on for HTTP-01 challenges
    #[serde(default = "default_http_port")]
    pub port: u16,

    /// Bind address for HTTP-01 server
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// Use existing HTTP server (integrate with HTTP handler)
    #[serde(default)]
    pub use_existing_server: bool,

    /// Redirect to HTTPS after challenge
    #[serde(default = "default_true")]
    pub redirect_to_https: bool,
}

fn default_http_port() -> u16 {
    80
}

fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}

impl Default for Http01Config {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 80,
            bind_address: "0.0.0.0".to_string(),
            use_existing_server: false,
            redirect_to_https: true,
        }
    }
}

/// DNS-01 challenge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dns01Config {
    /// Whether DNS-01 challenge is enabled
    #[serde(default)]
    pub enabled: bool,

    /// DNS provider type
    #[serde(default)]
    pub provider: DnsProvider,

    /// Propagation wait time in seconds
    #[serde(default = "default_propagation_wait")]
    pub propagation_wait_secs: u64,

    /// Propagation timeout in seconds
    #[serde(default = "default_propagation_timeout")]
    pub propagation_timeout_secs: u64,

    /// DNS resolvers to check propagation
    #[serde(default)]
    pub resolvers: Vec<String>,

    /// Provider-specific credentials
    #[serde(default)]
    pub credentials: DnsCredentials,
}

fn default_propagation_wait() -> u64 {
    60
}

fn default_propagation_timeout() -> u64 {
    300
}

impl Default for Dns01Config {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: DnsProvider::default(),
            propagation_wait_secs: 60,
            propagation_timeout_secs: 300,
            resolvers: Vec::new(),
            credentials: DnsCredentials::default(),
        }
    }
}

impl Dns01Config {
    /// Get propagation wait as Duration
    pub fn propagation_wait(&self) -> Duration {
        Duration::from_secs(self.propagation_wait_secs)
    }

    /// Get propagation timeout as Duration
    pub fn propagation_timeout(&self) -> Duration {
        Duration::from_secs(self.propagation_timeout_secs)
    }
}

/// DNS provider type
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsProvider {
    /// Manual DNS record management
    #[default]
    Manual,
    /// Cloudflare API
    Cloudflare,
    /// Route53 (AWS)
    Route53,
    /// DigitalOcean DNS
    DigitalOcean,
    /// Google Cloud DNS
    GoogleCloud,
    /// Azure DNS
    Azure,
    /// Custom webhook
    Webhook,
}

/// DNS provider credentials
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsCredentials {
    /// API key/token
    #[serde(default)]
    pub api_key: Option<String>,

    /// API secret
    #[serde(default)]
    pub api_secret: Option<String>,

    /// Zone ID
    #[serde(default)]
    pub zone_id: Option<String>,

    /// Additional provider-specific options
    #[serde(default)]
    pub options: std::collections::HashMap<String, String>,
}

/// External account binding (required by some CAs)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalAccountBinding {
    /// Key ID from the CA
    pub key_id: String,

    /// HMAC key (base64 URL-safe encoded)
    pub hmac_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AcmeConfig::default();
        assert!(config.enabled);
        assert!(config.contact_emails.is_empty());
        assert!(!config.accept_tos);
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_letsencrypt_staging() {
        let config = AcmeConfig::letsencrypt_staging();
        assert!(config.directory_url.contains("staging"));
    }

    #[test]
    fn test_letsencrypt_production() {
        let config = AcmeConfig::letsencrypt_production();
        assert!(config.directory_url.contains("acme-v02"));
        assert!(!config.directory_url.contains("staging"));
    }

    #[test]
    fn test_config_builder() {
        let config = AcmeConfig::letsencrypt_staging()
            .with_contacts(vec!["admin@example.com".to_string()])
            .with_domains(vec!["example.com".to_string()])
            .accept_terms();

        assert_eq!(config.contact_emails.len(), 1);
        assert_eq!(config.domains.len(), 1);
        assert!(config.accept_tos);
    }

    #[test]
    fn test_validation_success() {
        let config = AcmeConfig::letsencrypt_staging()
            .with_contacts(vec!["admin@example.com".to_string()])
            .with_domains(vec!["example.com".to_string()])
            .accept_terms();

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validation_no_domains() {
        let config = AcmeConfig::letsencrypt_staging()
            .with_contacts(vec!["admin@example.com".to_string()])
            .accept_terms();

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_no_email() {
        let config = AcmeConfig::letsencrypt_staging()
            .with_domains(vec!["example.com".to_string()])
            .accept_terms();

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_tos_not_accepted() {
        let config = AcmeConfig::letsencrypt_staging()
            .with_contacts(vec!["admin@example.com".to_string()])
            .with_domains(vec!["example.com".to_string()]);

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_invalid_email() {
        let config = AcmeConfig::letsencrypt_staging()
            .with_contacts(vec!["not-an-email".to_string()])
            .with_domains(vec!["example.com".to_string()])
            .accept_terms();

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_invalid_domain() {
        let config = AcmeConfig::letsencrypt_staging()
            .with_contacts(vec!["admin@example.com".to_string()])
            .with_domains(vec![".invalid.".to_string()])
            .accept_terms();

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_directory_urls() {
        assert!(DirectoryUrls::letsencrypt_staging().contains("letsencrypt"));
        assert!(DirectoryUrls::letsencrypt_production().contains("letsencrypt"));
        assert!(DirectoryUrls::zerossl().contains("zerossl"));
        assert!(DirectoryUrls::buypass_staging().contains("buypass"));
    }

    #[test]
    fn test_renewal_config() {
        let config = RenewalConfig::default();
        assert!(config.enabled);
        assert_eq!(config.days_before_expiry, 30);
        assert_eq!(config.check_interval().as_secs(), 12 * 60 * 60);
    }

    #[test]
    fn test_dns01_config() {
        let config = Dns01Config::default();
        assert!(!config.enabled);
        assert_eq!(config.propagation_wait().as_secs(), 60);
        assert_eq!(config.propagation_timeout().as_secs(), 300);
    }

    #[test]
    fn test_storage_config() {
        let config = StorageConfig::default();
        assert_eq!(config.storage_type, StorageType::File);
        assert_eq!(config.file_mode, 0o600);
    }
}
