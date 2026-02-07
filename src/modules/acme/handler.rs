//! ACME handler implementing ModuleContract

use super::client::{AcmeClient, ClientState};
use super::config::AcmeConfig;
use super::error::{AcmeError, AcmeResult};
use super::storage::Certificate;
use crate::module::{
    Capability, MetricsPayload, ModuleConfig, ModuleContract, ModuleError, ModuleManifest,
    ModuleResult, ModuleStatus,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Statistics for the ACME handler
#[derive(Debug, Default)]
pub struct AcmeStats {
    /// Total certificates issued
    pub certificates_issued: AtomicU64,
    /// Total certificates renewed
    pub certificates_renewed: AtomicU64,
    /// Certificate issuance failures
    pub issuance_failures: AtomicU64,
    /// Renewal failures
    pub renewal_failures: AtomicU64,
    /// HTTP-01 challenges completed
    pub http01_challenges: AtomicU64,
    /// DNS-01 challenges completed
    pub dns01_challenges: AtomicU64,
    /// Total renewal checks
    pub renewal_checks: AtomicU64,
    /// Active certificates
    pub active_certificates: AtomicU64,
    /// Certificates expiring soon
    pub expiring_soon: AtomicU64,
}

impl AcmeStats {
    /// Create new stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a certificate issuance
    pub fn record_issuance(&self, success: bool) {
        if success {
            self.certificates_issued.fetch_add(1, Ordering::Relaxed);
        } else {
            self.issuance_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a renewal
    pub fn record_renewal(&self, success: bool) {
        self.renewal_checks.fetch_add(1, Ordering::Relaxed);
        if success {
            self.certificates_renewed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.renewal_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a challenge completion
    pub fn record_challenge(&self, challenge_type: &str) {
        match challenge_type {
            "http-01" => self.http01_challenges.fetch_add(1, Ordering::Relaxed),
            "dns-01" => self.dns01_challenges.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    /// Update certificate counts
    pub fn update_counts(&self, active: u64, expiring: u64) {
        self.active_certificates.store(active, Ordering::Relaxed);
        self.expiring_soon.store(expiring, Ordering::Relaxed);
    }
}

/// Certificate info for external use
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Primary domain
    pub domain: String,
    /// All domains covered
    pub domains: Vec<String>,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Days until expiry
    pub days_until_expiry: i64,
    /// Whether renewal is needed
    pub needs_renewal: bool,
    /// Issuer
    pub issuer: String,
}

impl CertificateInfo {
    /// Create from a certificate
    pub fn from_certificate(cert: &Certificate, renewal_days: u32) -> Self {
        Self {
            domain: cert.primary_domain().to_string(),
            domains: cert.domains.clone(),
            expires_at: cert.expires_at,
            days_until_expiry: cert.days_until_expiry(),
            needs_renewal: cert.needs_renewal(renewal_days),
            issuer: cert.issuer.clone(),
        }
    }
}

/// ACME handler implementing ModuleContract
#[allow(dead_code)]
pub struct AcmeHandler {
    /// Configuration
    config: AcmeConfig,

    /// ACME client (wrapped in Arc<RwLock> for async access)
    client: Option<Arc<RwLock<AcmeClient>>>,

    /// Current status
    status: ModuleStatus,

    /// Statistics
    stats: Arc<AcmeStats>,

    /// Start time for uptime calculation
    started_at: Option<Instant>,

    /// Last renewal check time (for tracking)
    last_renewal_check: Option<Instant>,

    /// Renewal task handle
    renewal_task: Option<tokio::task::JoinHandle<()>>,

    /// Shutdown signal
    shutdown: Option<tokio::sync::watch::Sender<bool>>,
}

impl std::fmt::Debug for AcmeHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeHandler")
            .field("config", &self.config)
            .field("status", &self.status)
            .field("stats", &self.stats)
            .field("started_at", &self.started_at)
            .finish()
    }
}

impl AcmeHandler {
    /// Create a new ACME handler
    pub fn new() -> Self {
        Self::with_config(AcmeConfig::default())
    }

    /// Create an ACME handler with custom configuration
    pub fn with_config(config: AcmeConfig) -> Self {
        Self {
            config,
            client: None,
            status: ModuleStatus::Stopped,
            stats: Arc::new(AcmeStats::new()),
            started_at: None,
            last_renewal_check: None,
            renewal_task: None,
            shutdown: None,
        }
    }

    /// Get the ACME client
    pub fn client(&self) -> Option<&Arc<RwLock<AcmeClient>>> {
        self.client.as_ref()
    }

    /// Get statistics
    pub fn stats(&self) -> &AcmeStats {
        &self.stats
    }

    /// Request a certificate for domains
    pub async fn request_certificate(&self, domains: &[&str]) -> AcmeResult<Certificate> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| AcmeError::Internal("Client not initialized".to_string()))?;

        let mut client_guard = client.write().await;
        let result = client_guard.obtain_certificate(domains).await;

        match &result {
            Ok(_) => self.stats.record_issuance(true),
            Err(_) => self.stats.record_issuance(false),
        }

        result
    }

    /// Get certificate for a domain
    pub async fn get_certificate(&self, domain: &str) -> AcmeResult<Option<Certificate>> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| AcmeError::Internal("Client not initialized".to_string()))?;

        let client_guard = client.read().await;
        client_guard.get_certificate(domain)
    }

    /// List all certificates
    pub async fn list_certificates(&self) -> AcmeResult<Vec<String>> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| AcmeError::Internal("Client not initialized".to_string()))?;

        let client_guard = client.read().await;
        client_guard.list_certificates()
    }

    /// Get certificate info for all managed certificates
    pub async fn certificate_info(&self) -> AcmeResult<Vec<CertificateInfo>> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| AcmeError::Internal("Client not initialized".to_string()))?;

        let client_guard = client.read().await;
        let domains = client_guard.list_certificates()?;

        let mut info = Vec::new();
        for domain in domains {
            if let Some(cert) = client_guard.get_certificate(&domain)? {
                info.push(CertificateInfo::from_certificate(
                    &cert,
                    self.config.renewal.days_before_expiry,
                ));
            }
        }

        Ok(info)
    }

    /// Force renewal check
    pub async fn check_renewals(&self) -> AcmeResult<Vec<String>> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| AcmeError::Internal("Client not initialized".to_string()))?;

        let mut client_guard = client.write().await;
        let renewed = client_guard.check_renewals().await?;

        for domain in &renewed {
            self.stats.record_renewal(true);
            info!("Certificate renewed for {}", domain);
        }

        Ok(renewed)
    }

    /// Handle HTTP-01 challenge request
    pub fn handle_challenge_request(&self, path: &str) -> Option<String> {
        let client = self.client.as_ref()?;

        // This is synchronous for HTTP handler compatibility
        // Use try_read to avoid blocking
        let client_guard = match client.try_read() {
            Ok(guard) => guard,
            Err(_) => return None,
        };

        client_guard.http01_responder().handle_request(path)
    }

    /// Start the renewal background task
    fn start_renewal_task(&mut self) {
        if !self.config.renewal.enabled {
            debug!("Auto-renewal disabled");
            return;
        }

        // Only start the task if we're in a tokio runtime
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(h) => h,
            Err(_) => {
                debug!("No tokio runtime available, skipping renewal task");
                return;
            },
        };

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        self.shutdown = Some(shutdown_tx);

        let client = self.client.clone();
        let stats = self.stats.clone();
        let interval = Duration::from_secs(self.config.renewal.check_interval_secs);
        let renewal_days = self.config.renewal.days_before_expiry;

        let task = handle.spawn(async move {
            info!("Starting ACME renewal task with interval {:?}", interval);

            let mut interval_timer = tokio::time::interval(interval);

            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        info!("ACME renewal task shutting down");
                        break;
                    }
                    _ = interval_timer.tick() => {
                        if let Some(client) = &client {
                            debug!("Running scheduled renewal check");
                            stats.renewal_checks.fetch_add(1, Ordering::Relaxed);

                            let mut client_guard = client.write().await;
                            match client_guard.check_renewals().await {
                                Ok(renewed) => {
                                    for domain in renewed {
                                        stats.record_renewal(true);
                                        info!("Auto-renewed certificate for {}", domain);
                                    }
                                }
                                Err(e) => {
                                    stats.record_renewal(false);
                                    warn!("Renewal check failed: {}", e);
                                }
                            }

                            // Update certificate counts
                            if let Ok(domains) = client_guard.list_certificates() {
                                let mut active = 0u64;
                                let mut expiring = 0u64;

                                for domain in domains {
                                    if let Ok(Some(cert)) = client_guard.get_certificate(&domain) {
                                        if !cert.is_expired() {
                                            active += 1;
                                            if cert.needs_renewal(renewal_days) {
                                                expiring += 1;
                                            }
                                        }
                                    }
                                }

                                stats.update_counts(active, expiring);
                            }
                        }
                    }
                }
            }
        });

        self.renewal_task = Some(task);
    }

    /// Stop the renewal background task
    fn stop_renewal_task(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(true);
        }

        if let Some(task) = self.renewal_task.take() {
            task.abort();
        }
    }
}

impl Default for AcmeHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleContract for AcmeHandler {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("acme")
            .description(
                "ACME integration for automatic TLS certificate management with Let's Encrypt",
            )
            .version(1, 0, 0)
            .capability(Capability::TlsTermination)
            .capability(Capability::Custom("CertificateManagement".to_string()))
            .capability(Capability::Custom("AutomaticRenewal".to_string()))
            .capability(Capability::Custom("Http01Challenge".to_string()))
            .build()
    }

    fn init(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        if self.status != ModuleStatus::Stopped {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Stopped".to_string(),
            });
        }

        info!("Initializing ACME handler");

        // Parse configuration from raw TOML if available
        if let Some(raw_config) = config.raw_config() {
            if let Ok(acme_config) = toml::from_str::<AcmeConfig>(raw_config) {
                self.config = acme_config;
                debug!("Loaded ACME configuration from TOML");
            }
        }

        // Validate configuration
        if let Err(e) = self.config.validate() {
            return Err(ModuleError::ConfigError(format!(
                "Invalid ACME config: {}",
                e
            )));
        }

        // Create the ACME client
        let client = AcmeClient::new(self.config.clone())
            .map_err(|e| ModuleError::Internal(format!("Failed to create ACME client: {}", e)))?;

        self.client = Some(Arc::new(RwLock::new(client)));

        self.status = ModuleStatus::Initializing;
        info!("ACME handler initialized successfully");
        Ok(())
    }

    fn start(&mut self) -> ModuleResult<()> {
        if self.status != ModuleStatus::Initializing {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Initializing".to_string(),
            });
        }

        self.started_at = Some(Instant::now());
        self.status = ModuleStatus::Running;

        // Start renewal background task
        self.start_renewal_task();

        info!(
            "ACME handler started with directory: {}",
            self.config.directory_url
        );

        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        if self.status != ModuleStatus::Running {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Running".to_string(),
            });
        }

        // Stop renewal task
        self.stop_renewal_task();

        self.status = ModuleStatus::Stopped;
        self.started_at = None;

        info!("ACME handler stopped");
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    fn metrics(&self) -> MetricsPayload {
        let mut payload = MetricsPayload::new();

        // Counter metrics
        payload.counter(
            "certificates_issued",
            self.stats.certificates_issued.load(Ordering::Relaxed),
        );
        payload.counter(
            "certificates_renewed",
            self.stats.certificates_renewed.load(Ordering::Relaxed),
        );
        payload.counter(
            "issuance_failures",
            self.stats.issuance_failures.load(Ordering::Relaxed),
        );
        payload.counter(
            "renewal_failures",
            self.stats.renewal_failures.load(Ordering::Relaxed),
        );
        payload.counter(
            "http01_challenges",
            self.stats.http01_challenges.load(Ordering::Relaxed),
        );
        payload.counter(
            "dns01_challenges",
            self.stats.dns01_challenges.load(Ordering::Relaxed),
        );
        payload.counter(
            "renewal_checks",
            self.stats.renewal_checks.load(Ordering::Relaxed),
        );

        // Gauge metrics
        payload.gauge(
            "active_certificates",
            self.stats.active_certificates.load(Ordering::Relaxed) as f64,
        );
        payload.gauge(
            "expiring_soon",
            self.stats.expiring_soon.load(Ordering::Relaxed) as f64,
        );

        if let Some(started) = self.started_at {
            payload.gauge("uptime_secs", started.elapsed().as_secs() as f64);
        }

        payload
    }

    fn heartbeat(&self) -> bool {
        if self.status != ModuleStatus::Running {
            return false;
        }

        // Check client is ready
        if let Some(client) = &self.client {
            if let Ok(guard) = client.try_read() {
                return guard.state() == ClientState::Ready
                    || guard.state() == ClientState::Uninitialized;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::ModuleConfig;

    fn create_test_config() -> AcmeConfig {
        AcmeConfig {
            enabled: true,
            directory_url: "https://acme.example.com/directory".to_string(),
            contact_emails: vec!["test@example.com".to_string()],
            accept_tos: true,
            domains: vec!["example.com".to_string()],
            storage: super::super::config::StorageConfig {
                storage_type: super::super::config::StorageType::Memory,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_acme_handler_lifecycle() {
        let mut handler = AcmeHandler::with_config(create_test_config());
        assert_eq!(handler.status(), ModuleStatus::Stopped);

        let config = ModuleConfig::new();

        handler.init(config).unwrap();
        assert_eq!(handler.status(), ModuleStatus::Initializing);

        handler.start().unwrap();
        assert_eq!(handler.status(), ModuleStatus::Running);

        handler.stop().unwrap();
        assert_eq!(handler.status(), ModuleStatus::Stopped);
    }

    #[test]
    fn test_acme_handler_manifest() {
        let handler = AcmeHandler::new();
        let manifest = handler.manifest();
        assert_eq!(manifest.name, "acme");
        assert!(!manifest.capabilities.is_empty());
    }

    #[test]
    fn test_acme_handler_init_with_config() {
        let mut handler = AcmeHandler::with_config(create_test_config());

        let config = ModuleConfig::new();
        handler.init(config).unwrap();

        assert!(handler.client().is_some());
    }

    #[test]
    fn test_acme_handler_double_init() {
        let mut handler = AcmeHandler::with_config(create_test_config());

        let config = ModuleConfig::new();
        handler.init(config.clone()).unwrap();

        let result = handler.init(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_acme_handler_start_before_init() {
        let mut handler = AcmeHandler::new();
        let result = handler.start();
        assert!(result.is_err());
    }

    #[test]
    fn test_acme_stats() {
        let stats = AcmeStats::new();

        stats.record_issuance(true);
        stats.record_issuance(false);
        stats.record_renewal(true);
        stats.record_challenge("http-01");
        stats.record_challenge("dns-01");

        assert_eq!(stats.certificates_issued.load(Ordering::Relaxed), 1);
        assert_eq!(stats.issuance_failures.load(Ordering::Relaxed), 1);
        assert_eq!(stats.certificates_renewed.load(Ordering::Relaxed), 1);
        assert_eq!(stats.http01_challenges.load(Ordering::Relaxed), 1);
        assert_eq!(stats.dns01_challenges.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_certificate_info() {
        use super::super::storage::Certificate;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cert = Certificate::new(
            vec!["example.com".to_string()],
            "cert".to_string(),
            "key".to_string(),
            "chain".to_string(),
            now + 30 * 24 * 60 * 60, // 30 days
        );

        let info = CertificateInfo::from_certificate(&cert, 7);

        assert_eq!(info.domain, "example.com");
        assert!(!info.needs_renewal);
        assert!(info.days_until_expiry > 25);
    }

    #[test]
    fn test_certificate_info_needs_renewal() {
        use super::super::storage::Certificate;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cert = Certificate::new(
            vec!["example.com".to_string()],
            "cert".to_string(),
            "key".to_string(),
            "chain".to_string(),
            now + 5 * 24 * 60 * 60, // 5 days
        );

        let info = CertificateInfo::from_certificate(&cert, 7);

        assert!(info.needs_renewal);
        assert!(info.days_until_expiry < 7);
    }

    #[test]
    fn test_acme_handler_metrics() {
        let mut handler = AcmeHandler::with_config(create_test_config());
        let config = ModuleConfig::new();
        handler.init(config).unwrap();
        handler.start().unwrap();

        let metrics = handler.metrics();
        assert!(!metrics.counters.is_empty() || !metrics.gauges.is_empty());
    }

    #[test]
    fn test_acme_handler_heartbeat() {
        let mut handler = AcmeHandler::with_config(create_test_config());
        assert!(!handler.heartbeat());

        let config = ModuleConfig::new();
        handler.init(config).unwrap();
        handler.start().unwrap();

        // Heartbeat should work when running
        assert!(handler.heartbeat());

        handler.stop().unwrap();
        assert!(!handler.heartbeat());
    }

    #[tokio::test]
    async fn test_request_certificate_before_init() {
        let handler = AcmeHandler::new();
        let result = handler.request_certificate(&["example.com"]).await;
        assert!(result.is_err());
    }
}
