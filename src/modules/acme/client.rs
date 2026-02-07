//! ACME client for certificate management

use super::account::{Account, AccountCredentials};
use super::challenge::{
    Challenge, ChallengeStatus, ChallengeType, Http01Challenge, Http01Responder,
};
use super::config::AcmeConfig;
use super::error::{AcmeError, AcmeResult};
use super::order::{Authorization, Identifier, Order, OrderBuilder, OrderStatus};
use super::storage::{
    Certificate, CertificateStorage, FileCertificateStorage, MemoryCertificateStorage,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// ACME directory endpoints
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Directory {
    /// New nonce URL
    pub new_nonce: String,
    /// New account URL
    pub new_account: String,
    /// New order URL
    pub new_order: String,
    /// Revoke certificate URL
    pub revoke_cert: String,
    /// Key change URL
    pub key_change: String,
    /// Terms of service URL
    pub terms_of_service: Option<String>,
    /// Website URL
    pub website: Option<String>,
}

impl Directory {
    /// Create a mock directory for testing
    pub fn mock() -> Self {
        Self {
            new_nonce: "https://acme.example.com/new-nonce".to_string(),
            new_account: "https://acme.example.com/new-acct".to_string(),
            new_order: "https://acme.example.com/new-order".to_string(),
            revoke_cert: "https://acme.example.com/revoke-cert".to_string(),
            key_change: "https://acme.example.com/key-change".to_string(),
            terms_of_service: Some("https://acme.example.com/tos".to_string()),
            website: None,
        }
    }
}

/// ACME client state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// Not initialized
    Uninitialized,
    /// Directory fetched
    DirectoryFetched,
    /// Account registered
    AccountRegistered,
    /// Ready to issue certificates
    Ready,
    /// Error state
    Error,
}

/// ACME client for certificate management
#[allow(dead_code)]
pub struct AcmeClient {
    /// Client configuration
    config: AcmeConfig,

    /// Directory endpoints
    directory: Option<Directory>,

    /// Account
    account: Option<Account>,

    /// Certificate storage
    storage: Arc<dyn CertificateStorage>,

    /// HTTP-01 challenge responder
    http01_responder: Http01Responder,

    /// Current state
    state: ClientState,

    /// Pending orders
    pending_orders: HashMap<String, Order>,

    /// Current nonce (for replay protection)
    nonce: Option<String>,
}

impl AcmeClient {
    /// Create a new ACME client
    pub fn new(config: AcmeConfig) -> AcmeResult<Self> {
        // Create storage based on config
        let storage: Arc<dyn CertificateStorage> = match config.storage.storage_type {
            super::config::StorageType::File => Arc::new(FileCertificateStorage::new(
                &config.storage.path,
                config.storage.file_mode,
            )?),
            super::config::StorageType::Memory => Arc::new(MemoryCertificateStorage::new()),
        };

        Ok(Self {
            config,
            directory: None,
            account: None,
            storage,
            http01_responder: Http01Responder::new(),
            state: ClientState::Uninitialized,
            pending_orders: HashMap::new(),
            nonce: None,
        })
    }

    /// Create client with custom storage
    pub fn with_storage(config: AcmeConfig, storage: Arc<dyn CertificateStorage>) -> Self {
        Self {
            config,
            directory: None,
            account: None,
            storage,
            http01_responder: Http01Responder::new(),
            state: ClientState::Uninitialized,
            pending_orders: HashMap::new(),
            nonce: None,
        }
    }

    /// Get the current state
    pub fn state(&self) -> ClientState {
        self.state
    }

    /// Check if client is ready
    pub fn is_ready(&self) -> bool {
        self.state == ClientState::Ready
    }

    /// Get the HTTP-01 responder
    pub fn http01_responder(&self) -> &Http01Responder {
        &self.http01_responder
    }

    /// Initialize the client by fetching directory
    pub async fn initialize(&mut self) -> AcmeResult<()> {
        info!(
            "Initializing ACME client with directory: {}",
            self.config.directory_url
        );

        // Fetch directory
        self.directory = Some(self.fetch_directory().await?);
        self.state = ClientState::DirectoryFetched;
        debug!("Directory fetched successfully");

        // Register or load account
        self.ensure_account().await?;
        self.state = ClientState::AccountRegistered;
        debug!("Account ready");

        self.state = ClientState::Ready;
        info!("ACME client initialized and ready");

        Ok(())
    }

    /// Fetch ACME directory
    async fn fetch_directory(&self) -> AcmeResult<Directory> {
        // In production, make HTTP request to directory URL
        // For now, return mock directory
        debug!("Fetching ACME directory from {}", self.config.directory_url);

        // Simulate network request
        if self.config.directory_url.contains("letsencrypt") {
            Ok(Directory {
                new_nonce: format!(
                    "{}/acme/new-nonce",
                    self.config.directory_url.replace("/directory", "")
                ),
                new_account: format!(
                    "{}/acme/new-acct",
                    self.config.directory_url.replace("/directory", "")
                ),
                new_order: format!(
                    "{}/acme/new-order",
                    self.config.directory_url.replace("/directory", "")
                ),
                revoke_cert: format!(
                    "{}/acme/revoke-cert",
                    self.config.directory_url.replace("/directory", "")
                ),
                key_change: format!(
                    "{}/acme/key-change",
                    self.config.directory_url.replace("/directory", "")
                ),
                terms_of_service: Some(
                    "https://letsencrypt.org/documents/LE-SA-v1.3-September-21-2022.pdf"
                        .to_string(),
                ),
                website: Some("https://letsencrypt.org".to_string()),
            })
        } else {
            Ok(Directory::mock())
        }
    }

    /// Ensure account exists (register or load)
    async fn ensure_account(&mut self) -> AcmeResult<()> {
        // For memory storage, always register a new account
        if self.config.storage.storage_type == super::config::StorageType::Memory {
            return self.register_account().await;
        }

        // Try to load existing account from file storage
        let account_path = self.config.storage.path.join("account.json");
        if account_path.exists() {
            match Account::load(&account_path) {
                Ok(account) => {
                    info!("Loaded existing ACME account");
                    self.account = Some(account);
                    return Ok(());
                },
                Err(e) => {
                    warn!("Failed to load account, will register new: {}", e);
                },
            }
        }

        // Register new account
        self.register_account().await
    }

    /// Register a new account
    async fn register_account(&mut self) -> AcmeResult<()> {
        info!("Registering new ACME account");

        // Generate new key pair
        let credentials = AccountCredentials::generate()?;

        // Create account
        let account = Account::new(
            "pending".to_string(),
            self.directory
                .as_ref()
                .map(|d| d.new_account.clone())
                .unwrap_or_default(),
            credentials,
        );

        // In production, make POST to new_account endpoint
        // For now, simulate success
        let mut account = account;
        account.id = format!("acct-{}", generate_id());
        account.contacts = self
            .config
            .contact_emails
            .iter()
            .map(|e| format!("mailto:{}", e))
            .collect();
        account.tos_agreed = self.config.accept_tos;

        // Save account to file if using file storage
        if self.config.storage.storage_type == super::config::StorageType::File {
            let account_path = self.config.storage.path.join("account.json");
            std::fs::create_dir_all(&self.config.storage.path)?;
            account.save(&account_path)?;
        }

        self.account = Some(account);
        info!("ACME account registered successfully");

        Ok(())
    }

    /// Create a new order for certificates
    pub async fn create_order(&mut self, domains: &[&str]) -> AcmeResult<Order> {
        if !self.is_ready() {
            return Err(AcmeError::Account("Client not initialized".to_string()));
        }

        let builder = OrderBuilder::new().domains(domains.iter().map(|s| s.to_string()));
        builder.validate()?;

        info!("Creating order for domains: {:?}", domains);

        // Create identifiers
        let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::dns(*d)).collect();

        // In production, POST to new_order endpoint
        // For now, simulate order creation
        let order_id = generate_id();
        let order = Order::new(
            format!("https://acme.example.com/order/{}", order_id),
            identifiers,
            domains
                .iter()
                .enumerate()
                .map(|(i, _)| format!("https://acme.example.com/authz/{}-{}", order_id, i))
                .collect(),
            format!("https://acme.example.com/finalize/{}", order_id),
        );

        self.pending_orders.insert(order_id.clone(), order.clone());
        debug!("Order created: {}", order.url);

        Ok(order)
    }

    /// Get authorizations for an order
    pub async fn get_authorizations(&self, order: &Order) -> AcmeResult<Vec<Authorization>> {
        let mut authorizations = Vec::new();

        for (i, authz_url) in order.authorizations.iter().enumerate() {
            let domain = order
                .identifiers
                .get(i)
                .map(|id| id.value.clone())
                .unwrap_or_default();

            // Create challenges
            let challenges = vec![
                Challenge::new(
                    ChallengeType::Http01,
                    format!("{}/http01", authz_url),
                    generate_id(),
                    domain.clone(),
                ),
                Challenge::new(
                    ChallengeType::Dns01,
                    format!("{}/dns01", authz_url),
                    generate_id(),
                    domain.clone(),
                ),
            ];

            let authz = Authorization::new(authz_url.clone(), Identifier::dns(domain), challenges);

            authorizations.push(authz);
        }

        Ok(authorizations)
    }

    /// Prepare HTTP-01 challenge
    pub fn prepare_http01_challenge(&self, authz: &Authorization) -> AcmeResult<Http01Challenge> {
        let challenge = authz
            .http01_challenge()
            .ok_or_else(|| AcmeError::Challenge {
                challenge_type: "http-01".to_string(),
                message: "HTTP-01 challenge not available".to_string(),
            })?;

        let account = self
            .account
            .as_ref()
            .ok_or_else(|| AcmeError::Account("No account".to_string()))?;

        let http01 = Http01Challenge::new(challenge.clone(), account.key_thumbprint());

        // Register with responder
        self.http01_responder
            .add_challenge(&http01.token.token, &http01.token.key_authorization)?;

        debug!("HTTP-01 challenge prepared for {}", authz.domain());
        Ok(http01)
    }

    /// Respond to a challenge
    pub async fn respond_to_challenge(&self, challenge: &Challenge) -> AcmeResult<()> {
        info!(
            "Responding to {} challenge for {}",
            challenge.challenge_type.as_str(),
            challenge.domain
        );

        // In production, POST to challenge URL
        // Simulating success
        Ok(())
    }

    /// Poll challenge status
    pub async fn poll_challenge(&self, challenge: &Challenge) -> AcmeResult<ChallengeStatus> {
        debug!("Polling challenge status for {}", challenge.domain);

        // In production, GET challenge URL
        // Simulating success
        Ok(ChallengeStatus::Valid)
    }

    /// Wait for challenge to complete
    pub async fn wait_for_challenge(
        &self,
        challenge: &Challenge,
        timeout: Duration,
    ) -> AcmeResult<()> {
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            let status = self.poll_challenge(challenge).await?;

            match status {
                ChallengeStatus::Valid => {
                    info!("Challenge completed successfully for {}", challenge.domain);
                    return Ok(());
                },
                ChallengeStatus::Invalid => {
                    return Err(AcmeError::Challenge {
                        challenge_type: challenge.challenge_type.as_str().to_string(),
                        message: "Challenge failed".to_string(),
                    });
                },
                ChallengeStatus::Pending | ChallengeStatus::Processing => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                },
            }
        }

        Err(AcmeError::Timeout("Challenge timed out".to_string()))
    }

    /// Finalize order and get certificate
    pub async fn finalize_order(&mut self, order: &mut Order) -> AcmeResult<Certificate> {
        if order.status != OrderStatus::Ready {
            return Err(AcmeError::Order(format!(
                "Order not ready: {:?}",
                order.status
            )));
        }

        info!("Finalizing order for {:?}", order.domains());

        // Generate CSR
        let _csr = self.generate_csr(&order.domains())?;

        // In production, POST CSR to finalize URL
        // Simulate finalization
        order.status = OrderStatus::Processing;

        // Wait for processing
        tokio::time::sleep(Duration::from_millis(100)).await;
        order.status = OrderStatus::Valid;
        order.certificate = Some(format!("{}/cert", order.url));

        // Download certificate
        let cert = self.download_certificate(order).await?;

        // Store certificate
        self.storage.store(&cert)?;

        info!("Certificate obtained and stored for {:?}", order.domains());
        Ok(cert)
    }

    /// Generate CSR for domains
    fn generate_csr(&self, domains: &[&str]) -> AcmeResult<Vec<u8>> {
        debug!("Generating CSR for {:?}", domains);

        // In production, use rcgen or openssl to generate CSR
        // For now, return placeholder
        Ok(format!("CSR for {:?}", domains).into_bytes())
    }

    /// Download certificate from order
    async fn download_certificate(&self, order: &Order) -> AcmeResult<Certificate> {
        let cert_url = order
            .certificate
            .as_ref()
            .ok_or_else(|| AcmeError::Certificate("No certificate URL".to_string()))?;

        debug!("Downloading certificate from {}", cert_url);

        // In production, GET certificate URL
        // Simulate certificate download
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Certificate::new(
            order.domains().into_iter().map(|s| s.to_string()).collect(),
            "-----BEGIN CERTIFICATE-----\n(certificate data)\n-----END CERTIFICATE-----"
                .to_string(),
            "-----BEGIN PRIVATE KEY-----\n(private key data)\n-----END PRIVATE KEY-----"
                .to_string(),
            "-----BEGIN CERTIFICATE-----\n(chain data)\n-----END CERTIFICATE-----".to_string(),
            now + 90 * 24 * 60 * 60, // 90 days validity
        ))
    }

    /// Obtain certificate for domains (full flow)
    pub async fn obtain_certificate(&mut self, domains: &[&str]) -> AcmeResult<Certificate> {
        // Check if we already have a valid certificate
        if let Some(cert) = self.storage.find_for_domain(domains[0])? {
            if !cert.needs_renewal(self.config.renewal.days_before_expiry) {
                info!("Using existing certificate for {:?}", domains);
                return Ok(cert);
            }
            info!("Certificate needs renewal for {:?}", domains);
        }

        // Create order
        let mut order = self.create_order(domains).await?;

        // Get authorizations
        let authorizations = self.get_authorizations(&order).await?;

        // Complete challenges
        for authz in &authorizations {
            let challenge = match self.config.preferred_challenge {
                super::config::ChallengePreference::Http01 => authz.http01_challenge(),
                super::config::ChallengePreference::Dns01 => authz.dns01_challenge(),
                super::config::ChallengePreference::TlsAlpn01 => authz.http01_challenge(), // fallback
            };

            let challenge = challenge.ok_or_else(|| AcmeError::Challenge {
                challenge_type: "preferred".to_string(),
                message: "No suitable challenge available".to_string(),
            })?;

            // Prepare and respond
            if challenge.challenge_type == ChallengeType::Http01 {
                self.prepare_http01_challenge(authz)?;
            }

            self.respond_to_challenge(challenge).await?;
            self.wait_for_challenge(challenge, self.config.timeout())
                .await?;
        }

        // Update order status
        order.status = OrderStatus::Ready;

        // Finalize and get certificate
        self.finalize_order(&mut order).await
    }

    /// Check and renew certificates that need renewal
    pub async fn check_renewals(&mut self) -> AcmeResult<Vec<String>> {
        if !self.config.renewal.enabled {
            return Ok(Vec::new());
        }

        let mut renewed = Vec::new();
        let domains = self.storage.list()?;

        for domain in domains {
            if let Some(cert) = self.storage.load(&domain)? {
                if cert.needs_renewal(self.config.renewal.days_before_expiry) {
                    info!("Renewing certificate for {}", domain);

                    match self
                        .obtain_certificate(
                            &cert.domains.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                        )
                        .await
                    {
                        Ok(_) => {
                            renewed.push(domain);
                        },
                        Err(e) => {
                            warn!("Failed to renew certificate for {}: {}", domain, e);
                        },
                    }
                }
            }
        }

        Ok(renewed)
    }

    /// Get a certificate for a domain
    pub fn get_certificate(&self, domain: &str) -> AcmeResult<Option<Certificate>> {
        self.storage.find_for_domain(domain)
    }

    /// List all certificates
    pub fn list_certificates(&self) -> AcmeResult<Vec<String>> {
        self.storage.list()
    }
}

/// Generate a random ID
fn generate_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    format!("{:x}", now)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_client_creation() {
        let config = create_test_config();
        let client = AcmeClient::new(config).unwrap();
        assert_eq!(client.state(), ClientState::Uninitialized);
        assert!(!client.is_ready());
    }

    #[test]
    fn test_directory_mock() {
        let dir = Directory::mock();
        assert!(!dir.new_nonce.is_empty());
        assert!(!dir.new_account.is_empty());
        assert!(!dir.new_order.is_empty());
    }

    #[tokio::test]
    async fn test_client_initialize() {
        let config = create_test_config();
        let mut client = AcmeClient::new(config).unwrap();

        client.initialize().await.unwrap();
        assert!(client.is_ready());
        assert_eq!(client.state(), ClientState::Ready);
    }

    #[tokio::test]
    async fn test_create_order() {
        let config = create_test_config();
        let mut client = AcmeClient::new(config).unwrap();
        client.initialize().await.unwrap();

        let order = client
            .create_order(&["example.com", "www.example.com"])
            .await
            .unwrap();
        assert!(order.is_pending());
        assert_eq!(order.identifiers.len(), 2);
    }

    #[tokio::test]
    async fn test_get_authorizations() {
        let config = create_test_config();
        let mut client = AcmeClient::new(config).unwrap();
        client.initialize().await.unwrap();

        let order = client.create_order(&["example.com"]).await.unwrap();
        let authz = client.get_authorizations(&order).await.unwrap();

        assert_eq!(authz.len(), 1);
        assert!(authz[0].http01_challenge().is_some());
        assert!(authz[0].dns01_challenge().is_some());
    }

    #[tokio::test]
    async fn test_obtain_certificate() {
        let config = create_test_config();
        let mut client = AcmeClient::new(config).unwrap();
        client.initialize().await.unwrap();

        let cert = client.obtain_certificate(&["example.com"]).await.unwrap();
        assert_eq!(cert.primary_domain(), "example.com");
        assert!(!cert.is_expired());
    }

    #[tokio::test]
    async fn test_certificate_caching() {
        let config = create_test_config();
        let mut client = AcmeClient::new(config).unwrap();
        client.initialize().await.unwrap();

        // First request obtains certificate
        let cert1 = client.obtain_certificate(&["example.com"]).await.unwrap();

        // Second request should use cached certificate
        let cert2 = client.obtain_certificate(&["example.com"]).await.unwrap();

        assert_eq!(cert1.issued_at, cert2.issued_at);
    }

    #[test]
    fn test_http01_responder() {
        let config = create_test_config();
        let client = AcmeClient::new(config).unwrap();

        let responder = client.http01_responder();
        responder.add_challenge("token123", "auth456").unwrap();

        let response = responder.handle_request("/.well-known/acme-challenge/token123");
        assert_eq!(response, Some("auth456".to_string()));
    }
}
