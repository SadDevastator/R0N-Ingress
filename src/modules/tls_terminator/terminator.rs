//! TLS Terminator - the main terminator module.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::module::{
    Capability, MetricsPayload, ModuleConfig, ModuleContract, ModuleError, ModuleManifest,
    ModuleResult, ModuleStatus,
};

use super::certificate::CertificateStore;
use super::config::TlsTerminatorConfig;
use super::connection::{
    passthrough_connection, proxy_to_backend, AtomicConnectionStats, TlsConnection,
};
use super::error::TlsResult;
use super::sni::{extract_sni_from_client_hello, SniDecision, SniRouter};

/// The TLS Terminator module.
#[allow(dead_code)]
pub struct TlsTerminator {
    /// Current status.
    status: ModuleStatus,

    /// Configuration.
    config: Option<TlsTerminatorConfig>,

    /// Certificate store.
    certificate_store: Option<CertificateStore>,

    /// SNI router.
    sni_router: Option<Arc<SniRouter>>,

    /// Connection statistics.
    stats: Arc<AtomicConnectionStats>,

    /// Start time.
    started_at: Option<Instant>,

    /// Shutdown signal sender.
    shutdown_tx: Option<mpsc::Sender<()>>,

    /// Certificate reload interval.
    reload_interval: Option<Duration>,
}

impl TlsTerminator {
    /// Create a new TLS terminator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            status: ModuleStatus::Initializing,
            config: None,
            certificate_store: None,
            sni_router: None,
            stats: Arc::new(AtomicConnectionStats::new()),
            started_at: None,
            shutdown_tx: None,
            reload_interval: None,
        }
    }

    /// Get connection statistics.
    #[must_use]
    pub fn stats(&self) -> super::connection::ConnectionStats {
        self.stats.snapshot()
    }

    /// Handle a new TLS connection.
    async fn handle_connection(
        stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        acceptor: TlsAcceptor,
        backend: Option<SocketAddr>,
        stats: Arc<AtomicConnectionStats>,
        handshake_timeout: Duration,
    ) {
        stats.record_connection();

        // Perform TLS handshake with timeout
        let tls_result = timeout(handshake_timeout, acceptor.accept(stream)).await;

        let tls_stream = match tls_result {
            Ok(Ok(stream)) => {
                stats.record_handshake_success();
                stream
            },
            Ok(Err(e)) => {
                stats.record_handshake_failure();
                stats.record_connection_closed();
                warn!(peer = %peer_addr, error = %e, "TLS handshake failed");
                return;
            },
            Err(_) => {
                stats.record_handshake_failure();
                stats.record_connection_closed();
                warn!(peer = %peer_addr, "TLS handshake timeout");
                return;
            },
        };

        // Get SNI from the connection
        let sni_name = tls_stream.get_ref().1.server_name().map(|s| s.to_string());

        debug!(
            peer = %peer_addr,
            sni = ?sni_name,
            "TLS connection established"
        );

        let conn = TlsConnection::new(tls_stream, peer_addr, local_addr, sni_name);

        // Proxy to backend if configured
        if let Some(backend_addr) = backend {
            if let Err(e) = proxy_to_backend(conn, backend_addr, &stats).await {
                warn!(
                    peer = %peer_addr,
                    error = %e,
                    "Proxy error"
                );
            }
        }

        stats.record_connection_closed();
    }

    /// Handle passthrough mode for a connection.
    async fn handle_passthrough(
        stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
        sni_router: Arc<SniRouter>,
        stats: Arc<AtomicConnectionStats>,
    ) {
        use tokio::io::AsyncReadExt;

        stats.record_connection();

        // Peek at the initial data to extract SNI
        let mut initial_buf = vec![0u8; 1024];
        let mut stream = stream;

        // Read the initial Client Hello
        let n = match stream.peek(&mut initial_buf).await {
            Ok(n) => n,
            Err(e) => {
                error!(peer = %peer_addr, error = %e, "Failed to peek at initial data");
                stats.record_connection_closed();
                return;
            },
        };

        let initial_data = &initial_buf[..n];

        // Extract SNI
        let sni = match extract_sni_from_client_hello(initial_data) {
            Ok(Some(sni)) => sni,
            Ok(None) => {
                warn!(peer = %peer_addr, "No SNI in Client Hello");
                stats.record_connection_closed();
                return;
            },
            Err(e) => {
                error!(peer = %peer_addr, error = %e, "Failed to extract SNI");
                stats.record_connection_closed();
                return;
            },
        };

        // Route based on SNI
        match sni_router.resolve(&sni) {
            Some(SniDecision::Passthrough { backend }) => {
                // Read the actual data
                let mut read_buf = vec![0u8; n];
                if let Err(e) = stream.read_exact(&mut read_buf).await {
                    error!(peer = %peer_addr, error = %e, "Failed to read initial data");
                    stats.record_connection_closed();
                    return;
                }

                if let Err(e) = passthrough_connection(stream, backend, &read_buf, &stats).await {
                    warn!(peer = %peer_addr, error = %e, "Passthrough error");
                }
            },
            Some(SniDecision::Terminate { .. }) => {
                warn!(
                    peer = %peer_addr,
                    sni = %sni,
                    "Expected passthrough but got terminate decision"
                );
            },
            None => {
                warn!(peer = %peer_addr, sni = %sni, "No route found for SNI");
            },
        }

        stats.record_connection_closed();
    }

    /// Build TLS acceptor from SNI router.
    fn build_acceptor(sni_router: Arc<SniRouter>) -> TlsResult<TlsAcceptor> {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(sni_router);

        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    /// Certificate reload task.
    #[allow(dead_code)]
    async fn certificate_reload_task(
        mut store: CertificateStore,
        interval: Duration,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        let mut reload_interval = tokio::time::interval(interval);

        loop {
            tokio::select! {
                _ = reload_interval.tick() => {
                    let errors = store.reload_all();
                    for error in errors {
                        error!(error = %error, "Certificate reload failed");
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Certificate reload task shutting down");
                    break;
                }
            }
        }
    }
}

impl Default for TlsTerminator {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleContract for TlsTerminator {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("tls-terminator")
            .description("TLS termination with SNI routing, passthrough, and mTLS support")
            .version(1, 0, 0)
            .author("R0N Team")
            .capability(Capability::TlsTermination)
            .capability(Capability::Custom("sni-routing".to_string()))
            .capability(Capability::Custom("tls-passthrough".to_string()))
            .capability(Capability::Custom("mtls".to_string()))
            .capability(Capability::Custom("certificate-hot-reload".to_string()))
            .build()
    }

    fn init(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        info!("Initializing TLS Terminator");
        self.status = ModuleStatus::Initializing;

        // Parse configuration
        let terminator_config = if let Some(config_json) = config.get_string("config_json") {
            serde_json::from_str(config_json)
                .map_err(|e| ModuleError::ConfigError(format!("Invalid TLS config: {e}")))?
        } else {
            TlsTerminatorConfig::default()
        };

        // Validate configuration
        if terminator_config.listeners.is_empty() {
            return Err(ModuleError::ConfigError(
                "At least one listener is required".to_string(),
            ));
        }

        if terminator_config.certificates.is_empty() && !terminator_config.passthrough.enabled {
            return Err(ModuleError::ConfigError(
                "At least one certificate is required when passthrough is disabled".to_string(),
            ));
        }

        // Load certificates
        let mut certificate_store = CertificateStore::load_all(&terminator_config.certificates)
            .map_err(|e| ModuleError::ConfigError(format!("Failed to load certificates: {e}")))?;

        // Set default certificate
        if let Some(ref default_name) = terminator_config.default_certificate {
            certificate_store.set_default(default_name);
        }

        // Build SNI router
        let mut sni_router = SniRouter::new();

        for name in certificate_store.names() {
            if let Some(bundle) = certificate_store.get(name) {
                sni_router.add_bundle(bundle).map_err(|e| {
                    ModuleError::ConfigError(format!("Failed to add bundle {name}: {e}"))
                })?;
            }
        }

        if let Some(ref default_name) = terminator_config.default_certificate {
            sni_router.set_default(default_name);
        }

        // Add passthrough routes
        if terminator_config.passthrough.enabled {
            sni_router.add_passthrough_routes(terminator_config.passthrough.routes.clone());
        }

        self.certificate_store = Some(certificate_store);
        self.sni_router = Some(Arc::new(sni_router));
        self.config = Some(terminator_config);
        self.status = ModuleStatus::Running;

        info!("TLS Terminator initialized");
        Ok(())
    }

    fn start(&mut self) -> ModuleResult<()> {
        info!("Starting TLS Terminator");

        if !matches!(
            self.status,
            ModuleStatus::Running | ModuleStatus::Initializing
        ) {
            return Err(ModuleError::InvalidState {
                current: self.status.to_string(),
                expected: "Running or Initializing".to_string(),
            });
        }

        let config = self
            .config
            .as_ref()
            .ok_or_else(|| ModuleError::InvalidState {
                current: "No config".to_string(),
                expected: "Configuration set".to_string(),
            })?;

        let sni_router = self
            .sni_router
            .clone()
            .ok_or_else(|| ModuleError::InvalidState {
                current: "No SNI router".to_string(),
                expected: "SNI router initialized".to_string(),
            })?;

        let (shutdown_tx, _shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx.clone());

        let stats = Arc::clone(&self.stats);
        let handshake_timeout = Duration::from_secs(config.connection.handshake_timeout_secs);
        let listener_configs = config.listeners.clone();
        let passthrough_enabled = config.passthrough.enabled;

        // Build TLS acceptor
        let acceptor = Self::build_acceptor(Arc::clone(&sni_router))
            .map_err(|e| ModuleError::ConfigError(format!("Failed to build acceptor: {e}")))?;

        // Start listeners
        for listener_config in listener_configs {
            let acceptor = acceptor.clone();
            let sni_router = Arc::clone(&sni_router);
            let stats = Arc::clone(&stats);
            let backend = listener_config.backend.as_ref().map(|b| b.socket_addr());

            tokio::spawn(async move {
                let addr = listener_config.socket_addr();

                let listener = match TcpListener::bind(addr).await {
                    Ok(l) => {
                        info!(addr = %addr, name = ?listener_config.name, "TLS listener started");
                        l
                    },
                    Err(e) => {
                        error!(addr = %addr, error = %e, "Failed to bind TLS listener");
                        return;
                    },
                };

                loop {
                    match listener.accept().await {
                        Ok((stream, peer_addr)) => {
                            let local_addr = addr;

                            if passthrough_enabled {
                                // In passthrough mode, decide based on SNI
                                let sni_router = Arc::clone(&sni_router);
                                let stats = Arc::clone(&stats);

                                tokio::spawn(async move {
                                    Self::handle_passthrough(stream, peer_addr, sni_router, stats)
                                        .await;
                                });
                            } else {
                                // Normal termination mode
                                let acceptor = acceptor.clone();
                                let stats = Arc::clone(&stats);

                                tokio::spawn(async move {
                                    Self::handle_connection(
                                        stream,
                                        peer_addr,
                                        local_addr,
                                        acceptor,
                                        backend,
                                        stats,
                                        handshake_timeout,
                                    )
                                    .await;
                                });
                            }
                        },
                        Err(e) => {
                            error!(error = %e, "Accept error");
                        },
                    }
                }
            });
        }

        self.started_at = Some(Instant::now());
        self.status = ModuleStatus::Running;

        info!("TLS Terminator started");
        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        info!("Stopping TLS Terminator");

        if !matches!(self.status, ModuleStatus::Running) {
            return Err(ModuleError::InvalidState {
                current: self.status.to_string(),
                expected: "Running".to_string(),
            });
        }

        // Signal shutdown
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.try_send(());
        }

        self.status = ModuleStatus::Stopped;
        info!("TLS Terminator stopped");
        Ok(())
    }

    fn reload(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        info!("Reloading TLS Terminator configuration");

        // Parse new configuration
        let new_config: TlsTerminatorConfig =
            if let Some(config_json) = config.get_string("config_json") {
                serde_json::from_str(config_json)
                    .map_err(|e| ModuleError::ConfigError(format!("Invalid config: {e}")))?
            } else {
                return Err(ModuleError::ConfigError(
                    "No config_json provided for reload".to_string(),
                ));
            };

        // Reload certificates
        let new_store = CertificateStore::load_all(&new_config.certificates)
            .map_err(|e| ModuleError::ConfigError(format!("Failed to load certificates: {e}")))?;

        // Build new SNI router
        let mut new_router = SniRouter::new();
        for name in new_store.names() {
            if let Some(bundle) = new_store.get(name) {
                new_router.add_bundle(bundle).map_err(|e| {
                    ModuleError::ConfigError(format!("Failed to add bundle {name}: {e}"))
                })?;
            }
        }

        if let Some(ref default_name) = new_config.default_certificate {
            new_router.set_default(default_name);
        }

        if new_config.passthrough.enabled {
            new_router.add_passthrough_routes(new_config.passthrough.routes.clone());
        }

        self.certificate_store = Some(new_store);
        self.sni_router = Some(Arc::new(new_router));
        self.config = Some(new_config);

        info!("TLS Terminator configuration reloaded");
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    fn metrics(&self) -> MetricsPayload {
        let mut metrics = MetricsPayload::new();
        let stats = self.stats.snapshot();

        metrics.counter("total_connections", stats.total_connections);
        metrics.gauge("active_connections", stats.active_connections as f64);
        metrics.counter("successful_handshakes", stats.successful_handshakes);
        metrics.counter("failed_handshakes", stats.failed_handshakes);
        metrics.counter("bytes_read", stats.bytes_read);
        metrics.counter("bytes_written", stats.bytes_written);
        metrics.gauge(
            "uptime_seconds",
            self.started_at.map(|t| t.elapsed().as_secs()).unwrap_or(0) as f64,
        );

        metrics
    }

    fn heartbeat(&self) -> bool {
        self.status.is_operational()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminator_creation() {
        let terminator = TlsTerminator::new();
        assert!(matches!(terminator.status(), ModuleStatus::Initializing));
    }

    #[test]
    fn test_terminator_manifest() {
        let terminator = TlsTerminator::new();
        let manifest = terminator.manifest();

        assert_eq!(manifest.name, "tls-terminator");
        assert!(manifest.capabilities.contains(&Capability::TlsTermination));
    }

    #[test]
    fn test_terminator_init_no_listeners() {
        let mut terminator = TlsTerminator::new();

        let config_json = serde_json::json!({
            "listeners": [],
            "certificates": []
        });

        let mut config = ModuleConfig::new();
        config.set_string("config_json", config_json.to_string());

        let result = terminator.init(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_terminator_init_no_certs_no_passthrough() {
        let mut terminator = TlsTerminator::new();

        let config_json = serde_json::json!({
            "listeners": [{"port": 443}],
            "certificates": [],
            "passthrough": {"enabled": false}
        });

        let mut config = ModuleConfig::new();
        config.set_string("config_json", config_json.to_string());

        let result = terminator.init(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_terminator_stats() {
        let terminator = TlsTerminator::new();
        let stats = terminator.stats();

        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.active_connections, 0);
    }

    #[test]
    fn test_terminator_metrics() {
        let terminator = TlsTerminator::new();
        let metrics = terminator.metrics();

        assert!(!metrics.counters.is_empty() || !metrics.gauges.is_empty());
    }

    #[test]
    fn test_terminator_heartbeat() {
        let terminator = TlsTerminator::new();
        assert!(!terminator.heartbeat()); // Initializing is not operational
    }
}
