//! UDP Router - the main router module.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::module::{
    Capability, MetricsPayload, ModuleConfig, ModuleContract, ModuleError, ModuleManifest,
    ModuleResult, ModuleStatus,
};

use super::config::{BackendConfig, LoadBalanceStrategy, RouteConfig, UdpRouterConfig};
use super::error::{UdpRouterError, UdpRouterResult};
use super::session::{SessionId, SessionManager, SessionStats};
use super::socket::BoundSocket;

/// Router statistics.
#[derive(Debug, Clone, Default)]
pub struct RouterStats {
    /// Total datagrams received from clients.
    pub datagrams_received: u64,

    /// Total datagrams forwarded to backends.
    pub datagrams_forwarded: u64,

    /// Total datagrams received from backends.
    pub datagrams_from_backends: u64,

    /// Total datagrams sent to clients.
    pub datagrams_to_clients: u64,

    /// Total bytes received.
    pub bytes_received: u64,

    /// Total bytes sent.
    pub bytes_sent: u64,

    /// Routing errors.
    pub routing_errors: u64,

    /// Uptime in seconds.
    pub uptime_seconds: u64,

    /// Session statistics.
    pub sessions: SessionStats,
}

/// Backend health state.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BackendHealth {
    /// The backend address.
    pub address: SocketAddr,

    /// Whether the backend is healthy.
    pub healthy: bool,

    /// Consecutive failures.
    pub failures: u32,

    /// Last successful interaction.
    pub last_success: Option<Instant>,

    /// Last failure.
    pub last_failure: Option<Instant>,
}

/// Round-robin state for load balancing.
#[derive(Debug, Default)]
#[allow(dead_code)]
struct RoundRobinState {
    counters: HashMap<String, AtomicU64>,
}

impl RoundRobinState {
    #[allow(dead_code)]
    fn next(&self, route_name: &str, backend_count: usize) -> usize {
        let counter = self
            .counters
            .get(route_name)
            .map_or_else(|| 0, |c| c.fetch_add(1, Ordering::Relaxed) as usize);
        counter % backend_count
    }
}

/// The UDP Router module.
#[allow(dead_code)]
pub struct UdpRouter {
    /// Current status.
    status: ModuleStatus,

    /// Router configuration.
    config: Option<UdpRouterConfig>,

    /// Active bound sockets.
    sockets: Vec<Arc<BoundSocket>>,

    /// Session manager for stateful routing.
    session_manager: Option<Arc<SessionManager>>,

    /// Backend health states.
    health: Arc<RwLock<HashMap<SocketAddr, BackendHealth>>>,

    /// Statistics.
    stats: Arc<RouterStatsInner>,

    /// Round-robin state.
    round_robin: Arc<RoundRobinState>,

    /// Start time.
    started_at: Option<Instant>,

    /// Shutdown signal sender.
    shutdown_tx: Option<mpsc::Sender<()>>,
}

/// Inner statistics (atomic counters).
struct RouterStatsInner {
    datagrams_received: AtomicU64,
    datagrams_forwarded: AtomicU64,
    datagrams_from_backends: AtomicU64,
    datagrams_to_clients: AtomicU64,
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
    routing_errors: AtomicU64,
}

impl Default for RouterStatsInner {
    fn default() -> Self {
        Self {
            datagrams_received: AtomicU64::new(0),
            datagrams_forwarded: AtomicU64::new(0),
            datagrams_from_backends: AtomicU64::new(0),
            datagrams_to_clients: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            routing_errors: AtomicU64::new(0),
        }
    }
}

impl UdpRouter {
    /// Create a new UDP router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            status: ModuleStatus::Initializing,
            config: None,
            sockets: Vec::new(),
            session_manager: None,
            health: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RouterStatsInner::default()),
            round_robin: Arc::new(RoundRobinState::default()),
            started_at: None,
            shutdown_tx: None,
        }
    }

    /// Get router statistics.
    pub async fn stats(&self) -> RouterStats {
        let session_stats = if let Some(ref sm) = self.session_manager {
            sm.stats().await
        } else {
            SessionStats::default()
        };

        RouterStats {
            datagrams_received: self.stats.datagrams_received.load(Ordering::Relaxed),
            datagrams_forwarded: self.stats.datagrams_forwarded.load(Ordering::Relaxed),
            datagrams_from_backends: self.stats.datagrams_from_backends.load(Ordering::Relaxed),
            datagrams_to_clients: self.stats.datagrams_to_clients.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            routing_errors: self.stats.routing_errors.load(Ordering::Relaxed),
            uptime_seconds: self.started_at.map(|t| t.elapsed().as_secs()).unwrap_or(0),
            sessions: session_stats,
        }
    }

    /// Find a route for an incoming datagram.
    #[allow(dead_code)]
    fn find_route(&self, local_addr: SocketAddr, _peer: SocketAddr) -> Option<&RouteConfig> {
        let config = self.config.as_ref()?;

        config.routes.iter().find(|route| {
            let criteria = &route.match_criteria;

            // Match by port
            if let Some(port) = criteria.port {
                if local_addr.port() != port {
                    return false;
                }
            }

            // Match by address
            if let Some(ref addr) = criteria.address {
                if local_addr.ip().to_string() != *addr {
                    return false;
                }
            }

            // TODO: Match by source CIDR
            // if let Some(ref cidr) = criteria.source_cidr { ... }

            // Catch-all matches everything
            criteria.catch_all || criteria.port.is_some()
        })
    }

    /// Select a backend from a route using the configured load balancing strategy.
    #[allow(dead_code)]
    async fn select_backend<'a>(
        &self,
        route: &'a RouteConfig,
        peer: SocketAddr,
    ) -> Option<&'a BackendConfig> {
        if route.backends.is_empty() {
            return None;
        }

        let strategy = route.load_balance;

        // Filter healthy backends
        let health = self.health.read().await;
        let healthy_backends: Vec<_> = route
            .backends
            .iter()
            .filter(|b| {
                health
                    .get(&b.socket_addr())
                    .map(|h| h.healthy)
                    .unwrap_or(true) // Assume healthy if not tracked
            })
            .collect();

        if healthy_backends.is_empty() {
            warn!(route = %route.name, "No healthy backends");
            return None;
        }

        let selected = match strategy {
            LoadBalanceStrategy::RoundRobin => {
                let idx = self.round_robin.next(&route.name, healthy_backends.len());
                healthy_backends.get(idx).copied()
            },
            LoadBalanceStrategy::Random => {
                use std::collections::hash_map::RandomState;
                use std::hash::{BuildHasher, Hasher};

                let idx =
                    RandomState::new().build_hasher().finish() as usize % healthy_backends.len();
                healthy_backends.get(idx).copied()
            },
            LoadBalanceStrategy::IpHash => {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                peer.ip().hash(&mut hasher);
                let idx = hasher.finish() as usize % healthy_backends.len();
                healthy_backends.get(idx).copied()
            },
            LoadBalanceStrategy::WeightedRandom => {
                let total_weight: u32 = healthy_backends.iter().map(|b| b.weight).sum();
                if total_weight == 0 {
                    return healthy_backends.first().copied();
                }

                use std::collections::hash_map::RandomState;
                use std::hash::{BuildHasher, Hasher};

                let random = RandomState::new().build_hasher().finish() as u32 % total_weight;
                let mut cumulative = 0;
                for backend in &healthy_backends {
                    cumulative += backend.weight;
                    if random < cumulative {
                        return Some(*backend);
                    }
                }
                healthy_backends.last().copied()
            },
        };

        selected
    }

    /// Handle a received datagram.
    async fn handle_datagram(
        socket: Arc<BoundSocket>,
        buf: &[u8],
        peer: SocketAddr,
        local_addr: SocketAddr,
        route: RouteConfig,
        backend: BackendConfig,
        session_manager: Arc<SessionManager>,
        stats: Arc<RouterStatsInner>,
        health: Arc<RwLock<HashMap<SocketAddr, BackendHealth>>>,
    ) -> UdpRouterResult<()> {
        let backend_addr = backend.socket_addr();
        let session_id = SessionId::new(peer, local_addr);

        // Get or create session
        let session = if let Some(session) = session_manager.get_session(&session_id).await {
            session
        } else {
            session_manager
                .create_session(session_id.clone(), backend_addr, route.name.clone())
                .await
                .ok_or_else(|| UdpRouterError::ConfigError {
                    message: "Max sessions reached".to_string(),
                })?
        };

        // Forward datagram to backend
        let send_result = socket.send_to(buf, session.backend).await;

        match send_result {
            Ok(n) => {
                stats.datagrams_forwarded.fetch_add(1, Ordering::Relaxed);
                stats.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                session_manager.record_sent(&session_id, n).await;

                // Mark backend as healthy
                let mut health = health.write().await;
                if let Some(h) = health.get_mut(&backend_addr) {
                    h.healthy = true;
                    h.failures = 0;
                    h.last_success = Some(Instant::now());
                }

                debug!(
                    peer = %peer,
                    backend = %backend_addr,
                    bytes = n,
                    "Forwarded datagram to backend"
                );

                Ok(())
            },
            Err(e) => {
                stats.routing_errors.fetch_add(1, Ordering::Relaxed);

                // Update backend health
                let mut health = health.write().await;
                let entry = health.entry(backend_addr).or_insert_with(|| BackendHealth {
                    address: backend_addr,
                    healthy: true,
                    failures: 0,
                    last_success: None,
                    last_failure: None,
                });
                entry.failures += 1;
                entry.last_failure = Some(Instant::now());

                // After 3 consecutive failures, mark as unhealthy
                if entry.failures >= 3 {
                    entry.healthy = false;
                    warn!(
                        backend = %backend_addr,
                        "Backend marked unhealthy after {} failures",
                        entry.failures
                    );
                }

                Err(e)
            },
        }
    }

    /// Run session cleanup task.
    async fn session_cleanup_task(
        session_manager: Arc<SessionManager>,
        mut shutdown_rx: mpsc::Receiver<()>,
        interval: Duration,
    ) {
        let mut cleanup_interval = tokio::time::interval(interval);

        loop {
            tokio::select! {
                _ = cleanup_interval.tick() => {
                    let removed = session_manager.cleanup().await;
                    if removed > 0 {
                        debug!(removed, "Cleaned up expired sessions");
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Session cleanup task shutting down");
                    break;
                }
            }
        }
    }
}

impl Default for UdpRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleContract for UdpRouter {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("udp-router")
            .description("High-performance UDP routing and load balancing")
            .version(1, 0, 0)
            .author("R0N Team")
            .capability(Capability::UdpListener)
            .capability(Capability::LoadBalancing)
            .capability(Capability::Custom("session-tracking".to_string()))
            .capability(Capability::Custom("health-checks".to_string()))
            .build()
    }

    fn init(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        info!("Initializing UDP Router");
        self.status = ModuleStatus::Initializing;

        // Parse configuration from the module config values
        let router_config = if let Some(config_json) = config.get_string("config_json") {
            serde_json::from_str(config_json)
                .map_err(|e| ModuleError::ConfigError(format!("Invalid UDP router config: {e}")))?
        } else {
            // Use defaults - real implementation would parse the HashMap
            UdpRouterConfig::default()
        };

        // Validate configuration
        if router_config.listeners.is_empty() {
            return Err(ModuleError::ConfigError(
                "At least one listener is required".to_string(),
            ));
        }

        if router_config.routes.is_empty() {
            return Err(ModuleError::ConfigError(
                "At least one route is required".to_string(),
            ));
        }

        // Initialize session manager
        self.session_manager = Some(Arc::new(SessionManager::new(router_config.session.clone())));

        // Initialize health tracking for all backends
        let mut health = HashMap::new();
        for route in &router_config.routes {
            for backend in &route.backends {
                let addr = backend.socket_addr();
                health.insert(
                    addr,
                    BackendHealth {
                        address: addr,
                        healthy: true,
                        failures: 0,
                        last_success: None,
                        last_failure: None,
                    },
                );
            }
        }
        self.health = Arc::new(RwLock::new(health));

        // Initialize round-robin state
        let mut rr_counters = HashMap::new();
        for route in &router_config.routes {
            rr_counters.insert(route.name.clone(), AtomicU64::new(0));
        }
        self.round_robin = Arc::new(RoundRobinState {
            counters: rr_counters,
        });

        self.config = Some(router_config);
        self.status = ModuleStatus::Running;

        info!("UDP Router initialized");
        Ok(())
    }

    fn start(&mut self) -> ModuleResult<()> {
        info!("Starting UDP Router");

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

        let (shutdown_tx, _shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx.clone());

        // Create a second shutdown channel for the cleanup task
        let (cleanup_shutdown_tx, cleanup_shutdown_rx) = mpsc::channel(1);

        let session_manager =
            self.session_manager
                .clone()
                .ok_or_else(|| ModuleError::InvalidState {
                    current: "No session manager".to_string(),
                    expected: "Session manager initialized".to_string(),
                })?;

        // Spawn session cleanup task
        let cleanup_session_manager = Arc::clone(&session_manager);
        let cleanup_interval = config.session.timeout() / 10; // Cleanup 10x per timeout period
        tokio::spawn(async move {
            Self::session_cleanup_task(
                cleanup_session_manager,
                cleanup_shutdown_rx,
                cleanup_interval,
            )
            .await;
        });

        let stats = Arc::clone(&self.stats);
        let health = Arc::clone(&self.health);
        let routes = config.routes.clone();
        let listener_configs = config.listeners.clone();
        let max_datagram_size = config.max_datagram_size;

        // Spawn listener tasks
        for listener_config in listener_configs {
            let session_manager = Arc::clone(&session_manager);
            let stats = Arc::clone(&stats);
            let health = Arc::clone(&health);
            let routes = routes.clone();
            let _cleanup_shutdown_tx = cleanup_shutdown_tx.clone();

            tokio::spawn(async move {
                let socket = match BoundSocket::bind(listener_config.clone()).await {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        error!(error = %e, "Failed to bind UDP socket");
                        return;
                    },
                };

                let local_addr = socket.local_addr();
                info!(addr = %local_addr, "UDP listener started");

                let mut buf = vec![0u8; max_datagram_size];

                loop {
                    let recv_result = socket.recv_from(&mut buf).await;

                    match recv_result {
                        Ok((n, peer)) => {
                            stats.datagrams_received.fetch_add(1, Ordering::Relaxed);
                            stats.bytes_received.fetch_add(n as u64, Ordering::Relaxed);

                            // Find matching route
                            let route = routes.iter().find(|r| {
                                r.match_criteria
                                    .port
                                    .map_or(true, |p| p == local_addr.port())
                                    || r.match_criteria.catch_all
                            });

                            if let Some(route) = route {
                                if let Some(backend) = route.backends.first() {
                                    let socket = Arc::clone(&socket);
                                    let route = route.clone();
                                    let backend = backend.clone();
                                    let session_manager = Arc::clone(&session_manager);
                                    let stats = Arc::clone(&stats);
                                    let health = Arc::clone(&health);
                                    let datagram = buf[..n].to_vec();

                                    tokio::spawn(async move {
                                        if let Err(e) = Self::handle_datagram(
                                            socket,
                                            &datagram,
                                            peer,
                                            local_addr,
                                            route,
                                            backend,
                                            session_manager,
                                            stats,
                                            health,
                                        )
                                        .await
                                        {
                                            warn!(error = %e, "Failed to handle datagram");
                                        }
                                    });
                                } else {
                                    warn!(route = %route.name, "No backends configured");
                                }
                            } else {
                                warn!(addr = %local_addr, peer = %peer, "No route found for datagram");
                            }
                        },
                        Err(e) => {
                            error!(error = %e, "Receive error");
                        },
                    }
                }
            });
        }

        self.started_at = Some(Instant::now());
        self.status = ModuleStatus::Running;

        info!("UDP Router started");
        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        info!("Stopping UDP Router");

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
        info!("UDP Router stopped");
        Ok(())
    }

    fn reload(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        info!("Reloading UDP Router configuration");

        // Parse new configuration from config_json if present
        let new_config: UdpRouterConfig =
            if let Some(config_json) = config.get_string("config_json") {
                serde_json::from_str(config_json)
                    .map_err(|e| ModuleError::ConfigError(format!("Invalid config: {e}")))?
            } else {
                return Err(ModuleError::ConfigError(
                    "No config_json provided for reload".to_string(),
                ));
            };

        // Update session manager settings
        self.session_manager = Some(Arc::new(SessionManager::new(new_config.session.clone())));

        self.config = Some(new_config);

        info!("UDP Router configuration reloaded");
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    fn metrics(&self) -> MetricsPayload {
        let mut metrics = MetricsPayload::new();

        metrics.counter(
            "datagrams_received",
            self.stats.datagrams_received.load(Ordering::Relaxed),
        );
        metrics.counter(
            "datagrams_forwarded",
            self.stats.datagrams_forwarded.load(Ordering::Relaxed),
        );
        metrics.counter(
            "datagrams_from_backends",
            self.stats.datagrams_from_backends.load(Ordering::Relaxed),
        );
        metrics.counter(
            "datagrams_to_clients",
            self.stats.datagrams_to_clients.load(Ordering::Relaxed),
        );
        metrics.counter(
            "bytes_received",
            self.stats.bytes_received.load(Ordering::Relaxed),
        );
        metrics.counter("bytes_sent", self.stats.bytes_sent.load(Ordering::Relaxed));
        metrics.counter(
            "routing_errors",
            self.stats.routing_errors.load(Ordering::Relaxed),
        );
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
    fn test_router_creation() {
        let router = UdpRouter::new();
        assert!(matches!(router.status(), ModuleStatus::Initializing));
    }

    #[test]
    fn test_router_manifest() {
        let router = UdpRouter::new();
        let manifest = router.manifest();

        assert_eq!(manifest.name, "udp-router");
        assert!(manifest.capabilities.contains(&Capability::UdpListener));
        assert!(manifest.capabilities.contains(&Capability::LoadBalancing));
    }

    #[test]
    fn test_router_init_no_listeners() {
        let mut router = UdpRouter::new();

        // Create a config with empty listeners via config_json
        let config_json = serde_json::json!({
            "listeners": [],
            "routes": [{"name": "test", "match": {}, "backends": []}]
        });

        let mut config = ModuleConfig::new();
        config.set_string("config_json", config_json.to_string());

        let result = router.init(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_router_init_no_routes() {
        let mut router = UdpRouter::new();

        let config_json = serde_json::json!({
            "listeners": [{"port": 5353}],
            "routes": []
        });

        let mut config = ModuleConfig::new();
        config.set_string("config_json", config_json.to_string());

        let result = router.init(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_router_init_success() {
        let mut router = UdpRouter::new();

        let config_json = serde_json::json!({
            "listeners": [{"port": 5353}],
            "routes": [{
                "name": "dns",
                "match": {"port": 5353},
                "backends": [{"address": "8.8.8.8", "port": 53}]
            }]
        });

        let mut config = ModuleConfig::new();
        config.set_string("config_json", config_json.to_string());

        let result = router.init(config);
        assert!(result.is_ok());
        assert!(matches!(router.status(), ModuleStatus::Running));
    }

    #[test]
    fn test_router_stop_not_running() {
        let mut router = UdpRouter::new();

        // Initialize but set status to stopped
        let config_json = serde_json::json!({
            "listeners": [{"port": 5353}],
            "routes": [{
                "name": "dns",
                "match": {"port": 5353},
                "backends": [{"address": "8.8.8.8", "port": 53}]
            }]
        });

        let mut config = ModuleConfig::new();
        config.set_string("config_json", config_json.to_string());
        router.init(config).unwrap();
        router.status = ModuleStatus::Stopped;

        let result = router.stop();
        assert!(result.is_err());
    }

    #[test]
    fn test_router_heartbeat() {
        let router = UdpRouter::new();
        assert!(!router.heartbeat()); // Initializing is not operational
    }

    #[test]
    fn test_router_metrics() {
        let mut router = UdpRouter::new();

        let config_json = serde_json::json!({
            "listeners": [{"port": 5353}],
            "routes": [{
                "name": "dns",
                "match": {"port": 5353},
                "backends": [{"address": "8.8.8.8", "port": 53}]
            }]
        });

        let mut config = ModuleConfig::new();
        config.set_string("config_json", config_json.to_string());
        router.init(config).unwrap();

        let metrics = router.metrics();
        assert!(!metrics.counters.is_empty() || !metrics.gauges.is_empty());
    }
}
