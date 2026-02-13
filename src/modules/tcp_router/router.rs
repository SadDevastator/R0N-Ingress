//! TCP Router - the main router module.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::module::{
    Capability, MetricsPayload, ModuleConfig, ModuleContract, ModuleError, ModuleManifest,
    ModuleResult, ModuleStatus,
};

use super::config::{BackendConfig, LoadBalanceStrategy, RouteConfig, TcpRouterConfig};
use super::connection::Connection;
use super::error::TcpRouterResult;
use super::listener::{Listener, ListenerEvent};
use super::pool::ConnectionPool;

/// Router statistics.
#[derive(Debug, Clone, Default)]
pub struct RouterStats {
    /// Total connections received.
    pub total_connections: u64,

    /// Active connections.
    pub active_connections: u64,

    /// Total bytes received from clients.
    pub bytes_received: u64,

    /// Total bytes sent to clients.
    pub bytes_sent: u64,

    /// Total backend connections made.
    pub backend_connections: u64,

    /// Routing errors.
    pub routing_errors: u64,

    /// Uptime in seconds.
    pub uptime_seconds: u64,
}

/// Backend health state.
#[derive(Debug, Clone)]
pub struct BackendHealth {
    /// The backend address.
    pub address: SocketAddr,

    /// Whether the backend is healthy.
    pub healthy: bool,

    /// Consecutive failures.
    pub failures: u32,

    /// Last successful connection.
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

/// The TCP Router module.
pub struct TcpRouter {
    /// Current status.
    status: ModuleStatus,

    /// Router configuration.
    config: Option<TcpRouterConfig>,

    /// Active listeners.
    listeners: Vec<Listener>,

    /// Connection pool.
    pool: Option<ConnectionPool>,

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
    total_connections: AtomicU64,
    active_connections: AtomicU64,
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
    backend_connections: AtomicU64,
    routing_errors: AtomicU64,
}

impl Default for RouterStatsInner {
    fn default() -> Self {
        Self {
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            backend_connections: AtomicU64::new(0),
            routing_errors: AtomicU64::new(0),
        }
    }
}

impl TcpRouter {
    /// Create a new TCP router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            status: ModuleStatus::Initializing,
            config: None,
            listeners: Vec::new(),
            pool: None,
            health: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RouterStatsInner::default()),
            round_robin: Arc::new(RoundRobinState::default()),
            started_at: None,
            shutdown_tx: None,
        }
    }

    /// Get router statistics.
    #[inline]
    #[must_use]
    pub fn stats(&self) -> RouterStats {
        RouterStats {
            total_connections: self.stats.total_connections.load(Ordering::Relaxed),
            active_connections: self.stats.active_connections.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            backend_connections: self.stats.backend_connections.load(Ordering::Relaxed),
            routing_errors: self.stats.routing_errors.load(Ordering::Relaxed),
            uptime_seconds: self.started_at.map(|t| t.elapsed().as_secs()).unwrap_or(0),
        }
    }

    /// Find a route for an incoming connection.
    #[allow(dead_code)]
    fn find_route(&self, local_addr: SocketAddr) -> Option<&RouteConfig> {
        let config = self.config.as_ref()?;

        config.routes.iter().find(|route| {
            // Match by port
            if let Some(port) = route.match_criteria.port {
                if local_addr.port() != port {
                    return false;
                }
            }

            // Match by address
            if let Some(ref addr) = route.match_criteria.address {
                if local_addr.ip().to_string() != *addr {
                    return false;
                }
            }

            // Catch-all matches everything
            route.match_criteria.catch_all || route.match_criteria.port.is_some()
        })
    }

    /// Select a backend from a route using the configured load balancing strategy.
    #[allow(dead_code)]
    async fn select_backend<'a>(&self, route: &'a RouteConfig) -> Option<&'a BackendConfig> {
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
            LoadBalanceStrategy::LeastConnections => {
                // For now, fall back to round-robin
                // TODO: Track per-backend connection counts
                let idx = self.round_robin.next(&route.name, healthy_backends.len());
                healthy_backends.get(idx).copied()
            },
            LoadBalanceStrategy::IpHash => {
                // For now, fall back to round-robin
                // IP hash would need the client IP
                let idx = self.round_robin.next(&route.name, healthy_backends.len());
                healthy_backends.get(idx).copied()
            },
        };

        selected
    }

    /// Handle a new connection.
    async fn handle_connection(
        conn: Connection,
        route: RouteConfig,
        backend: BackendConfig,
        pool: ConnectionPool,
        stats: Arc<RouterStatsInner>,
        health: Arc<RwLock<HashMap<SocketAddr, BackendHealth>>>,
    ) {
        let conn_id = conn.id();
        let peer_addr = conn.peer_addr();
        let backend_addr = backend.socket_addr();

        debug!(conn_id, peer = %peer_addr, route = %route.name, "Handling connection");

        stats.total_connections.fetch_add(1, Ordering::Relaxed);
        stats.active_connections.fetch_add(1, Ordering::Relaxed);

        let result = Self::proxy_connection(conn, &backend, &pool, &stats).await;

        stats.active_connections.fetch_sub(1, Ordering::Relaxed);

        match result {
            Ok((bytes_in, bytes_out)) => {
                stats.bytes_received.fetch_add(bytes_in, Ordering::Relaxed);
                stats.bytes_sent.fetch_add(bytes_out, Ordering::Relaxed);

                // Mark backend as healthy
                let mut health = health.write().await;
                if let Some(h) = health.get_mut(&backend_addr) {
                    h.healthy = true;
                    h.failures = 0;
                    h.last_success = Some(Instant::now());
                }

                debug!(conn_id, bytes_in, bytes_out, "Connection completed");
            },
            Err(e) => {
                stats.routing_errors.fetch_add(1, Ordering::Relaxed);

                // Mark backend as potentially unhealthy
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
                    warn!(backend = %backend_addr, "Backend marked unhealthy after {} failures", entry.failures);
                }

                warn!(conn_id, error = %e, "Connection error");
            },
        }
    }

    /// Proxy data between client and backend.
    async fn proxy_connection(
        client_conn: Connection,
        backend: &BackendConfig,
        pool: &ConnectionPool,
        stats: &Arc<RouterStatsInner>,
    ) -> TcpRouterResult<(u64, u64)> {
        // Get a connection to the backend
        let mut backend_conn = pool.get(backend.socket_addr()).await?;
        stats.backend_connections.fetch_add(1, Ordering::Relaxed);

        let mut client_stream = client_conn.into_stream();
        let backend_stream = backend_conn.stream();

        let (mut client_read, mut client_write) = client_stream.split();
        let (mut backend_read, mut backend_write) = backend_stream.split();

        let client_to_backend = async {
            let mut buf = [0u8; 8192];
            let mut total = 0u64;
            loop {
                let n = client_read.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                backend_write.write_all(&buf[..n]).await?;
                total += n as u64;
            }
            Ok::<_, std::io::Error>(total)
        };

        let backend_to_client = async {
            let mut buf = [0u8; 8192];
            let mut total = 0u64;
            loop {
                let n = backend_read.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                client_write.write_all(&buf[..n]).await?;
                total += n as u64;
            }
            Ok::<_, std::io::Error>(total)
        };

        let (result_a, result_b) = tokio::join!(client_to_backend, backend_to_client);

        let bytes_in = result_a.unwrap_or(0);
        let bytes_out = result_b.unwrap_or(0);

        Ok((bytes_in, bytes_out))
    }
}

impl Default for TcpRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleContract for TcpRouter {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("tcp-router")
            .description("High-performance TCP routing and load balancing")
            .version(1, 0, 0)
            .author("R0N Team")
            .capability(Capability::TcpListener)
            .capability(Capability::LoadBalancing)
            .capability(Capability::Custom("connection-pooling".to_string()))
            .capability(Capability::Custom("health-checks".to_string()))
            .build()
    }

    fn init(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        info!("Initializing TCP Router");
        self.status = ModuleStatus::Initializing;

        // Parse configuration from the module config values
        // For now, we'll create a default config since ModuleConfig uses a HashMap
        // In a real implementation, we'd convert from the HashMap to TcpRouterConfig
        let router_config = if let Some(config_json) = config.get_string("config_json") {
            serde_json::from_str(config_json)
                .map_err(|e| ModuleError::ConfigError(format!("Invalid TCP router config: {e}")))?
        } else {
            // Build config from individual values
            // For now, use defaults - real implementation would parse the HashMap
            TcpRouterConfig::default()
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

        // Initialize connection pool
        self.pool = Some(ConnectionPool::new(router_config.pool.clone()));

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

        info!("TCP Router initialized");
        Ok(())
    }

    fn start(&mut self) -> ModuleResult<()> {
        info!("Starting TCP Router");

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
        self.shutdown_tx = Some(shutdown_tx);

        // Start listeners
        let pool = self.pool.clone().ok_or_else(|| ModuleError::InvalidState {
            current: "No pool".to_string(),
            expected: "Pool initialized".to_string(),
        })?;

        let stats = Arc::clone(&self.stats);
        let health = Arc::clone(&self.health);
        let routes = config.routes.clone();
        let listener_configs = config.listeners.clone();

        // Spawn the listener task
        tokio::spawn(async move {
            for listener_config in listener_configs {
                let mut listener = match Listener::bind(listener_config).await {
                    Ok(l) => l,
                    Err(e) => {
                        error!(error = %e, "Failed to bind listener");
                        continue;
                    },
                };

                let mut events = match listener.start().await {
                    Ok(e) => e,
                    Err(e) => {
                        error!(error = %e, "Failed to start listener");
                        continue;
                    },
                };

                let pool = pool.clone();
                let stats = Arc::clone(&stats);
                let health = Arc::clone(&health);
                let routes = routes.clone();

                tokio::spawn(async move {
                    while let Some(event) = events.recv().await {
                        match event {
                            ListenerEvent::NewConnection(conn) => {
                                let local_addr = conn.local_addr();

                                // Find matching route
                                let route = routes.iter().find(|r| {
                                    r.match_criteria
                                        .port
                                        .map_or(true, |p| p == local_addr.port())
                                        || r.match_criteria.catch_all
                                });

                                if let Some(route) = route {
                                    if let Some(backend) = route.backends.first() {
                                        let route = route.clone();
                                        let backend = backend.clone();
                                        let pool = pool.clone();
                                        let stats = Arc::clone(&stats);
                                        let health = Arc::clone(&health);

                                        tokio::spawn(async move {
                                            TcpRouter::handle_connection(
                                                conn, route, backend, pool, stats, health,
                                            )
                                            .await;
                                        });
                                    } else {
                                        warn!(route = %route.name, "No backends configured");
                                    }
                                } else {
                                    warn!(addr = %local_addr, "No route found for connection");
                                }
                            },
                            ListenerEvent::AcceptError(e) => {
                                error!(error = %e, "Accept error");
                            },
                            ListenerEvent::Stopped => {
                                info!("Listener stopped");
                                break;
                            },
                        }
                    }
                });
            }
        });

        self.started_at = Some(Instant::now());
        self.status = ModuleStatus::Running;

        info!("TCP Router started");
        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        info!("Stopping TCP Router");

        if !matches!(self.status, ModuleStatus::Running) {
            return Err(ModuleError::InvalidState {
                current: self.status.to_string(),
                expected: "Running".to_string(),
            });
        }

        // Stop all listeners
        for listener in &self.listeners {
            listener.stop();
        }

        // Signal shutdown
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.try_send(());
        }

        self.status = ModuleStatus::Stopped;
        info!("TCP Router stopped");
        Ok(())
    }

    fn reload(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        info!("Reloading TCP Router configuration");

        // Parse new configuration from config_json if present
        let new_config: TcpRouterConfig =
            if let Some(config_json) = config.get_string("config_json") {
                serde_json::from_str(config_json)
                    .map_err(|e| ModuleError::ConfigError(format!("Invalid config: {e}")))?
            } else {
                // Can't reload without proper config
                return Err(ModuleError::ConfigError(
                    "No config_json provided for reload".to_string(),
                ));
            };

        // Update pool settings
        if let Some(ref mut pool) = self.pool {
            // For now, we need to recreate the pool
            // A more sophisticated implementation would update in place
            *pool = ConnectionPool::new(new_config.pool.clone());
        }

        self.config = Some(new_config);

        info!("TCP Router configuration reloaded");
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    fn metrics(&self) -> MetricsPayload {
        let mut metrics = MetricsPayload::new();

        metrics.counter(
            "total_connections",
            self.stats.total_connections.load(Ordering::Relaxed),
        );
        metrics.gauge(
            "active_connections",
            self.stats.active_connections.load(Ordering::Relaxed) as f64,
        );
        metrics.counter(
            "bytes_received",
            self.stats.bytes_received.load(Ordering::Relaxed),
        );
        metrics.counter("bytes_sent", self.stats.bytes_sent.load(Ordering::Relaxed));
        metrics.counter(
            "backend_connections",
            self.stats.backend_connections.load(Ordering::Relaxed),
        );
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
        let router = TcpRouter::new();
        assert!(matches!(router.status(), ModuleStatus::Initializing));
    }

    #[test]
    fn test_router_manifest() {
        let router = TcpRouter::new();
        let manifest = router.manifest();

        assert_eq!(manifest.name, "tcp-router");
        assert!(manifest.capabilities.contains(&Capability::TcpListener));
        assert!(manifest.capabilities.contains(&Capability::LoadBalancing));
    }

    #[test]
    fn test_router_init_no_listeners() {
        let mut router = TcpRouter::new();

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
        let mut router = TcpRouter::new();

        let config_json = serde_json::json!({
            "listeners": [{"port": 8080}],
            "routes": []
        });

        let mut config = ModuleConfig::new();
        config.set_string("config_json", config_json.to_string());

        let result = router.init(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_router_init_valid_config() {
        let mut router = TcpRouter::new();

        let config_json = serde_json::json!({
            "listeners": [{"port": 8080}],
            "routes": [{
                "name": "test",
                "match": {"port": 8080},
                "backends": [{"address": "127.0.0.1", "port": 3000}]
            }]
        });

        let mut config = ModuleConfig::new();
        config.set_string("config_json", config_json.to_string());

        let result = router.init(config);
        assert!(result.is_ok());
        assert!(matches!(router.status(), ModuleStatus::Running));
    }

    #[test]
    fn test_router_stats_initial() {
        let router = TcpRouter::new();
        let stats = router.stats();

        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.bytes_received, 0);
    }

    #[test]
    fn test_router_metrics() {
        let router = TcpRouter::new();
        let metrics = router.metrics();

        assert!(metrics.counters.contains_key("total_connections"));
        assert!(metrics.gauges.contains_key("active_connections"));
    }
}
