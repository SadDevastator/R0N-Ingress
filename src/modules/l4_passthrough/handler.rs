//! L4 Passthrough handler implementing ModuleContract.

use crate::module::{
    Capability, MetricsPayload, ModuleConfig, ModuleContract, ModuleError, ModuleManifest,
    ModuleResult, ModuleStatus,
};
use crate::modules::l4_passthrough::config::{
    BackendConfig, L4PassthroughConfig, ListenerConfig, LoadBalanceStrategy, Protocol,
};
use crate::modules::l4_passthrough::connection::{ConnectionState, ConnectionStats};
use crate::modules::l4_passthrough::error::L4Error;
use crate::modules::l4_passthrough::tracker::ConnectionTracker;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn};

/// L4 Passthrough handler.
pub struct L4PassthroughHandler {
    /// Configuration.
    config: RwLock<L4PassthroughConfig>,

    /// Current status.
    status: RwLock<ModuleStatus>,

    /// Backend selectors by name.
    backends: Arc<std::sync::RwLock<HashMap<String, BackendSelector>>>,

    /// Connection tracker.
    tracker: Arc<ConnectionTracker>,

    /// Connection stats.
    stats: Arc<ConnectionStats>,

    /// Shutdown signal.
    shutdown: RwLock<Option<tokio::sync::broadcast::Sender<()>>>,
}

/// Backend selector with load balancing.
#[derive(Debug)]
struct BackendSelector {
    /// Backend configuration.
    #[allow(dead_code)]
    config: BackendConfig,

    /// Parsed addresses.
    addresses: Vec<SocketAddr>,

    /// Health status per address.
    healthy: Vec<bool>,

    /// Round-robin counter.
    rr_counter: AtomicUsize,

    /// Connection count per backend.
    connections: Vec<AtomicUsize>,

    /// Load balance strategy.
    strategy: LoadBalanceStrategy,
}

impl BackendSelector {
    /// Create a new backend selector.
    fn new(config: BackendConfig) -> Result<Self, L4Error> {
        let mut addresses = Vec::new();

        for addr_str in &config.addresses {
            let addr: SocketAddr = addr_str.parse().map_err(|e| {
                L4Error::InvalidConfig(format!("Invalid address '{}': {}", addr_str, e))
            })?;
            addresses.push(addr);
        }

        if addresses.is_empty() {
            return Err(L4Error::InvalidConfig(format!(
                "Backend '{}' has no addresses",
                config.name
            )));
        }

        let healthy = vec![true; addresses.len()];
        let connections = (0..addresses.len()).map(|_| AtomicUsize::new(0)).collect();

        Ok(Self {
            strategy: config.load_balance,
            config,
            addresses,
            healthy,
            rr_counter: AtomicUsize::new(0),
            connections,
        })
    }

    /// Select a backend address.
    fn select(&self, client_ip: Option<std::net::IpAddr>) -> Option<SocketAddr> {
        let healthy_indices: Vec<usize> = self
            .healthy
            .iter()
            .enumerate()
            .filter_map(|(i, h)| if *h { Some(i) } else { None })
            .collect();

        if healthy_indices.is_empty() {
            return None;
        }

        let idx = match self.strategy {
            LoadBalanceStrategy::RoundRobin => {
                let counter = self.rr_counter.fetch_add(1, Ordering::Relaxed);
                healthy_indices[counter % healthy_indices.len()]
            },
            LoadBalanceStrategy::LeastConnections => *healthy_indices
                .iter()
                .min_by_key(|&&i| self.connections[i].load(Ordering::Relaxed))
                .unwrap(),
            LoadBalanceStrategy::Random => {
                use std::time::{SystemTime, UNIX_EPOCH};
                let seed = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0) as usize;
                healthy_indices[seed % healthy_indices.len()]
            },
            LoadBalanceStrategy::IpHash => {
                if let Some(ip) = client_ip {
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    ip.hash(&mut hasher);
                    let hash = hasher.finish() as usize;
                    healthy_indices[hash % healthy_indices.len()]
                } else {
                    healthy_indices[0]
                }
            },
        };

        Some(self.addresses[idx])
    }

    /// Increment connection count for a backend.
    fn inc_connection(&self, addr: SocketAddr) {
        if let Some(idx) = self.addresses.iter().position(|&a| a == addr) {
            self.connections[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Decrement connection count for a backend.
    fn dec_connection(&self, addr: SocketAddr) {
        if let Some(idx) = self.addresses.iter().position(|&a| a == addr) {
            self.connections[idx].fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Mark a backend as unhealthy.
    #[allow(dead_code)]
    fn mark_unhealthy(&mut self, addr: SocketAddr) {
        if let Some(idx) = self.addresses.iter().position(|&a| a == addr) {
            self.healthy[idx] = false;
        }
    }

    /// Mark a backend as healthy.
    #[allow(dead_code)]
    fn mark_healthy(&mut self, addr: SocketAddr) {
        if let Some(idx) = self.addresses.iter().position(|&a| a == addr) {
            self.healthy[idx] = true;
        }
    }
}

impl Default for L4PassthroughHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl L4PassthroughHandler {
    /// Create a new L4 passthrough handler.
    pub fn new() -> Self {
        Self {
            config: RwLock::new(L4PassthroughConfig::default()),
            status: RwLock::new(ModuleStatus::Stopped),
            backends: Arc::new(std::sync::RwLock::new(HashMap::new())),
            tracker: Arc::new(ConnectionTracker::new()),
            stats: Arc::new(ConnectionStats::new()),
            shutdown: RwLock::new(None),
        }
    }

    /// Handle a TCP listener.
    async fn run_tcp_listener(
        listener_config: ListenerConfig,
        backend_name: String,
        backends: Arc<std::sync::RwLock<HashMap<String, BackendSelector>>>,
        tracker: Arc<ConnectionTracker>,
        stats: Arc<ConnectionStats>,
        buffer_size: usize,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) {
        let listener = match TcpListener::bind(&listener_config.bind).await {
            Ok(l) => l,
            Err(e) => {
                error!(
                    "Failed to bind TCP listener {}: {}",
                    listener_config.bind, e
                );
                return;
            },
        };

        info!(
            "TCP listener started on {} -> backend '{}'",
            listener_config.bind, backend_name
        );

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((client_stream, client_addr)) => {
                            let backend_name = backend_name.clone();
                            let backends = backends.clone();
                            let tracker = tracker.clone();
                            let stats = stats.clone();
                            let listener_name = listener_config.name.clone()
                                .unwrap_or_else(|| listener_config.bind.clone());
                            let connect_timeout = listener_config.connect_timeout;
                            let idle_timeout = listener_config.idle_timeout;

                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_tcp_connection(
                                    client_stream,
                                    client_addr,
                                    backend_name,
                                    backends,
                                    tracker,
                                    stats,
                                    listener_name,
                                    connect_timeout,
                                    idle_timeout,
                                    buffer_size,
                                ).await {
                                    debug!("TCP connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept TCP connection: {}", e);
                        }
                    }
                }
                _ = shutdown.recv() => {
                    info!("TCP listener {} shutting down", listener_config.bind);
                    break;
                }
            }
        }
    }

    /// Handle a single TCP connection.
    async fn handle_tcp_connection(
        mut client_stream: TcpStream,
        client_addr: SocketAddr,
        backend_name: String,
        backends: Arc<std::sync::RwLock<HashMap<String, BackendSelector>>>,
        tracker: Arc<ConnectionTracker>,
        stats: Arc<ConnectionStats>,
        listener_name: String,
        connect_timeout: Duration,
        idle_timeout: Duration,
        buffer_size: usize,
    ) -> Result<(), L4Error> {
        // Select backend
        let backend_addr = {
            let backends = backends.read().unwrap();
            let selector = backends
                .get(&backend_name)
                .ok_or_else(|| L4Error::NoBackend(backend_name.clone()))?;
            selector
                .select(Some(client_addr.ip()))
                .ok_or_else(|| L4Error::NoBackend(backend_name.clone()))?
        };

        // Connect to backend
        let mut backend_stream =
            match timeout(connect_timeout, TcpStream::connect(backend_addr)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    stats.backend_failure();
                    return Err(L4Error::BackendConnection(format!(
                        "Failed to connect to {}: {}",
                        backend_addr, e
                    )));
                },
                Err(_) => {
                    stats.backend_failure();
                    return Err(L4Error::Timeout(format!(
                        "Connection to {} timed out",
                        backend_addr
                    )));
                },
            };

        // Track connection
        let conn_id = tracker.track_connection(client_addr, backend_addr, listener_name);
        tracker.update_state(conn_id, ConnectionState::Active);
        stats.connection_accepted();

        // Increment backend connection count
        {
            let backends = backends.read().unwrap();
            if let Some(selector) = backends.get(&backend_name) {
                selector.inc_connection(backend_addr);
            }
        }

        debug!(
            "TCP connection {} established: {} -> {}",
            conn_id, client_addr, backend_addr
        );

        // Bidirectional copy
        let mut client_buf = vec![0u8; buffer_size];
        let mut backend_buf = vec![0u8; buffer_size];

        let result = loop {
            tokio::select! {
                // Client -> Backend
                result = timeout(idle_timeout, client_stream.read(&mut client_buf)) => {
                    match result {
                        Ok(Ok(0)) => break Ok(()), // Client closed
                        Ok(Ok(n)) => {
                            if let Err(e) = backend_stream.write_all(&client_buf[..n]).await {
                                break Err(L4Error::Io(e));
                            }
                            stats.bytes_received(n as u64);
                            tracker.update_bytes(conn_id, 0, n as u64);
                        }
                        Ok(Err(e)) => break Err(L4Error::Io(e)),
                        Err(_) => break Err(L4Error::Timeout("Idle timeout".to_string())),
                    }
                }
                // Backend -> Client
                result = timeout(idle_timeout, backend_stream.read(&mut backend_buf)) => {
                    match result {
                        Ok(Ok(0)) => break Ok(()), // Backend closed
                        Ok(Ok(n)) => {
                            if let Err(e) = client_stream.write_all(&backend_buf[..n]).await {
                                break Err(L4Error::Io(e));
                            }
                            stats.bytes_sent(n as u64);
                            tracker.update_bytes(conn_id, n as u64, 0);
                        }
                        Ok(Err(e)) => break Err(L4Error::Io(e)),
                        Err(_) => break Err(L4Error::Timeout("Idle timeout".to_string())),
                    }
                }
            }
        };

        // Cleanup
        tracker.update_state(conn_id, ConnectionState::Closed);
        tracker.remove_connection(conn_id);
        stats.connection_closed();

        {
            let backends = backends.read().unwrap();
            if let Some(selector) = backends.get(&backend_name) {
                selector.dec_connection(backend_addr);
            }
        }

        debug!("TCP connection {} closed", conn_id);
        result
    }

    /// Handle a UDP listener.
    async fn run_udp_listener(
        listener_config: ListenerConfig,
        backend_name: String,
        backends: Arc<std::sync::RwLock<HashMap<String, BackendSelector>>>,
        tracker: Arc<ConnectionTracker>,
        stats: Arc<ConnectionStats>,
        buffer_size: usize,
        session_timeout: Duration,
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) {
        let socket = match UdpSocket::bind(&listener_config.bind).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                error!(
                    "Failed to bind UDP listener {}: {}",
                    listener_config.bind, e
                );
                return;
            },
        };

        info!(
            "UDP listener started on {} -> backend '{}'",
            listener_config.bind, backend_name
        );

        let listener_name = listener_config
            .name
            .clone()
            .unwrap_or_else(|| listener_config.bind.clone());

        let mut buf = vec![0u8; buffer_size];

        // Backend sockets per client (for receiving responses)
        let backend_sockets: Arc<RwLock<HashMap<SocketAddr, Arc<UdpSocket>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        loop {
            tokio::select! {
                recv_result = socket.recv_from(&mut buf) => {
                    match recv_result {
                        Ok((len, client_addr)) => {
                            let data = buf[..len].to_vec();
                            let backend_name = backend_name.clone();
                            let backends = backends.clone();
                            let tracker = tracker.clone();
                            let stats = stats.clone();
                            let socket = socket.clone();
                            let backend_sockets = backend_sockets.clone();
                            let listener_name = listener_name.clone();

                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_udp_packet(
                                    data,
                                    client_addr,
                                    backend_name,
                                    backends,
                                    tracker,
                                    stats,
                                    socket,
                                    backend_sockets,
                                    listener_name,
                                    session_timeout,
                                ).await {
                                    debug!("UDP packet error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Failed to receive UDP packet: {}", e);
                        }
                    }
                }
                _ = shutdown.recv() => {
                    info!("UDP listener {} shutting down", listener_config.bind);
                    break;
                }
            }
        }
    }

    /// Handle a single UDP packet.
    async fn handle_udp_packet(
        data: Vec<u8>,
        client_addr: SocketAddr,
        backend_name: String,
        backends: Arc<std::sync::RwLock<HashMap<String, BackendSelector>>>,
        tracker: Arc<ConnectionTracker>,
        stats: Arc<ConnectionStats>,
        client_socket: Arc<UdpSocket>,
        backend_sockets: Arc<RwLock<HashMap<SocketAddr, Arc<UdpSocket>>>>,
        listener_name: String,
        session_timeout: Duration,
    ) -> Result<(), L4Error> {
        stats.bytes_received(data.len() as u64);

        // Check for existing session
        let backend_addr = if let Some(addr) = tracker.get_udp_session(client_addr, &listener_name)
        {
            tracker.touch_udp_session(client_addr, &listener_name);
            addr
        } else {
            // Select backend
            let addr = {
                let backends = backends.read().unwrap();
                let selector = backends
                    .get(&backend_name)
                    .ok_or_else(|| L4Error::NoBackend(backend_name.clone()))?;
                selector
                    .select(Some(client_addr.ip()))
                    .ok_or_else(|| L4Error::NoBackend(backend_name.clone()))?
            };

            // Create session
            tracker.get_or_create_udp_session(client_addr, addr, listener_name.clone());
            stats.connection_accepted();
            addr
        };

        // Get or create backend socket for this client
        let backend_socket = {
            let sockets = backend_sockets.read().await;
            sockets.get(&client_addr).cloned()
        };

        let backend_socket = match backend_socket {
            Some(s) => s,
            None => {
                // Create new socket for this client
                let socket = UdpSocket::bind("0.0.0.0:0").await?;
                let socket = Arc::new(socket);

                // Spawn response handler
                let client_socket = client_socket.clone();
                let response_socket = socket.clone();
                let tracker = tracker.clone();
                let stats = stats.clone();
                let listener_name = listener_name.clone();

                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65535];
                    loop {
                        match timeout(session_timeout, response_socket.recv_from(&mut buf)).await {
                            Ok(Ok((len, _from))) => {
                                // Forward response to client
                                if let Err(e) =
                                    client_socket.send_to(&buf[..len], client_addr).await
                                {
                                    warn!("Failed to send UDP response to {}: {}", client_addr, e);
                                    break;
                                }
                                stats.bytes_sent(len as u64);
                                tracker.update_udp_session_stats(
                                    client_addr,
                                    &listener_name,
                                    1,
                                    0,
                                    len as u64,
                                    0,
                                );
                            },
                            Ok(Err(e)) => {
                                debug!("UDP backend socket error: {}", e);
                                break;
                            },
                            Err(_) => {
                                // Session timeout
                                debug!("UDP session {} timed out", client_addr);
                                break;
                            },
                        }
                    }
                });

                let mut sockets = backend_sockets.write().await;
                sockets.insert(client_addr, socket.clone());
                socket
            },
        };

        // Send to backend
        backend_socket.send_to(&data, backend_addr).await?;
        tracker.update_udp_session_stats(client_addr, &listener_name, 0, 1, 0, data.len() as u64);

        Ok(())
    }
}

impl ModuleContract for L4PassthroughHandler {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("l4_passthrough")
            .description("Generic Layer 4 TCP/UDP passthrough")
            .version(1, 0, 0)
            .author("R0N Team")
            .capability(Capability::TcpListener)
            .capability(Capability::UdpListener)
            .capability(Capability::LoadBalancing)
            .build()
    }

    fn init(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        // Use blocking lock for sync context
        {
            let mut status = self.status.blocking_write();
            *status = ModuleStatus::Initializing;
        }

        // Parse configuration
        let mut l4_config = L4PassthroughConfig::default();

        if let Some(name) = config.get_string("name") {
            l4_config.name = name.to_string();
        }

        // Parse listeners from config
        if let Some(listeners_json) = config.get_string("listeners") {
            match serde_json::from_str::<Vec<ListenerConfig>>(listeners_json) {
                Ok(listeners) => l4_config.listeners = listeners,
                Err(e) => {
                    return Err(ModuleError::ConfigError(format!(
                        "Failed to parse listeners: {}",
                        e
                    )));
                },
            }
        }

        // Parse backends from config
        if let Some(backends_json) = config.get_string("backends") {
            match serde_json::from_str::<Vec<BackendConfig>>(backends_json) {
                Ok(backends) => l4_config.backends = backends,
                Err(e) => {
                    return Err(ModuleError::ConfigError(format!(
                        "Failed to parse backends: {}",
                        e
                    )));
                },
            }
        }

        // Initialize backend selectors
        let mut selectors = HashMap::new();
        for backend_config in &l4_config.backends {
            match BackendSelector::new(backend_config.clone()) {
                Ok(selector) => {
                    selectors.insert(backend_config.name.clone(), selector);
                },
                Err(e) => {
                    return Err(ModuleError::ConfigError(format!(
                        "Failed to create backend '{}': {}",
                        backend_config.name, e
                    )));
                },
            }
        }

        // Validate listeners reference valid backends
        for listener in &l4_config.listeners {
            if !selectors.contains_key(&listener.backend) {
                return Err(ModuleError::ConfigError(format!(
                    "Listener '{}' references unknown backend '{}'",
                    listener.bind, listener.backend
                )));
            }
        }

        {
            let mut backends = self.backends.write().unwrap();
            *backends = selectors;
        }
        {
            let mut cfg = self.config.blocking_write();
            *cfg = l4_config;
        }

        info!("L4 passthrough module initialized");
        Ok(())
    }

    fn start(&mut self) -> ModuleResult<()> {
        let current_status = self.status.blocking_read().clone();
        if current_status == ModuleStatus::Running {
            return Err(ModuleError::InvalidState {
                current: "Running".to_string(),
                expected: "Stopped or Initializing".to_string(),
            });
        }

        // Check we have a runtime
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(ModuleError::ConfigError(
                "No tokio runtime available".to_string(),
            ));
        }

        let config = self.config.blocking_read().clone();

        // Create shutdown channel
        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
        {
            let mut shutdown = self.shutdown.blocking_write();
            *shutdown = Some(shutdown_tx.clone());
        }

        let backends = self.backends.clone();

        // Start listeners
        for listener_config in config.listeners {
            let backend_name = listener_config.backend.clone();
            let tracker = self.tracker.clone();
            let stats = self.stats.clone();
            let shutdown_rx = shutdown_tx.subscribe();
            let backends = backends.clone();

            match listener_config.protocol {
                Protocol::Tcp => {
                    tokio::spawn(Self::run_tcp_listener(
                        listener_config,
                        backend_name,
                        backends,
                        tracker,
                        stats,
                        config.limits.buffer_size,
                        shutdown_rx,
                    ));
                },
                Protocol::Udp => {
                    tokio::spawn(Self::run_udp_listener(
                        listener_config,
                        backend_name,
                        backends,
                        tracker,
                        stats,
                        config.limits.udp_buffer_size,
                        config.tracking.udp_session_timeout,
                        shutdown_rx,
                    ));
                },
            }
        }

        // Start cleanup task
        let tracker = self.tracker.clone();
        let cleanup_interval = config.tracking.cleanup_interval;
        let udp_timeout = config.tracking.udp_session_timeout;
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let removed = tracker.cleanup_expired_udp_sessions(udp_timeout);
                        if removed > 0 {
                            debug!("Cleaned up {} expired UDP sessions", removed);
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        {
            let mut status = self.status.blocking_write();
            *status = ModuleStatus::Running;
        }
        info!("L4 passthrough module started");
        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        // Send shutdown signal
        {
            let mut shutdown = self.shutdown.blocking_write();
            if let Some(shutdown_tx) = shutdown.take() {
                let _ = shutdown_tx.send(());
            }
        }

        {
            let mut status = self.status.blocking_write();
            *status = ModuleStatus::Stopped;
        }
        info!("L4 passthrough module stopped");
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.blocking_read().clone()
    }

    fn metrics(&self) -> MetricsPayload {
        let mut payload = MetricsPayload::new();

        // Connection metrics
        payload.counter("connections_total", self.stats.total_connections());
        payload.gauge("connections_active", self.stats.active_connections() as f64);
        payload.counter("bytes_received_total", self.stats.total_bytes_received());
        payload.counter("bytes_sent_total", self.stats.total_bytes_sent());
        payload.counter(
            "connection_errors_total",
            self.stats.connection_errors.load(Ordering::Relaxed),
        );
        payload.counter(
            "backend_failures_total",
            self.stats.backend_failures.load(Ordering::Relaxed),
        );

        // Tracking metrics
        payload.gauge(
            "tracked_tcp_connections",
            self.tracker.active_connections() as f64,
        );
        payload.gauge(
            "tracked_udp_sessions",
            self.tracker.active_udp_sessions() as f64,
        );

        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_new() {
        let handler = L4PassthroughHandler::new();
        assert_eq!(handler.status(), ModuleStatus::Stopped);
    }

    #[test]
    fn test_handler_manifest() {
        let handler = L4PassthroughHandler::new();
        let manifest = handler.manifest();

        assert_eq!(manifest.name, "l4_passthrough");
        assert!(manifest.capabilities.contains(&Capability::TcpListener));
        assert!(manifest.capabilities.contains(&Capability::UdpListener));
    }

    #[test]
    fn test_handler_init() {
        let mut handler = L4PassthroughHandler::new();
        let mut config = ModuleConfig::new();
        config.set_string("name", "test-l4");

        handler.init(config).unwrap();

        let config = handler.config.blocking_read();
        assert_eq!(config.name, "test-l4");
    }

    #[test]
    fn test_handler_init_with_backends() {
        let mut handler = L4PassthroughHandler::new();
        let mut config = ModuleConfig::new();

        let backends_json = r#"[
            {
                "name": "mysql",
                "addresses": ["127.0.0.1:3306"],
                "load_balance": "round_robin",
                "pool_size": 10
            }
        ]"#;
        config.set_string("backends", backends_json);

        handler.init(config).unwrap();

        let backends = handler.backends.read().unwrap();
        assert!(backends.contains_key("mysql"));
    }

    #[test]
    fn test_handler_init_invalid_backend() {
        let mut handler = L4PassthroughHandler::new();
        let mut config = ModuleConfig::new();

        let backends_json = r#"[
            {
                "name": "mysql",
                "addresses": [],
                "load_balance": "round_robin",
                "pool_size": 10
            }
        ]"#;
        config.set_string("backends", backends_json);

        let result = handler.init(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_handler_lifecycle() {
        // This test requires a tokio runtime for start()
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let mut handler = L4PassthroughHandler::new();
        let config = ModuleConfig::new();

        handler.init(config).unwrap();

        // Use spawn_blocking to call start which contains blocking ops
        rt.block_on(async {
            tokio::task::spawn_blocking(move || {
                handler.start().unwrap();
                assert_eq!(handler.status(), ModuleStatus::Running);
                handler.stop().unwrap();
                assert_eq!(handler.status(), ModuleStatus::Stopped);
            })
            .await
            .unwrap();
        });
    }

    #[test]
    fn test_handler_heartbeat() {
        // This test requires a tokio runtime for start()
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let mut handler = L4PassthroughHandler::new();
        let config = ModuleConfig::new();

        handler.init(config).unwrap();
        assert!(!handler.heartbeat());

        rt.block_on(async {
            tokio::task::spawn_blocking(move || {
                handler.start().unwrap();
                assert!(handler.heartbeat());
                handler.stop().unwrap();
                assert!(!handler.heartbeat());
            })
            .await
            .unwrap();
        });
    }

    #[test]
    fn test_handler_metrics() {
        let handler = L4PassthroughHandler::new();
        let metrics = handler.metrics();

        assert!(metrics.counters.contains_key("connections_total"));
        assert!(metrics.gauges.contains_key("connections_active"));
    }

    #[test]
    fn test_backend_selector_round_robin() {
        let config = BackendConfig {
            name: "test".to_string(),
            addresses: vec![
                "127.0.0.1:3306".to_string(),
                "127.0.0.1:3307".to_string(),
                "127.0.0.1:3308".to_string(),
            ],
            load_balance: LoadBalanceStrategy::RoundRobin,
            health_check: None,
            pool_size: 10,
        };

        let selector = BackendSelector::new(config).unwrap();

        let a1 = selector.select(None).unwrap();
        let a2 = selector.select(None).unwrap();
        let a3 = selector.select(None).unwrap();
        let a4 = selector.select(None).unwrap();

        // Should cycle through addresses
        assert_ne!(a1, a2);
        assert_ne!(a2, a3);
        assert_eq!(a1, a4); // Wraps around
    }

    #[test]
    fn test_backend_selector_ip_hash() {
        let config = BackendConfig {
            name: "test".to_string(),
            addresses: vec!["127.0.0.1:3306".to_string(), "127.0.0.1:3307".to_string()],
            load_balance: LoadBalanceStrategy::IpHash,
            health_check: None,
            pool_size: 10,
        };

        let selector = BackendSelector::new(config).unwrap();
        let ip = "192.168.1.100".parse().unwrap();

        // Same IP should always get same backend
        let a1 = selector.select(Some(ip)).unwrap();
        let a2 = selector.select(Some(ip)).unwrap();
        let a3 = selector.select(Some(ip)).unwrap();

        assert_eq!(a1, a2);
        assert_eq!(a2, a3);
    }

    #[test]
    fn test_backend_selector_connection_tracking() {
        let config = BackendConfig {
            name: "test".to_string(),
            addresses: vec!["127.0.0.1:3306".to_string()],
            load_balance: LoadBalanceStrategy::LeastConnections,
            health_check: None,
            pool_size: 10,
        };

        let selector = BackendSelector::new(config).unwrap();
        let addr: SocketAddr = "127.0.0.1:3306".parse().unwrap();

        assert_eq!(selector.connections[0].load(Ordering::Relaxed), 0);

        selector.inc_connection(addr);
        assert_eq!(selector.connections[0].load(Ordering::Relaxed), 1);

        selector.dec_connection(addr);
        assert_eq!(selector.connections[0].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_stats() {
        let stats = ConnectionStats::new();

        stats.connection_accepted();
        stats.connection_accepted();
        assert_eq!(stats.active_connections(), 2);
        assert_eq!(stats.total_connections(), 2);

        stats.connection_closed();
        assert_eq!(stats.active_connections(), 1);

        stats.bytes_received(1000);
        stats.bytes_sent(500);
        assert_eq!(stats.total_bytes_received(), 1000);
        assert_eq!(stats.total_bytes_sent(), 500);
    }
}
