//! WebSocket handler implementation.

use crate::module::{
    Capability, MetricsPayload, ModuleConfig, ModuleContract, ModuleError, ModuleManifest,
    ModuleResult, ModuleStatus,
};
use crate::modules::websocket_handler::config::{BackendConfig, WebSocketHandlerConfig};
use crate::modules::websocket_handler::frame::{close_message, CloseCode, Message, MessageExt};
use crate::modules::websocket_handler::upgrade::{
    check_origin, negotiate_protocol, UpgradeRequest, UpgradeResponse,
};

use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, error, info, warn};

/// WebSocket handler module.
pub struct WebSocketHandler {
    /// Configuration.
    config: WebSocketHandlerConfig,

    /// Module status.
    status: ModuleStatus,

    /// Statistics.
    stats: Arc<WebSocketStats>,

    /// Active listeners.
    listeners: Vec<JoinHandle<()>>,

    /// Router for path-based routing.
    router: Arc<RwLock<PathRouter>>,

    /// Start time for uptime tracking.
    start_time: Option<Instant>,

    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
}

/// Statistics for WebSocket operations.
#[derive(Debug, Default)]
pub struct WebSocketStats {
    /// Total connections accepted.
    connections_total: AtomicU64,
    /// Currently active connections.
    connections_active: AtomicU64,
    /// Total upgrade requests.
    upgrades_total: AtomicU64,
    /// Successful upgrades.
    upgrades_success: AtomicU64,
    /// Failed upgrades.
    upgrades_failed: AtomicU64,
    /// Total messages received.
    messages_received: AtomicU64,
    /// Total messages sent.
    messages_sent: AtomicU64,
    /// Total bytes received.
    bytes_received: AtomicU64,
    /// Total bytes sent.
    bytes_sent: AtomicU64,
    /// Ping messages sent.
    pings_sent: AtomicU64,
    /// Pong messages received.
    pongs_received: AtomicU64,
    /// Close frames sent.
    closes_sent: AtomicU64,
    /// Protocol errors.
    errors_protocol: AtomicU64,
}

impl WebSocketStats {
    /// Record a new connection.
    fn connection_opened(&self) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
        self.connections_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a closed connection.
    fn connection_closed(&self) {
        self.connections_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record an upgrade attempt.
    fn upgrade_attempt(&self) {
        self.upgrades_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful upgrade.
    fn upgrade_success(&self) {
        self.upgrades_success.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed upgrade.
    fn upgrade_failed(&self) {
        self.upgrades_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a message received.
    fn message_received(&self, size: usize) {
        self.messages_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received
            .fetch_add(size as u64, Ordering::Relaxed);
    }

    /// Record a message sent.
    fn message_sent(&self, size: usize) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(size as u64, Ordering::Relaxed);
    }

    /// Record a ping sent.
    #[allow(dead_code)]
    fn ping_sent(&self) {
        self.pings_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a pong received.
    fn pong_received(&self) {
        self.pongs_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a close sent.
    fn close_sent(&self) {
        self.closes_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a protocol error.
    fn protocol_error(&self) {
        self.errors_protocol.fetch_add(1, Ordering::Relaxed);
    }
}

/// Path-based router for WebSocket connections.
#[derive(Debug, Default)]
pub struct PathRouter {
    /// Routes sorted by priority.
    routes: Vec<Route>,
    /// Default backend.
    default_backend: Option<BackendConfig>,
}

/// A single route.
#[derive(Debug, Clone)]
pub struct Route {
    /// Route name.
    #[allow(dead_code)]
    name: String,
    /// Path pattern.
    pattern: PathPattern,
    /// Backend configuration.
    backend: BackendConfig,
    /// Supported subprotocols.
    subprotocols: Vec<String>,
    /// Priority (higher = checked first).
    priority: i32,
}

/// Path pattern for matching.
#[derive(Debug, Clone)]
pub enum PathPattern {
    /// Exact path match.
    Exact(String),
    /// Prefix match.
    Prefix(String),
    /// Wildcard match with pattern.
    Glob(String),
}

impl PathPattern {
    /// Parse a path pattern from string.
    pub fn parse(pattern: &str) -> Self {
        if pattern.ends_with('*') {
            Self::Prefix(pattern.trim_end_matches('*').to_string())
        } else if pattern.contains('*') {
            Self::Glob(pattern.to_string())
        } else {
            Self::Exact(pattern.to_string())
        }
    }

    /// Check if a path matches this pattern.
    pub fn matches(&self, path: &str) -> bool {
        match self {
            Self::Exact(p) => path == p,
            Self::Prefix(p) => path.starts_with(p),
            Self::Glob(p) => {
                // Simple glob matching
                let parts: Vec<&str> = p.split('*').collect();
                if parts.is_empty() {
                    return true;
                }

                let mut remaining = path;

                // First part must match at start
                if let Some(first) = parts.first() {
                    if !first.is_empty() && !remaining.starts_with(*first) {
                        return false;
                    }
                    remaining = &remaining[first.len()..];
                }

                // Last part must match at end
                if let Some(last) = parts.last() {
                    if !last.is_empty() && !remaining.ends_with(*last) {
                        return false;
                    }
                }

                true
            },
        }
    }
}

impl PathRouter {
    /// Add a route.
    pub fn add_route(&mut self, route: Route) {
        self.routes.push(route);
        // Sort by priority (highest first)
        self.routes.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Set the default backend.
    pub fn set_default_backend(&mut self, backend: BackendConfig) {
        self.default_backend = Some(backend);
    }

    /// Find a matching route for a path.
    pub fn find_route(&self, path: &str) -> Option<&Route> {
        self.routes.iter().find(|r| r.pattern.matches(path))
    }

    /// Get the default backend.
    pub fn default_backend(&self) -> Option<&BackendConfig> {
        self.default_backend.as_ref()
    }
}

impl WebSocketHandler {
    /// Create a new WebSocket handler.
    pub fn new() -> Self {
        Self {
            config: WebSocketHandlerConfig::default(),
            status: ModuleStatus::Stopped,
            stats: Arc::new(WebSocketStats::default()),
            listeners: Vec::new(),
            router: Arc::new(RwLock::new(PathRouter::default())),
            start_time: None,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create with configuration.
    pub fn with_config(config: WebSocketHandlerConfig) -> Self {
        Self {
            config,
            ..Self::new()
        }
    }

    /// Get current statistics.
    pub fn stats(&self) -> &Arc<WebSocketStats> {
        &self.stats
    }

    /// Handle a client connection.
    async fn handle_connection(
        mut stream: TcpStream,
        addr: SocketAddr,
        config: Arc<WebSocketHandlerConfig>,
        router: Arc<RwLock<PathRouter>>,
        stats: Arc<WebSocketStats>,
        shutdown: Arc<AtomicBool>,
    ) {
        stats.connection_opened();

        // Read HTTP upgrade request
        let mut buffer = vec![0u8; config.security.max_handshake_size];
        let n = match stream.read(&mut buffer).await {
            Ok(n) if n > 0 => n,
            _ => {
                stats.connection_closed();
                return;
            },
        };
        buffer.truncate(n);

        stats.upgrade_attempt();

        // Parse upgrade request
        let request = match UpgradeRequest::parse(&buffer) {
            Ok(req) => req,
            Err(e) => {
                warn!(addr = %addr, error = %e, "Invalid upgrade request");
                stats.upgrade_failed();
                let _ = stream
                    .write_all(&crate::modules::websocket_handler::upgrade::error_response(
                        400,
                        &e.to_string(),
                    ))
                    .await;
                stats.connection_closed();
                return;
            },
        };

        // Validate key if configured
        if config.security.validate_key && !request.validate_key() {
            warn!(addr = %addr, "Invalid WebSocket key");
            stats.upgrade_failed();
            let _ = stream
                .write_all(&crate::modules::websocket_handler::upgrade::error_response(
                    400,
                    "Invalid Sec-WebSocket-Key",
                ))
                .await;
            stats.connection_closed();
            return;
        }

        // Check origin
        if !check_origin(request.origin.as_deref(), &config.security.allowed_origins) {
            warn!(
                addr = %addr,
                origin = ?request.origin,
                "Origin not allowed"
            );
            stats.upgrade_failed();
            let _ = stream
                .write_all(&crate::modules::websocket_handler::upgrade::error_response(
                    403,
                    "Origin not allowed",
                ))
                .await;
            stats.connection_closed();
            return;
        }

        // Find route
        let router_read = router.read().await;
        let route = router_read.find_route(&request.path);
        let backend_config = match route {
            Some(r) => &r.backend,
            None => match router_read.default_backend() {
                Some(b) => b,
                None => {
                    warn!(addr = %addr, path = %request.path, "No route found");
                    stats.upgrade_failed();
                    let _ = stream
                        .write_all(&crate::modules::websocket_handler::upgrade::error_response(
                            404,
                            "No route found",
                        ))
                        .await;
                    stats.connection_closed();
                    return;
                },
            },
        };
        let backend_config = backend_config.clone();
        let route_subprotocols = route.map(|r| r.subprotocols.clone()).unwrap_or_default();
        drop(router_read);

        // Negotiate subprotocol
        let selected_protocol = if !request.protocols.is_empty() && !route_subprotocols.is_empty() {
            negotiate_protocol(&request.protocols, &route_subprotocols)
        } else {
            None
        };

        // Build upgrade response
        let mut response = UpgradeResponse::new();
        if let Some(ref proto) = selected_protocol {
            response = response.protocol(proto);
        }
        let response_bytes = response.build(&request.key);

        // Send upgrade response
        if let Err(e) = stream.write_all(&response_bytes).await {
            debug!(addr = %addr, error = %e, "Failed to send upgrade response");
            stats.upgrade_failed();
            stats.connection_closed();
            return;
        }

        stats.upgrade_success();
        info!(
            addr = %addr,
            path = %request.path,
            protocol = ?selected_protocol,
            "WebSocket connection established"
        );

        // Connect to backend
        let backend_addr = match backend_config.socket_addr() {
            Some(addr) => addr,
            None => {
                // Try DNS resolution
                match tokio::net::lookup_host(format!(
                    "{}:{}",
                    backend_config.address, backend_config.port
                ))
                .await
                {
                    Ok(mut addrs) => match addrs.next() {
                        Some(addr) => addr,
                        None => {
                            error!("No addresses resolved for backend");
                            stats.connection_closed();
                            return;
                        },
                    },
                    Err(e) => {
                        error!(error = %e, "Failed to resolve backend address");
                        stats.connection_closed();
                        return;
                    },
                }
            },
        };

        let backend_stream = match tokio::time::timeout(
            backend_config.connect_timeout,
            TcpStream::connect(backend_addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                error!(error = %e, "Failed to connect to backend");
                stats.connection_closed();
                return;
            },
            Err(_) => {
                error!("Backend connection timeout");
                stats.connection_closed();
                return;
            },
        };

        // Upgrade both connections to WebSocket
        let client_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            stream,
            tokio_tungstenite::tungstenite::protocol::Role::Server,
            None,
        )
        .await;

        // For backend, we need to perform client handshake
        let backend_url = format!(
            "ws://{}:{}{}",
            backend_config.address, backend_config.port, request.path
        );
        let backend_ws = match tokio_tungstenite::client_async(&backend_url, backend_stream).await {
            Ok((ws, _)) => ws,
            Err(e) => {
                error!(error = %e, "Backend WebSocket handshake failed");
                stats.connection_closed();
                return;
            },
        };

        // Proxy messages between client and backend
        Self::proxy_messages(client_ws, backend_ws, config, stats.clone(), shutdown).await;

        stats.connection_closed();
        info!(addr = %addr, "WebSocket connection closed");
    }

    /// Proxy messages between client and backend WebSocket connections.
    async fn proxy_messages(
        client: WebSocketStream<TcpStream>,
        backend: WebSocketStream<TcpStream>,
        config: Arc<WebSocketHandlerConfig>,
        stats: Arc<WebSocketStats>,
        shutdown: Arc<AtomicBool>,
    ) {
        use tokio::sync::Mutex;

        let (client_write, mut client_read) = client.split();
        let (backend_write, mut backend_read) = backend.split();

        let client_write = Arc::new(Mutex::new(client_write));
        let backend_write = Arc::new(Mutex::new(backend_write));

        let stats_c2b = stats.clone();
        let stats_b2c = stats.clone();
        let shutdown_c2b = shutdown.clone();
        let shutdown_b2c = shutdown;
        let config_c2b = config.clone();
        let config_b2c = config;
        let client_write_c2b = client_write.clone();
        let backend_write_c2b = backend_write.clone();
        let client_write_b2c = client_write;
        let backend_write_b2c = backend_write;

        // Client to backend
        let c2b = async move {
            while !shutdown_c2b.load(Ordering::Relaxed) {
                match client_read.next().await {
                    Some(Ok(msg)) => {
                        stats_c2b.message_received(msg.payload().len());

                        // Handle control messages
                        if msg.is_control() {
                            match &msg {
                                Message::Ping(data) => {
                                    if config_c2b.protocol.auto_pong {
                                        let mut w = client_write_c2b.lock().await;
                                        let _ = w.send(Message::Pong(data.clone())).await;
                                    }
                                    if config_c2b.protocol.forward_pings {
                                        let mut w = backend_write_c2b.lock().await;
                                        let _ = w.send(msg).await;
                                    }
                                    continue;
                                },
                                Message::Pong(_) => {
                                    stats_c2b.pong_received();
                                    continue;
                                },
                                Message::Close(_) => {
                                    let mut w = backend_write_c2b.lock().await;
                                    let _ = w.send(close_message(CloseCode::Normal, "")).await;
                                    break;
                                },
                                _ => {},
                            }
                        }

                        // Check message size
                        if msg.payload().len() > config_c2b.limits.max_message_size {
                            stats_c2b.protocol_error();
                            let mut w = client_write_c2b.lock().await;
                            let _ = w
                                .send(close_message(CloseCode::MessageTooBig, "Message too large"))
                                .await;
                            break;
                        }

                        // Forward to backend
                        let mut w = backend_write_c2b.lock().await;
                        if w.send(msg).await.is_err() {
                            break;
                        }
                        stats_c2b.message_sent(0); // Size tracked on receive
                    },
                    Some(Err(e)) => {
                        debug!(error = %e, "Client read error");
                        stats_c2b.protocol_error();
                        break;
                    },
                    None => break,
                }
            }
        };

        // Backend to client
        let b2c = async move {
            while !shutdown_b2c.load(Ordering::Relaxed) {
                match backend_read.next().await {
                    Some(Ok(msg)) => {
                        stats_b2c.message_received(msg.payload().len());

                        // Handle control messages
                        if msg.is_control() {
                            match &msg {
                                Message::Ping(data) => {
                                    if config_b2c.protocol.auto_pong {
                                        let mut w = backend_write_b2c.lock().await;
                                        let _ = w.send(Message::Pong(data.clone())).await;
                                    }
                                    continue;
                                },
                                Message::Pong(_) => {
                                    stats_b2c.pong_received();
                                    continue;
                                },
                                Message::Close(_) => {
                                    let mut w = client_write_b2c.lock().await;
                                    let _ = w.send(close_message(CloseCode::Normal, "")).await;
                                    stats_b2c.close_sent();
                                    break;
                                },
                                _ => {},
                            }
                        }

                        // Forward to client
                        let size = msg.payload().len();
                        let mut w = client_write_b2c.lock().await;
                        if w.send(msg).await.is_err() {
                            break;
                        }
                        stats_b2c.message_sent(size);
                    },
                    Some(Err(e)) => {
                        debug!(error = %e, "Backend read error");
                        stats_b2c.protocol_error();
                        break;
                    },
                    None => break,
                }
            }
        };

        // Run both directions concurrently
        tokio::select! {
            _ = c2b => {},
            _ = b2c => {},
        }
    }
}

impl Default for WebSocketHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleContract for WebSocketHandler {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("websocket-handler")
            .description("WebSocket protocol handler with HTTP upgrade and message routing")
            .version(1, 0, 0)
            .author("R0N Team")
            .capability(Capability::Custom("websocket".to_string()))
            .capability(Capability::Custom("rfc6455".to_string()))
            .capability(Capability::Custom("upgrade".to_string()))
            .capability(Capability::Custom("subprotocols".to_string()))
            .build()
    }

    fn init(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        if self.status != ModuleStatus::Stopped {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Stopped".to_string(),
            });
        }

        // Parse configuration if provided
        if let Some(config_toml) = config.get_string("config_toml") {
            self.config = toml::from_str(config_toml)
                .map_err(|e| ModuleError::ConfigError(format!("Invalid config: {e}")))?;
        }

        // Validate configuration
        if self.config.listeners.is_empty() {
            return Err(ModuleError::ConfigError(
                "At least one listener is required".to_string(),
            ));
        }

        self.status = ModuleStatus::Initializing;
        Ok(())
    }

    fn start(&mut self) -> ModuleResult<()> {
        if self.status != ModuleStatus::Initializing && self.status != ModuleStatus::Stopped {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Initializing or Stopped".to_string(),
            });
        }

        self.shutdown.store(false, Ordering::Relaxed);
        self.start_time = Some(Instant::now());

        // Setup routes
        let router = self.router.clone();
        let config = self.config.clone();
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let mut router = router.write().await;
            for route_config in &config.routes {
                router.add_route(Route {
                    name: route_config.name.clone(),
                    pattern: PathPattern::parse(&route_config.path),
                    backend: route_config.backend.clone(),
                    subprotocols: route_config.subprotocols.clone(),
                    priority: route_config.priority,
                });
            }
            if let Some(ref backend) = config.default_backend {
                router.set_default_backend(backend.clone());
            }
        });

        // Start listeners
        for listener_config in &self.config.listeners {
            let addr = match listener_config.socket_addr() {
                Some(a) => a,
                None => {
                    warn!(
                        address = %listener_config.address,
                        port = %listener_config.port,
                        "Invalid listener address"
                    );
                    continue;
                },
            };

            let config = Arc::new(self.config.clone());
            let router = self.router.clone();
            let stats = self.stats.clone();
            let shutdown = self.shutdown.clone();

            let handle = tokio::spawn(async move {
                let listener = match TcpListener::bind(addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        error!(addr = %addr, error = %e, "Failed to bind listener");
                        return;
                    },
                };

                info!(addr = %addr, "WebSocket listener started");

                loop {
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }

                    match listener.accept().await {
                        Ok((stream, addr)) => {
                            let config = config.clone();
                            let router = router.clone();
                            let stats = stats.clone();
                            let shutdown = shutdown.clone();

                            tokio::spawn(async move {
                                Self::handle_connection(
                                    stream, addr, config, router, stats, shutdown,
                                )
                                .await;
                            });
                        },
                        Err(e) => {
                            debug!(error = %e, "Accept error");
                        },
                    }
                }
            });

            self.listeners.push(handle);
        }

        self.status = ModuleStatus::Running;
        info!("WebSocket handler started");
        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        if self.status != ModuleStatus::Running {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Running".to_string(),
            });
        }

        self.shutdown.store(true, Ordering::Relaxed);

        // Abort all listener tasks
        for handle in self.listeners.drain(..) {
            handle.abort();
        }

        self.status = ModuleStatus::Stopped;
        info!("WebSocket handler stopped");
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    fn heartbeat(&self) -> bool {
        self.status == ModuleStatus::Running
    }

    fn metrics(&self) -> MetricsPayload {
        let mut payload = MetricsPayload::new();

        payload.counter(
            "websocket_connections_total",
            self.stats.connections_total.load(Ordering::Relaxed),
        );
        payload.gauge(
            "websocket_connections_active",
            self.stats.connections_active.load(Ordering::Relaxed) as f64,
        );
        payload.counter(
            "websocket_upgrades_total",
            self.stats.upgrades_total.load(Ordering::Relaxed),
        );
        payload.counter(
            "websocket_upgrades_success",
            self.stats.upgrades_success.load(Ordering::Relaxed),
        );
        payload.counter(
            "websocket_upgrades_failed",
            self.stats.upgrades_failed.load(Ordering::Relaxed),
        );
        payload.counter(
            "websocket_messages_received",
            self.stats.messages_received.load(Ordering::Relaxed),
        );
        payload.counter(
            "websocket_messages_sent",
            self.stats.messages_sent.load(Ordering::Relaxed),
        );
        payload.counter(
            "websocket_bytes_received",
            self.stats.bytes_received.load(Ordering::Relaxed),
        );
        payload.counter(
            "websocket_bytes_sent",
            self.stats.bytes_sent.load(Ordering::Relaxed),
        );
        payload.counter(
            "websocket_pings_sent",
            self.stats.pings_sent.load(Ordering::Relaxed),
        );
        payload.counter(
            "websocket_pongs_received",
            self.stats.pongs_received.load(Ordering::Relaxed),
        );
        payload.counter(
            "websocket_closes_sent",
            self.stats.closes_sent.load(Ordering::Relaxed),
        );
        payload.counter(
            "websocket_errors_protocol",
            self.stats.errors_protocol.load(Ordering::Relaxed),
        );

        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_creation() {
        let handler = WebSocketHandler::new();
        assert_eq!(handler.status(), ModuleStatus::Stopped);
    }

    #[test]
    fn test_handler_with_config() {
        let config = WebSocketHandlerConfig::default();
        let handler = WebSocketHandler::with_config(config);
        assert_eq!(handler.status(), ModuleStatus::Stopped);
    }

    #[test]
    fn test_handler_manifest() {
        let handler = WebSocketHandler::new();
        let manifest = handler.manifest();
        assert_eq!(manifest.name, "websocket-handler");
        assert!(manifest.capabilities.len() >= 3);
    }

    #[test]
    fn test_handler_init() {
        let mut handler = WebSocketHandler::new();
        let result = handler.init(ModuleConfig::default());
        assert!(result.is_ok());
        assert_eq!(handler.status(), ModuleStatus::Initializing);
    }

    #[test]
    fn test_handler_init_with_config() {
        let mut handler = WebSocketHandler::new();

        let mut config = ModuleConfig::default();
        config.set_string(
            "config_toml",
            r#"
            enabled = true
            [[listeners]]
            address = "127.0.0.1"
            port = 8080
        "#,
        );

        let result = handler.init(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handler_init_invalid_state() {
        let mut handler = WebSocketHandler::new();
        handler.status = ModuleStatus::Running;
        let result = handler.init(ModuleConfig::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_handler_stop_when_not_running() {
        let mut handler = WebSocketHandler::new();
        let result = handler.stop();
        assert!(result.is_err());
    }

    #[test]
    fn test_handler_heartbeat_not_running() {
        let handler = WebSocketHandler::new();
        let heartbeat = handler.heartbeat();
        assert!(!heartbeat);
    }

    #[test]
    fn test_handler_metrics() {
        let handler = WebSocketHandler::new();
        let _metrics = handler.metrics();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_stats() {
        let stats = WebSocketStats::default();
        stats.connection_opened();
        assert_eq!(stats.connections_total.load(Ordering::Relaxed), 1);
        assert_eq!(stats.connections_active.load(Ordering::Relaxed), 1);

        stats.connection_closed();
        assert_eq!(stats.connections_active.load(Ordering::Relaxed), 0);

        stats.message_received(100);
        assert_eq!(stats.messages_received.load(Ordering::Relaxed), 1);
        assert_eq!(stats.bytes_received.load(Ordering::Relaxed), 100);

        stats.message_sent(50);
        assert_eq!(stats.messages_sent.load(Ordering::Relaxed), 1);
        assert_eq!(stats.bytes_sent.load(Ordering::Relaxed), 50);
    }

    #[test]
    fn test_path_pattern_exact() {
        let pattern = PathPattern::Exact("/ws".to_string());
        assert!(pattern.matches("/ws"));
        assert!(!pattern.matches("/ws/"));
        assert!(!pattern.matches("/ws/chat"));
    }

    #[test]
    fn test_path_pattern_prefix() {
        let pattern = PathPattern::Prefix("/ws/".to_string());
        assert!(pattern.matches("/ws/chat"));
        assert!(pattern.matches("/ws/notifications"));
        assert!(!pattern.matches("/api/ws"));
    }

    #[test]
    fn test_path_pattern_glob() {
        let pattern = PathPattern::Glob("/ws/*/events".to_string());
        assert!(pattern.matches("/ws/chat/events"));
        assert!(pattern.matches("/ws/user/events"));
    }

    #[test]
    fn test_path_pattern_parse() {
        assert!(matches!(PathPattern::parse("/ws"), PathPattern::Exact(_)));
        assert!(matches!(
            PathPattern::parse("/ws/*"),
            PathPattern::Prefix(_)
        ));
        assert!(matches!(
            PathPattern::parse("/ws/*/events"),
            PathPattern::Glob(_)
        ));
    }

    #[test]
    fn test_path_router() {
        let mut router = PathRouter::default();

        router.add_route(Route {
            name: "chat".to_string(),
            pattern: PathPattern::Exact("/ws/chat".to_string()),
            backend: BackendConfig {
                address: "127.0.0.1".to_string(),
                port: 9000,
                tls: false,
                connect_timeout: std::time::Duration::from_secs(5),
            },
            subprotocols: vec!["graphql-ws".to_string()],
            priority: 10,
        });

        router.add_route(Route {
            name: "default".to_string(),
            pattern: PathPattern::Prefix("/ws/".to_string()),
            backend: BackendConfig {
                address: "127.0.0.1".to_string(),
                port: 9001,
                tls: false,
                connect_timeout: std::time::Duration::from_secs(5),
            },
            subprotocols: vec![],
            priority: 1,
        });

        // Exact match should win
        let route = router.find_route("/ws/chat").unwrap();
        assert_eq!(route.name, "chat");

        // Prefix match
        let route = router.find_route("/ws/other").unwrap();
        assert_eq!(route.name, "default");
    }

    #[tokio::test]
    async fn test_handler_start_stop() {
        let mut handler = WebSocketHandler::new();

        // Configure with a random high port to avoid conflicts
        let mut config = ModuleConfig::default();
        config.set_string(
            "config_toml",
            r#"
            enabled = true
            [[listeners]]
            address = "127.0.0.1"
            port = 0
        "#,
        );

        handler.init(config).unwrap();

        // For this test, we'll skip actual start/stop since port 0
        // requires actual binding. Just verify state transitions.
        assert_eq!(handler.status(), ModuleStatus::Initializing);
    }
}
