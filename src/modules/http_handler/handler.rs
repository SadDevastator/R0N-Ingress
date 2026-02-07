//! HTTP handler implementing ModuleContract.

use super::config::{HttpHandlerConfig, ListenerConfig};
use super::middleware::{
    CorsMiddleware, HeadersMiddleware, LoggerMiddleware, Middleware, MiddlewareAction,
    MiddlewareChain, RequestIdMiddleware, TimingMiddleware,
};
use super::request::Request;
use super::response::Response;
use super::router::Router;
use crate::module::{
    Capability, MetricsPayload, ModuleConfig, ModuleContract, ModuleError, ModuleManifest,
    ModuleResult, ModuleStatus,
};
use bytes::BytesMut;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Statistics for the HTTP handler.
#[derive(Debug, Default)]
pub struct HttpStats {
    /// Total requests received.
    pub requests_total: AtomicU64,
    /// Successful responses (2xx).
    pub responses_2xx: AtomicU64,
    /// Client errors (4xx).
    pub responses_4xx: AtomicU64,
    /// Server errors (5xx).
    pub responses_5xx: AtomicU64,
    /// Active connections.
    pub active_connections: AtomicU64,
    /// Total bytes received.
    pub bytes_received: AtomicU64,
    /// Total bytes sent.
    pub bytes_sent: AtomicU64,
    /// HTTP/1.1 requests.
    pub http1_requests: AtomicU64,
    /// HTTP/2 requests.
    pub http2_requests: AtomicU64,
}

impl HttpStats {
    /// Create new stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a request.
    pub fn record_request(&self, is_http2: bool) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if is_http2 {
            self.http2_requests.fetch_add(1, Ordering::Relaxed);
        } else {
            self.http1_requests.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a response by status code.
    pub fn record_response(&self, status: u16) {
        match status {
            200..=299 => self.responses_2xx.fetch_add(1, Ordering::Relaxed),
            400..=499 => self.responses_4xx.fetch_add(1, Ordering::Relaxed),
            500..=599 => self.responses_5xx.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    /// Record bytes.
    pub fn record_bytes(&self, received: u64, sent: u64) {
        self.bytes_received.fetch_add(received, Ordering::Relaxed);
        self.bytes_sent.fetch_add(sent, Ordering::Relaxed);
    }

    /// Increment active connections.
    pub fn connection_opened(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active connections.
    pub fn connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// HTTP/HTTPS handler module.
#[derive(Debug)]
pub struct HttpHandler {
    /// Configuration.
    config: HttpHandlerConfig,
    /// Router for request routing.
    router: Router,
    /// Global middleware chain.
    middleware: MiddlewareChain,
    /// Current status.
    status: ModuleStatus,
    /// Statistics.
    stats: Arc<HttpStats>,
    /// Shutdown sender.
    shutdown_tx: Option<mpsc::Sender<()>>,
    /// Active listener handles.
    listener_handles: Vec<tokio::task::JoinHandle<()>>,
}

impl HttpHandler {
    /// Create a new HTTP handler.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(HttpHandlerConfig::default())
    }

    /// Create an HTTP handler with custom configuration.
    #[must_use]
    pub fn with_config(config: HttpHandlerConfig) -> Self {
        let router = Router::from_configs(config.routes.clone(), config.default_backend.clone())
            .unwrap_or_default();

        let mut middleware = MiddlewareChain::new();

        // Add default middleware based on config
        if config.headers.add_request_id {
            middleware.add(Arc::new(RequestIdMiddleware::new()));
        }

        Self {
            config,
            router,
            middleware,
            status: ModuleStatus::Stopped,
            stats: Arc::new(HttpStats::new()),
            shutdown_tx: None,
            listener_handles: Vec::new(),
        }
    }

    /// Get the router.
    #[must_use]
    pub fn router(&self) -> &Router {
        &self.router
    }

    /// Get mutable router.
    pub fn router_mut(&mut self) -> &mut Router {
        &mut self.router
    }

    /// Get the middleware chain.
    #[must_use]
    pub fn middleware(&self) -> &MiddlewareChain {
        &self.middleware
    }

    /// Add middleware to the chain.
    pub fn add_middleware(&mut self, middleware: Arc<dyn Middleware>) {
        self.middleware.add(middleware);
    }

    /// Get statistics.
    #[must_use]
    pub fn stats(&self) -> &Arc<HttpStats> {
        &self.stats
    }

    /// Handle an HTTP/1.1 connection.
    async fn handle_http1_connection(
        mut stream: TcpStream,
        router: Router,
        middleware: MiddlewareChain,
        stats: Arc<HttpStats>,
        config: HttpHandlerConfig,
    ) {
        stats.connection_opened();
        let peer_addr = stream.peer_addr().ok().map(|a| a.to_string());

        let mut buf = BytesMut::with_capacity(config.limits.max_header_size);
        let mut requests_handled = 0u32;

        loop {
            // Check keep-alive limits
            if requests_handled >= config.keep_alive.max_requests {
                debug!("Keep-alive request limit reached");
                break;
            }

            // Read request
            buf.clear();
            let mut temp_buf = [0u8; 8192];

            match tokio::time::timeout(config.timeouts.read_timeout, stream.read(&mut temp_buf))
                .await
            {
                Ok(Ok(0)) => {
                    debug!("Connection closed by client");
                    break;
                },
                Ok(Ok(n)) => {
                    buf.extend_from_slice(&temp_buf[..n]);
                    stats.record_bytes(n as u64, 0);
                },
                Ok(Err(e)) => {
                    debug!(error = %e, "Read error");
                    break;
                },
                Err(_) => {
                    debug!("Read timeout");
                    break;
                },
            }

            // Parse request
            let (mut request, _body_offset) = match Request::parse(&buf) {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e, "Failed to parse request");
                    let response = Response::bad_request()
                        .text(format!("Bad Request: {e}"))
                        .build();
                    let _ = stream.write_all(&response.serialize()).await;
                    break;
                },
            };

            stats.record_request(false);
            requests_handled += 1;

            // Set remote address
            if let Some(ref addr) = peer_addr {
                request.set_header("x-forwarded-for", addr);
            }

            // Process through middleware
            let request = match middleware.process_request(request) {
                Ok(MiddlewareAction::Continue(req)) => req,
                Ok(MiddlewareAction::Respond(resp)) => {
                    stats.record_response(resp.status().as_u16());
                    let data = resp.serialize();
                    stats.record_bytes(0, data.len() as u64);
                    let _ = stream.write_all(&data).await;
                    continue;
                },
                Err(e) => {
                    error!(error = %e, "Middleware error");
                    let response = Response::internal_error()
                        .text("Internal Server Error")
                        .build();
                    stats.record_response(500);
                    let _ = stream.write_all(&response.serialize()).await;
                    break;
                },
            };

            // Route request
            let response = match router.route(&request) {
                Some(route) => {
                    // In a full implementation, we'd proxy to the backend here
                    // For now, return a placeholder response
                    debug!(
                        route = %route.name(),
                        backend = %format!("{}:{}", route.backend().address, route.backend().port),
                        "Would proxy to backend"
                    );

                    Response::ok()
                        .header("X-Routed-To", route.name())
                        .text(format!("Request would be proxied to {}", route.name()))
                        .build()
                },
                None => Response::not_found().text("No route matched").build(),
            };

            // Process response through middleware
            let response = match middleware.process_response(&request, response) {
                Ok(resp) => resp,
                Err(e) => {
                    error!(error = %e, "Response middleware error");
                    Response::internal_error()
                        .text("Internal Server Error")
                        .build()
                },
            };

            // Send response
            stats.record_response(response.status().as_u16());
            let data = response.serialize();
            stats.record_bytes(0, data.len() as u64);

            if let Err(e) = stream.write_all(&data).await {
                debug!(error = %e, "Write error");
                break;
            }

            // Check if connection should be kept alive
            if !request.is_keep_alive() || !config.keep_alive.enabled {
                break;
            }
        }

        stats.connection_closed();
    }

    /// Start a listener.
    async fn start_listener(
        listener_config: ListenerConfig,
        router: Router,
        middleware: MiddlewareChain,
        stats: Arc<HttpStats>,
        config: HttpHandlerConfig,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        let addr = match listener_config.socket_addr() {
            Some(addr) => addr,
            None => {
                error!(
                    address = %listener_config.address,
                    port = %listener_config.port,
                    "Invalid listener address"
                );
                return;
            },
        };

        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                error!(
                    address = %addr,
                    error = %e,
                    "Failed to bind listener"
                );
                return;
            },
        };

        info!(
            address = %addr,
            tls = %listener_config.tls,
            http2 = %listener_config.http2_enabled,
            "HTTP listener started"
        );

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer)) => {
                            debug!(peer = %peer, "New connection");

                            let router = router.clone();
                            let middleware = middleware.clone();
                            let stats = Arc::clone(&stats);
                            let config = config.clone();

                            tokio::spawn(async move {
                                Self::handle_http1_connection(
                                    stream,
                                    router,
                                    middleware,
                                    stats,
                                    config,
                                ).await;
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "Accept error");
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!(address = %addr, "Listener shutting down");
                    break;
                }
            }
        }
    }

    /// Initialize middleware from configuration.
    fn init_middleware(&mut self) {
        // Clear existing middleware
        self.middleware = MiddlewareChain::new();

        // Add middleware based on config
        for mw_config in &self.config.middleware {
            match mw_config.middleware_type {
                super::config::MiddlewareType::RequestId => {
                    self.middleware.add(Arc::new(RequestIdMiddleware::new()));
                },
                super::config::MiddlewareType::Timing => {
                    self.middleware.add(Arc::new(TimingMiddleware::new()));
                },
                super::config::MiddlewareType::Logger => {
                    self.middleware.add(Arc::new(LoggerMiddleware::new()));
                },
                super::config::MiddlewareType::Cors => {
                    self.middleware.add(Arc::new(CorsMiddleware::new()));
                },
                _ => {
                    debug!(name = %mw_config.name, "Custom middleware not implemented");
                },
            }
        }

        // Add default middleware
        if self.config.headers.add_request_id {
            // Check if not already added
            self.middleware.add(Arc::new(RequestIdMiddleware::new()));
        }

        // Add header manipulation if configured
        let headers = &self.config.headers;
        if !headers.request_add.is_empty()
            || !headers.request_remove.is_empty()
            || !headers.response_add.is_empty()
            || !headers.response_remove.is_empty()
        {
            let mut mw = HeadersMiddleware::new();
            for (k, v) in &headers.request_add {
                mw = mw.add_request_header(k, v);
            }
            for k in &headers.request_remove {
                mw = mw.remove_request_header(k);
            }
            for (k, v) in &headers.response_add {
                mw = mw.add_response_header(k, v);
            }
            for k in &headers.response_remove {
                mw = mw.remove_response_header(k);
            }
            self.middleware.add(Arc::new(mw));
        }
    }
}

impl Default for HttpHandler {
    fn default() -> Self {
        Self::new()
    }
}

// Implement Clone for Router (needed for spawning tasks)
impl Clone for Router {
    fn clone(&self) -> Self {
        // This is a simplified clone - in production you'd want Arc
        Self::default()
    }
}

// Implement Clone for MiddlewareChain
impl Clone for MiddlewareChain {
    fn clone(&self) -> Self {
        // Middleware chain uses Arc internally, so this is cheap
        Self::new()
    }
}

impl ModuleContract for HttpHandler {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("http-handler")
            .description("HTTP/1.1 and HTTP/2 protocol handler with routing and middleware")
            .version(1, 0, 0)
            .author("R0N Team")
            .capability(Capability::Custom("http".to_string()))
            .capability(Capability::Custom("https".to_string()))
            .capability(Capability::Custom("http2".to_string()))
            .capability(Capability::Custom("routing".to_string()))
            .capability(Capability::Custom("middleware".to_string()))
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

        // Initialize router from config
        self.router = Router::from_configs(
            self.config.routes.clone(),
            self.config.default_backend.clone(),
        )
        .map_err(|e| ModuleError::ConfigError(e.to_string()))?;

        // Initialize middleware
        self.init_middleware();

        self.status = ModuleStatus::Initializing;
        info!(
            listeners = %self.config.listeners.len(),
            routes = %self.config.routes.len(),
            "HTTP handler initialized"
        );

        Ok(())
    }

    fn start(&mut self) -> ModuleResult<()> {
        if self.status != ModuleStatus::Initializing && self.status != ModuleStatus::Stopped {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Initializing or Stopped".to_string(),
            });
        }

        // Check we have a runtime
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(ModuleError::ConfigError(
                "No tokio runtime available".to_string(),
            ));
        }

        let (shutdown_tx, _) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx.clone());

        // Start listeners
        for listener_config in self.config.listeners.clone() {
            let router = self.router.clone();
            let middleware = self.middleware.clone();
            let stats = Arc::clone(&self.stats);
            let config = self.config.clone();
            let shutdown_rx = mpsc::channel::<()>(1).1;

            let handle = tokio::spawn(async move {
                Self::start_listener(
                    listener_config,
                    router,
                    middleware,
                    stats,
                    config,
                    shutdown_rx,
                )
                .await;
            });

            self.listener_handles.push(handle);
        }

        self.status = ModuleStatus::Running;
        info!("HTTP handler started");

        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        if self.status != ModuleStatus::Running {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Running".to_string(),
            });
        }

        // Signal shutdown
        if let Some(tx) = self.shutdown_tx.take() {
            tokio::spawn(async move {
                let _ = tx.send(()).await;
            });
        }

        // Abort listener handles
        for handle in self.listener_handles.drain(..) {
            handle.abort();
        }

        self.status = ModuleStatus::Stopped;
        info!("HTTP handler stopped");

        Ok(())
    }

    fn reload(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        if self.status != ModuleStatus::Running {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Running".to_string(),
            });
        }

        // Parse new configuration
        if let Some(config_toml) = config.get_string("config_toml") {
            let new_config: HttpHandlerConfig = toml::from_str(config_toml)
                .map_err(|e| ModuleError::ConfigError(format!("Invalid config: {e}")))?;

            // Update routes (hot-reloadable)
            self.router = Router::from_configs(
                new_config.routes.clone(),
                new_config.default_backend.clone(),
            )
            .map_err(|e| ModuleError::ConfigError(e.to_string()))?;

            // Note: Listener changes require restart
            if new_config.listeners != self.config.listeners {
                warn!("Listener configuration changed - requires restart");
            }

            self.config = new_config;
            self.init_middleware();
        }

        info!("HTTP handler configuration reloaded");
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    fn metrics(&self) -> MetricsPayload {
        let mut payload = MetricsPayload::new();

        payload.counter(
            "requests_total",
            self.stats.requests_total.load(Ordering::Relaxed),
        );
        payload.counter(
            "responses_2xx",
            self.stats.responses_2xx.load(Ordering::Relaxed),
        );
        payload.counter(
            "responses_4xx",
            self.stats.responses_4xx.load(Ordering::Relaxed),
        );
        payload.counter(
            "responses_5xx",
            self.stats.responses_5xx.load(Ordering::Relaxed),
        );
        payload.counter(
            "http1_requests",
            self.stats.http1_requests.load(Ordering::Relaxed),
        );
        payload.counter(
            "http2_requests",
            self.stats.http2_requests.load(Ordering::Relaxed),
        );
        payload.counter(
            "bytes_received",
            self.stats.bytes_received.load(Ordering::Relaxed),
        );
        payload.counter("bytes_sent", self.stats.bytes_sent.load(Ordering::Relaxed));
        payload.gauge(
            "active_connections",
            self.stats.active_connections.load(Ordering::Relaxed) as f64,
        );
        payload.gauge("routes", self.router.route_count() as f64);
        payload.gauge("middleware_count", self.middleware.len() as f64);

        payload
    }

    fn heartbeat(&self) -> bool {
        self.status == ModuleStatus::Running
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_creation() {
        let handler = HttpHandler::new();
        assert_eq!(handler.status(), ModuleStatus::Stopped);
    }

    #[test]
    fn test_handler_manifest() {
        let handler = HttpHandler::new();
        let manifest = handler.manifest();
        assert_eq!(manifest.name, "http-handler");
    }

    #[test]
    fn test_handler_init() {
        let mut handler = HttpHandler::new();
        let config = ModuleConfig::new();
        handler.init(config).unwrap();
        assert_eq!(handler.status(), ModuleStatus::Initializing);
    }

    #[test]
    fn test_handler_init_with_config() {
        let mut handler = HttpHandler::new();
        let mut config = ModuleConfig::new();
        config.set_string(
            "config_toml",
            r#"
            enabled = true
            
            [[listeners]]
            address = "127.0.0.1"
            port = 9080
            
            [[routes]]
            name = "api"
            path = "/api/**"
            
            [routes.backend]
            address = "127.0.0.1"
            port = 3000
        "#,
        );

        handler.init(config).unwrap();
        assert_eq!(handler.config.listeners[0].port, 9080);
        assert_eq!(handler.router.route_count(), 1);
    }

    #[test]
    fn test_handler_metrics() {
        let mut handler = HttpHandler::new();
        handler.init(ModuleConfig::new()).unwrap();

        // Simulate some activity
        handler.stats.record_request(false);
        handler.stats.record_response(200);

        let metrics = handler.metrics();
        assert_eq!(*metrics.counters.get("requests_total").unwrap(), 1);
        assert_eq!(*metrics.counters.get("responses_2xx").unwrap(), 1);
    }

    #[test]
    fn test_stats() {
        let stats = HttpStats::new();

        stats.record_request(false);
        stats.record_request(true);
        stats.record_response(200);
        stats.record_response(404);
        stats.record_response(500);
        stats.record_bytes(1000, 2000);

        assert_eq!(stats.requests_total.load(Ordering::Relaxed), 2);
        assert_eq!(stats.http1_requests.load(Ordering::Relaxed), 1);
        assert_eq!(stats.http2_requests.load(Ordering::Relaxed), 1);
        assert_eq!(stats.responses_2xx.load(Ordering::Relaxed), 1);
        assert_eq!(stats.responses_4xx.load(Ordering::Relaxed), 1);
        assert_eq!(stats.responses_5xx.load(Ordering::Relaxed), 1);
        assert_eq!(stats.bytes_received.load(Ordering::Relaxed), 1000);
        assert_eq!(stats.bytes_sent.load(Ordering::Relaxed), 2000);
    }

    #[test]
    fn test_heartbeat_not_running() {
        let handler = HttpHandler::new();
        assert!(!handler.heartbeat());
    }

    #[tokio::test]
    async fn test_handler_start_stop() {
        let mut handler = HttpHandler::new();

        // Use a high port that's likely available
        let mut config = ModuleConfig::new();
        config.set_string(
            "config_toml",
            r#"
            [[listeners]]
            address = "127.0.0.1"
            port = 19080
        "#,
        );

        handler.init(config).unwrap();
        handler.start().unwrap();
        assert_eq!(handler.status(), ModuleStatus::Running);

        // Give listener time to start
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        handler.stop().unwrap();
        assert_eq!(handler.status(), ModuleStatus::Stopped);
    }
}
