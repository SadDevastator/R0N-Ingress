//! TCP listener implementation.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::config::ListenerConfig;
use super::connection::Connection;
use super::error::{TcpRouterError, TcpRouterResult};

/// Event from the listener.
#[derive(Debug)]
pub enum ListenerEvent {
    /// A new connection was accepted.
    NewConnection(Connection),

    /// An error occurred while accepting.
    AcceptError(std::io::Error),

    /// The listener has stopped.
    Stopped,
}

/// Statistics for a listener.
#[derive(Debug, Clone, Default)]
pub struct ListenerStats {
    /// Total connections accepted.
    pub total_accepted: u64,

    /// Connections currently active.
    pub active_connections: u64,

    /// Total connection errors.
    pub accept_errors: u64,

    /// Listener uptime in seconds.
    pub uptime_seconds: u64,
}

/// A TCP listener that accepts connections.
pub struct Listener {
    /// Listener configuration.
    config: ListenerConfig,

    /// The bound address.
    bound_addr: SocketAddr,

    /// Whether the listener is running.
    running: Arc<AtomicBool>,

    /// Total connections accepted.
    total_accepted: Arc<AtomicU64>,

    /// Accept errors count.
    accept_errors: Arc<AtomicU64>,

    /// Active connections count.
    active_connections: Arc<AtomicU64>,

    /// Start time.
    started_at: Option<Instant>,
}

impl Listener {
    /// Bind a new listener to the configured address.
    ///
    /// # Errors
    ///
    /// Returns an error if binding fails.
    pub async fn bind(config: ListenerConfig) -> TcpRouterResult<Self> {
        let addr = SocketAddr::new(config.address, config.port);

        let listener =
            TokioTcpListener::bind(addr)
                .await
                .map_err(|e| TcpRouterError::BindError {
                    address: addr,
                    source: e,
                })?;

        let bound_addr = listener
            .local_addr()
            .map_err(|e| TcpRouterError::BindError {
                address: addr,
                source: e,
            })?;

        info!(
            name = config.name.as_deref().unwrap_or("unnamed"),
            address = %bound_addr,
            "TCP listener bound"
        );

        // We drop the initial listener here since we'll rebind in start()
        // This is just to validate the address is available
        drop(listener);

        Ok(Self {
            config,
            bound_addr,
            running: Arc::new(AtomicBool::new(false)),
            total_accepted: Arc::new(AtomicU64::new(0)),
            accept_errors: Arc::new(AtomicU64::new(0)),
            active_connections: Arc::new(AtomicU64::new(0)),
            started_at: None,
        })
    }

    /// Get the bound address.
    #[must_use]
    pub fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// Get the listener name.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.config.name.as_deref()
    }

    /// Check if the listener is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Get listener statistics.
    #[must_use]
    pub fn stats(&self) -> ListenerStats {
        ListenerStats {
            total_accepted: self.total_accepted.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            accept_errors: self.accept_errors.load(Ordering::Relaxed),
            uptime_seconds: self.started_at.map(|t| t.elapsed().as_secs()).unwrap_or(0),
        }
    }

    /// Start accepting connections.
    ///
    /// Returns a channel that receives listener events.
    ///
    /// # Errors
    ///
    /// Returns an error if the listener is already running or fails to bind.
    pub async fn start(&mut self) -> TcpRouterResult<mpsc::Receiver<ListenerEvent>> {
        if self.running.load(Ordering::Relaxed) {
            return Err(TcpRouterError::AlreadyRunning);
        }

        let listener = TokioTcpListener::bind(self.bound_addr).await.map_err(|e| {
            TcpRouterError::BindError {
                address: self.bound_addr,
                source: e,
            }
        })?;

        self.running.store(true, Ordering::Release);
        self.started_at = Some(Instant::now());

        let (tx, rx) = mpsc::channel(1024);

        let running = Arc::clone(&self.running);
        let total_accepted = Arc::clone(&self.total_accepted);
        let accept_errors = Arc::clone(&self.accept_errors);
        let active_connections = Arc::clone(&self.active_connections);
        let config = self.config.clone();

        tokio::spawn(async move {
            Self::accept_loop(
                listener,
                tx,
                running,
                total_accepted,
                accept_errors,
                active_connections,
                config,
            )
            .await;
        });

        Ok(rx)
    }

    /// Stop the listener.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Release);
    }

    /// The main accept loop.
    async fn accept_loop(
        listener: TokioTcpListener,
        tx: mpsc::Sender<ListenerEvent>,
        running: Arc<AtomicBool>,
        total_accepted: Arc<AtomicU64>,
        accept_errors: Arc<AtomicU64>,
        active_connections: Arc<AtomicU64>,
        config: ListenerConfig,
    ) {
        info!(address = %listener.local_addr().unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))), "Accept loop started");

        while running.load(Ordering::Relaxed) {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    if let Err(e) = Self::configure_stream(&stream, &config) {
                        warn!(peer = %peer_addr, error = %e, "Failed to configure stream");
                    }

                    match Connection::new(stream) {
                        Ok(conn) => {
                            total_accepted.fetch_add(1, Ordering::Relaxed);
                            active_connections.fetch_add(1, Ordering::Relaxed);

                            debug!(
                                peer = %peer_addr,
                                conn_id = conn.id(),
                                "Accepted connection"
                            );

                            if tx.send(ListenerEvent::NewConnection(conn)).await.is_err() {
                                warn!("Event channel closed, stopping listener");
                                break;
                            }
                        },
                        Err(e) => {
                            accept_errors.fetch_add(1, Ordering::Relaxed);
                            error!(error = %e, "Failed to wrap connection");
                        },
                    }
                },
                Err(e) => {
                    accept_errors.fetch_add(1, Ordering::Relaxed);

                    // Some errors are transient, others are fatal
                    if is_fatal_accept_error(&e) {
                        error!(error = %e, "Fatal accept error");
                        let _ = tx.send(ListenerEvent::AcceptError(e)).await;
                        break;
                    }

                    warn!(error = %e, "Transient accept error");
                },
            }
        }

        running.store(false, Ordering::Release);
        let _ = tx.send(ListenerEvent::Stopped).await;
        info!("Accept loop stopped");
    }

    /// Configure a newly accepted stream.
    fn configure_stream(stream: &TcpStream, config: &ListenerConfig) -> std::io::Result<()> {
        stream.set_nodelay(config.tcp_nodelay)?;

        // Note: TCP keepalive configuration requires platform-specific APIs
        // For now, we just set nodelay. Full keepalive would need socket2 crate.

        Ok(())
    }

    /// Decrement active connection count (call when connection closes).
    pub fn connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Check if an accept error is fatal (unrecoverable).
fn is_fatal_accept_error(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;

    matches!(
        error.kind(),
        ErrorKind::InvalidInput | ErrorKind::InvalidData | ErrorKind::NotFound
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn test_listener_bind() {
        let config = ListenerConfig::new(0); // Port 0 = random available port
        let listener = Listener::bind(config).await.unwrap();

        assert_ne!(listener.bound_addr().port(), 0);
        assert!(!listener.is_running());
    }

    #[tokio::test]
    async fn test_listener_start_stop() {
        let config = ListenerConfig::new(0);
        let mut listener = Listener::bind(config).await.unwrap();

        let mut events = listener.start().await.unwrap();
        assert!(listener.is_running());

        listener.stop();

        // Wait for stopped event
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while let Some(event) = events.recv().await {
                if matches!(event, ListenerEvent::Stopped) {
                    return;
                }
            }
        })
        .await
        .ok();
    }

    #[tokio::test]
    async fn test_listener_accept_connection() {
        let config = ListenerConfig::new(0);
        let mut listener = Listener::bind(config).await.unwrap();
        let addr = listener.bound_addr();

        let mut events = listener.start().await.unwrap();

        // Connect a client
        let client = TcpStream::connect(addr).await.unwrap();

        // Wait for the connection event
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
            .await
            .unwrap()
            .unwrap();

        match event {
            ListenerEvent::NewConnection(conn) => {
                assert_eq!(conn.local_addr().port(), addr.port());
            },
            _ => panic!("Expected NewConnection event"),
        }

        drop(client);
        listener.stop();
    }

    #[tokio::test]
    async fn test_listener_stats() {
        let config = ListenerConfig::new(0);
        let mut listener = Listener::bind(config).await.unwrap();
        let addr = listener.bound_addr();

        let mut events = listener.start().await.unwrap();

        // Connect multiple clients
        let mut clients = Vec::new();
        for _ in 0..3 {
            clients.push(TcpStream::connect(addr).await.unwrap());
        }

        // Wait for all connection events
        for _ in 0..3 {
            tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
                .await
                .unwrap();
        }

        let stats = listener.stats();
        assert_eq!(stats.total_accepted, 3);
        assert_eq!(stats.active_connections, 3);

        listener.stop();
    }
}
