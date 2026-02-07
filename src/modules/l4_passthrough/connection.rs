//! Connection information and state tracking.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection is being established.
    Connecting,
    /// Connection is active and transferring data.
    Active,
    /// Connection is idle (no recent activity).
    Idle,
    /// Connection is being closed.
    Closing,
    /// Connection is closed.
    Closed,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Connecting => write!(f, "connecting"),
            ConnectionState::Active => write!(f, "active"),
            ConnectionState::Idle => write!(f, "idle"),
            ConnectionState::Closing => write!(f, "closing"),
            ConnectionState::Closed => write!(f, "closed"),
        }
    }
}

/// Information about a single connection.
#[derive(Debug)]
pub struct ConnectionInfo {
    /// Unique connection ID.
    pub id: u64,

    /// Client address.
    pub client_addr: SocketAddr,

    /// Backend address.
    pub backend_addr: SocketAddr,

    /// Listener name or bind address.
    pub listener: String,

    /// Connection state.
    pub state: ConnectionState,

    /// Time when the connection was established.
    pub connected_at: Instant,

    /// Last activity time.
    pub last_activity: Instant,

    /// Bytes sent to client.
    pub bytes_to_client: u64,

    /// Bytes sent to backend.
    pub bytes_to_backend: u64,
}

impl ConnectionInfo {
    /// Create a new connection info.
    pub fn new(
        id: u64,
        client_addr: SocketAddr,
        backend_addr: SocketAddr,
        listener: String,
    ) -> Self {
        let now = Instant::now();
        Self {
            id,
            client_addr,
            backend_addr,
            listener,
            state: ConnectionState::Connecting,
            connected_at: now,
            last_activity: now,
            bytes_to_client: 0,
            bytes_to_backend: 0,
        }
    }

    /// Get connection duration.
    pub fn duration(&self) -> std::time::Duration {
        self.connected_at.elapsed()
    }

    /// Get idle duration.
    pub fn idle_duration(&self) -> std::time::Duration {
        self.last_activity.elapsed()
    }

    /// Total bytes transferred.
    pub fn total_bytes(&self) -> u64 {
        self.bytes_to_client + self.bytes_to_backend
    }
}

/// Atomic connection statistics.
#[derive(Debug, Default)]
pub struct ConnectionStats {
    /// Total connections accepted.
    pub connections_total: AtomicU64,
    /// Currently active connections.
    pub connections_active: AtomicU64,
    /// Total bytes received from clients.
    pub bytes_received: AtomicU64,
    /// Total bytes sent to clients.
    pub bytes_sent: AtomicU64,
    /// Total connection errors.
    pub connection_errors: AtomicU64,
    /// Total backend connection failures.
    pub backend_failures: AtomicU64,
}

impl ConnectionStats {
    /// Create new connection stats.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new connection.
    pub fn connection_accepted(&self) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
        self.connections_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a connection closed.
    pub fn connection_closed(&self) {
        self.connections_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record bytes received from client.
    pub fn bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record bytes sent to client.
    pub fn bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a connection error.
    #[allow(dead_code)]
    pub fn connection_error(&self) {
        self.connection_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a backend failure.
    pub fn backend_failure(&self) {
        self.backend_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current active connections.
    pub fn active_connections(&self) -> u64 {
        self.connections_active.load(Ordering::Relaxed)
    }

    /// Get total connections.
    pub fn total_connections(&self) -> u64 {
        self.connections_total.load(Ordering::Relaxed)
    }

    /// Get total bytes received.
    pub fn total_bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Get total bytes sent.
    pub fn total_bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn test_connection_state_display() {
        assert_eq!(ConnectionState::Connecting.to_string(), "connecting");
        assert_eq!(ConnectionState::Active.to_string(), "active");
        assert_eq!(ConnectionState::Idle.to_string(), "idle");
        assert_eq!(ConnectionState::Closing.to_string(), "closing");
        assert_eq!(ConnectionState::Closed.to_string(), "closed");
    }

    #[test]
    fn test_connection_info_new() {
        let client = make_addr(12345);
        let backend = make_addr(3306);
        let info = ConnectionInfo::new(1, client, backend, "mysql".to_string());

        assert_eq!(info.id, 1);
        assert_eq!(info.client_addr, client);
        assert_eq!(info.backend_addr, backend);
        assert_eq!(info.state, ConnectionState::Connecting);
        assert_eq!(info.bytes_to_client, 0);
        assert_eq!(info.bytes_to_backend, 0);
    }

    #[test]
    fn test_connection_info_duration() {
        let client = make_addr(12345);
        let backend = make_addr(3306);
        let info = ConnectionInfo::new(1, client, backend, "mysql".to_string());

        // Duration should be very small immediately after creation
        assert!(info.duration().as_millis() < 100);
        assert!(info.idle_duration().as_millis() < 100);
    }

    #[test]
    fn test_connection_info_total_bytes() {
        let client = make_addr(12345);
        let backend = make_addr(3306);
        let mut info = ConnectionInfo::new(1, client, backend, "mysql".to_string());

        info.bytes_to_client = 1000;
        info.bytes_to_backend = 500;
        assert_eq!(info.total_bytes(), 1500);
    }

    #[test]
    fn test_connection_stats() {
        let stats = ConnectionStats::new();

        stats.connection_accepted();
        stats.connection_accepted();
        assert_eq!(stats.active_connections(), 2);
        assert_eq!(stats.total_connections(), 2);

        stats.connection_closed();
        assert_eq!(stats.active_connections(), 1);
        assert_eq!(stats.total_connections(), 2);

        stats.bytes_received(1000);
        stats.bytes_sent(500);
        assert_eq!(stats.total_bytes_received(), 1000);
        assert_eq!(stats.total_bytes_sent(), 500);

        stats.connection_error();
        stats.backend_failure();
        assert_eq!(stats.connection_errors.load(Ordering::Relaxed), 1);
        assert_eq!(stats.backend_failures.load(Ordering::Relaxed), 1);
    }
}
