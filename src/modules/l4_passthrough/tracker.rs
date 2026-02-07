//! Connection tracking for L4 passthrough.

use crate::modules::l4_passthrough::connection::{ConnectionInfo, ConnectionState};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Connection tracker for monitoring active connections.
#[derive(Debug)]
pub struct ConnectionTracker {
    /// Active connections by ID.
    connections: RwLock<HashMap<u64, TrackedConnection>>,

    /// Next connection ID.
    next_id: AtomicU64,

    /// UDP sessions by (client_addr, listener).
    udp_sessions: RwLock<HashMap<(SocketAddr, String), UdpSession>>,

    /// Connection count per client IP.
    connections_per_ip: RwLock<HashMap<std::net::IpAddr, usize>>,
}

/// A tracked connection.
#[derive(Debug)]
struct TrackedConnection {
    /// Connection info.
    info: ConnectionInfo,
}

/// UDP session state.
#[derive(Debug)]
#[allow(dead_code)]
pub struct UdpSession {
    /// Session ID.
    pub id: u64,

    /// Client address.
    pub client_addr: SocketAddr,

    /// Backend address.
    pub backend_addr: SocketAddr,

    /// Listener name.
    pub listener: String,

    /// Session creation time.
    pub created_at: Instant,

    /// Last activity time.
    pub last_activity: Instant,

    /// Packets sent to client.
    pub packets_to_client: u64,

    /// Packets sent to backend.
    pub packets_to_backend: u64,

    /// Bytes sent to client.
    pub bytes_to_client: u64,

    /// Bytes sent to backend.
    pub bytes_to_backend: u64,
}

impl UdpSession {
    /// Create a new UDP session.
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
            created_at: now,
            last_activity: now,
            packets_to_client: 0,
            packets_to_backend: 0,
            bytes_to_client: 0,
            bytes_to_backend: 0,
        }
    }

    /// Update last activity time.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if session has expired.
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Session duration.
    #[allow(dead_code)]
    pub fn duration(&self) -> Duration {
        self.created_at.elapsed()
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionTracker {
    /// Create a new connection tracker.
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            udp_sessions: RwLock::new(HashMap::new()),
            connections_per_ip: RwLock::new(HashMap::new()),
        }
    }

    /// Generate a new unique connection ID.
    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Track a new TCP connection.
    pub fn track_connection(
        &self,
        client_addr: SocketAddr,
        backend_addr: SocketAddr,
        listener: String,
    ) -> u64 {
        let id = self.next_id();
        let info = ConnectionInfo::new(id, client_addr, backend_addr, listener);

        {
            let mut connections = self.connections.write().unwrap();
            connections.insert(id, TrackedConnection { info });
        }

        {
            let mut per_ip = self.connections_per_ip.write().unwrap();
            *per_ip.entry(client_addr.ip()).or_insert(0) += 1;
        }

        id
    }

    /// Update connection state.
    pub fn update_state(&self, id: u64, state: ConnectionState) {
        let mut connections = self.connections.write().unwrap();
        if let Some(conn) = connections.get_mut(&id) {
            conn.info.state = state;
            conn.info.last_activity = Instant::now();
        }
    }

    /// Update connection bytes.
    pub fn update_bytes(&self, id: u64, to_client: u64, to_backend: u64) {
        let mut connections = self.connections.write().unwrap();
        if let Some(conn) = connections.get_mut(&id) {
            conn.info.bytes_to_client += to_client;
            conn.info.bytes_to_backend += to_backend;
            conn.info.last_activity = Instant::now();
        }
    }

    /// Remove a tracked connection.
    pub fn remove_connection(&self, id: u64) -> Option<ConnectionInfo> {
        let conn = {
            let mut connections = self.connections.write().unwrap();
            connections.remove(&id)
        };

        if let Some(ref conn) = conn {
            let mut per_ip = self.connections_per_ip.write().unwrap();
            if let Some(count) = per_ip.get_mut(&conn.info.client_addr.ip()) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    per_ip.remove(&conn.info.client_addr.ip());
                }
            }
        }

        conn.map(|c| c.info)
    }

    /// Get connection info.
    pub fn get_connection(&self, id: u64) -> Option<ConnectionInfo> {
        let connections = self.connections.read().unwrap();
        connections.get(&id).map(|c| ConnectionInfo {
            id: c.info.id,
            client_addr: c.info.client_addr,
            backend_addr: c.info.backend_addr,
            listener: c.info.listener.clone(),
            state: c.info.state,
            connected_at: c.info.connected_at,
            last_activity: c.info.last_activity,
            bytes_to_client: c.info.bytes_to_client,
            bytes_to_backend: c.info.bytes_to_backend,
        })
    }

    /// Get number of active connections.
    pub fn active_connections(&self) -> usize {
        self.connections.read().unwrap().len()
    }

    /// Get connections per IP for a specific IP.
    pub fn connections_for_ip(&self, ip: std::net::IpAddr) -> usize {
        self.connections_per_ip
            .read()
            .unwrap()
            .get(&ip)
            .copied()
            .unwrap_or(0)
    }

    /// Get or create a UDP session.
    pub fn get_or_create_udp_session(
        &self,
        client_addr: SocketAddr,
        backend_addr: SocketAddr,
        listener: String,
    ) -> u64 {
        let key = (client_addr, listener.clone());

        {
            let sessions = self.udp_sessions.read().unwrap();
            if let Some(session) = sessions.get(&key) {
                return session.id;
            }
        }

        let id = self.next_id();
        let session = UdpSession::new(id, client_addr, backend_addr, listener);

        {
            let mut sessions = self.udp_sessions.write().unwrap();
            sessions.insert(key, session);
        }

        id
    }

    /// Update UDP session activity.
    pub fn touch_udp_session(&self, client_addr: SocketAddr, listener: &str) {
        let key = (client_addr, listener.to_string());
        let mut sessions = self.udp_sessions.write().unwrap();
        if let Some(session) = sessions.get_mut(&key) {
            session.touch();
        }
    }

    /// Update UDP session stats.
    pub fn update_udp_session_stats(
        &self,
        client_addr: SocketAddr,
        listener: &str,
        packets_to_client: u64,
        packets_to_backend: u64,
        bytes_to_client: u64,
        bytes_to_backend: u64,
    ) {
        let key = (client_addr, listener.to_string());
        let mut sessions = self.udp_sessions.write().unwrap();
        if let Some(session) = sessions.get_mut(&key) {
            session.packets_to_client += packets_to_client;
            session.packets_to_backend += packets_to_backend;
            session.bytes_to_client += bytes_to_client;
            session.bytes_to_backend += bytes_to_backend;
            session.touch();
        }
    }

    /// Get UDP session by client address and listener.
    pub fn get_udp_session(&self, client_addr: SocketAddr, listener: &str) -> Option<SocketAddr> {
        let key = (client_addr, listener.to_string());
        let sessions = self.udp_sessions.read().unwrap();
        sessions.get(&key).map(|s| s.backend_addr)
    }

    /// Cleanup expired UDP sessions.
    pub fn cleanup_expired_udp_sessions(&self, timeout: Duration) -> usize {
        let mut sessions = self.udp_sessions.write().unwrap();
        let before = sessions.len();
        sessions.retain(|_, session| !session.is_expired(timeout));
        before - sessions.len()
    }

    /// Get number of active UDP sessions.
    pub fn active_udp_sessions(&self) -> usize {
        self.udp_sessions.read().unwrap().len()
    }

    /// Cleanup idle TCP connections.
    pub fn cleanup_idle_connections(&self, timeout: Duration) -> usize {
        let mut to_remove = Vec::new();

        {
            let connections = self.connections.read().unwrap();
            for (id, conn) in connections.iter() {
                if conn.info.idle_duration() > timeout {
                    to_remove.push(*id);
                }
            }
        }

        let count = to_remove.len();
        for id in to_remove {
            self.remove_connection(id);
        }
        count
    }

    /// Get all connection info (for monitoring).
    pub fn all_connections(&self) -> Vec<ConnectionInfo> {
        let connections = self.connections.read().unwrap();
        connections
            .values()
            .map(|c| ConnectionInfo {
                id: c.info.id,
                client_addr: c.info.client_addr,
                backend_addr: c.info.backend_addr,
                listener: c.info.listener.clone(),
                state: c.info.state,
                connected_at: c.info.connected_at,
                last_activity: c.info.last_activity,
                bytes_to_client: c.info.bytes_to_client,
                bytes_to_backend: c.info.bytes_to_backend,
            })
            .collect()
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
    fn test_tracker_new() {
        let tracker = ConnectionTracker::new();
        assert_eq!(tracker.active_connections(), 0);
        assert_eq!(tracker.active_udp_sessions(), 0);
    }

    #[test]
    fn test_track_connection() {
        let tracker = ConnectionTracker::new();
        let client = make_addr(12345);
        let backend = make_addr(3306);

        let id = tracker.track_connection(client, backend, "mysql".to_string());
        assert!(id > 0);
        assert_eq!(tracker.active_connections(), 1);

        let info = tracker.get_connection(id).unwrap();
        assert_eq!(info.client_addr, client);
        assert_eq!(info.backend_addr, backend);
    }

    #[test]
    fn test_remove_connection() {
        let tracker = ConnectionTracker::new();
        let client = make_addr(12345);
        let backend = make_addr(3306);

        let id = tracker.track_connection(client, backend, "mysql".to_string());
        assert_eq!(tracker.active_connections(), 1);

        let info = tracker.remove_connection(id).unwrap();
        assert_eq!(info.id, id);
        assert_eq!(tracker.active_connections(), 0);

        assert!(tracker.remove_connection(id).is_none());
    }

    #[test]
    fn test_update_state() {
        let tracker = ConnectionTracker::new();
        let client = make_addr(12345);
        let backend = make_addr(3306);

        let id = tracker.track_connection(client, backend, "mysql".to_string());
        tracker.update_state(id, ConnectionState::Active);

        let info = tracker.get_connection(id).unwrap();
        assert_eq!(info.state, ConnectionState::Active);
    }

    #[test]
    fn test_update_bytes() {
        let tracker = ConnectionTracker::new();
        let client = make_addr(12345);
        let backend = make_addr(3306);

        let id = tracker.track_connection(client, backend, "mysql".to_string());
        tracker.update_bytes(id, 1000, 500);

        let info = tracker.get_connection(id).unwrap();
        assert_eq!(info.bytes_to_client, 1000);
        assert_eq!(info.bytes_to_backend, 500);
    }

    #[test]
    fn test_connections_per_ip() {
        let tracker = ConnectionTracker::new();
        let client1 = make_addr(12345);
        let client2 = make_addr(12346);
        let backend = make_addr(3306);

        tracker.track_connection(client1, backend, "mysql".to_string());
        tracker.track_connection(client2, backend, "mysql".to_string());

        // Same IP, different ports
        assert_eq!(tracker.connections_for_ip(client1.ip()), 2);
    }

    #[test]
    fn test_udp_session() {
        let tracker = ConnectionTracker::new();
        let client = make_addr(12345);
        let backend = make_addr(53);

        let id = tracker.get_or_create_udp_session(client, backend, "dns".to_string());
        assert!(id > 0);
        assert_eq!(tracker.active_udp_sessions(), 1);

        // Same client+listener should return same session
        let id2 = tracker.get_or_create_udp_session(client, backend, "dns".to_string());
        assert_eq!(id, id2);
        assert_eq!(tracker.active_udp_sessions(), 1);
    }

    #[test]
    fn test_udp_session_lookup() {
        let tracker = ConnectionTracker::new();
        let client = make_addr(12345);
        let backend = make_addr(53);

        tracker.get_or_create_udp_session(client, backend, "dns".to_string());

        let found = tracker.get_udp_session(client, "dns");
        assert_eq!(found, Some(backend));

        let not_found = tracker.get_udp_session(client, "other");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_cleanup_expired_udp_sessions() {
        let tracker = ConnectionTracker::new();
        let client = make_addr(12345);
        let backend = make_addr(53);

        tracker.get_or_create_udp_session(client, backend, "dns".to_string());
        assert_eq!(tracker.active_udp_sessions(), 1);

        // Cleanup with long timeout - nothing expires
        let removed = tracker.cleanup_expired_udp_sessions(Duration::from_secs(3600));
        assert_eq!(removed, 0);
        assert_eq!(tracker.active_udp_sessions(), 1);

        // Cleanup with zero timeout - everything expires
        let removed = tracker.cleanup_expired_udp_sessions(Duration::ZERO);
        assert_eq!(removed, 1);
        assert_eq!(tracker.active_udp_sessions(), 0);
    }

    #[test]
    fn test_all_connections() {
        let tracker = ConnectionTracker::new();
        let backend = make_addr(3306);

        for i in 0..5 {
            let client = make_addr(12345 + i);
            tracker.track_connection(client, backend, "mysql".to_string());
        }

        let all = tracker.all_connections();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn test_next_id_unique() {
        let tracker = ConnectionTracker::new();
        let mut ids = Vec::new();

        for _ in 0..100 {
            ids.push(tracker.next_id());
        }

        // All IDs should be unique
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 100);
    }
}
