//! UDP session tracking for stateful routing.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::debug;

use super::config::SessionSettings;

/// Unique session identifier.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SessionId {
    /// Client address (source of original request).
    pub client: SocketAddr,

    /// Local address (where the request was received).
    pub local: SocketAddr,
}

impl SessionId {
    /// Create a new session ID.
    #[must_use]
    pub fn new(client: SocketAddr, local: SocketAddr) -> Self {
        Self { client, local }
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.client, self.local)
    }
}

/// A UDP session tracking client-backend association.
#[derive(Debug, Clone)]
pub struct Session {
    /// Session identifier.
    pub id: SessionId,

    /// Backend address for this session.
    pub backend: SocketAddr,

    /// Route name.
    pub route: String,

    /// Session creation time.
    pub created_at: Instant,

    /// Last activity time.
    pub last_activity: Instant,

    /// Number of datagrams forwarded (client -> backend).
    pub datagrams_sent: u64,

    /// Number of datagrams received (backend -> client).
    pub datagrams_received: u64,

    /// Bytes sent to backend.
    pub bytes_sent: u64,

    /// Bytes received from backend.
    pub bytes_received: u64,
}

impl Session {
    /// Create a new session.
    #[must_use]
    pub fn new(id: SessionId, backend: SocketAddr, route: String) -> Self {
        let now = Instant::now();
        Self {
            id,
            backend,
            route,
            created_at: now,
            last_activity: now,
            datagrams_sent: 0,
            datagrams_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    /// Check if the session has expired.
    #[must_use]
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Check if the session has expired relative to a reference time.
    ///
    /// More efficient than `is_expired` when checking many sessions,
    /// as the caller snapshots `Instant::now()` once.
    #[must_use]
    pub fn is_expired_at(&self, now: Instant, timeout: Duration) -> bool {
        now.duration_since(self.last_activity) > timeout
    }

    /// Update the session on activity.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Record a sent datagram.
    pub fn record_sent(&mut self, bytes: usize) {
        self.datagrams_sent += 1;
        self.bytes_sent += bytes as u64;
        self.touch();
    }

    /// Record a received datagram.
    pub fn record_received(&mut self, bytes: usize) {
        self.datagrams_received += 1;
        self.bytes_received += bytes as u64;
        self.touch();
    }

    /// Get session age.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get time since last activity.
    #[must_use]
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }
}

/// Statistics for the session manager.
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    /// Total sessions created.
    pub total_created: u64,

    /// Current active sessions.
    pub active_sessions: usize,

    /// Sessions expired and removed.
    pub expired_sessions: u64,

    /// Session lookups.
    pub lookups: u64,

    /// Session lookup hits.
    pub lookup_hits: u64,
}

/// Manages UDP sessions for stateful routing.
pub struct SessionManager {
    /// Active sessions by session ID.
    sessions: RwLock<HashMap<SessionId, Session>>,

    /// Reverse mapping: backend -> client for response routing.
    backend_to_client: RwLock<HashMap<SocketAddr, SessionId>>,

    /// Session settings.
    settings: SessionSettings,

    /// Statistics.
    stats: SessionManagerStats,
}

/// Inner statistics (atomic counters).
struct SessionManagerStats {
    total_created: AtomicU64,
    expired_sessions: AtomicU64,
    lookups: AtomicU64,
    lookup_hits: AtomicU64,
}

impl Default for SessionManagerStats {
    fn default() -> Self {
        Self {
            total_created: AtomicU64::new(0),
            expired_sessions: AtomicU64::new(0),
            lookups: AtomicU64::new(0),
            lookup_hits: AtomicU64::new(0),
        }
    }
}

impl SessionManager {
    /// Create a new session manager.
    #[must_use]
    pub fn new(settings: SessionSettings) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            backend_to_client: RwLock::new(HashMap::new()),
            settings,
            stats: SessionManagerStats::default(),
        }
    }

    /// Get or create a session for a client.
    ///
    /// If a session exists and is not expired, returns it.
    /// If no session exists or it's expired, returns None (caller should create new session).
    pub async fn get_session(&self, id: &SessionId) -> Option<Session> {
        self.stats.lookups.fetch_add(1, Ordering::Relaxed);

        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(id) {
            if !session.is_expired(self.settings.timeout()) {
                self.stats.lookup_hits.fetch_add(1, Ordering::Relaxed);
                return Some(session.clone());
            }
        }
        None
    }

    /// Create a new session.
    ///
    /// Returns the created session, or None if max sessions reached.
    pub async fn create_session(
        &self,
        id: SessionId,
        backend: SocketAddr,
        route: String,
    ) -> Option<Session> {
        let mut sessions = self.sessions.write().await;

        // Check max sessions limit
        if sessions.len() >= self.settings.max_sessions {
            debug!(
                max = self.settings.max_sessions,
                current = sessions.len(),
                "Max sessions reached, cannot create new session"
            );
            return None;
        }

        let session = Session::new(id.clone(), backend, route);
        sessions.insert(id.clone(), session.clone());

        // Add reverse mapping
        let mut reverse = self.backend_to_client.write().await;
        reverse.insert(backend, id);

        self.stats.total_created.fetch_add(1, Ordering::Relaxed);

        debug!(
            session = %session.id,
            backend = %backend,
            "Created new session"
        );

        Some(session)
    }

    /// Update a session with sent data.
    pub async fn record_sent(&self, id: &SessionId, bytes: usize) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(id) {
            session.record_sent(bytes);
        }
    }

    /// Update a session with received data.
    pub async fn record_received(&self, id: &SessionId, bytes: usize) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(id) {
            session.record_received(bytes);
        }
    }

    /// Find a session by backend address (for response routing).
    pub async fn find_by_backend(&self, backend: &SocketAddr) -> Option<Session> {
        let reverse = self.backend_to_client.read().await;
        if let Some(id) = reverse.get(backend) {
            return self.get_session(id).await;
        }
        None
    }

    /// Remove expired sessions.
    pub async fn cleanup(&self) -> usize {
        let timeout = self.settings.timeout();
        let now = Instant::now();
        let mut sessions = self.sessions.write().await;

        let before = sessions.len();

        // Single-pass retain: collect backend addrs for reverse-map cleanup
        let mut expired_backends = Vec::new();
        sessions.retain(|_id, session| {
            if session.is_expired_at(now, timeout) {
                expired_backends.push(session.backend);
                false
            } else {
                true
            }
        });

        let removed = before - sessions.len();

        // Only acquire reverse-map lock if we actually removed something
        if removed > 0 {
            // Drop sessions lock before acquiring reverse to reduce contention
            drop(sessions);

            let mut reverse = self.backend_to_client.write().await;
            for backend in &expired_backends {
                reverse.remove(backend);
            }

            self.stats
                .expired_sessions
                .fetch_add(removed as u64, Ordering::Relaxed);
            debug!(removed, "Cleaned up expired sessions");
        }

        removed
    }

    /// Get session statistics.
    pub async fn stats(&self) -> SessionStats {
        let sessions = self.sessions.read().await;

        SessionStats {
            total_created: self.stats.total_created.load(Ordering::Relaxed),
            active_sessions: sessions.len(),
            expired_sessions: self.stats.expired_sessions.load(Ordering::Relaxed),
            lookups: self.stats.lookups.load(Ordering::Relaxed),
            lookup_hits: self.stats.lookup_hits.load(Ordering::Relaxed),
        }
    }

    /// Get the current session count.
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
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
    fn test_session_id() {
        let id = SessionId::new(make_addr(12345), make_addr(5353));
        assert_eq!(id.client.port(), 12345);
        assert_eq!(id.local.port(), 5353);
    }

    #[test]
    fn test_session_expiry() {
        let id = SessionId::new(make_addr(12345), make_addr(5353));
        let session = Session::new(id, make_addr(53), "test".to_string());

        // Session should not be expired immediately
        assert!(!session.is_expired(Duration::from_secs(60)));

        // Session should be expired if timeout is 0
        assert!(session.is_expired(Duration::from_nanos(1)));
    }

    #[tokio::test]
    async fn test_session_manager_create() {
        let settings = SessionSettings::default();
        let manager = SessionManager::new(settings);

        let id = SessionId::new(make_addr(12345), make_addr(5353));
        let backend = make_addr(53);

        let session = manager
            .create_session(id.clone(), backend, "test".to_string())
            .await
            .unwrap();

        assert_eq!(session.backend, backend);
        assert_eq!(session.route, "test");

        // Should be able to get the session
        let retrieved = manager.get_session(&id).await.unwrap();
        assert_eq!(retrieved.backend, backend);
    }

    #[tokio::test]
    async fn test_session_manager_max_sessions() {
        let settings = SessionSettings {
            max_sessions: 2,
            ..SessionSettings::default()
        };
        let manager = SessionManager::new(settings);

        // Create max sessions
        for i in 0..2 {
            let id = SessionId::new(make_addr(10000 + i), make_addr(5353));
            manager
                .create_session(id, make_addr(53), "test".to_string())
                .await
                .unwrap();
        }

        // Should fail to create another
        let id = SessionId::new(make_addr(20000), make_addr(5353));
        let result = manager
            .create_session(id, make_addr(53), "test".to_string())
            .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_session_manager_cleanup() {
        let settings = SessionSettings {
            timeout_secs: 0, // Immediate expiry
            ..SessionSettings::default()
        };
        let manager = SessionManager::new(settings);

        let id = SessionId::new(make_addr(12345), make_addr(5353));
        manager
            .create_session(id.clone(), make_addr(53), "test".to_string())
            .await
            .unwrap();

        // Session should exist
        assert_eq!(manager.session_count().await, 1);

        // Wait a tiny bit and cleanup
        tokio::time::sleep(Duration::from_millis(10)).await;
        let removed = manager.cleanup().await;

        assert_eq!(removed, 1);
        assert_eq!(manager.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_session_manager_find_by_backend() {
        let settings = SessionSettings::default();
        let manager = SessionManager::new(settings);

        let id = SessionId::new(make_addr(12345), make_addr(5353));
        let backend = make_addr(53);

        manager
            .create_session(id.clone(), backend, "test".to_string())
            .await
            .unwrap();

        // Should find by backend
        let session = manager.find_by_backend(&backend).await.unwrap();
        assert_eq!(session.id, id);
    }
}
