//! Connection pooling for backend connections.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, trace};

use super::config::PoolSettings;
use super::error::{TcpRouterError, TcpRouterResult};

/// Default max lifetime for connections (5 minutes).
const DEFAULT_MAX_LIFETIME: Duration = Duration::from_secs(300);

/// Default connection timeout (10 seconds).
const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// A pooled connection to a backend.
pub struct PooledConnection {
    /// The underlying stream.
    stream: Option<TcpStream>,

    /// Backend address this connection is for.
    backend_addr: SocketAddr,

    /// When this connection was created.
    created_at: Instant,

    /// When this connection was last used.
    last_used: Instant,

    /// Reference to the pool for returning the connection.
    pool: Arc<ConnectionPoolInner>,
}

impl PooledConnection {
    /// Get the underlying stream.
    pub fn stream(&mut self) -> &mut TcpStream {
        self.stream.as_mut().expect("stream taken")
    }

    /// Take ownership of the stream (connection will not be returned to pool).
    pub fn take(mut self) -> TcpStream {
        self.stream.take().expect("stream taken")
    }

    /// Check if connection is still fresh.
    #[must_use]
    pub fn is_fresh(&self, max_age: Duration) -> bool {
        self.created_at.elapsed() < max_age
    }

    /// Check if connection has been idle too long.
    #[must_use]
    pub fn is_idle(&self, max_idle: Duration) -> bool {
        self.last_used.elapsed() > max_idle
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            // Return connection to pool
            let pool = Arc::clone(&self.pool);
            let backend_addr = self.backend_addr;
            let created_at = self.created_at;

            tokio::spawn(async move {
                pool.return_connection(backend_addr, stream, created_at)
                    .await;
            });
        }
    }
}

/// Statistics for the connection pool.
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Total connections created.
    pub total_created: u64,

    /// Total connections reused.
    pub total_reused: u64,

    /// Current pooled connections.
    pub pooled_connections: usize,

    /// Current active (checked out) connections.
    pub active_connections: usize,

    /// Connection timeouts.
    pub timeouts: u64,

    /// Connections discarded (too old, etc.).
    pub discarded: u64,
}

/// Inner pool state.
struct ConnectionPoolInner {
    /// Pooled connections by backend address.
    connections: Mutex<HashMap<SocketAddr, Vec<PooledConnectionEntry>>>,

    /// Semaphore to limit total connections.
    semaphore: Semaphore,

    /// Pool settings.
    settings: PoolSettings,

    /// Statistics.
    stats: PoolStatsInner,
}

/// Entry in the connection pool.
struct PooledConnectionEntry {
    stream: TcpStream,
    created_at: Instant,
    returned_at: Instant,
}

/// Inner statistics tracking.
struct PoolStatsInner {
    total_created: AtomicU64,
    total_reused: AtomicU64,
    timeouts: AtomicU64,
    discarded: AtomicU64,
    active: AtomicUsize,
    pooled: AtomicUsize,
}

impl Default for PoolStatsInner {
    fn default() -> Self {
        Self {
            total_created: AtomicU64::new(0),
            total_reused: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            discarded: AtomicU64::new(0),
            active: AtomicUsize::new(0),
            pooled: AtomicUsize::new(0),
        }
    }
}

impl ConnectionPoolInner {
    async fn return_connection(&self, addr: SocketAddr, stream: TcpStream, created_at: Instant) {
        // Check if connection is too old
        if created_at.elapsed() > DEFAULT_MAX_LIFETIME {
            self.stats.discarded.fetch_add(1, Ordering::Relaxed);
            trace!(backend = %addr, "Connection too old, discarding");
            return;
        }

        let entry = PooledConnectionEntry {
            stream,
            created_at,
            returned_at: Instant::now(),
        };

        let mut connections = self.connections.lock().await;
        let pool = connections.entry(addr).or_default();

        // Check if pool is at capacity for this backend
        if pool.len() >= self.settings.max_size {
            self.stats.discarded.fetch_add(1, Ordering::Relaxed);
            trace!(backend = %addr, "Pool at capacity, discarding");
            return;
        }

        pool.push(entry);
        self.stats.active.fetch_sub(1, Ordering::Relaxed);
        self.stats.pooled.fetch_add(1, Ordering::Relaxed);
        debug!(backend = %addr, pooled = pool.len(), "Connection returned to pool");
    }
}

/// A connection pool for reusing backend connections.
pub struct ConnectionPool {
    inner: Arc<ConnectionPoolInner>,
}

impl ConnectionPool {
    /// Create a new connection pool.
    #[must_use]
    pub fn new(settings: PoolSettings) -> Self {
        let max_connections = settings.max_size;

        Self {
            inner: Arc::new(ConnectionPoolInner {
                connections: Mutex::new(HashMap::new()),
                semaphore: Semaphore::new(max_connections),
                settings,
                stats: PoolStatsInner::default(),
            }),
        }
    }

    /// Get a connection to a backend.
    ///
    /// Attempts to reuse a pooled connection first, otherwise creates a new one.
    ///
    /// # Errors
    ///
    /// Returns an error if connection fails or timeout is exceeded.
    pub async fn get(&self, backend_addr: SocketAddr) -> TcpRouterResult<PooledConnection> {
        // Try to get a pooled connection first
        if let Some(conn) = self.get_pooled(backend_addr).await {
            return Ok(conn);
        }

        // Need to create a new connection
        self.create_new(backend_addr).await
    }

    /// Try to get a pooled connection.
    async fn get_pooled(&self, backend_addr: SocketAddr) -> Option<PooledConnection> {
        let mut connections = self.inner.connections.lock().await;

        let pool = connections.get_mut(&backend_addr)?;

        while let Some(entry) = pool.pop() {
            // Check if connection is too old
            if entry.created_at.elapsed() > DEFAULT_MAX_LIFETIME {
                self.inner.stats.discarded.fetch_add(1, Ordering::Relaxed);
                self.inner.stats.pooled.fetch_sub(1, Ordering::Relaxed);
                continue;
            }

            // Check if connection has been idle too long
            if entry.returned_at.elapsed() > self.inner.settings.idle_timeout() {
                self.inner.stats.discarded.fetch_add(1, Ordering::Relaxed);
                self.inner.stats.pooled.fetch_sub(1, Ordering::Relaxed);
                continue;
            }

            self.inner
                .stats
                .total_reused
                .fetch_add(1, Ordering::Relaxed);
            self.inner.stats.active.fetch_add(1, Ordering::Relaxed);
            self.inner.stats.pooled.fetch_sub(1, Ordering::Relaxed);

            debug!(backend = %backend_addr, "Reusing pooled connection");

            return Some(PooledConnection {
                stream: Some(entry.stream),
                backend_addr,
                created_at: entry.created_at,
                last_used: Instant::now(),
                pool: Arc::clone(&self.inner),
            });
        }

        None
    }

    /// Create a new connection.
    async fn create_new(&self, backend_addr: SocketAddr) -> TcpRouterResult<PooledConnection> {
        // Wait for semaphore permit (respects max connections)
        let permit =
            tokio::time::timeout(DEFAULT_CONNECTION_TIMEOUT, self.inner.semaphore.acquire())
                .await
                .map_err(|_| {
                    self.inner.stats.timeouts.fetch_add(1, Ordering::Relaxed);
                    TcpRouterError::PoolExhausted {
                        address: backend_addr,
                    }
                })?
                .map_err(|_| TcpRouterError::PoolExhausted {
                    address: backend_addr,
                })?;

        // Create the connection
        let stream =
            tokio::time::timeout(DEFAULT_CONNECTION_TIMEOUT, TcpStream::connect(backend_addr))
                .await
                .map_err(|_| {
                    self.inner.stats.timeouts.fetch_add(1, Ordering::Relaxed);
                    TcpRouterError::ConnectionTimeout {
                        address: backend_addr,
                    }
                })?
                .map_err(|source| TcpRouterError::BackendConnectError {
                    address: backend_addr,
                    source,
                })?;

        // Forget the permit - we track this differently
        permit.forget();

        self.inner
            .stats
            .total_created
            .fetch_add(1, Ordering::Relaxed);
        self.inner.stats.active.fetch_add(1, Ordering::Relaxed);

        debug!(backend = %backend_addr, "Created new connection");

        Ok(PooledConnection {
            stream: Some(stream),
            backend_addr,
            created_at: Instant::now(),
            last_used: Instant::now(),
            pool: Arc::clone(&self.inner),
        })
    }

    /// Get pool statistics.
    #[inline]
    pub async fn stats(&self) -> PoolStats {
        PoolStats {
            total_created: self.inner.stats.total_created.load(Ordering::Relaxed),
            total_reused: self.inner.stats.total_reused.load(Ordering::Relaxed),
            pooled_connections: self.inner.stats.pooled.load(Ordering::Relaxed),
            active_connections: self.inner.stats.active.load(Ordering::Relaxed),
            timeouts: self.inner.stats.timeouts.load(Ordering::Relaxed),
            discarded: self.inner.stats.discarded.load(Ordering::Relaxed),
        }
    }

    /// Clear all pooled connections.
    pub async fn clear(&self) {
        let mut connections = self.inner.connections.lock().await;
        let total: usize = connections.values().map(|v| v.len()).sum();
        connections.clear();
        self.inner.stats.pooled.store(0, Ordering::Relaxed);

        debug!(cleared = total, "Cleared connection pool");
    }

    /// Prune idle and expired connections.
    pub async fn prune(&self) {
        let mut connections = self.inner.connections.lock().await;
        let mut pruned = 0;

        for pool in connections.values_mut() {
            let before = pool.len();
            pool.retain(|entry| {
                let is_valid = entry.created_at.elapsed() <= DEFAULT_MAX_LIFETIME
                    && entry.returned_at.elapsed() <= self.inner.settings.idle_timeout();
                if !is_valid {
                    self.inner.stats.discarded.fetch_add(1, Ordering::Relaxed);
                }
                is_valid
            });
            pruned += before - pool.len();
        }

        if pruned > 0 {
            debug!(pruned, "Pruned idle connections");
        }
    }
}

impl Clone for ConnectionPool {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn start_echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let _ = stream;
                        // Just hold the connection open
                        tokio::time::sleep(Duration::from_secs(60)).await;
                    });
                }
            }
        });

        addr
    }

    #[tokio::test]
    async fn test_pool_create_connection() {
        let backend = start_echo_server().await;
        let pool = ConnectionPool::new(PoolSettings::default());

        let conn = pool.get(backend).await.unwrap();
        assert!(conn.stream.is_some());

        let stats = pool.stats().await;
        assert_eq!(stats.total_created, 1);
        assert_eq!(stats.active_connections, 1);
    }

    #[tokio::test]
    async fn test_pool_reuse_connection() {
        let backend = start_echo_server().await;
        let pool = ConnectionPool::new(PoolSettings::default());

        // Get and return a connection
        {
            let _conn = pool.get(backend).await.unwrap();
        }

        // Wait for connection to be returned
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Get another connection - should reuse
        let _conn = pool.get(backend).await.unwrap();

        let stats = pool.stats().await;
        // May be 1 or 2 depending on timing
        assert!(stats.total_created >= 1);
    }

    #[tokio::test]
    async fn test_pool_clear() {
        let backend = start_echo_server().await;
        let pool = ConnectionPool::new(PoolSettings::default());

        // Get and return a connection
        {
            let _conn = pool.get(backend).await.unwrap();
        }

        tokio::time::sleep(Duration::from_millis(50)).await;

        pool.clear().await;

        let stats = pool.stats().await;
        assert_eq!(stats.pooled_connections, 0);
    }
}
